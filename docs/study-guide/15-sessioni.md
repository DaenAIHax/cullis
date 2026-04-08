# Capitolo 15 — Sessioni Inter-Agente

> *"Prima di parlare, ci si stringe la mano. Prima di scambiare dati, si apre una sessione."*

---

## Cos'e una sessione — spiegazione da bar

Immagina di prenotare una sala riunioni per un incontro d'affari:

1. **Tu chiedi** la sala (apri la sessione)
2. Il **responsabile** controlla se hai i permessi (policy check)
3. L'**altro partecipante** conferma che vuole venire (accept)
4. La riunione si svolge nella sala riservata (sessione attiva)
5. Alla fine, qualcuno chiude la sala (close)

Se il responsabile dice no, o l'altro partecipante rifiuta, la riunione non avviene. Nessun messaggio passa senza una sessione attiva.

```
Senza sessioni:
  Agente A ──"ciao!"──► Broker ──"ciao!"──► Agente B (chiunque scrive a chiunque)

Con sessioni:
  Agente A ──[apri sessione]──► Broker ──[policy check]──► PDP org A ✓
                                       ──[policy check]──► PDP org B ✓
                                       ──[notifica]──────► Agente B
  Agente B ──[accept]────────► Broker
  Solo ora: A ◄──[messaggi E2E]──► B    (canale protetto, con scope)
```

---

## Il modello di sessione

Ogni sessione in Cullis ha questi attributi:

```python
# app/broker/session.py — righe 33-47

@dataclass
class Session:
    session_id: str                      # UUID univoco
    initiator_agent_id: str              # chi ha aperto la sessione
    initiator_org_id: str                # organizzazione dell'initiator
    target_agent_id: str                 # destinatario
    target_org_id: str                   # organizzazione del target
    requested_capabilities: list[str]    # scope della sessione
    status: SessionStatus                # pending → active → closed
    created_at: datetime                 # quando e stata creata
    expires_at: datetime | None          # TTL (default: 60 minuti)
    used_nonces: set[str]                # nonce gia usati (anti-replay)
```

La sessione e uno **scope** limitato: non puoi fare tutto, puoi fare solo cio che le `requested_capabilities` permettono.

---

## Lifecycle — gli stati di una sessione

```
                    ┌─────────┐
                    │  Broker  │
                    │ creates  │
                    └────┬─────┘
                         │
                         ▼
                   ┌───────────┐
         ┌────────│  PENDING   │────────┐
         │        └───────────┘        │
         │              │              │
    target          target          timeout /
    rejects         accepts         expiry
         │              │              │
         ▼              ▼              ▼
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │  DENIED  │   │  ACTIVE  │   │  CLOSED  │
   └──────────┘   └────┬─────┘   └──────────┘
                       │
                  either party
                   closes / expiry
                       │
                       ▼
                  ┌──────────┐
                  │  CLOSED  │
                  └──────────┘
```

| Stato | Significato | Chi puo agire |
|-------|------------|---------------|
| **pending** | Sessione richiesta, in attesa di accettazione | Solo il target puo accept/reject |
| **active** | Entrambe le parti possono scambiare messaggi | Entrambi (send/poll/close) |
| **denied** | Il target ha rifiutato | Terminale — nessuna azione |
| **closed** | Chiusa esplicitamente o per timeout | Terminale — nessuna azione |

---

## Step 1: Apertura sessione — POST /broker/sessions

L'agente initiator chiama il broker per aprire una sessione:

```python
# app/broker/router.py — righe 55-70

@router.post("/sessions", response_model=SessionResponse,
             status_code=status.HTTP_201_CREATED)
async def request_session(
    body: SessionRequest,
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    await rate_limiter.check(current_agent.agent_id, "broker.session")
    # ...
```

Il body della richiesta contiene:

```json
{
  "target_agent_id": "steelco::supplier-a",
  "target_org_id": "steelco",
  "requested_capabilities": ["quoting", "invoicing"]
}
```

### Cosa controlla il broker prima di creare la sessione

Il broker esegue **5 verifiche** prima di creare la sessione:

```
1. TARGET ESISTE?
   → get_agent_by_id(target_agent_id)
   → se non esiste o non e attivo → 404

2. ORG CORRISPONDE?
   → target.org_id == body.target_org_id?
   → se no → 400

3. BINDING APPROVATO?
   → get_approved_binding(target_org_id, target_agent_id)
   → se il target non ha un binding approvato → 403

4. SCOPE VERIFICATO? (se policy_enforcement e attivo)
   → requested_capabilities ⊂ initiator.scope?
   → requested_capabilities ⊂ target.scope?
   → target.capabilities contiene le cap richieste?
   → se no → 403

5. POLICY PDP (doppio check federato)?
   → chiama PDP dell'org dell'initiator → allow/deny
   → chiama PDP dell'org del target → allow/deny
   → se ENTRAMBI non dicono allow → 403
```

```python
# app/broker/router.py — righe 133-153 — Policy evaluation federata

initiator_org = await get_org_by_id(db, current_agent.org)
target_org    = await get_org_by_id(db, body.target_org_id)

pdp_decision = await evaluate_session_policy(
    initiator_org_id=current_agent.org,
    initiator_webhook_url=initiator_org.webhook_url if initiator_org else None,
    target_org_id=body.target_org_id,
    target_webhook_url=target_org.webhook_url if target_org else None,
    initiator_agent_id=current_agent.agent_id,
    target_agent_id=body.target_agent_id,
    capabilities=body.requested_capabilities,
)
if not pdp_decision.allowed:
    raise HTTPException(status_code=403,
                        detail=f"Policy: {pdp_decision.reason}")
```

```
Analogia — il doppio visto:

  Vuoi viaggiare dall'Italia alla Svizzera.
  Servono DUE permessi:
    - L'Italia ti autorizza a uscire (PDP dell'org initiator)
    - La Svizzera ti autorizza a entrare (PDP dell'org target)

  Se anche UNO dei due dice no → viaggio annullato.
  Questo e il default-deny federato di Cullis.
```

### Notifica al target

Se la sessione viene creata con successo, il broker notifica il target in **due modi**:

```python
# app/broker/router.py — righe 175-194

# 1. Notifica persistente (sopravvive anche se l'agente e offline)
await create_notification(
    db,
    recipient_type="agent",
    recipient_id=body.target_agent_id,
    notification_type="session_pending",
    title=f"Session request from {current_agent.agent_id}",
    body=f"Capabilities: {', '.join(body.requested_capabilities)}",
    reference_id=session.session_id,
    org_id=target_binding.org_id,
)

# 2. Push WebSocket in tempo reale (se il target e connesso)
await ws_manager.send_to_agent(body.target_agent_id, {
    "type": "session_pending",
    "session_id": session.session_id,
    "initiator_agent_id": current_agent.agent_id,
    "capabilities": body.requested_capabilities,
})
```

---

## Step 2: Accettazione — POST /broker/sessions/{id}/accept

Il target riceve la notifica e decide se accettare o rifiutare:

```python
# app/broker/router.py — righe 207-252

@router.post("/sessions/{session_id}/accept", response_model=SessionResponse)
async def accept_session(session_id, current_agent, store, db):
    session = store.get(session_id)

    # Solo il target designato puo accettare
    if session.target_agent_id != current_agent.agent_id:
        raise HTTPException(403, "Only the target can accept")

    # La sessione deve essere in stato pending
    if session.status != SessionStatus.pending:
        raise HTTPException(409, f"Session is '{session.status}', cannot be accepted")

    store.activate(session_id)   # pending → active
    await save_session(db, session)
```

Il rifiuto funziona allo stesso modo:

```python
# app/broker/router.py — righe 255-307

@router.post("/sessions/{session_id}/reject")
async def reject_session(...):
    store.reject(session_id)     # pending → denied

    # Notifica l'initiator via WebSocket
    await ws_manager.send_to_agent(session.initiator_agent_id, {
        "type": "session_rejected",
        "session_id": session.session_id,
        "rejected_by": current_agent.agent_id,
    })
```

---

## Step 3: Messaggistica — POST /broker/sessions/{id}/messages

Una volta che la sessione e **active**, entrambi gli agenti possono scambiare messaggi:

```
POST /v1/broker/sessions/{session_id}/messages

Body (MessageEnvelope):
{
  "session_id": "550e8400-e29b-...",
  "sender_agent_id": "acme::buyer",
  "nonce": "unique-random-string",
  "timestamp": 1712345678,
  "client_seq": 0,
  "payload": { ... cifrato E2E ... },
  "signature": "base64url..."
}
```

Il broker esegue **6 controlli** su ogni messaggio:

```
1. SESSIONE ATTIVA?   → se non active → 409
2. PARTECIPANTE?      → sender deve essere initiator o target → 403
3. NONCE GIA USATO?   → replay protection (cache + DB UNIQUE) → 409
4. TIMESTAMP FRESCO?  → |now - timestamp| < 60 secondi → 409
5. FIRMA VALIDA?      → verifica outer signature con il cert → 401
6. POLICY MESSAGGIO?  → evaluates message-level policy → 403
```

```python
# app/broker/router.py — righe 419-451

# Anti-replay: nonce gia usato?
if session.is_nonce_cached(envelope.nonce):
    raise HTTPException(409, "Nonce already used - possible replay attack")

# Freshness: timestamp entro 60 secondi?
now_ts = int(datetime.now(timezone.utc).timestamp())
if abs(now_ts - envelope.timestamp) > 60:
    raise HTTPException(409, "Message timestamp too old or in the future")

# Verifica firma esterna
verify_message_signature(
    agent_rec.cert_pem, envelope.signature,
    session_id, current_agent.agent_id,
    envelope.nonce, envelope.timestamp,
    envelope.payload, client_seq=envelope.client_seq,
)
```

### Delivery al destinatario

Dopo la validazione, il broker **salva** il messaggio e lo **pusha** via WebSocket:

```python
# app/broker/router.py — righe 544-562

# Push via WebSocket se il destinatario e connesso
recipient_id = (
    session.target_agent_id
    if current_agent.agent_id == session.initiator_agent_id
    else session.initiator_agent_id
)
if ws_manager.is_connected(recipient_id):
    await ws_manager.send_to_agent(recipient_id, {
        "type": "new_message",
        "session_id": session_id,
        "message": {
            "seq": seq,
            "sender_agent_id": current_agent.agent_id,
            "payload": envelope.payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    })
```

Se il destinatario non e connesso via WebSocket, puo fare **polling**:

```
GET /v1/broker/sessions/{session_id}/messages?after=5

→ ritorna tutti i messaggi con seq > 5 non inviati da te
```

---

## Step 4: Chiusura — POST /broker/sessions/{id}/close

Entrambi i partecipanti possono chiudere la sessione:

```python
# app/broker/router.py — righe 310-363

@router.post("/sessions/{session_id}/close")
async def close_session(...):
    participants = {session.initiator_agent_id, session.target_agent_id}
    if current_agent.agent_id not in participants:
        raise HTTPException(403, "You are not a participant")

    if session.status != SessionStatus.active:
        raise HTTPException(409, f"Session is '{session.status}', cannot be closed")

    store.close(session_id)   # active → closed
```

Le sessioni hanno anche un **TTL automatico** (default 60 minuti):

```python
# app/broker/session.py — righe 104-106

def __init__(self, session_ttl_minutes: int = 60):
    self._sessions: dict[str, Session] = {}
    self._ttl = timedelta(minutes=session_ttl_minutes)
```

Se la sessione scade, il broker la chiude automaticamente al prossimo accesso:

```python
# app/broker/session.py — righe 49-52

def is_expired(self) -> bool:
    if self.expires_at is None:
        return False
    return datetime.now(timezone.utc) > self.expires_at
```

---

## WebSocket — notifiche in tempo reale

Il broker supporta WebSocket per push notifications. Il protocollo:

```
Client                                         Broker
──────                                         ──────

1. Connessione WebSocket:
   GET /v1/broker/ws  ──────────────────────►

2. Autenticazione:
   {"type":"auth", "token":"<JWT>",
    "dpop_proof":"<DPoP>"}  ────────────────►
                                               3. Verifica JWT + DPoP
                                               4. Verifica binding approvato
                                               5. Verifica token non revocato
                         ◄────────────────────
   {"type":"auth_ok", "agent_id":"acme::buyer"}

6. Da qui in poi, il server pusha:
                         ◄────────────────────
   {"type":"session_pending",
    "session_id":"...",
    "initiator_agent_id":"..."}

                         ◄────────────────────
   {"type":"new_message",
    "session_id":"...",
    "message":{...}}

7. Keepalive:
   {"type":"ping"}  ────────────────────────►
                         ◄────────────────────
   {"type":"pong"}
```

Protezioni sul WebSocket:

```python
# app/broker/router.py — righe 712, 834-836

_WS_AUTH_TIMEOUT = 10    # secondi per autenticarsi
_WS_IDLE_TIMEOUT = 300   # 5 minuti di inattivita → disconnect
_WS_MSG_LIMIT = 30       # max 30 messaggi per finestra
_WS_MSG_WINDOW = 60      # finestra di 60 secondi
```

| Protezione | Valore | Perche |
|------------|--------|--------|
| Auth timeout | 10s | Previene connessioni "fantasma" che occupano risorse |
| Idle timeout | 5 min | Libera risorse da client disconnessi silenziosamente |
| Rate limit | 30/min | Previene flooding del server |
| Token expiry check | ogni messaggio | Se il JWT scade durante la connessione, chiude |
| Origin validation | whitelist | Previene connessioni da origini non autorizzate |

---

## Anti-replay: la difesa a doppio livello

I nonce sono la prima difesa contro gli attacchi replay. Cullis usa un sistema a **due livelli**:

```
Livello 1: Cache in-memory (fast path)
  ┌─────────────────────────┐
  │  used_nonces: set[str]  │  ← fino a 100.000 nonce per sessione
  └─────────┬───────────────┘
            │ nonce gia visto? → REJECT immediatamente
            │ nonce nuovo? → passa al livello 2
            ▼
Livello 2: DB con UNIQUE constraint (source of truth)
  ┌───────────────────────────┐
  │  messages.nonce  UNIQUE   │  ← INSERT fallisce se duplicato
  └───────────────────────────┘
```

```python
# app/broker/session.py — righe 64-73

def cache_nonce(self, nonce: str) -> None:
    """Record a nonce in the in-memory cache."""
    if len(self.used_nonces) >= self._MAX_NONCES:
        self.used_nonces.pop()    # evict per non crescere all'infinito
    self.used_nonces.add(nonce)
```

Perche due livelli? La cache evita una query al DB per nonce ovviamente duplicati. Ma la cache puo perdere nonce (eviction, restart del server), quindi il DB con vincolo UNIQUE e la fonte di verita definitiva.

---

## Session store: limiti e eviction

Il session store in-memory ha protezioni contro l'esaurimento delle risorse:

```python
# app/broker/session.py — righe 102, 110-127

class SessionStore:
    _MAX_SESSIONS: int = 10_000   # cap massimo

    def _evict_stale(self) -> int:
        """Rimuove sessioni chiuse, denied o scadute."""
        to_remove = [
            sid for sid, s in self._sessions.items()
            if s.status in (SessionStatus.closed, SessionStatus.denied)
            or (s.expires_at is not None and s.expires_at < now)
        ]
        for sid in to_remove:
            del self._sessions[sid]
```

```
Analogia — le sale riunioni dell'hotel:

  L'hotel ha 10.000 sale. Quando chiedi una nuova sala:
  1. Prima libera le sale dove la riunione e finita o scaduta
  2. Se ci sono ancora sale libere → te ne assegna una
  3. Se tutte 10.000 sono occupate → "spiacenti, tutte occupate" (503)
```

---

## Capability-scoped sessions

Le sessioni in Cullis sono **scoped**: quando apri una sessione, dichiari quali capability ti servono. Il broker verifica che:

1. L'initiator ha quelle capability nel suo token scope
2. Il target ha quelle capability nel suo binding scope
3. Il target le pubblicizza effettivamente nel registry

```
Esempio:

  Agente "acme::buyer" ha scope: ["quoting", "invoicing", "inventory"]
  Agente "steelco::supplier" ha scope: ["quoting", "invoicing"]

  Richiesta: capabilities=["quoting", "invoicing"]  → OK (entrambi le hanno)
  Richiesta: capabilities=["inventory"]              → DENIED (il supplier non ha "inventory")
```

Questo limita cosa gli agenti possono fare all'interno della sessione: e il **principio del minimo privilegio** applicato alle sessioni.

---

## Il flusso completo — diagramma temporale

```
    Agente A                        Broker                         Agente B
    (initiator)                                                    (target)
    ──────────                      ──────                         ──────────

    POST /sessions
    {target: B, caps: [quoting]}
         │
         ├──────────────────────►  1. Verifica target esiste
                                   2. Verifica binding approvato
                                   3. Verifica scope
                                   4. Chiama PDP org A → allow ✓
                                   5. Chiama PDP org B → allow ✓
                                   6. Crea sessione (PENDING)
                                   7. Notifica persistente
                                   8. Push WebSocket ─────────────► riceve notifica
         ◄──────────────────────
    201 {session_id, status:pending}

                                                                   POST /sessions/{id}/accept
                                                                        │
                                   9. Verifica: e il target? ◄─────────┤
                                   10. Verifica: stato pending?
                                   11. Attiva sessione (ACTIVE)
                                        │
                                        ├──────────────────────────────►
                                   200 {status: active}

    POST /sessions/{id}/messages
    {payload: E2E_blob, sig: outer}
         │
         ├──────────────────────►  12. Sessione attiva?
                                   13. Partecipante legittimo?
                                   14. Nonce non replicato?
                                   15. Timestamp fresco?
                                   16. Firma esterna valida?
                                   17. Policy messaggio?
                                   18. Salva + push WS ──────────► riceve messaggio
         ◄──────────────────────
    202 {status: accepted}

                                                                   POST /sessions/{id}/close
                                                                        │
                                   19. Chiude sessione (CLOSED) ◄──────┤
```

---

## Riepilogo — cosa portarti a casa

- **Sessione** = canale temporaneo, scoped, tra due agenti. Nessun messaggio passa senza sessione attiva.
- **Lifecycle**: pending (aperta) → active (accettata) → closed (chiusa o scaduta). Il target puo anche rifiutare (denied).
- **Doppio policy check federato**: sia l'org dell'initiator che quella del target devono approvare. Default-deny.
- **Capability-scoped**: la sessione ha uno scope limitato alle capability richieste. Minimo privilegio.
- **WebSocket + polling**: push in tempo reale via WS, con fallback a REST polling. Protezioni: auth timeout, idle timeout, rate limit, token expiry check.
- **Anti-replay a doppio livello**: cache in-memory (fast path) + DB UNIQUE constraint (source of truth).
- **TTL automatico**: sessioni scadono dopo 60 minuti (configurabile). Il broker fa eviction delle sessioni stale.
- **Notifiche persistenti**: anche se il target e offline, la notifica lo aspetta nel DB.
- **Session store con cap**: massimo 10.000 sessioni simultanee, con eviction automatica.

---

Prossimo capitolo: [Capitolo 16 — Discovery e RFQ](16-discovery-rfq.md)
