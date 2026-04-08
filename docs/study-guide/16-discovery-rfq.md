# Capitolo 16 — Discovery e RFQ

> *"Prima di comprare, devi sapere chi vende. E prima di scegliere, devi chiedere i prezzi a tutti."*

---

## Cos'e la discovery — spiegazione da bar

Immagina di dover comprare 10 tonnellate di acciaio per la tua azienda. Non hai un fornitore fisso. Cosa fai?

1. **Cerchi chi vende acciaio** — sfogliando le Pagine Gialle, cercando per zona, per specializzazione, per nome
2. **Mandi una richiesta di preventivo** (RFQ) a tutti quelli che trovi
3. **Raccogli le risposte** entro una scadenza
4. **Scegli la migliore** e concludi l'affare

In Cullis, gli agenti AI fanno esattamente questo. La **discovery** e il "cercare chi vende acciaio", e l'**RFQ** (Request for Quote) e il "mandare la richiesta di preventivo a tutti".

```
Senza discovery:
  Buyer: "Devo parlare con steelco::supplier-a"
  → devi gia sapere chi e e come si chiama

Con discovery:
  Buyer: "Chi ha la capability 'steel_supply'?"
  → il broker ti restituisce la lista di tutti i fornitori
  → poi mandi l'RFQ a tutti → raccogli le quote
```

---

## Discovery multi-modale

Cullis non ha un solo modo di cercare agenti. Ne ha **sei**, combinabili tra loro:

```
┌─────────────────────────────────────────────────────────────┐
│                    FILTRI DI DISCOVERY                       │
│                                                             │
│  agent_id ──────── lookup diretto per ID interno            │
│  agent_uri ─────── lookup per SPIFFE URI                    │
│  org_id ─────────── tutti gli agenti di un'organizzazione   │
│  pattern ────────── glob match (es. "italmetal::*")         │
│  capability ────── agenti con TUTTE le capability (AND)     │
│  q ──────────────── ricerca full-text (nome, descrizione)   │
│                                                             │
│  Tutti i filtri sono COMBINABILI (intersezione)             │
└─────────────────────────────────────────────────────────────┘
```

**Analogia:** E come cercare un ristorante su Google Maps. Puoi filtrare per nome, per zona, per tipo di cucina, per valutazione — o combinare tutto: "ristorante giapponese a Milano con almeno 4 stelle".

### Endpoint: GET /registry/agents/search

```python
# app/registry/router.py — righe 120-143

@router.get("/agents/search", response_model=AgentListResponse)
async def search_agents_endpoint(
    capability: list[str] | None = Query(None),  # AND filter
    agent_id: str | None = Query(None),           # direct lookup
    agent_uri: str | None = Query(None),          # SPIFFE URI
    org_id: str | None = Query(None),             # filter by org
    pattern: str | None = Query(None),            # glob on agent_id
    q: str | None = Query(None),                  # free-text search
    include_own_org: bool = Query(False),          # include own org?
    ...
):
```

Almeno un filtro e obbligatorio — non puoi fare una ricerca senza parametri (sarebbe come chiedere "dammi tutti gli agenti del mondo").

---

## I sei filtri nel dettaglio

### 1. agent_id — lookup diretto

Il piu semplice: sai gia l'ID dell'agente e vuoi i suoi dettagli.

```
GET /registry/agents/search?agent_id=steelco::supplier-a

→ ritorna 0 o 1 agente
```

### 2. agent_uri — lookup per SPIFFE URI

Ogni agente ha un URI SPIFFE (vedi capitolo 07). Puoi cercare per URI:

```
GET /registry/agents/search?agent_uri=spiffe://cullis.local/steelco/supplier-a

→ il broker converte l'URI in agent_id e fa il lookup
```

```python
# app/registry/store.py — righe 203-208

if agent_uri and not agent_id:
    try:
        agent_id = spiffe_to_internal_id(agent_uri)
    except ValueError:
        return []
```

### 3. org_id — tutti gli agenti di un'organizzazione

Vuoi vedere tutti i fornitori di SteelCo? Filtra per organizzazione:

```
GET /registry/agents/search?org_id=steelco

→ ritorna tutti gli agenti attivi dell'org "steelco"
```

### 4. pattern — glob matching

Il glob matching usa la sintassi delle wildcard (`*`, `?`) per filtrare sugli agent_id:

```
GET /registry/agents/search?pattern=italmetal::*

→ ritorna tutti gli agenti il cui ID inizia con "italmetal::"
  (es. italmetal::buyer, italmetal::logistics, italmetal::admin)
```

Il pattern funziona anche sugli SPIFFE URI:

```python
# app/registry/store.py — righe 233-240

def _matches(a: AgentRecord) -> bool:
    if fnmatch(a.agent_id, pattern):
        return True
    try:
        spiffe = internal_id_to_spiffe(a.agent_id, trust_domain)
        return fnmatch(spiffe, pattern)
    except ValueError:
        return False
```

**Analogia:** E come cercare file con `ls *.pdf` — trovi tutti i file che finiscono con `.pdf`.

### 5. capability — filtro AND

Il filtro piu potente per il business: "trovami tutti gli agenti che hanno **tutte** queste capability":

```
GET /registry/agents/search?capability=steel_supply&capability=invoicing

→ ritorna solo agenti che hanno SIA steel_supply CHE invoicing
```

E un filtro AND, non OR: l'agente deve avere **tutte** le capability richieste.

```python
# app/registry/store.py — righe 244-248

if capabilities:
    def _has_all(a: AgentRecord) -> bool:
        agent_caps = set(a.capabilities)
        return all(c in agent_caps for c in capabilities)
    agents = [a for a in agents if _has_all(a)]
```

### 6. q — ricerca full-text

Ricerca libera su nome, descrizione, agent_id, org_id:

```
GET /registry/agents/search?q=acciaio

→ ritorna agenti il cui display_name, description, agent_id, o org_id
  contiene "acciaio" (case-insensitive)
```

```python
# app/registry/store.py — righe 252-257

if q:
    q_lower = q.lower()
    def _text_match(a: AgentRecord) -> bool:
        return (q_lower in a.agent_id.lower()
                or q_lower in a.display_name.lower()
                or q_lower in a.org_id.lower()
                or (a.description and q_lower in a.description.lower()))
```

---

## Filtri combinabili

I filtri si intersecano: ogni filtro restringe i risultati del precedente.

```
Esempio: "tutti i fornitori di acciaio dell'org steelco con capability invoicing"

  GET /registry/agents/search?org_id=steelco&capability=steel_supply&capability=invoicing

  Pipeline interna:
    tutti gli agenti attivi
      → filtro org_id = "steelco"     (es. da 500 a 12)
      → filtro capability AND         (es. da 12 a 3)
      → risultato: 3 agenti
```

L'unica eccezione: i lookup diretti (`agent_id`, `agent_uri`) bypassano l'esclusione della propria org, perche se cerchi per ID e perche sai gia cosa vuoi.

```python
# app/registry/router.py — righe 152-153

is_direct = bool(agent_id or agent_uri)
exclude = None if (is_direct or include_own_org) else current_agent.org
```

Di default, la discovery **esclude** gli agenti della tua stessa organizzazione (non ha senso che un buyer cerchi fornitori nella propria azienda). Puoi cambiare questo comportamento con `include_own_org=true`.

---

## RFQ — Request for Quote

La discovery ti dice **chi** puo fornirti qualcosa. L'RFQ ti permette di **chiedere i prezzi** a tutti contemporaneamente.

```
┌──────────────────────────────────────────────────────────────┐
│                      FLUSSO RFQ                              │
│                                                              │
│  Buyer                    Broker                  Suppliers   │
│  ─────                    ──────                  ─────────   │
│                                                              │
│  POST /broker/rfq         1. Discovery:                      │
│  {capability_filter:         trova agenti con                │
│   ["steel_supply"],          capability matching             │
│   payload: {item: ...},                                      │
│   timeout: 30s}           2. Policy check:                   │
│                              valuta PDP per                  │
│                              ogni candidato                  │
│                                                              │
│                           3. Broadcast:          ──────►  S1 │
│                              invia RFQ a tutti   ──────►  S2 │
│                              gli approvati       ──────►  S3 │
│                                                              │
│                           4. Collect:            ◄──────  S1 │
│                              raccoglie quote     ◄──────  S3 │
│                              con timeout                     │
│                                                              │
│  ◄── risposta con                                            │
│      tutte le quote       5. Close RFQ                       │
│      raccolte                                                │
└──────────────────────────────────────────────────────────────┘
```

**Analogia:** E come mandare una email circolare a tutti i fornitori di acciaio: "Mi servono 10 tonnellate, fatemi un prezzo entro 30 secondi." Chi risponde in tempo viene incluso nelle quote. Chi non risponde, pazienza.

---

## RFQ nel dettaglio — il codice

### Step 1: L'initiator manda la richiesta

```python
# app/broker/models.py — righe 92-99

class RfqRequest(BaseModel):
    capability_filter: list[str]    # agenti con TUTTE queste capability
    payload: dict                    # il contenuto dell'RFQ (cosa compri)
    timeout_seconds: int = 30        # finestra per le risposte (5-120s)
    context: dict = {}               # metadata opzionale
```

### Step 2: Il broker scopre i candidati

```python
# app/broker/rfq.py — righe 46-49

candidates = await search_agents_by_capabilities(
    db,
    capabilities=request.capability_filter,
    exclude_org_id=initiator.org,     # escludi la tua stessa org
)
```

La ricerca esclude automaticamente l'organizzazione del buyer — non vuoi mandare un RFQ ai tuoi stessi agenti.

### Step 3: Policy check per ogni candidato

Non basta trovare gli agenti: il broker deve verificare che la **policy** permetta la comunicazione con ciascuno:

```python
# app/broker/rfq.py — righe 71-84

for agent in candidates:
    target_org = await get_org_by_id(db, agent.org_id)
    decision = await evaluate_session_policy(
        initiator_org_id=initiator.org,
        initiator_webhook_url=initiator_org.webhook_url,
        target_org_id=agent.org_id,
        target_webhook_url=target_org.webhook_url,
        initiator_agent_id=initiator.agent_id,
        target_agent_id=agent.agent_id,
        capabilities=request.capability_filter,
    )
    if decision.allowed:
        approved.append(agent)
```

```
Esempio con 5 candidati:

  Candidato 1: policy OK     → approvato
  Candidato 2: policy DENIED → scartato (log in audit)
  Candidato 3: policy OK     → approvato
  Candidato 4: policy OK     → approvato
  Candidato 5: policy DENIED → scartato (log in audit)

  → 3 approvati, 2 scartati
```

### Step 4: Broadcast via WebSocket + notifica persistente

```python
# app/broker/rfq.py — righe 139-155

for agent in approved:
    await ws_manager.send_to_agent(agent.agent_id, rfq_message)
    await create_notification(
        db,
        recipient_type="agent",
        recipient_id=agent.agent_id,
        notification_type="rfq_request",
        title=f"RFQ from {initiator.agent_id}",
        body=f"Capabilities: {', '.join(request.capability_filter)}",
        reference_id=rfq_id,
        org_id=agent.org_id,
    )
```

Ogni agente approvato riceve sia un push WebSocket (se connesso) che una notifica persistente (se offline).

### Step 5: Raccolta risposte con timeout

Questo e il meccanismo piu interessante. Il broker usa un `asyncio.Queue` per raccogliere le risposte:

```python
# app/broker/rfq.py — righe 126-171

queue: asyncio.Queue = asyncio.Queue()
_rfq_queues[rfq_id] = queue

# Broadcast... (vedi sopra)

# Collect con timeout
quotes: list[RfqQuote] = []
deadline = asyncio.get_event_loop().time() + request.timeout_seconds
while len(quotes) < len(approved):
    remaining = deadline - asyncio.get_event_loop().time()
    if remaining <= 0:
        break
    try:
        quote = await asyncio.wait_for(queue.get(), timeout=remaining)
        quotes.append(quote)
    except asyncio.TimeoutError:
        break
```

```
Timeline con timeout=30s e 3 supplier approvati:

  t=0s:   broadcast a S1, S2, S3
  t=5s:   S1 risponde → quote 1 raccolta
  t=12s:  S3 risponde → quote 2 raccolta
  t=30s:  timeout! S2 non ha risposto
           → chiude l'RFQ con status "timeout"
           → ritorna 2 quote al buyer
```

### Step 6: I supplier rispondono

```python
# app/broker/rfq.py — righe 197-262

async def submit_rfq_response(db, rfq_id, responder, payload):
    # 1. L'RFQ esiste e e ancora open?
    rfq = ... # fetch da DB
    if rfq.status != "open":
        return False

    # 2. Il responder era tra gli approvati?
    matched = json.loads(rfq.matched_agents_json)
    if responder.agent_id not in matched:
        return False

    # 3. Ha gia risposto? (no duplicati)
    existing = ... # check DB
    if existing:
        return False

    # 4. Salva la risposta e pushala nella queue
    quote = RfqQuote(
        responder_agent_id=responder.agent_id,
        responder_org_id=responder.org,
        payload=payload,
        received_at=now,
    )
    queue = _rfq_queues.get(rfq_id)
    if queue:
        await queue.put(quote)
```

Controlli anti-abuso:
- Solo agenti nel set `matched_agents` possono rispondere
- Nessuna risposta duplicata (un agente, una quote)
- L'RFQ deve essere ancora in stato `open`

---

## Transaction Tokens — autorizzazione single-use

Dopo che il buyer ha ricevuto le quote e scelto un fornitore, serve un modo per **autorizzare l'operazione**. Qui entrano i **transaction token**.

```
┌─────────────────────────────────────────────────────────┐
│               FLUSSO TRANSACTION TOKEN                  │
│                                                         │
│  1. Human approva la quote nel dashboard                │
│  2. Broker emette un transaction token:                 │
│     - TTL: 30-60 secondi                                │
│     - Legato al payload specifico (hash)                │
│     - Single-use (consumato dopo il primo uso)          │
│  3. L'agente usa il token per inviare il messaggio      │
│  4. Broker valida e consuma il token                    │
│  5. Audit log registra la catena completa               │
│     RFQ → approvazione → esecuzione                    │
└─────────────────────────────────────────────────────────┘
```

**Analogia:** E come un biglietto del treno: vale per un solo viaggio, ha una scadenza, e ha stampato sopra il percorso (payload). Se provi a usarlo per un percorso diverso, non funziona. Se lo usi due volte, non funziona. Se e scaduto, non funziona.

### Struttura del token

```python
# app/auth/transaction_token.py — righe 63-80

claims = {
    "iss": "cullis-broker",
    "aud": "cullis",
    "sub": spiffe_id,              # chi e l'agente
    "agent_id": agent_id,
    "org": org_id,
    "token_type": "transaction",   # tipo speciale
    "act": {"sub": approved_by},   # chi ha approvato (human) — RFC 8693 actor chain
    "txn_type": txn_type,          # tipo di transazione
    "resource_id": resource_id,    # risorsa coinvolta
    "payload_hash": payload_hash,  # SHA-256 del payload approvato
    "parent_jti": parent_jti,      # JTI del token dell'agente (catena di autorizzazione)
    "exp": int(expires_at.timestamp()),  # scadenza breve (30-60s)
    "jti": jti,                    # ID univoco del token
}
```

### Il claim `act` — RFC 8693 Actor Chain

Il claim `act` segue **RFC 8693** (OAuth 2.0 Token Exchange) e implementa la catena di delega:

```json
{
  "sub": "spiffe://atn.local/org/acme/agent/buyer",
  "act": {
    "sub": "admin@acme.com"
  }
}
```

```
Significato:
  "L'agente acme::buyer agisce PER CONTO DI admin@acme.com"

  Catena di responsabilita:
    1. admin@acme.com ha approvato la transazione nel dashboard
    2. Il broker ha emesso un transaction token per acme::buyer
    3. acme::buyer usa il token per inviare il messaggio

  Se qualcosa va storto, l'audit trail mostra CHI ha approvato:
    → non solo "l'agente ha fatto X"
    → ma "l'agente ha fatto X perche admin@acme.com ha approvato"
```

Il `parent_jti` chiude la catena: collega il transaction token al JWT originale dell'agente, e opzionalmente al `rfq_id` per tracciare l'intera negoziazione: `RFQ → approvazione umana → esecuzione`.

### Payload hash — verifica integrita

Il transaction token contiene l'hash SHA-256 del payload approvato:

```python
# app/auth/transaction_token.py — righe 146-149

def compute_payload_hash(payload: dict) -> str:
    """Compute SHA-256 hash of a canonical JSON payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
```

Quando l'agente usa il token, il broker ricalcola l'hash del payload effettivo e lo confronta:

```python
# app/auth/transaction_token.py — righe 135-136

if record.payload_hash != actual_payload_hash:
    raise ValueError("Payload hash mismatch — "
                     "message does not match approved payload")
```

Se l'agente prova a inviare un payload diverso da quello approvato, il token viene rifiutato.

### Single-use — consumo atomico

```python
# app/auth/transaction_token.py — righe 138-141

# Consume atomically
record.status = "consumed"
record.consumed_at = now
await db.commit()
```

```
Stati del transaction token:

  active ───► consumed    (usato con successo)
    │
    └──────► expired      (TTL scaduto senza uso)
```

Un token non puo essere riusato: dopo il primo utilizzo diventa `consumed`. Se scade senza essere usato, diventa `expired`.

---

## La catena completa: Discovery → RFQ → Transaction

Ecco il flusso end-to-end di una negoziazione tra agenti:

```
Buyer Agent                    Broker                    Supplier Agents
─────────────                  ──────                    ───────────────

1. DISCOVERY
   GET /registry/agents/search
   ?capability=steel_supply ──►
                                trova S1, S2, S3
   ◄── [{S1}, {S2}, {S3}]

2. RFQ BROADCAST
   POST /broker/rfq
   {capability_filter:
    ["steel_supply"],
    payload: {item: "steel",
              qty: 10000},
    timeout: 30} ──────────►
                                policy check per S1,S2,S3
                                S1: allow, S2: deny, S3: allow
                                broadcast a S1, S3 ──────►  S1 riceve RFQ
                                                    ──────►  S3 riceve RFQ

3. QUOTE COLLECTION
                                                    ◄──────  S1: {price: 45/kg}
                                                    ◄──────  S3: {price: 42/kg}
   ◄── {quotes: [S1:45, S3:42],
        status: "closed"}

4. HUMAN APPROVAL (dashboard)
   Admin sceglie S3 (prezzo migliore)
   → broker emette transaction token
     con payload_hash del messaggio di ordine

5. EXECUTE WITH TRANSACTION TOKEN
   POST /broker/sessions/{id}/messages
   + transaction token
   {payload: {action: "buy",
              supplier: "S3",
              qty: 10000,
              price: 42}} ────►
                                valida transaction token:
                                - not expired? ✓
                                - not consumed? ✓
                                - payload_hash match? ✓
                                consuma token (single-use)
                                inoltra a S3 ───────────►  S3 riceve ordine
```

---

## Sicurezza della discovery

La discovery non e un "libero accesso a tutti i dati". Ci sono protezioni:

```
┌─────────────────────────────────────────────────────┐
│              PROTEZIONI DISCOVERY                   │
│                                                     │
│  1. AUTENTICAZIONE: solo agenti con JWT valido      │
│     possono cercare                                 │
│                                                     │
│  2. ESCLUSIONE OWN-ORG: di default non vedi        │
│     i tuoi colleghi (a meno di include_own_org)     │
│                                                     │
│  3. SOLO AGENTI ATTIVI: is_active == True           │
│                                                     │
│  4. ALMENO UN FILTRO: nessuna ricerca "dammi        │
│     tutto" — serve almeno un parametro              │
│                                                     │
│  5. DATI PUBBLICI: la discovery mostra solo info    │
│     pubbliche (ID, nome, capability, org).          │
│     Mai: chiavi private, secret, cert interni       │
└─────────────────────────────────────────────────────┘
```

---

## Dove vive il codice

| File | Cosa fa |
|---|---|
| `app/registry/store.py` | Logica di ricerca: `search_agents()` con tutti i filtri |
| `app/registry/router.py` | Endpoint REST: `GET /registry/agents/search` |
| `app/broker/rfq.py` | Ciclo di vita RFQ: broadcast, collect, timeout |
| `app/broker/models.py` | Modelli Pydantic: `RfqRequest`, `RfqQuote`, `RfqResponse` |
| `app/auth/transaction_token.py` | Creazione, validazione, consumo transaction token |

---

## Riepilogo — cosa portarti a casa

- **Discovery multi-modale**: 6 filtri combinabili (agent_id, SPIFFE URI, org_id, glob, capability AND, full-text)
- I filtri si **intersecano**: ogni filtro restringe i risultati del precedente
- Di default **escludi la tua org** dai risultati (non cerchi fornitori tra i tuoi colleghi)
- **RFQ** = broadcast automatico a tutti i supplier matching, con raccolta quote e timeout
- Il broker fa **policy check** su ogni candidato prima del broadcast — un supplier non approvato dalla policy non riceve l'RFQ
- Le risposte sono raccolte con **asyncio.Queue + timeout** — chi risponde in tempo viene incluso
- **Transaction token**: single-use, TTL breve (30-60s), legato al **payload hash** — l'agente non puo cambiare il payload dopo l'approvazione umana
- La catena completa e: Discovery → RFQ → Approvazione umana → Transaction token → Esecuzione
- Tutto e registrato nell'**audit log** per tracciabilita completa

---

*Prossimo capitolo: [17 — Policy Architecture: Dual-Org Evaluation](17-policy-dual-org.md) — come le policy di due organizzazioni diverse vengono valutate insieme*
