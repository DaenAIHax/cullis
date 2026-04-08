# Capitolo 17 — Policy Architecture — Dual-Org Evaluation

> *"Per aprire una porta servono due chiavi. Se anche una sola manca, la porta resta chiusa."*

---

## La storia del condominio — spiegazione da bar

Immagina un condominio con due appartamenti confinanti. Mario (appartamento A) vuole aprire un passaggio nel muro per parlare direttamente con Giulia (appartamento B).

Non basta che Mario dica "io voglio". Servono due permessi:

1. Il **regolamento del condominio di Mario** deve permettergli di aprire passaggi verso l'esterno
2. Il **regolamento del condominio di Giulia** deve permettere che qualcuno entri da fuori

Se anche uno solo dei due regolamenti dice "no", il passaggio non si apre. Nessun amministratore singolo puo' forzare la decisione dell'altro.

Questo e' esattamente come funziona la **dual-org policy evaluation** in Cullis: ogni sessione tra agenti di organizzazioni diverse richiede il consenso di **entrambe** le organizzazioni.

---

## PEP vs PDP — chi fa cosa

Due sigle che sembrano uguali ma hanno ruoli molto diversi.

### PEP — Policy Enforcement Point (il buttafuori)

Il PEP e' il broker Cullis. Non decide nulla da solo: riceve la richiesta, la inoltra al decisore, e poi **esegue** la decisione.

**Analogia:** Il cameriere al ristorante. Non decide lui se puoi sederti al tavolo VIP. Chiama il responsabile (PDP), aspetta la risposta, e poi ti accompagna o ti manda via.

### PDP — Policy Decision Point (il decisore)

Il PDP e' il servizio che valuta le regole e decide "allow" o "deny". In Cullis, ogni organizzazione ha il **suo** PDP — un webhook HTTP oppure un'istanza OPA.

**Analogia:** Il responsabile del ristorante che ha la lista prenotazioni e le regole della casa ("niente scarpe da ginnastica", "solo su prenotazione", "VIP al privé").

| Sigla   | Nome completo              | Chi e'                         | Dove vive                  |
|---------|----------------------------|--------------------------------|----------------------------|
| **PEP** | Policy Enforcement Point   | Il broker Cullis               | Infrastruttura del broker  |
| **PDP** | Policy Decision Point      | Webhook/OPA della singola org  | Infrastruttura dell'org    |

```
                        ┌──────────────────────────────────┐
                        │           BROKER (PEP)           │
                        │    Non decide — esegue e basta   │
                        └──────────┬───────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
             ┌──────▼──────┐              ┌──────▼──────┐
             │  PDP Org A  │              │  PDP Org B  │
             │  (webhook)  │              │  (webhook)  │
             │             │              │             │
             │ Regole di A │              │ Regole di B │
             └─────────────┘              └─────────────┘
                   │                             │
                   ▼                             ▼
              allow/deny                    allow/deny
                   │                             │
                   └──────────┬──────────────────┘
                              │
                     Entrambi "allow"?
                        │          │
                       SI'        NO
                        │          │
                        ▼          ▼
                   Sessione    Sessione
                    aperta     rifiutata
```

La separazione e' fondamentale: il broker (PEP) non sa **nulla** delle regole interne delle organizzazioni. Ogni org mantiene la sovranita' sulle proprie policy.

---

## Default-deny — il principio cardine

In Cullis, la regola d'oro e':

> **Tutto e' vietato finche' non e' esplicitamente permesso.**

Guarda come e' dichiarato nel codice del policy engine:

```python
# Da: app/policy/engine.py (riga 1-8)

"""
Policy engine — evaluates whether a session or message is allowed.

Defaults:
  - sessions: default deny  (without a policy, nothing passes)
  - messages: default allow (if the session is open, messages pass
                              unless an explicit policy blocks them)
"""
```

Nota la distinzione:
- **Sessioni**: default **deny** — senza policy esplicita, nessuna sessione si apre
- **Messaggi**: default **allow** — se la sessione e' aperta, i messaggi passano (a meno che una policy li blocchi)

**Analogia:** E' come un firewall. Per le connessioni nuove (sessioni), tutto e' bloccato di default. Ma una volta che la connessione e' stabilita (sessione aperta), il traffico al suo interno scorre — a meno che non ci sia una regola specifica che lo blocca.

Ecco tutti i casi in cui scatta il deny automatico:

| Situazione                                    | Risultato    |
|-----------------------------------------------|--------------|
| Org A non ha policy configurate               | **DENY**     |
| Org A non ha PDP webhook registrato           | **DENY**     |
| PDP di Org B non risponde (timeout 5s)        | **DENY**     |
| PDP risponde con HTTP 500                     | **DENY**     |
| PDP risponde con JSON invalido                | **DENY**     |
| PDP risponde `{"decision": "deny"}`           | **DENY**     |
| Entrambi rispondono `{"decision": "allow"}`   | **ALLOW**    |

Nel codice:

```python
# Da: app/policy/engine.py (riga 105-111)

if not policies:
    decision = PolicyDecision(
        allowed=False,
        reason="No policy defined — default deny",
    )
    await self._audit(db, "session", decision, org_id, agent_id, session_id)
    return decision
```

Nessuna policy = nessun accesso. Punto.

---

## Il flusso Dual-Org — passo per passo

Quando l'agente `buyer` di Org A vuole aprire una sessione con l'agente `supplier` di Org B, ecco cosa succede:

```
Agente Buyer (Org A)              Broker (PEP)                PDP Org A        PDP Org B
      │                              │                           │                │
      │── "Voglio una sessione" ────▶│                           │                │
      │   con supplier di Org B      │                           │                │
      │                              │                           │                │
      │                   FASE 1:    │── POST /policy ──────────▶│                │
      │                   Org A      │   context: "initiator"    │                │
      │                   puo'       │                           │                │
      │                   iniziare?  │◀── {"decision":"allow"} ──│                │
      │                              │                           │                │
      │                   FASE 2:    │── POST /policy ───────────────────────────▶│
      │                   Org B      │   context: "target"       │                │
      │                   accetta?   │                           │                │
      │                              │◀── {"decision":"allow"} ──────────────────│
      │                              │                           │                │
      │                   Entrambi   │                           │                │
      │                   allow!     │                           │                │
      │                              │                           │                │
      │◀── Sessione creata ─────────│                           │                │
      │                              │                           │                │
```

E' come un matrimonio: il prete chiede "vuoi tu?" a entrambi. Se anche solo uno dice "no" (o non si presenta), niente matrimonio.

Nel codice, questo flusso e' gestito dalla funzione `evaluate_session_via_webhooks`:

```python
# Da: app/policy/webhook.py (riga 279-318)

async def evaluate_session_via_webhooks(
    initiator_org_id: str,
    initiator_webhook_url: str | None,
    target_org_id: str,
    target_webhook_url: str | None,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
) -> WebhookDecision:
    """
    Call both orgs' PDP webhooks. Returns DENY if either denies.
    Both calls are made even if the first denies (for audit completeness).
    """
    initiator_decision = await call_pdp_webhook(
        org_id=initiator_org_id,
        webhook_url=initiator_webhook_url,
        # ... altri parametri ...
        session_context="initiator",
    )

    target_decision = await call_pdp_webhook(
        org_id=target_org_id,
        webhook_url=target_webhook_url,
        # ... altri parametri ...
        session_context="target",
    )

    if not initiator_decision.allowed:
        return initiator_decision
    if not target_decision.allowed:
        return target_decision
    return WebhookDecision(allowed=True, reason="both PDPs allowed", org_id="broker")
```

Dettaglio importante: **entrambe le chiamate vengono fatte sempre**, anche se la prima fallisce. Questo garantisce audit completo — sai sempre cosa ha detto ogni organizzazione.

---

## I tre tipi di policy

Cullis gestisce tre livelli di policy, ciascuno con un default diverso:

```
  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  SESSION POLICY  │     │ MESSAGE POLICY  │     │CAPABILITY POLICY│
  │                  │     │                 │     │                 │
  │ "Puoi aprire     │     │ "Questo msg     │     │ "Puoi usare     │
  │  una sessione?"  │     │  puo' passare?" │     │  questa skill?" │
  │                  │     │                 │     │                 │
  │ Default: DENY    │     │ Default: ALLOW  │     │ Embed in session│
  └─────────────────┘     └─────────────────┘     └─────────────────┘
        ▲                       ▲                       ▲
        │                       │                       │
    Prima della            Durante la              Al momento
    connessione            sessione               della richiesta
```

### 1. Session Policy — "chi puo' parlare con chi"

La piu' importante. Decide se una sessione puo' essere aperta. Default: **deny**. Condizioni valutabili:

- **target_org_id**: con quali organizzazioni posso comunicare?
- **capabilities**: quali operazioni sono permesse?
- **max_active_sessions**: quante sessioni contemporanee sono consentite?

```python
# Da: app/policy/models.py (riga 9-21)

class SessionConditions(BaseModel):
    target_org_id: list[str] = Field(
        default_factory=list,
        description="Organizations allowed. Empty = any.",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description="Permitted capabilities. Empty list = any.",
    )
    max_active_sessions: int | None = Field(
        default=None,
        description="Maximum number of concurrent active sessions.",
    )
```

**Analogia:** La lista invitati di una festa. Specifica: chi puo' venire (org), cosa puo' fare (capabilities), e quante persone al massimo (max_sessions).

Esempio di policy session in JSON:

```json
{
  "policy_id": "banca-a::session-v1",
  "org_id": "banca-a",
  "policy_type": "session",
  "rules": {
    "effect": "allow",
    "conditions": {
      "target_org_id": ["partner-org", "supplier-org"],
      "capabilities": ["order.read", "order.write"],
      "max_active_sessions": 50
    }
  }
}
```

### 2. Message Policy — "cosa puo' transitare"

Una volta che la sessione e' aperta, i messaggi di default passano. Ma puoi aggiungere regole sui messaggi:

- **max_payload_size_bytes**: dimensione massima del payload
- **required_fields**: campi obbligatori nel messaggio
- **blocked_fields**: campi vietati (es. dati sensibili)

```python
# Da: app/policy/models.py (riga 29-42)

class MessageConditions(BaseModel):
    max_payload_size_bytes: int | None = Field(
        default=None,
        description="Maximum size of the serialized JSON payload in bytes.",
    )
    required_fields: list[str] = Field(
        default_factory=list,
        description="Fields that must be present in the payload.",
    )
    blocked_fields: list[str] = Field(
        default_factory=list,
        description="Fields that must NOT be present in the payload.",
    )
```

**Analogia:** Il metal detector all'aeroporto. Sei gia' passato dal check-in (sessione aperta), ma prima di salire sull'aereo controlliamo: niente liquidi oltre 100ml (max size), carta d'imbarco obbligatoria (required fields), niente coltelli (blocked fields).

### 3. Capability Policy — "cosa sai fare"

Le capability vengono valutate come condizione nelle session policy. Se un agente richiede la capability `payment.execute` ma la policy permette solo `order.read`, la sessione viene negata:

```python
# Da: app/policy/engine.py (riga 132-138)

allowed_caps: list[str] = conditions.get("capabilities", [])
if allowed_caps:
    blocked = [c for c in capabilities if c not in allowed_caps]
    if blocked:
        is_match = False
        last_deny_reason = f"Capabilities {blocked} not permitted by policy"
```

```
Binding agente:    capabilities: ["purchase", "negotiate"]
                                     │
Session request:   capabilities: ["purchase"]     <-- OK, sottoinsieme
Session request:   capabilities: ["admin"]        <-- DENY, non nel binding
```

---

## Role-based: chi inizia conta

Il campo `session_context` nel payload del webhook dice al PDP il **ruolo** della sua organizzazione nella sessione:

- `"initiator"` — la mia org sta **iniziando** la sessione
- `"target"` — la mia org e' il **destinatario** della sessione

Questo permette regole asimmetriche:

```
                    PDP di Org A
              ┌─────────────────────────┐
              │ session_context="initiator"
              │                         │
              │ "Posso uscire verso     │
              │  Org B? Si', e' nella   │
              │  mia whitelist."        │
              │  --> ALLOW              │
              └─────────────────────────┘

                    PDP di Org B
              ┌─────────────────────────┐
              │ session_context="target" │
              │                         │
              │ "Org A vuole entrare?   │
              │  Verifico nel mio LDAP. │
              │  OK, autorizzato."      │
              │  --> ALLOW              │
              └─────────────────────────┘
```

Nel codice del PDP template (`enterprise-kit/pdp-template/pdp_server.py`):

```python
# Rule 2: allowed initiator orgs (when we are the target)
if context == "target" and rules["allowed_initiator_orgs"]:
    if initiator_org not in rules["allowed_initiator_orgs"]:
        return "deny", f"Org {initiator_org} is not in the allowed initiators list"

# Rule 3: allowed target orgs (when we are the initiator)
if context == "initiator" and rules["allowed_target_orgs"]:
    if target_org not in rules["allowed_target_orgs"]:
        return "deny", f"Org {target_org} is not in the allowed targets list"
```

---

## Il backend dispatcher

Il broker non chiama direttamente webhook o OPA. Passa attraverso un **dispatcher** (`app/policy/backend.py`) che sceglie il backend in base alla configurazione:

```python
# Da: app/policy/backend.py (riga 44-77)

backend = settings.policy_backend.lower()

if backend == "opa":
    from app.policy.opa import evaluate_session_via_opa
    return await evaluate_session_via_opa(...)

# Default: webhook backend
from app.policy.webhook import evaluate_session_via_webhooks
return await evaluate_session_via_webhooks(...)
```

```
                ┌─────────────────┐
                │ evaluate_session │
                │ _policy()       │
                └───────┬─────────┘
                        │
              ┌─────────▼──────────┐
              │ POLICY_BACKEND = ? │
              └─────────┬──────────┘
                   │          │
            "webhook"      "opa"
                   │          │
                   ▼          ▼
          ┌────────────┐  ┌──────────┐
          │ Dual-org   │  │ OPA REST │
          │ webhook    │  │ API call │
          │ (2 calls)  │  │ (single) │
          └────────────┘  └──────────┘
```

La variabile d'ambiente `POLICY_BACKEND` determina la scelta. Se il valore non e' riconosciuto, il sistema cade su webhook con un warning nel log.

Con il backend `webhook`, il broker chiama i PDP di entrambe le org (dual-org). Con il backend `opa`, il broker chiama OPA una sola volta (OPA ha le policy di entrambe le org caricate).

---

## Il motore built-in (PolicyEngine)

Oltre ai PDP esterni (webhook/OPA), Cullis ha un **policy engine interno** nel file `app/policy/engine.py`. La classe `PolicyEngine` gestisce due fasi per le sessioni:

```
  Fase 1: Policy dell'org initiator (default-deny)
  ─────────────────────────────────────────────────
  --> Cerca policy di tipo "session" per l'org A
  --> Se non ne trova: DENY
  --> Se ne trova una con effect="deny": DENY
  --> Se ne trova una con effect="allow" e condizioni soddisfatte: ALLOW

  Fase 2: Policy dell'org target (opt-out)
  ─────────────────────────────────────────
  --> Cerca policy di tipo "session" per l'org B
  --> Se non ne trova: ALLOW (opt-out, non ha configurato nulla)
  --> Se ne trova una con effect="deny" e match: DENY
  --> Altrimenti: mantieni la decisione della Fase 1
```

Nota l'asimmetria: l'**initiator** deve avere una policy esplicita (default-deny), mentre il **target** ha un approccio opt-out (se non ha configurato nulla, accetta). Questo perche' il target ha comunque il PDP webhook come ulteriore linea di difesa.

---

## Demo mode — bypass delle policy

Per lo sviluppo e le demo, Cullis supporta il bypass di tutte le policy:

```python
# Da: app/policy/engine.py (riga 52-55)

from app.config import is_policy_enforced
if not is_policy_enforced():
    decision = PolicyDecision(
        allowed=True,
        reason="Policy enforcement disabled (demo mode)"
    )
```

Tutto passa. Utile per testing, **mai** per produzione.

**Analogia:** E' come togliere la serratura dalla porta durante un trasloco. Comodo per portare dentro i mobili, ma la rimetterai prima di dormirci.

---

## Audit trail — ogni decisione e' tracciata

Ogni valutazione di policy (allow o deny) viene loggata con metriche OpenTelemetry:

```python
# Da: app/policy/engine.py (riga 283-308)

async def _audit(self, db, policy_type, decision, org_id, agent_id, session_id):
    if decision.allowed:
        POLICY_ALLOW_COUNTER.add(1, {"policy_type": policy_type})
    else:
        POLICY_DENY_COUNTER.add(1, {"policy_type": policy_type})
    await log_event(
        db,
        event_type="policy.evaluated",
        result="ok" if decision.allowed else "denied",
        # ...
    )
```

Questo significa che puoi:
- Vedere quante sessioni sono state bloccate per org
- Capire quale policy specifica ha bloccato
- Ricostruire la storia di ogni tentativo di sessione

---

## Riepilogo — cosa portarti a casa

- **PEP (broker) applica, PDP (org) decide**: la separazione e' fondamentale per la sovranita' di ogni organizzazione
- **Default-deny**: senza una policy esplicita che dice "allow", la risposta e' sempre NO. Per le sessioni, nessuna policy = nessun accesso
- **Dual-org evaluation**: il broker chiede il permesso a ENTRAMBE le organizzazioni. Se anche una sola dice no, la sessione non si apre
- **Tre tipi di policy**: session (default-deny), message (default-allow), capability (embedded nelle session policy)
- **`session_context`** distingue se l'org sta iniziando la sessione o la sta ricevendo, permettendo regole diverse per ruolo
- **Audit completo**: ogni decisione viene tracciata, anche i deny. Entrambe le chiamate PDP vengono fatte sempre per completezza
- **Demo mode**: il bypass esiste ma e' solo per lo sviluppo. In produzione, `policy_enforcement=True` sempre

---

*Prossimo capitolo: [18 — Open Policy Agent (OPA) e Rego](18-opa-rego.md) — come usare OPA come backend di policy per Cullis*
