# Capitolo 18 — Open Policy Agent (OPA) e Rego

> *"Le regole non servono se non le scrive qualcuno che le capisce.
> Rego e' il linguaggio per scriverle in modo che anche la macchina le capisca."*

---

## Cos'e' OPA — spiegazione da bar

Pensa a un arbitro di calcio. L'arbitro non gioca, non tifa — ha solo il regolamento e fischia quando qualcuno sgarra.

```
  REGOLAMENTO           +  SITUAZIONE IN CAMPO    =  DECISIONE
  (file .rego)             (input JSON)              ("allow" / "deny")
```

OPA (Open Policy Agent) e' quell'arbitro. Gli dai:
1. Le **regole** scritte in Rego (il regolamento)
2. I **dati** su chi vuole fare cosa (la situazione)

E lui ti dice: "passa" o "non passa".

La cosa bella? L'arbitro e' **esterno** alla partita. Puoi cambiare le regole senza toccare il codice del broker o degli agenti. Aggiungi una riga al file `.rego`, riavvii OPA, e la nuova regola e' attiva.

**Perche' e' importante?** Separare le regole dal codice significa che il team di security/compliance puo' modificare le policy senza aspettare un rilascio software. Il broker rimane uguale — cambiano solo le regole.

---

## Architettura di OPA — i tre ingredienti

OPA funziona con tre ingredienti che si combinano per produrre una decisione:

```
  ┌──────────────────────────────────────────────────────┐
  │                    OPA SERVER                        │
  │                                                      │
  │   ┌──────────┐     ┌──────────┐     ┌────────────┐  │
  │   │  POLICY  │  +  │   DATA   │  =  │  DECISION  │  │
  │   │ (.rego)  │     │ (.json)  │     │            │  │
  │   │          │     │          │     │ allow:true │  │
  │   │ "se org  │     │ config:  │     │ reason:"ok"│  │
  │   │  non e'  │     │  allowed │     │            │  │
  │   │  nella   │     │  _orgs:  │     └────────────┘  │
  │   │  lista,  │     │  ["a","b"]     ▲               │
  │   │  deny"   │     │          │     │               │
  │   └──────────┘     └──────────┘     │               │
  │                                      │               │
  └──────────────────────────────────────┼───────────────┘
                                         │
                              POST /v1/data/atn/session/allow
                              Body: {"input": {...}}
                                         │
                              ┌──────────┴──────────┐
                              │   CULLIS BROKER     │
                              │   (o PDP server)    │
                              └─────────────────────┘
```

| Ingrediente | Cosa contiene                    | Dove vive nel progetto                        |
|-------------|----------------------------------|-----------------------------------------------|
| **Policy**  | Regole scritte in Rego           | `enterprise-kit/opa/policy/atn/session.rego`  |
| **Data**    | Configurazione (whitelist, ecc.) | `enterprise-kit/opa/config.json`              |
| **Input**   | La richiesta specifica           | Inviato dal broker via HTTP POST              |

**Analogia:** Pensa a un giudice (OPA). Ha il codice penale (policy .rego), la giurisprudenza e le leggi speciali del suo paese (data .json), e il caso specifico da giudicare (input). Combinando tutto, emette la sentenza.

OPA espone un'API REST. Il broker fa una POST con l'input, e OPA restituisce la decisione. Semplice.

---

## Rego — le basi del linguaggio

Rego e' un linguaggio **dichiarativo**: non dici "fai questo, poi quest'altro", ma descrivi **le condizioni** sotto cui qualcosa e' vero o falso. Se vieni da Python o JavaScript, all'inizio sembra strano — ma il concetto chiave e' semplice.

### Concetto 1: Package e default

```rego
package atn.session        # namespace — corrisponde al path dell'API

default allow := false     # se nessuna regola matcha, il risultato e' false
```

Il `package` definisce dove OPA espone il risultato. Con `package atn.session`, la query sara':

```
POST /v1/data/atn/session/allow
```

**Analogia:** Il `package` e' come l'indirizzo di un ufficio. Se il package e' `atn.session`, la "stanza" dove trovi la risposta e' `/v1/data/atn/session/allow`.

Il `default` e' il **default-deny** — se nessuna regola si attiva, la risposta e' "no".

### Concetto 2: Regole con condizioni

```rego
# Se l'org initiator NON e' nella whitelist --> deny
allow := false if {
    count(allowed_orgs) > 0                        # la lista esiste e non e' vuota
    not input.initiator_org_id in allowed_orgs     # e l'org non c'e' dentro
}
```

Leggi questo come: "allow e' false SE la lista non e' vuota E l'org non e' nella lista".

Ogni riga dentro le `{}` e' una condizione. Tutte devono essere vere (AND implicito) perche' la regola si applichi.

**Analogia:** E' come una lista di controlli a un checkpoint. "Hai il passaporto? Si'. Il visto e' valido? Si'. Non sei nella lista nera? No." Tutte le condizioni devono passare.

### Concetto 3: Iterazione con `some`

```rego
# Per ogni capability richiesta, verifica che sia nella lista permessa
allow := false if {
    count(allowed_capabilities) > 0
    some cap in input.capabilities          # per ogni capability richiesta
    not cap in allowed_capabilities         # se non e' nella whitelist
}
```

`some cap in input.capabilities` e' come un `for cap in lista` in Python, ma dichiarativo: "esiste almeno un cap tale che..."

### Concetto 4: Risultati strutturati

Invece di restituire solo `true`/`false`, puoi restituire un oggetto con la motivazione:

```rego
allow := {"allow": false, "reason": reason} if {
    count(allowed_initiator_orgs) > 0
    not input.initiator_org_id in allowed_initiator_orgs
    reason := sprintf("org %s is not in allowed initiator orgs",
                      [input.initiator_org_id])
}
```

Il `sprintf` funziona come in C/Go: formatta una stringa con argomenti.

### Concetto 5: Dati esterni con `data.`

```rego
allowed_initiator_orgs := data.config.allowed_initiator_orgs if {
    data.config.allowed_initiator_orgs
} else := []
```

`data.config` fa riferimento al file JSON di configurazione caricato in OPA. Cosi' puoi cambiare la whitelist senza toccare il file Rego.

**Analogia:** E' come separare il modulo di un contratto (il template Rego) dai dati che ci metti dentro (il JSON). Stesso modulo, dati diversi per ogni cliente.

---

## La policy Rego di Cullis — pezzo per pezzo

Il file `enterprise-kit/opa/policy/atn/session.rego` implementa le regole di sessione. Vediamolo:

```rego
# enterprise-kit/opa/policy/atn/session.rego

package atn.session
import rego.v1

default allow := {"allow": false, "reason": "no matching policy rule"}
```

Il default e' un oggetto con `allow: false` — **default-deny**, coerente con il principio di Cullis.

### Le regole di deny

Ogni regola controlla una condizione specifica:

```rego
# Deny se un agente e' nella blocklist
allow := {"allow": false, "reason": reason} if {
    some agent in blocked_agents
    agent == input.initiator_agent_id
    reason := sprintf("agent %s is blocked", [agent])
}

# Deny se l'org initiator non e' nella whitelist
allow := {"allow": false, "reason": reason} if {
    count(allowed_initiator_orgs) > 0
    not input.initiator_org_id in allowed_initiator_orgs
    reason := sprintf("org %s is not in allowed initiator orgs",
                      [input.initiator_org_id])
}

# Deny se una capability non e' permessa
allow := {"allow": false, "reason": reason} if {
    count(allowed_capabilities) > 0
    some cap in input.capabilities
    not cap in allowed_capabilities
    reason := sprintf("capability %s is not allowed", [cap])
}
```

### La regola di allow (catch-all positivo)

```rego
# Allow se nessuna regola di deny ha matchato
allow := {"allow": true, "reason": "all checks passed"} if {
    not _any_blocked
    not _initiator_org_blocked
    not _target_org_blocked
    not _capability_blocked
}
```

Le regole helper (`_any_blocked`, `_initiator_org_blocked`, ecc.) sono definite in fondo al file come condizioni riutilizzabili:

```rego
_any_blocked if {
    some agent in blocked_agents
    agent == input.initiator_agent_id
}

_initiator_org_blocked if {
    count(allowed_initiator_orgs) > 0
    not input.initiator_org_id in allowed_initiator_orgs
}

_capability_blocked if {
    count(allowed_capabilities) > 0
    some cap in input.capabilities
    not cap in allowed_capabilities
}
```

### L'input document

Ecco cosa riceve OPA dal broker Cullis:

```json
{
  "input": {
    "initiator_agent_id": "org-a::buyer-agent",
    "initiator_org_id":   "org-a",
    "target_agent_id":    "org-b::supplier-agent",
    "target_org_id":      "org-b",
    "capabilities":       ["order.read", "order.write"]
  }
}
```

### Il file di configurazione (data)

```json
{
  "config": {
    "allowed_initiator_orgs": [],
    "allowed_target_orgs": [],
    "allowed_capabilities": [],
    "blocked_agents": []
  }
}
```

Liste vuote = tutto permesso. Aggiungi valori per restringere:

```json
{
  "config": {
    "allowed_initiator_orgs": ["partner-org", "supplier-org"],
    "allowed_target_orgs": ["partner-org"],
    "allowed_capabilities": ["order.read", "inventory.check"],
    "blocked_agents": ["org-x::rogue-agent"]
  }
}
```

---

## Integrazione OPA nel broker Cullis

Il file `app/policy/opa.py` e' l'adattatore che traduce il formato Cullis nel formato OPA:

```python
# Da: app/policy/opa.py (riga 62-93)

async def evaluate_session_via_opa(
    opa_url: str,
    initiator_org_id: str,
    target_org_id: str,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
) -> WebhookDecision:

    url = f"{opa_url.rstrip('/')}/v1/data/atn/session/allow"

    input_doc = {
        "input": {
            "initiator_agent_id": initiator_agent_id,
            "initiator_org_id": initiator_org_id,
            "target_agent_id": target_agent_id,
            "target_org_id": target_org_id,
            "capabilities": capabilities,
        }
    }
```

La risposta OPA viene tradotta in `WebhookDecision` per compatibilita' con il resto del broker:

```python
# Da: app/policy/opa.py (riga 116-127)

data = resp.json()
result = data.get("result", {})

if isinstance(result, bool):
    allowed = result
    reason = ""
elif isinstance(result, dict):
    allowed = bool(result.get("allow", False))
    reason = str(result.get("reason", ""))[:512]
```

OPA puo' restituire sia un booleano semplice che un oggetto strutturato. L'adattatore gestisce entrambi i casi. Anche qui, timeout di 5 secondi e default-deny su qualsiasi errore.

---

## Webhook vs OPA — quando usare quale

```
  WEBHOOK (per-org)                    OPA (broker-side)
  ──────────────────                   ──────────────────
  ┌──────┐  ┌──────┐                  ┌──────────────┐
  │PDP A │  │PDP B │                  │     OPA      │
  │      │  │      │                  │              │
  │regole│  │regole│                  │ regole A + B │
  │org A │  │org B │                  │ in un unico  │
  │      │  │      │                  │ file .rego   │
  └──┬───┘  └──┬───┘                  └──────┬───────┘
     │         │                              │
     │         │                              │
  2 chiamate HTTP                    1 chiamata HTTP
  (dual-org)                         (policy combinate)
```

| Aspetto              | Webhook                        | OPA                              |
|----------------------|--------------------------------|----------------------------------|
| Dove vivono le regole | Infra di ogni org             | Infra del broker                 |
| Quante chiamate      | 2 (una per org)                | 1 (OPA ha tutto)                 |
| Sovranita'           | Totale (ogni org gestisce)     | Centralizzata (broker gestisce)  |
| Latenza              | 2x network round-trip          | 1x localhost                     |
| Caso d'uso           | Produzione multi-org           | Dev, single-tenant, POC          |
| Flessibilita'        | Ogni org puo' usare il suo stack | Tutte le org condividono Rego  |

**Analogia:** Webhook e' come avere un avvocato per ogni famiglia. OPA e' come avere un unico giudice che conosce le leggi di tutte le famiglie. L'avvocato e' piu' flessibile (ogni famiglia sceglie il suo), il giudice e' piu' veloce (una sola udienza).

---

## Setup Docker Compose con OPA

Il file `enterprise-kit/pdp-template/docker-compose.opa.yml` configura OPA come sidecar:

```yaml
# enterprise-kit/pdp-template/docker-compose.opa.yml

services:
  opa:
    image: openpolicyagent/opa:latest
    ports:
      - "8181:8181"
    command:
      - "run"
      - "--server"
      - "--addr=0.0.0.0:8181"
      - "--log-level=info"
      - "/policies"
      - "/data/config.json"
    volumes:
      - ../opa/policy:/policies:ro
      - ../opa/config.json:/data/config.json:ro
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8181/health"]

  pdp-server:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "9000:9000"
    environment:
      - OPA_URL=http://opa:8181
    command: ["python", "pdp_server.py", "--port", "9000",
              "--opa-url", "http://opa:8181"]
    depends_on:
      opa:
        condition: service_healthy
```

Due container:

1. **`opa`** — il server OPA che carica le policy Rego e i dati di config
2. **`pdp-server`** — il PDP webhook che inoltra le decisioni a OPA

```
  Broker ──POST──> pdp-server:9000 ──POST──> opa:8181
                   /policy                    /v1/data/atn/session/allow
```

Per avviare:

```bash
cd enterprise-kit/pdp-template
docker compose -f docker-compose.opa.yml up
```

Per usare OPA direttamente dal broker (senza il PDP server intermedio):

```bash
# Nel .env del broker:
POLICY_BACKEND=opa
OPA_URL=http://opa:8181
```

---

## Scrivere policy Rego personalizzate

Vuoi aggiungere una regola che blocca le sessioni fuori orario lavorativo?

```rego
# Aggiungi in fondo a session.rego

# Deny sessions outside business hours (9-18 UTC)
allow := {"allow": false, "reason": "sessions only allowed 9-18 UTC"} if {
    hour := time.clock(time.now_ns())[0]
    hour < 9
}

allow := {"allow": false, "reason": "sessions only allowed 9-18 UTC"} if {
    hour := time.clock(time.now_ns())[0]
    hour >= 18
}
```

Vuoi limitare a massimo 3 capability per sessione?

```rego
allow := {"allow": false, "reason": reason} if {
    count(input.capabilities) > 3
    reason := sprintf("too many capabilities: %d (max 3)",
                      [count(input.capabilities)])
}
```

### Testare le policy con OPA CLI

```bash
# Testa una policy senza avviare il server
echo '{"input": {
  "initiator_org_id": "org-a",
  "target_org_id": "org-b",
  "initiator_agent_id": "org-a::agent-1",
  "target_agent_id": "org-b::agent-2",
  "capabilities": ["order.read"]
}}' | opa eval -d enterprise-kit/opa/policy/ \
               -d enterprise-kit/opa/config.json \
               -I 'data.atn.session.allow'
```

---

## Sicurezza dell'adattatore OPA

L'adattatore OPA di Cullis include validazione dell'URL per prevenire abusi:

```python
# Da: app/policy/opa.py (riga 32-59)

def validate_opa_url(opa_url: str) -> None:
    """Validate OPA URL scheme and check that it does not resolve
    to private IPs."""
    parsed = urlparse(opa_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(...)

    # localhost is expected in dev/Docker setups
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        _log.warning("OPA_URL points to loopback — acceptable in dev")
        return

    # Check for link-local and reserved IPs
    for ... in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_link_local or ip.is_reserved:
            raise ValueError(f"OPA_URL resolves to reserved IP: {ip}")
```

A differenza del webhook (dove l'URL e' fornito dall'utente e serve protezione SSRF completa), l'URL di OPA e' configurazione del server — quindi localhost e' permesso (tipico in Docker), ma gli IP riservati e link-local vengono comunque bloccati.

Timeout e default-deny identici al webhook: 5 secondi, e su qualsiasi errore la risposta e' DENY.

---

## Riepilogo — cosa portarti a casa

- **OPA** e' un motore di policy esterno di CNCF che valuta regole scritte in **Rego** e restituisce decisioni via API REST
- **Tre ingredienti**: policy (file .rego), dati (file .json), input (richiesta HTTP) producono la decisione
- **Rego** e' dichiarativo: descrivi condizioni, non procedure. Tutte le condizioni in un blocco `{}` sono in AND implicito
- **Default-deny** anche in OPA: `default allow := {"allow": false, ...}`
- Cullis supporta OPA come **alternativa** ai PDP webhook, configurabile con `POLICY_BACKEND=opa` e `OPA_URL`
- Il PDP server template puo' fare da **proxy verso OPA** (`--opa-url`) oppure il broker puo' chiamare OPA direttamente
- Le policy Rego si possono **personalizzare** aggiungendo regole al file `session.rego` e riavviando OPA
- **Webhook = per-org, sovranita' totale. OPA = centralizzato, bassa latenza.** La scelta dipende dal caso d'uso

---

*Prossimo capitolo: [19 — PDP Webhook](19-pdp-webhook.md) — il meccanismo con cui ogni organizzazione gestisce le proprie regole di autorizzazione*
