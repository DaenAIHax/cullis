# Capitolo 19 — PDP Webhook

> *"Ogni palazzo ha il suo portiere. E il portiere decide chi entra e chi no —
> non il condominio dall'altra parte della strada."*

---

## Cos'e' un PDP Webhook — spiegazione da bar

Immagina che devi organizzare una cena tra due famiglie. Prima di fissare la data, chiami entrambe le mamme:

```
  Tu:     "Signora Rossi, i suoi possono venire a cena dai Bianchi?"
  Rossi:  "Si', va bene."       <-- {"decision": "allow"}

  Tu:     "Signora Bianchi, i Rossi possono venire da voi?"
  Bianchi: "No, abbiamo ospiti." <-- {"decision": "deny", "reason": "occupied"}
```

Tu non decidi nulla — fai solo le telefonate e riporti. Se anche una sola mamma dice no, la cena non si fa. E se una non risponde al telefono entro 5 secondi? Niente cena — meglio non rischiare.

Questo e' esattamente il PDP webhook di Cullis. Il broker (tu) chiama i PDP (le mamme) e applica la risposta.

Un webhook e' una **callback HTTP**: invece di andare tu a chiedere le informazioni, le informazioni vengono **spinte** (push) verso un URL che hai registrato in anticipo.

---

## Il pattern in Cullis

Il flusso completo funziona cosi':

```
  1. Org A registra il suo PDP webhook: https://pdp.org-a.com/policy
  2. Org B registra il suo PDP webhook: https://pdp.org-b.com/policy
  3. Agent A vuole parlare con Agent B
  4. Il broker chiama il PDP di Org A (session_context: "initiator")
  5. Il broker chiama il PDP di Org B (session_context: "target")
  6. Se entrambi dicono "allow" --> sessione aperta
```

```
  Org A                   Broker                   Org B
  (PDP A)                 (PEP)                    (PDP B)
    │                       │                        │
    │   POST /policy        │                        │
    │<──────────────────────│                        │
    │   {"decision":"allow"}│                        │
    │──────────────────────>│                        │
    │                       │   POST /policy         │
    │                       │───────────────────────>│
    │                       │  {"decision":"allow"}  │
    │                       │<───────────────────────│
    │                       │                        │
    │                  ALLOW (both)                   │
    │                       │                        │
```

**Analogia:** E' come un ponte levatoio con due torri di guardia, una per lato. Ogni torre deve dare il via libera perche' il ponte si abbassi. Se anche una sola torre non risponde, il ponte resta alzato.

---

## Formato del payload (Request)

Quando il broker chiama il PDP webhook, invia questa richiesta HTTP:

```http
POST https://pdp.org-a.com/policy
Content-Type: application/json
X-ATN-Signature: <HMAC-SHA256>    (futuro — non ancora enforced)
```

```json
{
  "initiator_agent_id": "org-a::buyer-agent",
  "initiator_org_id":   "org-a",
  "target_agent_id":    "org-b::supplier-agent",
  "target_org_id":      "org-b",
  "capabilities":       ["order.read", "order.write"],
  "session_context":    "initiator"
}
```

| Campo                  | Tipo       | Descrizione                                    |
|------------------------|------------|------------------------------------------------|
| `initiator_agent_id`   | `string`   | ID completo dell'agente che inizia             |
| `initiator_org_id`     | `string`   | Organizzazione dell'agente initiator           |
| `target_agent_id`      | `string`   | ID completo dell'agente destinatario           |
| `target_org_id`        | `string`   | Organizzazione dell'agente target              |
| `capabilities`         | `string[]` | Capability richieste per la sessione           |
| `session_context`      | `string`   | `"initiator"` o `"target"` — il ruolo dell'org |

Il campo `session_context` e' cruciale: dice al PDP **in che ruolo** si trova la sua organizzazione:

- `"initiator"` --> "Il tuo agente vuole aprire una sessione. Lo autorizzi?"
- `"target"` --> "Qualcuno vuole parlare con il tuo agente. Lo fai entrare?"

Nel codice, il payload viene costruito cosi':

```python
# Da: app/policy/webhook.py (riga 179-187)

payload = {
    "initiator_agent_id": initiator_agent_id,
    "initiator_org_id":   initiator_org_id,
    "target_agent_id":    target_agent_id,
    "target_org_id":      target_org_id,
    "capabilities":       capabilities,
    "session_context":    session_context,
}
```

---

## Formato della risposta (Response)

Il PDP deve rispondere con HTTP 200 e un JSON.

**Sessione autorizzata:**

```json
{
  "decision": "allow"
}
```

**Sessione rifiutata:**

```json
{
  "decision": "deny",
  "reason": "Org org-x is not in the allowed initiators list"
}
```

| Campo      | Tipo     | Obbligatorio | Descrizione                          |
|------------|----------|--------------|--------------------------------------|
| `decision` | `string` | Si'          | `"allow"` oppure `"deny"`            |
| `reason`   | `string` | No           | Motivazione del deny (max 512 char)  |

Qualsiasi valore diverso da `"allow"` o `"deny"` viene trattato come **deny**:

```python
# Da: app/policy/webhook.py (riga 240-247)

data = resp.json()
decision = data.get("decision", "deny").lower()
if decision not in ("allow", "deny"):
    _log.warning(
        "PDP webhook for org '%s' returned invalid decision '%s' — default-deny",
        org_id, decision,
    )
    decision = "deny"
reason = str(data.get("reason", ""))[:512]  # limit reason length
```

---

## Timeout, retry e fallback

### Timeout: 5 secondi

Il broker aspetta al massimo 5 secondi per la risposta del PDP:

```python
# Da: app/policy/webhook.py (riga 44)

_WEBHOOK_TIMEOUT = 5.0  # seconds
```

**Analogia:** E' come la telefonata alla mamma. Se non risponde dopo 5 squilli, riattacchi e la cena non si fa. Non stai li' ad aspettare mezz'ora.

Se il PDP non risponde in tempo, il risultato e' DENY:

```python
# Da: app/policy/webhook.py (riga 263-269)

except httpx.TimeoutException:
    _log.warning("PDP webhook timeout for org '%s' — default-deny", org_id)
    return WebhookDecision(
        allowed=False,
        reason=f"PDP webhook for '{org_id}' timed out after {_WEBHOOK_TIMEOUT}s",
        org_id=org_id,
    )
```

### Nessun retry

Il broker **non ripete** la chiamata. Se il PDP e' giu', la sessione non si apre. Questo e' intenzionale:

- Un retry potrebbe ritardare la risposta all'agente
- Se il PDP e' instabile, meglio non aprire sessioni
- L'org puo' (e deve) configurare alta disponibilita' sul proprio PDP

### Fallback: default-deny su qualsiasi errore

Ecco **tutti** i casi e il loro risultato:

```
  ┌─────────────────────────────────┬─────────────┐
  │  Situazione                     │  Risultato  │
  ├─────────────────────────────────┼─────────────┤
  │  Nessun webhook URL configurato │  DENY       │
  │  URL non risolvibile (DNS)      │  DENY       │
  │  URL punta a IP privato (SSRF)  │  DENY       │
  │  Timeout (> 5 secondi)          │  DENY       │
  │  HTTP status != 200             │  DENY       │
  │  Risposta > 4096 bytes          │  DENY       │
  │  JSON invalido                  │  DENY       │
  │  decision != "allow"/"deny"     │  DENY       │
  │  Qualsiasi eccezione            │  DENY       │
  │  decision == "deny"             │  DENY       │
  │  decision == "allow"            │  ALLOW      │
  └─────────────────────────────────┴─────────────┘
```

Un **solo** caso produce ALLOW. Tutti gli altri producono DENY. Questo e' il default-deny in azione.

---

## Protezione anti-SSRF — tre livelli di difesa

Il PDP webhook URL e' registrato dall'organizzazione. Un attaccante potrebbe registrare un URL come `http://169.254.169.254/latest/meta-data/` (l'endpoint dei metadata AWS) per rubare credenziali cloud. Questo attacco si chiama **SSRF** (Server-Side Request Forgery).

Cullis ha **tre livelli** di protezione:

### Livello 1: Validazione pre-request

Prima di fare la chiamata HTTP, il broker risolve il DNS e controlla tutti gli IP risultanti:

```python
# Da: app/policy/webhook.py (riga 70-102)

def _validate_and_resolve_webhook_url(url: str) -> str:
    # Blocca hostname interni noti
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"Webhook URL points to loopback address")

    # Risolvi DNS e controlla tutti gli IP risultanti
    addr_infos = socket.getaddrinfo(hostname, ...)
    for ... in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(f"Webhook URL resolves to private/reserved IP")
```

### Livello 2: DNS pinning (anti-rebinding)

Un attacco DNS rebinding funziona cosi': al momento della validazione il dominio risolve a un IP pubblico (passa il check), ma al momento della richiesta HTTP risolve a un IP privato (attacco riuscito).

Cullis previene questo con il **DNS pinning**: risolve l'IP una volta e forza la connessione a quell'IP specifico:

```python
# Da: app/policy/webhook.py (riga 105-130)

class _PinnedDNSBackend(httpcore.AsyncNetworkBackend):
    """Network backend that pins DNS resolution to a pre-resolved IP."""

    async def connect_tcp(self, host, port, ...):
        # Connette all'IP pinnato invece di risolvere di nuovo il DNS
        return await self._backend.connect_tcp(
            self._pinned_ip, port, ...
        )
```

```
  SENZA DNS PINNING              CON DNS PINNING
  -----------------              -----------------
  1. Valida: evil.com            1. Valida: evil.com
     --> 1.2.3.4 (pubblico)         --> 1.2.3.4 (pubblico)
                                     --> PINNO 1.2.3.4
  2. Connetti: evil.com          2. Connetti: 1.2.3.4
     --> 10.0.0.1 (privato!)        --> 1.2.3.4 (pinnato)
     ATTACCO RIUSCITO               ATTACCO BLOCCATO
```

**Analogia:** E' come segnarsi il numero di targa di un taxi prima di salire. Se quando arrivi il taxi ha una targa diversa, non sali — qualcuno lo ha sostituito.

### Livello 3: Validazione post-request

Anche dopo aver ricevuto la risposta, il broker controlla da quale IP e' arrivata:

```python
# Da: app/policy/webhook.py (riga 48-67)

def _validate_response_ip(resp: httpx.Response) -> None:
    """Post-request SSRF check: verify that the server IP
    is not private/loopback."""
    network_stream = resp.extensions.get("network_stream")
    if network_stream is not None:
        server_addr = network_stream.get_extra_info("server_addr")
        if server_addr:
            ip = ipaddress.ip_address(server_addr[0])
            if ip.is_private or ip.is_loopback:
                raise ValueError(f"Response came from private IP: {ip}")
```

Tre livelli di difesa perche' nessun singolo controllo e' infallibile. Belt and suspenders — cintura e bretelle.

---

## Limite dimensione risposta

Per evitare che un PDP malevolo invii una risposta enorme e causi un esaurimento di memoria:

```python
# Da: app/policy/webhook.py (riga 44-45)

_WEBHOOK_TIMEOUT = 5.0   # seconds
_MAX_RESPONSE_BODY = 4096  # bytes
```

```python
# Da: app/policy/webhook.py (riga 228-237)

if len(resp.content) > _MAX_RESPONSE_BODY:
    _log.warning(
        "PDP webhook response too large for org '%s' (%d bytes) — default-deny",
        org_id, len(resp.content),
    )
    return WebhookDecision(
        allowed=False,
        reason=f"PDP webhook response too large ({len(resp.content)} bytes)",
        org_id=org_id,
    )
```

4 KB sono piu' che sufficienti per `{"decision":"allow"}`. Se la risposta e' piu' grande, c'e' qualcosa che non va.

---

## Il template PDP nell'enterprise-kit

Il progetto include un **PDP server pronto all'uso** in `enterprise-kit/pdp-template/`. E' un punto di partenza che puoi personalizzare per la tua organizzazione.

### Struttura dei file

```
enterprise-kit/pdp-template/
├── pdp_server.py            <-- server FastAPI con le regole
├── rules.json               <-- configurazione delle regole
├── Dockerfile               <-- per containerizzare
└── docker-compose.opa.yml   <-- setup con OPA sidecar
```

### Il server PDP

Il cuore e' la funzione `evaluate()` che controlla le regole una per una:

```python
# Da: enterprise-kit/pdp-template/pdp_server.py (riga 73-108)

def evaluate(body: dict, rules: dict) -> tuple[str, str]:
    """Valuta una richiesta di sessione contro le regole locali."""

    # Regola 1: agenti bloccati
    if initiator_agent in rules["blocked_agents"]:
        return "deny", f"Agent {initiator_agent} is blocked"

    # Regola 2: whitelist org initiator (quando siamo target)
    if context == "target" and rules["allowed_initiator_orgs"]:
        if initiator_org not in rules["allowed_initiator_orgs"]:
            return "deny", f"Org {initiator_org} not in allowed list"

    # Regola 3: whitelist org target (quando siamo initiator)
    if context == "initiator" and rules["allowed_target_orgs"]:
        if target_org not in rules["allowed_target_orgs"]:
            return "deny", f"Org {target_org} not in allowed list"

    # Regola 4: capability permesse
    if rules["allowed_capabilities"]:
        blocked = [c for c in capabilities
                   if c not in rules["allowed_capabilities"]]
        if blocked:
            return "deny", f"Capabilities not allowed: {blocked}"

    return "allow", ""
```

L'endpoint esposto e' `POST /policy`:

```python
# Da: enterprise-kit/pdp-template/pdp_server.py (riga 139-161)

@app.post("/policy")
async def policy_decision(request: Request):
    body = await request.json()

    # Forward to OPA if configured, otherwise use local rules
    if opa_url:
        decision, reason = await _forward_to_opa(opa_url, body)
    else:
        decision, reason = evaluate(body, rules)

    resp: dict = {"decision": decision}
    if reason:
        resp["reason"] = reason
    return JSONResponse(resp)
```

### Il file rules.json

```json
{
  "allowed_initiator_orgs": ["partner-org", "supplier-org"],
  "allowed_target_orgs": ["partner-org", "supplier-org"],
  "allowed_capabilities": ["order.read", "order.write", "inventory.check"],
  "blocked_agents": [],
  "max_sessions_per_org": 0
}
```

| Campo                    | Descrizione                              | Default     |
|--------------------------|------------------------------------------|-------------|
| `allowed_initiator_orgs` | Chi puo' contattarci (vuoto = tutti)     | `[]`        |
| `allowed_target_orgs`    | Chi possiamo contattare (vuoto = tutti)  | `[]`        |
| `allowed_capabilities`   | Capability permesse (vuoto = tutte)      | `[]`        |
| `blocked_agents`         | Agenti bloccati (es. incident response)  | `[]`        |
| `max_sessions_per_org`   | Limite sessioni per org (0 = illimitato) | `0`         |

### Il Dockerfile

```dockerfile
# enterprise-kit/pdp-template/Dockerfile

FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY pdp_server.py .
COPY rules.json .
EXPOSE 9000
CMD ["python", "pdp_server.py", "--port", "9000", "--config", "rules.json"]
```

Minimale: solo FastAPI e uvicorn. Il PDP e' pensato per essere leggero.

### Avvio rapido

```bash
# Standalone (senza Docker)
cd enterprise-kit/pdp-template
python pdp_server.py --port 9000 --config rules.json

# Con Docker
docker build -t my-pdp .
docker run -p 9000:9000 my-pdp

# Con OPA sidecar
docker compose -f docker-compose.opa.yml up
```

---

## Costruire un PDP personalizzato

Il template e' un punto di partenza. In produzione vorrai integrare con i tuoi sistemi interni. Ecco come.

### Passo 1: Implementa l'endpoint

Il tuo PDP deve esporre un endpoint POST che:

1. Accetta il payload JSON descritto sopra (6 campi)
2. Risponde con `{"decision": "allow"}` o `{"decision": "deny", "reason": "..."}`
3. Risponde entro 5 secondi
4. Risponde sempre con HTTP 200 (anche per i deny — il broker tratta qualsiasi altro status come deny)

```python
# Esempio minimo in Flask
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/policy")
def policy():
    body = request.json
    org = body["initiator_org_id"]
    context = body["session_context"]

    # Integra con il tuo sistema di autorizzazione
    if context == "target":
        allowed = check_ldap(org)
    else:
        allowed = check_whitelist(org)

    if allowed:
        return jsonify({"decision": "allow"})
    return jsonify({"decision": "deny", "reason": f"org {org} not authorized"})
```

### Passo 2: Registra il webhook nel broker

Quando la tua organizzazione fa onboarding su Cullis, registra l'URL del PDP. Il broker lo usera' per ogni richiesta di sessione che coinvolge la tua org.

### Passo 3: Idee per logiche personalizzate

```
  ┌────────────────────────────────────────────────────────┐
  │  COSA PUOI FARE NEL TUO PDP                           │
  ├────────────────────────────────────────────────────────┤
  │  - Verificare l'agente contro LDAP/Active Directory    │
  │  - Controllare orari lavorativi (no sessioni di notte) │
  │  - Rate limiting per org o per agente                  │
  │  - Geofencing (blocca richieste da certi paesi)        │
  │  - Compliance check (no cross-border per dati GDPR)    │
  │  - Approvazione manuale per capability sensibili       │
  │  - Integrazione con SIEM per incident response         │
  │  - A/B testing di policy (canary deployment)           │
  └────────────────────────────────────────────────────────┘
```

**Analogia:** Il PDP e' come il portiere del tuo palazzo. Puoi istruirlo come vuoi: "non far entrare nessuno dopo le 22", "i corrieri solo con preavviso", "il signor Rossi mai piu'". Le istruzioni sono tue e solo tue.

### Passo 4: Modalita' ibrida (PDP + OPA)

Il PDP template puo' funzionare come **proxy verso OPA**: gestisce la logica semplice localmente e inoltra le decisioni complesse a OPA:

```bash
python pdp_server.py --port 9000 --opa-url http://opa:8181
```

In questa modalita', il PDP riceve la richiesta dal broker, la inoltra a OPA, e restituisce la risposta di OPA al broker. Il meglio di entrambi i mondi: la flessibilita' di un webhook con la potenza di Rego.

---

## Checklist per un PDP production-ready

```
  [ ] Risponde sempre entro 5 secondi (anche in caso di errore interno)
  [ ] Risponde sempre con HTTP 200 (il broker tratta !200 come deny)
  [ ] Ha un health check endpoint (GET /health)
  [ ] Logga ogni decisione per audit
  [ ] Ha alta disponibilita' (se il PDP e' giu', nessuna sessione si apre)
  [ ] Le regole sono versionabili (git, database, config management)
  [ ] Non espone endpoint su IP privati del broker (SSRF protection)
  [ ] La risposta JSON e' < 4096 bytes
  [ ] Il campo "decision" e' esattamente "allow" o "deny" (lowercase)
  [ ] Il campo "reason" e' < 512 caratteri
```

---

## Riepilogo — cosa portarti a casa

- **Il PDP webhook e' il portiere della tua organizzazione**: il broker chiama il tuo URL per ogni sessione, e tu decidi se autorizzare o rifiutare
- **Payload semplice**: 6 campi in input, 2 campi in output. Facile da implementare in qualsiasi linguaggio
- **`session_context`** ti dice se la tua org e' initiator o target, permettendo regole diverse per ruolo
- **Default-deny totale**: timeout, errori, HTTP non-200, JSON invalido, webhook non configurato — tutto produce DENY
- **5 secondi di timeout**, nessun retry. Se il PDP e' giu', nessuna sessione si apre. Alta disponibilita' e' responsabilita' dell'org
- **Protezione anti-SSRF a tre livelli**: validazione URL pre-request, DNS pinning anti-rebinding, validazione IP post-request
- **Template pronto all'uso** in `enterprise-kit/pdp-template/` — personalizzabile con rules.json o integrabile con OPA
- **Il PDP e' sotto il tuo controllo**: puoi integrare LDAP, SIEM, geofencing, compliance — qualsiasi logica di business della tua organizzazione

---

*Prossimo capitolo: [20 — ...](20-placeholder.md)*
