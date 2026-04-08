# Capitolo 33 — MCP Proxy — Enterprise Gateway

> *"Non tutti devono sapere guidare un camion per mandare un pacco — basta portarlo all'ufficio spedizioni."*

---

## A cosa serve il Proxy — spiegazione da bar

Immagina un'azienda con 50 dipendenti che devono spedire pacchi all'estero. Due opzioni:

1. **Ogni dipendente** impara le regole doganali, compila la documentazione, porta il pacco in aeroporto, paga il cargo... per ognuno dei 50.
2. **L'azienda apre un ufficio spedizioni interno.** I dipendenti portano il pacco li', l'ufficio si occupa di tutto: documentazione, dogana, tracking.

L'MCP Proxy e' l'ufficio spedizioni. Gli agenti AI interni dell'organizzazione parlano col proxy usando una semplice **API key**, e il proxy gestisce tutta la complessita': certificati x509, DPoP, crittografia E2E, registrazione sul broker.

```
┌─────────────────────────────────────────────────────────────┐
│                    ORGANIZZAZIONE                           │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Agent A  │  │ Agent B  │  │ Agent C  │   agenti interni │
│  │ API key  │  │ API key  │  │ API key  │   (no crypto)    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
│       │              │              │                        │
│       └──────────────┼──────────────┘                        │
│                      │                                       │
│              ┌───────▼────────┐                              │
│              │   MCP PROXY    │  ← gestisce x509, DPoP, E2E │
│              │   porta 9100   │                              │
│              └───────┬────────┘                              │
│                      │                                       │
└──────────────────────┼───────────────────────────────────────┘
                       │ HTTPS
               ┌───────▼────────┐
               │  CULLIS BROKER │
               │   (esterno)    │
               └────────────────┘
```

**Senza il proxy:** ogni agente interno deve avere il proprio certificato x509, la propria chiave privata, gestire DPoP, fare login al broker...

**Con il proxy:** ogni agente interno ha una API key — il proxy fa tutto il resto.

---

## Auto-PKI: niente piu' openssl manuali

Una delle barriere piu' grandi nell'adozione di Cullis e' la **PKI** (Public Key Infrastructure): generare CA, firmare certificati, distribuire chiavi private... Roba da sysadmin senior.

Il proxy risolve questo con **Auto-PKI**: genera automaticamente tutto.

```
Dashboard: "Crea nuovo agente"
  │
  ├─ 1. Genera chiave RSA-2048 per l'agente
  │
  ├─ 2. Crea certificato x509:
  │     CN: "myorg::sales"
  │     O:  "myorg"
  │     SAN: spiffe://atn.local/myorg/sales
  │     Firmato dalla CA dell'organizzazione
  │     Validita': 365 giorni
  │
  ├─ 3. Salva chiave privata in Vault (o DB come fallback)
  │
  ├─ 4. Genera API key: sk_local_sales_a1b2c3d4
  │     (mostrata UNA VOLTA — poi solo l'hash bcrypt e' salvato)
  │
  ├─ 5. Registra l'agente sul broker (best-effort)
  │
  └─ 6. Login al broker per "pinnare" il certificato
```

**Analogia:** E' come un'azienda che ha il proprio ufficio badges. Quando un nuovo dipendente entra, l'HR gli crea il badge (certificato), lo registra nel sistema (broker), e gli da' il codice del badge (API key). Il dipendente non deve sapere come funziona il sistema di sicurezza — ha il suo badge e basta.

> **In Cullis:** guarda `mcp_proxy/egress/agent_manager.py` — la classe `AgentManager` con `create_agent()` e `_generate_agent_cert()`.

---

## Autenticazione API Key: semplice dentro, sicura fuori

Il proxy ha due "facce" di autenticazione:

### Lato interno (agenti → proxy): API Key

```
Agent interno                          MCP Proxy
  │                                      │
  │── POST /v1/egress/sessions ─────────▶│
  │   Header: X-API-Key: sk_local_...    │
  │                                      │
  │   Il proxy:                          │
  │   1. Prende la API key               │
  │   2. Cerca tra gli hash bcrypt       │
  │      degli agenti attivi             │
  │   3. Se match → identifica agente    │
  │   4. Se no match → 401              │
```

Le API key hanno il formato `sk_local_{name}_{hex}` e sono hashate con **bcrypt** nel database — se qualcuno accede al DB, non puo' ricostruire le chiavi.

### Lato esterno (proxy → broker): x509 + DPoP

```
MCP Proxy                              Cullis Broker
  │                                      │
  │── client_assertion JWT ─────────────▶│
  │   (cert x509 dell'agente)            │
  │   DPoP proof (EC P-256)              │
  │                                      │
  │◀── access_token ────────────────────│
  │                                      │
  │── richiesta + DPoP proof ──────────▶│
```

**Analogia:** Dentro l'azienda entri con il badge (API key). Fuori dall'azienda, l'ufficio spedizioni usa il passaporto diplomatico (x509 + DPoP). Tu non vedi il passaporto — l'ufficio lo gestisce per te.

> **In Cullis:** guarda `mcp_proxy/auth/api_key.py` per la verifica API key e `mcp_proxy/egress/broker_bridge.py` per l'autenticazione verso il broker.

---

## Il BrokerBridge: un client per agente

Il cuore dell'egress e' il `BrokerBridge` — mantiene un `CullisClient` autenticato per ogni agente interno.

```
┌──────────────────────────────────────────┐
│             BrokerBridge                 │
│                                          │
│  _clients: {                             │
│    "myorg::buyer":  CullisClient (auth)  │
│    "myorg::sales":  CullisClient (auth)  │
│    "myorg::support": CullisClient (auth) │
│  }                                       │
│                                          │
│  Lazy init:                              │
│  - Primo accesso → crea client + login   │
│  - Accessi successivi → usa cache        │
│  - Errore auth → evict + retry           │
└──────────────────────────────────────────┘
```

Quando un agente interno fa una richiesta:

1. Il proxy verifica la API key e identifica l'agente
2. Chiede al BrokerBridge un `CullisClient` per quell'agente
3. Se non esiste, ne crea uno e fa login con cert+key (da Vault o DB)
4. Usa il client per la richiesta al broker
5. Se il login e' scaduto, il bridge fa automaticamente evict + re-login

```python
async def get_client(self, agent_id: str) -> CullisClient:
    if agent_id in self._clients:
        return self._clients[agent_id]  # cache hit
    # cache miss → crea e autentica
    client = await self._create_client(agent_id)
    self._clients[agent_id] = client
    return client
```

> **In Cullis:** guarda `mcp_proxy/egress/broker_bridge.py`.

---

## Dashboard: gestione visuale

Il proxy include una **dashboard web** su porta 9100 per gestire tutto senza usare la CLI:

```
Dashboard (porta 9100)
  │
  ├── Setup Wizard
  │   └── Configura broker_url, org_id, genera CA
  │
  ├── Agents
  │   ├── Crea agente (nome, display_name, capabilities)
  │   ├── Lista agenti attivi/disattivati
  │   ├── Ruota API key
  │   └── Disattiva agente
  │
  ├── Sessions
  │   └── Vedi sessioni broker per ogni agente
  │
  ├── Policies
  │   ├── Agenti bloccati
  │   ├── Organizzazioni permesse
  │   └── Capability consentite
  │
  ├── PKI
  │   ├── CA dell'organizzazione
  │   └── Certificati agenti
  │
  └── Audit Log
      └── Log immutabile di tutte le operazioni
```

La dashboard e' autenticata con `admin_secret` (configurato in `proxy.env`).

---

## Il flusso completo: dall'invite token all'operativita'

```
1. INVITE TOKEN
   L'admin della rete Cullis genera un invite token
   e lo manda all'organizzazione che vuole unirsi.

2. SETUP WIZARD
   L'admin dell'org apre la dashboard e inserisce:
   - broker_url
   - org_id
   - invite_token
   - org_secret
   Il proxy:
   - Genera CA dell'organizzazione (auto-PKI)
   - Chiama /v1/onboarding/join sul broker
   - Salva configurazione nel DB

3. APPROVAZIONE
   L'admin della rete approva la richiesta.
   L'organizzazione e' ora parte della rete.

4. CREAZIONE AGENTI
   L'admin dell'org crea agenti via dashboard:
   - "sales" con capability ["quote", "order.write"]
   - "support" con capability ["ticket.read"]
   Per ogni agente il proxy:
   - Genera cert x509 (firmato dalla CA org)
   - Salva key in Vault
   - Genera API key
   - Registra sul broker

5. OPERATIVITA'
   Gli agenti interni usano le API key:
   POST /v1/egress/discover  (cerca agenti)
   POST /v1/egress/sessions  (apri sessione)
   POST /v1/egress/send      (manda messaggio E2E)
   GET  /v1/egress/messages   (ricevi messaggi)
```

**Analogia:** E' come aprire una filiale all'estero. L'headquarter (admin rete) ti da' il permesso (invite token). Tu apri l'ufficio (setup wizard), assumi dipendenti (crea agenti), e inizi a lavorare. I dipendenti non devono sapere come funziona il visto di lavoro — ci pensa l'ufficio personale (proxy).

---

## Ingress vs Egress: due direzioni, due porte

Il proxy gestisce traffico in **due direzioni**:

```
                    INGRESS                         EGRESS
              (dall'esterno verso                (dall'interno verso
               gli agenti interni)               il mondo esterno)

  Broker                                    Agente interno
    │                                           │
    │── JWT + DPoP ──▶ ┌──────────┐             │
    │                  │          │ ◀── API key ─│
    │                  │  PROXY   │              │
    │   Verifica:      │          │  Verifica:   │
    │   - JWT valido   │          │  - API key   │
    │   - DPoP proof   │ ingress  │    bcrypt    │
    │   - JWKS broker  │  ┌──┐   │              │
    │   - Capability   │  │  │   │  egress      │
    │     check        │  │DB│   │  ┌──┐        │
    │                  │  │  │   │  │  │        │
    │                  │  └──┘   │  └──┘        │
    │                  │          │              │
    │◀── risultato ───│          │── risultato ▶│
    │                  └──────────┘              │
```

### Ingress: /v1/ingress/*

- **Chi chiama:** il broker (agenti remoti via broker)
- **Auth:** JWT emesso dal broker + DPoP proof
- **Validazione:** JWKS del broker (chiavi pubbliche per verificare i JWT)
- **Cosa fa:** esegue tool registrati nel proxy (definiti in `tools.yaml`)
- **Capability check:** il tool richiede una capability, il JWT ha uno scope — se non matcha, 403

### Egress: /v1/egress/*

- **Chi chiama:** agenti interni dell'organizzazione
- **Auth:** API key nell'header `X-API-Key`
- **Cosa fa:** proxifica le richieste verso il broker, gestendo tutta la crypto
- **Endpoint:** sessions, send, messages, discover, tools/invoke

```
Ingress endpoints:
  POST /v1/ingress/execute   ← esegui tool con JWT + DPoP
  GET  /v1/ingress/tools     ← lista tool disponibili

Egress endpoints:
  POST /v1/egress/sessions           ← apri sessione
  GET  /v1/egress/sessions           ← lista sessioni
  POST /v1/egress/sessions/{id}/accept
  POST /v1/egress/sessions/{id}/close
  POST /v1/egress/send               ← manda messaggio E2E
  GET  /v1/egress/messages/{id}      ← ricevi messaggi
  POST /v1/egress/discover           ← cerca agenti
  POST /v1/egress/tools/invoke       ← invoca tool remoto
```

> **In Cullis:** guarda `mcp_proxy/ingress/router.py` e `mcp_proxy/egress/router.py`.

---

## PDP Built-in: policy senza server esterno

Il proxy include un **PDP (Policy Decision Point) integrato** su `/pdp/policy`. Il broker chiama questo endpoint ogni volta che un agente dell'organizzazione e' coinvolto in una richiesta di sessione.

```python
# Le regole vengono dalla dashboard (tabella proxy_config)
rules = {
    "blocked_agents": ["evil::hacker"],        # agenti bloccati
    "allowed_orgs": ["acme", "chipfactory"],   # org permesse
    "capabilities": ["quote", "order.write"],  # capability consentite
}
```

Logica di valutazione:
- **Nessuna regola configurata** = allow all (default permissivo)
- **blocked_agents**: se l'agente e' nella lista → deny
- **allowed_orgs**: se l'org del peer non e' nella lista → deny
- **capabilities**: se le capability richieste non sono consentite → deny

> **In Cullis:** guarda il metodo `pdp_policy()` in `mcp_proxy/main.py`.

---

## Database: SQLite minimale

Il proxy usa **SQLite con WAL mode** — nessun server database da gestire:

```
┌─────────────────────────────────────────────┐
│              mcp_proxy.db (SQLite)           │
│                                              │
│  internal_agents                             │
│  ├── agent_id (PK)                           │
│  ├── display_name                            │
│  ├── capabilities (JSON array)               │
│  ├── api_key_hash (bcrypt)                   │
│  ├── cert_pem                                │
│  ├── is_active                               │
│  └── created_at                              │
│                                              │
│  audit_log (APPEND-ONLY)                     │
│  ├── id, timestamp, agent_id, action         │
│  ├── tool_name, status, detail               │
│  └── request_id, duration_ms                 │
│                                              │
│  proxy_config (key-value)                    │
│  ├── broker_url                              │
│  ├── org_id, org_secret                      │
│  ├── org_ca_key, org_ca_cert                 │
│  └── agent_key:{agent_id} (fallback Vault)   │
└─────────────────────────────────────────────┘
```

**L'audit log e' append-only** — nessuna operazione UPDATE o DELETE e' esposta. Se qualcuno compromette il proxy, non puo' cancellare le tracce.

> **In Cullis:** guarda `mcp_proxy/db.py` per schema e operazioni.

---

## Configurazione: proxy.env

Tutte le impostazioni sono variabili d'ambiente con prefisso `MCP_PROXY_`:

```bash
# proxy.env

# Broker connection
MCP_PROXY_BROKER_URL=https://broker.cullis.tech
MCP_PROXY_ORG_ID=myorg
MCP_PROXY_BROKER_JWKS_URL=https://broker.cullis.tech/.well-known/jwks.json

# Security
MCP_PROXY_ADMIN_SECRET=un-segreto-molto-lungo-e-casuale
MCP_PROXY_ENVIRONMENT=production  # "production" attiva check obbligatori

# Vault (opzionale)
MCP_PROXY_SECRET_BACKEND=vault
MCP_PROXY_VAULT_ADDR=https://vault.internal:8200
MCP_PROXY_VAULT_TOKEN=hvs.your-token

# Network
MCP_PROXY_HOST=0.0.0.0
MCP_PROXY_PORT=9100
MCP_PROXY_ALLOWED_ORIGINS=https://dashboard.myorg.com
```

In modalita' **production**, il proxy rifiuta di partire se:
- `ADMIN_SECRET` e' ancora il default `change-me-in-production`
- `BROKER_JWKS_URL` e' vuoto
- `BROKER_JWKS_URL` usa HTTP invece di HTTPS

> **In Cullis:** guarda `mcp_proxy/config.py` per `ProxySettings` e `validate_config()`.

---

## Health check e readiness

Il proxy espone tre endpoint per orchestratori (Kubernetes, Docker Compose):

| Endpoint | Cosa verifica | Uso |
|----------|--------------|-----|
| `GET /health` | Processo vivo | Liveness probe |
| `GET /healthz` | Processo vivo | Alias liveness |
| `GET /readyz` | DB scrivibile + JWKS cache fresca | Readiness probe |

Il readiness check fallisce (503) se il database non e' scrivibile o se la cache JWKS e' troppo vecchia — l'orchestratore non mandera' traffico a un'istanza non pronta.

---

## Riepilogo — cosa portarti a casa

- **Il proxy e' l'ufficio spedizioni** dell'organizzazione: semplifica l'adozione di Cullis da "ogni agente gestisce crypto" a "ogni agente ha una API key"
- **Auto-PKI**: genera CA org, certificati agenti, chiavi RSA — zero `openssl` manuali
- **API key interne** (bcrypt hash) + **x509/DPoP esterno** — due livelli di auth
- **BrokerBridge**: mantiene un `CullisClient` autenticato per ogni agente, con lazy init e auto re-login
- **Ingress** (broker → proxy): JWT + DPoP, tool execution, capability check
- **Egress** (agenti → proxy → broker): API key, sessioni, messaggi E2E, discover
- **PDP integrato**: policy configurabili da dashboard, default allow
- **SQLite + WAL**: nessun server database, audit log append-only
- **Dashboard web** per gestire tutto visualmente: agenti, PKI, policy, audit
- **Startup validation** in production: rifiuta configurazioni insicure

---

*Capitolo precedente: [32 — TypeScript SDK](32-typescript-sdk.md)*
