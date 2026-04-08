# Capitolo 30 — Python SDK (cullis-agent-sdk)

> *"Un buon SDK e' come un coltellino svizzero: tanti strumenti, un solo oggetto in tasca."*

---

## A cosa serve l'SDK — spiegazione da bar

Immagina di dover spedire un pacco in un altro paese. Potresti:

1. Andare all'ufficio doganale, compilare la dichiarazione, portare il pacco all'aeroporto, pagare il cargo, tracciare la spedizione, gestire la ricevuta di ritorno...
2. Oppure andare alle Poste, dare il pacco allo sportello e dire "spedisci".

L'SDK e' lo sportello delle Poste. Tu dici "manda questo messaggio a quell'agente" e lui si occupa di certificati x509, token DPoP, crittografia end-to-end, firme digitali, retry automatici... tutto sotto il cofano.

---

## Architettura: CullisClient come punto unico

L'intera SDK ruota attorno a una singola classe: `CullisClient`. Tutto passa da li'.

```
┌─────────────────────────────────────────────────────┐
│                   CullisClient                      │
│                                                     │
│  ┌─────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │  Auth   │  │ Sessions │  │    Messaging       │  │
│  │ login() │  │ open()   │  │ send()  poll()     │  │
│  │ DPoP    │  │ accept() │  │ decrypt_payload()  │  │
│  │ x509    │  │ close()  │  │ E2E encrypt/sign   │  │
│  └────┬────┘  └────┬─────┘  └────────┬───────────┘  │
│       │            │                 │              │
│  ┌────▼────────────▼─────────────────▼───────────┐  │
│  │              _authed_request()                │  │
│  │   Authorization: DPoP + nonce retry           │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │                              │
│  ┌───────────────────▼───────────────────────────┐  │
│  │              httpx.Client                     │  │
│  │   HTTP/2, TLS, timeout, connection pooling    │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Analogia:** `CullisClient` e' come il cruscotto di un'auto. Tu tocchi il volante, i pedali e il cambio — ma sotto ci sono motore, trasmissione, freni, ABS, tutti coordinati senza che tu debba pensarci.

> **In Cullis:** guarda `cullis_sdk/client.py` — la classe `CullisClient` con tutti i metodi pubblici.

---

## Autenticazione: x509 + DPoP, tutto gestito internamente

Quando chiami `client.login()`, succedono almeno 5 cose sotto il cofano:

```python
from cullis_sdk import CullisClient

client = CullisClient("https://broker.example.com")
client.login("acme::buyer", "acme", "cert.pem", "key.pem")
```

Ecco cosa fa `login()` internamente:

```
login("acme::buyer", "acme", "cert.pem", "key.pem")
  │
  ├─ 1. Legge cert.pem e key.pem da disco
  │
  ├─ 2. Costruisce un client_assertion JWT:
  │     - sub/iss: "acme::buyer"
  │     - aud: "agent-trust-broker"
  │     - header x5c: certificato DER in base64
  │     - firmato con la chiave privata dell'agente
  │
  ├─ 3. Genera coppia di chiavi EC P-256 efimera per DPoP
  │     (nuova ogni sessione, non salvata)
  │
  ├─ 4. Costruisce DPoP proof JWT (RFC 9449):
  │     - htm: POST, htu: token_url
  │     - header jwk: chiave pubblica efimera
  │
  ├─ 5. POST /v1/auth/token con assertion + DPoP
  │     ← se 401 "use_dpop_nonce": salva nonce, riprova
  │
  └─ 6. Salva access_token per le richieste successive
```

**Analogia:** E' come fare il check-in in aeroporto. Tu mostri il passaporto (x509), ti danno la carta d'imbarco (JWT token), e la carta ha il tuo nome e la tua foto stampati sopra (DPoP binding) — se qualcuno la ruba, non puo' usarla perche' non ha la tua faccia.

C'e' anche `login_from_pem()` per ambienti enterprise dove i certificati vengono da un secret manager (Vault, AWS KMS) invece che da file su disco:

```python
# Da Vault o secret manager — niente file su disco
client.login_from_pem("acme::buyer", "acme", cert_pem_string, key_pem_string)
```

> **In Cullis:** guarda `cullis_sdk/auth.py` per `build_client_assertion()`, `generate_dpop_keypair()` e `build_dpop_proof()`.

---

## I metodi principali

### Discovery — trovare agenti nella rete

```python
# Cerca agenti con una capability specifica
agents = client.discover(capabilities=["order.write"])

# Cerca per organizzazione
agents = client.discover(org_id="chipfactory")

# Cerca per pattern sull'agent_id
agents = client.discover(pattern="chipfactory::*")

# Ricerca full-text
agents = client.discover(q="manufacturing chips")
```

Ogni risultato e' un oggetto `AgentInfo` con `agent_id`, `org_id`, `display_name`, `capabilities`.

**Analogia:** E' come cercare un idraulico sulle Pagine Gialle — puoi cercare per specializzazione, per zona, o per nome.

### Sessioni — il ciclo di vita completo

```
Buyer                    Broker                   Supplier
  │                        │                         │
  │── open_session() ─────▶│                         │
  │                        │── notifica "pending" ──▶│
  │                        │                         │
  │                        │◀── accept_session() ────│
  │◀── "active" ───────────│                         │
  │                        │                         │
  │══ send()/poll() ══════▶│◀════════════════════════│
  │    (messaggi E2E)      │    (messaggi E2E)       │
  │                        │                         │
  │── close_session() ────▶│                         │
```

```python
# Apri sessione (richiede approvazione da entrambe le org)
session_id = client.open_session(
    target_agent_id="chipfactory::sales",
    target_org_id="chipfactory",
    capabilities=["order.write"],
)

# L'altro agente accetta
client.accept_session(session_id)

# Lista sessioni attive
sessions = client.list_sessions(status="active")

# Chiudi quando hai finito
client.close_session(session_id)
```

### Messaggi — invio E2E crittografato

```python
client.send(
    session_id=session_id,
    sender_agent_id="acme::buyer",
    payload={"type": "order", "item": "GPU-A100", "qty": 1000},
    recipient_agent_id="chipfactory::sales",
)
```

Un singolo `send()` fa internamente 6 operazioni:

1. **Inner signature** — firma il plaintext con RSA-PSS (non-repudiazione)
2. **Fetch recipient pubkey** — scarica la chiave pubblica del destinatario (con cache TTL 5min)
3. **Encrypt** — AES-256-GCM per i dati, RSA-OAEP per la chiave AES
4. **Outer signature** — firma il ciphertext (integrita' per il broker)
5. **Build envelope** — assembla session_id, nonce, timestamp, client_seq
6. **POST con retry** — 3 tentativi con backoff in caso di errore di rete

```python
# Ricevi messaggi (decrittazione automatica)
messages = client.poll(session_id, after=-1)
for msg in messages:
    print(f"{msg.sender_agent_id}: {msg.payload}")
```

### RFQ — Request For Quote

```python
# Broadcast: "chi puo' vendermi 1000 GPU?"
rfq = client.create_rfq(
    capability_filter=["gpu.supply"],
    payload={"item": "A100", "quantity": 1000},
    timeout_seconds=30,
)

# L'altro agente risponde con un preventivo
client.respond_to_rfq(rfq.rfq_id, {"price_per_unit": 850, "delivery_days": 14})

# Raccogli i preventivi
result = client.get_rfq(rfq.rfq_id)
for quote in result.quotes:
    print(f"{quote.agent_id}: {quote.payload}")
```

**Analogia:** E' come mandare una richiesta di preventivo a tutti gli idraulici della zona. Loro rispondono con prezzo e tempistica, tu scegli.

### Transaction Token — operazioni critiche

```python
# Token monouso per un'operazione specifica (es. conferma ordine)
txn = client.request_transaction_token(
    txn_type="order.confirm",
    payload_hash="sha256-del-payload",
    session_id=session_id,
    counterparty_agent_id="chipfactory::sales",
    ttl_seconds=60,
)
# txn contiene un JWT monouso, legato a questa specifica operazione
```

---

## Il bundle crittografico: cullis_sdk.crypto

La directory `cullis_sdk/crypto/` contiene due moduli che fanno il lavoro sporco:

### message_signer.py — Firma dei messaggi

```
Canonical string (deterministico):
  "{session_id}|{sender}|{nonce}|{timestamp}|{client_seq}|{canonical_json(payload)}"

Firma:
  RSA-PSS-SHA256  oppure  ECDSA-SHA256  (dipende dal tipo di chiave)

Encoding:
  base64url (URL-safe, senza padding)
```

La stringa canonica e' deterministica: `sort_keys=True`, nessuno spazio, `ensure_ascii=True`. Qualsiasi modifica al payload, session_id, nonce o sender invalida la firma.

### e2e.py — Crittografia end-to-end

Schema a doppia busta:

```
┌─────────────────────────────────────────────────┐
│              BUSTA ESTERNA (ciphertext)          │
│                                                 │
│  AES-256-GCM encrypts:                          │
│  ┌──────────────────────────────────────────┐   │
│  │  BUSTA INTERNA (plaintext)               │   │
│  │  { "payload": {...}, "inner_sig": "..." } │   │
│  └──────────────────────────────────────────┘   │
│                                                 │
│  AES key wrapped con:                           │
│  - RSA-OAEP-SHA256  (per chiavi RSA)            │
│  - ECDH + HKDF       (per chiavi EC)            │
│                                                 │
│  AAD = "{session_id}|{sender}|{client_seq}"     │
│  (Additional Authenticated Data — lega il       │
│   ciphertext al contesto della sessione)        │
└─────────────────────────────────────────────────┘
```

**Perche' due firme?**

- **Inner signature** (plaintext): il destinatario puo' provare che il mittente ha firmato quel messaggio specifico (non-repudiazione legale)
- **Outer signature** (ciphertext): il broker verifica l'integrita' durante il transito, senza poter leggere il contenuto

> **In Cullis:** guarda `cullis_sdk/crypto/message_signer.py` e `cullis_sdk/crypto/e2e.py`.

---

## I tipi: cullis_sdk.types

Tutti i tipi sono dataclass stdlib — nessuna dipendenza da Pydantic:

| Tipo | Campi chiave | Uso |
|------|-------------|-----|
| `AgentInfo` | agent_id, org_id, capabilities | Risultato di `discover()` |
| `SessionInfo` | session_id, status, initiator/target | Risultato di `list_sessions()` |
| `InboxMessage` | seq, sender_agent_id, payload | Risultato di `poll()` |
| `RfqResult` | rfq_id, status, quotes | Risultato di `create_rfq()` |
| `RfqQuote` | agent_id, payload | Singolo preventivo in un RFQ |

> **In Cullis:** guarda `cullis_sdk/types.py`.

---

## Packaging: pyproject.toml + hatchling

L'SDK e' impacchettata con standard moderni (PEP 517/518):

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "cullis-agent-sdk"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "httpx>=0.24.0",           # HTTP client (HTTP/2, async-ready)
    "cryptography>=41.0.0",    # x509, RSA, EC, AES
    "PyJWT[crypto]>=2.8.0",    # JWT encode/decode
    "websockets>=12.0",        # WebSocket real-time
]
```

**Solo 4 dipendenze runtime** — niente framework pesanti, niente Pydantic, niente SQLAlchemy. L'SDK e' leggera di proposito: deve poter girare in un container minimale o in un Lambda.

**Analogia:** E' come un telefono con poche app preinstallate ma essenziali — non ti serve il bloatware, servono solo le app che funzionano bene.

Installazione:

```bash
pip install cullis-agent-sdk
# oppure da sorgente
pip install -e .
```

---

## WebSocket: eventi in tempo reale

Oltre al polling, l'SDK supporta connessioni WebSocket per ricevere eventi push:

```python
ws = client.connect_websocket()
for event in ws:
    if event["type"] == "new_message":
        msg = client.decrypt_payload(event["message"])
        print(f"Nuovo messaggio: {msg['payload']}")
    elif event["type"] == "session_pending":
        client.accept_session(event["session_id"])
ws.close()
```

La connessione WebSocket si autentica automaticamente con DPoP — tu non devi fare nulla.

---

## Esempio completo: buyer che ordina GPU

```python
from cullis_sdk import CullisClient

with CullisClient("https://broker.cullis.tech") as client:
    # 1. Login
    client.login("acme::buyer", "acme", "certs/buyer.pem", "certs/buyer-key.pem")

    # 2. Trova chi vende GPU
    suppliers = client.discover(capabilities=["gpu.supply"])
    print(f"Trovati {len(suppliers)} fornitori")

    # 3. Apri sessione col primo
    target = suppliers[0]
    sid = client.open_session(target.agent_id, target.org_id, ["gpu.supply"])

    # 4. Invia ordine (E2E crittografato)
    client.send(sid, "acme::buyer",
                {"type": "order", "item": "A100", "qty": 500},
                recipient_agent_id=target.agent_id)

    # 5. Aspetta risposta
    messages = client.poll(sid)
    for m in messages:
        print(f"{m.sender_agent_id}: {m.payload}")

    # 6. Chiudi
    client.close_session(sid)
```

---

## Riepilogo — cosa portarti a casa

- **CullisClient** e' il punto unico di accesso: login, discover, sessioni, messaggi, RFQ
- **L'autenticazione** (x509 + DPoP + nonce retry) e' completamente nascosta — tu chiami `login()` e basta
- **I messaggi sono E2E crittografati** con doppia firma (inner per non-repudiazione, outer per integrita' di trasporto)
- **Il bundle crypto** (`cullis_sdk/crypto/`) contiene `message_signer` e `e2e` — supporta sia RSA che EC
- **4 dipendenze runtime**, packaging con hatchling, Python >= 3.10
- **WebSocket** per eventi real-time, con autenticazione DPoP trasparente

---

*Prossimo capitolo: [31 — MCP — Model Context Protocol](31-mcp-protocol.md) — come dare strumenti Cullis a qualsiasi LLM*
