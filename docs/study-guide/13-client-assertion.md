# Capitolo 13 — Client Assertion (x509 + JWT)

> *"Non ti dico una password. Ti mostro il mio passaporto firmato e dimostro di possederlo."*

---

## Cos'è un Client Assertion — spiegazione da bar

Quando vai in banca, puoi identificarti in due modi:

1. **Username + password**: dici il tuo codice cliente e la tua password. La banca verifica che corrispondano a quelli nel suo database. Problema: se qualcuno vede la tua password, può entrare.

2. **Documento + firma**: mostri la carta d'identità e firmi un modulo. La banca verifica il documento con l'ente emittente e confronta la firma. Nessuna password scambiata.

Il **client assertion** è il metodo #2, in versione digitale. L'agente non manda un secret — manda un **JWT firmato con la propria chiave privata**, con il certificato allegato per la verifica.

---

## Perché non usare un semplice client_secret?

```
Metodo classico — client_secret:
  POST /oauth/token
  client_id=acme-buyer
  client_secret=sUpEr-SeCrEt-123      ← il segreto viaggia sulla rete!

Problemi:
  1. Il secret deve essere trasmesso → può essere intercettato
  2. Il secret è nel database del broker → se il DB è compromesso, tutti i secret sono esposti
  3. Per ruotare il secret, sia l'agente sia il broker devono aggiornarsi
  4. Non c'è non-repudiation — il broker ha lo stesso secret, potrebbe generare richieste false
```

```
Metodo Cullis — client_assertion:
  POST /v1/auth/token
  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
  client_assertion=eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlD...

Vantaggi:
  1. La chiave privata NON viaggia sulla rete — solo la firma e il cert pubblico
  2. Il broker non custodisce segreti — verifica il cert con la CA dell'org
  3. Rotazione: l'agente genera un nuovo cert, il broker verifica con la stessa CA
  4. Non-repudiation: solo l'agente ha la chiave privata → le firme sono dimostrabili
```

---

## Il flusso completo — dal boot al token

Ecco cosa succede quando un agente si accende e si autentica con il broker:

### Step 1: L'agente carica le sue credenziali

```python
# L'agente legge il certificato e la chiave privata
# Da file (.pem):
agent_cert = load_pem_x509_certificate(open("agent.pem").read())
agent_key = load_pem_private_key(open("agent-key.pem").read())

# Da Vault (production):
agent_cert, agent_key = vault_client.read("secret/agents/buyer")

# Da MCP Proxy (enterprise): l'agente non vede i cert!
# Usa solo un API key, il proxy gestisce tutto
```

### Step 2: L'agente costruisce il client_assertion JWT

```python
import jwt
import uuid
import time
import base64

# Codifica il certificato in base64 DER per il header x5c
cert_der = agent_cert.public_bytes(serialization.Encoding.DER)
cert_b64 = base64.b64encode(cert_der).decode()

# Header del JWT
header = {
    "alg": "RS256",             # firmato con RSA
    "typ": "JWT",
    "x5c": [cert_b64],          # catena certificati (almeno il cert dell'agente)
}

# Payload del JWT
now = int(time.time())
payload = {
    "sub": "acme::buyer",                     # chi sono (= CN del certificato)
    "iss": "acme::buyer",                     # lo emetto io stesso
    "aud": "agent-trust-broker",              # per il broker
    "exp": now + 300,                          # scade tra 5 minuti
    "iat": now,                                # emesso adesso
    "jti": str(uuid.uuid4()),                  # ID unico (anti-replay)
}

# Firma con la chiave PRIVATA dell'agente
client_assertion = jwt.encode(
    payload,
    agent_key,
    algorithm="RS256",
    headers=header,
)
```

### Step 3: L'agente invia la richiesta di autenticazione

```
POST /v1/auth/token HTTP/1.1
Host: broker:8443
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ...dpop_proof...

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlD...
```

### Step 4: Il broker verifica (i 12 step del capitolo 06)

```
Broker riceve il client_assertion:

 1. Decodifica header → estrae x5c
 2. Carica il certificato dell'agente da x5c[0]
 3. Estrae CN=acme::buyer e O=acmebuyer dal Subject
 4. Carica la CA di "acmebuyer" dal database
    → Verifica che l'org sia "active" e la CA sia configurata
 5. Verifica che la CA abbia BasicConstraints CA=true
 6. VERIFICA CRITTOGRAFICA: la firma del cert è stata fatta dalla CA
    ca_public_key.verify(agent_cert.signature, agent_cert.tbs_bytes)
 7. Controlla dimensione chiave (≥ 2048 bit RSA)
 8. Controlla validità temporale (non scaduto)
 9. Controlla revoca (serial_hex non in revoked_certs)
10. VERIFICA FIRMA JWT con la pubkey del certificato
    jwt.decode(assertion, cert_public_key, algorithms=["RS256"])
11. Controlla sub, iss, aud, exp, jti
12. Verifica SPIFFE SAN se presente
13. Consuma il jti (anti-replay)
```

### Step 5: Il broker emette il session token

```python
# Se tutto OK, il broker crea un JWT di sessione:
session_token = jwt.encode({
    "sub": "acme::buyer",
    "iss": "agent-trust-broker",
    "aud": "agent-trust-broker",
    "exp": now + 3600,                              # 1 ora
    "iat": now,
    "jti": str(uuid.uuid4()),
    "org_id": "acmebuyer",
    "scope": ["purchase", "negotiate"],              # dal binding
    "cert_thumbprint": "a3b7c9...",                  # SHA-256 del cert
    "jkt": dpop_thumbprint,                          # se DPoP attivo
}, broker_private_key, algorithm="RS256")

# Risposta:
# {"access_token": "eyJ...", "token_type": "DPoP", "expires_in": 3600}
```

### Step 6: L'agente usa il token per le richieste successive

```
GET /v1/broker/sessions HTTP/1.1
Authorization: DPoP eyJ...session_token...
DPoP: eyJ...nuovo_dpop_proof...

→ Il broker verifica:
  1. Token valido (firma, scadenza, audience)
  2. DPoP proof valido (firma, jti, htm, htu, nonce)
  3. jkt nel token corrisponde alla chiave nel proof
  → Tutto OK → accesso concesso
```

---

## Diagramma temporale completo

```
Agente                                    Broker
  │                                         │
  │  [carica cert + key da file/Vault]      │
  │                                         │
  │  [costruisce client_assertion JWT]      │
  │  [firma con chiave privata]             │
  │                                         │
  │  [genera chiave DPoP effimera EC P-256] │
  │  [costruisce DPoP proof]                │
  │                                         │
  │── POST /v1/auth/token ────────────────▶│
  │   client_assertion=eyJ...               │
  │   DPoP: eyJ...proof...                  │
  │                                         │── estrai cert da x5c
  │                                         │── carica CA org dal DB
  │                                         │── verifica catena cert
  │                                         │── verifica firma JWT
  │                                         │── verifica DPoP proof
  │                                         │── controlla revoca + JTI
  │                                         │── carica binding (scope)
  │                                         │── emetti session token
  │                                         │   con jkt + scope
  │                                         │
  │◀── 200 {"access_token":"eyJ..."} ──────│
  │                                         │
  │  [salva token in memoria]               │
  │                                         │
  │── GET /v1/broker/sessions ────────────▶│
  │   Authorization: DPoP eyJ...token       │
  │   DPoP: eyJ...NUOVO_proof              │
  │                                         │── verifica token
  │                                         │── verifica DPoP proof
  │                                         │── jkt match? ✓
  │                                         │
  │◀── 200 [sessions list] ────────────────│
  │                                         │
```

---

## Il campo x5c — la catena certificati

Il campo `x5c` nel header del JWT è un array di certificati in base64(DER):

```json
{
  "alg": "RS256",
  "x5c": [
    "MIICpDCCAYwCCQD6...",     // x5c[0] = cert dell'agente
    "MIIDqTCCApGgAwIB..."      // x5c[1] = cert della org CA (opzionale)
  ]
}
```

L'ordine è bottom-up:
- `x5c[0]` = il certificato dell'agente (end entity)
- `x5c[1]` = il certificato della CA intermedia (opzionale — il broker lo ha nel DB)

In Cullis, tipicamente `x5c` contiene solo il cert dell'agente. Il broker ha già la CA dell'org registrata nel database, quindi non serve inviarla ogni volta.

---

## Confronto dei metodi di autenticazione

| Metodo | Segreto condiviso? | Non-repudiation? | Key on wire? | Cullis |
|---|---|---|---|---|
| Username + Password | Sì (password) | No | Sì (password) | No |
| API Key | Sì (key) | No | Sì (key) | Solo nel Proxy (locale) |
| Client Secret | Sì (secret) | No | Sì (secret) | No |
| **Client Assertion x509** | **No** | **Sì** | **No (solo cert pubblico)** | **Agenti → Broker** |
| mTLS | No | Sì | No | Futuro (optional) |

Il client assertion è il metodo che offre il miglior compromesso sicurezza/praticità per Cullis.

---

## Riepilogo — cosa portarti a casa

- Il **client assertion** è un JWT firmato con la chiave privata dell'agente, con il certificato nell'header x5c
- **Nessun segreto condiviso** — la chiave privata non lascia mai l'agente
- Il broker verifica: catena cert → firma JWT → DPoP proof → revoca → JTI → emette session token
- Il flusso completo: carica cert → costruisci JWT → firma → invia con DPoP proof → ricevi session token
- L'header **x5c** contiene i certificati in base64(DER), ordine bottom-up
- Il session token contiene: scope (dal binding), jkt (DPoP), cert_thumbprint
- Per le richieste successive: Authorization DPoP + nuovo DPoP proof ad ogni richiesta
- Il **MCP Proxy** astrae tutto questo: gli agenti interni usano solo un API key

---

*Fine Parte III — Prossima: [Parte IV — Messaging e Sessioni](14-e2e-encryption.md)*
