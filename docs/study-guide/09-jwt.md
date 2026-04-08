# Capitolo 09 — JWT — JSON Web Token

> *"Un biglietto del treno con scritto chi sei, dove puoi andare, e quando scade — firmato dal controllore."*

---

## Cos'è un JWT — spiegazione da bar

Vai a un concerto. All'ingresso mostri il documento, ti verificano, e ti danno un **braccialetto**. Da quel momento, per entrare nelle varie aree (palco, backstage, bar VIP), mostri solo il braccialetto — non devi rifare l'identificazione ogni volta.

Il braccialetto dice:
- **Chi sei** (nome stampato)
- **Dove puoi andare** (colore = aree accessibili)
- **Quando scade** (data del concerto)
- **Chi l'ha emesso** (timbro dell'organizzatore)

Un **JWT** (JSON Web Token, pronuncia "jot") è il braccialetto digitale. È una stringa di testo che contiene informazioni (claims) sull'utente, firmata da chi l'ha emessa. Chiunque può leggerla, ma solo l'emittente può produrne una valida.

---

## Struttura — i tre pezzi

Un JWT è composto da tre parti separate da punti:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY21lOjpidXllciIsImlzcyI6ImFnZW50LXRydXN0LWJyb2tlciIsImV4cCI6MTcxMjM0NTY3OH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└──────────── HEADER ──────────────┘.└──────────────────────── PAYLOAD ───────────────────────────┘.└────────── SIGNATURE ──────────┘
```

### 1. Header — "come è firmato"

```json
{
  "alg": "RS256",       // algoritmo di firma
  "typ": "JWT",         // tipo di token
  "x5c": ["MIIC..."]   // (opzionale) catena certificati in base64
}
```

### 2. Payload — "cosa dice"

```json
{
  "sub": "acme::buyer",              // subject — chi è il titolare
  "iss": "agent-trust-broker",       // issuer — chi ha emesso il token
  "aud": "agent-trust-broker",       // audience — per chi è destinato
  "exp": 1712345678,                 // expiration — quando scade (Unix timestamp)
  "iat": 1712342078,                 // issued at — quando è stato emesso
  "jti": "550e8400-e29b-41d4-a716",  // JWT ID — identificatore unico
  "org_id": "acmebuyer",             // claim custom — organizzazione
  "scope": ["purchase", "negotiate"] // claim custom — capability
}
```

### 3. Signature — "la prova che è autentico"

```
RSASHA256(
  base64urlEncode(header) + "." + base64urlEncode(payload),
  chiave_privata_del_broker
)
```

La firma è calcolata su header + payload. Se qualcuno modifica anche un solo byte del payload (es. cambia `exp` per estendere la scadenza), la firma non corrisponde più → token invalido.

---

## Claims standard (RFC 7519)

I claims sono le informazioni dentro il payload. Lo standard ne definisce alcuni:

| Claim | Nome | Significato | Esempio |
|---|---|---|---|
| `iss` | Issuer | Chi ha creato il token | `"agent-trust-broker"` |
| `sub` | Subject | Di chi parla il token | `"acme::buyer"` |
| `aud` | Audience | Per chi è il token | `"agent-trust-broker"` |
| `exp` | Expiration | Quando scade (Unix timestamp) | `1712345678` |
| `iat` | Issued At | Quando è stato creato | `1712342078` |
| `nbf` | Not Before | Non valido prima di... | `1712342078` |
| `jti` | JWT ID | ID unico del token | `"550e8400-e29b..."` |

**Attenzione:** il payload è codificato in base64, **NON è cifrato**. Chiunque può decodificarlo e leggere i claims. La firma garantisce solo che non è stato **modificato**, non che è **segreto**.

```
# Chiunque può fare questo:
echo "eyJzdWIiOiJhY21lOjpidXllciJ9" | base64 -d
# → {"sub":"acme::buyer"}

# Ma nessuno può MODIFICARE il payload e mantenere la firma valida
# (a meno che non abbia la chiave privata del broker)
```

---

## Algoritmi di firma — HS256, RS256, ES256

### HS256 — HMAC + SHA-256 (simmetrico)

```
Una sola chiave (secret) condivisa tra emittente e verificatore.

  Firma:    HMAC-SHA256(header.payload, "super-secret-key")
  Verifica: ricalcola HMAC con la stessa chiave → deve corrispondere

Pro: veloce, semplice
Contro: la chiave è condivisa — chi verifica può anche falsificare
Uso: app monolitiche dove emittente = verificatore
```

**Cullis NON usa HS256.** Perché: se il broker emette i token E li verifica, nessun problema. Ma se gli agenti o i proxy devono verificare i token, dovrebbero avere la stessa secret → rischio. Con asimmetrico, serve solo la chiave pubblica per verificare.

### RS256 — RSA + SHA-256 (asimmetrico) — QUELLO CHE USA CULLIS

```
Due chiavi: privata (firma) e pubblica (verifica).

  Firma:    RSA-PKCS1v15-SHA256(header.payload, chiave_privata_broker)
  Verifica: chiunque con la chiave_pubblica_broker può verificare

Pro: chi verifica NON può falsificare (non ha la chiave privata)
Contro: più lento di HS256, firma più grande (256 byte per RSA-2048)
Uso: sistemi distribuiti dove emittente ≠ verificatore
```

### ES256 — ECDSA P-256 + SHA-256 (asimmetrico)

```
Come RS256 ma con curve ellittiche.

  Firma:    ECDSA-SHA256(header.payload, chiave_privata_EC_P256)
  Verifica: con la chiave_pubblica_EC

Pro: firma molto più piccola (64 byte vs 256), più veloce
Contro: verifica leggermente più lenta
Uso: dove serve compattezza (DPoP proof, mobile)
```

### In Cullis — chi usa cosa

| Token | Algoritmo | Chi firma | Chi verifica |
|---|---|---|---|
| JWT di sessione (broker → agente) | **RS256** | Broker (chiave privata CA) | Agenti/Proxy (chiave pubblica via JWKS) |
| Client assertion (agente → broker) | **RS256** o **ES256** | Agente (chiave privata dal cert) | Broker (chiave pubblica dal cert x509) |
| DPoP proof | **ES256** o **PS256** | Agente (chiave effimera) | Broker |

---

## I due JWT in Cullis

In Cullis ci sono due JWT distinti con scopi diversi:

### JWT #1 — Client Assertion (agente → broker)

Questo è il "passaporto" che l'agente presenta per autenticarsi:

```
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "x5c": ["MIIC..."]     ← catena certificati dell'agente
}

Payload:
{
  "sub": "acme::buyer",                              ← chi sono
  "iss": "acme::buyer",                              ← lo dico io stesso
  "aud": "agent-trust-broker",                       ← per il broker
  "exp": 1712342378,                                 ← scade tra 5 minuti
  "iat": 1712342078,                                 ← emesso adesso
  "jti": "550e8400-e29b-41d4-a716-446655440000"      ← ID unico (anti-replay)
}

Firmato con: chiave privata RSA dell'agente (quella del certificato)
```

**Chi lo verifica:** il broker, usando la chiave pubblica estratta dal certificato nel header x5c.

**Caratteristiche:**
- Vita brevissima (5 minuti) — è un "biglietto di ingresso" monouso
- Il `jti` finisce nella blacklist dopo l'uso → non riutilizzabile
- L'header `x5c` contiene il certificato che il broker verifica contro la CA dell'org

### JWT #2 — Session Token (broker → agente)

Questo è il "braccialetto" che il broker dà all'agente dopo l'autenticazione:

```
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "broker-key-1"   ← ID della chiave del broker (per JWKS lookup)
}

Payload:
{
  "sub": "acme::buyer",
  "iss": "agent-trust-broker",
  "aud": "agent-trust-broker",
  "exp": 1712352878,                   ← scade tra qualche ora
  "iat": 1712342078,
  "jti": "random-uuid",
  "org_id": "acmebuyer",
  "scope": ["purchase", "negotiate"],  ← capability del binding
  "cert_thumbprint": "a3b7c9...",      ← SHA-256 del cert presentato
  "jkt": "dBjftJeZ4CVP..."            ← thumbprint DPoP (se DPoP attivo)
}

Firmato con: chiave privata della Broker CA
```

**Chi lo verifica:** il broker stesso (a ogni richiesta successiva), oppure chiunque abbia la chiave pubblica del broker (via JWKS endpoint).

**Caratteristiche:**
- Vita più lunga (ore) — è il token di sessione
- Contiene `scope` con le capability dell'agente
- Contiene `jkt` se DPoP è attivo → il token è legato alla chiave crittografica dell'agente
- Contiene `cert_thumbprint` per verifiche successive

---

## JTI — replay protection

Il `jti` (JWT ID) è la difesa contro il **replay attack**:

```
Senza JTI:
  1. L'agente si autentica → riceve token
  2. Eve intercetta il client_assertion
  3. Eve ri-invia lo stesso client_assertion → riceve un nuovo token!
  4. Eve ha un token valido senza avere la chiave privata

Con JTI:
  1. L'agente si autentica con jti="abc123" → riceve token
  2. Il broker registra "abc123" nella blacklist
  3. Eve ri-invia lo stesso client_assertion con jti="abc123"
  4. Il broker controlla: "abc123" è nella blacklist → 401 RIFIUTATO
```

### Come funziona la blacklist

```python
# check_and_consume_jti:
# 1. Controlla se il jti è già stato usato
# 2. Se sì → 401 Unauthorized (replay detected)
# 3. Se no → registra il jti con il suo expiration time
# 4. I jti scaduti vengono rimossi automaticamente (lazy cleanup)

await check_and_consume_jti(db, jti="abc123", expires_at=datetime(2026,4,8,15,0))
```

Backend per la blacklist:
- **Redis** (production): veloce, con TTL automatico
- **Database** (fallback): tabella `jti_blacklist` con lazy cleanup
- **In-memory** (dev): dizionario Python

---

## JWT e sicurezza — le trappole classiche

### 1. "Nessun algoritmo" (alg: none)

```json
{"alg": "none", "typ": "JWT"}
```

Un JWT con `alg: "none"` non ha firma. Alcune librerie vecchie lo accettavano!

**Cullis:** accetta solo `["RS256", "ES256"]` — esplicitamente whitelist. Nessun `none`, nessun `HS256`.

### 2. Confusione simmetrico/asimmetrico

Un attaccante manda un JWT firmato HS256 usando la chiave PUBBLICA del server come secret. Se il server non controlla l'algoritmo, verifica con la chiave pubblica come HMAC secret → valido!

**Cullis:** l'algoritmo è forzato nel codice, non letto dal header del token.

### 3. Token non scadono

JWT senza `exp` sono validi per sempre. Se rubati → accesso permanente.

**Cullis:** `exp` è obbligatorio (`"verify_exp": True`). Token senza scadenza → rifiutato.

### 4. Audience non verificato

Un JWT emesso per il servizio A viene presentato al servizio B. Se B non controlla `aud` → lo accetta.

**Cullis:** `aud` deve essere `"agent-trust-broker"` (`"verify_aud": True`).

---

## Decodificare un JWT — esercizio pratico

```python
import jwt
import json
import base64

token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhY21lOjpidXllciJ9.signature..."

# METODO 1: Decodifica SENZA verificare (solo per debug!)
payload = jwt.decode(token, options={"verify_signature": False})
print(payload)  # {"sub": "acme::buyer", ...}

# METODO 2: Decodifica CON verifica (production)
payload = jwt.decode(
    token,
    public_key_pem,                    # chiave pubblica PEM
    algorithms=["RS256"],              # whitelist algoritmi
    audience="agent-trust-broker",     # verifica audience
    options={"verify_exp": True},      # verifica scadenza
)

# METODO 3: A mano (per capire la struttura)
header_b64, payload_b64, signature_b64 = token.split(".")
header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
print("Header:", header)
print("Payload:", payload)
```

---

## Riepilogo — cosa portarti a casa

- **JWT** = tre parti base64 separate da punti: header.payload.signature
- Il payload è **leggibile da tutti** (base64, non cifrato) — la firma garantisce solo l'integrità
- **RS256** (RSA + SHA-256) è l'algoritmo usato da Cullis — asimmetrico, chi verifica non può falsificare
- In Cullis ci sono **due JWT**: client_assertion (agente → broker, breve) e session token (broker → agente, lungo)
- Il **JTI** (JWT ID) protegge dal replay: ogni token usato una sola volta → blacklist
- Trappole: `alg: none`, confusione alg, no `exp`, no `aud` — Cullis le evita tutte con whitelist e verifiche esplicite

---

*Prossimo capitolo: [10 — JWKS — JSON Web Key Set](10-jwks.md) — come distribuire le chiavi pubbliche per la verifica*
