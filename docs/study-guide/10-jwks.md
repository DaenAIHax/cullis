# Capitolo 10 — JWKS — JSON Web Key Set

> *"Non mi mandare la chiave per posta. Mettila in bacheca — vengo io a prenderla quando mi serve."*

---

## Il problema — spiegazione da bar

Il broker firma i JWT con la sua chiave privata. Gli agenti e i proxy devono **verificare** quei JWT con la chiave pubblica del broker. Ma come la ottengono?

**Opzione A — hardcode:** copi la chiave pubblica e la incolli nella configurazione di ogni agente. Funziona, ma quando il broker cambia chiave devi aggiornare tutti.

**Opzione B — endpoint JWKS:** il broker pubblica le sue chiavi pubbliche su un URL noto. Chiunque deve verificare un token va a scaricarle. Quando il broker aggiunge o ruota una chiave, tutti la vedono automaticamente.

JWKS è l'Opzione B — lo standard per **pubblicare chiavi pubbliche** in modo automatico.

---

## JWK — JSON Web Key (RFC 7517)

Un JWK è la rappresentazione JSON di una chiave crittografica. Ecco una chiave RSA pubblica in formato JWK:

```json
{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM...",
  "e": "AQAB",
  "kid": "broker-key-2026",
  "use": "sig",
  "alg": "RS256"
}
```

### I campi

| Campo | Significato | Esempio |
|---|---|---|
| `kty` | Key Type — tipo di chiave | `"RSA"`, `"EC"`, `"OKP"` |
| `n` | Modulo RSA (base64url) | `"0vx7ago..."` |
| `e` | Esponente RSA (base64url) | `"AQAB"` (= 65537) |
| `kid` | Key ID — identificatore unico | `"broker-key-2026"` |
| `use` | Uso: `"sig"` (firma) o `"enc"` (cifratura) | `"sig"` |
| `alg` | Algoritmo previsto | `"RS256"` |

Per chiavi EC (curve ellittiche):

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "kid": "dpop-key-1",
  "use": "sig",
  "alg": "ES256"
}
```

| Campo EC | Significato |
|---|---|
| `crv` | Curva (`"P-256"`, `"P-384"`, `"P-521"`) |
| `x` | Coordinata X del punto sulla curva (base64url) |
| `y` | Coordinata Y del punto sulla curva (base64url) |

---

## JWKS — il set di chiavi (l'endpoint)

Un JWKS è semplicemente un array di JWK in un oggetto `{"keys": [...]}`:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "broker-key-2026",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nn...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "broker-key-2025",
      "use": "sig",
      "alg": "RS256",
      "n": "rFH5C5hn5TBnG8RfzWQVqUKa3Fc...",
      "e": "AQAB"
    }
  ]
}
```

Pubblicato all'endpoint: `https://broker.example.com/.well-known/jwks.json`

### Perché ci sono due chiavi?

Per la **rotazione**. Quando il broker genera una nuova chiave:

1. Aggiunge la nuova chiave al JWKS (`broker-key-2026`)
2. Inizia a firmare i nuovi token con la nuova chiave
3. I token vecchi (firmati con `broker-key-2025`) sono ancora validi fino alla scadenza
4. Chi verifica: guarda il `kid` nel header del JWT → cerca la chiave corrispondente nel JWKS
5. Dopo qualche settimana, rimuove la vecchia chiave dal JWKS

```
Timeline di rotazione:

  T0: JWKS = [key-2025]
      Token firmati con key-2025

  T1: JWKS = [key-2025, key-2026]          ← aggiungi la nuova
      Nuovi token firmati con key-2026
      Vecchi token ancora verificabili con key-2025

  T2: JWKS = [key-2026]                    ← rimuovi la vecchia
      Tutti i token key-2025 sono scaduti
```

**Analogia:** È come cambiare la serratura di casa. Per un periodo tieni sia la vecchia sia la nuova chiave, finché tutti quelli che avevano la vecchia non hanno ricevuto la nuova.

---

## JWK Thumbprint — RFC 7638

### Cos'è

Il thumbprint è un hash deterministico che identifica univocamente una chiave. Serve per dire "questa chiave qui" senza dover confrontare tutti i campi.

### Come si calcola

1. Prendi solo i campi **obbligatori** della chiave, in **ordine alfabetico**
2. Serializza in JSON (compatto, no spazi)
3. Calcola SHA-256

```
Per chiave EC P-256:
  Campi obbligatori (in ordine): crv, kty, x, y
  
  JSON: {"crv":"P-256","kty":"EC","x":"f83OJ3D2...","y":"x_FEzRu9..."}
  
  Thumbprint = base64url(SHA-256(JSON))
  → "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

Per chiave RSA:
  Campi obbligatori (in ordine): e, kty, n
  
  JSON: {"e":"AQAB","kty":"RSA","n":"0vx7ago..."}
  
  Thumbprint = base64url(SHA-256(JSON))
```

### Implementazione in Cullis (`app/auth/dpop.py:100-118`)

```python
def _compute_jkt(jwk: dict) -> str:
    """RFC 7638 JWK Thumbprint — SHA-256."""
    kty = jwk.get("kty")
    
    if kty == "EC":
        # Ordine alfabetico: crv, kty, x, y
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"), sort_keys=True,
        )
    elif kty == "RSA":
        # Ordine alfabetico: e, kty, n
        canonical = json.dumps(
            {"e": jwk["e"], "kty": kty, "n": jwk["n"]},
            separators=(",", ":"), sort_keys=True,
        )
    
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64url_encode(digest)
```

### A cosa serve

Il thumbprint viene usato nel **claim `jkt`** del token DPoP-bound (lo vediamo nel prossimo capitolo):

```json
{
  "sub": "acme::buyer",
  "jkt": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
```

Questo lega il token alla chiave: "questo token può essere usato SOLO da chi possiede la chiave con questo thumbprint."

---

## Il flusso completo — dal JWKS alla verifica

```
1. Il broker pubblica JWKS su /.well-known/jwks.json
   → Contiene le chiavi pubbliche con kid

2. Il broker firma un JWT con kid="broker-key-2026"
   Header: {"alg": "RS256", "kid": "broker-key-2026"}

3. L'agente (o il proxy) riceve il JWT

4. L'agente scarica il JWKS:
   GET https://broker.example.com/.well-known/jwks.json

5. Cerca la chiave con kid="broker-key-2026" nel set

6. Verifica la firma del JWT con quella chiave pubblica

7. Se la firma è valida → il JWT è autentico
```

```
Agente                              Broker
  │                                   │
  │◀──── JWT (kid: "key-2026") ──────│  ← token firmato
  │                                   │
  │──── GET /.well-known/jwks.json ─▶│  ← scarica chiavi
  │◀──── {"keys": [...]} ────────────│
  │                                   │
  │  Trova "key-2026" nel JWKS        │
  │  Verifica firma con pubkey        │
  │  ✓ Token autentico               │
```

---

## kid — il Key ID

Il `kid` (Key ID) è il collegamento tra un JWT e la chiave nel JWKS:

```
JWT Header:
  {"alg": "RS256", "kid": "broker-key-2026"}
                          ────────────────
                                │
JWKS:                           │
  {"keys": [                    │
    {"kid": "broker-key-2025", "kty": "RSA", ...},   ← no match
    {"kid": "broker-key-2026", "kty": "RSA", ...},   ← MATCH!
  ]}
```

Come viene generato il `kid`:
- Può essere qualsiasi stringa unica
- Spesso è il **thumbprint** della chiave (RFC 7638) — così è deterministico
- In Cullis: calcolato come SHA-256 thumbprint

---

## JWKS e caching

In production, non vuoi scaricare il JWKS a ogni verifica. Si usa il **caching**:

```
Prima richiesta:
  GET /.well-known/jwks.json → 200
  Cache-Control: max-age=3600
  → Salva in cache per 1 ora

Richieste successive (entro 1 ora):
  → Usa la versione in cache, nessuna richiesta HTTP

Se un kid non è nella cache:
  → Ri-scarica il JWKS (potrebbe esserci una nuova chiave)
  → Se ancora non c'è → token invalido
```

---

## Riepilogo — cosa portarti a casa

- **JWK** = rappresentazione JSON di una chiave (pubblica o privata)
- **JWKS** = array di JWK pubblicato su `/.well-known/jwks.json`
- Il **kid** nel JWT header dice quale chiave del JWKS usare per la verifica
- Il **thumbprint** (RFC 7638) è l'hash SHA-256 dei campi obbligatori — identifica una chiave in modo deterministico
- La **rotazione** funziona pubblicando la nuova chiave nel JWKS prima di ritirare la vecchia
- In Cullis il thumbprint è usato per il claim `jkt` che lega il token alla chiave DPoP

---

*Prossimo capitolo: [11 — DPoP — Demonstration of Proof-of-Possession](11-dpop.md) — come rendere un token non rubabile*
