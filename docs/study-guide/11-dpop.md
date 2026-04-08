# Capitolo 11 — DPoP — Demonstration of Proof-of-Possession

> *"Il biglietto del treno non basta. Devi dimostrare che sei tu a tenerlo in mano."*

---

## Il problema dei Bearer Token — spiegazione da bar

Un **bearer token** è come un biglietto del treno senza nome: chiunque lo possieda può usarlo. Se lo perdi, chi lo trova può viaggiare al posto tuo.

```
Bearer Token (classico OAuth):
  Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWI...

  Se Eve intercetta questo header:
    → Eve copia il token
    → Eve lo usa da un altro computer
    → Il server non ha modo di distinguere Eve dall'agente legittimo
    → Eve ha accesso completo fino alla scadenza del token
```

Questo è il **token theft attack** — uno dei problemi più comuni in OAuth. TLS protegge il transito, ma non copre:
- Log server che registrano l'header Authorization
- Memory dump di un processo compromesso
- Proxy/middlebox malconfigurato che logga gli header
- Malware sul client che legge la memoria

### La soluzione DPoP

**DPoP** (Demonstration of Proof-of-Possession, RFC 9449) lega il token a una chiave crittografica. Non basta avere il token — devi dimostrare di avere anche la **chiave privata** corrispondente.

```
DPoP Token:
  Authorization: DPoP eyJhbGciOiJSUzI1NiJ9.eyJzdWI...
  DPoP: eyJhbGciOiJFUzI1NiJ9...                        ← DPoP proof

  Se Eve intercetta entrambi gli header:
    → Eve ha il token
    → Eve ha il proof (ma il proof è monouso: contiene nonce e timestamp)
    → Eve NON ha la chiave privata EC P-256
    → Eve non può generare un NUOVO proof
    → Eve NON può usare il token
```

**Analogia:** È la differenza tra un badge aziendale (bearer) e un badge + impronta digitale (DPoP). Anche se rubi il badge, senza l'impronta digitale non passi.

---

## Come funziona — passo per passo

### Fase 1: L'agente genera una chiave effimera

```python
from cryptography.hazmat.primitives.asymmetric import ec

# Chiave effimera EC P-256 — generata una volta, usata per tutta la sessione
dpop_private_key = ec.generate_private_key(ec.SECP256R1())
dpop_public_key = dpop_private_key.public_key()
```

**Effimera** = creata per questa sessione, non salvata a lungo termine. Se l'agente si riavvia, ne genera una nuova.

### Fase 2: L'agente chiede un token al broker

Quando l'agente si autentica (con il client_assertion x509), include un **DPoP proof** nella richiesta:

```
POST /v1/auth/token
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn19...
```

Il DPoP proof è un JWT speciale:

```json
// Header
{
  "typ": "dpop+jwt",           // tipo speciale
  "alg": "ES256",              // algoritmo EC
  "jwk": {                     // chiave PUBBLICA dell'agente (inline)
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}

// Payload
{
  "jti": "unique-id-12345",           // ID unico (anti-replay)
  "htm": "POST",                       // HTTP Method
  "htu": "https://broker:8443/v1/auth/token",  // HTTP URL (target)
  "iat": 1712342078,                   // timestamp
  "nonce": "server-nonce-abc"          // nonce dal server (anti-replay lato server)
}
```

**Firmato con:** la chiave PRIVATA EC P-256 dell'agente (quella effimera).

### Fase 3: Il broker verifica il DPoP proof e emette il token

```
Broker verifica il DPoP proof:
  1. ✓ typ == "dpop+jwt"
  2. ✓ alg è asimmetrico (ES256, PS256 — no HS256!)
  3. ✓ jwk presente nell'header (chiave pubblica)
  4. ✓ jwk non contiene "d" (= non c'è la chiave privata)
  5. ✓ Firma valida con la jwk
  6. ✓ jti mai usato prima
  7. ✓ iat recente (entro la finestra: -5s, +60s)
  8. ✓ htm corrisponde al metodo HTTP della richiesta
  9. ✓ htu corrisponde all'URL della richiesta
  10. ✓ nonce è valido (corrente o precedente)

Se tutto OK:
  → Calcola jkt = SHA-256 thumbprint della jwk
  → Emette un JWT con il claim jkt:
    {"sub": "acme::buyer", "jkt": "dBjftJeZ4CVP...", ...}
  → Il token è ora LEGATO a quella chiave
```

### Fase 4: Ogni richiesta successiva

Per ogni richiesta, l'agente deve includere un **nuovo** DPoP proof:

```
GET /v1/broker/sessions
Authorization: DPoP eyJ...token...
DPoP: eyJ...nuovo_proof...
```

Il broker verifica:
1. Il proof è valido (firma, jti, htm, htu, nonce, iat)
2. La chiave nel proof corrisponde al `jkt` nel token (thumbprint match)
3. Il token è ancora valido

```
Verifica binding:

  Token:                    DPoP Proof:
  {"jkt": "dBjftJeZ..."}   {"jwk": {"kty":"EC", "crv":"P-256", ...}}
         │                            │
         │                            ▼
         │                   jkt = SHA256(canonical(jwk))
         │                            │
         └────── devono corrispondere ─┘
         
  Se corrispondono → il proof è stato firmato con la chiave legata al token
  Se NON corrispondono → qualcuno sta usando un token rubato con una chiave diversa → RIFIUTATO
```

---

## Server Nonce — RFC 9449 Section 8

Il server nonce aggiunge un altro layer anti-replay:

```
Flusso con nonce:

  Agente                          Broker
    │                               │
    │── richiesta SENZA nonce ────▶│
    │◀── 401 + DPoP-Nonce: "abc" ──│  ← "usa questo nonce"
    │                               │
    │── richiesta CON nonce "abc" ─▶│
    │◀── 200 OK ────────────────────│  ← accettato
    │                               │
    │── prossima richiesta ─────────▶│
    │   (nonce: "abc" ancora valido) │
    │◀── 200 OK ────────────────────│
    │                               │
    │   ... dopo 300 secondi ...     │
    │── richiesta con nonce "abc" ──▶│
    │◀── 401 + DPoP-Nonce: "xyz" ──│  ← nonce ruotato, eccone uno nuovo
    │                               │
    │── richiesta CON nonce "xyz" ─▶│
    │◀── 200 OK ────────────────────│
```

### Implementazione in Cullis (`app/auth/dpop.py:45-74`)

```python
# Stato globale
_current_nonce: str | None = None
_previous_nonce: str | None = None
_nonce_generated_at: float = 0

_NONCE_ROTATION_SECONDS = 300     # ruota ogni 5 minuti

def generate_dpop_nonce() -> str:
    return os.urandom(16).hex()   # 128 bit di randomness

def get_current_dpop_nonce() -> str:
    global _current_nonce, _previous_nonce, _nonce_generated_at
    now = time.monotonic()
    if now - _nonce_generated_at > _NONCE_ROTATION_SECONDS:
        _previous_nonce = _current_nonce       # mantieni il vecchio per un ciclo
        _current_nonce = generate_dpop_nonce()
        _nonce_generated_at = now
    return _current_nonce

def _is_valid_nonce(nonce: str) -> bool:
    # Accetta sia il nonce corrente sia quello precedente
    # → grace period durante la rotazione
    return hmac.compare_digest(nonce, _current_nonce) or \
           (_previous_nonce and hmac.compare_digest(nonce, _previous_nonce))
```

Perché tenere il `_previous_nonce`? Perché durante la rotazione, un agente potrebbe aver ricevuto il nonce vecchio 1 secondo prima della rotazione e inviare il proof 1 secondo dopo. Senza grace period → fallimento spurio.

---

## La verifica completa — 12 check (`app/auth/dpop.py:181-320`)

```
DPoP Proof ricevuto dal server:

 1. ✓ Decodifica header senza verificare firma
 2. ✓ typ == "dpop+jwt"
 3. ✓ alg ∈ {ES256, PS256} — solo asimmetrico!
 4. ✓ jwk presente, non contiene "d" (campo chiave privata)
 5. ✓ Calcola jkt (thumbprint)
 6. ✓ Verifica firma con la jwk dall'header
 7. ✓ jti presente e non vuoto
 8. ✓ iat entro la finestra: [now - 5s, now + 60s]
        (clock_skew=5s, iat_window=60s)
 9. ✓ htm corrisponde al metodo HTTP (case-insensitive)
10. ✓ htu corrisponde all'URL (normalizzato: no query, no fragment,
        scheme e host lowercase)
11. ✓ Se c'è un access_token: ath == base64url(SHA-256(token))
12. ✓ nonce corrisponde al nonce corrente o precedente

Solo DOPO tutti i check:
13. Consuma il jti (registra come usato → anti-replay)
```

### HTU Normalization — un dettaglio importante

L'URL nel proof (`htu`) viene normalizzato prima del confronto:

```python
def _normalize_htu(raw: str) -> str:
    parsed = urlparse(raw)
    # Rimuovi query string e fragment
    # Lowercase su scheme e host
    # WebSocket: wss:// → https://, ws:// → http://
    scheme = parsed.scheme.lower()
    if scheme == "wss": scheme = "https"
    if scheme == "ws": scheme = "http"
    return urlunparse((scheme, parsed.netloc.lower(), parsed.path, "", "", ""))
```

Perché? Perché `https://Broker:8443/v1/auth/token?foo=bar` e `https://broker:8443/v1/auth/token` devono essere considerate la stessa URL ai fini del DPoP.

### Access Token Hash (ath)

Quando il proof accompagna un access token, il proof contiene l'hash del token:

```python
# Nel proof:
"ath": base64url(SHA-256(access_token))

# Verifica:
expected_ath = base64url(SHA-256(access_token_dal_header_authorization))
if proof_ath != expected_ath:
    raise "DPoP proof ath does not match the access token"
```

Questo lega il proof al token specifico. Non puoi usare un proof creato per un token con un altro token.

---

## DPoP nel MCP Proxy (`mcp_proxy/auth/dpop.py`)

Il proxy ha la propria implementazione standalone (no dipendenze da `app/`):

```python
class InMemoryDpopJtiStore:
    """JTI store per il proxy — in-memory con asyncio.Lock."""
    
    def __init__(self, ttl: int = 300):
        self._store: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._ttl = ttl
    
    async def consume_jti(self, jti: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            # Lazy eviction quando lo store raggiunge 100k entries
            if len(self._store) > 100_000:
                self._store = {k: v for k, v in self._store.items() 
                               if now - v < self._ttl}
            
            if jti in self._store:
                return False  # replay!
            
            self._store[jti] = now
            return True       # first use
```

---

## Bearer vs DPoP — confronto visuale

```
BEARER TOKEN (classico):

  Agente legittimo:
    Authorization: Bearer eyJ...token...     → ✓ accesso

  Eve ruba il token:
    Authorization: Bearer eyJ...token...     → ✓ accesso (PROBLEMA!)


DPoP TOKEN:

  Agente legittimo:
    Authorization: DPoP eyJ...token...
    DPoP: eyJ...proof_firmato_con_chiave_privata...    → ✓ accesso

  Eve ruba il token E il proof:
    Authorization: DPoP eyJ...token...
    DPoP: eyJ...proof_rubato...
    → ✗ RIFIUTATO — il proof ha jti monouso (già consumato)
    
  Eve ruba il token e crea un NUOVO proof:
    Authorization: DPoP eyJ...token...
    DPoP: eyJ...proof_di_eve...
    → ✗ RIFIUTATO — il jkt nel token non corrisponde alla chiave di Eve
    
  Eve dovrebbe avere la chiave PRIVATA dell'agente per creare un proof valido.
  La chiave privata non viaggia mai sulla rete → Eve non può ottenerla
  (a meno di compromettere la memoria del processo dell'agente)
```

---

## Perché ES256 e non RS256 per i DPoP proof?

| | RS256 | ES256 |
|---|---|---|
| Dimensione firma | 256 byte | 64 byte |
| Dimensione proof JWT | ~800 byte | ~400 byte |
| Velocità firma | Più lento | **Più veloce** |
| Dimensione chiave pubblica | ~300 byte | ~90 byte |

I DPoP proof vengono inviati ad **ogni richiesta**. Devono essere piccoli e veloci da generare. ES256 (ECDSA con P-256) è la scelta naturale.

---

## Riepilogo — cosa portarti a casa

- I **bearer token** sono come contanti: chi li ha li usa. Se rubati → accesso immediato
- **DPoP** lega il token a una chiave crittografica: servono ENTRAMBI per l'accesso
- L'agente genera una **chiave effimera EC P-256** e la usa per firmare i DPoP proof
- Il broker calcola il **jkt** (thumbprint SHA-256) della chiave e lo mette nel token
- Ogni richiesta include un **nuovo proof** con: jti unico, htm, htu, timestamp, nonce server
- Il **server nonce** (rotazione ogni 300s, grace period con previous) aggiunge anti-replay lato server
- La verifica è un processo a **12 check** — tutti devono passare
- **ES256** è preferito per i proof: piccolo, veloce, adatto a richieste frequenti
- Codice: `app/auth/dpop.py` (broker), `mcp_proxy/auth/dpop.py` (proxy standalone)

---

*Prossimo capitolo: [12 — OAuth 2.0 e OIDC Federation](12-oauth-oidc.md) — il framework di autorizzazione e la federazione con Identity Provider esterni*
