# Capitolo 12 — OAuth 2.0 e OIDC Federation

> *"Non gestisco io la tua password. Chiedo al tuo governo se sei chi dici di essere."*

---

## OAuth 2.0 — spiegazione da bar

Vuoi che un'app (Spotify) acceda alle tue foto su Google. Potresti dare la password di Google a Spotify... ma sarebbe folle. Spotify avrebbe accesso a TUTTO il tuo Google.

**OAuth 2.0** è il protocollo che risolve questo: Spotify ti reindirizza su Google, tu autorizzi l'accesso alle sole foto, Google dà a Spotify un **token** con permessi limitati. Spotify non vede mai la tua password.

```
Tu                  Spotify               Google
│                     │                     │
│── "connetti Google"─▶│                     │
│                     │── redirect ─────────▶│
│◀────────────────────────── pagina login ──│
│── "sì, autorizza foto" ──────────────────▶│
│                     │◀── token (solo foto) │
│                     │                     │
│  Spotify ora può leggere le tue foto       │
│  ma NON le tue email, NON il tuo Drive     │
```

### I ruoli in OAuth

| Ruolo | Chi è | Esempio |
|---|---|---|
| **Resource Owner** | Tu (il proprietario dei dati) | L'utente |
| **Client** | L'app che vuole accedere | Spotify |
| **Authorization Server** | Chi decide se autorizzare | Google Accounts |
| **Resource Server** | Dove stanno i dati | Google Photos API |

---

## I grant type — come si ottiene il token

### Authorization Code (con PKCE) — per app con utente

```
Il flusso più comune, usato da app web e mobile:

1. L'app genera un code_verifier (stringa random)
   e un code_challenge (SHA-256 del verifier)
2. L'app reindirizza l'utente all'authorization server
   con il code_challenge
3. L'utente si autentica e autorizza
4. L'authorization server reindirizza l'utente all'app
   con un authorization_code monouso
5. L'app scambia code + code_verifier per un token
6. Il server verifica che SHA-256(code_verifier) == code_challenge
   → se sì, emette il token

PKCE (Proof Key for Code Exchange):
  Previene l'attacco di intercettazione del code.
  Anche se Eve intercetta il code, senza il code_verifier
  non può scambiarlo per un token.
```

### Client Credentials — per machine-to-machine

```
Nessun utente coinvolto. Il client si autentica direttamente:

  POST /oauth/token
  grant_type=client_credentials
  client_id=my-service
  client_secret=super-secret
  scope=read:data

  → Token emesso direttamente al client

Usato per: servizi backend, microservizi, agenti automatici
```

**Questo è il grant più vicino a ciò che fa Cullis** — ma Cullis va oltre: usa x509 + DPoP invece di client_secret.

---

## OIDC — OpenID Connect

OIDC è un **layer sopra OAuth 2.0** che aggiunge l'**identità**. OAuth dice "sei autorizzato", OIDC dice "sei autorizzato E so chi sei".

### La differenza

```
OAuth 2.0:
  "Ecco un access_token. Puoi accedere alle foto."
  → Ma chi è l'utente? Non lo dice.

OIDC:
  "Ecco un access_token E un id_token."
  → L'id_token contiene: nome, email, foto, org...
  → Ora sai CHI è l'utente, non solo che è autorizzato.
```

### L'ID Token

L'id_token è un JWT che contiene l'identità dell'utente:

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",         // ID unico utente
  "aud": "my-app-client-id",
  "exp": 1712345678,
  "iat": 1712342078,
  "name": "Mario Rossi",
  "email": "mario@acmebuyer.com",
  "email_verified": true,
  "hd": "acmebuyer.com"                  // hosted domain (org)
}
```

### Discovery — .well-known/openid-configuration

Ogni OIDC provider pubblica la propria configurazione su un URL standard:

```
GET https://accounts.google.com/.well-known/openid-configuration

{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "scopes_supported": ["openid", "email", "profile"],
  "response_types_supported": ["code", "token", "id_token"],
  ...
}
```

Questo permette la **discovery automatica**: il client non deve hardcodare gli endpoint — li scopre da questo documento.

---

## OIDC Federation in Cullis

### A cosa serve

In Cullis, OIDC è usato per l'**autenticazione degli admin umani** delle organizzazioni. Non per gli agenti (che usano x509+DPoP), ma per le persone che gestiscono la dashboard.

```
Senza OIDC:
  Admin → login con username/password locale sul broker
  → Il broker deve gestire password, hash, reset...

Con OIDC:
  Admin → "Login con Okta" / "Login con Azure AD"
  → Redirect all'IdP aziendale
  → L'IdP verifica le credenziali (anche con MFA!)
  → Redirect back con id_token
  → Il broker sa chi è l'admin senza aver mai visto una password
```

### Per-org IdP config

Ogni organizzazione in Cullis può avere il proprio Identity Provider:

```
Org A (AcmeBuyer):
  IdP: Okta
  Client ID: xxx
  Client Secret: [encrypted in KMS]
  Issuer: https://acme.okta.com

Org B (Widgets Corp):
  IdP: Azure AD
  Client ID: yyy
  Client Secret: [encrypted in KMS]
  Issuer: https://login.microsoftonline.com/tenant-id

Org C (piccola azienda):
  IdP: nessuno (usa admin_secret locale)
```

### Client Secret encrypted at rest

Il client secret OIDC è un segreto sensibile. Cullis lo cifra con il KMS prima di salvarlo nel database:

```
Salvataggio:
  client_secret_clear → KMS.encrypt() → client_secret_encrypted → DB

Uso:
  DB → client_secret_encrypted → KMS.decrypt() → client_secret_clear → invio all'IdP

Se il database viene compromesso:
  → L'attaccante ha solo il ciphertext
  → Senza la chiave KMS non può decifrare
  → Il client_secret è al sicuro
```

---

## RFC 8693 — Token Exchange (roadmap)

Token Exchange è un meccanismo per **scambiare un token per un altro** con scope diverso. È nella roadmap di Cullis per la **user delegation chain**.

### Il concetto

```
Scenario: un utente umano chiede al proprio agente di fare qualcosa.
L'agente deve operare "per conto dell'utente", non per conto proprio.

Senza delegation:
  Agente → broker: "Io sono acme::buyer, apri sessione"
  → Ma chi ha autorizzato l'agente? L'agente agisce autonomamente.

Con delegation (RFC 8693):
  Utente → token exchange → agente ottiene un token con:
    - subject: l'agente (acme::buyer)
    - actor: l'utente (mario@acme.com)
    - scope: limitato a quello che l'utente ha autorizzato

  Agente → broker: "Io sono acme::buyer, che agisce per conto di mario@acme.com"
  → Audit trail: "mario ha autorizzato l'agente a fare X"
  → Policy: possono essere basate su chi ha autorizzato, non solo sull'agente
```

### Transaction Token in Cullis

I transaction token sono un'implementazione parziale del concetto:

```json
{
  "sub": "acme::buyer",
  "actor": {
    "sub": "acme::buyer"
  },
  "scope": "single-transaction",
  "payload_hash": "sha256:abc123...",    // hash del payload della transazione
  "exp": 1712342378                       // scadenza brevissima
}
```

Proprietà:
- **Monouso**: legato a una specifica transazione (payload_hash)
- **TTL corto**: scade in minuti, non ore
- **Actor chain**: traccia chi ha autorizzato cosa

---

## Il confronto: OAuth/OIDC classico vs Cullis

| | OAuth/OIDC classico | Cullis |
|---|---|---|
| **Chi si autentica** | Utenti umani | Agenti AI (machine) + admin umani |
| **Credenziali** | Username/password via browser | x509 cert + chiave privata (agenti), OIDC (admin) |
| **Token binding** | Bearer (rubabile) | DPoP (legato a chiave) |
| **Grant type** | Authorization Code + PKCE | x509 client_assertion (agenti), OIDC code (admin) |
| **Scope** | Definiti dall'authorization server | Capability binding per-agente, per-org |
| **Policy** | Single authorization server | **Dual-org PDP** (entrambe le org decidono) |
| **Federation** | Un IdP per tutti | **Per-org IdP** (ogni org il proprio) |

---

## Riepilogo — cosa portarti a casa

- **OAuth 2.0** è il framework per l'autorizzazione delegata — "accedi ai miei dati senza la mia password"
- **OIDC** aggiunge l'identità sopra OAuth — "so anche CHI sei, non solo che sei autorizzato"
- I grant type principali: **Authorization Code + PKCE** (utenti), **Client Credentials** (machine)
- In Cullis, OIDC è usato per gli **admin umani** delle dashboard, non per gli agenti
- Ogni org può avere il proprio **IdP** (Okta, Azure AD, Google) — federazione OIDC per-org
- Il **client secret** è cifrato con KMS — sicuro anche se il DB è compromesso
- **RFC 8693** (Token Exchange) è nella roadmap per la delegation chain: "l'agente agisce per conto di un utente"
- I **transaction token** sono un'implementazione parziale: monouso, TTL corto, actor chain

---

*Prossimo capitolo: [13 — Client Assertion (x509 + JWT)](13-client-assertion.md) — il flusso completo di login dell'agente*
