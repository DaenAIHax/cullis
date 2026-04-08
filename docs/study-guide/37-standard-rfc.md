# Capitolo 37 — Mappa degli Standard e RFC

> *"Non reinventare la ruota — usa quelle che hanno gia superato un milione di crash test."*

---

## Perche gli standard contano — spiegazione da bar

Immagina di costruire una casa. Puoi inventare il tuo sistema elettrico, i tuoi tubi, le tue prese. Ma quando chiami un elettricista, non sapra dove mettere le mani. E quando vendi la casa, nessuno si fidera dell'impianto "custom".

Gli **standard** e gli **RFC** (Request for Comments) sono come le norme edilizie: tutti li conoscono, tutti li rispettano, e quando dici "il mio sistema usa RFC 7519", un security engineer sa esattamente cosa aspettarsi.

Cullis non inventa protocolli — **compone standard esistenti** per risolvere un problema nuovo (trust federato tra agenti AI). Ogni componente e costruito su uno standard riconosciuto.

---

## La tabella di riferimento

```
┌────────────────────────┬──────────────────────────────────────┐
│     Standard / RFC     │         Dove Cullis lo usa           │
├────────────────────────┼──────────────────────────────────────┤
│  RFC 7519 (JWT)        │  Token di accesso, client assertion  │
│  RFC 7517 (JWK)        │  JWKS endpoint, chiavi pubbliche    │
│  RFC 7638 (JWK Thumb.) │  Key ID (kid), DPoP binding (jkt)   │
│  RFC 9449 (DPoP)       │  Proof of possession per-richiesta  │
│  RFC 8693 (Token Exch.)│  Transaction token                  │
│  RFC 5280 (x509)       │  Certificati agente e CA            │
│  SPIFFE                │  Identita agente (URI SAN)          │
│  NIST SP 800-207       │  Architettura Zero Trust            │
│  OWASP                 │  Checklist sicurezza                │
│  OpenTelemetry         │  Tracce, metriche, osservabilita    │
│  OPA / Rego            │  Policy decision (alternativa PDP)  │
│  MCP                   │  Protocollo tool proxy              │
└────────────────────────┴──────────────────────────────────────┘
```

---

## RFC 7519 — JSON Web Token (JWT)

**Cos'e:** Un formato compatto per trasmettere claim (affermazioni) tra due parti, firmato digitalmente.

**Analogia:** Un biglietto del treno con il tuo nome, la destinazione, e un timbro del controllore. Chiunque puo leggere il biglietto, ma solo il controllore puo timbrarlo. Se il timbro e autentico, il biglietto e valido.

**Dove Cullis lo usa:**
- **Token di accesso** emessi dal broker dopo l'autenticazione (`app/auth/jwt.py`, funzione `create_access_token`)
- **Client assertion** firmata dall'agente per autenticarsi (`app/auth/x509_verifier.py`, verifica del JWT nel step 9)
- **Transaction token** per operazioni singole approvate da umano (`app/auth/transaction_token.py`)

**Claim principali in Cullis:**
```
{
  "iss": "cullis-broker",              ← chi ha emesso il token
  "aud": "cullis",                     ← a chi e destinato
  "sub": "spiffe://atn.local/org/agent", ← identita SPIFFE
  "agent_id": "org::agent",            ← ID interno
  "org": "org_id",                     ← organizzazione
  "scope": ["purchase", "negotiate"],  ← capability autorizzate
  "cnf": {"jkt": "..."},              ← DPoP key binding
  "jti": "uuid-univoco",              ← anti-replay
  "exp": 1712678400                    ← scadenza
}
```

---

## RFC 7517 — JSON Web Key (JWK) / JWKS

**Cos'e:** Un formato JSON per rappresentare chiavi crittografiche, e un set di chiavi (JWKS).

**Analogia:** Una rubrica telefonica pubblica delle chiavi. Invece di scambiarsi le chiavi a mano, le pubblichi in un formato standard e chiunque puo trovarle.

**Dove Cullis lo usa:**
- **Endpoint JWKS** (`/.well-known/jwks.json`): pubblica la chiave di firma del broker in formato JWK, permettendo a chiunque di verificare i token emessi
- Conversione RSA PEM → JWK (`app/auth/jwks.py`, funzione `rsa_pem_to_jwk`)

> **In Cullis:** guarda `app/auth/jwks.py` per la conversione e `app/main.py` per l'endpoint JWKS.

---

## RFC 7638 — JWK Thumbprint

**Cos'e:** Un metodo per calcolare un identificatore univoco (thumbprint) di una chiave JWK usando SHA-256 sulla sua rappresentazione canonica.

**Analogia:** L'impronta digitale di una chiave. Due chiavi identiche producono la stessa impronta. E compatta, facile da confrontare.

**Dove Cullis lo usa:**
- **Key ID (kid)** del broker: calcolato come thumbprint della chiave pubblica di firma (`app/auth/jwks.py`, funzione `compute_kid`)
- **DPoP binding (jkt)**: il thumbprint della chiave DPoP dell'agente e nel claim `cnf.jkt` del token (`app/auth/dpop.py`, funzione `compute_jkt`)

Il thumbprint e calcolato con i soli membri "richiesti" della JWK, in ordine alfabetico:
- RSA: `{"e": ..., "kty": "RSA", "n": ...}`
- EC: `{"crv": ..., "kty": "EC", "x": ..., "y": ...}`

---

## RFC 9449 — DPoP (Demonstrating Proof of Possession)

**Cos'e:** Un meccanismo per legare un token di accesso a una chiave crittografica specifica, e dimostrare il possesso di quella chiave ad ogni richiesta.

**Analogia:** Un badge aziendale con la tua foto e impronta digitale. Non basta mostrare il badge (token) — devi anche mettere il dito sul lettore (prova di possesso) ogni volta che entri.

**Dove Cullis lo usa:**
- **Ogni richiesta API** richiede `Authorization: DPoP <token>` + header `DPoP: <proof-jwt>` (`app/auth/jwt.py`, funzione `get_current_agent`)
- **Autenticazione WebSocket**: il client deve inviare un `dpop_proof` nel messaggio auth (`app/broker/router.py`, step 2b)
- **Server nonce** (RFC 9449 sezione 8): il broker emette un nonce che il client deve includere nella prossima prova, eliminando problemi di clock skew (`app/auth/dpop.py`)

**12 verifiche del DPoP proof:**
```
1. JWT strutturalmente valido
2. typ == "dpop+jwt"
3. alg in {ES256, PS256}
4. jwk presente e pubblica (no "d")
5. jkt calcolabile
6. Firma valida
7. jti presente e non replayato
8. iat nella finestra temporale
9. htm corrispondente (GET/POST)
10. htu corrispondente (URL canonico)
11. ath == hash del token (se presente)
12. nonce del server valido
```

---

## RFC 8693 — Token Exchange

**Cos'e:** Un protocollo per scambiare un tipo di token con un altro, tipicamente per delegare un sottoinsieme di permessi.

**Dove Cullis lo usa:**
- **Transaction token**: dopo l'approvazione umana di una quota, il broker emette un token single-use legato a una specifica azione e payload hash (`app/auth/transaction_token.py`)
- Il flusso: token di accesso → approvazione dashboard → transaction token → esecuzione → token consumato

---

## RFC 5280 — x509 Certificates

**Cos'e:** Lo standard per i certificati a chiave pubblica (PKI), che definisce formato, estensioni, revoca e validazione della catena.

**Analogia:** Un passaporto internazionale. Emesso da un'autorita (CA), contiene la tua identita, ha una data di scadenza, e puo essere verificato da chiunque conosca l'autorita emittente.

**Dove Cullis lo usa:**
- **Certificato agente**: ogni agente ha un certificato x509 firmato dalla CA della sua organizzazione (`app/auth/x509_verifier.py`)
- **Verifica catena**: agent cert → org CA → broker CA
- **Estensioni verificate**: BasicConstraints (CA=true per le CA), ExtendedKeyUsage (clientAuth), SubjectAlternativeName (SPIFFE URI)
- **Revoca**: il serial number del certificato e controllato contro la lista di revoca (`app/auth/revocation.py`)
- **Algoritmi**: SHA-256+ obbligatorio, RSA >= 2048 bit, EC P-256/P-384/P-521

---

## SPIFFE — Secure Production Identity Framework for Everyone

**Cos'e:** Uno standard per le identita dei workload (servizi, agenti) in ambienti distribuiti. Definisce un formato URI per l'identita: `spiffe://trust-domain/path`.

**Analogia:** Un codice fiscale per i software. Ogni servizio ha un identificativo univoco e universale, indipendente dal server su cui gira.

**Dove Cullis lo usa:**
- **Identita agente**: l'internal ID `org::agent-name` viene convertito in SPIFFE ID `spiffe://atn.local/org/agent-name` (`app/spiffe.py`)
- **Claim JWT**: il campo `sub` del token contiene lo SPIFFE ID
- **Certificate SAN**: il certificato x509 dell'agente puo contenere lo SPIFFE ID come URI SAN, e il broker lo verifica (`app/auth/x509_verifier.py`, step 11)
- **Validazione**: trust domain, path component, e formato URI sono tutti validati secondo lo standard SPIFFE

---

## NIST SP 800-207 — Zero Trust Architecture

**Cos'e:** Il documento di riferimento del NIST che definisce l'architettura Zero Trust: principi, componenti (PEP, PDP), e modelli di deployment.

**Dove Cullis lo usa:**

| Principio NIST | Implementazione Cullis | File |
|---|---|---|
| Tutto e una risorsa | Ogni agente, sessione, messaggio e protetto | `app/broker/router.py` |
| Comunicazione sempre protetta | E2E encryption + TLS | `app/e2e_crypto.py` |
| Accesso per sessione | Sessioni scoped con TTL | `app/broker/session.py` |
| Policy dinamiche | PDP webhook + OPA, dual-org | `app/policy/engine.py` |
| Monitoraggio continuo | Audit hash chain + OpenTelemetry | `app/db/audit.py` |
| Default deny | Nessuna sessione senza policy allow | `app/policy/engine.py` |

---

## OWASP — Open Web Application Security Project

**Cos'e:** Una community che pubblica linee guida, strumenti e classifiche per la sicurezza delle applicazioni web. La piu nota e la OWASP Top 10.

**Dove Cullis lo usa:**
- **Injection detection**: regex + LLM judge per prompt injection inter-agent (`app/injection/detector.py`)
- **CSRF protection**: per-session token con `hmac.compare_digest` (`app/dashboard/session.py`)
- **Security headers**: CSP, HSTS, X-Frame-Options, nosniff su ogni risposta (`app/main.py`)
- **Input validation**: UUID regex per session_id, lunghezza massima per payload, required fields check (`app/broker/router.py`)

> Vedi il [Capitolo 34](34-owasp-agent.md) per l'analisi dettagliata.

---

## OpenTelemetry

**Cos'e:** Uno standard aperto per la raccolta di tracce distribuite, metriche e log da applicazioni cloud-native. Vendor-neutral.

**Analogia:** Le scatole nere degli aerei, ma per il software. Registrano tutto quello che succede, e quando qualcosa va storto, puoi ricostruire esattamente la sequenza di eventi.

**Dove Cullis lo usa:**
- **Tracce distribuite**: ogni operazione critica crea uno span (autenticazione, sessioni, policy, DPoP) (`app/telemetry.py`)
- **Metriche**: contatori per sessioni create/negate, policy allow/deny, rate limit rifiutati, latenza verifica x509 (`app/telemetry_metrics.py`)
- **Auto-instrumentazione**: SQLAlchemy, Redis, HTTPX sono instrumentati automaticamente
- **Esportazione OTLP/gRPC**: tracce e metriche inviate a Jaeger (o qualsiasi collector OpenTelemetry)
- **Graceful degradation**: se OTel non si inizializza, il sistema funziona con tracer/meter no-op

---

## OPA / Rego — Open Policy Agent

**Cos'e:** Un motore di policy general-purpose. Le policy sono scritte in Rego (un linguaggio dichiarativo). OPA espone un'API REST per valutare le policy.

**Analogia:** Un consulente legale esterno. Invece di codificare le regole nel software, le scrivi in un linguaggio separato e chiedi al consulente: "Questa operazione e permessa?"

**Dove Cullis lo usa:**
- **Backend PDP alternativo**: Cullis supporta due backend per le policy decision — webhook (per-org) e OPA (centralizzato) (`app/policy/opa.py`)
- **Configurazione**: `POLICY_BACKEND=opa` + `OPA_URL=http://opa:8181`
- **Validazione URL**: l'URL OPA viene validato per schema (http/https) e risoluzione DNS (no IP riservati/link-local)
- **Default-deny**: timeout, errori HTTP, risposte malformate → deny

---

## MCP — Model Context Protocol

**Cos'e:** Un protocollo di Anthropic per standardizzare l'interfaccia tra modelli AI e tool/risorse esterne. Definisce come un modello scopre, invoca, e riceve risultati dai tool.

**Dove Cullis lo usa:**
- **MCP Proxy**: gateway enterprise che interpone sicurezza tra l'agente e i tool (`mcp_proxy/`)
- **Tool registry**: definizione YAML dei tool con capability, domini autorizzati, e secret injection (`mcp_proxy/tools.yaml`)
- **Domain whitelist**: ogni tool dichiara i domini HTTP che puo contattare (`mcp_proxy/tools/http_whitelist.py`)
- **Capability check**: l'agente puo invocare solo i tool per cui ha la capability nel binding

---

## Mappa visiva — dove si incontrano gli standard

```
                         ┌─────────────────────┐
                         │   NIST SP 800-207    │
                         │   (architettura)     │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
    ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
    │   Identita      │   │   Autorizzaz.   │   │   Osservabilita │
    │                 │   │                 │   │                 │
    │ x509 (RFC 5280) │   │ OPA / Rego     │   │ OpenTelemetry   │
    │ SPIFFE          │   │ OWASP          │   │ Audit hash chain│
    │ JWT (RFC 7519)  │   │ Policy engine  │   │                 │
    │ JWK (RFC 7517)  │   │                 │   │                 │
    │ DPoP (RFC 9449) │   │                 │   │                 │
    └─────────────────┘   └─────────────────┘   └─────────────────┘
              │                     │
              ▼                     ▼
    ┌─────────────────┐   ┌─────────────────┐
    │   Binding       │   │   Tool Proxy    │
    │                 │   │                 │
    │ JWK Thumbprint  │   │ MCP             │
    │  (RFC 7638)     │   │ Domain whitelist│
    │ Token Exchange  │   │                 │
    │  (RFC 8693)     │   │                 │
    └─────────────────┘   └─────────────────┘
```

---

## Tabella di riferimento rapido

| Standard | RFC/Spec | Componente Cullis | File principale |
|---|---|---|---|
| JWT | RFC 7519 | Token, client assertion | `app/auth/jwt.py` |
| JWK/JWKS | RFC 7517 | Endpoint chiavi pubbliche | `app/auth/jwks.py` |
| JWK Thumbprint | RFC 7638 | kid, DPoP jkt | `app/auth/jwks.py`, `app/auth/dpop.py` |
| DPoP | RFC 9449 | Proof of possession | `app/auth/dpop.py` |
| Token Exchange | RFC 8693 | Transaction token | `app/auth/transaction_token.py` |
| x509 | RFC 5280 | Certificati agente/CA | `app/auth/x509_verifier.py` |
| SPIFFE | spiffe.io | Identita workload | `app/spiffe.py` |
| Zero Trust | NIST 800-207 | Architettura complessiva | `app/policy/engine.py` |
| OWASP | owasp.org | Checklist sicurezza | `app/injection/`, `app/main.py` |
| OpenTelemetry | opentelemetry.io | Tracce e metriche | `app/telemetry.py` |
| OPA/Rego | openpolicyagent.org | Policy decision | `app/policy/opa.py` |
| MCP | modelcontextprotocol.io | Tool proxy enterprise | `mcp_proxy/` |

---

## Riepilogo — cosa portarti a casa

- Cullis **non inventa protocolli** — compone standard esistenti e riconosciuti
- L'**identita** si basa su RFC 5280 (x509) + SPIFFE + RFC 7519 (JWT) + RFC 9449 (DPoP)
- L'**autorizzazione** usa OPA/Rego come alternativa al webhook PDP
- L'**osservabilita** e coperta da OpenTelemetry (tracce + metriche) e audit hash chain
- Il **tool proxy** usa MCP con domain whitelist per-tool
- La **sicurezza applicativa** segue le raccomandazioni OWASP
- L'**architettura** segue NIST SP 800-207 (Zero Trust Architecture)
- Ogni componente ha un file specifico nel codebase — la tabella di riferimento rapido sopra e il tuo punto di partenza

---

*Questo capitolo e un riferimento rapido. Per i dettagli di ogni standard, torna ai capitoli dedicati nella guida.*
