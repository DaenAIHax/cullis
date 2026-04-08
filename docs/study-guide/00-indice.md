# Cullis — Guida Completa allo Studio

> Ogni capitolo spiega la teoria, gli RFC/standard di riferimento, e come Cullis li implementa.

---

## Parte I — Fondamenti

### 01. Zero Trust Architecture
- Principi: never trust, always verify, least privilege
- NIST SP 800-207 — modello di riferimento
- Policy Enforcement Point (PEP) vs Policy Decision Point (PDP)
- Perché Zero Trust per agenti AI inter-organizzativi
- Come Cullis implementa Zero Trust: default-deny, DPoP binding, policy federata

### 02. Federazione e Trust Domain
- Federazione vs centralizzazione: pro e contro
- Trust domain: definizione, confini, root of trust
- ADFS/SAML come analogia per umani → Cullis come analogia per agenti
- Cross-organization trust: ogni org mantiene sovranità sulle proprie policy
- Architettura Cullis: Broker (control plane neutrale) + Proxy (data plane per org)

### 03. Threat Modeling per Agent-to-Agent
- STRIDE applicato ad agenti AI
- Superficie d'attacco: impersonazione, replay, prompt injection, MITM, rogue CA
- Threat model Cullis: 5 scenari prioritari e relative contromisure
- Chain of trust: da dove parte la fiducia e dove può rompersi

---

## Parte II — Crittografia e PKI

### 04. Crittografia Asimmetrica (RSA, ECDSA, ECDH)
- RSA: keypair, firma, cifratura, dimensioni (2048, 4096)
- Curva Ellittica: ECDSA (firma), ECDH (key agreement), curve P-256/P-384
- Confronto RSA vs EC: performance, sicurezza, casi d'uso
- Libreria `cryptography` in Python: generazione chiavi, serializzazione PEM/DER

### 05. Crittografia Simmetrica (AES-GCM)
- AES: block cipher, modalità (CBC, GCM, CTR)
- AES-256-GCM: authenticated encryption, nonce/IV, tag di autenticazione
- Additional Authenticated Data (AAD): perché e come usarlo
- Cullis: AES-256-GCM per payload E2E, session_id come AAD, sequence number anti-reorder

### 06. PKI — Public Key Infrastructure
- Concetti: CA, certificato, catena di fiducia, CRL, OCSP
- Struttura x509v3: Subject, Issuer, SAN, Key Usage, Extended Key Usage, validity
- PKI a 3 livelli Cullis: Broker CA (RSA-4096) → Org CA (RSA-4096) → Agent Cert (RSA-2048)
- Generazione certificati: `generate_certs.py`, auto-PKI nel MCP Proxy
- Verifica catena: `app/auth/x509_verifier.py` — come il broker valida un agent cert
- Certificate thumbprint pinning (SHA-256): prevenzione rogue CA swap

### 07. SPIFFE — Secure Production Identity Framework
- Problema: identità workload in ambienti distribuiti
- SPIFFE ID: formato URI `spiffe://trust-domain/path`
- SVID (SPIFFE Verifiable Identity Document): x509-SVID vs JWT-SVID
- SAN (Subject Alternative Name): dove va lo SPIFFE ID nel certificato
- Cullis: `spiffe://cullis.local/{org_id}/{agent_id}` — verifica SAN opzionale/obbligatoria
- SPIRE come implementazione di riferimento (non usato in Cullis, ma contesto)

### 08. Revoca Certificati
- CRL (Certificate Revocation List) vs OCSP (Online Certificate Status Protocol)
- Problemi: latenza, distribuzione, stapling
- Cullis: tabella `revoked_certs`, endpoint `/admin/certs/revoke`, check in-band
- Workflow: admin revoca → broker rifiuta auth → agent deve ri-registrarsi

---

## Parte III — Autenticazione e Token

### 09. JWT — JSON Web Token
- Struttura: Header.Payload.Signature (RFC 7519)
- Algoritmi di firma: HS256, RS256, ES256 — quando usare quale
- Claims standard: iss, sub, aud, exp, iat, jti
- RS256 in Cullis: il broker firma JWT con la propria CA key
- JTI (JWT ID): replay protection — blacklist con TTL (Redis o in-memory)

### 10. JWKS — JSON Web Key Set
- RFC 7517: formato JWK, parametri (kty, n, e, kid, use, alg)
- RFC 7638: JWK Thumbprint — calcolo deterministico del kid
- Endpoint `/.well-known/jwks.json`: discovery automatica delle chiavi pubbliche
- Key rotation: aggiungere nuova chiave, mantenere la vecchia per validazione
- Cullis: JWKS endpoint per validazione token da parte dei proxy e agent

### 11. DPoP — Demonstration of Proof-of-Possession
- Problema: bearer token rubato → impersonazione
- RFC 9449: DPoP proof JWT, binding token→chiave, server nonce
- Flusso: client genera EC P-256 ephemeral → DPoP proof in header → server verifica binding
- Server nonce rotation (Section 8): anti-replay
- `jkt` claim: SHA-256 thumbprint della chiave pubblica DPoP nel token
- Cullis: `app/auth/dpop.py` — implementazione completa, binding bidirezionale

### 12. OAuth 2.0 e OIDC Federation
- OAuth 2.0: Authorization Code, Client Credentials, PKCE
- OpenID Connect: ID Token, UserInfo, Discovery (`.well-known/openid-configuration`)
- OIDC per Cullis: login organizzazioni via Okta/Azure AD/Google
- Per-org IdP config: ogni organizzazione può avere il proprio Identity Provider
- Client secret encrypted at rest via KMS
- RFC 8693: Token Exchange — actor chain per delegation (roadmap Cullis)

### 13. Client Assertion (x509 + JWT)
- `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- Costruzione: JWT RS256 firmato con chiave privata dell'agente
- Header x5c: catena certificati in base64 DER
- Flusso completo login Cullis: agent → client_assertion → broker verifica x509 chain → emette JWT+DPoP

---

## Parte IV — Messaging e Sessioni

### 14. End-to-End Encryption
- Perché E2E: il broker non deve leggere i messaggi (zero-knowledge forwarding)
- Key Encapsulation: RSA-OAEP-SHA256 per wrappare la session key AES
- Payload: AES-256-GCM con AAD (session_id + sequence number)
- Dual signing RSA-PSS: inner sign (non-repudiation del mittente) + outer sign (integrità trasporto)
- Sequence number: protezione anti-reorder
- `cullis_sdk/crypto/e2e.py` e `message_signer.py`: implementazione

### 15. Sessioni Inter-Agente
- Modello sessione: initiator apre → policy check → responder accetta/rifiuta
- Capability-scoped: ogni sessione specifica le capability richieste
- Ciclo di vita: open → pending → active → closed
- WebSocket push: notifiche real-time per nuove sessioni/messaggi
- Session management nel broker: `app/broker/session_store.py`

### 16. Discovery e RFQ
- Discovery multi-modale: agent_id, SPIFFE URI, org_id, glob pattern, capability
- Filtri combinabili: "tutti gli agenti dell'org X con capability supply"
- RFQ (Request for Quote): broadcast a supplier matching → raccolta quote con timeout
- Transaction tokens: single-use, TTL-bound, payload-hash-verified
- `app/registry/discovery.py`, `app/broker/rfq.py`

---

## Parte V — Policy Engine

### 17. Policy Architecture — Dual-Org Evaluation
- PEP (broker) vs PDP (per-org webhook o OPA)
- Default-deny: nessuna sessione procede senza allow esplicito da entrambe le org
- Policy evaluation flow: broker chiama PDP org A + PDP org B → entrambi devono dare allow
- Tipi di policy: session policy, message policy, capability policy
- Role-based: initiator_role + responder_role determinano le regole

### 18. Open Policy Agent (OPA) e Rego
- OPA: cos'è, architettura (data + policy → decisione)
- Rego: linguaggio dichiarativo per policy
- Integrazione Cullis: OPA come backend alternativo, Rego policies incluse
- Bundle Docker Compose sidecar: deploy OPA accanto al broker
- Scrivere policy Rego per Cullis: input schema, esempi

### 19. PDP Webhook
- Pattern: broker HTTP POST al PDP dell'org con contesto sessione/messaggio
- Payload: initiator, responder, capabilities, org_ids
- Risposta: `{"allow": true/false, "reason": "..."}`
- Template PDP in `enterprise-kit/`: regole configurabili + forwarding OPA opzionale
- Timeout, retry, fallback (default-deny su errore)

---

## Parte VI — Infrastruttura e Deploy

### 20. FastAPI — Framework Web
- ASGI, dependency injection, Pydantic validation, OpenAPI auto-docs
- Middleware: CORS, CSRF, security headers, rate limiting
- WebSocket: gestione connessioni, auth, heartbeat
- Background tasks e lifespan events
- Struttura Cullis: router modulare, dependency override per test

### 21. SQLAlchemy Async + Alembic
- SQLAlchemy 2.0: async engine, session, mapped classes
- Pattern: `async with AsyncSession() as session`
- Alembic: migration management, auto-generate, versioning
- Cullis: SQLite per dev/proxy, PostgreSQL 16 per broker production
- StaticPool per test in-memory

### 22. Docker e Docker Compose
- Container: immagine, layer, multi-stage build
- Docker Compose: service definition, networking, volumes, health checks
- Cullis: `docker-compose.yml` (broker), `docker-compose.proxy.yml` (proxy)
- Networking: bridge network, service discovery DNS
- Deploy script: `deploy.sh` — one-command setup

### 23. HashiCorp Vault
- Cos'è: secrets management, dynamic secrets, encryption as a service
- KV v2: versioned secrets, metadata
- Cullis KMS adapter: `app/kms/` — local filesystem (dev) o Vault (prod)
- Proxy + Vault: chiavi private agenti in Vault, mai su disco
- `login_from_pem()`: per secret manager — chiave mai su filesystem

### 24. Redis
- Strutture dati: strings, sets, sorted sets, pub/sub
- Uso in Cullis: JTI blacklist (replay protection), rate limiting (sliding window), WebSocket pub/sub
- Fallback in-memory per dev senza Redis
- TTL-based expiry per JTI e rate limit counters

### 25. Nginx e TLS
- Reverse proxy: terminazione TLS, proxy_pass, WebSocket upgrade
- Certificati TLS: Let's Encrypt, self-signed per dev
- Configurazione Cullis: porta 8443 HTTPS → 8000 HTTP interno
- Security headers: HSTS, CSP, X-Frame-Options

### 26. PostgreSQL
- Perché Postgres: ACID, JSON, full-text search, performance
- Connection pooling: asyncpg + SQLAlchemy async
- Migration: Alembic per schema evolution
- Cullis: broker production usa Postgres 16, dev usa SQLite

---

## Parte VII — Observability e Audit

### 27. Audit Ledger Crittografico
- Audit log append-only: evento + SHA-256 hash chain
- Tamper detection: verificare l'integrità della catena
- Export: NDJSON e CSV con filtri (date, org, event type)
- SIEM integration: Splunk, Datadog, ELK-ready
- `app/db/audit.py`: implementazione, `log_event()` + SSE hook

### 28. OpenTelemetry e Jaeger
- OpenTelemetry: traces, metrics, logs — standard vendor-neutral
- Instrumentazione automatica: FastAPI, SQLAlchemy, Redis, HTTPX
- Custom spans e metrics per operazioni Cullis
- Jaeger: distributed tracing UI, porta 16686
- Configurazione: `OTEL_EXPORTER_*` env vars

### 29. Dashboard Real-Time (SSE)
- Server-Sent Events vs WebSocket vs polling
- `app/dashboard/sse.py`: manager SSE, broadcast per categoria
- Hook in `log_event()`: ogni evento → notifica SSE
- Frontend: EventSource JS, indicatore "Live", refresh selettivo per pagina

---

## Parte VIII — SDK e Integrazioni

### 30. Python SDK (cullis-agent-sdk)
- Architettura: `CullisClient` come entry point unico
- Auth: x509 + DPoP, tutto gestito internamente
- Metodi: login, discover, open/accept/close session, send, RFQ, transaction tokens
- Crypto bundle: `cullis_sdk.crypto` (message_signer, e2e) — zero dipendenze dal broker
- Packaging: pyproject.toml, hatchling, `pip install cullis-agent-sdk`

### 31. MCP — Model Context Protocol
- Cos'è MCP: protocollo per dare tool agli LLM (Anthropic standard)
- Trasporti: stdio, SSE, HTTP
- Tool definition: nome, descrizione, schema parametri
- `cullis_sdk/mcp_server.py`: 10 tool MCP
- Configurazione Claude Desktop/Code come MCP server
- Qualsiasi LLM MCP-compatibile → agente Cullis con zero codice

### 32. TypeScript SDK
- `sdk-ts/`: BrokerClient per Node.js
- Login, discover, sessions, E2E send, RFQ, transaction tokens
- Pattern e differenze rispetto al Python SDK

### 33. MCP Proxy — Enterprise Gateway
- Ruolo: semplifica l'adozione per le organizzazioni
- Auto-PKI: genera CA e cert agenti, nessun openssl manuale
- API Key auth locale: agenti interni usano API key, il proxy gestisce x509/DPoP
- Dashboard: register org, create agents, PKI management, Vault config
- Flusso: invite token → register → approve → create agents → ready
- Ingress vs Egress: inbound (JWT+DPoP dal broker) vs outbound (API key da agenti locali)

---

## Parte IX — Sicurezza Applicativa

### 34. OWASP Top 10 per Agent Systems
- Injection: prompt injection inter-agente, SQL injection, command injection
- SSRF: domain whitelist nel MCP Proxy
- CSRF: per-session token, timing-safe verification
- Broken Authentication: certificate pinning, DPoP binding
- Security Headers: CSP, X-Frame-Options DENY, HSTS, nosniff

### 35. WebSocket Security
- Origin validation
- Auth timeout: connessione chiusa se non autenticata entro N secondi
- Connection limits: per-agent, per-org
- Binding check: WebSocket legato alla sessione autenticata
- Heartbeat/keepalive

### 36. Rate Limiting
- Sliding window: per-endpoint, per-agent
- Backend: Redis (prod) o in-memory (dev)
- Configurazione per endpoint
- Protezione da brute-force e DoS

---

## Parte X — Standard e RFC di Riferimento

### 37. Mappa degli Standard
| Standard | Dove in Cullis |
|---|---|
| RFC 7519 (JWT) | Token broker, client assertion |
| RFC 7517 (JWK) | JWKS endpoint |
| RFC 7638 (JWK Thumbprint) | kid calculation, DPoP jkt |
| RFC 9449 (DPoP) | Token binding |
| RFC 8693 (Token Exchange) | Transaction tokens, actor chain |
| RFC 5280 (x509) | Certificati PKI |
| SPIFFE | Agent identity URI |
| NIST SP 800-207 | Zero Trust Architecture |
| OWASP | Security hardening |
| OpenTelemetry | Observability |
| OPA / Rego | Policy engine |
| MCP (Anthropic) | LLM tool protocol |

---

## Appendici

### A. Glossario
- Tutti i termini tecnici usati nella guida

### B. Comandi di Riferimento
- Setup, deploy, test, admin, demo

### C. Architettura Visuale
- Diagrammi Mermaid: flusso auth, sessione E2E, policy evaluation
