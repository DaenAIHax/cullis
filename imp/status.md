# Cullis — Status: cosa c'e e cosa manca

Ultimo aggiornamento: 2026-04-12 sessione 8 (attach-CA, smoke production-grade, deploy hardening + runbook)

---

## FATTO

### Identita e autenticazione
- [x] PKI a 3 livelli: Broker CA > Org CA > Agent Certificate
- [x] SPIFFE ID nel SAN x509 (`spiffe://trust-domain/org/agent`)
- [x] JWT RS256 firmati dal broker con chiave KMS
- [x] DPoP (RFC 9449) — token bound a chiave EC P-256 efimera, obbligatorio su ogni endpoint
- [x] JTI replay protection per client_assertion e DPoP proof
- [x] DPoP Server Nonce (RFC 9449 §8) — nonce server-side, rotazione 5 min, grace period, retry automatico nel SDK
- [x] Certificate Thumbprint Pinning — SHA-256 del cert pinnato al primo login, anti Rogue CA
- [x] Certificate Rotation — endpoint API + dashboard per rotazione esplicita con validazione CA chain
- [x] Revoca certificati (admin, preventiva)
- [x] Revoca token (self-service + admin per org)

### Crittografia messaggi
- [x] E2E AES-256-GCM + RSA-OAEP-SHA256 (il broker non legge il plaintext)
- [x] Doppia firma RSA-PSS: inner (non-repudiation) + outer (transport integrity)
- [x] Formato canonico per firma: `session_id|sender|nonce|timestamp|canonical_json`
- [x] AAD legato alla sessione (previene cross-session replay)

### Policy e autorizzazione
- [x] PDP Webhook federato — il broker chiama entrambe le org, default-deny
- [x] Binding org-agente con approvazione esplicita
- [x] Scope capability sulle sessioni (deve essere nel binding di entrambi)
- [x] Autorizzazione basata solo su capabilities (ruoli rimossi — semplificazione architetturale)
- [x] Rate limiting sliding window per endpoint/agente

### Infrastruttura
- [x] KMS Adapter pattern (local filesystem / HashiCorp Vault KV v2)
- [x] WebSocket push real-time + fallback REST polling
- [x] Audit log append-only (no UPDATE/DELETE)
- [x] Capability discovery cross-org
- [x] Onboarding flow (join > admin review > approve/reject)
- [x] Persistenza sessioni su PostgreSQL con restore al restart
- [x] SDK Python per agenti (auth, DPoP, E2E, firma, WebSocket)

### Deployment
- [x] Docker Compose (broker, postgres, vault, redis, mock PDP x2, nginx TLS)
- [x] Nginx reverse proxy con TLS self-signed (HTTPS, WebSocket wss://, proxy headers)
- [x] setup.sh one-command (PKI, TLS cert, container, Vault init)
- [x] Dockerfile broker (proxy-headers per forwarded proto)
- [x] generate_demo_certs.py per org demo (locale, non nel repo)
- [x] **Deploy hardening production-ready (2026-04-12)**:
  - `docker-compose.prod.yml` fail-fast `${VAR:?}` su ADMIN_SECRET/DASHBOARD_SIGNING_KEY/VAULT_TOKEN
  - `vault/init-vault.sh` genera scoped broker token (policy `secret/data/broker` only), no root token nel broker env
  - `scripts/generate-env.sh --prod` scrive REDIS_PASSWORD + VAULT_ALLOW_HTTP=false + POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=false
  - `deploy_broker.sh` (enterprise) pre-flight validation blocca boot se .env ha valori default
- [x] **MCP Proxy deploy hardening (2026-04-12)**:
  - `proxy.env.example` + `scripts/generate-proxy-env.sh` simmetrici al broker
  - `docker-compose.proxy.standalone.yml` override per deploy remote broker (bridge net)
  - `docker-compose.proxy.prod.yml` fail-fast sui vars richiesti
  - Mount `/certs` per custom CA bundle su broker HTTPS con CA aziendale
- [x] **Runbook operativo** `docs/operations-runbook.md` — 8 scenari incident response

### Onboarding avanzato
- [x] **Flusso `/onboarding/attach`** (2026-04-12) — admin pre-registra org, emette invite bound a org_id, proxy carica CA + ruota secret in unico call. Copre caso "azienda partecipante installa proxy dopo che broker admin ha già creato l'org" (vs `/join` generico)
- [x] Invite token tipizzati (`org-join` vs `attach-ca`), `validate_and_consume(expected_type=...)` + `inspect_invite` non-consuming

### Smoke test production-grade
- [x] **`./demo_network/smoke.sh full`** (2026-04-12) — one-command pre-merge gate, ~75-120s, 12 servizi, stack production-like reale (Postgres + Redis + Vault HTTPS + policy enforcement ON)
- [x] 8 assertion automatiche (A1 Vault scoped token, A2 PDP ALLOW+DENY, A3 SSRF unit test, A4 dashboard key persistence, A5 cert revoke, A6 binding revoke, A7 audit hash chain, A8 MCP proxy ingress JWT+DPoP+nonce)
- [x] CI workflow `.github/workflows/smoke.yml` come gate di ogni PR (path-filter skippa docs-only)

### Kit integrazione enterprise
- [x] Guida "Bring Your Own CA" (`enterprise-kit/BYOCA.md`) — step-by-step per reparto sicurezza
- [x] Template Docker Compose agente (`enterprise-kit/docker-compose.agent.yml`)
- [x] Template PDP webhook con regole configurabili (`enterprise-kit/pdp-template/`)
- [x] Script quickstart interattivo (`enterprise-kit/quickstart.sh`) — genera CA, cert, registra org+agente
- [x] Regole di esempio (`pdp-template/rules.json`) — allowed orgs, capabilities, blocked agents

### Redis (multi-worker ready)
- [x] Connection pool async con graceful fallback a in-memory
- [x] DPoP JTI store Redis (SET NX EX atomico, zero race condition)
- [x] Rate limiter Redis (sorted set sliding window, pipeline atomica)
- [x] WebSocket Pub/Sub (local-first, Redis cross-worker fallback)
- [x] Background listener per messaggi Redis su canali `ws:agent:{id}`

### Dashboard multi-ruolo
- [x] Login unificato (user + password) — admin o org, singolo form
- [x] Cookie firmato HMAC-SHA256 (scadenza 8h, httponly, secure, samesite=lax)
- [x] Ruolo admin: vede tutto, onboard org, approve/reject, register agent ovunque
- [x] Ruolo org: vede solo propri agenti/sessioni/audit, registra agenti solo propri
- [x] Organizations page (admin-only, nascosta dalla sidebar per org user)
- [x] Overview con stats filtrate per ruolo
- [x] Agents con capabilities, binding status, WebSocket live
- [x] Sessions con filtro status, scoped per org
- [x] Sessions: bottone Close per admin su sessioni active/pending (broker dashboard)
- [x] Sessions: auto-close pending dopo 60s inattivita (background reaper, 15s sweep)
- [x] Sessions: API close accetta anche sessioni pending (non solo active)
- [x] Audit Log con ricerca full-text, scoped per org
- [x] Form "Onboard Org" (admin): CA PEM, webhook URL, approve diretto
- [x] Form "Register Agent": dropdown org, agent name, capabilities, binding auto-approvato
- [x] Delete agent dalla pagina Agents (con revoca binding)
- [x] Policies page: lista session policy per org, create form (org, target org, capabilities, effect), deactivate
- [x] Bottoni Approve/Reject su org pending
- [x] Badge HTMX nella sidebar: contatore org pending e sessioni pending (auto-refresh 10s)
- [x] Notifiche persistenti in DB (session_pending, cleared on accept)
- [x] Endpoint REST `GET /broker/notifications` per agenti
- [x] Audit log row expand (click per aprire dettaglio completo: JSON, hash, session, request ID)
- [x] 35 test, dark theme, Tailwind + HTMX, zero build frontend
- [x] Link "Traces" nella sidebar (admin-only) → apre Jaeger UI in nuova tab
- [x] Self-registration pubblica (`/dashboard/register`) — org in status pending, admin approva
- [x] Settings page per org (`/dashboard/settings`) — upload CA certificate con lock/unlock
- [x] Admin unlock CA certificate dalla pagina orgs
- [x] Agent bundle download (zip: cert, key, .env, start.sh, SDK, demo scripts)
- [x] Root redirect `/` → `/dashboard/login`
- [x] Sidebar: policies nascosto per org user, settings visibile solo per org user
- [x] `register_org()` accetta parametro `status` (default active, self-registration usa pending)
- [x] Agent developer portal (`/dashboard/agents/{id}`) — pagina stile Stripe/Twilio per agente
- [x] Agent info: status, capabilities, binding, WebSocket live/offline, cert expiry
- [x] Credentials: Option 1 BYOCA upload cert (production), Option 2 generate demo (dev only)
- [x] Upload cert valida: PEM parse, CN == agent_id, firma CA org chain
- [x] Credentials-only download (zip: agent.pem + agent-key.pem + agent.env)
- [x] Integration guide con tab Python/TypeScript/cURL, snippet pre-compilati, copy button
- [x] Recent activity: ultimi 10 eventi audit per agente
- [x] RFQ list page (`/dashboard/rfqs`) + detail page (`/dashboard/rfq/{id}`) con quote e approve
- [x] RFQ approval emette transaction token e lo invia via WebSocket

### Production readiness
- [x] `.env.example` completo con tag [REQUIRED]/[PRODUCTION], comandi generazione secrets
- [x] `docker-compose.prod.yml` — override produzione: restart policy, resource limits, JSON logging
- [x] `docs/ops-runbook.md` — 9 sezioni: deploy, update, backup, key rotation, revocation, monitoring, audit, troubleshooting, checklist

### SDK TypeScript
- [x] `sdk-ts/` — SDK completo per Node.js/TypeScript
- [x] BrokerClient: login, discover, sessions, send E2E, poll, RFQ, transaction tokens
- [x] auth.ts: client assertion RS256 + DPoP ES256 (RFC 9449)
- [x] crypto.ts: AES-256-GCM + RSA-OAEP + RSA-PSS (match esatto del Python)
- [x] types.ts, utils.ts, README.md, examples/basic-agent.ts

### Migrazione PyJWT
- [x] python-jose → PyJWT[crypto] — fix CVE-2024-33663 e CVE-2024-33664
- [x] 11 file migrati (source + test), zero regressioni

### SDK Python — secret manager support
- [x] `login_from_pem(agent_id, org_id, cert_pem, key_pem)` — accetta PEM string direttamente
- [x] Supporto Vault, AWS KMS, Azure Key Vault — chiave privata mai su disco
- [x] `login()` delega a `login_from_pem()` dopo lettura file

### Dashboard security hardening
- [x] CSRF token per-session (random 16 byte in cookie, hidden field su ogni form POST, verify timing-safe)
- [x] Auth enforcement su approve/reject org (require_login + admin check)
- [x] Auth enforcement su badge endpoints (no data leak a utenti non autenticati)
- [x] Badge pending sessions scoped per org (org user vede solo le proprie)
- [x] Cookie `secure=True` (trasmesso solo su HTTPS)
- [x] Security headers middleware: X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy, CSP su /dashboard
- [x] Input validation: org_id/agent_id regex alfanumerico max 128 char, webhook URL scheme check (http/https), capabilities format/count limit, display name max length
- [x] 15 test di sicurezza dedicati (CSRF, auth enforcement, security headers, input validation)

### Demo scenario ERP-triggered
- [x] `demo/generate_org_certs.py` — genera CA org o cert agente (--org / --agent), separati
- [x] `demo/create_policies.py` — crea session policy bidirezionali tra due org
- [x] `demo/inventory.json` — inventario simulato con soglie e config buyer agent
- [x] `demo/inventory_watcher.py` — monitor inventario, triggera buyer automaticamente
- [x] `demo/buyer_agent.py` — agente on-demand: auth, discover, negoziazione JSON ibrida (LLM + structured), WebSocket, salva risultato
- [x] `demo/supplier_agent.py` — agente daemon: WebSocket in ascolto, risponde con catalogo via LLM + JSON strutturato
- [x] PDP webhook skip se non configurato (allow) — permette demo senza mock PDP
- [x] Cookie `secure` condizionale (solo HTTPS) — fix login su localhost HTTP

### OpenTelemetry (traces + metrics)
- [x] TracerProvider + MeterProvider con OTLP/gRPC exporter a Jaeger
- [x] Auto-instrumentation: FastAPI, SQLAlchemy, Redis, HTTPX
- [x] Custom spans: `auth.issue_token`, `auth.x509_verify`, `auth.x509_chain_verify`, `broker.create_session`, `pdp.webhook_call`
- [x] Counters: auth success/deny, session created/denied, policy allow/deny, rate limit reject
- [x] Histograms: auth duration, x509 verify duration, PDP webhook latency
- [x] Jaeger all-in-one in docker-compose (UI su porta 16686)
- [x] Graceful degradation: broker funziona anche senza Jaeger
- [x] OTel disabilitato nei test (`OTEL_ENABLED=false`)

### GitHub repo
- [x] Repo privato su GitHub (`DaenAIHax/Agent-Trust-Network`)
- [x] `.gitignore` configurato: file locali (appunti, script CLI, cert, config Claude) esclusi dal repo
- [x] README.md ufficiale con architettura WIMSE/CB4A, deployment generico
- [x] Solo codice core su GitHub: `app/`, `agents/`, `tests/`, `enterprise-kit/`, `nginx/`, Docker, setup

### Deploy Docker (testato end-to-end)
- [x] `./setup.sh` one-command: PKI, TLS cert, container build, Vault init, health check
- [x] Nginx HTTPS su porta 8443 (self-signed), WebSocket wss:// proxy
- [x] DPoP HTU corretto con `BROKER_PUBLIC_URL=https://localhost:8443`
- [x] Vault KMS async fix (`await` su `client.get`)
- [x] SDK `verify_tls=False` per self-signed localhost, WebSocket SSL context
- [x] Demo agenti (supplier + buyer) funzionanti via HTTPS + wss://

### Database & Migrations
- [x] Alembic migrations — sostituito `create_all` con migrazioni versionabili
- [x] Migrazione iniziale con tutte le 10 tabelle (473ecda4a4ca)
- [x] `SKIP_ALEMBIC=1` per test (SQLite in-memory con `create_all`)
- [x] `DATABASE_URL` env var per override in produzione

### API Versioning
- [x] Tutti gli endpoint API sotto `/v1/` (auth, registry, broker, policy, onboarding, admin)
- [x] Dashboard e health non versionati
- [x] SDK, agenti demo, bootstrap aggiornati

### Nonce Atomicity (anti-replay after crash)
- [x] `save_message()` usa `INSERT ON CONFLICT DO NOTHING` — DB e source of truth per nonce
- [x] In-memory `used_nonces` e solo cache (fast-path reject)
- [x] Rollback in-memory automatico se DB insert fallisce

### JWKS + Key Rotation Infrastructure
- [x] `GET /.well-known/jwks.json` — endpoint pubblico con chiave broker in formato JWK (RFC 7517)
- [x] `kid` nel JWT header — JWK Thumbprint SHA-256 (RFC 7638)
- [x] `Cache-Control: public, max-age=3600` sull'endpoint JWKS
- [x] Infrastruttura per key rotation (kid-based key selection)

### E2E AAD con Client Sequence Number (anti-reordering)
- [x] `client_seq` nel AAD di AES-256-GCM — previene reordering attack MitM
- [x] Counter client-side per-session auto-incrementante
- [x] Incluso in firma interna (non-repudiation) e firma esterna (transport integrity)
- [x] Backward compatible — `client_seq=None` usa formato AAD vecchio
- [x] Migrazione Alembic per colonna `client_seq` in `session_messages`

### Structured Logging
- [x] `LOG_FORMAT=json` per output JSON single-line (SIEM-ready)
- [x] `JsonFormatter` con timestamp, level, logger, message, extra, exception
- [x] Toggle via env var, text mode default (noop)

### Session Reject
- [x] `POST /sessions/{id}/reject` — target agent rifiuta sessione pending
- [x] Status denied, WS notification all'initiator, audit log

### Audit Log Hash Chain
- [x] SHA-256 hash chain su ogni entry (`entry_hash`, `previous_hash`)
- [x] `verify_chain()` walker per verificare integrita completa
- [x] Dashboard: bottone "Verify Hash Chain" (admin-only), colonna hash
- [x] Tamper detection: qualsiasi modifica rompe la catena

### OIDC Federation
- [x] OIDC login per org admin (ogni org configura il suo IdP: Okta, Azure AD, Google)
- [x] OIDC login per network admin (provider globale via env var)
- [x] admin_secret resta come fallback per bootstrap/emergenze
- [x] OAuth 2.0 Authorization Code Flow con PKCE (RFC 7636)
- [x] State in cookie firmato (anti-CSRF), nonce (anti-replay), redirect_uri hardcoded
- [x] SSO tab nella login page, OIDC config nell'org onboarding, badge SSO nella tabella orgs
- [x] Migrazione Alembic per colonne OIDC su organizations

### Test
- [x] 478+ test, 45 file (inclusi 11 proxy smoke test, 17 enrollment, 9 network directory)
- [x] PKI effimera in-memory per i test (nessuna dipendenza da filesystem)
- [x] SQLite in-memory per test unitari
- [x] Mock PDP webhook nel conftest

### Security Audit Round 1 (2026-04-04)
- [x] 6 critical fix (JTI race condition, policy webhook default-deny, rate limiter Lua atomica)
- [x] 8 high fix (x509 key size check, CORS, SSRF protection, WebSocket hardening, timing attacks)
- [x] 9 medium fix (unicode normalization, DPoP nonce lock, binding scope validation, cookie signing key separata)
- [x] Low fix (HSTS, Cache-Control, Italian strings translated)
- [x] Dashboard hardening (CSP unsafe-inline removed, login rate limit, Pydantic size limits, input validation)
- [x] Fix residui: SSRF DNS pinning con TLS SNI, WebSocket binding check, audit chain race condition lock

### Security Audit Round 2 (2026-04-05)
- [x] 4 HIGH fix: CSRF bypass await, Vault TLS enforcement, session store memory DoS eviction, python-jose CVE tracked
- [x] 14 MEDIUM fix: HKDF random salt, message signer sanitization, EC curve whitelist, WS Origin validation, WS auth timeout, session state locking, closed session polling block, dual-org policy engine, org endpoint auth, onboarding/agent input validation regex, OPA SSRF protection, pending org agent registration block
- [x] 10 LOW fix: constant-time thumbprint, revocation cleanup buffer, KMS backend RuntimeError, session pagination, polling rate limit, message rollback, session_id UUID validation, binding re-approve block, logout POST+CSRF, proxy-headers documentation
- [x] 73 nuovi test (3 file), lavoro parallelizzato su 3 terminali concorrenti

### Security Audit Round 3 (2026-04-05)
- [x] C2: Org isolation su `GET /agents/{id}` e `/public-key` — richiede same-org o approved binding
- [x] H1: XSS fix in audit template (escape esplicito su attributo `title`)
- [x] H2: Nonce cache DoS — eviction (set.pop) invece di blanket deny a 100K
- [x] H3: Timing attack org secret — `verify_org_credentials()` con dummy bcrypt hash, sempre constant-time
- [x] H4: Context field validation — depth max 4 livelli, solo string keys
- [x] 11 nuovi test in `tests/test_audit_r3.py`
- [x] False positive verificati: C1 (session enumeration — gia filtrata per agent_id), C3 (save_session gia dentro lock)

### CI/CD Green
- [x] Ruff lint: 146 errori fixati (F401, F841, F811, E712) in 35+ file
- [x] E402 ignorato (pattern intenzionale: env setup prima degli import)
- [x] Pin `fastapi<1.0`, `starlette<1.0` per compat TemplateResponse API
- [x] **464+ test verdi (3 skip: postgres integration richiede Docker)**
- [x] Security job (pip-audit) verde
- [x] Alembic migration verification in CI (upgrade head su DB pulito)
- [x] Ephemeral KMS provider nel conftest (test non dipendono da certs/ su disco)
- [x] Admin secret cache reset tra test (no stale bcrypt hash)

### Production Deployment Automation (2026-04-06)
- [x] `deploy.sh` — one-command con modalità dev/prod/Let's Encrypt
- [x] `vault/config.hcl` — file storage backend per Vault produzione
- [x] `vault/init-vault.sh` — init + unseal Shamir 5/3, idempotente
- [x] `scripts/pg-backup.sh` — pg_dump giornaliero, 30-day rotation, gzip
- [x] `scripts/pg-restore.sh` — restore con conferma interattiva
- [x] `validate_config()` — blocca boot in prod se config critiche mancano
- [x] `ENVIRONMENT` env var — development/production per startup strictness
- [x] CORS default vuoto (fail-safe), WebSocket origin check allineato
- [x] README.md riscritto — features, SDKs, enterprise, security, positioning

### Community & Open Source
- [x] LICENSE Apache 2.0
- [x] CONTRIBUTING.md (dev setup, PR workflow, code conventions)
- [x] SECURITY.md (private vulnerability reporting, response timeline)
- [x] GitHub issue templates (bug, feature, security redirect)
- [x] Pull request template con checklist
- [x] GitHub Actions CI (pytest, ruff lint, pip-audit)
- [x] Dipendenze aggiornate: cryptography 46.0.6, python-jose 3.4+, python-multipart 0.0.22+
- [x] 7 CVE risolte (cryptography, python-jose, python-multipart, starlette)
- [x] Pin minimi in requirements.txt (>=) invece di esatti (==)
- [x] Test postgres skippati in CI (nessun container)
- [x] 478+ test, 45 file (inclusi 11 proxy smoke test, 17 enrollment, 9 network directory)

### Rebrand → Cullis (2026-04-06)
- [x] Dominio `cullis.io` registrato su Cloudflare
- [x] Rebrand completo: README, CONTRIBUTING, SECURITY, ops-runbook, issue templates
- [x] Dashboard: login, base, register, overview → "Cullis"
- [x] FastAPI app title → "Cullis — Federated Trust Broker"
- [x] OTEL_SERVICE_NAME → `cullis-broker`
- [x] deploy.sh, setup.sh, scripts, vault config → header "Cullis"
- [x] SDK Python + TypeScript → docstrings "Cullis"
- [x] Enterprise kit: BYOCA, quickstart, PDP template, OPA → "Cullis"
- [x] Landing page (docs/index.html) → "Cullis"

### Sprint 5A: Enterprise Readiness (2026-04-05)
- [x] `threading.Lock` → `asyncio.Lock` (rate limiter, DPoP JTI store) + rimozione lock non necessario da DPoP nonce
- [x] OIDC client secret encryption via KMS (HKDF-SHA256 + Fernet, prefisso `enc:v1:`, legacy plaintext passthrough)
- [x] `GET /healthz` (liveness) + `GET /readyz` (readiness: DB + Redis + KMS check)
- [x] `GET /v1/admin/audit/export` — NDJSON o CSV, filtri date/org/event_type, admin-only, streaming
- [x] 23 nuovi test (KMS encryption, health, audit export)

### Sprint 5B: OPA Policy Integration (2026-04-05)
- [x] OPA adapter (`app/policy/opa.py`) — REST client per Open Policy Agent, default-deny su errore/timeout
- [x] Policy backend dispatcher (`app/policy/backend.py`) — `POLICY_BACKEND=webhook|opa`
- [x] Rego policy completa (`enterprise-kit/opa/policy/atn/session.rego`) — allowed_orgs, blocked_agents, capabilities
- [x] PDP template con flag `--opa-url` per forwarding a OPA
- [x] `docker-compose.opa.yml` per deploy OPA sidecar
- [x] 9 nuovi test (OPA allow/deny/timeout/error, backend dispatch, backward compat)

### Enterprise Demo Lab (2026-04-05)
- [x] ERPNext v15 integration — stock levels, reorder thresholds, Purchase Order creation via REST API
- [x] Odoo CE v17 integration — product catalog, price lists, Sale Order creation via XML-RPC
- [x] ERP connector (`erp_connector.py`) — stock query, low stock detection, PO creation
- [x] CRM connector (`crm_connector.py`) — catalog read, partner management, SO creation
- [x] Buyer agent v2 — reads ERPNext, negotiates via ATN, creates real Purchase Orders
- [x] Supplier agent v2 — reads Odoo catalog, responds with real prices, creates Sale Orders
- [x] Docker Compose per VM: ERPNext stack (MariaDB + Redis), Odoo stack (PostgreSQL), OPA per-org
- [x] OPA Rego policies per-org: allowed orgs, capabilities, blocked agents
- [x] Seed scripts: ERPNext (company, warehouse, items, stock) + Odoo (products, prices, customer)
- [x] Demo testata end-to-end: 2 negoziazioni, 2 Purchase Orders creati
- [x] Guida deployment 3-VM con firewall rules e troubleshooting
- [x] Fix infrastrutturali: Dockerfile (alembic), nginx (WS /v1/), asyncio.to_thread (Alembic lifespan)

### Admin Secret Vault + Dashboard Settings (2026-04-06)
- [x] `app/kms/admin_secret.py` — modulo dedicato per hash bcrypt admin secret in Vault/local
- [x] Bootstrap automatico: `.env` → bcrypt hash → Vault (`secret/data/broker.admin_secret_hash`)
- [x] Login admin: bcrypt verify da Vault (fallback .env se Vault down)
- [x] `GET /dashboard/admin/settings` — pagina Admin Settings con form cambio password
- [x] `POST /dashboard/admin/settings/password` — cambio password (bcrypt, CSRF, min 12 char, audit log)
- [x] Template `admin_settings.html` con info KMS backend (badge Stored in KMS / Fallback)
- [x] Link "Settings" nella sidebar admin (dopo Policies)
- [x] Verifica constant-time con dummy hash (anti timing-attack)
- [x] Admin secret mai piu in chiaro — solo hash bcrypt in Vault

### Strategia & Documentazione
- [x] Piano strategico (`strategia.md`) — posizionamento, business model, target, roadmap 3 mesi
- [x] Piano marketing (`marketing.md`) — brand, launch plan, content strategy, materiali enterprise
- [x] Guida concetti (`guida_concetti.md` + PDF) — 25 sezioni, crypto dalle basi al flusso completo
- [x] CLAUDE.md aggiornato con stato reale del progetto

### Enhanced Discovery + RFQ + Transaction Tokens (2026-04-05)
- [x] Discovery multi-modo: agent_id, SPIFFE URI, org_id, glob pattern, capability — filtri combinabili
- [x] Parametro `include_own_org` per includere la propria org nei risultati
- [x] Validazione capability del target alla creazione sessione (agent deve advertise la cap)
- [x] RFQ broadcast (`POST /v1/broker/rfq`) — trova supplier matching, valuta policy, broadcast, raccoglie quote con timeout
- [x] RFQ response (`POST /v1/broker/rfq/{id}/respond`) — supplier invia quote, dedup, audit
- [x] RFQ status polling (`GET /v1/broker/rfq/{id}`) — stato e quote raccolte
- [x] RFQ DB models: `rfq_requests` + `rfq_responses` con UNIQUE constraint
- [x] RFQ notification via WebSocket + notifica persistente per agenti offline
- [x] Transaction token (`POST /v1/auth/token/transaction`) — single-use, TTL 10-300s, bound a payload hash
- [x] TokenPayload esteso: `act` (RFC 8693 actor), `txn_type`, `resource_id`, `payload_hash`, `token_type`
- [x] Validazione transaction token nel message send — consume atomico, audit chain completa
- [x] Audit trail: rfq.created → rfq.broadcast → rfq.response_received → rfq.closed → auth.transaction_token_issued → broker.transaction_executed
- [x] 21 nuovi test (8 discovery, 7 RFQ, 6 transaction token)

---

### MCP Proxy — Org-Level Enterprise Gateway (2026-04-07)
- [x] **Fase 1** — Skeleton + Config (`config.py`, `main.py`, `models.py`, `db.py` SQLite async)
- [x] **Fase 2** — Auth (DPoP RFC 9449, JWT RS256 validation, JWKS client async + 1h cache, API key auth bcrypt)
- [x] **Fase 3** — Tool Registry + Executor (decorator `@register`, WhitelistedTransport httpx depth-1 wildcard, SecretProvider Vault/env, 30s timeout)
- [x] **Fase 4** — Ingress Router (`POST /v1/ingress/execute`, `GET /v1/ingress/tools`, 2 builtin demo tools)
- [x] **Fase 5** — Egress Gateway (AgentManager x509 cert issuance, BrokerBridge CullisClient pool, 7 egress endpoints)
- [x] **Fase 6** — Dashboard UI (11 template HTML, Jinja2 + HTMX + Tailwind dark theme)
  - Login: broker URL + invite token (sostituisce quickstart.sh)
  - Register org: auto-genera CA RSA-4096, chiama broker `/onboarding/join` con invite token
  - Org status polling HTMX (pending/active/rejected banner auto-refresh 10s)
  - Agents CRUD: crea agente con cert x509 firmato Org CA + binding auto al broker + API key locale
  - Agent delete + deactivate (danger zone)
  - Agent developer portal con integration guide (6 tab: Python, cURL, Node.js, Docker, MCP Config, IoT)
  - Snippet pre-compilati con valori reali dell'agente (proxy_url, agent_id, org_id, api_key)
  - Download .env file per agente
  - Warning sicurezza per IoT (per-device keys, TPM) e browser SPA (non supportato)
  - PKI: overview CA, export cert, rotate CA con conferma
  - Vault: config, test connettivita, migrazione chiavi DB→Vault
  - Tools: registry viewer, reload da YAML
  - Policies: editor regole JSON built-in + webhook PDP esterno
  - Audit log: paginato, filtrabile per agente/azione/status
- [x] **Fase 7** — Deploy (`Dockerfile`, `requirements-proxy.txt`, `docker-compose.proxy.yml` standalone)
- [x] Enterprise hardening: audit log append-only, rate limiting per API key, structured JSON logging
- [x] Zero import da `app/` — componente standalone deployabile indipendentemente
- [x] 45 route, 44 file Python/HTML/YAML
- [x] Sessions page: lista sessioni broker di tutti gli agent interni, filtro status, bottone Close
- [x] Close session via proxy: chiama broker API tramite BrokerBridge, audit log
- [x] **Enrollment Token** — connessione automatica agente→proxy con link monouso
  - `GET /v1/enroll/{token}` — endpoint pubblico, token bcrypt-hashed, TTL configurabile (5min-24h), monouso
  - Enrollment = key rotation (API key generata al consumo, non conservata in chiaro)
  - Dashboard: bottone "Generate Enrollment Link" con TTL selector + URL copiabile + QR code
  - Tab "Quick Connect" con snippet one-liner per curl, Python SDK, Docker, Node.js
  - `CullisClient.from_enrollment(url)` nell'SDK — bootstrap completo in 1 riga
  - `from_enrollment(url, save_config=".env")` salva config su file
  - Alembic migration `0002_enrollment_tokens`
  - 17 test (token format, single-use, expiry, HTTP endpoint, key rotation, auth verification, audit log)
- [x] **Network Directory** — pagina dashboard per vedere tutti gli agenti nel network
  - `GET /proxy/network` — card grid responsive con tutti gli agenti visibili dal broker
  - Ogni card: display name, agent ID, org badge (colore deterministico da hash org), SPIFFE URI, capabilities, description
  - Click card → espande dettaglio con SPIFFE ID copiabile, agent ID copiabile, snippet Python per open_session
  - Search HTMX debounced 300ms (free-text su nome/org/description)
  - Filter bar con chip per capability
  - HTMX partial rendering (`network_partial.html`) per refresh senza reload pagina
  - Badge contatore nel sidebar (auto-refresh 30s)
  - Empty state per broker offline / nessun agente / nessun risultato
  - `BrokerBridge.list_all_agents()` — discover con `pattern=*`
  - 9 test (auth, bridge errors, agent display, search, capability filter, HTMX partial, SPIFFE URIs, discovery failure)

### Broker: Invite Tokens + Org Self-Status (2026-04-07)
- [x] `app/onboarding/invite_store.py` — token one-time crittograficamente sicuri (SHA-256 hash, expiry, revocazione)
- [x] Dashboard admin: genera invite token (label + TTL), revoca, lista con status
- [x] `POST /v1/onboarding/join` — richiede invite_token, valida + consuma atomicamente
- [x] `GET /v1/registry/orgs/me` — org self-status check con X-Org-Id + X-Org-Secret (no admin secret)
- [x] Alembic migration `b2c3d4e5f6a7` per tabella `invite_tokens`
- [x] Template `invite_created.html` con copy token + avviso one-time
- [x] CSP fix: `'unsafe-inline'` per script inline nella dashboard (tab management)
- [x] Tab agent manage: `type="button"` per fix click handler

### E2E Testato + Networking Docker (2026-04-07/08)
- [x] E2E completo via proxy: open session → accept → send E2E message → poll → reply → receive (tutti 200)
- [x] `POST /pdp/policy` integrato nel proxy (PDP built-in, no container separato)
- [x] PDP valuta regole dalla dashboard Policies page (default: allow all)
- [x] Docker networking: proxy si unisce a `agent-trust_default` via external network
- [x] Broker→PDP raggiungibile via Docker DNS (`http://mcp-proxy:9100/pdp/policy`)
- [x] Proxy→Broker raggiungibile via Docker DNS (`http://broker:8000`)
- [x] AgentManager: login al broker dopo creazione agente (pinna cert thumbprint + registra public key)
- [x] AgentManager: crea binding + auto-approve dopo registrazione agente
- [x] AgentManager: legge broker_url e org_secret dal DB proxy_config
- [x] BrokerBridge: aggiunto `accept_session()` + endpoint `POST /v1/egress/sessions/{id}/accept`
- [x] SDK: `sys.exit(1)` sostituito con eccezioni (ConnectionError, PermissionError)
- [x] Mock PDPs rimossi da `docker-compose.yml` (ogni org usa il PDP del proprio proxy)

### Deploy Split (2026-04-08)
- [x] `deploy.sh` → wrapper interattivo (broker / proxy / both)
- [x] `deploy_broker.sh` — broker + postgres + redis + vault + nginx + jaeger
- [x] `deploy_proxy.sh` — proxy (si unisce alla rete del broker)
- [x] Backward compatible: `./deploy.sh --dev` deploya il broker come prima

### Asset di lancio — Marketing & content (2026-04-09)
- [x] **Logo PNG croppato** (`imp/logo_cullis.png`): da 2200×1201 (16:9 wide, logo decentrato a destra) a 1000×1000 quadrato, droppando la stellina decorativa marginale. Backup in `.bak`, originale `.orig` intatto
- [x] **Blog post rebrandato** (`imp/blog_why_api_keys_broken.md`): "Agent Trust Network / ATN" → "Cullis", `GITHUB_LINK` placeholder → `https://github.com/cullis-security/cullis`, footer con `hello@cullis.io` + `security@cullis.io` + `cullis.io`
- [x] **Paragrafo "Why Cullis"** aggiunto al blog: origine dal portcullis (saracinesca medievale come metafora del trust gateway, "zero standing trust, every passage checked")
- [x] **Blog HTML production-ready** (`docs/blog/why-api-keys-broken.html`): 703 righe, 28KB, self-contained, design system identico alla landing (Instrument Serif italic, Satoshi, DM Mono, accent teal `#00e5c7`, sfondo void), nav fissa con scroll-shrink, footer 4 colonne (Project/Security/Community), Open Graph + Twitter Card + structured data BlogPosting schema, responsive + `prefers-reduced-motion`
- [x] **X drafts rebrandati** (`imp/social_drafts_x.md`): "ATN" → "Cullis", "Agent Trust Network" → "Cullis", `[GITHUB_LINK]` → `github.com/cullis-security/cullis`, `git clone` aggiornato, `cd agent-trust-network` → `cd cullis`, **"200+ tests" → "440+ tests"** (verificato `pytest --collect-only` = 446 totali, 443 collected)
- [x] **LinkedIn drafts rebrandati** (`imp/social_drafts_linkedin.md`): "Agent Trust Network" → "Cullis", `[GITHUB_LINK]` → repo URL reale, **"388 tests" → "440+ tests"**, **rimosso claim non verificabile "2 internal security audits"** dal launch post + dalla talking points table
- [x] **Launch cheat sheet** (`imp/launch_cheatsheet.md`): pre-flight checklist + Fase 1 (D-7 pre-launch) + Fase 2 (D0 launch day con sequenza minuto per minuto: blog 08:00 → LinkedIn 08:30 → X 09:00 → Show HN 10:00 → r/netsec 11:00 → outreach 14:00) + Fase 3 (follow-up D+4/+8/+10/+14), snippet pronti per HN/Reddit/mention, target metriche, errori da evitare
- [x] **Cloudflare Pages config diagnosi**: identificato che la GitHub App di Cloudflare era ancora bound a `DaenAIHax/cullis` (vecchio handle) e non si è migrata dopo il transfer org. Webhook `gh api repos/cullis-security/cullis/hooks` = `[]`. Fix scelto: manual upload via Cloudflare Pages dashboard. Build output directory deve essere `docs` (non vuoto, altrimenti Pages serve la repo root e il sito è 404)
- [x] **Verificato live**: `cullis.io` HTTP 200 via Cloudflare, repo `cullis-security/cullis` PUBLIC + Apache-2.0, `pytest --collect-only -q` = 446 test totali

### Multi-VM Deploy + TLS Hardening (2026-04-10)
- [x] `deploy_broker.sh --public-url` — CA-signed TLS cert con SAN da LAN IP/hostname, chiave CA caricata su Vault + rimossa da disco
- [x] `deploy_proxy.sh --dev` — profilo con nginx HTTPS terminator + Vault, auto-detect LAN IP, `--instance` per co-location
- [x] `docker-compose.proxy.dev.yml` — layered compose: Vault dev + nginx + rete isolata
- [x] `nginx-proxy/` — template reverse proxy HTTPS, cert scaffolding per istanze
- [x] Broker CA public endpoint (`/v1/.well-known/broker-ca.pem`) — TOFU bootstrap, cache 1h, no DPoP required
- [x] Broker setup wizard — dashboard UI per configurare URL pubblico, trust domain, policy flags, invite token a runtime
- [x] `broker_http_client()` centralizzato (`mcp_proxy/auth/broker_http.py`) — singolo punto per CA bundle config, elimina 12× `verify=False`
- [x] `mcp_proxy/config.py`: `broker_ca_path` setting con validazione prod (fail-fast) e dev (warning + fallback)
- [x] JWKS client rispetta broker CA bundle
- [x] `CullisClient verify_tls` centralizzato via `cullis_client_verify()`
- [x] Vault key storage abstraction (`store_org_ca_key` / `fetch_org_ca_key`) con auto-migrazione DB→Vault
- [x] First-boot admin password flow (bcrypt 12 round, minimo 12 char)
- [x] Binding approve/re-approve da agent detail page
- [x] Agent env file download per demo agent multi-VM (`CULLIS_*` env vars)
- [x] Dashboard test message sender (HTMX, one-shot via BrokerBridge)
- [x] Org reset (danger zone) per recovery Vault dev mode
- [x] Policy webhook TLS verification toggle (`POLICY_WEBHOOK_VERIFY_TLS`)
- [x] Demo scripts (sender/checker) supportano `CULLIS_*` env vars per cross-VM
- [x] `scripts/generate-env.sh` — path non-interattivo via `BROKER_PUBLIC_URL`, rimossa opzione HTTP
- [x] `docs/multivm-runbook.md` — walkthrough completo 3-VM
- [x] `docs/blog/why-api-keys-broken.html` — blog post pubblicabile
- [x] `tests/test_broker_ca_endpoint.py` — 5 test per endpoint CA pubblico
- [x] E2E 3-VM verificato: broker (VM1) + 2 proxy Milan/NewYork (VM2/VM3), sender→checker cross-org funzionante

### Code Audit — 8 Bug Fix (2026-04-10)
- [x] **B1** sender timeout message diceva "5s" ma il timeout reale era 30s — ora f-string dinamica
- [x] **B2** import duplicato `get_agent_by_id` in `app/broker/router.py` — rimosso alias `_get_agent_by_id`
- [x] **B3** cookie proxy `secure=False` hardcoded — ora legge `proxy_public_url` scheme
- [x] **B4** badge HTML con f-string non safe — `int(count)` esplicito prima dell'interpolazione
- [x] **B5** nessun audit log per login admin — aggiunto `log_event` per success (bcrypt/env), denied
- [x] **B6** policy toggle scriveva su `_policy_override` in-memory (perso al restart) — ora scrive su `Settings.policy_enforcement`
- [x] **B7** cookie broker `Secure` flag usava `"https" in url` string match — ora `urlparse().scheme == "https"`
- [x] **B8** proxy `/readyz` tornava 200 senza BrokerBridge — ora riporta `broker_bridge` status

### Launch Sprint + Dashboard Integrations (2026-04-11, sessione 7)
- [x] README riscritto: badge v0.2.0, 12 feature, enterprise section, architecture Prometheus/Grafana, 460+ test / 64k+ LOC
- [x] Landing page: 7° pillar tab Observability, sezione Enterprise (3 card amber: SAML, Cloud KMS, Audit Export), 3 righe comparison table
- [x] Plugin wiring completato: auth backends + middleware consumati in main.py (5/5 extension points)
- [x] Integration kit: `docs/integration-guide.md`, `enterprise-kit/examples/` (5 file), `enterprise-kit/README.md`
- [x] Dashboard Integrations broker: 6 card (Prometheus, Grafana, Jaeger, SIEM, Alertmanager, Vault), HTMX test, `BrokerConfig` model
- [x] Dashboard Integrations proxy: 7 card (2 linked + 5 configurabili), stessa UX
- [x] Social/HN drafts aggiornati: 460+ test, enterprise features, Prometheus/Grafana
- [x] `create_all` dopo Alembic per tabelle non migrate
- [x] First-boot password flow fixato: ADMIN_SECRET default → warning in dev (non crash)
- [x] 464+ test verdi, 0 regressioni

---

## IN PIANIFICAZIONE

### Unified .env Generation — FATTO
- [x] Estrarre logica .env da `deploy.sh` in `scripts/generate-env.sh` standalone
- [x] `setup.sh` chiama `generate-env.sh --defaults` se `.env` manca
- [x] `deploy.sh` delega a `generate-env.sh` (elimina codice duplicato)
- [x] `docker-compose.yml` usa `${POSTGRES_PASSWORD:-atn}` in postgres + broker
- [x] `validate_config()` blocca boot se ADMIN_SECRET e' il default in prod; warning in dev per first-boot flow
- Piano: `imp/unified_env_plan.md`

---

## DA FARE

### Fix demo lasciati aperti (scelte intenzionali da risolvere prima di prod)

Queste non sono bug — sono scorciatoie consapevoli per far girare la demo 3-VM. Vanno chiuse prima del primo deploy reale.

- [x] **D1 — `_vault_verify()` return False** — agent console ora legge `broker_ca_cert_path` se HTTPS, fallback `False` in dev (ecc4712)
- [x] **D2 — CSRF su test endpoint HTMX** — `verify_csrf()` aggiunto a `/setup/test-connection`, `/policies/test-webhook`, `/vault/test` (ecc4712)
- [x] **D3 — `policy_webhook_verify_tls=false`** — startup warning in prod via `validate_config()` (ecc4712)
- [x] **D5 — Error messages leak dettagli** — `safe_error()` helper in `app/config.py`, sanitizza 12 callsite in prod, dettagli solo in dev (ecc4712)
- [x] **D8 — `unsafe-inline` nel CSP** — nonce per-request su tutti gli inline `<script>`, `_NonceTemplates` wrapper auto-inject, rimosso `unsafe-inline` da `script-src` (ecc4712)

### Production-ready (P0 — bloccante per primo cliente)

- [ ] **TLS reale** — Let's Encrypt o CA aziendale (oggi self-signed). Richiede dominio
- [x] **`deploy.sh`** — script one-command: genera secrets, configura TLS (self-signed/LE/CA propria), avvia Docker
- [x] **Vault produzione** — `vault/config.hcl` file storage + `vault/init-vault.sh` Shamir 5/3 unsealing
- [x] **CORS origins** — default vuoto (fail-safe), lista configurabile da `.env`, WebSocket origin allineato
- [x] **Alembic in CI** — migration verificata su DB pulito in GitHub Actions
- [x] **Postgres backup cron** — `scripts/pg-backup.sh` (30-day rotation) + `scripts/pg-restore.sh` — DEPRECATED
- [x] **Backup/restore unificato** — `scripts/backup.sh` (Postgres parallelo + Redis + Vault + config), `scripts/restore.sh`, cron automation, SHA256 integrity, 700/600 perms, tar traversal protection (44b20d8) — DA TESTARE
- [ ] **Vault auto-unseal** — AWS KMS / Azure Key Vault / GCP CKMS. Oggi manual Shamir 3/5, un restart richiede operatore
- [x] **Proxy DB: SQLite → Postgres** — SQLAlchemy ORM, Alembic migrations, dual-backend (SQLite dev, Postgres prod) (437c610)
- [x] **Semver + image tagging** — `VERSION` file, `bump.sh`, `CHANGELOG.md`, `release.yml` su tag push, v0.2.0 (65a10af)
- [ ] **Secret rotation** — API key expiry, Vault token lease renewal, admin password rotation. Oggi tutto statico forever
- [ ] **mTLS proxy→broker** — oggi unilaterale, il broker non verifica l'identita del proxy chiamante
- [x] **Redis produzione** — prod guard (crash se no redis_url), `is_redis_available()`, readyz ping (b550d53)
- [ ] **Helm chart validato** — broker chart esiste (HPA/PDB/NetworkPolicy) ma README dice "not yet production-validated". Test E2E su almeno 1 cloud managed (EKS o GKE)

### Production-ready (P1 — primo cliente enterprise)

- [ ] **Rate limit tuning** — calibrare bucket per carico atteso (i default sono per demo)
- [ ] **Log aggregation** — `LOG_FORMAT=json` c'è, serve doc per Loki/ELK/Datadog
- [x] **Monitoring alerting** — `enterprise-kit/monitoring/cullis-alerts.yml`: 8 alert Prometheus su 3 gruppi (cert pinning, audit chain, DPoP replay, auth failure rate, PDP latency)
- [x] **Startup validation** — `validate_config()` blocca boot in produzione se DB SQLite, PKI mancante, o admin_secret default
- [x] **Graceful shutdown** — drain mode con SIGTERM, WebSocket close code 1012, `/readyz` 503 durante drain
- [ ] **Health check CI** — aggiungere `docker compose up` + health check nel pipeline
- [x] **Helm chart proxy** — 19 template (Deployment, Service, Ingress, HPA, PDB, NetworkPolicy, ServiceMonitor, Postgres/Vault StatefulSet), values.yaml + values-dev.yaml (acf1e50) — DA TESTARE su k8s
- [x] **Audit log retention + export** — enterprise module: S3 export con watermark, background task, API status/trigger/history, gated da license key — DA TESTARE con S3/MinIO
- [ ] **Cert expiry alerting** — agent cert 365d senza warning, break silenzioso
- [ ] **Prometheus metrics proxy** — broker ha `/metrics` opt-in, proxy non ha niente
- [x] **Grafana dashboards** — 2 dashboard JSON (Broker Overview + Security Signals), Prometheus + Grafana in docker-compose, provisioning automatico (7cc8f09) — DA TESTARE
- [ ] **DR runbook** — procedure failover attivo-passivo documentate, Vault snapshot + recovery, RTO/RPO definiti

### Open-Core Strategy

Decisione architetturale: **Opzione 1 — Plugin / repo privato** (codice enterprise mai nel repo pubblico).

Il repo pubblico `cullis-security/cullis` resta il core engine (Apache 2.0). Il repo privato `cullis-security/cullis-enterprise` importa il core come dipendenza e monta route/middleware aggiuntivi sopra la FastAPI app.

**Immagini Docker:**
- `cullis/broker` — build dal repo pubblico, community
- `cullis/broker-enterprise` — build dal repo privato, registry privato (GHCR)
- Stessa logica per `cullis/proxy` e `cullis/proxy-enterprise`

**Prerequisito architetturale per il pattern plugin:**
- [x] **Hook system nel core** — `app/plugins.py` con 5 extension point (routers, lifespan hooks, KMS providers, auth backends, middleware), `app/main.py` monta plugin al startup (61056f2)
- [x] **Interfacce stabili** — plugin registrano via `register_router()`, `register_lifespan_hook()`, `register_kms_provider()`, `register_auth_backend()`, `register_middleware()`

**Linea di demarcazione Open Source vs Enterprise:**

| Community (Apache 2.0) | Enterprise (licenza commerciale) |
|---|---|
| PKI 3 livelli, E2E, DPoP, SPIFFE | SAML 2.0 |
| OIDC base (admin + per-org) | SCIM directory sync (AD/Okta → ruoli dashboard) |
| Vault KMS | AWS KMS / Azure Key Vault / GCP CKMS nativi (no Vault) |
| PostgreSQL singolo nodo | HA: Redis Cluster, Postgres multi-nodo |
| Policy engine locale (OPA singolo) | OPA federato dual-node |
| Audit log append-only | Audit export immutabile (S3/Datadog) + retention policy |
| Dashboard admin single-user | Multi-admin RBAC con per-user audit trail |
| Prometheus alert rules | Grafana dashboards preconfezionate + SLA monitoring |
| MCP Proxy standard | LLM Firewall: ispezione post-decrittazione nel proxy |

**Licensing:**
- [x] **License key JWT** — RSA-2048, pubkey hardcodata in `app/license.py`, validazione offline, `has_feature()` + `require_feature()` → 402 (d58f4e2)
- [x] **Generatore license key** — `scripts/license-gen.sh` + `scripts/license_gen.py`, supporta ISO date + duration (365d/12m/1y), `--features all` (d58f4e2)

### Enterprise features (da implementare nel repo privato)

**Identity B2B (contratto-closer per banche/sanita):**
- [x] **SAML 2.0** — SP-initiated SSO, ACS response validation, role mapping, IdP metadata auto-discovery, 6 endpoint API (login, acs, metadata, slo, config GET/POST). `python3-saml` (OneLogin) (dbab297 enterprise) — DA TESTARE con Okta/Azure AD
- [ ] **SCIM 2.0** — skippato: serve prima Multi-admin RBAC (oggi non ci sono utenti multipli da sincronizzare)

**Hardware Security (riduce attriti di adozione):**
- [x] **AWS KMS provider** — Secrets Manager per PEM + KMS envelope encryption, prefix `aws:v1:` (d4ddf8d enterprise) — DA TESTARE
- [x] **Azure Key Vault provider** — Key Vault Secrets per PEM + Keys RSA-OAEP, prefix `azure:v1:` (d4ddf8d enterprise) — DA TESTARE
- [x] **GCP Cloud KMS provider** — Secret Manager per PEM + Cloud KMS symmetric, prefix `gcp:v1:` (d4ddf8d enterprise) — DA TESTARE

**LLM Firewall (differenziatore unico):**
- [ ] **Injection detection nel proxy** — spostare `app/injection/` (13 regex + LLM judge) nel proxy come middleware post-decrittazione opt-in. Con E2E il broker non vede il plaintext, quindi il check va nel proxy dell'org ricevente
- [ ] **Schema validation strict** — validazione JSON schema dei payload prima della consegna all'agent

**Compliance (superare i CISO):**
- [x] **Audit export S3** — background task con watermark DB, gzip JSON Lines, drain mode, 3 API endpoint (status/trigger/history), 10 test (8d1fd43 enterprise) — DA TESTARE con S3/MinIO
- [ ] **Retention policy** — TTL configurabile + archiviazione automatica
- [ ] **Multi-admin RBAC** — ruoli per-utente con audit trail individuale
- [ ] **Pentest esterno CREST** — investimento esterno, non codice. Letter of Attestation per procurement

### Backlog

**OIDC user mapping**
- MVP: chiunque dal provider dell'org entra come "org admin"
- Future: mapping utente individuale, group/role claims, per-user RBAC

**Agent deletion cascade**
- Cascade a sessions/messages/notifications

**SDK Go**
- Per agenti performance-critical

**Scaling — Vertical (singolo broker piu veloce)**

Gia implementato:
- [x] FastAPI ASGI asincrono (nessun blocking thread per I/O)
- [x] EC P-256 per DPoP (verifica ~100x piu veloce di RSA-4096)
- [x] WebSocket limit 100 connessioni per org (anti resource exhaustion)
- [x] Redis JTI store SET NX EX atomico (zero race condition)
- [x] Rate limiter Redis sorted set sliding window (pipeline atomica)
- [x] asyncio.Lock su audit hash chain (corretto, serializza le scritture)

Da fare:
- [ ] **Pool size esplicito** — `create_async_engine` oggi usa default SQLAlchemy (pool_size=5, max_overflow=10 = 15 conn max). Esporre `DB_POOL_SIZE` e `DB_MAX_OVERFLOW` in config.py e documentare sizing per carico atteso
- [ ] **Audit hash chain sharding per org** — oggi `_audit_chain_lock` e globale: tutte le org in fila indiana. Shardare con `_audit_chain_lock_{org_id}` → 1 catena per org, scritture parallele tra org diverse. Il limite di ~200 write/sec diventa ~200 write/sec *per org*
- [ ] **Audit async (off critical path)** — oggi `log_event()` e sincrono nel request handler: l'agente aspetta che hash + INSERT + commit finiscano prima di ricevere 200. Spostare in coda (Redis Streams o asyncio.Queue) e scrivere in background. L'API diventa istantanea
- [ ] **Audit micro-batching** — raccogliere N eventi in finestra temporale (es. 50ms), calcolare un singolo Merkle root, fare 1 INSERT batch. Con 20 batch/sec si gestiscono 4.000+ msg/sec
- [ ] **Connection pooling PgBouncer** — interporre PgBouncer tra broker e Postgres per riuso aggressivo delle connessioni (transaction mode). Riduce il costo per connessione

**Scaling — Horizontal (piu broker in parallelo)**

Gia implementato:
- [x] Redis Pub/Sub per WebSocket cross-worker (ws_manager.py dual-mode: local + Redis)
- [x] Redis rate limiting globale (contatore condiviso tra worker)
- [x] Redis JTI blacklist globale (anti-replay cross-worker)
- [x] `BROKER_PUBLIC_URL` per DPoP HTU dietro reverse proxy
- [x] Nginx config per TLS termination e proxy headers

Da fare:
- [ ] **Nginx load balancer config** — oggi Nginx fa TLS termination per 1 upstream. Aggiungere upstream multi-worker con `ip_hash` (sticky per WebSocket) o `least_conn`. Template per N worker
- [ ] **Audit chain cross-worker** — con N worker, `_audit_chain_lock` (asyncio.Lock) e locale al processo. Serve lock distribuito: Redis `SET NX EX` o advisory lock Postgres `pg_advisory_xact_lock()` per serializzare la hash chain tra worker
- [ ] **Session affinity WebSocket** — WebSocket upgrade deve finire sullo stesso worker per tutta la durata. Nginx `ip_hash` o cookie-based sticky. Fallback: Redis Pub/Sub gia gestisce il cross-worker ma sticky riduce latenza
- [ ] **Docker Compose multi-worker** — template `docker-compose.scale.yml` con `deploy.replicas: N` + Nginx upstream dinamico
- [ ] **Kubernetes HPA** — Helm chart broker ha gia HPA template, ma non testato. Metric: CPU + custom metric `cullis_ws_connections_active` da Prometheus
- [ ] **Horizontal scaling proxy** — Redis per session state proxy, sticky routing per agent→proxy

**Scaling — Multi-Region (broker geograficamente distribuiti)**

Niente implementato — architettura teorica, ma il design e solido.

- [ ] **Modello A: Singolo trust domain geo-distribuito** — stessi cert, Postgres read replica cross-region (AWS RDS Multi-AZ / Citus), Redis Enterprise geo-replicate. Pro: semplice. Contro: latenza transoceanica per scritture, single point of failure CA
- [ ] **Modello B: Federazione multi-broker (cross-domain)** — ogni regione ha il suo stack completo (CA, DB, Redis). Le CA si cross-certificano (firma reciproca). Routing server-to-server: broker Milano legge dominio SPIFFE e inoltra a broker New York. Pro: resilienza totale (region down = le altre continuano). Contro: complessita di implementazione
  - [ ] Cross-certification PKI — API per scambio e firma reciproca dei certificati CA tra trust domain
  - [ ] Routing SPIFFE-based — broker legge trust domain dallo SPIFFE ID e inoltra al broker remoto
  - [ ] Protocollo server-to-server — mTLS tra broker, forward del pacchetto E2E cifrato (zero-knowledge preservato)
  - [ ] Conflict resolution — audit log per-region, riconciliazione asincrona
- [ ] **Vault replication** — Vault Enterprise performance replication o Vault Integrated Storage Raft multi-DC

**Infra & supply chain**
- [ ] Network policies k8s (isolamento org-level)
- [ ] Image signing + SBOM (cosign, Trivy)
- [ ] Terraform/CDK modules per self-service deploy

**Compliance avanzata**
- GDPR data purge API (right-to-be-forgotten per org)
- Audit log firma asimmetrica (proof tamper-resistant)
- Encryption at rest (DB + backup)
- SOC 2 Type II — documentazione processi, data retention, SLA

**Altre**
- Notification recipient_id non validato
- Limite dimensione ciphertext E2E
- Beckn protocol per commerce agent-to-agent
- Hyperledger per audit ledger distribuito

---

## Architettura file

```
app/                          # Broker FastAPI (~60 moduli + templates, ~17000 righe)
  auth/                       # x509, JWT, DPoP (RFC 9449), JTI, revoca, firma messaggi
  broker/                     # Sessioni, messaggi, WebSocket, persistenza, notifiche
  dashboard/                  # Dashboard web multi-ruolo (Jinja2 + HTMX + Tailwind)
    templates/                # HTML templates (base, overview, orgs, agents, sessions, audit, login, forms)
    session.py                # Cookie firmato HMAC-SHA256 per auth dashboard
    router.py                 # Route HTML + operazioni (onboard, approve, register)
  policy/                     # Engine, store, webhook PDP, OPA adapter, backend dispatcher
  registry/                   # Org, agenti, binding, capability discovery
  onboarding/                 # Join request, admin approve/reject
  kms/                        # KMS Adapter (local, vault) + secret encryption (HKDF+Fernet+random salt)
  redis/                      # Connection pool async, graceful fallback
  rate_limit/                 # Sliding window (in-memory / Redis sorted set)
  db/                         # SQLAlchemy models, audit log
alembic/                      # Alembic migrations (async)
  env.py                      # Config con import modelli + DATABASE_URL override
  versions/                   # Migration files
agents/                       # SDK Python + agenti demo (buyer, manufacturer)
tests/                        # 32 file test, 350+ test, PKI effimera, SQLite in-memory
enterprise-lab/               # Demo Lab 3-VM con ERP/CRM reali
  connectors/                 # ERPNext REST + Odoo XML-RPC wrappers
  vm1-broker/                 # Docker Compose broker stack
  vm2-buyer/                  # ERPNext + OPA + buyer agent v2
  vm3-supplier/               # Odoo CE + OPA + supplier agent v2
certs/                        # Certificati x509 generati
```
