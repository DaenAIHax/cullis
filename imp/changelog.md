# Cullis — Changelog implementazioni

Log delle implementazioni per sessione. Aggiornato dopo ogni sessione di lavoro.

---

## 2026-04-13 — Session Reliability Layer M3.6 (router integration)

Chiuso M3.6 (router integration) sul branch `feature/m3-message-durability`
sopra M3.1 (schema) + M3.2 (queue ops) già presenti. Ripreso dopo
discussione architetturale che ha prodotto ADR-001 (intra-org routing +
Guardian). M3 broker-side resta valido per path cross-org.

### Nuovi endpoint / comportamento broker
- `POST /v1/broker/sessions/{id}/messages` accetta due nuovi query params:
  - `ttl_seconds` (1..86400, default 300) — TTL della riga in coda
  - `idempotency_key` (opt, max 128) — dedup chiave `(recipient, key)`
- Se il recipient NON è connesso via WS localmente → `mq.enqueue()` con
  ciphertext = canonical JSON di `envelope.payload`; risposta
  `{status:"queued", msg_id, deduped}`
- Se il recipient è connesso → push WS diretto invariato, risposta `{status:"accepted"}`
- Nuovo `POST /v1/broker/sessions/{id}/messages/{msg_id}/ack` —
  204/400/404/409, scoped a `current_agent.agent_id` (niente info leak)

### WS drain su connect/resume
- Helper `_drain_queue_for_agent` chiamato dopo `auth_ok` e alla fine di
  `_handle_ws_resume`
- Ogni messaggio queued consegnato come `new_message` con `queued:true` + `msg_id`
- Drain non muta stato — SDK deve ack via REST per chiudere la riga
- Failure durante drain loggati, non abortono la sessione WS

### Sweeper TTL expiry
- `session_sweeper._sweep_message_queue()` invocato ad ogni ciclo `sweep_once`
- Chiama `mq.sweep_expired()` e per ogni riga scaduta emette `message_expired`
  best-effort al sender (fields: type, session_id, msg_id, recipient_agent_id, reason="ttl")
- Isolato in try/except — errori DB/WS non rompono il session sweep

### Metriche nuove (OpenTelemetry)
- `atn.message.queued`, `atn.message.queue_deduped`, `atn.ws.queue_drained`,
  `atn.message.expired`

### Test
- `tests/test_m3_router_integration.py` (8), `tests/test_m3_ws_drain.py` (4),
  `tests/test_m3_sweeper_ttl.py` (3) — totale 15 nuovi test
- Tutte le suite reliability/queue esistenti invariate (M1+M2+M3 unit)

### Commit sequence sul branch
- `3d265ca` — queue fallback + query params
- `0131546` — ack endpoint
- `9fcae25` — WS drain
- `9b13ea0` — sweeper TTL + notify

### Decisioni chiave (vedi anche ADR-001)
- Presence: enqueue solo se `ws_manager.is_connected` locale è False.
  Multi-worker deliverato via Redis pub/sub + drain al reconnect, dedupe
  client-side su msg_id.
- Query params invece di wrapper body — zero regressione sui ~20 test
  esistenti. SDK aggiungerà i params in M3.4/M3.5.
- Ack 409 vs 404 distinti: extra SELECT utile per diagnostica SDK.
- Sender scoping: ack da non-recipient ritorna 404 (no info leak).

---

## 2026-04-12 — Attach-CA + smoke production-grade + deploy hardening (sessione 8)

### Flusso attach-CA (onboarding org pre-registrate)
- Nuovo tipo di invite `attach-ca` vincolato a `linked_org_id`, migrazione Alembic `c3d4e5f6a7b8`
- `app/onboarding/invite_store.py`: due invite types (`org-join` + `attach-ca`), `validate_and_consume(expected_type=...)`, nuovo `inspect_invite`
- `app/onboarding/router.py`:
  - `POST /v1/onboarding/attach` — carica CA su org esistente + ruota `secret_hash` (proxy claima l'org), supporta `webhook_url`
  - `POST /v1/onboarding/invite/inspect` — legge type + org_id senza consumare (per wizard proxy che branca automaticamente)
  - `POST /v1/admin/orgs/{id}/attach-invite` — admin genera invite legato a org_id
- `app/registry/org_store.py`: nuovo `update_org_secret` (bcrypt rehash)
- `/onboarding/join` ora rifiuta attach-ca token; `/onboarding/attach` rifiuta org-join token
- Dashboard: bottone "Attach-CA invite" in `orgs.html`, distinzione flow in `invite_created.html`
- Wizard MCP proxy: chiama `/inspect`, se attach-ca usa `linked_org_id` come fonte di verità + chiama `/attach`
- 8 nuovi test in `tests/test_attach_ca.py` — happy path + cross-type attacks + secret rotation verificata

### Smoke test production-grade (`demo_network/`)
- Obiettivo: pre-merge gate che esercita lo stack prod in ~75-120s, one command `./smoke.sh full`
- **Topologia**: 12 container (ca-init, traefik, broker-init, broker, postgres, redis, vault, vault-init, bootstrap, 2x proxy+init, sender, checker, prober)
- **Stack reale**: Postgres + Redis + Vault HTTPS con token scoped (policy `secret/data/broker` only, no root)
- **Hardening Fase A** — 8 assertion automatiche:
  - A1 Vault HTTPS + scoped token via `vault-init` dedicato
  - A2 PDP real policies — ALLOW (sender→checker) + DENY (banned-sender blocked in proxy-b policy_rules)
  - A3 SSRF guard unit test — `tests/test_security_fixes.py::test_webhook_ssrf_localhost_blocked` fixato (forza `allow_private_ips=False` in test)
  - A4 `DASHBOARD_SIGNING_KEY` persistente — smoke logga, restart broker, verifica cookie ancora valido
  - A5 Cert revocation — revoke via `/v1/admin/certs/revoke` → login successivo 401
  - A6 Binding revocation — revoke → login/session 403
  - A7 Audit hash chain integrity — export NDJSON, recompute sha256 per 33+ entries
  - A8 MCP Proxy ingress `/v1/ingress/tools` con JWT+DPoP+nonce → 200
- **File chiave**:
  - `demo_network/compose.yml` — topologia completa
  - `demo_network/smoke.sh` — `up | check | down | logs | dashboard | full`, auto-print endpoints + credenziali dopo `up`, retry intelligente su nonce check, failure dump auto
  - `demo_network/bootstrap/bootstrap.py` — registra 2 org (una via `/join`, una via `/attach`) + 4 agent (sender, checker, banned-sender, revoked-agent, unbound-agent)
  - `demo_network/proxy-init/seed.py` — seeda `proxy_config` SQLite (broker_url, org_ca, webhook, optional policy_rules JSON)
  - `demo_network/vault-init/init.sh` — crea broker-policy + token scoped
  - `demo_network/verify_audit_chain.py` — recompute hash chain
  - `demo_network/sender/send.py` + `checker/check.py` — SDK-based, 5 phase sender (allow/deny/revoked-cert/revoked-binding/ingress)
- **CI**: workflow `.github/workflows/smoke.yml` blocca PR se smoke rosso; path filter skippa PR docs-only
- **Memoria**: `feedback_smoke_gate.md` — regola "ogni modifica a app/mcp_proxy/cullis_sdk/alembic passa smoke"

### Deploy hardening (production-ready)
#### Broker
- `docker-compose.yml` — propaga `DASHBOARD_SIGNING_KEY` + `POLICY_WEBHOOK_ALLOW_PRIVATE_IPS`, `VAULT_ALLOW_HTTP` env-driven
- `docker-compose.prod.yml` — fail-fast `${VAR:?}` su ADMIN_SECRET/DASHBOARD_SIGNING_KEY/VAULT_TOKEN, forza `VAULT_ALLOW_HTTP=false` + `POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=false`
- `scripts/generate-env.sh` — prod aggiunge REDIS_PASSWORD + flag hardening + dedupe ENVIRONMENT
- `vault/init-vault.sh` — scrive `broker-policy`, genera scoped token 30d renewable, salva in `vault/broker-token` (no root token nel broker env)
- `.env.example` — quickstart VAULT_TOKEN via init-vault.sh, documentati policy flags
- `deploy_broker.sh` (enterprise repo) — pre-flight validation `.env` blocca `docker compose up` se values default

#### MCP Proxy
- `proxy.env.example` — simmetrico a `.env.example`, documenta ogni MCP_PROXY_* var
- `scripts/generate-proxy-env.sh` — genera random admin secret + signing key, modes `--defaults|--prod|--force`
- `docker-compose.proxy.yml` — propaga BROKER_URL + BROKER_JWKS_URL + PROXY_PUBLIC_URL + DASHBOARD_SIGNING_KEY + ALLOWED_ORIGINS + mount `/certs` per custom CA bundle
- `docker-compose.proxy.standalone.yml` — override per remote broker (bridge net invece di external `agent-trust_default`), usa `!override` + `!reset` (Compose 2.20+)
- `docker-compose.proxy.prod.yml` — fail-fast sui vars richiesti + restart always + resource limits
- `deploy_proxy.sh` (enterprise repo) — supporta `--prod` + `--standalone` + pre-flight validation + `--env-file proxy.env`

#### Runbook
- `docs/operations-runbook.md` — 8 scenari incident response: broker down, postgres down, vault sealed, redis down, TLS expired, agent compromise, admin lockout, blanket triage. Ogni sezione: symptom + confirm command + recovery + verify + prevent. Tabella backup finale.

### Crypto roadmap (agent parallelo)
- Sprint 1 — TS SDK ECDH + fix base64url interop (commit `133edbe`)
- Sprint 2 — mTLS hybrid binding opt-in (commit `12d701e`) — Check #13 in x509_verifier, 3 modes (off default/optional/required), zero blast radius retrocompat, 6 nuovi test in `tests/test_mtls_binding.py`
- Sprint 3 — ECC agent certs (Ed25519/ES256) — in corso (file touched: `generate_certs.py`, `tests/cert_factory.py`, `tests/test_auth_ec.py`)

### Scalability doc
- `imp/scalability.md` — nuova sezione "Decisione Redis HA e Postgres HA": HA non in smoke (correttezza vs scalabilità), va in `deploy/` recipes. Matrice single-node vs Sentinel vs Cluster vs Managed. Broker oggi single-Redis (`from_url`), Sentinel richiede ~30 righe di refactor in `app/broker/redis_client.py`.

### Commit timeline (sessione)
- attach-ca flow — `c78a280`
- smoke demo_network 12 servizi — `c66a070`
- smoke fix SIGPIPE + retry — `d40e4e7`
- smoke auto-print dashboard — `27fd867`
- smoke prod-like (Postgres+Redis+Vault) — `4122fa0`
- smoke A5+A6 cert/binding revoke — `3344bda`
- lint fix — `8a70e4c`
- smoke A7+A8 audit+ingress — `957cca1`
- CI install Node (parallel agent) — `31d0366`
- deploy broker hardening — `c685197`
- mTLS hybrid binding (parallel agent) — `12d701e`
- deploy proxy hardening + runbook — `bf7599a`

### Test: tutti green (smoke full + unit)
- Smoke: 8/8 assertion pass, ~75-120s
- Unit: tests/test_attach_ca.py 8 nuovi, tests/test_security_fixes SSRF fixato

---

## 2026-04-11 — Launch sprint + Dashboard Integrations (sessione 7)

### README riscritto per il lancio
- Badge `v0.2.0/preview`, warning tono positivo, 12 feature (da 9)
- Sezione Enterprise Features: SAML, Cloud KMS, audit export, license key, plugin API
- Architecture diagram: Prometheus/Grafana, stats 460+ test / 64k+ LOC
- Tolto "Contact for enterprise" → "self-service from dashboard"

### Landing page (docs/index.html)
- 7° pillar tab: Observability (mock metrics Grafana)
- Sezione Enterprise: 3 card amber (SAML SSO, Cloud KMS, Audit Export)
- 3 righe comparison table, nav link Enterprise, CTA self-service

### Plugin wiring completato
- Auth backends + middleware ora consumati in `app/main.py` (erano dead code)
- 5/5 extension points funzionali, 9 test in `test_plugins_wiring.py`

### Integration kit
- `docs/integration-guide.md` — guida SIEM, KMS, alerting, IdP, PDP
- `enterprise-kit/examples/` — 5 file config/skeleton (Fluent Bit, rsyslog, Prometheus remote_write, KMS plugin, auth backend plugin)
- `enterprise-kit/README.md` — indice con tabella integrazioni

### Dashboard Integrations — self-service
- **Broker** `/dashboard/admin/integrations` — 6 card (Prometheus, Grafana, Jaeger, SIEM, Alertmanager, Vault), HTMX test, save to `broker_config` table
- **Proxy** `/proxy/integrations` — 7 card (2 linked: Vault→existing, PDP→existing, 5 configurabili), stessa UX
- `BrokerConfig` model key-value (nuovo)
- `create_all` dopo Alembic per tabelle non migrate

### Social/HN aggiornati
- Test count 440+ → 460+, menzione enterprise extensions + Prometheus/Grafana

### Fix
- `validate_config`: ADMIN_SECRET default → warning in dev (non crash)
- First-boot password creation flow funzionante con `docker compose up`

### Test: 464 passed, 0 regressions

---

## 2026-04-11 — Enrollment token + Network directory (sessione 6)

### Enrollment Token — connessione automatica agente→proxy
- `mcp_proxy/enroll.py` — **nuovo**: endpoint `GET /v1/enroll/{token}`, pubblico (no auth), token monouso
- `mcp_proxy/db/models.py` — tabella `enrollment_tokens` (token_hash bcrypt, agent_id, expires_at, is_used)
- `mcp_proxy/db/crud.py` — 4 funzioni CRUD: `create_enrollment_token`, `consume_enrollment_token` (bcrypt verify + expiry + atomic mark-used), `list_enrollment_tokens`, `delete_expired_enrollment_tokens`
- `mcp_proxy/dashboard/router.py` — `POST /agents/{id}/enrollment-token` con TTL configurabile (5min-24h)
- `mcp_proxy/dashboard/templates/agent_detail.html`:
  - Card "Quick Connect" nell'Overview tab con bottone "Generate Enrollment Link" + TTL selector
  - Enrollment URL copiabile + QR code (canvas JS) + one-liner curl/Python/Docker
  - Tab "Quick Connect" nel Connect panel con snippet completi per ogni runtime
- `cullis_sdk/client.py` — `CullisClient.from_enrollment(url, save_config=None)`: classmethod che fa GET all'enrollment URL, riceve API key + config, ritorna client pronto all'uso. `proxy_headers()` per chiamate egress
- `mcp_proxy/alembic/versions/0002_enrollment_tokens.py` — migration Alembic
- `mcp_proxy/main.py` — mount enrollment router, esclusione da DPoP-Nonce
- Sicurezza: token bcrypt-hashed in DB (plaintext mostrato una volta), TTL 15min default, monouso, enrollment = key rotation (API key generata al consumo), audit log `agent.enroll`
- `tests/test_enrollment.py` — **17 test**: token format, unicità, create/consume, single-use, expiry, invalid token, list, cleanup, HTTP endpoint (success, key rotation, key works for auth, single-use, expired, invalid, bad format, no DPoP-Nonce, audit log)

### Network Directory — tutti gli agenti del network visibili dalla dashboard
- `mcp_proxy/egress/broker_bridge.py` — `list_all_agents(agent_id, q, capability)`: discover con `pattern=*`
- `mcp_proxy/dashboard/router.py` — `GET /proxy/network` (full page + HTMX partial), `GET /badge/network`
- `mcp_proxy/dashboard/templates/base.html` — link "Network" nel sidebar con globe icon + badge auto-refresh 30s
- `mcp_proxy/dashboard/templates/network.html` — **nuovo**: pagina directory con search HTMX debounced, capability filter chips, agent card grid responsive (1-2-3 colonne)
- `mcp_proxy/dashboard/templates/network_partial.html` — **nuovo**: fragment HTMX per il grid di card agenti
  - Ogni card: display name, agent ID mono, org badge (colore deterministico da hash), capabilities chip, description
  - Click → espande dettaglio: SPIFFE URI copiabile, agent ID copiabile, snippet Python `open_session()`
  - Org color accent bar sul top della card
  - Empty state per errori / nessun risultato / broker offline
- `tests/test_network_directory.py` — **9 test**: auth required, no bridge, no agents, agent display, search query, capability filter, HTMX partial, SPIFFE URIs, discovery failure

### Riepilogo sessione
- **10 file modificati**, **6 file creati**
- **26 nuovi test** (17 enrollment + 9 network), tutti green
- 478+ test totali (era 452+)

---

## 2026-04-10 — Infra enterprise completa: backup, Helm, license, SAML, Cloud KMS, Grafana (sessione 5)

### Backup & Restore unificato (44b20d8)
- `scripts/backup.sh` — subcommand: full, postgres, redis, vault, config
- `scripts/restore.sh` — subcommand: full, postgres, redis, vault, config, list
- Postgres dump parallelo (broker + proxy) per consistenza point-in-time
- Redis BGSAVE + copy dump.rdb
- Vault volume snapshot + vault-keys.json
- Config archive (.env, certs/, nginx/certs/)
- Security: 700/600 perms, SHA256SUMS, tar path-traversal + wildcard injection protection
- `scripts/backup-cron.sh` + `scripts/install-backup-cron.sh` per automazione
- `scripts/BACKUP-NOTES.md` documentazione operativa
- `pg-backup.sh` e `pg-restore.sh` marcati DEPRECATED

### Proxy production mode (44b20d8)
- `docker-compose.proxy.prod.yml` — Vault server mode con volume persistente, resource limits, restart
- `vault/proxy-config.hcl` — file storage per proxy Vault instance
- `deploy_proxy.sh --prod` — compose prod, skip self-signed, vault init check

### Helm chart proxy (acf1e50)
- `deploy/helm/cullis-proxy/` — 19 template, 1390 righe
- Deployment, Service, Ingress, ConfigMap, Secret, ServiceAccount
- HPA (1-5 replicas), PDB, NetworkPolicy (con egress verso broker)
- ServiceMonitor per Prometheus
- Postgres + Vault StatefulSet opzionali (dev mode)
- `values.yaml` (prod) + `values-dev.yaml` (dev)

### License key RSA (d58f4e2)
- Keypair RSA-2048 generata (`certs/license/private.pem` gitignored, `public.pem`)
- Pubkey hardcodata in `app/license.py` (placeholder → chiave reale)
- `scripts/license-gen.sh` + `scripts/license_gen.py` — CLI generatore license JWT RS256
- Supporta ISO date, duration (365d/12m/1y), `--features all`
- Round-trip verificato: `has_feature()` / `require_feature()` funzionano con JWT reali

### Audit export S3 (enterprise repo, 8d1fd43 + 89e9769)
- `hook.py` — background task: query audit_log > watermark → serialize JSON Lines → gzip → S3
- `s3.py` — boto3 PutObject in thread executor
- `router.py` — 3 endpoint API: GET status, POST trigger, GET history
- Watermark persistito in DB (sopravvive restart)
- Drain mode su batch pieni
- 10 test (watermark, S3 upload mock, export cycle, endpoint gating)

### SAML 2.0 (enterprise repo, dbab297)
- `config.py` — SamlConfig dataclass + DB persistence (SamlConfigRecord table)
- `sp.py` — wrapper python3-saml: AuthnRequest, ACS response validation, metadata XML, SLO
- `router.py` — 6 endpoint: login, acs, metadata, slo, config GET/POST
- Auto-discovery IdP metadata da URL (parse XML per entity ID, SSO URL, x509 cert)
- Role mapping: SAML attribute → ruolo dashboard (admin/org)
- Tutti gli endpoint gated da `require_feature("saml")`

### Dashboard — audit log expand (eb9cf36)
- Click su qualsiasi riga audit → pannello dettaglio espandibile
- Broker: details JSON completo, entry hash + previous hash (selezionabili), session ID
- Proxy: detail completo, request ID, duration, agent, action, tool
- Vanilla JS `toggleDetail()`, nessuna dipendenza esterna

### Dashboard test fix
- 3 stale test fixati (`test_org_login_and_scoped_view`, `test_org_cannot_onboard`, `test_approve_requires_admin`)
- Login org rimosso nel first-boot flow → test riscritti per verificare accesso non-autenticato

### Proxy smoke test (44b20d8)
- `tests/test_proxy_smoke.py` — 11 test
- Health endpoints (/health, /healthz, /readyz, /pdp/health)
- Security headers (X-Frame-Options, CSP, HSTS, nosniff, no-store)
- DPoP-Nonce non su health endpoint
- PDP default-allow e blocked agent
- Exception handler (500, no traceback leak)
- Config prod guard (SQLite reject, admin secret reject)

### Rebrand metriche e trust domain (12ac626)
- Tutte le metriche rinominate da `atn.*` a `cullis.*` (16 metriche)
- Trust domain default da `atn.local` a `cullis.local`
- 20 file aggiornati (codice, test, compose, docs, alert rules)
- Pure rename, nessuna logica cambiata

### Grafana + Prometheus (7cc8f09)
- `prometheus/prometheus.yml` — scrape broker `/metrics` ogni 15s, alert rules da enterprise-kit
- `grafana/provisioning/` — datasource Prometheus + auto-load dashboard JSON
- `grafana/dashboards/broker-overview.json` — traffico, latenza p50/p95/p99, policy, rate limit
- `grafana/dashboards/broker-security.json` — cert pinning, audit chain, DPoP replay, token revocati, KMS seal
- Docker compose: Prometheus porta 9090, Grafana porta 3000
- Prod overrides: password obbligatoria, Prometheus non esposto, log rotation

### Cloud KMS — AWS, Azure, GCP (enterprise repo, d4ddf8d)
- `broker/kms/aws.py` — Secrets Manager per PEM + KMS envelope encryption (`aws:v1:` prefix)
- `broker/kms/azure.py` — Key Vault Secrets per PEM + Key Vault Keys RSA-OAEP (`azure:v1:` prefix)
- `broker/kms/gcp.py` — Secret Manager per PEM + Cloud KMS symmetric (`gcp:v1:` prefix)
- Tutti: async via executor, cache in-memory, `invalidate_cache()`, legacy plaintext passthrough

### Test
- 452 passed, 2 failed (postgres integration, richiede Docker)
- 60.000+ righe di codice totali nel progetto
- Tutto implementato da testare end-to-end su deploy reale

### Da testare
- [ ] Backup/restore su deploy reale
- [ ] Helm chart proxy su k8s/minikube
- [ ] Proxy --prod su VM
- [ ] Grafana dashboard su localhost:3000
- [ ] License key gating (402)
- [ ] Audit export S3 (MinIO o bucket reale)
- [ ] SAML con Okta/Azure AD dev
- [ ] Cloud KMS con account cloud
- [ ] Audit log expand UI
- [ ] Metriche cullis.* su /metrics

---

## 2026-04-10 — Semver v0.2.0, demo frozen, audit hardening D1-D8 (sessione 4)

### Semver + release tooling (65a10af)
- `VERSION` file come single source of truth
- `bump.sh` — patcha 7 file in agent-trust + opzionale `--enterprise`
- `CHANGELOG.md` root (keepachangelog.com, inglese)
- `.github/workflows/release.yml` — validate tag → test → docker push ghcr.io → SDK build → GitHub Release
- `ci.yml` ora espone `workflow_call` per riuso
- `Dockerfile` con `ARG APP_VERSION` per bake in `/health`
- Tutte le versioni bumped 0.1.0 → 0.2.0 (agent-trust + cullis-enterprise)
- `.gitignore` aggiornato per non ignorare CHANGELOG.md

### Demo frozen (c722675)
- Immagini Docker `cullis-broker:demo` e `cullis-mcp-proxy:demo` pushate su `ghcr.io/cullis-security/`
- `docker-compose.demo.yml` ora usa `image:` da ghcr.io, non builda da source
- `deploy_demo.sh` rimosso step `compose build`
- Da ora in poi: modifiche a `app/` e `mcp_proxy/` non impattano la demo
- Per aggiornare: rebuild + push manuale deliberato

### Security hardening D1-D8 (ecc4712, 16 file, 99+/38-)
- **D1** — `agent_console.py` ora legge `broker_ca_cert_path` per TLS verify su HTTPS, fallback False in dev
- **D2** — `verify_csrf()` aggiunto a `/setup/test-connection`, `/policies/test-webhook`, `/vault/test` (mcp_proxy)
- **D3** — `validate_config()` logga warning se `policy_webhook_verify_tls=False` in production
- **D5** — `safe_error(generic_msg, exc)` helper in `app/config.py`: dev ritorna dettagli, prod ritorna messaggio generico. Applicato a 12 callsite: readyz (3), broker-ca.pem, agent console, transaction token, SSO (2), cert verification (2), OPA, PDP webhook (2)
- **D8** — CSP nonce per-request:
  - Middleware `security_headers` genera `request.state.csp_nonce` via `secrets.token_urlsafe(16)`
  - `_NonceTemplates` wrapper auto-inject `csp_nonce` in ogni `TemplateResponse` (router.py + agent_console.py)
  - `script-src` ora usa `'nonce-{nonce}'` al posto di `'unsafe-inline'`
  - `style-src` resta `'unsafe-inline'` (Tailwind genera stili inline, nonce per CSS non praticabile)
  - 9 template aggiornati: base.html (4 script), login.html (2), register.html (2), agent_console.html (1), agent_detail.html (1), agent_manage.html (1)

### Test
- 407 passed, 0 failed (escludendo test_dashboard preesistenti e postgres integration)
- Smoke test demo: up → send → checker log OK con immagini frozen

---

## 2026-04-10 — Enterprise gap analysis + open-core strategy (strategy session)

Terza sessione della giornata. Analizzato documento esterno con raccomandazioni enterprise-readiness. Incrociato ogni punto con lo stato reale del codebase. Definita la strategia open-core e la linea di demarcazione community vs enterprise.

### Analisi documento enterprise-readiness — cosa avevamo gia

Il documento sovrastimava i gap in alcune aree:
- **Prometheus alert rules** → gia 8 regole in `enterprise-kit/monitoring/cullis-alerts.yml` (cert pinning, audit chain, DPoP replay, auth failure, PDP latency)
- **OIDC** → gia completo con Authorization Code + PKCE, per-org + admin, role mapping via claim path, JWKS cache
- **Vault KMS** → gia implementato con `KMSProvider` protocol estensibile via factory
- **Helm chart broker** → esiste con 20 template (HPA 2-10 replicas, PDB minAvailable=1, NetworkPolicy, resource limits, Prometheus ServiceMonitor). README dice "not yet production-validated" ma la struttura e solida

### Cosa mancava davvero

1. **SCIM** — non era nemmeno nel backlog, critico per enterprise (AD/Okta → ruoli automatici)
2. **Helm chart proxy** — broker ha Helm, proxy zero. Senza questo nessun deploy k8s per le org
3. **LLM Firewall nel proxy** — il modulo `app/injection/` (13 regex + Claude Haiku LLM judge) e dead code nel contesto E2E perche il broker non vede il plaintext. Va spostato nel proxy come middleware post-decrittazione
4. **Grafana dashboards** — le metriche ci sono, manca la visualizzazione preconfezionata. Low effort, alto impatto commerciale
5. **License key** — nessun meccanismo di gating. Chiunque puo usare tutto

### Fix demo — 5 scorciatoie intenzionali da chiudere

Dalla sessione precedente avevamo identificato 8 scelte demo intenzionali (D1-D8). 3 erano gia accettabili (D4 broker_ca_path ha validazione prod, D6 SSRF admin-only, D7 Vault token dev). 5 vanno chiuse:

- **D1** `_vault_verify()` hardcoded False — serve env var `MCP_PROXY_VAULT_VERIFY_TLS`
- **D2** CSRF mancante su 3 test endpoint HTMX — aggiungere `verify_csrf()`
- **D3** `policy_webhook_verify_tls=false` senza warning in prod
- **D5** Error messages leak exception details
- **D8** CSP `unsafe-inline` — richiede refactor template con nonce

### Decisione open-core: Pattern Plugin / Repo Privato

Scelta **Opzione 1** — il codice enterprise vive in un repo privato separato (`cullis-enterprise`) che importa il core come dipendenza Python e monta route/middleware aggiuntivi sulla FastAPI app.

Motivazione: il codice enterprise non tocca mai il repo pubblico. Un solo codebase core, una pipeline CI per il core + una per enterprise. Niente fork divergenti.

**Prerequisiti architetturali:**
1. Hook system — dependency injection points nel core (il KMS factory gia segue il pattern, estenderlo a auth e audit)
2. Interfacce stabili — API interne versionato che il plugin enterprise consuma

**Immagini Docker:**
- `cullis/broker` (community) e `cullis/broker-enterprise` (registry privato GHCR)
- `cullis/proxy` e `cullis/proxy-enterprise`

**License key:** JWT firmato RSA dalla chiave privata Cullis, validazione offline con pubkey hardcodata nel core. Payload: `{tier, exp, features[]}`. Gate nel codice: `license.has_feature("saml")`.

### Linea di demarcazione definita

**Community (Apache 2.0):** PKI/E2E/DPoP/SPIFFE, OIDC, Vault KMS, Postgres singolo, policy engine locale, audit log append-only, dashboard single-admin, Prometheus alerts, MCP Proxy standard.

**Enterprise (licenza commerciale):** SAML 2.0, SCIM directory sync, AWS/Azure/GCP KMS nativi, HA (Redis Cluster + Postgres multi-nodo), OPA federato, audit export S3/Datadog + retention, multi-admin RBAC, Grafana dashboards, LLM Firewall proxy.

La regola: open source tutto cio che serve allo sviluppatore singolo, fai pagare cio che serve ai manager, ai CISO e alla compliance.

`imp/status.md` aggiornato con nuove sezioni: "Fix demo lasciati aperti", "Open-Core Strategy", "Enterprise features".

---

## 2026-04-10 — Session lifecycle: auto-close pending, close da broker e proxy dashboard

### Problema
Le sessioni aperte sul broker restavano in stato `pending` indefinitamente se il target agent non le accettava. Il TTL era 60 minuti (troppo lungo), l'eviction girava solo alla creazione di nuove sessioni, e non c'era modo di chiudere manualmente una sessione dalla dashboard.

### Modifiche

**Broker API — close accetta pending** (`app/broker/router.py:344`)
- L'endpoint `POST /sessions/{id}/close` ora accetta sessioni `pending` oltre che `active`. Prima restituiva 409 Conflict per le pending.

**Background reaper — auto-close pending dopo 60s** (`app/main.py` + `app/broker/session.py`)
- Nuovo metodo `SessionStore.close_stale_pending(max_pending_seconds=60)` — trova e chiude sessioni pending piu vecchie di 60s.
- Nuova coroutine `_pending_session_reaper()` — background task nel lifespan del broker, sweep ogni 15s. Persiste su DB via `save_session()` ed emette SSE `session_closed` per refresh dashboard real-time.

**Broker dashboard — bottone Close** (`app/dashboard/router.py` + `sessions.html`)
- Nuova route `POST /dashboard/sessions/{session_id}/close` con CSRF protection.
- Bottone rosso "Close" su ogni riga active/pending nella tabella sessioni. Confirm dialog prima dell'azione.
- Audit event `session_closed` con `closed_by: dashboard_admin`.

**Proxy dashboard — pagina Sessions** (`mcp_proxy/dashboard/`)
- Nuova pagina `GET /proxy/sessions` — aggrega sessioni di tutti gli agent interni via `BrokerBridge.list_sessions()`. Mostra agent locale, agent remoto, org remota, status. Filtro per status (all/active/pending/closed).
- Nuova route `POST /proxy/sessions/{agent_id}/{session_id}/close` — chiude via bridge con audit log.
- Nuovo template `sessions.html` con bottone Close e layout coerente con le altre pagine proxy.
- Link "Sessions" aggiunto nella sidebar del proxy (`base.html`).

### File modificati
- `app/broker/router.py` — close accetta pending
- `app/broker/session.py` — `close_stale_pending()`
- `app/main.py` — `_pending_session_reaper()` + task nel lifespan
- `app/dashboard/router.py` — route `session_close`
- `app/dashboard/templates/sessions.html` — colonna Actions + bottone Close
- `mcp_proxy/dashboard/router.py` — route `sessions_list` + `session_close`
- `mcp_proxy/dashboard/templates/sessions.html` — nuovo template
- `mcp_proxy/dashboard/templates/base.html` — nav link Sessions

---

## 2026-04-10 — Multi-VM deploy, TLS hardening, code audit completo (engineering session)

Sessione divisa in due fasi: (1) verifica e completamento del deploy 3-VM con 8 bug fix emersi da un code audit completo, (2) gap analysis per produzione enterprise.

### Code audit — 3 subagenti paralleli per entry point

Lanciati 3 audit indipendenti, uno per ciascun entry point di deploy (`deploy_demo.sh`, `deploy_broker.sh`, `deploy_proxy.sh`). Ogni agente ha tracciato il grafo completo deploy script → compose → app code → handlers → templates, cercando dead code, flussi logici rotti, hardening gaps.

**Risultato lordo:** ~30 finding tra critical, high, medium, low. Dopo incrocio con i diff delle modifiche 3-VM, separati in:
- 8 bug reali (B1-B8) — fixati nella stessa sessione
- 8 scelte demo intenzionali (D1-D8) — `_vault_verify()` return False, CSRF su test endpoint HTMX, ecc.
- 4 issue gia fixati dal lavoro 3-VM (F1-F4) — centralizzazione verify=False, CA key path validation, ecc.

**Positive findings confermati:** DPoP RFC 9449 corretto, SSRF protection con DNS pinning, SQLAlchemy parametrizzato ovunque, Jinja2 autoescaping, CSRF HMAC-SHA256 su tutti i POST state-changing, graceful shutdown con drain mode, zero import incrociati broker/proxy.

### 8 bug fix (branch `feat/multivm-hardening`)

**B1 — sender timeout message:** `sender.py:140` diceva "5s" ma `_ACCEPT_WAIT_SECONDS = 30`. Sostituito con f-string dinamica `f"...within {_ACCEPT_WAIT_SECONDS:.0f}s..."`.

**B2 — import duplicato:** `app/broker/router.py` importava `get_agent_by_id` alla riga 25 e di nuovo come `_get_agent_by_id` alla riga 37. Rimosso il primo, rinominato il secondo, aggiornato l'unico uso a riga 437.

**B3 — cookie proxy secure=False hardcoded:** `mcp_proxy/dashboard/session.py:117` aveva `secure=False` con commento "set True behind TLS terminator" ma nessuno lo faceva. Ora legge `get_settings().proxy_public_url` e usa `startswith("https")`. Applicato sia a `set_session()` che a `clear_session()`.

**B4 — badge f-string non safe:** `app/dashboard/router.py` badge endpoints per pending-orgs e pending-sessions interpolavano `{count}` direttamente. Ora `int(count)` esplicito prima dell'interpolazione — defense-in-depth anche se `func.count()` di SQLAlchemy torna sempre int.

**B5 — nessun audit per login admin:** Il login handler (`app/dashboard/router.py:74-139`) non loggava ne successi ne fallimenti. Aggiunti 3 `log_event()`: `admin.login/ok` con method=bcrypt, `admin.login/ok` con method=env_secret (fallback), `admin.login/denied` con reason=invalid_password. Tutti includono `client_ip`.

**B6 — policy toggle non persistente:** `app/config.py` usava una variabile globale `_policy_override` separata da `Settings.policy_enforcement`. Al restart si perdeva. Eliminato `_policy_override`, `set_policy_enforcement()` ora scrive direttamente su `get_settings().policy_enforcement` (singleton Pydantic). Nota: il valore resta in-memory fino al restart — la persistenza cross-restart richiede il setup wizard o cambio env var.

**B7 — cookie broker Secure flag con string match:** `app/dashboard/session.py:118` usava `"https" in url.lower()` che matcherebbe anche `http://https-test.local`. Sostituito con `urlparse(url).scheme == "https"`. Applicato sia a `set_session()` che a `clear_session()`.

**B8 — health proxy senza bridge check:** `mcp_proxy/main.py` `/readyz` tornava 200 anche se BrokerBridge non era inizializzato (nessun broker_url configurato). Aggiunto check `broker_bridge` nel readiness probe — ora riporta `not_initialized` se mancante. Non blocca il readyz (il proxy puo funzionare senza egress per setup iniziale) ma e visibile.

### Gap analysis per produzione enterprise

Audit completo di `deploy_broker.sh` e `deploy_proxy.sh` per identificare cosa manca per vendere a clienti reali. Analisi su 12 assi: TLS, secrets, database, Vault, observability, availability, backup/DR, network, hardening, CI/CD, multi-tenancy, compliance.

**P0 bloccanti identificati:** Vault auto-unseal (un restart perde chiavi), proxy SQLite→Postgres (non scala), cert auto-renewal (365d self-signed), semver+image tags (nessun rollback), secret rotation (statico forever).

**P1 primo cliente enterprise:** Helm chart proxy, backup/DR runbook, audit log retention+export, cert expiry alerting, metrics proxy, mTLS proxy→broker, multi-admin RBAC.

**P2 differenziatori:** horizontal scaling, k8s network policies, image signing+SBOM, GDPR purge, Terraform modules, multi-region.

Status e DA FARE aggiornati in `imp/status.md`.

---

## 2026-04-09 — Asset di lancio: logo, blog HTML, social rebrand, cheat sheet (marketing session)

Sessione interamente dedicata alla preparazione del materiale di lancio. Nessuna modifica al broker o al proxy. Output: blog post pronto in HTML production-ready, drafts social rebrandati, cheat sheet operativo per le 3 fasi del lancio (pre-launch / D0 / follow-up), logo PNG croppato. Diagnosticato e flagged un blocker di deploy su Cloudflare Pages.

### Logo PNG cropped — `imp/logo_cullis.png`

L'utente lo riteneva "molto largo". Analisi pixel-per-pixel via PIL: source 2200×1201, background `#151c27` uniforme, contenuto cyan (portcullis grid) confinato a x=820-1380 / y=320-1092 — ovvero 820 px di margine sinistro vuoto contro 70 px a destra. Una stellina decorativa minima (~14 pixel cyan) a x=2082-2130, isolata, parte di una composizione "wide" che non aveva senso in un crop tight.

Crop scelto: square 1000×1000 centrato sul grid (`(600, 201, 1600, 1201)`), drop della stellina, mantenuto background dark. File size 1.4MB → 770KB. Backup `imp/logo_cullis.png.bak`, originale `.orig` (2814×1536) intatto. Verificato visualmente.

Nota: `docs/cullis.svg`, `app/static/cullis.svg`, `cullis.svg` sono già con `viewBox="520 199 368 370"` (cropped tight, senza stellina). Il PNG era l'unico asset non allineato — la landing live usa solo SVG quindi il crop non impatta il sito.

### Blog post — rebrand + "Why Cullis"

`imp/blog_why_api_keys_broken.md`:
- "Agent Trust Network (ATN)" → "Cullis"
- `[GITHUB_LINK]` placeholder × 2 → `https://github.com/cullis-security/cullis`
- Footer: aggiunto `hello@cullis.io` (general) + `security@cullis.io` (disclosure) + link a `cullis.io`
- Author tag: "Agent Trust Network is Apache-2.0 licensed" → "Cullis is Apache-2.0 licensed and lives at cullis.io"

Aggiunto paragrafo "Why Cullis" (~80 parole) inserito dopo "We're building this", spiegando l'origine dal portcullis (saracinesca metallica medievale) come metafora deliberata: chokepoint hardened, identità crittografica al posto del riconoscimento facciale, "zero standing trust, every passage checked". Hook narrativo che ATN non aveva.

### Blog HTML production-ready — `docs/blog/why-api-keys-broken.html`

Conversione del markdown in HTML self-contained pronto per il deploy. 703 righe, 28KB. Design system identico a `docs/index.html`:

| Token | Valore |
|---|---|
| Display headings | Instrument Serif italic, accent `--accent-cyan #00e5c7` |
| Body | Satoshi 1.05rem line-height 1.75 |
| Mono / code blocks | DM Mono, background `--bg-elevated`, border-left teal 2px |
| Brand lockup | Chakra Petch (nav logo) |
| Backgrounds | `--bg-void #050508` body, `--bg-elevated #10121a` code |

**Struttura:**
- `<head>`: meta description SEO + Open Graph (og:type article, article:published_time, article:section, article:tag×4) + Twitter Card + JSON-LD `BlogPosting` schema completo (headline, author Organization, publisher logo, datePublished, mainEntityOfPage, wordCount)
- Nav fissa con scroll-shrink (RAF-throttled, padding `1.15rem→0.7rem`, logo `32→26px` a scroll>80px) — coerente con la landing
- Article container `max-width: 720px`, padding top 8rem per non sovrapporre la nav fissa
- Eyebrow con dot pulse + breadcrumb "Cullis · Blog"
- H1 `clamp(2.4rem, 5vw, 3.6rem)` Instrument Serif, line-height 1.08
- Subtitle 1.18rem secondary
- Article meta strip (data, reading time 7 min, autore) con sep dots, border-bottom subtle
- H2 italic teal con letterspacing
- Bullets custom: dash teal `width:6px;height:1px` invece di disc
- Code blocks: border-left accent 2px, padding generoso, scrollabili
- Inline code: cyan + bordo subtle
- Footer 4 colonne (Brand · Project · Security · Community) identico alla landing
- Footer bottom con copyright + tagline "Engineered for zero-trust, built for the agent era"
- Background noise texture inline SVG (`opacity: 0.04`, fixed inset)
- Responsive `<768px`: padding ridotto, font ridotto, code blocks 0.78rem, nav links 3+ nascosti, footer 1-col
- A11y: `prefers-reduced-motion` disabilita transizioni, ARIA su nav, semantic `<article>`/`<footer>`, `rel="noopener"` su tutti i `target="_blank"`

Path interni: `../cullis.svg`, `../favicon-32.png`, `../apple-touch-icon.png`, `../` per home — funzionano con la struttura `cullis.io/` → `cullis.io/blog/why-api-keys-broken.html`. Canonical URL `https://cullis.io/blog/why-api-keys-broken` (clean URL senza .html).

### Social drafts — rebrand `imp/social_drafts_x.md`

- Header file: "ATN Social Media Drafts" → "Cullis Social Media Drafts"
- Tweet 1 launch announcement: "Introducing Agent Trust Network (ATN)" → "Introducing Cullis", `[GITHUB_LINK]` → `cullis.io · github.com/cullis-security/cullis`
- Tweet 2 launch: "ATN is a credential broker" → "Cullis is a credential broker"
- Tweet 6 launch numbers: **"200+ tests" → "440+ tests"** (verificato `pytest --collect-only -q` = 446 totali, 443 collected, 3 deselected)
- Tweet 7 quickstart: `git clone [GITHUB_LINK]` → `git clone https://github.com/cullis-security/cullis`, `cd agent-trust-network` → `cd cullis`
- Tweet 8 CTA: `[GITHUB_LINK]` → `github.com/cullis-security/cullis`
- 3a Red Team Angle: "Agent Trust Network is open source now" → "Cullis is open source now"
- 3b Technical Flex: "Every ATN access token" → "Every Cullis access token"
- 3e Build-in-Public: "ATN build update" → "Cullis build update", repo link aggiornato
- Header sezione: "## 2. LAUNCH DAY THREAD: Introducing Agent Trust Network" → "Cullis"

Verifica finale: zero residui di `ATN|GITHUB_LINK|Agent Trust Network|agent-trust-network|200+ tests` nel file.

### Social drafts — rebrand `imp/social_drafts_linkedin.md`

- Header file: "LinkedIn Post Drafts — Agent Trust Network" → "Cullis"
- Post 2 LAUNCH ANNOUNCEMENT (topic + body): "Agent Trust Network (ATN)" → "Cullis", `[GITHUB_LINK]` → `https://github.com/cullis-security/cullis`
- **"388 tests passing" → "440+ tests passing"**
- **Rimosso claim "has been through 2 internal security audits"** dal launch post (claim non verificabile, rischio reputazionale al lancio — l'utente lo ha confermato)
- Post 3 TECHNICAL DEEP-DIVE: "In ATN, every access token" → "In Cullis", "the security primitives in Agent Trust Network" → "in Cullis"
- Post 4 FOUNDER STORY: "That is how Agent Trust Network was built" → "Cullis"
- Talking Points table: "388 tests" → "440+ tests", **rimossa riga "Security audits | 2 internal security audits completed"**, differentiator vs SPIFFE/OAuth: "ATN solves" → "Cullis solves" / "ATN is built" → "Cullis is built"

### Launch cheat sheet — `imp/launch_cheatsheet.md` (nuovo)

Documento operativo per il giorno del lancio. Struttura:

1. **Pre-flight checklist** — 8 item da chiudere prima di D-7 (deploy verificato, homepage URL repo, blog HTML pubblicato, og-image presente, GitHub social preview, account social loggati, test card preview LinkedIn/Slack)
2. **Fase 1 — Pre-launch (D-7 → D-1)** — LinkedIn pre-launch post mat, X pre-launch thread pom (stesso giorno), poi silenzio D-3 → D-1
3. **Fase 2 — Launch day (D0)** — sequenza minuto per minuto:
   - 07:30 final check `curl -s https://cullis.io | head -3`
   - 08:00 blog post LIVE
   - 08:30 LinkedIn launch
   - 09:00 X launch thread
   - 10:00 Show HN (titolo + URL + body)
   - 11:00 Reddit r/netsec (link al blog)
   - 14:00 outreach soft (Simon Willison X mention, tl;dr sec mail)
4. **Regole D0** — rispondere entro 1h, no argomentazioni difensive, no nuovi commit durante 24h, monitor metriche
5. **Fase 3 — Follow-up (D+4 → D+14)** — LinkedIn deep-dive D+4, X technical flex D+4, LinkedIn founder story D+8, X red team angle D+10, X engagement bait D+14
6. **Metriche fine settimana 1** — target minimi vs buoni (stars, HN posizione, impression LinkedIn/X, first PR, first "trying it" reply)
7. **Snippet pronti copia-incolla** — HN title + body 2 paragrafi, Reddit r/netsec title, X mention Simon Willison
8. **Errori da evitare** — niente marketing speak su HN/r/netsec, niente cross-posting reddit, dev.to dopo 24-48h con `rel=canonical` verso cullis.io, mai rispondere ai troll, niente troppe feature alla volta

### Cloudflare Pages — diagnostica deploy desync

User vede badge "repo not found" sulla landing live. Investigazione:

1. `curl -s https://cullis.io | grep shields.io` → live HTML referenzia ancora `DaenAIHax/cullis` (vecchio nome). Local `docs/index.html` (commit `b0beeb6`) ha già `cullis-security/cullis`. ⇒ deploy desync.
2. `gh api repos/cullis-security/cullis/pages` → 404 (GitHub Pages non abilitato).
3. Nessun `wrangler.toml` / `netlify.toml` / `vercel.json` nel repo.
4. `gh api repos/cullis-security/cullis/hooks` → `[]` (zero webhook sul repo).
5. Conferma user: deploy via **Cloudflare Pages connesso a Git**.

Screenshot user rivela: il connettore Cloudflare ha **ancora** "Git repository: DaenAIHax/cullis" (vecchio handle, nemmeno `cullis-security/cullis`) + warning blu *"There is an internal issue with your Cloudflare Workers & Pages Git installation. If this issue persists after reinstalling your installation please contact support"*.

Causa: la GitHub App di Cloudflare Pages era installata su `DaenAIHax` personal account. Quando il repo è stato trasferito all'org `cullis-security`, la App non si è migrata + il webhook non è stato ricreato sul nuovo path.

Tentativo di fix: empty commit per triggerare webhook (`git commit --allow-empty -m "chore(deploy): trigger Cloudflare Pages rebuild after repo rename"` + `git push -u origin main`). Verificato dopo 90s: `curl -s https://cullis.io` ancora vecchia URL → webhook **non** ha fatto fuoco (confermato come previsto).

Soluzione adottata dall'user: **manual upload via Cloudflare Pages dashboard**, bypassando completamente la GitHub App. Build settings: framework preset `None`, build command vuoto, **build output directory `docs`** (importante — vuoto serviva la repo root e i file index.html non sono lì; si trovano in `docs/`).

Nota tecnica: durante il push, `git config --get branch.main.remote` era vuoto (tracking config persa, probabilmente da operazioni passate). Risolto con `git push -u origin main`.

### Verifiche stato corrente

| Cosa | Stato |
|---|---|
| Repo `cullis-security/cullis` | PUBLIC, Apache-2.0, in org, last push commit `5e40914` (empty) |
| Landing `https://cullis.io` | HTTP 200 via Cloudflare (DYNAMIC, no edge cache) |
| Test count | 446 totali, 443 collected (3 deselected, probabilmente e2e che richiedono Docker), 39 file di test + 1 e2e |
| Description repo | "Trust infrastructure for AI agents across organizations. Verified identity, explicit authorization, cryptographic audit trail." |
| Homepage URL repo | **NON impostato** ancora (TODO: `gh repo edit cullis-security/cullis --homepage https://cullis.io`) |
| `docs/og-image.png` | **MANCANTE** (referenced da `<meta property="og:image">` in index.html e in blog HTML — share su LinkedIn/X mostreranno card rotte fino a creazione) |

### TODO sbloccato per prossima sessione

1. Verificare deploy Cloudflare propagato (badge `repo not found` → fixato dopo manual upload nuovo)
2. Deployare anche `docs/blog/why-api-keys-broken.html` (= prossimo upload Pages)
3. `gh repo edit cullis-security/cullis --homepage https://cullis.io` (1 comando)
4. Generare `docs/og-image.png` 1200×630 dal logo croppato + tagline (deferred dall'user con "lascia cosi adesso l'immagine")
5. Decidere se aggiungere link "Blog" alla nav della landing
6. Decidere se creare `docs/blog/index.html` (per ora 1 solo articolo, può aspettare)

---

## 2026-04-08 — Landing cullis.io + restyle broker dashboard (UI session)

Sessione dedicata alla presentation layer: rework completo del sito marketing `docs/index.html` (11 sprint audit-driven) e restyle coerente di tutti i 23 template del broker dashboard per allinearli al design system del MCP proxy. Nessuna modifica a logica applicativa.

### Landing cullis.io — `docs/index.html`

Stato iniziale: 1282 righe, 15 feature card, stats fake, tagline vago, comparison vs strawman. Stato finale: ~2100 righe, 6 pilastri interattivi, comparison vs competitor reali, hero con terminale Python auto-typing.

**Sprint 1 — Hero redesign + a11y base.** Tagline nuovo *"Cryptographic identity and E2E messaging for AI agents that work across organizations"*. Hero a 2 colonne: testo+CTA sinistra, terminale animato Python SDK destra (self-typing con `@keyframes line-in` staggered + cursor blinking). CTA ribilanciate: `Read the Docs →` primary + `View on GitHub` ghost. Fix contrasto `--text-tertiary #555868 → #6e7180` (WCAG AA, 18 occorrenze SVG architecture sostituite). `@media (prefers-reduced-motion: reduce)` che disabilita reveal, typing, cursor, pulse, flow-line.

**Sprint 2 — Features 15 → 6 pilastri.** Collapsed in: Identity, E2E Encryption, Federated Authorization, Tamper-Evident Audit, Self-Service Federation, SDK & Developer Tools. Poi sostituito dal layout tabbed di Sprint 10.

**Sprint 3 — Enterprise → Use Cases.** Rimossa seconda griglia "Enterprise features" (duplicata con Features). Sostituita con 3 use case concreti con flow numerato: (1) Cross-Org RFQ Negotiation per supply chain, (2) Multi-Tenant SaaS customer↔vendor agents, (3) Regulated B2B Data Exchange con BYOCA + OPA.

**Sprint 4 — Comparison con competitor reali.** Rimossi API Keys/OAuth (strawman). Colonne nuove: MCP (raw), SPIFFE/SPIRE, Vault+Consul, Cullis. 9 righe mirate sulla federazione cross-org. Aggiunta nota "composes with" per chiarire posizionamento (Cullis compone con questi tool, non li sostituisce).

**Sprint 5 — Stats bar → Standards bar.** Rimossi numeri non credibili (`450+ tests`, `2 components`, ecc.). Sostituiti con standards/facts bar: RFC 9449, SPIFFE, x509·mTLS, AES-256-GCM, Apache 2.0, Self-Hosted. Ogni tile ha hover con border-line teal che si estende.

**Sprint 6 — Meta social + favicon + structured data.** Open Graph (FB/LinkedIn) + Twitter card + JSON-LD `SoftwareApplication` schema + canonical URL + theme-color. Favicon SVG primario + PNG fallback 32×32 + apple-touch-icon 180×180 (file PNG da generare separatamente).

**Sprint 7 — Copy button terminale Quickstart.** Bottone `Copy` nella barra terminale con clipboard feedback (`.copied` state + "Copied" label). Attributo `data-copy` per mantenere il testo copiato pulito (no HTML).

**Sprint 8 — Social proof hero.** Strip con: GitHub stars badge via shields.io (stile teal custom `color=6e7180&labelColor=00000000`), link Discussions, badge Apache 2.0. Footer CTA: `Contributing Guide` → `Join Discussions` (community-first).

**Sprint 9 — Nav scroll-shrink.** Nav padding `1.15rem → 0.7rem` a scroll > 80px, logo `32px → 26px`, background opacity + blur intensify. RAF-throttled scroll listener.

**Sprint 10 — Pillars tabbed showcase (stile Tailscale).** Sostituito `.pillar-grid` 2×3 con: 6 tab in riga + stage 2-col che swap contenuto al click. Tab attivo si alza `translateY(-6px)` con gradient teal + freccia diamante che punta al pannello. Animation `panel-fade` 0.5s. 6 mock visual custom (coerenti con terminal style `#0c0d12` + 3 dot macOS + badge teal):
1. **Identity** — card agent con Pinned badge + SPIFFE ID + thumbprint SHA-256
2. **E2E** — 3-node flow Agent A → `Broker BLIND` (rosso) → Agent B con stamp AES-256-GCM · RSA-OAEP · RSA-PSS×2
3. **Authorization** — dual PDP verdict (Org A allow, Org B allow) + session granted
4. **Audit** — hash-chain 4 blocchi con ID + hash troncato + verify stamp
5. **Federation** — 4-step onboarding flow (generate invite → paste → auto PKI → active)
6. **SDKs** — Python code snippet con `cullis.vault.load_pem` (coerente con pattern BYOCA)

Keyboard navigation: Arrow ←/→ tra tab con focus shift. ARIA completo: `role="tablist/tab/tabpanel"`, `aria-selected`, `aria-controls`, `aria-labelledby`.

**Sprint 11 — Audit closure.** Tagline CTA: *"Engineered for zero-trust, built for the agent era"* (sostituisce *"Built by security researchers..."*, che rischiava di essere marketing gonfiato per un solo-dev). Footer bottom matches. `<nav role="navigation" aria-label="Primary">`. Architecture SVG con `<title>` + `<desc>` verbose per screen reader (lettura del flow completo agent → proxy → broker → PDP). Terminal Quickstart: `.sr-only` labels per distinguere prompt/cmd/output/comment senza affidarsi solo al colore (WCAG 1.4.1). Noise texture opacity `0.025 → 0.04` (ora visibile). Problem cards: 3 icone diverse (broken lock, broken link, crossed eye) invece di 3 identiche `×`. Footer Community column aggiunta: Discussions, Changelog, `hello@cullis.io`. Roadmap link aggiunto a Project column. `rel="noopener"` su tutti gli `target="_blank"` rimasti.

### Design system finalizzato (site + dashboard)

| Token | Valore |
|---|---|
| Display | Instrument Serif (italic teal per `<em>`) |
| Body | Satoshi |
| Mono | DM Mono |
| Brand | Chakra Petch (solo logo lockup) |
| BG void | `#050508` |
| BG surface | `#0a0b10` |
| Accent teal | `#00e5c7` (identico a MCP proxy dashboard) |
| Text tertiary | `#6e7180` (WCAG AA, raised from `#555868`) |

### Broker dashboard — restyle 23 template (`app/dashboard/templates/`)

Refactor completo per allineare il broker dashboard allo stile del MCP proxy. Tailwind config con `surface/accent/info` color tokens, font system Chakra Petch (heading) + DM Sans (body) + JetBrains Mono (code). Sidebar con `nav-active` border-left teal + accent background. Top bar con `header_title` block + status pulse-dot badges. Card con `backdrop-blur` + `card-glow` hover. Form inputs `bg-surface-950` + `border-gray-700/60` + focus teal. Bottoni primari cyber-style Chakra Petch teal → bianco con glow hover. Custom scrollbar, toast container, `showToast`/`copyToClipboard` globals.

**Template refactorati:** base, login, overview, agents, sessions, orgs, audit, policies, policy_create, agent_detail, agent_manage, agent_register, agent_console, rfqs, rfq_detail, register, org_onboard, org_upload_ca, invite_created, cert_rotate, cert_upload, settings (preservata sezione OIDC Role Mapping aggiunta in parallelo dalla session fix-test), admin_settings.

Nessuna modifica a: logica HTMX, SSE, CSRF, endpoint URL, form action, ARIA condizionali, script SSE `connect()` (solo adeguamento selettori CSS per il nuovo dot style 1.5×1.5 + colori accent).

### TODO non bloccanti (documentati in `docs/website_plan.md`)

**Asset esterni da generare:**
- `docs/og-image.png` 1200×630 per social share preview
- `docs/favicon-32.png` + `apple-touch-icon.png` 180×180

**Performance:**
- Font self-hosting (~200KB → ~60KB stimato). Subset suggerito: Satoshi 400/500/700, Instrument Serif 400 italic, DM Mono 400/500, Chakra Petch 600. Richiede download woff2 in `docs/fonts/` + `@font-face` inline.

**Branding pending (decisione umana):**
- Rename repo/org `DaenAIHax/cullis` → `cullis-security/cullis` (handle personale informale per vendere Trust Broker enterprise a banche/assicurazioni)
- Dichiarare maintainer come "Independent Security Researcher" o "Software Architect" (il codice legittima il titolo)
- Origin story 3-4 righe nel README
- Setup mailbox `hello@cullis.io` a dominio live

### Commit

- `6053fa7` — Restyle broker dashboard to match MCP proxy aesthetic (23 file, +1358/-976)
- (next) — Landing cullis.io: 11-sprint audit-driven redesign (2 file: `docs/index.html`, `docs/website_plan.md`)

### File NUOVI creati in sessione

- `docs/website_plan.md` — piano sito completo con audit history, 11 sprint documentati, TODO gap analysis, deploy instructions
- `memory/project_landing_redesign.md` — memoria persistente per Claude

---

## 2026-04-07/08 — MCP Proxy Enterprise Gateway + E2E + Deploy Split

### MCP Proxy (implementato — 44 file, 7500+ righe)
Componente standalone (`mcp_proxy/`) che sostituisce quickstart.sh e la generazione manuale dei certificati. Le org fanno tutto dalla dashboard del proxy.

**Flusso enterprise completo:**
1. Broker admin genera invite token dalla dashboard broker
2. Org admin apre proxy dashboard → inserisce broker URL + invite token
3. Registra org → CA generata automaticamente (RSA-4096) → proxy chiama broker `/onboarding/join`
4. Broker admin approva → polling HTMX aggiorna banner a "Active"
5. Crea agente → cert x509 firmato Org CA → binding auto al broker → API key locale

**Moduli:**
- `config.py` — ProxySettings pydantic-settings, `proxy.env` separato dal broker `.env`
- `db.py` — SQLite async via aiosqlite (internal_agents, audit_log, proxy_config)
- `auth/` — DPoP RFC 9449 (port da broker), JWT RS256 validation, JWKS client (1h cache + retry), API key bcrypt
- `tools/` — ToolRegistry decorator, WhitelistedTransport httpx, SecretProvider (Vault/env), executor con timeout 30s
- `ingress/router.py` — `POST /v1/ingress/execute`, `GET /v1/ingress/tools` (JWT+DPoP auth)
- `egress/` — AgentManager (x509 cert issuance + Vault storage), BrokerBridge (CullisClient pool per-agent), 7 endpoint (sessions, send, discover, tools/invoke)
- `dashboard/` — 11 template HTML: login, register, agents, agent_detail, tools, pki, vault, policies, audit, setup, base
- `Dockerfile` + `docker-compose.proxy.yml` — deploy standalone con volume per SQLite

**Dashboard features:**
- Login con broker URL + invite token (non piu password)
- Register org con auto-generazione CA + chiamata broker
- Agent CRUD con cert + binding broker + API key one-time
- Agent delete permanente + deactivate
- PKI overview: CA info, export cert, rotate con conferma
- Vault: config, test, migrazione chiavi DB→Vault
- Audit log paginato e filtrabile
- Policy editor (regole JSON built-in + webhook PDP esterno)
- Banner org status HTMX auto-refresh

### Broker: Invite Tokens
- `app/onboarding/invite_store.py` — generazione/validazione/consumo atomico token
- SHA-256 hash (plaintext mai salvato), expiry configurabile, revocazione admin
- Dashboard: genera token (label + TTL), lista con status, revoca
- `POST /v1/onboarding/join` ora richiede invite_token obbligatorio
- Template `invite_created.html` con copy button

### Broker: Org Self-Status
- `GET /v1/registry/orgs/me` — org può controllare il proprio status (pending/active/rejected)
- Auth via X-Org-Id + X-Org-Secret (no admin secret richiesto)
- Usato dal proxy per polling status dopo registrazione

### Broker fixes
- CSP: aggiunto `'unsafe-inline'` a script-src per dashboard (fix tab JavaScript)
- Agent manage tabs: aggiunto `type="button"` ai tab buttons (fix click handler)
- Alembic: fix multiple heads (invite_tokens migration chain → dipende da agent_description)
- `sse-starlette` pinnato a `>=2.0,<3.0` (fix conflitto con starlette 0.41)
- `requirements.txt`: aggiunto pin sse-starlette

### Agent Developer Portal
- Agent detail page riscritta come developer portal con 4 tab: Overview, Connect, Activity, Danger Zone
- **Connect tab**: 6 sub-tab con snippet pre-compilati (valori reali dell'agente):
  - Python (httpx) — discover, open session, send, poll
  - cURL — tutti gli endpoint egress
  - Node.js (fetch) — stesso flusso
  - Docker — docker run + compose con env vars
  - MCP Config — JSON per Claude/LLM con cullis_sdk.mcp_server
  - IoT/Edge — env vars + warning sicurezza (TPM, per-device keys)
- Copy button su ogni snippet
- Warning: browser SPA non supportato (API key esposta in JS)
- `GET /proxy/agents/{id}/env-download` — scarica .env con configurazione agente
- Router passa `proxy_url`, `broker_url`, `org_id`, `agent_name`, `api_key_display` al template
- Dopo rotate key, snippet mostrano la key reale

### README + Landing Page
- README riscritto: sezione Two Components (Broker + Proxy), architettura mermaid con fasi ①-⑦, MCP Proxy section, quick start aggiornato, self-hosted ovunque
- Landing page (`docs/index.html`): nuove feature cards (MCP Proxy, Auto PKI, Invite Onboarding), SVG architettura con proxy layer, enterprise section aggiornata, quick start con 2 step (broker + proxy), comparison table +2 righe

### E2E Communication Testato (2026-04-07/08)
Flusso completo verificato: Agent → API Key → Proxy → x509+DPoP+E2E → Broker → Decryption → Agent
- Open session [200] → Accept [200] → Send E2E message [200] → Poll [200] → Reply [200] → Receive [200]
- Fix critici durante il debugging:
  - `cullis_sdk/client.py`: `sys.exit(1)` → eccezioni (uccideva il proxy)
  - `main.py`: init BrokerBridge + AgentManager nel lifespan
  - `agent_manager.py`: login al broker per pinnare cert, binding + auto-approve, legge config dal DB
  - `broker_bridge.py` + `egress/router.py`: aggiunto `accept_session`
  - Trust domain default corretto: `cullis.local` → `atn.local`

### Docker Networking Fix
- Proxy si unisce alla rete `agent-trust_default` del broker (external network)
- PDP integrato nel proxy (`POST /pdp/policy`) — rimosso container PDP separato
- Broker→PDP via Docker DNS: `http://mcp-proxy:9100/pdp/policy` ✓
- Proxy→Broker via Docker DNS: `http://broker:8000` ✓
- Mock PDPs rimossi da `docker-compose.yml`

### Deploy Split
- `deploy.sh` → wrapper interattivo (broker / proxy / both), backward compat con `--dev`
- `deploy_broker.sh` — broker completo (PKI, .env, Docker, Vault, migrations)
- `deploy_proxy.sh` — proxy (build, start, health check)

---

## 2026-04-07 — Unified .env Generation + MCP Proxy planning

### Unified .env Generation (implementato)
- `scripts/generate-env.sh` — script standalone con `--defaults`, `--prod`, `--force`
- `setup.sh` — chiama `generate-env.sh --defaults --force` se `.env` manca
- `deploy.sh` — ~90 righe inline sostituite con 5 righe che delegano a `generate-env.sh`
- `docker-compose.yml` — `POSTGRES_PASSWORD` variabile (`${POSTGRES_PASSWORD:-atn}`)
- `app/config.py` — `validate_config()` blocca boot se ADMIN_SECRET e' il default (anche in dev)
- `tests/conftest.py` — `ADMIN_SECRET=test-secret-not-default`, ADMIN_HEADERS aggiornato
- 380 test passano, 0 regressioni

### Piano MCP Proxy Egress Gateway (`imp/mcp_proxy_plan.md`)
- Architettura completa: `mcp_proxy/` come componente standalone (zero import da `app/`)
- 16 file pianificati: config, main, models, router, auth (4 moduli), tools (5 moduli + 2 builtin), YAML, Dockerfile
- Decisioni architetturali:
  - JWKS: fetch remoto + cache 1h + retry su kid miss
  - Tool Registry: decoratore `@tool_registry.register()`
  - Domain whitelist: custom `WhitelistedTransport` httpx (defense-in-depth)
  - Secrets: `SecretProvider` protocol (Vault-first, env fallback)
  - Config: pydantic-settings + YAML per tool definitions
- Auth: port DPoP + JWT validation da broker (solo validazione, no token creation)
- 5 fasi implementazione definite con file list per fase
- Flusso richiesta documentato end-to-end (DPoP+JWT → capability check → tool dispatch)
- Rischi e mitigazioni mappati
- Piano verifica con 8 test case

### Piano Unified .env Generation (`imp/unified_env_plan.md`)
- Problema: `docker compose up` senza `deploy.sh` gira con `ADMIN_SECRET=change-me-in-production`
- Soluzione: estrarre generazione .env in `scripts/generate-env.sh` standalone
- `setup.sh` e `deploy.sh` chiamano lo stesso script (zero duplicazione)
- `docker-compose.yml`: POSTGRES_PASSWORD variabile (non piu' hardcoded `atn`)
- `validate_config()`: blocca boot se ADMIN_SECRET e' default (anche in development)
- Ultima linea di difesa: chi fa `docker compose up` diretto senza .env → errore chiaro

### Status aggiornato
- Sezione "IN PIANIFICAZIONE" aggiunta con MCP Proxy + Unified .env

---

## 2026-04-06 — Rebrand completo → Cullis

### Rebrand (5 agenti paralleli)
- README.md, CONTRIBUTING.md, SECURITY.md, ops-runbook, issue templates → "Cullis"
- FastAPI app title → "Cullis — Federated Trust Broker"
- Dashboard templates: base, login, register, overview → "Cullis"
- config.py: `otel_service_name` → `cullis-broker`
- docker-compose.yml, .env.example: OTEL_SERVICE_NAME → `cullis-broker`
- deploy.sh, setup.sh, pg-backup.sh, pg-restore.sh → header "Cullis"
- vault/config.hcl, vault/init-vault.sh → header "Cullis"
- SDK Python (sdk.py) docstring → "Cullis"
- SDK TypeScript: package.json, README, index.ts → "Cullis"
- Enterprise kit: BYOCA.md, quickstart.sh, docker-compose, PDP template, OPA policy → "Cullis"
- Landing page (docs/index.html) → "Cullis" (in corso)
- Dominio: **cullis.io** registrato su Cloudflare

### Cosa NON è cambiato (intenzionalmente)
- Nomi moduli Python (`app/`, `agents/`), variabili, import paths
- Nomi container Docker, service names
- Logger name `agent_trust` (interno, non user-facing)
- OPA package path `atn.session`
- GitHub repo URL (da rinominare separatamente)

---

## 2026-04-06 — Naming & Brand Strategy

### Brainstorming nome (3 round con Gemini + Claude)
- Esplorati ~40 nomi da: latino, Tolkien, JJK, Dune, HP, GoT, Marvel, architettura medievale, pattern startup
- Scartati per conflitti: Pactum (Pactum AI), Trustline (Stellar), Sigil (ebook editor), Keystone (OpenStack), Citadel (hedge fund), Janus (WebRTC), Bifrost (crypto), Mentat (skincare), Tenet (healthcare)
- Shortlist finale: Argonath, Cullis, Barbican, Fidelius, Bulwark, Anor
- **Decisione: Cullis** — dalla "portcullis" (saracinesca medievale), metafora di allow/deny

### Strategia azienda vs prodotto
- **Cullis** = nome prodotto (trust broker)
- Nome azienda = da definire durante l'anno (pattern HashiCorp/Vault)
- Dominio: **cullis.tech** ($6.99/anno su Porkbun) — .dev e .com presi
- Dopo validazione clienti → nome azienda definitivo + dominio .com o .dev

### Domini verificati (disponibilità)
- cullis.dev ❌ (preso, parcheggiato su Netlify)
- cullis.com ❌ (preso)
- cullis.tech ✅ $6.99/anno (rinnovo $50.98)
- cullis.io ✅ $28.12/anno

---

## 2026-04-06 — Production Deployment Automation + CI Green

### Production Blockers Risolti
- `deploy.sh` — script one-command con modalità dev/prod/Let's Encrypt, genera secrets, PKI, avvia Docker
- CORS fix — default da `*` a vuoto (fail-safe), WebSocket origin check allineato
- Startup validation — `validate_config()` blocca boot in produzione se config critiche mancano (DB, PKI, admin_secret)
- `ENVIRONMENT` env var — `development` (default) o `production` per strictness
- Vault produzione — `vault/config.hcl` (file storage), `vault/init-vault.sh` (Shamir 5/3 unsealing)
- Postgres backup — `scripts/pg-backup.sh` (30-day rotation) + `scripts/pg-restore.sh`
- `docker-compose.prod.yml` — Vault prod override con volume persistente + IPC_LOCK
- `.env.example` aggiornato con ENVIRONMENT, CORS docs, Vault prod notes

### README.md
- Riscritto da zero — one-liner, key features raggruppati, SDKs, enterprise, security, positioning table
- Allineato a stato reale del progetto (350+ test, 3 audit rounds, 7 CVE, SDK TS, OIDC, OPA, RFQ)

### Dashboard Settings
- BYOCA + Generate Demo CA — due opzioni nel settings template con warning produzione
- Admin Settings page con cambio password (bcrypt, CSRF, min 12 char, audit log)
- Admin secret in Vault con bootstrap automatico da .env

### CI Pipeline Green
- Alembic migration verification — `alembic upgrade head` su DB pulito in CI
- 8 fix ruff lint (F401 unused imports, F841 unused variable)
- 11 test fix per CI:
  - Dashboard login: reset admin_secret cache + hmac fallback sempre attivo
  - Certs: inject ephemeral KMS provider nel conftest (no dipendenza da certs/ su disco)
  - org_store: `extra` property spostata nella classe OrganizationRecord
  - Nonce cache: eviction (H2) invece di blocking, allineati entrambi i test
  - Health readyz: mock Redis/KMS
  - Login form fields: `user_id`/`password` al posto dei vecchi `login_type`/`admin_secret`
- Rimosso `-x` da pytest, ignorati test postgres integration (richiedono Docker)
- **Risultato: 381 passed, 4 skipped, 0 failed**

### Risultato sessione
- 10 commit, ~1600 righe aggiunte
- CI completamente verde per la prima volta con tutti i production blockers risolti
- Rimane solo TLS (Let's Encrypt) — richiede dominio

---

## 2026-04-06 — Agent Developer Portal + PyJWT + SDK TS + Prod Config

### Agent Developer Portal
- `GET /dashboard/agents/{id}` — pagina stile Stripe/Twilio per agente
- Sezione 1: Agent info (status, capabilities, binding, WebSocket live/offline, cert expiry)
- Sezione 2: Credentials con due opzioni (stesso pattern di org settings):
  - **Option 1 — Upload Certificate (BYOCA):** upload cert firmato dalla CA org, valida PEM + CN + chain CA. Chiave privata mai sul broker.
  - **Option 2 — Generate Demo Credentials (dev only):** genera cert+key sul broker con warning amber
- `POST /dashboard/agents/{id}/upload-cert` — upload con validazione completa
- `POST /dashboard/agents/{id}/credentials` — download zip credentials-only (agent.pem, agent-key.pem, agent.env)
- Sezione 3: Integration Guide con tab Python/TypeScript/cURL, snippet pre-compilati con broker URL e agent ID, copy button
- Sezione 4: Recent Activity — ultimi 10 eventi audit per agente
- agents.html: nome agente cliccabile, "Download Bundle" sostituito con "Details"

### Dashboard RFQ Pages
- `GET /dashboard/rfqs` — lista RFQ scoped per ruolo
- `GET /dashboard/rfq/{id}` — dettaglio con quote raccolte
- `POST /dashboard/rfq/{id}/approve` — approva quote, emette transaction token, invia via WS
- Link RFQs aggiunto alla sidebar

### Alembic Migration
- `a1b2c3d4e5f6_add_rfq_and_transaction_token_tables.py` — crea `rfq_requests`, `rfq_responses`, `transaction_tokens` con indici e constraint
- `alembic/env.py` aggiornato con import nuovi modelli

### Migrazione python-jose → PyJWT
- Fix CVE-2024-33663 (ECDSA bypass) e CVE-2024-33664 (PBES2 DoS)
- 11 file migrati: jwt.py, dpop.py, x509_verifier.py, transaction_token.py, sdk.py, cert_factory.py, 5 test file
- `requirements.txt`: `python-jose[cryptography]` → `PyJWT[crypto]>=2.8.0`

### SDK TypeScript
- `sdk-ts/` — SDK completo per Node.js che replica agents/sdk.py
- `client.ts`: BrokerClient con login, discover, sessions, send E2E, poll, RFQ, transaction tokens
- `auth.ts`: client assertion RS256, DPoP proof ES256 (RFC 9449), JWK thumbprint
- `crypto.ts`: AES-256-GCM + RSA-OAEP encryption, RSA-PSS signing (match esatto Python)
- `types.ts`: interfacce TypeScript per tutte le API
- `README.md` + `examples/basic-agent.ts`

### Production Configuration
- `.env.example` riscritto: sezioni organizzate, tag [REQUIRED]/[PRODUCTION], comandi generazione secrets
- `docker-compose.prod.yml`: rimuove mock PDP, restart policy, resource limits, JSON logging, trace sampling 10%
- `docs/ops-runbook.md`: 9 sezioni (deploy, update, backup, key rotation, revocation, monitoring, audit, troubleshooting, production checklist)

### BYOCA Certificate Upload (security fix)
- `POST /dashboard/agents/{id}/upload-cert` — upload cert firmato dalla CA org
- Validazione: PEM parse, CN == agent_id, firma chain CA org
- Chiave privata non tocca mai il broker — pattern BYOCA come per org settings
- Credentials section con due opzioni: Option 1 BYOCA (production) / Option 2 Generate Demo (dev)

### SDK login_from_pem()
- Nuovo metodo `BrokerClient.login_from_pem(agent_id, org_id, cert_pem, key_pem)`
- Accetta PEM string direttamente — supporto Vault, AWS KMS, Azure Key Vault
- Chiave privata mai scritta su disco
- `login()` ora delega a `login_from_pem()` internamente
- Integration snippets nella dashboard aggiornati con Option A (file) / Option B (secret manager)

### Risultato sessione
- 10 commit, ~3500 righe aggiunte
- 21 nuovi test + zero regressioni su test esistenti
- 3 agenti paralleli su worktree isolati (PyJWT, Dashboard RFQ, SDK TS)
- Flusso enterprise completo: org registra → upload CA → register agent → upload agent cert → copia snippet → agente connesso

---

## 2026-04-06 — Social Media Drafts + Generate Demo CA

### Social media content
- `imp/social_drafts_x.md` — Draft post per X/Twitter
  - Thread pre-lancio (7 tweet): problema agent identity, no product mention
  - Thread launch day (8 tweet): annuncio ATN, feature key, quickstart, CTA
  - 5 post standalone: red team angle, DPoP flex, hot take, engagement, milestone template
- `imp/social_drafts_linkedin.md` — Draft post per LinkedIn
  - Post thought leadership pre-lancio (165 parole): enterprise identity problem
  - Post lancio (222 parole): annuncio con stats e architettura
  - Post tecnico DPoP (218 parole): analogia cash vs credit card
  - Post storia personale (196 parole): da red team a builder

---

## 2026-04-06 — Admin Secret in Vault + Cambio Password Dashboard

### Admin secret spostato da .env a Vault
- Nuovo modulo `app/kms/admin_secret.py` — gestione hash bcrypt admin secret via KMS backend
- Bootstrap automatico: al primo avvio, hasha `ADMIN_SECRET` dal .env e lo salva in Vault (`secret/data/broker.admin_secret_hash`)
- Supporto backend local (file `certs/.admin_secret_hash` chmod 600) e vault (KV v2 merge-write con CAS)
- Verifica constant-time con dummy hash (anti timing-attack, stesso pattern di `verify_org_credentials`)
- Cache in memoria per performance, aggiornata atomicamente al cambio password
- Fallback: se Vault non disponibile, confronto diretto con .env (resilienza)

### Cambio password admin dalla dashboard
- `GET /dashboard/admin/settings` — pagina Admin Settings (solo ruolo admin)
- `POST /dashboard/admin/settings/password` — cambio password con validazione:
  - Verifica password attuale (bcrypt)
  - Minimo 12 caratteri, conferma match
  - CSRF protection
- Nuovo hash scritto in Vault + cache aggiornata, audit log `admin.password_changed`
- Template `admin_settings.html`: form cambio password + info KMS backend (badge "Stored in KMS" / "Fallback to .env")
- Link "Settings" aggiunto nella sidebar admin (dopo Policies, prima di Audit Log)

### Login admin aggiornato
- `router.py` login: bcrypt verify contro hash da Vault (sostituisce `hmac.compare_digest` plaintext)
- Fallback automatico a .env se hash non disponibile in Vault

### Sicurezza
- Admin secret **mai piu in chiaro** — solo hash bcrypt (rounds=12) in Vault
- Password cambiabile senza accesso al server (zero file editing)
- Persistente: sopravvive ai restart container

### File modificati/creati
- `app/kms/admin_secret.py` (nuovo)
- `app/dashboard/templates/admin_settings.html` (nuovo)
- `app/main.py` — bootstrap nel lifespan
- `app/dashboard/router.py` — login + 2 nuove route admin settings
- `app/dashboard/templates/base.html` — link sidebar admin

---

## 2026-04-06 — Generate Demo CA dalla Dashboard

### Nuova feature: Generate Demo CA
- `POST /dashboard/settings/generate-ca` — genera CA RSA 4096 per l'org
- Chiave privata salvata in Vault del broker (`secret/data/org/{org_id}`) + disco (`certs/{org_id}/`)
- Cert pubblico salvato nel record org + locked
- Metadata `ca_source: broker-generated-demo` per distinguere da BYOCA
- Audit log: `registry.ca_certificate_generated` con warning mode=demo

### Template settings.html aggiornata
- **Option 1 — BYOCA** (production): upload CA cert manuale, chiave resta nell'infra dell'org
- **Option 2 — Generate Demo CA** (dev only): bottone con warning amber prominente
- Warning esplicito: "Not for production. The broker must never possess organization CA private keys."
- Divisore visuale "or" tra le due opzioni

### Flusso ora completo dalla dashboard (demo)
1. `./setup.sh` → broker pronto
2. Admin login → approva org
3. Org login → Settings → "Generate Demo CA" → CA pronta
4. Org → Register Agent → Download Bundle → agent pronto con cert firmato
5. Nessun CLI richiesto per il flusso demo

---

## 2026-04-05 — Go-to-Market: Landing Page, Blog Post, Issues

### Landing page (GitHub Pages)
- `agent-trust-clean/docs/index.html` — single-file, dark theme industrial-security
- Sezioni: hero, problema (3 card), 6 feature, architettura ASCII, quickstart terminal, tabella comparativa, CTA, footer
- Responsive, CSS animations (IntersectionObserver), zero dipendenze JS
- Font: Instrument Serif + Satoshi + DM Mono
- Pronta per GitHub Pages (`docs/` folder)

### Blog post pre-lancio
- `imp/blog_why_api_keys_broken.md` — "Why API Keys Are Broken for AI Agents"
- ~1600 parole, target HN/dev.to
- Struttura: hook scenario → stato attuale → threat model → proprietà soluzione → intro ATN → CTA
- Include pseudocode per DPoP, E2E envelope, cert chain, audit record
- Placeholder `GITHUB_LINK` da sostituire con URL repo reale

### Good First Issues
- `imp/good_first_issues.md` — 16 issue pronte per GitHub
- 4 documentation, 4 testing, 3 code quality, 3 features, 2 devex
- Ogni issue con: titolo, body, file da modificare, difficulty, label
- Formato copy-paste per GitHub Issues

---

## 2026-04-05 — Piano Strategico Go-to-Market + Carriera/Startup

### Analisi competitiva (3 agenti paralleli)
- **Competitive landscape**: analizzato posizionamento vs SPIFFE/SPIRE, Vault, OpenFGA, LangChain/CrewAI, MCP, Google A2A. ATN è l'unico che combina: federated policy + DPoP + E2E + audit tamper-evident + multi-org
- **Launch strategy**: playbook completo per Show HN, Reddit (5 subreddit), Twitter/X, LinkedIn, Product Hunt, awesome lists, CNCF Landscape
- **Startup vs career path**: analisi modelli open-core (HashiCorp, Tailscale, Teleport), TAM ($5-7B → $45-65B 2030), investor target (OSS Capital, YC, a16z)

### Decisioni strategiche
- **Percorso**: Hybrid (career leverage ora, startup se market pull)
- **Timeline lancio**: 6 settimane (build in public → soft launch → Show HN)
- **Revenue model**: Free OSS → Team $500-2K/mo → Enterprise $5K-50K/mo → Platform API usage-based
- **Tagline**: "The trust layer for AI agents — federated identity, zero-knowledge messaging, compliance-grade audit"
- **Pitch**: "The Let's Encrypt + OAuth for AI agents"

### Conferenze target 2026
- BSides (facile CFP), Black Hat Arsenal, DEF CON AI Village, AI Engineer Summit, KubeCon, IETF

### Piano salvato in
- `/home/daenaihax/.claude/plans/eager-stargazing-rose.md`

---

## 2026-04-05 — Fresh Repo per Pubblicazione (Audit + Pulizia)

### Security Audit pre-pubblicazione
- Scansione completa git history per secret/credenziali leaked
- Trovati: demo secrets in file cancellati (`enterprise-lab/`, `agents/*.env`), `ADMIN_SECRET=trustlink-admin-2026`, `VAULT_TOKEN=dev-root-token` nella history
- API key Anthropic presente solo in `.env` locale (non in git) — da revocare
- Nessun secret reale nella git history, solo default demo

### Analisi file essenziali vs bagaglio
- Classificazione di ogni file/directory: SHIP vs DO NOT SHIP
- 160 file essenziali identificati su 300+ totali
- Rimossi: `imp/`, `demo/`, `enterprise-lab/`, `drafts/`, `org-node/`, agent demo (`buyer.py`, `manufacturer.py`, `client.py`, `mock_pdp.py`), script CLI legacy (`admin.py`, `bootstrap.py`, `policy.py`, `generate_demo_certs.py`, `join_agent.py`), `agent.sh`, `reset.sh`
- Mantenuti: `join.py` (onboarding tool), `revoke.py` (ops utility), `generate_certs.py` (usato da setup.sh)

### Fresh repo creato: `~/projects/agent-trust-clean/`
- Opzione A scelta: nuovo repo con history pulita (1 commit, zero secret)
- **docker-compose.yml** — rimossi 2 servizi `mock-pdp-manufacturer` e `mock-pdp-buyer`
- **setup.sh** — rimossi riferimenti demo (mock-pdp, generate_org_certs), aggiunto next steps con `join.py`
- **run.sh** — rimosso path nix-store hardcodato (`/nix/store/.../libstdc++.so.6`)
- **.env.example** — commenti tradotti in inglese, aggiunto `ADMIN_SECRET`
- **.gitignore** — riscritto: aggiunti pattern IDE (`.vscode/`, `.idea/`), build (`dist/`, `build/`, `*.egg-info/`), cache (`.mypy_cache/`, `.ruff_cache/`), log (`*.log`), `.DS_Store`, `nginx/certs/`
- Rimossi dal .gitignore i file che non esistono più nel fresh repo (voci legacy)

### Metriche
- File: 300+ → **160**
- Dimensione: ~5MB → **1.5MB**
- History: 46 commit (con secret demo) → **1 commit pulito**

### TODO post-sessione
- [ ] Revocare API key Anthropic `sk-ant-api03-E_rGn7...`
- [ ] Creare repo GitHub pubblico: `gh repo create DaenAIHax/agent-trust-network --public --source=. --push`

---

## 2026-04-05 — Enhanced Discovery + RFQ Broadcast + Transaction Tokens

### Phase 1: Enhanced Discovery (8 test)
- `app/registry/store.py` — nuova `search_agents()` unificata: agent_id, SPIFFE URI, org_id, glob pattern, capability — tutti combinabili
- `app/registry/router.py` — `GET /v1/registry/agents/search` esteso con 6 parametri opzionali + `include_own_org`
- `app/broker/router.py` — validazione capability target alla creazione sessione (agent must advertise the cap)
- Direct lookup (agent_id/SPIFFE) bypassa esclusione propria org
- Pattern matching via `fnmatch` su agent_id e SPIFFE URI

### Phase 2: RFQ Broadcast (7 test)
- `app/broker/rfq.py` (nuovo) — logica core: discovery → policy check per-recipient → broadcast WebSocket + notifica persistente → collect con timeout → persist + audit
- `app/broker/db_models.py` — `RfqRecord` + `RfqResponseRecord` (UNIQUE constraint per-responder)
- `app/broker/models.py` — `RfqRequest`, `RfqRespondRequest`, `RfqQuote`, `RfqResponse`
- `app/broker/router.py` — 3 endpoint: `POST /v1/broker/rfq`, `POST /v1/broker/rfq/{id}/respond`, `GET /v1/broker/rfq/{id}`
- Rate limit: 5 RFQ/min, 20 response/min
- Audit trail: rfq.created → rfq.broadcast → rfq.response_received → rfq.closed

### Phase 3: Transaction Tokens (6 test)
- `app/auth/transaction_db.py` (nuovo) — `TransactionTokenRecord` (jti PK, txn_type, payload_hash, approved_by, status active|consumed|expired)
- `app/auth/transaction_token.py` (nuovo) — `create_transaction_token()`, `validate_and_consume_transaction_token()`, `compute_payload_hash()`
- `app/auth/models.py` — `TokenPayload` esteso con `act` (RFC 8693 actor), `txn_type`, `resource_id`, `payload_hash`, `parent_jti`, `token_type`
- `app/auth/router.py` — `POST /v1/auth/token/transaction` (DPoP auth, agent richiede per se stesso)
- `app/broker/router.py` — validazione transaction token nel message send: payload hash match, single-use consume, audit chain
- Audit chain completa: rfq_id → transaction_token.jti → session_message

### Connessione tra le 3 feature
Discovery trova i supplier → RFQ raccoglie le quote → Umano/orchestratore sceglie → Transaction token autorizza l'ordine → Agente esegue in sessione 1:1

### Risultato
- 21 nuovi test (8 + 7 + 6), 3 file test
- Zero regressioni sui test esistenti
- 9 file nuovi, 8 file modificati

---

## 2026-04-05 — Dashboard: Self-Registration, Settings, Agent Bundle

### Login unificato
- `app/dashboard/router.py` — rimossi tab admin/org/SSO, singolo form user+password. Se user=admin verifica admin_secret, altrimenti prova come org
- `app/dashboard/templates/login.html` — form semplificato, link a registration page

### Self-registration organizzazioni
- `GET/POST /dashboard/register` — pagina pubblica (no login), org registrata con status=pending
- `app/registry/org_store.py` — `register_org()` accetta parametro `status` (default active)
- `app/dashboard/templates/register.html` — form con org_id, display name, password, conferma password
- Validazione: ID regex, password min 6 char, org duplicata, rate limit

### Organization Settings
- `GET /dashboard/settings` — pagina settings per org user (CA certificate upload)
- `POST /dashboard/settings/ca` — upload CA PEM con validazione (parse x509), lock dopo upload
- `POST /dashboard/orgs/{org_id}/unlock-ca` — admin sblocca CA per rotazione
- `app/dashboard/templates/settings.html` — info org, form upload CA, stato locked
- `app/dashboard/templates/orgs.html` — bottone "Unlock CA" per admin su org attive

### Agent Bundle Download
- `POST /dashboard/agents/{agent_id}/bundle` — genera zip con cert firmato dalla CA org, chiave privata, .env, start.sh, SDK, demo scripts
- `_generate_agent_cert()` — genera cert agente in-memory con SPIFFE SAN, firmato da CA org
- Cert pinnato in DB via `rotate_agent_cert()`
- CSRF + auth enforcement (admin o same-org)

### Altre modifiche
- `app/main.py` — root redirect `/` → `/dashboard/login`
- `app/dashboard/templates/base.html` — settings link per org, policies nascosto per non-admin
- `app/dashboard/templates/agents.html` — bottone "Download Bundle"
- `nginx/nginx.conf` — listen 8443 (allineato a Docker port mapping)

### Infra (non nel repo)
- `enterprise-lab/` — agent polling invece di WebSocket, fix ERPNext headers, register try/except
- `org-node/` — template docker-compose con Vault locale per cert storage
- Entrambi aggiunti a `.gitignore`, rimossi dal tracking git

---

## 2026-04-05 — Security Audit Round 3 + CI Green

### Security Audit Round 3 — Deep Codebase Review (3 agenti paralleli)
Terza revisione completa: auth/crypto, broker/policy, registry/dashboard/templates. 3 CRITICAL, 4 HIGH, 7 MEDIUM, 7 LOW/INFO identificati. 2 CRITICAL (C1, C3) verificati come false positive. Fix applicati ai finding confermati.

### Fix CRITICAL (1 confermato)
- **C2** `app/registry/router.py` — Cross-org agent info disclosure: `GET /agents/{id}` e `/public-key` accessibili da qualsiasi agente autenticato. Aggiunto check org isolation (same-org o approved binding richiesto)

### Fix HIGH (4)
- **H1** `app/dashboard/templates/audit.html` — XSS via `event.details` in attributo `title=""`: aggiunto escape esplicito `| e`
- **H2** `app/broker/session.py` — Nonce cache DoS: dopo 100K nonce, `is_nonce_cached()` rifiutava TUTTI i messaggi. Cambiato a eviction (`set.pop()`) mantenendo il DB come source of truth
- **H3** `app/registry/org_store.py` + 4 caller — Timing attack org secret: short-circuit su `not org or ...` leakava esistenza org via timing. Nuova `verify_org_credentials()` con dummy bcrypt hash per constant-time
- **H4** `app/broker/models.py` — Context field senza schema: `SessionRequest.context` accettava JSON arbitrario 16KB. Aggiunto check profondita max 4 livelli + string-only keys

### False positive verificati
- **C1** Session enumeration — `list_for_agent()` filtra gia per agent_id (solo sessioni dove l'agente e partecipante)
- **C3** Race condition accept_session — `save_session()` era gia dentro il blocco `async with store._lock`

### Test
- `tests/test_audit_r3.py` — 11 test: org isolation (cross-org blocked, same-org allowed), nonce eviction, constant-time org verify, context depth/size validation, structural lock verification

### CI/CD — Da rosso a verde
- **Ruff lint**: 146 errori fixati in 35+ file (F401 unused imports, F841 unused vars, F811 redefinitions, E712 SQLAlchemy True/False comparisons)
- **E402 ignorato** in CI (pattern intenzionale: `os.environ.setdefault()` prima degli import)
- **Pin dipendenze**: `fastapi<1.0`, `starlette<1.0` (Starlette 1.0 rimosso TemplateResponse old API), `jinja2>=3.1`
- **Risultato CI**: 209 passed, 1 skipped (readyz senza Redis/KMS), lint verde, pip-audit verde

### Risultato
- 350+ test, 32 file test
- CI verde su GitHub Actions (prima sessione con CI passing)
- Repo pronto per pubblicazione

---

## 2026-04-05 — Enterprise Demo Lab: ERP/CRM reali (ERPNext + Odoo)

### Infrastruttura
- `enterprise-lab/` — directory completa per demo 3-VM con sistemi enterprise reali
- `vm1-broker/docker-compose.yml` — broker stack (PostgreSQL, Redis, Vault, Nginx, Jaeger)
- `vm2-buyer/docker-compose.yml` — ERPNext v15 + MariaDB + Redis + OPA
- `vm3-supplier/docker-compose.yml` — Odoo CE v17 + PostgreSQL + OPA
- OPA Rego policies per-org: allowed orgs, capabilities, blocked agents

### Connectors
- `connectors/erp_connector.py` — ERPNext REST API wrapper (stock levels, reorder thresholds, Purchase Orders)
- `connectors/crm_connector.py` — Odoo XML-RPC wrapper (catalog, price lists, Sale Orders, partner management)

### Agenti enterprise
- `vm2-buyer/buyer_agent.py` — legge stock da ERPNext, negozia via ATN, crea Purchase Order reali
- `vm3-supplier/supplier_agent.py` — legge catalogo da Odoo, risponde con prezzi reali, crea Sale Order

### Seed scripts
- `vm2-buyer/seed_erpnext.py` — crea company, warehouse, supplier, 4 items con stock e reorder levels, API user
- `vm3-supplier/seed_odoo.py` — crea categoria, 4 prodotti con SKU/prezzi, sconti volume, customer

### Fix durante testing
- `Dockerfile` — aggiunto `alembic/` e `alembic.ini` (mancavano nel container)
- `app/db/database.py` — Alembic `command.upgrade()` wrappato in `asyncio.to_thread()` (conflitto `asyncio.run` nel lifespan)
- `nginx/nginx.conf` — aggiunta location `/v1/broker/ws` per WebSocket proxy (mancava dopo API versioning)
- `docker-compose.yml` — `VAULT_ALLOW_HTTP=true` per dev, `POLICY_BACKEND` e `OPA_URL` env vars
- Buyer agent: polling affidabile invece di WebSocket (timing issues con WS)
- Supplier agent: polling fallback per messaggi, estrazione org_id da agent_id
- ERPNext: `X-Frappe-Site-Name` header per routing multi-site, Fiscal Year 2026, Stock Entry submit
- Odoo: stock quantities via `stock.quant`, partner search domain fix

### Risultato
- Demo end-to-end funzionante: ERPNext stock check → ATN auth → OPA policy → negoziazione LLM → Purchase Order in ERPNext
- 2 negoziazioni completate: BLT-M10-ZN (2000 units, €0.08) e BLT-M8-ZN (5000 units, €0.05)
- `enterprise-lab/README.md` — guida deployment 3-VM completa con troubleshooting

---

## 2026-04-05 — Sprint 6: Security Audit Round 2 (28 findings)

### Security Audit Round 2 — Deep Code Review
Seconda revisione completa del codebase. 28 finding identificati (#17–#44), tutti fixati in sessione parallela (3 terminali Claude concorrenti su file separati).

### Fix HIGH (4)
- **#17** `app/dashboard/router.py` — `verify_csrf()` non awaited su `/dashboard/audit/verify`: aggiunto `await`
- **#18** `app/kms/vault.py` — Vault token inviato su HTTP: validazione `https://` obbligatoria quando `kms_backend=vault`, override esplicito `VAULT_ALLOW_HTTP=true` per dev
- **#19** `app/broker/session.py` — Session store unbounded growth (memory DoS): aggiunto eviction periodica sessioni expired/closed, cap massimo 10.000 sessioni
- **#20** `python-jose` con CVE note — tracciato per migrazione futura a PyJWT (CVE-2024-33663, CVE-2024-33664)

### Fix MEDIUM (14)
- **#21** `app/kms/secret_encrypt.py` — HKDF `salt=None` deterministica: salt random 16 byte per-encryption, formato `enc:v1:<salt_hex>:<token>`, backward compat con formato senza salt
- **#22** `app/auth/dpop.py` — DPoP nonce non condivisi tra worker: documentato che Redis e' obbligatorio in multi-worker
- **#23** `app/auth/message_signer.py` — Exception detail leak in firma messaggi: messaggio generico + log server-side
- **#24** `app/auth/x509_verifier.py` — Nessuna validazione curve EC: whitelist P-256, P-384, P-521, rifiuto curve deboli
- **#25** `app/broker/router.py` — CORS non protegge WebSocket: validazione header `Origin` contro `allowed_origins` prima di accept
- **#26** `app/broker/router.py` — WebSocket auth senza timeout: `asyncio.wait_for(receive_json(), timeout=10)`, previene connection exhaustion
- **#27** `app/broker/router.py` — Race condition state transitions sessione: `asyncio.Lock` su SessionStore per accept/reject/close atomici
- **#28** `app/broker/router.py` — Message polling su sessioni chiuse: check stato sessione, solo active permesso
- **#29** `app/policy/engine.py` — Policy engine valuta solo initiator org: corretto per valutare policies di entrambe le org (dual-deny)
- **#30** `app/registry/org_router.py` — GET org senza autenticazione: aggiunta dipendenza auth (admin o org member)
- **#31** `app/onboarding/router.py` — Input validation mancante su `org_id`: regex `^[a-z0-9][a-z0-9._-]*$`, max_length
- **#32** `app/registry/models.py` — Input validation mancante su `agent_id`: regex pattern su Pydantic model
- **#33** `app/policy/opa.py` — OPA adapter senza SSRF protection: `validate_opa_url()` con check schema e IP, chiamata allo startup
- **#34** `app/registry/router.py` — Org pending possono registrare agenti: check `org.status != "active"` aggiunto

### Fix LOW (10)
- **#35** `app/registry/store.py` — Cert thumbprint comparison non constant-time: `hmac.compare_digest()`
- **#36** `app/auth/revocation.py` — Revocation cleanup cancella entry prematuramente: buffer 30 min per token lifetime
- **#37** `app/kms/factory.py` — KMS backend sconosciuto fallback silenzioso: `raise RuntimeError`
- **#38** `app/broker/router.py` — `list_sessions` senza paginazione: aggiunto `limit`/`offset` con default 100
- **#39** `app/broker/router.py` — No rate limit su message polling: aggiunto rate limit 120/min
- **#40** `app/broker/router.py` — In-memory message state non rollbacked su DB error generico: try/except con rollback completo
- **#41** `app/broker/router.py` — No format validation su `session_id`: UUID regex validation su tutti i path params
- **#42** `app/registry/binding_store.py` — Binding revocato ri-approvabile: check status `pending` prima di approve
- **#43** `app/dashboard/router.py` — Dashboard logout via GET: cambiato a POST con CSRF token
- **#44** `app/rate_limit/limiter.py` — Rate limiter bypassabile via X-Forwarded-For: documentazione dipendenza `--proxy-headers`

### Test
- `tests/test_audit_r2_t1.py` — 14 test (T1: dashboard, auth, registry, kms)
- `tests/test_audit_r2_t2.py` — 32 test (T2: broker, policy, WebSocket, sessions)
- `tests/test_audit_r2_t3.py` — 27 test (T3: onboarding, crypto, x509, revocation)
- Fix regressioni: `test_dashboard` (logout POST), `test_onboarding` (agent registration order), `test_opa` (mock validate_opa_url)

### Risultato
- 350 test verdi (277 precedenti + 73 nuovi), 30 file test
- Zero regressioni, backward compatible
- Lavoro parallelizzato su 3 terminali Claude concorrenti senza conflitti file

---

### Security Audit Round 1 — Fix residui (2026-04-05)
- **#5** `app/db/audit.py` — Race condition hash chain: `asyncio.Lock` serializza read+insert+commit
- **#6** `app/policy/webhook.py` — SSRF IP pinning rompe HTTPS: `_PinnedDNSBackend` httpcore mantiene hostname per TLS SNI
- **#15** `app/broker/router.py` — WebSocket auth non verifica binding: aggiunto `get_approved_binding()` step 2d
- 3 nuovi test, 277 test verdi

---

## 2026-04-05 — Sprint 5B: OPA Policy Integration

### OPA Adapter
- `app/policy/opa.py` (nuovo) — OPA REST client: POST a `/v1/data/atn/session/allow`, timeout 5s, default-deny su errore/timeout
- `app/policy/backend.py` (nuovo) — Factory dispatcher: `evaluate_session_policy()` smista a webhook o OPA basato su `POLICY_BACKEND` env var
- `app/config.py` — `policy_backend: str = "webhook"`, `opa_url: str = ""`
- `app/broker/router.py` — Sostituito import diretto `evaluate_session_via_webhooks` con `evaluate_session_policy` (backend-agnostic)
- `tests/conftest.py` + `tests/test_policy.py` — Mock aggiornati al nuovo entry point

### Enterprise OPA Kit
- `enterprise-kit/opa/policy/atn/session.rego` — Policy Rego completa: allowed_orgs, blocked_agents, capabilities, default-deny
- `enterprise-kit/opa/config.json` — Configurazione dati separata (override senza toccare Rego)
- `enterprise-kit/pdp-template/pdp_server.py` — Flag `--opa-url` per forwarding a OPA invece di rules.json locale
- `enterprise-kit/pdp-template/docker-compose.opa.yml` — OPA sidecar + PDP server

### Test
- `tests/test_opa.py` — 9 test: OPA allow/deny/boolean/timeout/http-error/input-validation, backend dispatch webhook/opa/no-url

### Risultato
- 274 test verdi (265 precedenti + 9 nuovi OPA), 27 file test
- Zero regressioni, backward compatible (POLICY_BACKEND=webhook di default)

---

## 2026-04-05 — Sprint 5A: Enterprise Readiness (asyncio, KMS encrypt, health, audit export)

### threading.Lock → asyncio.Lock
- `app/rate_limit/limiter.py` — `threading.Lock` → `asyncio.Lock`, `_check_memory()` async
- `app/auth/dpop_jti_store.py` — `threading.Lock` → `asyncio.Lock` su `InMemoryDpopJtiStore`
- `app/auth/dpop.py` — Rimosso `threading.Lock` dal nonce (asyncio single-threaded, lock non necessario)

### OIDC Client Secret Encryption via KMS
- `app/kms/secret_encrypt.py` (nuovo) — HKDF-SHA256 + Fernet, prefisso `enc:v1:` per ciphertext
- `app/kms/provider.py` — +2 metodi protocollo: `encrypt_secret()`, `decrypt_secret()`
- `app/kms/local.py` + `app/kms/vault.py` — Implementazione encrypt/decrypt via helper condiviso
- `app/registry/org_store.py` — `update_org_oidc()` cifra il secret, `get_org_oidc_secret()` decifra on read
- `app/dashboard/router.py` — Decifra OIDC secret prima del token exchange
- Legacy plaintext (senza prefisso `enc:v1:`) trattato as-is (migrazione trasparente)

### Health/Readiness Endpoints
- `app/main.py` — `GET /healthz` (liveness, sempre 200), `GET /readyz` (readiness: check DB + Redis + KMS, 200 o 503)
- Esclusi da DPoP-Nonce header injection
- `/health` legacy invariato (backward compat)

### Audit Export Endpoint
- `app/db/audit.py` — `query_audit_logs()` con filtri: start, end, org_id, event_type, limit
- `app/onboarding/router.py` — `GET /v1/admin/audit/export` (admin-only): NDJSON o CSV, streaming, date range, max 50k entries
- Header `Content-Disposition` per download diretto

### Test
- `tests/test_kms_encryption.py` — 10 test: roundtrip, prefix, legacy passthrough, wrong key, corruption, KMS provider integration
- `tests/test_health.py` — 5 test: healthz, readyz, no DPoP-Nonce, legacy /health
- `tests/test_audit_export.py` — 8 test: JSON/CSV format, filtri org/event_type, limit, auth, hash chain

### Risultato
- 265 test verdi (242 precedenti + 23 nuovi), 27 file test
- Zero regressioni

---

## 2026-04-04 — Security Audit & Hardening

### Audit completo del codebase
Revisione security engineer su tutto il codice core: auth, crypto, broker, registry, onboarding, WebSocket, policy webhook, dashboard, rate limiting. Identificate 12 vulnerabilità (3 critical, 4 high, 5 medium). Tutte le critical e high fixate.

### Fix Critical

**1. Race condition replay nonce nei messaggi**
- `app/broker/router.py` — `cache_nonce()` spostato PRIMA di `store_message()`: due richieste concorrenti con lo stesso nonce non possono più passare entrambe il fast-path in-memory. Il DB resta source of truth, ma la finestra di race è chiusa.

**2. Sessioni attive dopo revoke binding**
- `app/broker/session.py` — nuovo metodo `close_all_for_agent()`: chiude tutte le sessioni active/pending dell'agente
- `app/registry/binding_router.py` — al revoke: chiude sessioni + disconnette WebSocket forzatamente. Prima un agente revocato poteva continuare a scambiare messaggi su sessioni già aperte.

**3. DNS rebinding nella SSRF protection webhook**
- `app/policy/webhook.py` — rinominata `_validate_webhook_url` → `_validate_and_resolve_webhook_url`: ritorna l'IP risolto. La connessione HTTP usa l'IP pinnato (hostname nel Host header per TLS/SNI), eliminando la finestra di DNS rebinding tra validazione e richiesta.

### Fix High

**4. Admin secret default non bloccante**
- `app/config.py` — log `CRITICAL` allo startup se `admin_secret` è ancora `"change-me-in-production"`. Rende impossibile ignorare la misconfiguration in produzione.

**5. Rate limit su `/onboarding/join`**
- `app/onboarding/router.py` — aggiunto rate limit 5 req/300s per IP client
- `app/rate_limit/limiter.py` — registrato bucket `onboarding.join`; migrato `threading.Lock` → `asyncio.Lock` (fix debito tecnico)

**6. TOCTOU nel WebSocket connection limit per org**
- `app/broker/ws_manager.py` — aggiunto `asyncio.Lock` attorno a `connect()`/`disconnect()`. Check del limite e registrazione ora atomici. Refactor interno: `_disconnect_unlocked()` per evitare deadlock.

**7. Error message information disclosure**
- `app/onboarding/router.py` — eccezioni CA certificate: dettagli interni loggati server-side, messaggio HTTP generico al client
- `app/auth/x509_verifier.py` — sanitizzati 3 error path: org CA invalid, JWT signature, chain verification. Nessun `{exc}` esposto nelle risposte HTTP.

### Test
- `tests/test_security_fixes.py` — aggiornato import `_validate_and_resolve_webhook_url`
- 242 test verdi, 0 regressioni, 4 skipped (postgres integration richiede Docker)

### Finding positivi (già sicuri)
- JWT RS256 only, nessun algorithm confusion
- DPoP binding corretto con `cnf.jkt` (RFC 9449)
- Timing-safe comparison ovunque (`hmac.compare_digest`)
- Atomic JTI consumption (PostgreSQL `ON CONFLICT` + Redis `SET NX`)
- E2E crypto corretta (AES-256-GCM + RSA-OAEP + doppia firma PSS)
- Bcrypt per org secrets, security headers completi

---

## 2026-04-04 — Sprint 3: OIDC Federation

### OIDC Login per Dashboard
- `app/dashboard/oidc.py` (nuovo) — OIDC client: discovery cache, PKCE (RFC 7636), token exchange, ID token validation (sig, iss, aud, nonce, exp)
- `app/dashboard/session.py` — OIDC state cookie (`atn_oidc_state`): set/get/clear, firmato HMAC-SHA256, TTL 10 min
- `app/dashboard/router.py` — `GET /oidc/start` (initia flow), `GET /oidc/callback` (valida code+state, crea sessione)
- `app/config.py` — `admin_oidc_issuer_url`, `admin_oidc_client_id`, `admin_oidc_client_secret` per network admin OIDC
- `app/registry/org_store.py` — `oidc_issuer_url`, `oidc_client_id`, `oidc_client_secret` su OrganizationRecord + `oidc_enabled` property + `update_org_oidc()`
- `alembic/versions/7043c1ddb652_add_oidc_columns_to_organizations.py` — migrazione 3 colonne nullable
- `requirements.txt` — aggiunto `authlib>=1.3.0`

### Templates
- `login.html` — terzo tab "SSO": Admin SSO button (se configurato) + Organization SSO con campo org_id
- `org_onboard.html` — sezione collapsible "OIDC Configuration" (issuer URL, client ID, client secret)
- `orgs.html` — colonna "SSO" con badge Configured/Off

### Security
- PKCE obbligatorio (code_verifier/code_challenge S256)
- State in cookie firmato (anti-CSRF), nonce nell'ID token (anti-replay)
- Cookie state one-time use, redirect_uri hardcoded (no open redirect)
- Rate limit su callback
- Issuer URL validato HTTPS, audience check, expiry check

### Test
- `tests/test_oidc.py` — 11 test: unit (state creation, PKCE, roundtrip) + integration (start/callback flows, error handling, state mismatch)

### Risultato
- 242 test verdi (231 precedenti + 11 nuovi OIDC), 24 file test
- Zero regressioni, backward compatible (secret-based auth invariato)

---

## 2026-04-04 — Sprint 2: Enterprise Readiness (logging, reject, audit chain)

### Structured JSON Logging
- `app/logging_config.py` (nuovo) — `JsonFormatter` single-line JSON, `configure_logging()` toggle via `LOG_FORMAT` env var
- `app/config.py` — `log_format: str = "text"` setting
- `app/main.py` — `configure_logging()` at module level, `_QuietBadgeFilter` re-applied after handler reset
- `tests/test_logging.py` — 5 test: JSON parsing, exception serialization, noop text mode

### Session Reject Endpoint
- `app/broker/session.py` — `reject()` method: pending → denied
- `app/broker/persistence.py` — `closed_at` set for denied status too
- `app/broker/router.py` — `POST /sessions/{session_id}/reject`: only target, only pending, audit log, WS notification to initiator
- `tests/test_broker.py` — 3 nuovi test: reject pending, reject non-pending fails, non-target fails

### Audit Log Hash Chain (SOC2)
- `app/db/audit.py` — `entry_hash` + `previous_hash` columns, `compute_entry_hash()` SHA-256, chain in `log_event()`, `verify_chain()` walker
- `alembic/versions/7f54c1eb5e89_add_audit_log_hash_chain.py` — migration
- `app/dashboard/router.py` — `POST /audit/verify` admin-only endpoint
- `app/dashboard/templates/audit.html` — hash column, "Verify Hash Chain" button, result banner
- `tests/test_audit_chain.py` — 6 test: hash creation, chain linkage, determinism, verify valid, tamper detection, empty chain

### Risultato
- 231 test verdi (217 precedenti + 14 nuovi), 23 file test
- Zero regressioni

---

## 2026-04-04 — Sprint 1: Core Security (nonce atomici, E2E AAD, JWKS)

### Task 1: Nonce + Message Persistence Atomici
- `app/broker/persistence.py` — `save_message()` usa `INSERT ON CONFLICT DO NOTHING` sul campo `nonce` (UNIQUE). Pattern identico a `jti_blacklist.py`. Ritorna `bool` (True=inserito, False=replay)
- `app/broker/router.py` — `send_message`: fast-path in-memory cache, poi DB atomico come source of truth. Rollback in-memory se DB insert fallisce (`_messages.pop()`, `_next_seq -= 1`)
- `app/broker/session.py` — rimosso `consume_nonce()`, sostituito con `is_nonce_cached()` (read-only) + `cache_nonce()` (post-DB)
- `tests/test_security_fixes.py` — aggiornato test nonce capacity per nuova API

### Task 3: JWKS Endpoint + kid nel JWT
- `app/auth/jwks.py` (nuovo) — `rsa_pem_to_jwk()`, `compute_kid()` (RFC 7638 JWK Thumbprint SHA-256), `build_jwks()`
- `app/auth/jwt.py` — `create_access_token` aggiunge `kid` nel JWT header via `headers={"kid": kid}`
- `app/main.py` — `GET /.well-known/jwks.json` unauthenticato, `Cache-Control: public, max-age=3600`, escluso da DPoP-Nonce
- `tests/test_jwks.py` (nuovo) — 6 test: JWK valido, no auth, cache-control, no DPoP-Nonce, kid matching, compute_kid deterministico

### Task 2: E2E AAD con Client Sequence Number (anti-reordering)
- `app/broker/models.py` — `client_seq: int | None` in `MessageEnvelope` e `InboxMessage`
- `app/broker/db_models.py` — `client_seq = Column(Integer, nullable=True)` in `SessionMessageRecord`
- `alembic/versions/3ee228696375_add_client_seq_to_session_messages.py` — migrazione Alembic
- `app/e2e_crypto.py` — `encrypt_for_agent` e `decrypt_from_agent`: AAD = `session_id|sender|client_seq` quando presente, formato vecchio altrimenti (backward compat)
- `app/auth/message_signer.py` — `sign_message` e `verify_message_signature`: `client_seq` nel canonical form
- `app/e2e_crypto.py` — `verify_inner_signature`: `client_seq` nel canonical form
- `app/broker/session.py` — `StoredMessage` e `store_message`: campo `client_seq`
- `app/broker/persistence.py` — `save_message` e `restore_sessions`: persist/restore `client_seq`
- `app/broker/router.py` — `send_message`: `client_seq` passato in signature verify, store, WS push, polling
- `agents/sdk.py` — `_client_seq` counter per-session auto-incrementante, incluso in AAD + firma + envelope
- `tests/cert_factory.py` — `sign_message` e `make_encrypted_envelope`: parametro `client_seq`

### Risultato
- 217 test verdi (211 precedenti + 6 nuovi JWKS), 20 file test
- Zero regressioni, backward compatibility confermata (client_seq nullable)

---

## 2026-04-04 — Sprint 0: Alembic Migrations + API Versioning /v1/

### Alembic Migrations
- Sostituito `metadata.create_all` con Alembic per migrazioni versionabili
- `alembic/env.py` — configurato per async SQLAlchemy, importa tutti i 10 modelli
- `alembic/versions/473ecda4a4ca_initial_schema.py` — migrazione iniziale (10 tabelle, indici, constraint)
- `alembic.ini` — SQLite default, sovrascrivibile via `DATABASE_URL` env var
- `app/db/database.py` — `init_db()` esegue `alembic upgrade head` in produzione; fallback a `create_all` con `SKIP_ALEMBIC=1` (test)
- `tests/conftest.py` — setta `SKIP_ALEMBIC=1` (test continuano con SQLite in-memory + `create_all`)
- `requirements.txt` — aggiunto `alembic>=1.18.0`

### API Versioning `/v1/`
- Tutti gli endpoint API sotto `/v1/` (auth, registry, broker, policy, onboarding, admin)
- Dashboard (`/dashboard`) e health (`/health`) restano non-versionati
- `app/main.py` — router parent `APIRouter(prefix="/v1")` con tutti i sub-router API
- Aggiornati 17 file test (152 occorrenze di path)
- `agents/sdk.py` — tutti i path API prefissati con `/v1/`
- `agents/client.py` — WebSocket URL aggiornato a `/v1/broker/ws`
- `bootstrap.py` — tutti i path API aggiornati
- `app/broker/router.py` — WebSocket HTU aggiornato per DPoP proof
- Mock PDP e webhook URL non toccati (server esterni, non API broker)

### Risultato
- 217 test raccolti, 211 passed, 4 skipped, 2 failed (solo postgres integration — richiedono Docker)
- Zero regressioni rispetto a prima dello sprint

---

## 2026-04-04 — CI fix, dipendenze, strategia

### CI GitHub Actions
- Upgrade dipendenze vulnerabili: `cryptography` 44→46.0.6, `python-jose` 3.3→3.4+, `python-multipart` 0.0.20→0.0.22+
- CVE risolte: CVE-2024-12797, CVE-2026-26007, CVE-2026-34073, PYSEC-2024-232/233, CVE-2026-24486, CVE-2025-54121, CVE-2025-62727
- Fix test e2e: capabilities agente allineate con scope binding (nuova validazione)
- Skip test postgres in CI (nessun container disponibile)
- Pin minimi (`>=`) invece di esatti (`==`) in requirements.txt
- 211 test verdi, 0 failed

### Community & Open Source
- LICENSE Apache 2.0
- CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT (Contributor Covenant)
- GitHub issue templates (bug, feature, security redirect)
- PR template con checklist
- GitHub Actions CI: pytest + ruff lint + pip-audit

### Strategia & Marketing
- Piano strategico completo in `strategia.md` (posizionamento, business model, target clienti, roadmap 3 mesi)
- Piano marketing in `marketing.md` (brand, content strategy, launch plan, developer funnel, materiali enterprise)
- Guida concetti in `guida_concetti.md` + PDF (25 sezioni, dalle basi crypto al flusso completo)
- CLAUDE.md aggiornato con stato reale del progetto (DPoP, E2E, dashboard, debito tecnico)
- Co-Authored-By Claude rimosso da tutta la history git

### Cleanup repo GitHub
- Rimossi: `repository/`, `files/`, `showcase/`, file vecchi dalla root
- Spostati in `miglioramenti/`: idee future (payments, traceability, mcp_proxy, trust_federation)
- Gitignored: `miglioramenti/`, `demo/`, `drafts/`, script CLI, `.env`, certs, CLAUDE.md, CHANGELOG.md
- README.md aggiornato con Mermaid diagrams (5 diagrammi: trust router, session flow, PKI, DPoP, E2E)
- Sezione Deployment resa generica
- Rimossa sezione Prompt Injection (broker non legge plaintext con E2E)

---

## 2026-04-04 — Security Audit & Hardening (dual-agent)

Due agenti di security audit hanno lavorato in parallelo. I fix sono organizzati per fase.

### Critical Fixes (Agent 1 — Phase 1)
- **C1** Policy webhook default-allow → default-deny when no PDP webhook configured (`webhook.py`)
- **C2** Message policy engine now called in `send_message()` — was dead code (`broker/router.py`)
- **C4** JTI blacklist TOCTOU race condition — atomic `INSERT ON CONFLICT DO NOTHING` + boundary fix `< → <=` (`jti_blacklist.py`)
- **C6** Redis rate limiter race condition — two separate pipelines → single atomic Lua script (`limiter.py`)

### High Fixes (Agent 1 — Phase 2)
- **H1** X.509 validation: minimum RSA key size 2048 bit, EKU clientAuth check (`x509_verifier.py`)
- **H2** CORS: `allow_credentials=False` when `allow_origins=*` — prevents CSRF with wildcard (`main.py`)
- **H3** `POST /registry/agents` now requires org credentials (`X-Org-Id` + `X-Org-Secret`) — was unprotected (`registry/router.py`)
- **H4** SSRF protection on PDP webhook URLs: DNS resolution + private/reserved IP block (`webhook.py`)
- **H5** Injection LLM judge: fail-closed when enabled but unavailable; disabled via config = pass-through (`detector.py`)
- **H6** CA certificate validated on onboarding: X.509 format, BasicConstraints, key size ≥2048, validity (`onboarding/router.py`)
- **H7** Expired sessions return `None` from `SessionStore.get()` — prevents operations on expired sessions (`session.py`)
- **H8** OTLP exporter `insecure` flag now configurable via `OTEL_EXPORTER_INSECURE`, default `False` (`telemetry.py`, `config.py`)
- **L2** Added `Strict-Transport-Security` header (`main.py`)
- **L6** Italian error messages in x509_verifier translated to English

### Medium Fixes (Agent 1 — Phase 3)
- **M1** Unicode normalization (NFKD) before injection pattern matching — prevents zero-width space bypass (`patterns.py`)
- **M2** `get_current_dpop_nonce()` reads `_current_nonce` under lock — prevents race with rotation (`dpop.py`)
- **M3** Webhook response validation: decision must be `allow`/`deny`, reason truncated to 512 chars (`webhook.py`)
- **M4** Binding scope validated as subset of agent capabilities — prevents scope inflation (`binding_router.py`)
- **M5** Certificate revocation checked before pinning/accepting cert (`store.py`)
- **M6** Dashboard cookie HMAC uses dedicated `DASHBOARD_SIGNING_KEY`, not admin_secret (`session.py`, `config.py`)
- **M8** Message timestamp window reduced from 300s to 60s — aligned with DPoP iat window (`broker/router.py`)
- **M9** In-memory rate limiter: LRU eviction at 50k subjects — prevents memory exhaustion DoS (`limiter.py`)

### Dashboard & API Hardening (Agent 2)
- Timing attacks: `hmac.compare_digest()` in 6 locations (admin secret, DPoP nonce, DPoP ath)
- `POST/GET /registry/orgs` now require admin secret header
- Dashboard login rate limited (5 attempts / 5 min / IP)
- WebSocket: idle timeout 5min, message rate limit 30/60s, token expiry re-check, per-org connection limit 100
- CSP: removed `unsafe-inline` from `script-src`
- Pydantic size limits: payload 1MB, metadata 16KB, context 16KB, rules 32KB
- `max_length` on agent_id, org_id, display_name, nonce, signature
- Audit search query truncated to 100 char
- Certificate CN no longer reflected in error messages
- Jaeger URL validated with `urlparse`
- All Italian strings translated to English (6 file)

### Backend Security Fixes (Agent 2)
- Unbounded nonce set → cap 100K per session (memory DoS)
- Session expiry enforced on message send
- Envelope session_id validated against URL path
- SSRF hardening: no redirect, IP validation, response size limit 4KB, DNS rebinding defense
- Cert revocation atomic INSERT ON CONFLICT (TOCTOU fix)
- CA cert upload: validation (BasicConstraints, key size, validity) + agent invalidation on CA rotation
- Cache-Control: no-store on all responses
- Redis auth support in docker-compose
- Vault dev-root-token parametrized via env var

### Cross-Org Isolation, E2E Verification & Infra Hardening (Agent 2 — Phase 3)

#### Cross-Organization Isolation
- Notification model now includes `org_id` column — prevents cross-org notification leak when agents share the same ID across organizations (`broker/notifications.py`)
- All notification queries filter by `org_id` when available (`broker/notifications.py`, `broker/router.py`)

#### E2E Encryption Hardening
- Added `verify_inner_signature()` function for recipient-side non-repudiation verification (`e2e_crypto.py`)
- SDK now raises `ValueError` on E2E decryption failure instead of silently returning ciphertext (`agents/sdk.py`)

#### Timing Attacks (additional)
- DPoP nonce comparison uses `hmac.compare_digest()` — was using `==` (`auth/dpop.py`)
- DPoP access token hash (ath) comparison uses `hmac.compare_digest()` — was using `!=` (`auth/dpop.py`)

#### Docker & Infrastructure
- Dockerfile runs as non-root user (`appuser`) instead of root (`Dockerfile`)
- `FORWARDED_ALLOW_IPS` restricted from `*` to Docker internal network `172.16.0.0/12` (`docker-compose.yml`, `Dockerfile`)
- Nginx: added HSTS header, cipher suite hardening (`HIGH:!aNULL:!MD5:!RC4`), `X-Content-Type-Options`, `X-Frame-Options`, `client_max_body_size 2m` (`nginx/nginx.conf`)
- Vault error messages no longer leak HTTP response body to callers (`app/kms/vault.py`)
- Private key files generated with `chmod 600` automatically (`generate_certs.py`, `join.py`)

### Known Issues (backlog)
- E2E encryption AAD does not include sequence number (reordering attack)
- Nonce consumption and message persistence not atomic (replay after crash)
- Agent deletion does not cascade to sessions/messages/notifications
- Message polling lacks pagination (DoS via `after=0`)
- No session reject endpoint (pending sessions can only be accepted or expire)
- Token reuse on WebSocket reconnection — no rotation (`agents/sdk.py`)
- Public key cache in SDK without cryptographic integrity check (`agents/sdk.py`)
- Auto-instrumentation OTEL may capture sensitive query/key data (`telemetry.py`)
- No dependency lock file — supply chain risk (`requirements.txt`)

---

## 2026-04-04 — GitHub repo + cleanup

### GitHub repo
- Creato repo **DaenAIHax/Agent-Trust-Network** (private) su GitHub
- Git identity: DaenAIHax / DaenAIHax@users.noreply.github.com
- Initial commit: 199 file, ~32k righe
- Force push su main (sovrascrive contenuto precedente)

### Cleanup repo
- **Eliminati da GitHub (`.gitignore`):** `miglioramenti/`, `demo/`, `drafts/`, `admin.py`, `bootstrap.py`, `join.py`, `join_agent.py`, `policy.py`, `revoke.py`, `generate_certs.py`, `generate_demo_certs.py`, `agents/*.env`, `run.sh`, `reset.sh`, `agent.sh`, `CLAUDE.md`, `.claude/`
- **Eliminati completamente:** `repository/`, `files/`, `showcase/` (cartelle intere + 64MB video), `files.zip`, `showcase.zip`, `progress.md`, `roadmap.md`, `roadmapV2.md`, `flusso_policy.md`, `cript_messages.md`, `security_context.md`, `commands.md`, `project_tree.txt`
- **Spostati in `miglioramenti/`:** `payments.md`, `traceability_ledger.md`, `transaction_token.md`, `trust_federation.md`, `mcp_proxy.md`
- **README.md** aggiornato: sostituito con readmeV2 (WIMSE/CB4A aligned), sezione Deployment resa generica (rimossi comandi demo-specifici)

### Risultato
- Su GitHub rimane solo il codice core: `app/`, `agents/` (senza .env), `tests/`, `enterprise-kit/`, `nginx/`, `docker-compose.yml`, `Dockerfile`, `setup.sh`, `shell.nix`, `requirements.txt`, `pytest.ini`, `README.md`, `.env.example`
- File locali (appunti, script CLI, certificati, config Claude) restano sul disco ma fuori dal repo

---

## 2026-04-04 — OpenTelemetry (traces + metrics + Jaeger)

### Implementato
- **`app/telemetry.py`** (nuovo) — init TracerProvider, MeterProvider, auto-instrumentors (FastAPI, SQLAlchemy, Redis, HTTPX), graceful degradation
- **`app/telemetry_metrics.py`** (nuovo) — 7 counters (auth success/deny, session created/denied, policy allow/deny, rate limit reject) + 3 histograms (auth duration, x509 verify, PDP webhook latency)
- **`app/config.py`** — 5 settings OTel: enabled, service_name, endpoint, sampler_arg, metrics interval
- **`app/main.py`** — `init_telemetry()` nel lifespan prima di `init_db()`, `FastAPIInstrumentor.instrument_app()`, `shutdown_telemetry()` allo shutdown
- **`app/auth/router.py`** — span `auth.issue_token`, counters success/deny per reason, histogram durata
- **`app/auth/x509_verifier.py`** — span `auth.x509_verify` + child `auth.x509_chain_verify`, histogram durata
- **`app/broker/router.py`** — span `broker.create_session`, counters created/denied
- **`app/policy/engine.py`** — counters allow/deny per policy_type nella funzione _audit
- **`app/policy/webhook.py`** — span `pdp.webhook_call`, histogram latenza per org_id
- **`app/rate_limit/limiter.py`** — counter reject su entrambi i backend (in-memory + Redis)
- **`docker-compose.yml`** — servizio Jaeger all-in-one (UI 16686, OTLP 4317), env vars OTel nel broker
- **`tests/conftest.py`** — `OTEL_ENABLED=false` prima degli import app

### Dashboard — link Jaeger
- Voce "Traces" nella sidebar (admin-only), icona fulmine + icona link esterno
- Apre Jaeger UI in nuova tab, URL derivato da `OTEL_EXPORTER_OTLP_ENDPOINT`
- `_ctx()` helper passa `jaeger_url` a tutti i template via `base.html`

### Risultato
- 203 test verdi, zero regressioni
- Jaeger UI su http://localhost:16686, raggiungibile dalla dashboard
- Traces visibili per auth, sessioni, policy, PDP webhook
- Broker funziona anche senza Jaeger (graceful degradation)

---

## 2026-04-04 — Certificate Thumbprint Pinning (anti Rogue CA)

### Problema
L'Org CA poteva generare certificati arbitrari per i propri agenti con chiavi diverse. Il broker accettava qualsiasi cert firmato dalla CA e sovrascriveva `cert_pem` senza verifiche. Questo rompeva la non-repudiation e permetteva impersonation intra-org.

### Implementato
- **`cert_thumbprint` column** in `AgentRecord` — SHA-256 hex del DER del certificato
- **Pinning al primo login** — `update_agent_cert()` salva il thumbprint la prima volta, rifiuta cert con thumbprint diverso ai login successivi
- **`compute_cert_thumbprint()`** — helper per calcolare SHA-256 del DER
- **`rotate_agent_cert()`** — rotazione esplicita con invalidazione token attivi
- **x509 verifier** — ritorna anche il thumbprint, calcolato al parsing del cert DER
- **Auth router** — verifica thumbprint dopo binding check, 401 "Certificate thumbprint mismatch" se diverso
- **API endpoint** `POST /registry/agents/{id}/rotate-cert` — auth via org secret, valida cert (CA chain, CN match, scadenza), audit log con vecchio/nuovo thumbprint
- **Dashboard** — pagina "Rotate Certificate" con form upload PEM, thumbprint mostrato nella tabella agenti, link "Rotate Cert" per ogni agente
- **Validazione cert nella rotazione** — verifica firmato dalla Org CA, CN corrisponde, non scaduto
- **cert_factory.py** — `make_agent_cert_alternate()` e `make_assertion_alternate()` con cache separata per test pinning

### File modificati
- `app/registry/store.py` — colonna, helper, update_agent_cert, rotate_agent_cert
- `app/auth/x509_verifier.py` — thumbprint nel return
- `app/auth/router.py` — pinning check
- `app/registry/router.py` — endpoint rotate-cert API + _validate_cert_for_agent
- `app/registry/models.py` — RotateCertRequest, RotateCertResponse
- `app/dashboard/router.py` — GET/POST rotate-cert, thumbprint in agent list
- `app/dashboard/templates/agents.html` — colonna thumbprint + bottone Rotate
- `app/dashboard/templates/cert_rotate.html` — nuovo template
- `tests/test_auth.py` — 5 nuovi test pinning
- `tests/cert_factory.py` — alternate cert helpers

### Test
- 5 nuovi test: pin al primo login, stesso cert OK, cert diverso rifiutato, rotazione accettata, vecchio cert rifiutato dopo rotazione
- 203 test verdi, zero regressioni

---

## 2026-04-04 — Demo scenario ERP-triggered + dashboard policy + fix

### DPoP Server Nonce (RFC 9449 §8)
- Nonce server-side generato ogni 5 min con rotazione (current + previous validi)
- `app/auth/dpop.py` — `generate_dpop_nonce()`, `get_current_dpop_nonce()`, `_is_valid_nonce()`, step 12 in `verify_dpop_proof`
- `app/main.py` — middleware che aggiunge `DPoP-Nonce` header su ogni risposta API
- `agents/sdk.py` — `_dpop_nonce` field, nonce in claims, retry automatico su 401 `use_dpop_nonce`, `_authed_request` wrapper
- `tests/cert_factory.py` — `DPoPHelper` auto-primes nonce, `make_dpop_proof` accetta `nonce` param
- 5 nuovi test: nonce required, valid accepted, wrong rejected, previous still valid, response header
- 198 test verdi, zero regressioni

### Deploy produzione Docker
- Nginx reverse proxy con TLS self-signed (`nginx/nginx.conf`, `nginx/generate_tls_cert.sh`)
- WebSocket proxy pass (`/broker/ws` → upgrade connection)
- HTTP → HTTPS redirect
- `docker-compose.yml` aggiornato: aggiunto servizio nginx, `BROKER_PUBLIC_URL=https://localhost`, `FORWARDED_ALLOW_IPS=*`
- `Dockerfile` broker: aggiunto `--proxy-headers` e `--forwarded-allow-ips`
- `setup.sh` aggiornato: genera TLS cert, aspetta nginx, output con URL https

### Dashboard — Policies page
- Nuova pagina "Policies" nella sidebar (tra Sessions e Audit Log)
- Lista session policy con org, target org, capabilities, effect, status (active/inactive)
- Form "Create Session Policy": org, target org, capabilities, effect (allow/deny)
- Policy ID auto-generato come `{org}::session-{target}-v1`
- Bottone "Deactivate" (soft delete — storico preservato)
- Scoped per ruolo: admin vede tutte, org user vede solo le proprie
- CSRF protection su tutti i POST

### Precedente nella stessa sessione: Demo scenario ERP-triggered + fix dashboard

### Demo completa (`demo/`)
- `generate_org_certs.py` — due modalità: `--org` genera CA, `--agent` genera cert agente (separati)
- `create_policies.py` — crea session policy bidirezionali tra electrostore e chipfactory
- `inventory.json` — inventario simulato con soglie, config buyer hardcoded
- `inventory_watcher.py` — monitor che triggera buyer automaticamente (zero parametri)
- `buyer_agent.py` — agente on-demand con negoziazione JSON ibrida (LLM decide, messaggi strutturati), WebSocket
- `supplier_agent.py` — daemon in ascolto con WebSocket, risponde da catalogo via LLM + JSON
- `demo_commands.md` — tutti i comandi passo-passo per riprodurre la demo

### Fix dashboard
- Form "Register Agent" semplificato: solo org, agent name, display name (opzionale), capabilities
- Agent ID costruito automaticamente come `org_id::agent_name`
- Binding auto-creato e auto-approvato alla registrazione
- Bottone Delete agent con revoca binding
- Badge log silenziati (filtro uvicorn access log)

### Fix broker
- PDP webhook: se non configurato → skip (allow) invece di deny. Permette demo senza mock PDP
- Cookie `secure` condizionale: `True` solo se `BROKER_PUBLIC_URL` contiene https

---

## 2026-04-03 — Rimozione ruoli + Kit enterprise

### Rimozione sistema ruoli
Semplificazione architetturale: l'autorizzazione funziona solo tramite capabilities.
I ruoli aggiungevano complessità senza valore reale — le capabilities sono più granulari e flessibili.

**Rimosso:**
- Colonna `role` da `AgentRecord`
- Funzione `_auto_binding` (binding ora sempre esplicito)
- `list_agents_by_role()`, `list_role_policies()`
- Endpoint `/policy/roles` (POST, GET, DELETE)
- `_evaluate_role_policies()` nel policy engine
- Campo `target_role` da `SessionConditions`
- `RolePolicyCreateRequest`, `RolePolicyResponse`
- Parametro `role` da SDK, bootstrap, join_agent, policy.py
- Template HTML campo role in agent_register
- `test_role_policy.py` (13 test rimossi — non più necessari)

**File toccati:** 16 file modificati, 1 file test eliminato

### Kit integrazione enterprise
- `enterprise-kit/BYOCA.md` — guida "Bring Your Own CA" step-by-step per reparto sicurezza
- `enterprise-kit/docker-compose.agent.yml` — template Docker Compose per deploy agente lato cliente
- `enterprise-kit/pdp-template/pdp_server.py` — server PDP con regole configurabili (allowed orgs, capabilities, blocked agents)
- `enterprise-kit/pdp-template/rules.json` — esempio regole personalizzabili
- `enterprise-kit/pdp-template/Dockerfile` — container pronto per il PDP
- `enterprise-kit/quickstart.sh` — script interattivo: genera CA + cert + registra org e agente in un comando

### Risultato
- 193 test verdi, zero regressioni
- Architettura semplificata: solo capabilities, niente ruoli
- Kit enterprise pronto per onboarding clienti

---

## 2026-04-03 — Dashboard security hardening

### Audit e fix
- **CSRF protection** — token random 16 byte generato al login, salvato nel cookie firmato, verificato (timing-safe) su ogni POST. Hidden field `csrf_token` in tutti i form (onboard, approve, reject, register agent)
- **Auth enforcement approve/reject** — endpoint `POST /orgs/{id}/approve` e `/reject` erano accessibili senza autenticazione. Aggiunto `require_login` + check `is_admin`
- **Auth enforcement badge** — endpoint `/badge/pending-orgs` e `/badge/pending-sessions` leak-avano conteggi a utenti non autenticati. Aggiunto session check, pending sessions scoped per org
- **Cookie `secure=True`** — il cookie di sessione veniva trasmesso anche su HTTP. Aggiunto flag `secure` su `set_cookie` e `delete_cookie`
- **Security headers middleware** — `X-Frame-Options: DENY` (anti-clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (no camera/mic/geo), CSP con `frame-ancestors 'none'` su tutte le route `/dashboard`
- **Input validation** — org_id e agent_id validati con regex alfanumerico (max 128 char), webhook URL scheme check (solo http/https con hostname valido), capabilities format e count limit, display name max 256 char

### File modificati
- `app/dashboard/session.py` — CSRF token generation, `verify_csrf()`, `secure=True`
- `app/dashboard/router.py` — auth check su approve/reject/badge, CSRF validation su tutti i POST, input validation helpers
- `app/main.py` — security headers middleware
- `app/dashboard/templates/orgs.html` — CSRF hidden field su form approve/reject
- `app/dashboard/templates/org_onboard.html` — CSRF hidden field
- `app/dashboard/templates/agent_register.html` — CSRF hidden field
- `tests/test_dashboard.py` — da 20 a 35 test (+15 test di sicurezza: CSRF, auth enforcement, headers, input validation)

### Risultato
- 206 test verdi, zero regressioni
- Dashboard coperta contro CSRF, clickjacking, IDOR su approve/reject, info disclosure su badge, XSS (gia ok), input injection

---

## 2026-04-03 — DPoP RFC 9449 + pulizia

### Implementato
- **DPoP obbligatorio (RFC 9449)** — token binding a chiave EC P-256 efimera
  - `app/auth/dpop.py` — verify_dpop_proof, compute_jkt (RFC 7638), build_htu
  - `app/auth/dpop_jti_store.py` — store JTI in-memory con TTL (interface Redis-ready)
  - `app/auth/jwt.py` — create_access_token aggiunge `cnf.jkt`, get_current_agent verifica DPoP
  - `app/auth/router.py` — /auth/token richiede header DPoP
  - `app/auth/models.py` — `cnf` su TokenPayload, `token_type: "DPoP"`
  - `app/broker/router.py` — WebSocket auth con DPoP proof
  - `agents/sdk.py` — chiave EC efimera al login, DPoP proof per-request
  - Normalizzazione HTU per reverse proxy (`BROKER_PUBLIC_URL`, ws:// > http://)
  - `run.sh` aggiornato con --proxy-headers e --forwarded-allow-ips
  - CORS: header DPoP aggiunto a allow_headers
- **Test DPoP** — 20 unit test in test_dpop.py + 16 integration test in test_auth.py
- **Migrazione test suite** — tutti i 18 file test aggiornati per DPoP (Bearer rimosso ovunque)
- **Roadmap aggiornata** — PDP Webhook e DPoP marcati come implementati

### Decisioni architetturali
- DPoP obbligatorio (non opt-in) — ATN e un sistema nuovo, gli agenti sono macchine aggiornabili
- ES256 (P-256) per chiavi DPoP — piu veloce di RSA per chiavi efimere
- JTI tracking rigoroso con TTL 300s — Redis arrivera con il pub/sub WebSocket
- Server nonce rimandato — il JTI tracking e sufficiente per A2A
- `BROKER_PUBLIC_URL` come override canonico per HTU dietro proxy

### Pulizia
- Tutti i file in `miglioramenti/` spostati in `archive/`
- Creato `readmeV2.md` — README enterprise per presentazioni
- Creato `status.md` — cosa c'e e cosa manca
- Creato `changelog.md` — questo file

---

## 2026-04-03 — Dashboard multi-ruolo + Redis multi-worker

### Dashboard con autenticazione e ruoli
- **Login page** `/dashboard/login` con due tab: Network Admin e Organization
- **Cookie firmato** HMAC-SHA256 con scadenza 8h, httponly, samesite=lax
- **Ruolo admin**: vede tutto — tutte le org, agenti, sessioni, audit. Puo onboardare org, approve/reject, registrare agenti per qualsiasi org
- **Ruolo org**: vede solo i propri dati — propri agenti, proprie sessioni, proprio audit. Puo registrare agenti solo nella propria org. Non vede "Organizations" nella sidebar, non puo onboardare altre org
- **5 pagine** a `/dashboard`: Overview, Organizations (admin-only), Agents, Sessions, Audit Log
- **Operazioni admin**: form "Onboard Org" (CA PEM + webhook + approve diretto), bottoni Approve/Reject su org pending, form "Register Agent" con auto-binding
- **Badge HTMX** nella sidebar: contatore org pending e sessioni pending, auto-refresh ogni 10s
- **Notifiche persistenti**: tabella `notifications` in DB, create alla richiesta sessione, marcate come acted all'accept. Endpoint `GET /broker/notifications` per agenti. Sopravvivono restart.
- **20 test** in `test_dashboard.py`: login/logout, rendering, onboarding, agent registration, scoped filtering, admin-only access control
- FastAPI + Jinja2 + Tailwind CSS (CDN) + HTMX, zero dipendenze frontend, zero build step

---

## 2026-04-03 — Redis multi-worker

### Implementato
- **Redis connection pool** (`app/redis/pool.py`) — async client con graceful fallback a in-memory
- **DPoP JTI store Redis** — `SET NX EX` atomico, zero race condition tra worker
- **Rate limiter Redis** — sorted set sliding window con pipeline atomica
- **WebSocket Pub/Sub** — local-first delivery, Redis cross-worker fallback, background listener
- **Config** — `REDIS_URL` in config.py e docker-compose.yml
- **Lifespan** — init Redis al startup, graceful shutdown (listener cancel, pubsub close)
- `verify_dpop_proof` e `rate_limiter.check` convertiti in async

### Risultato
- Il broker supporta deployment multi-worker (`uvicorn --workers N`)
- Senza Redis tutto funziona come prima (fallback automatico a in-memory)
- 171 test verdi, zero regressioni

---

## Pre-2026-04-03 — Settimane 1-3

### Settimana 1 — Fondamenta
- PKI a 3 livelli (Broker CA > Org CA > Agent Certificate)
- SPIFFE ID nel SAN x509
- JWT RS256 con chiave broker
- Registry org/agenti/binding con approvazione
- Session broker con persistenza PostgreSQL
- Audit log append-only
- Rate limiting sliding window
- Test suite con PKI effimera

### Settimana 2 — Messaggistica e sicurezza
- WebSocket push real-time + fallback REST polling
- E2E AES-256-GCM + RSA-OAEP (il broker non legge il plaintext)
- Doppia firma RSA-PSS (inner non-repudiation + outer transport)
- Prompt injection detection (regex + LLM judge)
- Capability discovery cross-org
- Onboarding flow (join/approve/reject)
- Revoca certificati e token

### Settimana 3 — Enterprise
- KMS Adapter pattern (local + HashiCorp Vault KV v2)
- PDP Webhook federato (entrambe le org devono approvare, default-deny)
- Role policy con auto-binding
- SDK Python per agenti (auth, E2E, firma, WebSocket)
- Agenti demo (buyer + manufacturer) con negoziazione LLM-powered
- Test E2E completo (registrazione > auth > sessione > messaggi cifrati > replay attack > intrusion)
- Docker Compose (broker, postgres, vault, redis, mock PDP x2)
- setup.sh one-command (PKI, container, Vault init, bootstrap)
- Dockerfile broker
- generate_demo_certs.py per org demo
