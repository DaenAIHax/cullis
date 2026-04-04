# Changelog

## 2026-04-04 — Security Audit & Hardening

### Critical Fixes (Phase 1 — by other agent)

- **C1** Policy webhook default-allow → default-deny when no PDP webhook configured (`policy/webhook.py`)
- **C2** Message policy engine now called in `send_message()` — was dead code (`broker/router.py`)
- **C3** Injection detector integrated into production message flow (`broker/router.py`)
- **C4** JTI blacklist race condition fixed — atomic `INSERT ON CONFLICT DO NOTHING` (`auth/jti_blacklist.py`)
- **C5** `extract_strings()` now recursive — nested payloads no longer bypass injection check (`injection/patterns.py`)
- **C6** Redis rate limiter race condition fixed — atomic Lua script (`rate_limit/limiter.py`)

### Dashboard & New Vulnerabilities (Phase 2)

#### Timing Attacks — constant-time comparison everywhere

- Admin secret comparison uses `hmac.compare_digest()` in all 3 locations (`dashboard/router.py`, `onboarding/router.py`, `policy/router.py`)
- DPoP nonce comparison uses `hmac.compare_digest()` (`auth/dpop.py`)
- DPoP access token hash (ath) comparison uses `hmac.compare_digest()` (`auth/dpop.py`)

#### Authentication & Authorization

- `POST /registry/orgs` and `GET /registry/orgs` now require admin secret header (`registry/org_router.py`)
- Dashboard login rate limited — 5 attempts per 5 minutes per IP (`dashboard/router.py`, `rate_limit/limiter.py`)

#### WebSocket Hardening

- Idle timeout — connections closed after 5 minutes of inactivity (`broker/router.py`)
- Message rate limiting — max 30 messages per 60 seconds per connection (`broker/router.py`)
- Token expiry re-validated on every loop iteration (`broker/router.py`)
- Per-org connection limit — max 100 concurrent WebSocket connections per organization (`broker/ws_manager.py`)

#### Content Security Policy

- Removed `'unsafe-inline'` from `script-src` in dashboard CSP (`main.py`)

#### Input Validation

- Pydantic models now enforce size limits: payload (1 MB), metadata (16 KB), context (16 KB), rules (32 KB) (`registry/models.py`, `broker/models.py`, `policy/models.py`, `registry/org_router.py`)
- `max_length` constraints on `agent_id`, `org_id`, `display_name`, `nonce`, `signature` fields
- Audit log search query truncated to 100 characters to prevent expensive LIKE queries (`dashboard/router.py`)

#### Information Disclosure

- Certificate CN value no longer reflected in error messages (`dashboard/router.py`)
- Generic error message for certificate verification failures (`dashboard/router.py`)
- Jaeger URL constructed with proper `urlparse` validation (`dashboard/router.py`)

#### Internationalization

- All Italian strings translated to English: `spiffe.py`, `auth/revocation.py`, `auth/models.py`, `onboarding/router.py`, `registry/router.py`, `policy/router.py`

#### Infrastructure

- Broker CA private key permissions fixed: 644 → 600 (`certs/broker-ca-key.pem`)

### Known Issues (to be addressed)

- Webhook SSRF — no URL validation for internal IPs (`policy/webhook.py`)
- LLM injection judge fails open when API unavailable (`injection/detector.py`)
- CA certificate not validated at onboarding intake (`onboarding/router.py`)
- Session expiration returns object instead of None (`broker/session.py`)
- Telemetry insecure mode configurable but defaults to secure (`telemetry.py`)
- E2E encryption AAD does not include sequence number (`e2e_crypto.py`)
- Nonce consumption and message persistence not atomic (`broker/router.py`)
- Agent deletion does not cascade to sessions/messages (`dashboard/router.py`)
- Message polling lacks pagination (`broker/router.py`)
