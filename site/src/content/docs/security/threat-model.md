---
title: "Threat model"
description: "STRIDE threat model for Cullis Mastio (mcp_proxy/) and the Cullis Python SDK (cullis_sdk/): system boundaries, trust assumptions, per-component threats, mitigations in code, and residual risks."
category: "Security"
order: 1
updated: "2026-05-23"
---

# Threat model

This document is a self-driven threat model of the two components
this repository ships: **Cullis Mastio** (`mcp_proxy/`), the
per-organisation agent gateway, and the **Cullis Python SDK**
(`cullis_sdk/`), the library agents link against to authenticate,
make LLM calls, and call MCP tools through the gateway. It is
written for security reviewers (CISO, blue-team architects, customer
security engineering) who need to convince themselves that the
component they are about to install on their infrastructure has been
reasoned about adversarially, that the mitigations claimed are
present in code, and that the residual risks are stated honestly.

It is **not** a substitute for a third-party penetration test. We
intend to commission one once the first paying customer engagement
funds it. Until then, this document plus the public `/security-review`
output on every merged PR, the supply-chain attestations on every
released artefact, and the audit-log hash chain that ships in the
bundle are the artefacts we expect a reviewer to inspect.

Every claim in the per-component sections below has been
cross-checked against the codebase by a verification pass on
2026-05-23. Where a stated mitigation is partial, aspirational, or
implemented differently from the design intent, we say so explicitly
inline ("on the roadmap", "today: …", "we do not currently …") and
list the corresponding gap in the open-items table at the end of the
document. We would rather call out a real gap here than have a
reviewer discover it.

## Scope

In scope:

- **Cullis Mastio** (`mcp_proxy/`): FastAPI process that handles
  agent enrollment, DPoP-bound token issuance, the policy decision
  point (PDP), the MCP reverse proxy, the embedded AI gateway, and
  the append-only audit chain. Shipped as a Docker bundle
  (`packaging/mastio-bundle/`) and a Helm chart
  (`deploy/helm/cullis-mastio/`).
- **Cullis SDK** (`cullis_sdk/`): Python client used by an agent
  process to authenticate (`from_identity_dir`, `login_via_proxy`,
  `login_via_proxy_with_local_key`), call LLMs through the gateway
  (`chat_completion`, `chat_completion_stream`), and call MCP tools
  through the proxy (`list_mcp_tools`, `call_mcp_tool`).

Out of scope (treated as trust assumptions, see below):

- The operating system and container runtime hosting the bundle.
- The TLS PKI used to terminate edge connections.
- The downstream LLM providers reached through the embedded AI
  gateway (Anthropic, OpenAI, Bedrock, Vertex, Ollama, …).
- Identity providers federated through SAML SSO or SPIRE.
- The HashiCorp Vault deployment used as KMS in production: we
  assume the operator has secured it per the vendor's hardening
  guide.
- Any component that lives outside this repository (desktop
  clients, multi-org federation services, additional dashboards):
  not shipped here, not analysed here.

## Audience

Two readers:

- **A reviewing CISO or security architect** evaluating whether the
  Cullis Mastio is fit to live next to their existing fleet, carrying
  identity and policy decisions for AI agents that touch internal
  data. This reader wants STRIDE coverage, explicit residual risks,
  and references to the code where mitigations live.
- **An operator on the customer side** running the bundle. This
  reader wants to know which trust assumptions they are inheriting,
  what they must configure correctly, and what failure modes they
  are expected to monitor.

If you fit either profile and a section reads as marketing rather
than as analysis, that is a bug. File an issue against
`cullis-security/cullis`.

## Methodology

The model uses **STRIDE** (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege)
per trust boundary. For each component we:

1. Describe the data flow that crosses the boundary.
2. Enumerate STRIDE threats relevant to that flow.
3. Reference the mitigation already in code, with the architectural
   decision record (ADR), pull request, or operational runbook that
   establishes it.
4. Call out residual risk: the part of the threat that the mitigation
   does **not** cover, and what compensating control we expect the
   operator to provide.

## System boundaries

```
              ┌──────────────────────────────────────────────┐
              │                  Operator                    │
              │   (deploys + monitors + holds admin secret)  │
              └────────────────────┬─────────────────────────┘
                                   │ admin dashboard
                                   │ (HTTPS + CSRF + httponly cookie)
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│                          Cullis Mastio host                        │
│                                                                    │
│   ┌───────────┐    DPoP+JWT     ┌────────────────────────────┐     │
│   │   Agent   │  ◀──────────▶   │      Cullis Mastio         │     │
│   │  (SDK)    │   cert pinning  │  (mcp_proxy, FastAPI)      │     │
│   └───────────┘                 │                            │     │
│                                 │   ┌─────────────────┐      │     │
│                                 │   │   PDP + policy  │      │     │
│                                 │   │  (default-deny  │      │     │
│                                 │   │   session)      │      │     │
│                                 │   └─────────────────┘      │     │
│                                 │                            │     │
│   ┌───────────┐                 │   ┌─────────────────┐      │     │
│   │  MCP tool │  reverse proxy  │   │  AI gateway     │      │     │
│   │  upstream │  ◀───────────▶  │   │ (embedded       │      │     │
│   │ (Slack…)  │                 │   │  LiteLLM)       │      │     │
│   └───────────┘                 │   └─────────────────┘      │     │
│                                 │                            │     │
│                                 │   ┌─────────────────┐      │     │
│                                 │   │  Audit chain    │      │     │
│                                 │   │ (append-only,   │      │     │
│                                 │   │  hash-chained,  │      │     │
│                                 │   │  per-org)       │      │     │
│                                 │   └────────┬────────┘      │     │
│                                 │            │ KMS calls     │     │
│                                 │            ▼               │     │
│                                 │   ┌─────────────────┐      │     │
│                                 │   │ KMS backend     │      │     │
│                                 │   │ (Vault prod /   │      │     │
│                                 │   │  local dev)     │      │     │
│                                 │   └─────────────────┘      │     │
│                                 └────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────┘
```

Each labelled arrow is a trust boundary; we enumerate STRIDE per
arrow class in the per-component sections below.

## Trust assumptions

The threat model is only meaningful relative to what we treat as
trusted. The following are **assumed correct** and not analysed
further in this document:

| Assumption | Why we make it | What you should verify |
|---|---|---|
| Host OS not compromised; container runtime enforces process isolation | We rely on standard Linux + containerd / Docker semantics. Cullis cannot defend against a root-shell on the host. | Standard OS hardening (CIS benchmark or equivalent). Drop privileges on the runtime, run rootless if possible. |
| TLS PKI not subverted | The bundle's nginx sidecar terminates TLS using a cert issued from the operator's chain. We trust the chain. | Use a CA your security team accepts; rotate on the CA's schedule; monitor CT logs for the issued cert. |
| Container image signature path is honest | Sigstore + Rekor transparency log is consulted at pull time. We assume `cosign verify` is genuinely run and not bypassed. | Run `cosign verify` in your CI before promotion, not just at first deploy. |
| Downstream LLM providers are not actively malicious | The embedded AI gateway forwards requests to Anthropic, OpenAI, Bedrock, etc. We assume they behave per their docs. | Pin the API key per agent (ADR-017). Use an outbound content filter if you need redaction. |
| Vault is correctly deployed | If you choose Vault as the Org CA private key store, that vault is what stops a Mastio host compromise from also leaking the org root key. | Apply the vendor hardening guide; rotate KMS keys on your schedule; restrict policy to the smallest possible verbs. See `operate/vault-org-ca.md`. |
| NTP is configured on the host | Every JWT and DPoP proof has a `nbf` / `exp` / `iat` window. Heavy clock drift breaks signature verification. | Run chrony / systemd-timesyncd; alert on drift > 30 s. |

Anything below this line assumes the above hold.

## Component: agent authentication

### Data flow

- Agent enrollment via one of two paths supported in this repository:
  the dashboard-driven flow (`POST /v1/admin/agents/...` in
  `mcp_proxy/admin/agents.py`) which mints an agent cert under the
  Org CA, or **BYOCA** (the customer signs the cert from their own
  PKI and the Mastio pins the SHA-256 DER thumbprint at first
  contact, `mcp_proxy/admin/enroll.py`). SPIFFE / SPIRE SVIDs are a
  variant of BYOCA from the proxy's point of view.
- Steady-state requests sign a **DPoP proof** (RFC 9449) bound to
  the per-agent keypair; the proxy validates `htu` (target URL),
  `htm` (HTTP method), `iat` (issued-at), and the `ath` claim
  binding to the access token, with `cnf.jkt` thumbprint matching
  enforced on the access token itself (`mcp_proxy/auth/dpop.py`).
- The proxy also supports **client-cert pinning** via a SHA-256 DER
  digest of the presented certificate
  (`mcp_proxy/auth/client_cert.py`). This is pinning, not formal
  RFC 8705 §3 `cnf.x5t#S256` token-level binding; we treat it as
  defence in depth rather than a substitute for DPoP.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of an agent identity | Attacker presents a stolen API key or cert | DPoP proof requires the matching private key; the key is never sent over the wire. The SDK reads it from an identity dir (`from_identity_dir`, see `cullis_sdk/auth.py`); operators provision it at mode 0600 next to the agent. | If the host is compromised and the private key file is exfiltrated, the attacker can impersonate the agent until the cert is rotated. Rotation is admin-driven (dashboard at `/proxy/agents/<id>`, or — when wired — the `POST /registry/agents/<id>/rotate-cert` shape referenced in `mcp_proxy/lifespan/cert_expiry_watcher.py`). |
| Spoofing of an enrollment | Attacker tricks the proxy into enrolling a hostile agent | Each path requires either interactive admin approval through the dashboard (CSRF + `MCP_PROXY_ADMIN_SECRET`) or a customer-signed cert that the operator's PKI already trusts (BYOCA / SPIFFE). No path is purely network-reachable without prior trust. The dashboard surfaces the agent's public-key fingerprint pre-approval. | An admin who clicks "enrol" on a hostile request enrolls a hostile agent. The 4-eyes approval hook (`mcp_proxy/admin/approval_hook.py`, `ACTION_AGENT_ENROLL`) is wired on the dashboard enrollment endpoint and can be configured to require a second admin's signoff. |
| Tampering with the DPoP proof | Replay a captured proof from elsewhere | Redis-backed JTI cache rejects any DPoP `jti` seen in the configured window (`mcp_proxy/auth/dpop_jti_store.py`, `_DEFAULT_TTL = 300` seconds = 5 minutes; `SET NX EX` semantics). `htu` is checked literally including scheme + host + port: a middlebox that strips port 9443 fails. | Replay protection cold-starts empty; first-N requests in the window after a proxy restart have lower replay protection until the cache fills. We do not currently warm the cache from a persistent store. |
| Repudiation by an agent | Agent claims it never made a call | Each call is signed end-to-end (DPoP) and logged to the append-only audit chain with `agent_id`, action, tool name, status, request ID, duration, and the verified DPoP `jkt` thumbprint denormalised onto the row (`local_audit.dpop_jkt`, migration `0033_audit_dpop_jkt`). The chain `previous_hash` / `entry_hash` columns lock historical records under SHA-256. | If the agent claims key compromise, the audit chain attributes the call to the agent's registry ID and to the DPoP `jkt` that was present at request time. Customers needing per-person attribution should pair Cullis with their IdP (SAML SSO or similar) so that the user principal is bound to the agent enrollment. |
| Information disclosure of the cert + key on enrollment | Material shipped over an insecure channel | The dashboard offers the new cert + key PEMs as a one-time download with `Content-Disposition: attachment`, and writes nothing to the response body that gets cached. The operator copies the bytes onto the agent host out-of-band. | A screenshot of the download page leaks the material. We rely on operator hygiene; runbook guidance is in `operate/rotate-keys.md` and the bundle README. |
| DoS via enrollment flood | Attacker hammers the enrollment endpoints | Both `/v1/enrollment/start` and `/v1/enrollment/{id}/status` are rate-limited per source IP (`mcp_proxy/enrollment/router.py`, calling `get_agent_rate_limiter()`). | A compromised admin token bypasses the rate limit. The 4-eyes plugin (open-core hook) can be configured to gate the enrollment approve step as a compensating control. |
| Elevation of privilege | Agent claims a role / capability it was not enrolled with | Roles and capabilities are stored on the registry record server-side; the agent cannot include a claim that overrides what the registry says. The PDP looks up the registry, not the proof. | A SQL-injection or registry-tampering vector would defeat this. We mitigate with parameterised queries throughout (SQLAlchemy), `/security-review` on every PR, and the audit chain providing forensic detection. |

### References

- `mcp_proxy/auth/dpop.py`, `mcp_proxy/auth/client_cert.py`,
  `mcp_proxy/auth/dpop_jti_store.py`
- `mcp_proxy/admin/agents.py`, `mcp_proxy/admin/enroll.py`,
  `mcp_proxy/enrollment/router.py`
- `cullis_sdk/auth.py`, `cullis_sdk/dpop.py`
- ADR-013 (layered defence)

## Component: registry

### Data flow

The registry is the SQLite (default) or Postgres (opt-in) database
behind every PDP decision. It holds: agent enrollment records
(public key, cert thumbprint, role, capabilities), local user
principals (when the dashboard runs in multi-user mode), and
configuration (`proxy_config` table).

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing via stale registry entry | Decommissioned agent's record left active | The dashboard surfaces last-seen time and a one-click revoke. Cert thumbprint pinning means even a copy of the old key with the right fingerprint is rejected after revocation. The cert-expiry watcher (`mcp_proxy/lifespan/cert_expiry_watcher.py`) raises operator-visible warnings as the cert approaches expiry. | Customers who never click revoke leave attack surface up. We do not auto-expire records, intentionally; an expired record breaking a real production agent is a higher-cost failure mode. Operational guidance is in `operate/runbook.md`. |
| Tampering with a record (privilege escalation) | Attacker rewrites a role field directly in the DB | SQLAlchemy uses parameterised queries throughout. Write paths are admin-only (CSRF + httponly cookie + `MCP_PROXY_ADMIN_SECRET`). The audit chain captures every state-changing write with the admin's principal. | Host root can rewrite the SQLite file directly. The hash chain in the audit log makes after-the-fact tampering detectable; the dashboard's **Verify chain** action (`POST /proxy/audit/verify`, `mcp_proxy/dashboard/audit_routes.py:594`) and the standalone CLI (`scripts/cullis-audit-verify.py`) catch a broken link. |
| Repudiation of a registry write | Admin claims they did not change a record | Every write goes through the dashboard signed cookie + audit chain entry. The audit entry includes the admin principal and the action verb. | Same as before: hash chain detects retroactive deletion; live forgery requires both DB write + audit chain write that hashes correctly to the prior row, which is the level of effort we deliberately raise. |
| Information disclosure of registry contents | Read access leaks agent metadata | The Mastio does not expose a public read endpoint on agent records; the dashboard read paths require admin auth. The bundle's nginx config separates dashboard paths from public TLS listeners. | A misconfigured nginx that proxies admin endpoints to the public listener would leak. Do not edit the bundle's nginx config without re-running the security review. |
| Denial of service via registry growth | Attacker creates many junk records | Enrollment endpoints are rate-limited (see above). The `InternalAgent` and `local_audit` tables index hot lookup columns; pathological growth degrades query latency before it degrades disk, and is detectable via `/readyz` and the dashboard overview. | An attacker with valid admin credentials can still flood. 4-eyes gates a configured set of admin actions but does not gate enrollment by default — the operator can opt in. |
| Elevation of privilege | Reading the registry to discover an admin token | The registry never stores admin secrets in plaintext. Admin tokens are bcrypt-hashed and looked up by constant-time prefix to avoid both timing leaks and the event-loop stall the legacy full-scan path produced. | Hash leakage allows offline attack; bcrypt cost factor 12 mitigates but does not eliminate. Rotation policy is in `operate/rotate-keys.md`. |

### References

- `mcp_proxy/db.py`, `mcp_proxy/db_models.py`
- Append-only triggers: migration
  `mcp_proxy/alembic/versions/0031_audit_append_only_v2.py`
- Hash chain: `mcp_proxy/audit_chain.py`, migration
  `0023_audit_hash_chain.py`
- DPoP-on-row: migration `0033_audit_dpop_jkt.py`

## Component: MCP proxy (reverse proxy + DPoP gateway)

### Data flow

Agents call MCP tool endpoints through Cullis Mastio rather than
directly. The proxy:

1. Validates the DPoP proof and the access token against the
   registry.
2. Consults the PDP (`mcp_proxy/policy/`) for `(agent, session,
   tool, model, server)` allow/deny decisions.
3. Reverse-proxies to the upstream MCP server
   (`mcp_proxy/reverse_proxy/forwarder.py`,
   `mcp_proxy/tools/mcp_resource_forwarder.py`), stripping or
   rewriting headers as policy dictates.
4. Writes the call + result hash to the audit chain.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of an upstream MCP server | DNS or middlebox attack redirects to a hostile MCP | Per-tool upstream URL is configured by the org admin and stored in the registry. The bundle calls upstream over TLS with the operator's trust store. Outbound HTTP is gated by a per-tool domain allow-list (`mcp_proxy/tools/http_whitelist.py`, `WhitelistedTransport`). | If the operator pins by URL but never by cert / SPKI hash, a CA misissuance is in scope. Configure the per-tool domain allow-list narrowly; default empty means deny. |
| Tampering with the request en route | Attacker between proxy and upstream rewrites headers | TLS between Mastio and upstream is the default. Inbound trust headers carrying the `X-Cullis-*` prefix are stripped at the ASGI boundary (`mcp_proxy/middleware/strip_x_cullis_headers.py`) so a forwarded request cannot be tricked into elevating itself by setting one. | A vulnerable upstream that trusts headers we do not control (e.g. `X-Forwarded-User`) is in scope; document your trust contract per upstream. |
| Tampering with the policy decision | Attacker forces the PDP to allow | The PDP is in-process; calls to an out-of-process PDP webhook are timeout-bounded (5 s) and **fail-deny on timeout** (`mcp_proxy/policy/federation.py:116`, `except httpx.TimeoutException`). Decision inputs (tool name, principal type, model, target, session ID, reason) are written into the audit row `details` JSON and participate in the entry-level SHA-256 chain. | A compromised in-process PDP code path skips the webhook and is the same threat as code-tampering on the Mastio container. The mitigation is at the image-integrity layer (cosign + SBOM). |
| Repudiation of a tool call | Agent claims the call was not theirs | Every tool call is logged with `agent_id`, action, tool name, status, detail, request ID, duration, and the DPoP `jkt` thumbprint. The audit log hash-chains via `entry_hash` / `previous_hash`. | Audit writes happen after the call has been authorised and dispatched; an audit-write failure is logged but does **not** block the call. A configurable audit-fail-deny mode is on the roadmap. |
| Information disclosure via the proxy | A proxied response leaks sensitive content to the agent | Cullis does not classify content; we forward what the upstream returns. Customers needing outbound content filtering should run their own classifier upstream. | Without an external classifier, content classification is the operator's responsibility. The proxy adds no leak surface beyond what the upstream already exposes. |
| Denial of service against the proxy | Agent flood overwhelms the process | A per-agent rate limiter is implemented at the proxy layer (`mcp_proxy/auth/rate_limit.py`, in-memory single-worker and Redis-backed multi-worker). Container resource limits cap the host-level blast radius. The body-size limit middleware (`mcp_proxy/middleware/limit_request_body.py`) and the DB-latency circuit breaker (`mcp_proxy/middleware/db_latency_circuit_breaker.py`) shed load before the process saturates. | A motivated attacker with valid credentials can still saturate. Exposing the rate-limit field as a per-tool PDP knob is partly aspirational (present in the scope model, not enforced from policy today). |
| Elevation of privilege via header injection | Agent injects an `X-Cullis-Admin: true`-shaped header | Inbound `X-Cullis-*` headers are dropped from the ASGI scope before any handler runs (`mcp_proxy/middleware/strip_x_cullis_headers.py`). The auth path derives the agent and org identity from the DPoP proof / cert pin against the registry, never from request headers. | A custom plugin or upstream middleware that introduces a trusting header is in scope. Document the contract with each upstream. |

### References

- `mcp_proxy/reverse_proxy/`, `mcp_proxy/tools/`,
  `mcp_proxy/middleware/`
- ADR-029 (tool-level PDP)
- `mcp_proxy/audit_chain.py` (per-org chain, retry path
  `_AUDIT_CHAIN_MAX_RETRIES = 5`)

## Component: AI gateway (embedded LiteLLM)

### Data flow

ADR-017: Mastio embeds LiteLLM as the default AI gateway for outbound
LLM calls (`/v1/llm/...`). The gateway is selected by
`settings.ai_gateway_backend` (`mcp_proxy/config.py`); the default
`litellm_embedded` runs in-process. It terminates an OpenAI-shaped
or Anthropic-shaped client request, applies per-agent rate limits
and key selection, and forwards to the configured upstream provider.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the gateway | Agent thinks it is calling Anthropic, hits a proxy | The gateway runs in-process inside Mastio (`mcp_proxy/egress/ai_gateway.py` calls `litellm.acompletion()` directly); no extra hop. The upstream URL is operator-configured; upstream **credentials** are encrypted at rest using Fernet (`mcp_proxy/tools/secret_encrypt.py`, prefix `enc:v1:`). The Fernet master key is **not** KMS-backed today: it lives in `MCP_PROXY_SECRET_ENCRYPTION_KEY_B64` (env) or is auto-generated and stored in the `proxy_config` table. HSM-backed encryption is on the roadmap (see open items). | If the operator points the upstream to an attacker-controlled URL, no Cullis mitigation helps. Use TLS pinning at the bundle's outbound boundary (NetworkPolicy in k8s, host firewall on VPS). If you need HSM-grade protection of the Fernet master key today, mount the env var from a secrets manager such as Vault Agent. |
| Tampering with the prompt or response | A man-in-the-middle alters the LLM payload | The gateway terminates TLS to the upstream; we do not re-encrypt or sign payloads. Customers needing payload integrity guarantees on the wire should run their own provider proxy with their own pinning. | This is a known limitation of any LLM gateway: prompt/response signing is not standardised. We default-deny on TLS errors. |
| Repudiation | Agent denies sending a prompt | Every LLM call is audited identically to a tool call (per-agent, per-DPoP-`jti`, with a hash of the prompt and response and the response summary surfaced under `details`). | The prompt hash is one-way: we cannot reproduce the prompt from the log. This is intentional (privacy / no plaintext retention by default), but means a forensic investigation must rely on the agent's logs for prompt reconstruction. |
| Information disclosure of upstream API keys | The gateway logs the upstream API key | Mastio's gateway never logs the upstream API key. Several competing AI gateways do log upstream keys to their telemetry endpoint as part of their value proposition; we explicitly do not. Upstream credentials live as Fernet-encrypted `creds_json` in `ai_provider_credentials` (migration `0027_ai_provider_creds.py`, encryption added in `0032_ai_creds_at_rest_encrypt.py`). | Operator-side observability that scrapes the gateway's stderr could pick up the key if the upstream emits it in an error message. We sanitise known upstream error patterns; new upstreams should be reviewed. |
| Information disclosure of prompts | Sensitive content sent to an upstream the customer does not control | The customer chooses the upstream. Cullis does not redact by default. | Redaction is the customer's responsibility. This is by design: Cullis is infrastructure, not a content classifier. |
| DoS via expensive prompt | Agent issues a 100k-token prompt repeatedly | Per-agent rate limit + per-agent token budget enforcement (`mcp_proxy/auth/rate_limit.py`, `TokenBudgetLimiter`). Defaults are finite. | An operator who sets the budget to infinity inherits the cost risk. |
| Elevation of privilege via prompt injection | Agent persuades the gateway to forward to a different upstream | Routing decisions are made server-side from the registry, not from the request body. Prompt injection cannot redirect the gateway. | Prompt injection against the *upstream LLM* can still cause it to misbehave; this is the upstream's responsibility. |

### References

- ADR-017 (embedded LiteLLM)
- `mcp_proxy/egress/ai_gateway.py`,
  `mcp_proxy/egress/llm_chat_router.py`,
  `mcp_proxy/egress/provider_catalog.py`
- `mcp_proxy/tools/secret_encrypt.py`

## Component: policy bridge (OPA Data API + CloudEvents sink)

### Data flow

PR #907: Mastio exposes its policy + audit surface via two standards-shaped endpoints so external data planes (any gateway that speaks OPA + CloudEvents) can use Cullis as control plane without writing glue. `POST /v1/data/cullis/policy/{path}` accepts an OPA Data API request (`{"input": {...}}`) and returns `{"result": {"decision": ...}}`. `POST /v1/integrations/cloudevents` accepts a CloudEvents HTTP-binding event and persists it as one row on the hash-chained `audit_log`. Both endpoints share a single HMAC-SHA256 guard via `X-Cullis-Integration-Signature` keyed on `MCP_PROXY_INTEGRATIONS_HMAC_SECRET`.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the calling gateway | An unauthenticated peer on the Mastio network probes the OPA endpoint to discover `policy_rules` content via differential responses | The HMAC signature is required when `MCP_PROXY_INTEGRATIONS_HMAC_SECRET` is set; missing or mismatched signatures return 401 with **no body** so the caller cannot use timing or shape to distinguish "bad signature" from "wrong path" (audit 2026-04-30 lane 3 H3 same threat as `/pdp/policy`). Distinct secret from `pdp_webhook_hmac_secret` so rotation does not couple two trust boundaries. | When the operator deploys without setting the secret (documented rollout posture), any peer on the Mastio network can read the OPA decisions + write audit rows. The Mastio logs a warning at boot. Operator must enable HMAC before production traffic. |
| Tampering with audit_log via the sink | Attacker injects forged rows that pollute the audit chain | Every row goes through `db.log_audit` which appends to the hash-chained `audit_log` table protected by the F-A-402 plpgsql trigger (BEFORE UPDATE/DELETE, RAISE). The CloudEvent `source` lands on `agent_id` prefixed with `external:` so dashboard queries and the `cullis-audit-verify.py` chain walk can isolate bridge rows from native Cullis agents. The HMAC gate above is the front-line defence; the trigger + hash chain are the integrity backstop. | An operator-trusted gateway that becomes compromised can write believable rows. The audit chain still detects tampering after the fact (rows hash-chain forward); the operator's gateway-side audit is the in-time gate. |
| Repudiation | A peer denies sending a policy query | Same as the legacy PDP webhook: every request is bound by HMAC + lands in the audit log if it materialises a decision. The CloudEvent sink writes `request_id = ce-id` so an external trace can be reconciled against the Cullis chain. | No client-side non-repudiation: the HMAC binds only to a shared secret, not to a per-peer keypair. mTLS at the front layer can add that — out of scope for this endpoint, in scope for the Mastio's main listener. |
| Information disclosure via OPA decision shape | An attacker probes the OPA endpoint with crafted `input` to enumerate the operator's `policy_rules` content | Unknown paths return `{"result": null}` (OPA convention) without revealing which paths exist; the HMAC gate keeps unauthorised peers out entirely when configured. | When the operator runs without HMAC the `policy_rules` content is enumerable, same as the legacy PDP webhook in that posture. |
| DoS via expensive CloudEvents bodies | Attacker floods the sink with large payloads | The `audit_log.detail` JSON has a 16 KiB cap (`AUDIT_DETAILS_MAX_BYTES`, F-A-410) before `log_audit` writes — large bodies are rejected at the row boundary, not after a chain commit. Global request-body size limit middleware (`F-A-303`, 2 MiB default) caps the inbound payload before parsing. | Operator-side rate limit (NetworkPolicy / nginx) is the right outer perimeter. The Mastio's global rate limiter (`global_rate_limit`, 500 RPS default) is the next-inner. |
| Elevation of privilege | A peer with the HMAC secret tries to write rows attributing them to a native Cullis agent | The `external:` prefix on `agent_id` is computed server-side from the CloudEvent `source` (untrusted) — the caller cannot suppress it. Cullis-native rows never carry that prefix; dashboard + audit verifier discriminate cleanly. | A peer with the HMAC secret is by definition trusted at the policy-bridge layer; the prefix is for cross-plane visibility, not for privilege segregation. |

### References

- `mcp_proxy/integrations/policy_bridge.py`, `mcp_proxy/integrations/__init__.py`
- `mcp_proxy/main.py` route registration
- `mcp_proxy/middleware/strip_x_cullis_headers.py` allowlist entry for `x-cullis-integration-signature`
- `operate/policy-bridge.md` or `integrations/policy-bridge.md` for the operator-side deploy

## Component: Rego policy engine (embedded WASM)

### Data flow

PR #908 + #909: the operator authors Rego in the dashboard Policies → Rego tab. The backend compiles via the bundled `opa build -t wasm` (OPA v1.16.2, SHA-256-pinned in `scripts/opa-sha256.txt`) and persists both the source and the base64-encoded WASM bundle inside the existing `proxy_config.policy_rules` JSON document. At decision time, `try_rego_decision` (in `mcp_proxy.policy.__init__`) reads the WASM, instantiates `OPAPolicy` via `opa-wasmtime` (process-wide cached on SHA-256), evaluates against the OPA-shaped input, and returns `{"decision": ..., "reason"?}`. The legacy allowlist (`blocked_agents`, `allowed_orgs`, `tool_rules`) backs up the Rego path: empty Rego → allowlist; Rego runtime eval error → allowlist + warning log.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the Rego author | Attacker pushes a malicious Rego that always allows | The Rego authoring surface (`/proxy/policies/rego`) is admin-protected (dashboard cookie + CSRF) — same trust boundary as every other policy-editing route. There is no public path that writes `policy_rules.rego`. | An attacker with admin credentials is the trust root for Cullis; this is the same posture as any other policy product. The hash-chained audit log is the post-hoc detection (`policy.rego_save` row stamped with the WASM sha256 prefix). |
| Tampering at the compile step | Malformed Rego could exercise an `opa build` parser bug | The bundled OPA binary is **SHA-256-pinned** at Dockerfile build time (`scripts/opa-sha256.txt`) for both amd64 and arm64; supply-chain attestation covers the layer. Compile is bounded at 10 seconds and runs under the proxy container's uid, not root. Output bundle is extracted via `tarfile.extractfile` which returns a file-like in memory (NOT `extractall` — no filesystem write, no CVE-2007-4559 path-traversal surface). | An upstream OPA CVE we have not patched yet would still apply; we track OPA's security advisories. |
| Tampering with the persisted WASM | Operator with DB access edits `rego_wasm_base64` to inject custom WASM | The persisted bundle is operator-trusted (same admin who could edit the JSON config could also push Rego through the dashboard). At eval time `opa-wasmtime` instantiates the WASM in a sandbox with **no host imports** (the engine passes no `builtins=` kwarg, so the WASM has only the OPA WASM ABI — memory + JSON manipulation, no FFI to host filesystem / network / syscalls). | A wasmtime sandbox-escape CVE (out of scope per rule #9 of the security-review filter) would apply. We track wasmtime's advisories. |
| Repudiation of a policy change | Operator denies saving a Rego that allowed a transaction | The Save flow writes `policy.rego_save` (success) or `policy.rego_save` with `status=compile_error` (failed compile) into the audit log, with the operator's `admin` agent_id, the resulting WASM byte length, and the SHA-256 prefix. Audit log is hash-chained. | The dashboard session does not currently bind a WebAuthn assertion to the Save click; an admin password that leaked would let an attacker push a Rego silently. ADR-033 WebAuthn user-session binding (Phase 2) addresses this in a future release. |
| Information disclosure via compile diagnostics | `opa build` stderr leaks internal paths | The compile runs in a `tempfile.TemporaryDirectory` so the path is `/tmp/cullis-rego-<random>/policy.rego`. The dashboard surfaces the diagnostic verbatim to the operator (intentional UX: they need to see the line/column). The path is non-secret. | The diagnostic is shown only to authenticated admin users on the editor page. |
| DoS via Rego compile or eval loop | Runaway compile or eval consumes CPU | Compile is bounded at 10 seconds (`_COMPILE_TIMEOUT_SECONDS`). Eval has **no per-call timeout today** — a pathologically slow Rego would block one async task; the global rate limit + the synchronous nature of the call (one decision per request) bound the blast radius. | Per-eval timeout is on the roadmap (open items). |
| Elevation of privilege through Rego rules | Operator's Rego authorises an agent that shouldn't be authorised | This is the operator's policy by construction — the engine evaluates what the operator wrote. The legacy allowlist + the existing PDP federation gates around the Rego output are the orthogonal defences (Rego decides allow vs deny, federation decides whether the cross-org peer can even be reached). | An operator who writes an over-permissive Rego carries the same liability as an over-permissive YAML allowlist. The decision is auditable per row. |

### References

- `mcp_proxy/policy/rego_engine.py` (compile + cache + eval)
- `mcp_proxy/policy/__init__.py` (`try_rego_decision` two-layer dispatcher)
- `mcp_proxy/dashboard/rego_rules.py` + `templates/rego_rules.html` (authoring surface)
- `scripts/opa-sha256.txt` (binary pin)
- `mcp_proxy/Dockerfile` (`opa-build` stage)
- `scripts/bench-rego-eval.py` (perf bench)
- `operate/rego-policies.md` for the operator workflow

## Component: license verifier

### Data flow

The Mastio carries an offline RS256 license verifier
(`mcp_proxy/license.py`) that gates paid feature dispatch. In the
public repository the bundled public key is a placeholder; a real
deployment overrides it via `CULLIS_LICENSE_PUBKEY_PATH`. The token
itself is read from `CULLIS_LICENSE_KEY` (raw JWT) or
`CULLIS_LICENSE_PATH` (file). Missing or invalid token = community
tier, no paid features.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of a license | Attacker forges a JWT with paid features | Verification is RS256 against the embedded (or operator-overridden) pubkey; the private key is held by Cullis Inc. There is no fallback path that accepts an unsigned token. | Compromise of the priv-key would bypass the protection for every customer of that build. Annual rotation is the commitment; HSM-backed signing is a P2 item. |
| Tampering with the verifier | Attacker patches the verifier to always return true | The verifier code is baked in the cosign-signed image; tampering invalidates the cosign attestation. The verifier is exercised on every paid-feature dispatch. | Custom builds bypass cosign. Operators should run `cosign verify` on every deploy, not just at first install. |
| Repudiation | Customer claims they never imported the license | License import via the admin dashboard is audit-logged and gated by the 4-eyes approval hook (`ACTION_LICENSE_IMPORT`, `mcp_proxy/dashboard/settings_routes.py`). | If multiple admins are configured and they disagree about who imported, the audit chain resolves it. |
| Information disclosure | The license JWT contains customer-identifying data | The JWT contains the customer org name, tier, entitlements, and an expiry. No secrets, no PII. The HTTP error response for license-related failures returns only `{error, feature, tier}`. | Exception messages logged at debug level may include payload context. The HTTP client-facing response is already minimal; a dedicated JWT scrubber on the generic exception path is on the roadmap. |
| DoS via license rejection | A genuinely valid license fails verification | The verifier exits with a clear error code per case (expired, wrong signature, malformed). The dashboard surfaces these specifically. | Clock-skew on the host causes false negatives on `nbf` / `exp`. We require NTP. |
| Elevation of privilege | Patched verifier enables features that were not paid for | `cosign verify` is the answer; the second answer is that the audit chain naming the paid feature fired in the absence of a matching license JWT (a detectable contradiction). | We do not phone home for license validation. This is intentional (air-gap support) but means we trust the operator's image-integrity stance. |

### References

- `mcp_proxy/license.py`
- `mcp_proxy/admin/approval_hook.py` (`ACTION_LICENSE_IMPORT`)

## Component: KMS backend

### Data flow

The Org CA private key (used to sign agent certificates) can live in
two places in this repository, chosen at deploy time via
`MCP_PROXY_KMS_BACKEND` (`mcp_proxy/kms/factory.py`):

- `local` (development default): the key is stored in the
  `proxy_config` table of the Mastio's own SQLite or Postgres
  database. The row is wrapped in a Fernet envelope keyed by
  `MCP_PROXY_DB_ENCRYPTION_KEY` (`pki_key_store` table, migration
  `0038_pki_key_store.py`).
- `vault` (production): HashiCorp Vault KV v2 path (ADR-031,
  `mcp_proxy/kms/vault.py`).

The production-mode startup validator (`mcp_proxy/config.py:1007`)
**refuses** `MCP_PROXY_KMS_BACKEND=local` and exits with `SystemExit(1)`:
running production requires the Vault backend (or an enterprise
cloud-KMS plugin loaded out-of-tree). It additionally refuses an
empty `MCP_PROXY_DB_ENCRYPTION_KEY`, so even `local` mode in dev
will not silently fall back to an unencrypted key store.

A **separate** env var, `MCP_PROXY_SECRET_BACKEND`, governs how
short-lived agent credentials are encrypted (env vs Vault). The
production-mode startup validator also refuses
`MCP_PROXY_SECRET_BACKEND=env` in production.

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the KMS | Application points at an attacker-controlled Vault | The Vault URL is set at deploy time and pinned via the same trust store as the rest of the host's outbound TLS. AppRole auth + Vault token rotation are standard Vault hardening. | If the operator wires the wrong URL on day one, we cannot detect it. The dashboard validates connectivity but not authenticity beyond TLS. |
| Tampering with stored keys | Attacker rewrites the KV v2 entry | Vault KV v2 is versioned; tampering is detectable by reading the version history. Cloud KMS providers (out-of-tree enterprise plugins) keep the key inside the HSM-backed service; no read endpoint exists. | A Vault compromise is the customer's exposure; we do not defend against it from inside Mastio. |
| Repudiation of a KMS operation | Operator denies signing a CSR | KMS calls are audited inside Mastio (caller, target key path, operation type). Vault's own audit log provides the second source of truth. | Aligning the two logs requires effort; we provide the field names but not an out-of-the-box correlation tool. |
| Information disclosure of the org CA private key | A compromised Mastio host reads the key | With `local`: the key is in the Mastio database, wrapped in a Fernet envelope keyed by `MCP_PROXY_DB_ENCRYPTION_KEY`. A host compromise that also recovers the env-var passphrase reads the key. With `vault`: the host has only a short-TTL Vault token; the key material is held by Vault. | `local` mode is for development only; the production validator refuses it. The migration CLI (`mcp-proxy migrate-org-ca-to-vault`, `mcp_proxy/cli/`) moves an existing local-backed key into Vault. |
| DoS via KMS unavailability | Vault is down | Cert signing fails fast. The proxy `/readyz` reports the KMS status; cached certs continue to work until they expire. | Long Vault outages eventually expire all certs and disable agent enrollment. Operators should monitor Vault availability per the vendor's runbook. |
| Elevation of privilege via KMS misuse | Attacker requests signing of a CSR they did not generate | The KMS-side ACL allows only Mastio's role to call the signing verb; Mastio itself enforces that the CSR matches an authenticated admin request. The 4-eyes hook (`ACTION_PKI_ROTATE_CA`) can require a second admin's signoff per Org-CA rotation. | A compromised admin token bypasses Mastio's check (Vault still rate-limits and audits). 4-eyes is the recommended compensating control. |

### References

- ADR-031 (Vault as Org CA private key store)
- `mcp_proxy/kms/factory.py`, `mcp_proxy/kms/vault.py`,
  `mcp_proxy/kms/local.py`, `mcp_proxy/kms/pki_at_rest.py`
- `mcp_proxy/cli/` (`migrate-org-ca-to-vault`)
- `operate/vault-org-ca.md`

## Component: Cullis SDK (client-side)

### Data flow

The SDK runs in the agent's process and holds the agent's private
key on disk. It uses `from_identity_dir` to load the cert + key,
calls `login_via_proxy` to obtain a short-lived bearer + DPoP nonce,
and uses `_authed_request` to attach a DPoP proof to every
subsequent call. It re-logs in on 401 (token expiry,
`_relogin_callable`).

### STRIDE

| Threat | Detail | Mitigation | Residual |
|---|---|---|---|
| Spoofing of the SDK against a fake Mastio | Agent's DNS or HTTP proxy points at a hostile endpoint | The SDK verifies the Mastio server cert against the OS trust store (or an operator-supplied bundle via the `tls_ca` argument). For pinned deployments the operator can supply a pinned bundle on disk; the SDK does not phone home to fetch trust roots. | If the operator wires the wrong base URL on day one, the SDK has no out-of-band way to detect it. Use TLS pinning or your own DNS hygiene. |
| Tampering with the on-disk identity | Attacker rewrites the cert or key on the agent host | The SDK reads the files at load time and reports a clear error if the cert chain does not validate against the Org CA the bundle's PEMs identify. Mode 0600 on the files is operator hygiene. | A root-shell on the agent host wins; this is the same trust boundary as host OS compromise. The cert thumbprint pin server-side detects a swapped key on the next call. |
| Repudiation by the agent process | Agent claims its SDK never made a call | All authentication and call-site events ride the same per-request DPoP path as a curl client; the server-side audit chain is the source of truth. | Same residual as the proxy section: an audit-write failure does not block the call. |
| Information disclosure of the bearer token | Token logged to stdout by accident | The SDK's logger (`cullis_sdk/_logging.py`) does not emit the bearer or the DPoP nonce at INFO or below; debug-level traces redact `Authorization` and `DPoP` headers. | A misconfigured `httpx` debug logger added by the agent operator can re-introduce the leak. The SDK README documents the safe debug pattern. |
| DoS against the agent process | Mastio returns 401 in a tight loop | The SDK retries login at most once per 401 (`_relogin_callable`) and surfaces a typed exception on a second failure rather than busy-looping. | An agent that wraps the SDK in its own retry loop without backoff can still hammer the proxy; the per-agent rate limiter on the proxy side caps it. |
| Elevation of privilege | Agent code mutates SDK state to claim a higher role | The SDK never sends a role claim; the proxy looks up the registry. Anything the agent process believes about its own privileges is local. | An agent that lies to *itself* still gets only what the proxy authorises. |

### References

- `cullis_sdk/auth.py`, `cullis_sdk/client.py`, `cullis_sdk/dpop.py`
- `cullis_sdk/README.md`

## Cross-cutting threats

### Supply chain

Every released image and bundle ships with:

- A **cosign signature** generated by GitHub Actions OIDC keyless
  signing; the certificate identity is verifiable against the
  release workflow path on `cullis-security/cullis`.
- A **CycloneDX SBOM** generated by Syft, attached to the GitHub
  Release.
- A **Trivy scan** that gates HIGH/CRITICAL vulnerabilities with
  `ignore-unfixed=true`: vulnerabilities without an upstream fix are
  documented as residual rather than blocking the release. The base
  image typically carries a small number of HIGH unfixed CVEs that
  we list explicitly in each release's SBOM rather than blocking
  on.

Residual: customers who require a zero-unfixed posture should
rebuild from source with their own base image; the recipe is
documented in the bundle README.

### Insider threat

We treat the bundle operator as semi-trusted: they can deploy, take
backups, and rotate keys. They can also read the data bind mount and
the SQLite file. The defences against an insider with operator
credentials are:

- **Audit chain**: every state-changing action goes into the
  append-only log, which hash-chains under SHA-256. An insider who
  tampers with the log breaks the chain; the dashboard's
  **Verify chain** action and the standalone CLI catch it.
- **4-eyes approval hook**: at configurable depth, a set of
  state-changing actions requires a second admin's signoff before
  they take effect. The currently wired set is `policies.save`,
  `pki.rotate_ca`, `mastio_key.rotate`, `vault.migrate_keys`,
  `users.delete`, `agents.delete`, `agent.enroll`,
  `license.import`. Federation peer changes (`federation.peer`) are
  defined but not yet wired in this repository's open-core surface.
- **Append-only triggers**: the `local_audit` table has SQLite (and
  Postgres) triggers that raise on `UPDATE` / `DELETE`
  (`mcp_proxy/alembic/versions/0031_audit_append_only_v2.py`). Even
  admin DB access cannot rewrite history without dropping the
  triggers (an act that itself leaves an audit trail elsewhere).

Residual: a colluding pair of admins defeats 4-eyes. A single admin
with all roles has full control by design.

### Key lifecycle

| Key | Lifetime | Rotation | Compromise recovery |
|---|---|---|---|
| Per-agent keypair (SDK) | Per enrollment | Dashboard at `/proxy/agents/<id>` (`Rotate cert`) | Revoke + re-enroll the agent. Existing DPoP proofs are immediately rejected (cert thumbprint mismatch). |
| Org CA private key | Long-lived (years) | Dashboard `/proxy/pki/rotate-ca` (mint or operator-supplied) | Re-issues every agent cert. Plan a maintenance window unless every agent re-enrolls programmatically. |
| Dashboard admin secret | Long-lived | Rotate via env + restart | Re-issue all admin tokens. |
| KMS / Vault tokens | Per Vault policy (short TTL) | Automated by Vault | Vault revokes; Mastio retries with a fresh token. |
| Fernet master key for at-rest encryption | Long-lived | Operator-driven rotation + DB migration | Re-encrypt the `proxy_config` and `pki_key_store` rows under the new key. |

### Audit log integrity

- Append-only schema: triggers on `local_audit` (and the legacy
  `audit_log` table) reject `UPDATE` / `DELETE` on SQLite and
  Postgres alike (`mcp_proxy/alembic/versions/
  0031_audit_append_only_v2.py`).
- Each entry has an `entry_hash` (SHA-256 of canonical
  representation) and a `previous_hash` linking to the prior entry
  (`mcp_proxy/alembic/versions/0023_audit_hash_chain.py`,
  `mcp_proxy/audit_chain.py`). The DPoP `jkt` thumbprint is
  denormalised onto the row
  (`0033_audit_dpop_jkt.py`) so a forensic query does not have to
  re-derive trust state from a separate request log.
- Multi-worker safety: writes go through a bounded retry path
  (`mcp_proxy.db._AUDIT_CHAIN_MAX_RETRIES = 5`) that resolves
  `UNIQUE(chain_seq)` contention from concurrent uvicorn workers.
  Validated under sustained 4-worker writes (≈ 472k rows / 30 min,
  0 IntegrityError) in the 2026-05-18 stress run.
- Online verify: `POST /proxy/audit/verify` (dashboard) runs the
  same per-org chain check as the standalone CLI
  (`scripts/cullis-audit-verify.py`) and reports first-broken-seq +
  expected vs actual hash.

Residual: this repository does not ship a cross-org anchor. An
operator who needs an external append-only witness should pipe
audit exports into a SIEM or external timestamp service. The
**Cullis Audit Envelope** export format (per-org NDJSON with the
chain head + verify metadata) is the offline ship format; see
`operate/audit-export.md`.

## Residual risk summary

The threats this model does **not** mitigate:

- **Host compromise**: root on the Mastio host reads everything on
  the data bind mount. KMS (Vault) raises the bar for the Org CA
  key; everything else is in scope.
- **Compromised license signing key**: a single Cullis-side key
  custody failure affects every customer of that build. Annual
  rotation is the commitment; HSM-backed signing is a P2 item once
  funded.
- **Colluding admins**: 4-eyes assumes the two admins are not the
  same person and not colluding.
- **Upstream LLM provider behaviour**: Cullis is not a content
  classifier. Prompt-injection defence at the *upstream* is the
  upstream's responsibility.
- **Quantum-resistant cryptography**: not in scope yet. RSA-4096,
  ECDSA P-256, and RSA-OAEP-SHA256 are the current primitives.
- **Side-channels on bcrypt**: cost factor 12; we treat this as
  meeting OWASP 2024 guidance but not as eliminating offline
  attacks on a leaked hash.

## Open items (planned hardening)

| Item | Status | Tracking |
|---|---|---|
| Third-party penetration test (LoA) | Deferred until first paid engagement | Roadmap |
| HSM-backed license signing (YubiHSM2 / CloudHSM) | P2 | Roadmap |
| Reproducible builds + dep lockfile | P1 | Roadmap |
| Image CVE watcher scheduled job | P2 | Roadmap |
| Quantum-resistant primitives review | Not started | Tracking EU AI Act / DORA guidance |
| Public REST endpoint for cert rotation (`/registry/agents/{id}/rotate-cert`) | P2 | Today rotation is dashboard-driven |
| Configurable audit-fail-deny mode | P1 | Today: audit-write failure logs but does not block the call |
| Wire `ACTION_FEDERATION_PEER` approval hook | P2 | Constant defined in `approval_hook.py`; not yet referenced from a handler in this repo |
| HSM-backed Fernet master key for at-rest secret encryption | P2 | Today: env-supplied `MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`, or auto-generated and DB-stored |
| Per-tool PDP rate-limit knob enforcement | P2 | Field present in the scope model, not enforced from policy today |
| Dedicated JWT scrubber on the generic exception path | P3 | Today: HTTP responses for license errors are already minimal |
| DPoP JTI cache warm-from-persistent-store on restart | P3 | Today: cold-starts empty; first-window after restart has weaker replay protection |
| Strict Rego mode (`MCP_PROXY_POLICY_STRICT_REGO=true`) | P1 | Today: a runtime `RegoEvalError` falls through to the legacy allowlist with a warning log. Strict mode would fail-closed (deny) instead, which is the right posture for some pilots. |
| Per-eval Rego timeout | P2 | Today: only the compile path is timed out (10 s). A pathologically slow operator-authored Rego could block one async task per call. |
| Per-instance `OPAPolicy` lock for `asyncio.to_thread` migration | P3 | Today: the wasmtime store on top of each cached instance is not concurrent-native-safe, but FastAPI on the single-threaded asyncio loop never overlaps eval on the same instance. A future PR that moves eval onto a thread pool needs to add a per-instance lock. |
| WebAuthn binding on dashboard Rego Save | P2 | Today: admin cookie + CSRF guards the Save endpoint. ADR-033 Phase 2 will add a WebAuthn user-signed assertion on policy-changing calls. |

## References

- `SECURITY.md` (responsible disclosure, severity-tier SLA)
- `operate/runbook.md` (incident response)
- `operate/disaster-recovery.md` (backup + restore)
- `operate/rotate-keys.md` (agent cert + Org CA rotation)
- `operate/audit-export.md` (chain viewer + verify + offline export)
- `operate/vault-org-ca.md` (KMS migration to Vault)
