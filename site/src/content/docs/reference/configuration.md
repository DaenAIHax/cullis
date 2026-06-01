---
title: "Configuration reference"
description: "Every environment variable the Mastio reads at boot — defaults, formats, and which ones you must set in production."
category: "Reference"
order: 30
updated: "2026-05-23"
---

# Configuration reference

**Who this is for**: an operator writing `proxy.env`, `.env`, or Helm `values.yaml` and needing the authoritative answer on what each variable does. Variables are grouped by the subsystem that reads them.

Conventions:

- `MCP_PROXY_*` — read by the Mastio (the org gateway, FastAPI app under `mcp_proxy/`)
- `CULLIS_*` — read by the SDK (`cullis_sdk`) and, for a few shared fields, the Mastio

Required variables in bold. Safe defaults mean "OK for sandbox / eval"; production-grade defaults are called out where they differ.

## Mastio

### Core identity

| Variable | Default | Purpose |
|---|---|---|
| **`MCP_PROXY_ORG_ID`** | *(derived at first boot)* | The org slug this Mastio represents. Lowercase, no whitespace. The first-boot wizard derives it from the admin's email domain if you do not set it explicitly. |
| **`MCP_PROXY_PROXY_PUBLIC_URL`** | *(none)* | The URL clients use to reach the Mastio. DPoP `htu` is derived from this — a mismatch with the caller's URL returns 401. Include scheme and port. |

### Admin + dashboard

| Variable | Default | Purpose |
|---|---|---|
| **`MCP_PROXY_ADMIN_SECRET`** | *(none)* | The Mastio's admin secret. First-boot wizard bcrypts it into the secret backend; the value in the env is only consulted when the bcrypt hash is empty. |
| **`MCP_PROXY_DASHBOARD_SIGNING_KEY`** | *(none)* | HMAC key used to sign dashboard session cookies. Any 32+ bytes of entropy. Rotate to invalidate all sessions. |
| `MCP_PROXY_ALLOWED_ORIGINS` | `*` (dev) | Comma-separated origins allowed by the dashboard's CORS. **Set explicit origins in production.** |
| `MCP_PROXY_FORCE_LOCAL_PASSWORD` | `false` | Hardening: `true` disables OIDC dashboard login and forces local-password only. |
| `MCP_PROXY_LOCAL_AUTH_ENABLED` | `true` | Inverse of the toggle above, retained for clarity. |

### Persistence

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_DATABASE_URL` | `sqlite+aiosqlite:////data/mcp_proxy.db` | Async SQLAlchemy URL. Use `postgresql+asyncpg://...` in production. |
| `MCP_PROXY_REDIS_URL` | `redis://redis:6379/0` | DPoP JTI store + cross-worker pub/sub. Ephemeral — no backup needed. |

### Secrets backend

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_SECRET_BACKEND` | `file` | `file` (local PEMs in `/certs`) or `vault` (HashiCorp Vault KV v2). |
| `MCP_PROXY_VAULT_ADDR` | *(none)* | Vault address. HTTPS in production. |
| `MCP_PROXY_VAULT_TOKEN` | *(none)* | Vault token with access to the Mastio's KV path. Scope with a tight policy; rotate annually. |
| `MCP_PROXY_VAULT_CA_CERT_PATH` | *(none)* | Path to the CA cert trusted for Vault's TLS. Leave empty to use the system trust store. |
| `MCP_PROXY_VAULT_VERIFY_TLS` | `true` | Set to `false` **only** for dev Vault on HTTP. |

### PKI + auth

| Variable | Default | Purpose |
|---|---|---|
| `MCP_PROXY_STRICT_PKI` | `false` | `true` refuses to boot on a legacy Org CA with `pathLen=0`. See [Apply updates § Remediate a legacy Org CA](../operate/apply-updates#worked-example--org-ca-pathlen0). |
| `MCP_PROXY_EGRESS_DPOP_MODE` | `optional` | `off` / `optional` / `required`. Whether the Mastio requires an RFC 9449 DPoP key-possession proof (bound to the agent's registered `dpop_jkt`) on `/v1/egress/*`. `required` refuses cert-only requests with `401`; set it for zero-trust / regulated deploys. |
| `MCP_PROXY_PDP_URL` | *(none)* | Policy Decision Point webhook. Set to wire an external OPA / custom PDP. |
| `CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS` | `300` | Minimum seconds between consecutive signing-key rotations. Rate-limits accidental back-to-back rotates. |

## SDK

| Variable | Default | Purpose |
|---|---|---|
| `CULLIS_PROXY_URL` | *(none)* | Default Mastio URL when `CullisClient.from_identity_dir(...)` is called without `mastio_url`. |
| `CULLIS_ORG_ID` | *(none)* | Default org slug for SDK constructors. |
| `CULLIS_AGENT_ID` | *(none)* | Default agent id. |
| `CULLIS_EXTENSION_URI` | `cullis-trust/v1` | A2A extension URI the SDK advertises. Override only when interop-testing against a non-default registry. |

## Environment templates

Start from `.env.example` at the repo root and `packaging/mastio-bundle/proxy.env.example`. Both carry the complete variable list with commentary; this page is the authoritative definition when the two drift.

For a minimal production Mastio `.env`:

```bash
# Identity
MCP_PROXY_ORG_ID=acme
MCP_PROXY_PROXY_PUBLIC_URL=https://mastio.acme.com

# Admin
MCP_PROXY_ADMIN_SECRET=<32+ bytes of entropy>
MCP_PROXY_DASHBOARD_SIGNING_KEY=<32+ bytes of entropy>
MCP_PROXY_ALLOWED_ORIGINS=https://mastio.acme.com

# Persistence
MCP_PROXY_DATABASE_URL=postgresql+asyncpg://cullis:@postgres:5432/cullis
MCP_PROXY_REDIS_URL=redis://redis:6379/0

# Secrets
MCP_PROXY_SECRET_BACKEND=vault
MCP_PROXY_VAULT_ADDR=https://vault.acme.internal:8200
MCP_PROXY_VAULT_TOKEN=<scoped token>
```

## Next

- [Mastio bundle](../install/mastio-bundle) — step-by-step `docker compose` deploy with a production `.env`
- [Mastio on Kubernetes](../install/mastio-kubernetes) — Helm `values.yaml` equivalents
- [Rotate keys](../operate/rotate-keys) — which variables participate in key rotation
