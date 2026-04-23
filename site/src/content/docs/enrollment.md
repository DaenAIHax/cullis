---
title: "Agent enrollment — the three methods"
description: "Under ADR-011, enrollment and runtime auth are separate layers. Three ways to enroll, one runtime path (API-key + DPoP via the Mastio)."
category: "Identity"
order: 25
updated: "2026-04-22"
---

# Cullis — Agent enrollment

Under [ADR-011](../architecture) Cullis separates two concerns:

- **Enrollment** — a one-time handshake that turns whatever identity the agent already has (OIDC login via Connector, Org-CA cert, SVID) into a stable runtime credential.
- **Runtime auth** — the credential the agent presents on every subsequent call: an **API key + DPoP proof**, always sent to the agent's Mastio (never directly to the Court).

All three methods below are equivalent at the output layer — they persist the same runtime artifacts on disk (`api-key`, `dpop.jwk`, `agent.json`) and produce the same runtime client. The difference is only in how the Mastio verifies the caller during enrollment.

---

## Which method to pick

| Method | Pick it when | Trust anchor |
|---|---|---|
| `connector` | dev laptops, interactive onboarding | OIDC login via Connector Desktop, admin approves in the Mastio dashboard |
| `byoca` | programmatic agents, CI/CD, enterprise PKI already in place, air-gapped bootstrap | operator-held admin secret + Org-CA-signed cert |
| `spiffe` | K8s workloads under SPIRE | operator-held admin secret + SVID verified against the SPIRE trust bundle |

BYOCA and SPIFFE are **enrollment** primitives. Runtime auth via SPIFFE/BYOCA direct login to the Court is legacy and emits deprecation headers (see [Migration from direct login](migration-from-direct-login.md)).

> **"Admin token" is not a separate flow.** `X-Admin-Secret` is the header that BYOCA and SPIFFE use when called non-interactively (sandbox bootstrap, Helm hook, CI/CD). The SDK's `enroll_via_byoca` / `enroll_via_spiffe` classmethods send it for you; a raw `curl` or `httpx.post(...)` to the same endpoint works identically — see the BYOCA section below.

---

## Method 1 — connector (interactive, end-user)

The user runs the [Connector Desktop](https://cullis.io/downloads), authenticates via OIDC against their corporate IdP (Google, Okta, Azure AD), and the Mastio admin approves the pending enrollment from the dashboard. The Connector persists credentials under `~/.cullis/identity/<org>/`.

```bash
cullis-connector enroll --site https://mastio.acme.corp
# Device-code flow: Connector opens a browser for OIDC login.
# Admin sees a pending enrollment in the Mastio dashboard + clicks Approve.
# On success, credentials are written under ~/.cullis/identity/<org>/.
```

Internally the Connector calls `POST /v1/enrollment/start` and polls until the admin approves — no SDK primitive wraps this flow today. The SDK simply **loads** the persisted identity at runtime:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_connector()  # reads ~/.cullis/identity/<org>/
client.send_oneshot('acme::target-bot', {'hello': 'world'})
```

---

## Method 2 — BYOCA (cert + key)

The operator holds an Org-CA-signed cert + private key (typically exported from Vault, Sectigo, or an enterprise CA). The Mastio verifies the signature chain against its loaded Org CA and emits the runtime credentials.

### Via the SDK

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_byoca(
    'https://mastio.acme.corp',
    admin_secret='$MASTIO_ADMIN_SECRET',
    agent_name='inventory-bot',
    cert_pem=open('agent.pem').read(),
    private_key_pem=open('agent-key.pem').read(),
    capabilities=['inventory.read', 'inventory.write'],
    persist_to='/etc/cullis/agent/',
)
```

A SPIFFE URI in the cert's `SubjectAlternativeName` is picked up automatically and persisted as `spiffe_id` on the `internal_agents` row.

### Via raw HTTP (sandbox bootstrap, Helm hook, CI/CD)

Same endpoint, no SDK dependency — handy when the bootstrap runs in a language other than Python, or inside a minimal container:

```bash
curl -X POST https://mastio.acme.corp/v1/admin/agents/enroll/byoca \
  -H "X-Admin-Secret: $MASTIO_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "inventory-bot",
    "display_name": "Inventory bot",
    "capabilities": ["inventory.read", "inventory.write"],
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "dpop_jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  }'
# 201 → { "agent_id": "...", "api_key": "sk_local_...", "dpop_jkt": "...", ... }
# The plaintext api_key is returned exactly once. Persist it to disk
# and feed it to CullisClient.from_api_key_file on subsequent runs.
```

This is the pattern the Cullis sandbox uses in `sandbox/bootstrap/bootstrap_mastio.py` to onboard pre-minted agents without pulling the SDK.

---

## Method 3 — SPIFFE (SVID + trust bundle)

The operator has a workload running under SPIRE with an X.509-SVID. The Mastio verifies the SVID against the SPIRE trust bundle.

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_spiffe(
    'https://mastio.acme.corp',
    admin_secret='$MASTIO_ADMIN_SECRET',
    agent_name='k8s-inventory',
    svid_pem=open('svid.pem').read(),
    svid_key_pem=open('svid-key.pem').read(),
    trust_bundle_pem=open('spire-bundle.pem').read(),  # optional if set on the Mastio
    capabilities=['inventory.read'],
    persist_to='/etc/cullis/agent/',
)
```

The SPIFFE URI SAN on the SVID is **mandatory** for this method — without it the cert is not a valid SVID and the endpoint returns 400. The URI gets pinned as `spiffe_id`, the cert material lives under `cert_pem` (SPIRE rotates the SVID; the runtime credentials stay valid because auth is API-key + DPoP, not the SVID itself).

Trust bundle resolution:

1. `body.trust_bundle_pem` (per-request override)
2. `proxy_config.spire_trust_bundle` on the Mastio (operator-configured baseline)
3. Neither → 503

As with BYOCA, the SDK classmethod is just a wrapper around `POST /v1/admin/agents/enroll/spiffe` with `X-Admin-Secret` — same curl pattern works.

---

## Runtime — one path for every method

```python
from cullis_sdk import CullisClient

client = CullisClient.from_api_key_file(
    mastio_url='https://mastio.acme.corp',
    api_key_path='/etc/cullis/agent/api-key',
    dpop_key_path='/etc/cullis/agent/dpop.jwk',
)

# Cross-org A2A message (no session — ADR-008 one-shot envelope).
client.send_oneshot('globex::fulfillment-bot', {'order_id': 'A123'})
```

`from_connector()` is the equivalent constructor for Method 1 — same runtime API, reads `~/.cullis/identity/<org>/` instead of an explicit path.

No direct calls to the Court. No cert on the wire at runtime. DPoP proof binds every request to the keypair the Mastio pinned at enrollment time.

---

## Internals — what gets written where

| File | Owner | Contents | Permissions |
|---|---|---|---|
| `persist_to/api-key` | SDK / Connector | plaintext API key (shown once by server) | `0600` |
| `persist_to/dpop.jwk` | SDK / Connector | private DPoP JWK, EC P-256 | `0600` |
| `persist_to/agent.json` | SDK / Connector | `{agent_id, org_id, mastio_url}` | `0644` |

On the Mastio side the row in `internal_agents` carries `enrollment_method`, `spiffe_id` (nullable), `enrolled_at`, and `dpop_jkt` (the thumbprint the server compares each proof against).

---

## See also

- [Endpoint reference](enrollment-api-reference.md) — request / response schemas for each endpoint
- [Migration from direct login](migration-from-direct-login.md) — moving existing SPIFFE/BYOCA deployments off `/v1/auth/token`
- [SPIFFE onboarding](spiffe-onboarding.md) — deploying SPIRE alongside Cullis
