---
title: "Python SDK quickstart"
description: "From `pip install cullis-sdk` to a Mastio-authenticated agent. Provision once, run forever — copy-paste runnable."
category: "Quickstart"
order: 30
updated: "2026-05-22"
---

# Python SDK quickstart

**Scope of this page**: enrollment + transport-layer authentication. LLM completions and MCP tool calls (`client.chat_completion`, `client.call_mcp_tool`) are documented on their own pages — this one gets you to the point where those calls work.

**Python only.** TypeScript / Go / Java SDKs are not available publicly.

**Who this is for**: a Python developer writing an agent that authenticates to a Cullis Mastio (org gateway) and makes LLM completions + MCP tool calls through it.

The flow is two phases that happen at different times by different people:

1. **Provisioning** (one-time, operator). Mastio mints or accepts a cert+key+DPoP key for the agent. Files end up on disk. **If someone in your team already handed you the three files, skip to step 3.**
2. **Runtime** (every agent start, agent itself). Agent reads those files and authenticates to Mastio via mTLS.

> **Need a Mastio to talk to?** A single-host Docker bundle gives you `https://localhost:9443` in two commands — see [Install Mastio on Docker](../install/mastio-bundle). The rest of this page uses `https://mastio.acme.corp` as a placeholder; substitute the host you actually reach.

> **Known issue, current release**: `client.chat_completion()` has a DPoP pinning bug that surfaces as a 401 with no auto-retry. Workaround in the reference agents is a direct `httpx.Client(cert=...)` call against `POST /v1/llm/chat` — `agent_kyc_screener/main_stack.py` lines 162–176 in the demo stack shows the pattern. mTLS still applies, only the SDK helper path is broken. Tracked, fix on the roadmap.

## 1. Install

```bash
pip install cullis-sdk
```

Python 3.10+. No required system dependencies. Linux, macOS, Windows supported.

Pin to a released minor in your `pyproject.toml` so a breaking minor bump doesn't surprise a future-you:

```toml
cullis-sdk = ">=0.1,<0.2"
```

For SPIRE/SPIFFE workload-API integration (only if you provision via SPIRE — section 2c), install the extra:

```bash
pip install 'cullis-sdk[spiffe]'
```

## 2. Provision an identity (one-time, operator)

The agent's runtime identity is **three files**:

- `cert.pem` — x509 client cert, with SAN like `spiffe://acme.corp/orga/<agent-name>`
- `agent-key.pem` — private key matching the cert
- `dpop.jwk` — EC P-256 private key bound to the cert thumbprint (DPoP, [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — a JWT that proves the request comes from the holder of the matching private key, not just a token bearer)

**A note on agent IDs.** Cullis identifies agents as `<org-id>::<agent-name>` (e.g. `orga::kyc-screener`). When you call the **raw HTTP admin API** you pass the full `agent_id`. When you call the **SDK** you pass only `agent_name` — the SDK derives the org from the admin token and prepends it. The two paths show both styles below.

Pick one of the three provisioning paths depending on whether your org already has a PKI.

### a. Mastio mints the cert (no existing PKI)

If your org doesn't have a Certificate Authority yet, let Mastio mint everything from its org-scoped CA. Run this once from an operator script:

```bash
# One-off, from your operator workstation or a CI/CD provisioning step
curl -X POST https://mastio.acme.corp/v1/admin/agents/create \
  -H "X-Admin-Secret: $MASTIO_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
        "agent_id": "orga::kyc-screener",
        "display_name": "KYC Screener",
        "capabilities": ["kyc.read", "kyc.submit"]
      }' \
  > kyc-screener.json

# The response carries cert_pem + key_pem + dpop_jwk. Persist to disk:
jq -r .cert_pem  kyc-screener.json > /etc/cullis/agents/kyc/cert.pem
jq -r .key_pem   kyc-screener.json > /etc/cullis/agents/kyc/agent-key.pem
jq -r .dpop_jwk  kyc-screener.json > /etc/cullis/agents/kyc/dpop.jwk
chmod 0600 /etc/cullis/agents/kyc/*
```

Mastio pins the cert thumbprint in its DB. From this moment any TLS handshake presenting that exact cert authenticates as `orga::kyc-screener`.

### b. BYOCA — your org has a PKI (recommended for banks)

Your organisation already runs a CA (HashiCorp Vault, AD CS, EJBCA, AWS Private CA, whatever). The agent has a cert + private key signed by it. You hand both to Mastio once; Mastio verifies the chain and pins the thumbprint.

```python
import os
from pathlib import Path
from cullis_sdk import CullisClient

# Operator-side script, run once per agent at provisioning time
with open("/path/to/agent.pem") as f:
    cert_pem = f.read()
with open("/path/to/agent-key.pem") as f:
    private_key_pem = f.read()

CullisClient.enroll_via_byoca(
    "https://mastio.acme.corp",
    admin_secret=os.environ["MASTIO_ADMIN_SECRET"],   # ← admin privilege
    agent_name="kyc-screener",                         # org prefix auto-prepended
    display_name="KYC Screener",
    cert_pem=cert_pem,
    private_key_pem=private_key_pem,
    capabilities=["kyc.read", "kyc.submit"],
    persist_to="/etc/cullis/agents/kyc/",              # writes cert.pem + agent-key.pem + dpop.jwk
)
```

Mastio verifies the chain against the Org CA you previously attached (see [BYOCA enrollment](../enroll/byoca)), pins the thumbprint, mints a DPoP key, persists the three files at `persist_to` using the same filenames the runtime constructor expects.

→ Full chain rules + CA attach flow: [BYOCA enrollment](../enroll/byoca).

### c. SPIRE — workload identity from a SPIRE agent

Your agent runs in a SPIRE-attested environment (Kubernetes with SPIRE installed). The SPIRE workload API hands the agent an SVID; the SDK exchanges it for cert+key pinned in Mastio.

```python
import os
from cullis_sdk import CullisClient

CullisClient.enroll_via_spiffe(
    "https://mastio.acme.corp",
    admin_secret=os.environ["MASTIO_ADMIN_SECRET"],
    agent_name="kyc-screener",                         # org prefix auto-prepended
    persist_to="/var/lib/cullis/agents/kyc/",          # writes cert.pem + agent-key.pem + dpop.jwk
)
```

→ Full SPIRE flow: [SPIRE enrollment](../enroll/spire).

## 3. Runtime — load identity + authenticate (every agent start)

Once the three files are on disk, the agent's entrypoint is the same regardless of how you provisioned them:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_identity_dir(
    mastio_url="https://mastio.acme.corp",
    cert_path="/etc/cullis/agents/kyc/cert.pem",
    key_path="/etc/cullis/agents/kyc/agent-key.pem",
    dpop_key_path="/etc/cullis/agents/kyc/dpop.jwk",
    ca_chain_path="/etc/cullis/ca/orga-ca.pem",   # to verify Mastio's TLS cert
)
client.login_via_proxy_with_local_key()
```

**Where does `ca_chain_path` come from?** It's the Org CA cert that signs Mastio's own TLS cert. Operators export it from the Mastio dashboard (PKI → Export CA Certificate) or fetch it from the bundle's `nginx-certs/org-ca.crt`. Distribute it alongside the three identity files. If you set `verify_tls=False` you don't need it, but that's for local dogfood only.

**Two-line mental model**:

- `from_identity_dir(...)` is **pure local**: opens 3 files, builds an httpx client. **No network call.** If this fails, your error is a `FileNotFoundError` or bad PEM format.
- `login_via_proxy_with_local_key()` is the **first network call**. mTLS handshake + DPoP challenge + token issue. If this fails, your error is a TLS / 401 / connection error pointing at the Mastio.

**Verify it works**: if `login_via_proxy_with_local_key()` returns without raising, you are authenticated. The SDK has cached a short-lived token bound to your cert + DPoP key, and will auto-attach it to every subsequent call. There is no explicit `.ping()` to run — a successful login is the green light.

### What happens under the hood

1. The SDK opens a TLS handshake to Mastio **presenting the agent cert as a client cert** (mTLS, [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) — the TLS-layer counterpart to OAuth client authentication).
2. Mastio compares the cert's SHA-256 thumbprint against the one pinned at provisioning. Mismatch → 401.
3. The DPoP key signs subsequent egress requests, binding the token to the keypair. Mastio rejects replays from other clients.
4. From here on `client` has an authenticated session. No admin secret in scope, no enrollment call at startup.

`from_identity_dir` is the only runtime constructor you need. Production agents that load credentials from Vault, K8s secrets, HSMs, or any other secret store use this same call once the material has been read into the three file paths.

## What's next

- [BYOCA enrollment](../enroll/byoca) — full cert chain rules and CA attach flow
- [SPIRE enrollment](../enroll/spire) — workload API integration in detail
- [Configuration](../reference/configuration) — every `CULLIS_*` env var the SDK reads
- [Enrollment API reference](../reference/enrollment-api) — raw HTTP if you'd rather not use the SDK
- [Mastio on Docker](../install/mastio-bundle) — stand up a local Mastio at `https://localhost:9443` in two commands

The SDK exposes `cullis_sdk.__version__` if you need to assert the running version in your own diagnostics.
