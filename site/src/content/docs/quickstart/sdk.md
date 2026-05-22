---
title: "Python SDK quickstart"
description: "From `pip install cullis-sdk` to a Mastio-authenticated agent. Provision once, run forever — copy-paste runnable."
category: "Quickstart"
order: 30
updated: "2026-05-22"
---

# Python SDK quickstart

**Who this is for**: a Python developer writing an agent that authenticates to a Cullis Mastio (org gateway) and makes LLM completions + MCP tool calls through it.

The flow is two phases that happen at different times by different people:

1. **Provisioning** (one-time, operator). Mastio mints or accepts a cert+key+DPoP key for the agent. Files end up on disk.
2. **Runtime** (every agent start, agent itself). Agent reads those files and authenticates to Mastio via mTLS.

This page shows both phases. The runtime block (step 3) is the same regardless of how you provisioned.

## 1. Install

```bash
pip install cullis-sdk
```

Python 3.10+. No required system dependencies. Linux, macOS, Windows supported.

For SPIRE/SPIFFE workload-API integration (only if you provision via SPIRE — section 2b), install the extra:

```bash
pip install 'cullis-sdk[spiffe]'
```

## 2. Provision an identity (one-time, operator)

The agent's runtime identity is **three files**:

- `cert.pem` — x509 client cert, with SAN like `spiffe://acme.corp/orga/<agent-name>`
- `agent-key.pem` — private key matching the cert
- `dpop.jwk` — EC private key bound to the cert for replay protection (DPoP, RFC 9449)

Pick one of the two provisioning paths depending on whether your org already has a PKI.

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
# Operator-side script, run once per agent at provisioning time
from cullis_sdk import CullisClient

CullisClient.enroll_via_byoca(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",   # ← admin privilege
    agent_name="kyc-screener",
    display_name="KYC Screener",
    cert_pem=open("/path/to/agent.pem").read(),
    private_key_pem=open("/path/to/agent-key.pem").read(),
    capabilities=["kyc.read", "kyc.submit"],
    persist_to="/etc/cullis/agents/kyc/",   # writes cert.pem + key.pem + dpop.jwk
)
```

Mastio verifies the chain against the Org CA you previously attached (see [BYOCA enrollment](../enroll/byoca)), pins the thumbprint, mints a DPoP key, persists the three files at `persist_to`.

→ Full chain rules + CA attach flow: [BYOCA enrollment](../enroll/byoca).

### c. SPIRE — workload identity from a SPIRE agent

Your agent runs in a SPIRE-attested environment (Kubernetes with SPIRE installed). The SPIRE workload API hands the agent an SVID; the SDK exchanges it for cert+key pinned in Mastio.

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_spiffe(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",
    agent_name="kyc-screener",
    persist_to="/var/lib/cullis/agents/kyc/",
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

What happens under the hood:

1. The SDK opens a TLS handshake to Mastio **presenting the agent cert as a client cert** (mTLS, RFC 8705).
2. Mastio compares the cert's SHA-256 thumbprint against the one pinned at provisioning. Mismatch → 401.
3. The DPoP key signs subsequent egress requests, binding the token to the keypair (RFC 9449). Mastio rejects replays from other clients.
4. From here on `client` has an authenticated session. No admin secret in scope, no enrollment call at startup.

`from_identity_dir` is the only runtime constructor you need. Production agents that load credentials from Vault, K8s secrets, HSMs, or any other secret store use this same call once the material has been read.

## What's next

- [BYOCA enrollment](../enroll/byoca) — full cert chain rules and CA attach flow
- [SPIRE enrollment](../enroll/spire) — workload API integration in detail
- [Configuration](../reference/configuration) — every `CULLIS_*` env var the SDK reads
- [Enrollment API reference](../reference/enrollment-api) — raw HTTP if you'd rather not use the SDK

If anything in here breaks against the version on your machine, the SDK exposes `cullis_sdk.__version__` — pin to a released minor in your project's `pyproject.toml` (`cullis-sdk>=0.1,<0.2`) so a future-you doesn't get surprised by a breaking minor bump.
