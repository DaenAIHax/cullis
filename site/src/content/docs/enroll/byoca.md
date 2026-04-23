---
title: "BYOCA enrollment"
description: "Enroll programmatic agents using a cert signed by your organization's PKI — Vault, Sectigo, an internal CA, or a Helm-chart-generated CA. The Mastio verifies the chain, pre-flights the material, and issues runtime credentials."
category: "Enroll"
order: 20
updated: "2026-04-23"
---

# BYOCA enrollment

**Who this is for**: a platform engineer provisioning headless agents (CI/CD jobs, backend services, scheduled workflows) where the organization already runs an internal PKI. BYOCA — "bring your own CA" — lets you use the cert material your security team already manages instead of a Connector approval click.

If you're an end-user developer on a laptop, use the [Connector device-code flow](connector-device-code) instead. If your agents already hold a SPIRE SVID, use [SPIRE enrollment](spire).

## Prerequisites

- Your org's Org CA has been uploaded to the Mastio (either at first-boot wizard time or via `POST /proxy/pki/attach-ca`)
- The Mastio admin secret (`$MASTIO_ADMIN_SECRET`)
- A cert + private key for the agent, signed by the Org CA
- Python 3.10+ with `pip install cullis-sdk` — or any HTTP client if you'd rather script the endpoint directly

## The protocol, at a glance

1. **Pre-flight** — you hand the Mastio a cert + key. It:
   - Verifies the cert chains to the current Org CA
   - Checks the cert is not revoked and not expired
   - Confirms the key proves possession of the cert (test signature)
   - Extracts any SPIFFE URI in `SubjectAlternativeName` and pins it as `spiffe_id`
2. **Enroll** — on success the Mastio:
   - Inserts a row in `internal_agents` with `enrollment_method='byoca'`
   - Generates a DPoP-bound API key (`sk_local_...`)
   - Returns the plaintext API key **exactly once** — it's stored only as a bcrypt hash server-side
3. **Persist** — you write the API key, DPoP JWK, and `agent.json` somewhere the agent can read at runtime

Runtime auth is then identical to every other enrollment method: API key + DPoP proof, sent to the Mastio, never to the Court.

## 1. Enroll via the SDK

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_byoca(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",
    agent_name="inventory-bot",
    display_name="Inventory service",
    cert_pem=open("agent.pem").read(),
    private_key_pem=open("agent-key.pem").read(),
    capabilities=["inventory.read", "inventory.write"],
    persist_to="/etc/cullis/agent/",
)
```

Expected side effects:

```
/etc/cullis/agent/api-key         # 0600 — the plaintext API key
/etc/cullis/agent/dpop.jwk        # 0600 — private DPoP JWK (EC P-256)
/etc/cullis/agent/agent.json      # 0644 — {agent_id, org_id, mastio_url}
```

The SDK returns the `AgentEnrollResponse` object so you can read the API key into your own secret manager instead of persisting to disk. If `persist_to` is omitted, the SDK doesn't write anywhere — you own the storage.

### Capabilities

The `capabilities` list is the set of tool-call scopes the agent is allowed to request. The Mastio enforces capability checks at session open time; the Court enforces them at cross-org message send. Common scopes:

- `oneshot.message` — send A2A messages without opening a session (ADR-008)
- `session.open` — initiate stateful sessions with other agents
- `order.read`, `order.write`, `inventory.*` — domain-specific tool scopes

Agents get exactly the intersection of `capabilities` declared at enrollment and what the resource binding (`POST /v1/admin/mcp-resources/bindings`) allows.

### SPIFFE URI auto-pickup

If your cert carries a SPIFFE URI in `SubjectAlternativeName` (e.g. `spiffe://acme.corp/inventory-bot`), the Mastio:

1. Verifies the URI trust domain matches the org's configured trust domain
2. Pins the URI as `spiffe_id` on the `internal_agents` row
3. Uses it as the canonical sender id in audit events

This is transparent — nothing to configure on your side beyond issuing the cert with the right SAN.

## 2. Enroll via raw HTTP

Useful when the bootstrap runs in a language other than Python, inside a minimal container, or from a Helm hook. Same endpoint, same semantics.

```bash
curl -X POST https://mastio.acme.corp/v1/admin/agents/enroll/byoca \
    -H "X-Admin-Secret: $MASTIO_ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{
        "agent_name": "inventory-bot",
        "display_name": "Inventory service",
        "capabilities": ["inventory.read", "inventory.write"],
        "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
        "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}
    }'
```

Expected response (201):

```json
{
  "agent_id": "acme::inventory-bot",
  "api_key": "sk_local_9f4a2b1e3c5d7e8f...",
  "dpop_jkt": "3f:4a:9b:2b:1e:...",
  "enrolled_at": "2026-04-23T19:12:08Z",
  "mastio_url": "https://mastio.acme.corp"
}
```

The plaintext `api_key` is returned exactly once. The server stores only the bcrypt hash. Persist it to a `0600`-mode file or to your secret manager; the agent needs it to mint DPoP-bound tokens on subsequent calls.

See [Enrollment API reference](../reference/enrollment-api) for the full request/response schema.

## 3. Runtime

```python
from cullis_sdk import CullisClient

client = CullisClient.from_api_key_file(
    mastio_url="https://mastio.acme.corp",
    api_key_path="/etc/cullis/agent/api-key",
    dpop_key_path="/etc/cullis/agent/dpop.jwk",
)

client.send_oneshot("globex::fulfillment-bot", {"order_id": "A123"})
```

No cert on the wire at runtime. No direct call to the Court. The DPoP proof binds every request to the keypair the Mastio pinned during enrollment — stolen API keys alone can't impersonate the agent.

## 4. Re-enroll after Org CA rotation

An Org CA rotation ([Rotate keys § 3](../operate/rotate-keys#3-rotate-the-org-ca)) invalidates every agent's leaf cert. For BYOCA-enrolled agents, the Mastio can't auto-re-sign — the org holds the private keys. The re-enrollment flow:

1. Your CA issues a fresh cert for each agent (same subject, same keypair is fine)
2. Re-run `enroll_via_byoca` with the new `cert_pem`
3. Pass the same `agent_name` — the Mastio detects the existing row and updates the cert + chain in place rather than creating a duplicate
4. The `api_key` stays valid; only the cert thumbprint changes

A worked example automating this for all BYOCA agents under one org:

```python
from cullis_sdk import CullisClient

admin_secret = os.environ["MASTIO_ADMIN_SECRET"]
agents = CullisClient.list_agents(
    "https://mastio.acme.corp",
    admin_secret=admin_secret,
    enrollment_method="byoca",
)

for agent in agents:
    new_cert = issue_cert_from_vault(agent.agent_name)   # your CI step
    CullisClient.enroll_via_byoca(
        "https://mastio.acme.corp",
        admin_secret=admin_secret,
        agent_name=agent.agent_name,
        cert_pem=new_cert.cert_pem,
        private_key_pem=new_cert.private_key_pem,
        capabilities=agent.capabilities,
        update_existing=True,
    )
```

The `update_existing=True` flag is the contract: without it the Mastio refuses to overwrite an existing row to avoid accidental clobber.

## Troubleshoot

**`400 cert_not_signed_by_org_ca`**
: The cert's issuer chain doesn't terminate at the Org CA the Mastio has loaded. Confirm with `openssl verify -CAfile org-ca.pem agent.pem`. If you recently rotated the Org CA, make sure the Mastio loaded the new one (`/healthz` should show no `org_ca_legacy_pathlen_zero` warning).

**`400 key_does_not_match_cert`**
: The `private_key_pem` doesn't correspond to the `cert_pem`. Double-check with `openssl x509 -in agent.pem -noout -pubkey | openssl md5` vs. `openssl pkey -in agent-key.pem -pubout | openssl md5` — the two hashes must match.

**`403 admin_secret_invalid`**
: The `X-Admin-Secret` header is wrong or the Mastio admin secret was recently rotated. Pull the current value from your secret manager; the bcrypt hash in Vault is the authoritative source.

**`409 agent_already_enrolled`**
: A row with `agent_id=acme::inventory-bot` already exists. Pass `update_existing=True` (SDK) or `"update_existing": true` (raw HTTP) if you intended to re-enroll, or pick a different `agent_name`.

**`400 spiffe_uri_wrong_trust_domain`**
: Your cert's SPIFFE SAN points at a trust domain the Mastio doesn't trust (or the Mastio has no trust domain configured). Fix either the SAN or the Mastio's `CULLIS_TRUST_DOMAIN` env var. See the [SPIRE enrollment page](spire) for trust-bundle semantics.

## Next

- [Enrollment API reference](../reference/enrollment-api) — full request / response schemas
- [Rotate keys § 3](../operate/rotate-keys#3-rotate-the-org-ca) — when Org CA rotation forces BYOCA re-enrollment
- [SPIRE enrollment](spire) — if your agents already run under SPIRE
- [Migration from direct login](../reference/migration-from-direct-login) — if you have legacy agents on the direct-to-Court path
