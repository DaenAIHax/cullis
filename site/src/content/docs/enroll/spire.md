---
title: "SPIRE enrollment"
description: "Enroll Cullis agents against short-lived SPIFFE SVIDs minted by SPIRE — the right choice when SPIRE is already your workload identity fabric."
category: "Enroll"
order: 30
updated: "2026-04-23"
---

# SPIRE enrollment

**Who this is for**: a platform engineer whose organization already runs SPIRE as the workload identity fabric, and who wants Cullis to trust the same SPIFFE identities the rest of the stack does. If you don't run SPIRE, use [Connector](connector-device-code) (laptops) or [BYOCA](byoca) (long-lived agents with an org CA) instead.

## When SPIRE is the right enrollment method

- SPIRE already issues SVIDs to your K8s workloads, and you want those same workloads to talk to Cullis as the identities SPIRE attested.
- Your agents live in short-lived containers (K8s pods, autoscaling workers) where rotating long-lived BYOCA certs is painful.
- You want automatic cert rotation (typical SVID TTL ~1h) without manual API calls to the Mastio.

Stay on [BYOCA](byoca) when agents are long-lived, externally issued, and the operators prefer manual rotation with certificate thumbprint pinning as a stronger anti-rogue-CA control.

## Threat model — read this before you deploy

Moving to SPIRE shifts what the Mastio enforces. Be deliberate:

- **The Org CA stops being the signing oracle.** It becomes an offline trust anchor. Your SPIRE server holds a short-lived intermediate signed by the Org CA; SVIDs mint under that intermediate. A compromised SPIRE server can mint SVIDs until the intermediate rotates or is revoked.
- **Thumbprint pinning is disabled** for SPIRE-enrolled agents. Pinning assumes cert stability across calls — SVIDs change every hour, so pinning would break auth. Identity is instead bound by chain walk + SPIFFE URI match, and ultimately by SPIRE's workload attestation (which Cullis delegates to).
- **Org CA `pathLenConstraint ≤ 1`.** The Mastio refuses to onboard an Org CA with `pathLen > 1` under a declared `trust_domain`. One intermediate only.
- **One `trust_domain` per `org_id`.** Two SPIRE clusters under the same logical org need two separate orgs on the Court.

If this trade-off isn't acceptable, don't enable SPIRE enrollment for that org — stay on BYOCA.

## Prerequisites

- An Org CA (your SPIFFE trust domain's root of trust). Keep the private key offline or in an HSM. Issue it with `BasicConstraints: CA=true, pathLen=1`.
- A SPIRE server configured with your Org CA as `UpstreamAuthority`. Any topology works — single server, HA pair, multi-region — as long as every SPIRE instance chains to the same Org CA.
- A Cullis Mastio deployed in your org
- A `trust_domain` chosen — conventionally reverse-DNS under your control (`acme.com`, `payments.acme.internal`). Must be unique across orgs on the Court.
- The Mastio admin secret (`$MASTIO_ADMIN_SECRET`)

## 1. Register the org with a `trust_domain`

Two flows, depending on whether your org is already on the Court.

### A. Fresh onboarding via invite token

The Court admin mints an invite:

```bash
curl -X POST https://court.example.com/v1/admin/invites \
    -H "X-Admin-Secret: $COURT_ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"label": "acme onboarding", "ttl_hours": 24}'
```

Your org redeems it with the trust domain declared:

```bash
curl -X POST https://court.example.com/v1/onboarding/join \
    -H "Content-Type: application/json" \
    -d '{
        "org_id": "acme",
        "display_name": "Acme Corp",
        "secret": "<long random>",
        "contact_email": "sec@acme.com",
        "ca_certificate": "-----BEGIN CERTIFICATE-----\n...Org CA PEM...",
        "invite_token": "<token>",
        "trust_domain": "acme.com"
    }'
```

The Court validates:

- `trust_domain` is syntactically valid and not already claimed
- Org CA has `CA=true` and key size ≥ 2048 RSA or a recognised EC curve
- Org CA `pathLenConstraint ≤ 1`

A 400 on pathLen means your CA was issued too permissively — re-issue it and retry. Don't request a Court-side waiver; it would widen the trust surface silently.

The org starts in `pending`. The Court admin approves it with `POST /v1/admin/orgs/{org_id}/approve`.

### B. `attach-ca` for a pre-provisioned org

If the Court admin already created your org (no CA yet) and issued an `attach-ca` invite:

```bash
curl -X POST https://court.example.com/v1/onboarding/attach \
    -H "Content-Type: application/json" \
    -d '{
        "ca_certificate": "...PEM...",
        "invite_token": "<attach-ca token>",
        "secret": "<long random>",
        "trust_domain": "acme.com"
    }'
```

Same pathLen rule applies.

## 2. Configure SPIRE

Set your Org CA as SPIRE's `UpstreamAuthority` (minimal example, adapt to your topology):

```hcl
UpstreamAuthority "disk" {
    plugin_data {
        cert_file_path = "/etc/spire/org-ca.pem"
        key_file_path  = "/etc/spire/org-ca-key.pem"
    }
}
```

Create a registration entry for each workload:

```bash
spire-server entry create \
    -spiffeID spiffe://acme.com/workload/sales-agent \
    -parentID spiffe://acme.com/spire/agent/x509pop/... \
    -selector unix:uid:1000
```

The SPIFFE ID's last path segment becomes the Cullis agent name. For the entry above, `agent_id = "acme::sales-agent"`.

## 3. Enroll the workload against the Mastio

Pull the SVID + trust bundle from the Workload API and POST to `/v1/admin/agents/enroll/spiffe`. The SDK wrapper:

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_spiffe(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",
    agent_name="sales-agent",
    svid_pem=open("svid.pem").read(),
    svid_key_pem=open("svid-key.pem").read(),
    trust_bundle_pem=open("spire-bundle.pem").read(),
    capabilities=["quote.read", "quote.write"],
    persist_to="/etc/cullis/agent/",
)
```

The SPIFFE URI SAN on the SVID is **mandatory** — without it the endpoint returns `400 svid_missing_spiffe_uri`. The URI pins as `spiffe_id` on the `internal_agents` row; SPIRE rotates the SVID, but the Cullis runtime credentials (API key + DPoP JWK) stay valid because runtime auth isn't the SVID — it's the pinned jkt.

### Trust bundle resolution

1. `body.trust_bundle_pem` (per-request override)
2. `proxy_config.spire_trust_bundle` on the Mastio (operator-configured baseline)
3. Neither → `503 spire_trust_bundle_not_configured`

### Via raw HTTP

Same semantics when you'd rather not pull the SDK:

```bash
curl -X POST https://mastio.acme.corp/v1/admin/agents/enroll/spiffe \
    -H "X-Admin-Secret: $MASTIO_ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{
        "agent_name": "sales-agent",
        "capabilities": ["quote.read", "quote.write"],
        "svid_pem": "-----BEGIN CERTIFICATE-----\n...",
        "svid_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
        "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\n...",
        "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}
    }'
```

See [Enrollment API reference](../reference/enrollment-api) for the full schema.

## 4. Runtime

Runtime auth is identical to every other enrollment method — API key + DPoP proof to the Mastio:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_api_key_file(
    mastio_url="https://mastio.acme.corp",
    api_key_path="/etc/cullis/agent/api-key",
    dpop_key_path="/etc/cullis/agent/dpop.jwk",
)

client.send_oneshot("globex::fulfillment-bot", {"order_id": "A123"})
```

SPIRE continues to rotate the SVID. When the SVID expires, the Cullis credentials don't — the Mastio doesn't re-verify the SVID on every call, only at enrollment. On the next Org CA rotation (or if you explicitly revoke), you'll re-run `enroll_via_spiffe` to pick up the new cert material.

## 5. Validate end-to-end

From the workload host:

```bash
spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock

python -c "
from cullis_sdk import CullisClient
c = CullisClient.from_api_key_file(
    mastio_url='https://mastio.acme.corp',
    api_key_path='/etc/cullis/agent/api-key',
    dpop_key_path='/etc/cullis/agent/dpop.jwk',
)
print('agent_id:', c.agent_id)
print('token_prefix:', c.get_token()[:24])
"
```

On the Court, check the audit:

```bash
curl -s "https://court.example.com/v1/admin/audit/export?org_id=acme&event_type=auth.token_issued" \
    -H "X-Admin-Secret: $COURT_ADMIN" \
    | jq -s 'last'
```

You should see `agent.id=acme::sales-agent` with chain length 2 in the span attributes (`auth.x509_chain_verify.chain.length`).

## Deprecated — direct-to-Court SPIFFE login

Cullis used to support `CullisClient.from_spiffe_workload_api(...)` — a one-shot call that pulled an SVID and minted a token straight from the Court. That path is **deprecated**. It still works and emits a `DeprecationWarning` + `Deprecation: true` + `Sunset` response headers until the Court's `/v1/auth/token` returns `410 Gone`. New deployments treat SPIRE as an *enrollment* primitive (section 3 above) and use `from_api_key_file(...)` at runtime.

If you have existing workloads on the direct-login path, see [Migration from direct login](../reference/migration-from-direct-login) for the zero-downtime move.

## Operational notes

### Mixed mode inside the same org

An agent either authenticates with a classic BYOCA cert (pinning on) or with an SVID (pinning off). Both can coexist under the same `org_id` — the Mastio discriminates per-cert, not per-org. The `trust_domain` on the org enables the SVID path; it doesn't disable BYOCA for agents that don't present SVIDs.

### Multiple proxies in the same trust domain

`N` Mastios can share a `trust_domain` as long as every SPIRE instance chains to the same Org CA. The Court accepts any SVID whose chain terminates at the registered Org CA, regardless of which intermediate signed it. HA, multi-region, site isolation — all work naturally.

### Name Constraints (recommended, not enforced)

If your CA supports it, issue the Org CA with a `nameConstraints` extension limiting acceptable SPIFFE URIs to your trust domain:

```
permittedSubtrees: URI:.acme.com
```

Cullis doesn't verify `nameConstraints` programmatically today, but OpenSSL / browsers do, and any third-party auditor will expect it. Defence-in-depth against SPIRE-side misconfiguration.

### Rotating the Org CA

Coordinated rotation:

1. Issue a new Org CA with `pathLen=1`
2. Configure SPIRE to use both old and new as `UpstreamAuthority` during the overlap
3. Register the new CA on the Court with `POST /v1/registry/orgs/{org_id}/certificate` (classic rotate — no invite consumed)
4. Once all workloads rotated SVIDs under the new intermediate, decommission the old CA

Workloads don't need to reconnect — SPIRE rotation + SDK re-auth covers the window within an SVID TTL.

### Revoking a single workload

- SPIRE-native: `spire-server entry delete <id>`. The workload loses its SVID within one rotation cycle.
- Cullis-native: `POST /v1/admin/certs/revoke` with the SVID's `serial_hex` for immediate effect at the Court. Useful if SPIRE rotation is slow or its signing material is compromised.

## Troubleshoot

| Symptom | Likely cause |
|---|---|
| `No organization registered for trust domain 'X'` | `trust_domain` not declared at `/onboarding/join`, or registered with a different value. Check `organizations.trust_domain` in the Court DB. |
| `CA pathLenConstraint is 2 — pathLen must be ≤ 1` | Org CA too permissive. Re-issue with `pathLen=1` and re-register via `attach-ca`. |
| `certificate chain broken at position 0` | `x5c` ordering wrong (must be leaf first, then intermediates; never the trust anchor) or SDK sending only the leaf. Confirm `len(x5c) >= 2`. |
| `Agent not found or org mismatch` | The `agent_id` derived from the SVID's last path segment isn't registered on the Court. Re-run step 3. |
| `certificate chain contains a duplicate entry` | Your SDK is appending the Org CA to `x5c`. Strip it — the trust anchor is implicit. |
| `svid_missing_spiffe_uri` | The SVID has no SPIFFE URI SAN. SPIRE workload attestation didn't bind a SPIFFE ID. Check the registration entry. |

## Next

- [BYOCA enrollment](byoca) — the alternative when SPIRE isn't part of your stack
- [Enrollment API reference](../reference/enrollment-api) — `POST /v1/admin/agents/enroll/spiffe` full schema
- [Migration from direct login](../reference/migration-from-direct-login) — moving legacy direct-to-Court deployments onto this enrollment path
- [Rotate keys § 3](../operate/rotate-keys#3-rotate-the-org-ca) — the Org CA rotation flow in detail

## References

- ADR-003 — SPIRE 3-level PKI for SPIRE-mode agents
- RFC 7515 §4.1.6 — `x5c` header semantics
- [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards)
- [SPIRE UpstreamAuthority](https://github.com/spiffe/spire/blob/main/doc/plugin_server_upstreamauthority_disk.md)
