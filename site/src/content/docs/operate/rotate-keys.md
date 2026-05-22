---
title: "Rotate keys"
description: "Rotate the Org CA root key, re-issue a single agent's cert, and remediate a legacy Org CA shape — what the Mastio does under the hood and how to recover from a mid-rotation issue."
category: "Operate"
order: 20
updated: "2026-05-22"
---

# Rotate keys

**Who this is for**: a Mastio operator rotating the Org CA (rare — invalidates every enrolled agent) or rotating a single agent's cert (routine, on compromise or for scheduled hygiene). Both flows run from the dashboard or one API call.

## Prerequisites

- Mastio admin secret loaded in your password manager
- `curl` on a host that can reach the Mastio public URL
- For the Org CA rotation: a maintenance window or a programmatic re-enrollment pipeline for every agent

## What rotates, and when

| Key | Frequency | Pattern |
|---|---|---|
| **Agent cert** | On compromise, host change, scheduled hygiene (annual) | Single API call. Cheap, no other agent affected. |
| **Org CA** (P-256 root) | CA compromise, compliance-mandated rotation, remediate a legacy pathLen=0 shape | Re-issues every agent cert. Maintenance window. |

## 1. Rotate an agent cert

The Mastio pins a SHA-256 thumbprint of each agent's cert at enrollment time. Rotating the cert keeps the agent's identity (same `agent_id`, same capabilities, same audit chain) but swaps the cert+key material. Most common reason: the agent's private key may have leaked, or the host the agent runs on is being decommissioned.

### From the dashboard

1. Open `https://mastio.example.com/proxy/agents/<agent_id>`.
2. Click **Rotate cert**.
3. The Mastio mints a fresh cert+key under the current Org CA and pins the new thumbprint. The old thumbprint is removed immediately.

The dashboard offers the new PEMs as a one-time download. Save them to the agent's identity dir and restart the agent.

### From the API

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
MASTIO="https://localhost:9443"
AGENT_ID="orga::kyc-screener"

curl -sk -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
     "$MASTIO/registry/agents/$AGENT_ID/rotate-cert" \
     > rotated-cert.json

jq -r .cert_pem rotated-cert.json > cert.pem
jq -r .key_pem  rotated-cert.json > agent-key.pem
chmod 0600 cert.pem agent-key.pem
```

The response shape mirrors the original enrollment response (`cert_pem`, `key_pem`, `dpop_jwk`). Deploy the new material to the agent's identity dir (`/etc/cullis/agents/<name>/`) and restart the agent process; the SDK picks up the new files on next start.

### What to verify

- `curl ... /v1/auth/token` with the **old** cert → 401 `Certificate has been revoked`
- `curl ... /v1/auth/token` with the **new** cert → 200
- Audit log entry `agent.cert_rotated` recorded for `$AGENT_ID` (see [Audit export](audit-export))

## 2. Rotate the Org CA

Rotating the Org CA re-issues every agent's cert. Plan for a maintenance window unless you have a programmatic re-enrollment pipeline (BYOCA callers regenerating from CI/CD, SPIRE agents whose SVID rotates automatically).

### Before you start

- **Announce the window** to every agent operator in your org
- **Take a backup** of the Mastio (see [Disaster recovery](disaster-recovery))
- **Stage the new CA material** if you're providing your own (PEM + key), or let the Mastio mint a fresh CA in place

### Flow

1. Open `https://mastio.example.com/proxy/pki/rotate-ca` in the dashboard.
2. Choose one of:
   - **Mastio-minted**: Mastio generates a new P-256 root and replaces the current Org CA atomically.
   - **Operator-supplied**: paste or upload your new CA cert + key. The Mastio refuses material that doesn't chain cleanly or reuses the previous key.
3. Confirm the pre-flight check (the form shows the new CA's fingerprint, expiry, and subject before commit).
4. On commit, the Mastio updates the Org CA, invalidates every pinned thumbprint, and emits an `org_ca.rotated` audit event.

### After

Every agent under this Mastio re-enrolls on its next session:

- **Mastio-minted enrollments**: re-run the per-agent enrollment (dashboard or `POST /registry/agents/<id>/rotate-cert` if the agent record persists).
- **BYOCA callers**: re-issue agent certs under the new Org CA from your PKI, then call `CullisClient.enroll_via_byoca(...)` to re-pin the thumbprint.
- **SPIRE callers**: the next SVID rotation handles it automatically (provided the SPIRE registration entry maps to the new CA).

See [BYOCA enrollment](../enroll/byoca) for the re-enrollment mechanics.

### API equivalent

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
MASTIO="https://localhost:9443"

# Mastio-minted (the typical path)
curl -sk -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
     "$MASTIO/pki/rotate-ca?mode=mint"

# Operator-supplied
curl -sk -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
     -F "ca_cert=@new-org-ca.pem" \
     -F "ca_key=@new-org-ca-key.pem" \
     "$MASTIO/pki/rotate-ca?mode=upload"
```

### What to verify

- `curl ... /healthz` no longer carries the `org_ca_legacy_pathlen_zero` warning (if you were remediating one — see section 3)
- The dashboard's PKI page shows the new fingerprint as active, the previous CA marked as `superseded`
- One agent end-to-end (re-enroll + mint a token + make a call) succeeds against the new chain

## 3. Remediate a legacy Org CA (pathLen=0)

Mastios bootstrapped before Cullis v0.1 issued an Org CA with `BasicConstraints(pathLen=0)`, which blocks the three-tier chain verified by external OpenSSL / Go crypto/x509 / webpki libraries. The Mastio itself runs fine internally; downstream consumers that pull the chain (compliance auditors, external verifiers) reject it.

### Detect

```bash
curl -sk https://localhost:9443/healthz | jq '.warnings // []'
# []                                       on a clean Mastio
# ["org_ca_legacy_pathlen_zero"]           on a legacy one
```

The `cullis_proxy_legacy_ca_pathlen_zero` Prometheus gauge mirrors this.

### Remediate

Rotate the Org CA as in section 2 above (Mastio-minted mode). The new CA emits the correct `pathLen=1` shape and the warning disappears on next boot.

### Optional: fail fast on legacy PKI

Set `MCP_PROXY_STRICT_PKI=1` in `proxy.env` to refuse boot on a legacy shape. Useful for hardening environments where you want the rotation enforced today. The default is OFF until Cullis ships the framework-update auto-migrator (see [Apply updates](apply-updates)).

```bash
echo 'MCP_PROXY_STRICT_PKI=1' >> proxy.env
./deploy.sh --pull
# Logs: "MCP_PROXY_STRICT_PKI=1 refuses boot on legacy Org CA. Run POST /pki/rotate-ca."
```

## Troubleshoot

**Agents fail with 401 immediately after Org CA rotation**
: Expected. Every pinned thumbprint is invalidated by the rotation. Re-enroll the affected agents under the new CA (see section 2, "After").

**`POST /pki/rotate-ca` returns 409**
: Another rotation is in progress or the Mastio is mid-bootstrap. Wait 30 seconds, retry. If it persists, check `docker compose -p cullis-mastio logs mcp-proxy | grep pki.rotate` for the underlying error.

**`/healthz` returns `warnings: ["org_ca_legacy_pathlen_zero"]` after a rotation**
: The rotation didn't commit. Re-open the dashboard PKI page and verify the new fingerprint is active. If the warning persists, the previous CA was restored from a backup — re-run the rotation.

**Dashboard shows two "active" CAs**
: Only the row marked as `current` is used for signing new agent certs. The previous CA is retained as `superseded` for verification purposes (an agent whose cert was signed by it can still verify until that cert expires or is rotated). The UI label is about DB rows, not active signing.

## Next

- [Disaster recovery](disaster-recovery) — take a backup before any rotation
- [Apply updates](apply-updates) — framework updates that may force a rotation
- [Audit export](audit-export) — prove rotation events to auditors with the hash chain
- [Vault as Org CA private key store](vault-org-ca) — move the Org CA root key out of the local DB and into Vault
