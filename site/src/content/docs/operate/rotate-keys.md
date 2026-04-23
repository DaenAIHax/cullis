---
title: "Rotate keys"
description: "Rotate the Mastio signing key without downtime, recover from a mid-rotation crash, and remediate a legacy Org CA."
category: "Operate"
order: 20
updated: "2026-04-23"
---

# Rotate keys

**Who this is for**: a Mastio operator rotating the Mastio signing key (routine) or the Org CA (rare — invalidates every enrolled agent). Both flows run from the dashboard or one API call; this page shows what happens under the hood and how to recover if a rotation lands mid-crash.

## Prerequisites

- Mastio admin secret loaded in your password manager
- `docker compose` access to the Mastio host (only for recovery)
- `curl` on the host you run the API calls from

## What rotates, and when

| Key | Owner | Rotate because | Pattern |
|---|---|---|---|
| Mastio signing key (P-256) | Each Mastio | Scheduled annual rotation or compromise suspicion | Stage-before-propagate (see below) |
| Org CA (P-256 root) | Org admin | CA compromise, compliance-mandated rotation, remediate a legacy shape | Destructive — re-enrolls every agent |
| Court signing key | Network operator | Compromise | Out of scope for the Mastio operator |

## 1. Rotate the Mastio signing key

The Mastio signs the `X-Cullis-Mastio-Signature` header the Court pins at onboarding (ADR-009). Rotating this key is safe and reversible when nothing crashes; the code takes four steps atomically:

1. Generate a new P-256 keypair in memory.
2. Insert it in the `mastio_keys` table with `activated_at IS NULL` — **staged** but invisible to the active-signer query.
3. Propagate the new public key + a proof-of-possession signature to the Court (or to the federation publisher in air-gapped mode).
4. Activate the staged row and deprecate the previous active row in a single transaction (`pg_advisory_xact_lock` on Postgres).

If step 4 succeeds, `countersign` signs with the new key on the next call. The old key sits in `mastio_keys` with `deprecated_at` set, still valid for verification until the audit retention window passes.

### From the dashboard

1. Open `https://mastio.example.com/proxy/mastio-key/rotate`.
2. Log in with the admin secret.
3. Type the exact `confirm_text` shown on the page (guards against a stray click).
4. Press **Rotate now**.

Within 3 seconds the page redirects to the overview and the new `kid` is listed as active.

### From the API

```bash
curl -X POST https://mastio.example.com/proxy/mastio-key/rotate \
    -H "Cookie: session=$DASHBOARD_SESSION" \
    -H "X-CSRF-Token: $CSRF" \
    --data-urlencode "confirm_text=rotate-mastio-signing-key"
```

Expected: `302` to `/proxy/overview`, new `kid` visible in `/proxy/mastio-key/list`.

### What to verify

- `curl -s https://mastio.example.com/v1/admin/mastio-pubkey -H "X-Admin-Secret: $ADMIN"` returns the new PEM.
- Fire one agent call — it should succeed without re-enrollment.
- The `cullis_mastio_rotation_staged` Prometheus gauge is 0.

## 2. Recover from a mid-rotation crash

If the Mastio process crashes **between step 3 (propagator-ACK from the Court) and step 4 (local commit)**, you end up with:

- A staged row in `mastio_keys`
- The Court already pinning the new pubkey
- The Mastio still serving the old key as active

The boot-time detector catches this on restart. You'll see:

- `ERROR cullis_proxy_mastio_rotation_halted` in the logs with remediation text
- `/healthz` returning 200, but `/proxy/mastio-key/complete-staged` prompting in the dashboard
- `cullis_mastio_rotation_staged` Prometheus gauge flipped to 1
- Every `countersign()` call raising `RuntimeError: signing halted`

Agents cannot mint tokens until you resolve it. The Mastio holds open traffic rather than emit tokens the Court would 403.

### Decide: activate or drop

You need to know which key the Court currently pins.

```bash
ORG=$(docker compose exec proxy env | grep MCP_PROXY_ORG_ID | cut -d= -f2)
curl -s "https://court.example.com/v1/registry/orgs/$ORG" \
    -H "X-Admin-Secret: $COURT_ADMIN" \
    | jq .mastio_pubkey
```

Compare to the staged pubkey:

```bash
curl -s https://mastio.example.com/proxy/mastio-key/list \
    -H "Cookie: session=$DASHBOARD_SESSION" \
    | jq '.staged'
```

**If the Court's pubkey matches the staged one** → the propagator succeeded before the crash. Activate the staged row:

```bash
curl -X POST https://mastio.example.com/proxy/mastio-key/complete-staged \
    -H "Cookie: session=$DASHBOARD_SESSION" \
    -H "X-CSRF-Token: $CSRF" \
    --data-urlencode "decision=activate" \
    --data-urlencode "confirm_text=activate-staged-mastio-key"
```

**If the Court's pubkey matches the prior active** → the propagator failed, the Court never saw the new key. Drop the staged row:

```bash
curl -X POST https://mastio.example.com/proxy/mastio-key/complete-staged \
    -H "Cookie: session=$DASHBOARD_SESSION" \
    -H "X-CSRF-Token: $CSRF" \
    --data-urlencode "decision=drop" \
    --data-urlencode "confirm_text=drop-staged-mastio-key"
```

The Mastio does not query the Court on your behalf — you own the decision, and the endpoint is authoritative for whichever way you call it.

### What to verify

- Prometheus gauge `cullis_mastio_rotation_staged` = 0
- Logs emit `INFO cullis_proxy_mastio_rotation_recovered` with the decision you chose
- One fresh agent call succeeds

## 3. Rotate the Org CA

Rotating the Org CA re-issues every agent's cert. Plan for a maintenance window unless you have a programmatic re-enrollment pipeline (BYOCA callers regenerating from CI/CD).

**Before you start**

- Announce the window to every agent operator in your org
- Make sure `./scripts/pg-backup.sh` ran in the last 24 hours
- Stage the new CA material (PEM + key) in Vault or your preferred KMS

**Flow**

1. Open `https://mastio.example.com/proxy/pki/rotate-ca` in the dashboard.
2. Upload the new CA cert + key (or paste the PEM; the form accepts both).
3. Confirm the pre-flight check — the Mastio refuses a CA that doesn't chain cleanly or that reuses the previous key material.
4. Every agent under this Mastio re-enrolls on its next session (Connectors prompt on the desktop, BYOCA clients call `enroll_via_byoca` with the new Org CA).

See [BYOCA enrollment](../enroll/byoca) for the re-enrollment mechanics.

## 4. Remediate a legacy Org CA (pathLen=0)

Mastios bootstrapped before Cullis v0.1 issued an Org CA with `BasicConstraints(pathLen=0)`, which blocks the three-tier chain verified by external OpenSSL / Go crypto/x509 / webpki libraries. Intra-org traffic still works; federation peers silently reject your agents' chains.

**Detect**

```bash
curl -s https://mastio.example.com/healthz | jq '.warnings // []'
# [] on a clean proxy
# ["org_ca_legacy_pathlen_zero"] on a legacy one
```

The `cullis_proxy_legacy_ca_pathlen_zero` Prometheus gauge mirrors this.

**Remediate**

Rotate the Org CA as in section 3 above. The new CA emits the correct `pathLen=1` shape, the warning disappears on next boot.

**Optional: fail fast on legacy PKI**

Set `MCP_PROXY_STRICT_PKI=1` in `proxy.env` to refuse boot on a legacy shape. Useful for CI / sandbox / environments where you want enforcement today. The default is OFF until Cullis ships the framework-update auto-migrator.

## Troubleshoot

**`RuntimeError: signing halted` in every agent call**
: You're in the post-crash halted state of section 2. Resolve via `/proxy/mastio-key/complete-staged` with decision `activate` or `drop`.

**Dashboard shows "two active keys"**
: Only the row with `deprecated_at IS NULL` is active for signing; the others are verify-only history. The UI label is about DB rows, not signers. If the gauge is 0, you're fine.

**`/healthz` returns `warnings: ["org_ca_legacy_pathlen_zero"]`**
: You're on a pre-Cullis v0.1 Org CA. Section 4 above is the fix.

## Next

- [Apply updates](apply-updates) — framework updates and the sign-halt pattern that guards them
- [Audit export](audit-export) — prove rotation events to auditors with the hash chain
- [Runbook § Vault sealed](runbook#3-vault-sealed-or-unreachable) — rotate fails if Vault is sealed; unseal first
