---
title: "Apply updates"
description: "Framework updates: pending-updates registry, boot detector, sign-halt on critical migrations, and how to apply or roll back a concrete migration like the Org CA pathLen=0 fix."
category: "Operate"
order: 30
updated: "2026-05-22"
---

# Apply updates

**Who this is for**: a Mastio operator whose deploy boots with a **pending-updates** warning, or who wants to understand how Cullis ships cross-cutting PKI/protocol fixes without silently breaking agents.

## Prerequisites

- A reasonably recent Mastio image (`docker compose -p cullis-mastio exec mcp-proxy printenv CULLIS_MASTIO_VERSION`). On the bundle, `./deploy.sh --upgrade <version>` keeps you current.
- Admin secret available
- A fresh backup of the deploy — see [Disaster recovery](disaster-recovery)
- `curl`, `jq`

## What a framework update is

Some bugs need more than a code change. Consider the Org CA that Cullis v0.1 emitted with `BasicConstraints(pathLen=0)` — a `git pull` + rebuild patched the generator, but every Mastio already bootstrapped kept the broken CA in its database. External verifiers (compliance auditors, stdlib x509 libraries) reject those chains.

A **framework update** is a Python migration class that ships alongside the code fix. The Mastio discovers it at boot, inserts a row in the `pending_updates` table, and — if the migration is marked `critical` and affects enrollment methods the proxy actively uses — halts signing until the operator applies it. The admin then calls one endpoint to run the migration, which mutates state idempotently and records a rollback snapshot.

Three surfaces:

1. **Registry** — `mcp_proxy/updates/migrations/` holds migration classes. Each migration declares its `migration_id`, `migration_type`, `criticality`, `affects_enrollments`, and a `description` string that shows up verbatim in the dashboard.
2. **Boot detector** — runs after Mastio identity bootstrap. Every registered migration's `check()` runs; pending rows insert with `status='pending'`; the `cullis_pending_updates_total{status}` gauge refreshes; a `critical` migration whose `affects_enrollments` intersects the live enrollment types flips the sign-halt flag.
3. **Admin apply/rollback** — `POST /proxy/updates/<id>/apply` runs `up()`, writes a snapshot to `migration_state_backups`, marks the row `applied`. `POST /proxy/updates/<id>/rollback` restores from the snapshot.

## Detect pending updates

### `/healthz`

```bash
curl -sk https://localhost:9443/healthz | jq
```

Example output:

```json
{
  "status": "ok",
  "warnings": ["org_ca_legacy_pathlen_zero"],
  "pending_updates": 1
}
```

A clean Mastio omits both `warnings` and `pending_updates`.

### Prometheus gauge

```
cullis_pending_updates_total{status="pending"} 1
cullis_pending_updates_total{status="applied"} 0
cullis_pending_updates_total{status="rolled_back"} 0
```

Alert on `cullis_pending_updates_total{status="pending"} > 0` for more than 24 hours in production.

### Dashboard + admin API

The dashboard exposes the pending list at `https://mastio.example.com/proxy/updates` — JSON list is available at `/proxy/updates/api`:

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
curl -sk https://localhost:9443/proxy/updates/api \
    -H "X-Admin-Secret: $ADMIN_SECRET" | jq
```

Example:

```json
[
  {
    "migration_id": "2026-04-23-org-ca-pathlen-1",
    "description": "Rotate the Org CA to BasicConstraints(pathLen=1) preserving every agent's public key — repairs proxies whose Org CA was generated before PR #284 fixed the pathLen=0 bug.",
    "migration_type": "cert-schema",
    "criticality": "critical",
    "affects_enrollments": ["connector"],
    "status": "pending",
    "detected_at": "2026-04-23T19:04:21Z"
  }
]
```

**A note on `affects_enrollments`**: the label `"connector"` is the internal enrollment-type tag for **Mastio-managed enrollment** (the Mastio holds the Org CA private key and mints agent certs itself). It is NOT a reference to the Connector binary, which is no longer part of the public repo. BYOCA-enrolled agents are flagged separately because their cert material lives outside the Mastio.

## Sign halt

If the boot detector sees a migration with `criticality == "critical"` and `affects_enrollments` that overlaps your deploy's active enrollment types, it engages a **sign halt**: every signing call raises `RuntimeError: signing halted — pending migration {id}`. Agents cannot mint new DPoP-bound tokens until you apply the update.

This is deliberate. The alternative is issuing tokens external verifiers will reject for reasons you can't diagnose from logs.

Indicators of a sign halt in progress:

- `ERROR cullis_proxy_sign_halt_pending_migration` in the logs with the `migration_id`
- `/healthz` returns 200 but `/v1/auth/token` and every signing call fails fast with a human-readable `503`
- `cullis_mastio_sign_halted` gauge = 1

## Apply an update

Review the migration first. Read the `description`, check the PR linked in the release notes, confirm the rollback snapshot behavior matches your recovery tolerance.

### From the admin API

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
MASTIO="https://localhost:9443"
MIGRATION_ID="2026-04-23-org-ca-pathlen-1"

curl -sk -X POST "$MASTIO/proxy/updates/$MIGRATION_ID/apply" \
    -H "X-Admin-Secret: $ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"confirm": true}'
```

Expected:

```json
{"migration_id": "2026-04-23-org-ca-pathlen-1", "status": "applied", "applied_at": "2026-04-23T19:08:12Z"}
```

The migration runs idempotently: `check()` short-circuits to no-op if the state is already fixed. Re-applying is safe but the backup snapshot is overwritten.

### From the dashboard

`https://mastio.example.com/proxy/updates` lists every registered migration with description, criticality badge, and two buttons (**Apply** / **View rollback plan**). Same outcome as the API call above.

## Roll back

Every successful apply writes a snapshot to `migration_state_backups` keyed by `migration_id`. Roll back with:

```bash
curl -sk -X POST "$MASTIO/proxy/updates/$MIGRATION_ID/rollback" \
    -H "X-Admin-Secret: $ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"confirm": true}'
```

Expected: `{"migration_id": "...", "status": "rolled_back", "rolled_back_at": "..."}`.

A second rollback for the same `migration_id` fails with `404 no snapshot` — state has already moved. The row moves to `status='rolled_back'`; the boot detector won't re-propose it to `pending`. If you want the migration back in `pending`, drop the row manually.

**SQLite (default)**:

```bash
docker compose -p cullis-mastio exec mcp-proxy sqlite3 /data/mcp_proxy.db \
    "DELETE FROM pending_updates WHERE migration_id = '$MIGRATION_ID';"
```

**Postgres (opt-in)**:

```bash
psql -h "$PG_HOST" -U cullis -d cullis -c \
    "DELETE FROM pending_updates WHERE migration_id = '$MIGRATION_ID';"
```

The detector will re-insert it on next boot if `check()` still returns True.

## Worked example — Org CA pathLen=0

Migration id: `2026-04-23-org-ca-pathlen-1`.

**What it does**

- Detects `BasicConstraints(pathLen=0)` on the Org CA root
- Generates a fresh RSA-4096 Org CA with `pathLen=1`, inheriting `notAfter` from the old CA
- Re-signs every agent's leaf certificate, preserving subject, public key, SAN, and validity
- Assigns fresh 128-bit leaf serials (RFC 5280 §4.1.2.2) to avoid stale-cache verifier conflicts
- Writes the pre-apply state to `migration_state_backups` before mutating anything

**Why agents don't re-enroll**

The migration preserves agent public keys. Agents keep signing with the private keys they already hold. Only the cert chain changes — the SDK reloads the Org CA bundle on the next handshake without any user-visible step.

**What is explicitly out of scope**

- **BYOCA agents**. The org holds their private keys, not the Mastio, so the auto-migrator can't re-sign leaves. BYOCA operators re-run `enroll_via_byoca` against the new Org CA. Tracked separately.
- **Expired Org CA**. The migration refuses to run if the current CA's `notAfter` is in the past — the repair would extend expiry silently. Use the operator-driven Org CA rotation instead (see [Rotate keys § 2](rotate-keys#2-rotate-the-org-ca)).

## Verify after apply

- `cullis_pending_updates_total{status="pending"}` = 0 (for this migration)
- `/healthz` drops `org_ca_legacy_pathlen_zero` from the `warnings` array
- `cullis_mastio_sign_halted` = 0
- One agent end-to-end (mint a token + make a call) succeeds against the new chain

## Troubleshoot

**Apply returns `409 already applied`**
: The row is already `status='applied'`. Read `detected_at` + `applied_at` — someone else applied it (check the audit log, filter `event_type=admin.update_applied`). No action needed.

**Apply returns `412 sign halt mismatch`**
: Another migration is engaged on the halt flag. Apply that one first, or drop it explicitly; `GET /proxy/updates/api?status=pending` lists them in order.

**`up()` raises mid-apply**
: The snapshot was written before the mutation — rollback is safe. Call `POST /proxy/updates/{id}/rollback`, inspect the logs (`cullis_proxy_update_apply_failed` with a traceback), then either fix the environment and retry, or escalate the migration as a defect.

**I want to disable a migration I consider incompatible**
: Set `status='rolled_back'` directly in `pending_updates` via SQL (commands above). The detector respects non-`pending` rows. This is a last resort — the migration shipped as `critical` for a reason, and the halt will re-engage on any subsequent `detected_at` if you delete the row.

## Next

- [Rotate keys](rotate-keys) — manual key rotation when a framework update isn't the right tool
- [Disaster recovery](disaster-recovery) — take a backup before applying any update
- [Audit export](audit-export) — confirm apply events landed in the hash chain
- [Runbook § monitoring](runbook#monitoring) — where to point Prometheus at the new gauge
