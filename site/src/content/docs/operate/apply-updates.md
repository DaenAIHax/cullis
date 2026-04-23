---
title: "Apply updates"
description: "Framework updates: pending-updates registry, boot detector, sign-halt on critical migrations, and how to apply or roll back a concrete migration like the Org CA pathLen=0 fix."
category: "Operate"
order: 30
updated: "2026-04-23"
---

# Apply updates

**Who this is for**: a Mastio operator on v0.2.0 or later whose proxy boots with a **pending-updates** warning, or who wants to understand how Cullis ships cross-cutting PKI/protocol fixes without silently breaking agents.

> **Requires Mastio v0.2.0 or later.** The framework registry, boot detector, Prometheus gauge, and admin endpoints described here were introduced with the federation-hardening plan (Parte 1). On earlier versions, rely on [Rotate keys](rotate-keys) for one-off PKI repairs.

## Prerequisites

- Mastio v0.2.0+ running (check `docker compose exec proxy cat /app/VERSION`)
- Admin secret available
- A fresh Postgres backup (`./scripts/pg-backup.sh`)
- `curl`, `jq`

## What a framework update is

Some bugs need more than a code change. Consider the Org CA that Cullis v0.1 emitted with `BasicConstraints(pathLen=0)` — a `git pull` + rebuild patched the generator, but every proxy already bootstrapped kept the broken CA in its database. External federation peers silently rejected those chains.

A **framework update** is a Python migration class that ships alongside the code fix. The Mastio discovers it at boot, inserts a row in the `pending_updates` table, and — if the migration is marked `critical` and affects enrollment methods the proxy actively uses — halts signing until the operator applies it. The admin then calls one endpoint to run the migration, which mutates state idempotently and records a rollback snapshot.

Three surfaces:

1. **Registry** — `mcp_proxy/updates/migrations/` holds migration classes. Each migration declares its `migration_id`, `migration_type`, `criticality`, `affects_enrollments`, and a `description` string that shows up verbatim in the dashboard.
2. **Boot detector** — runs after `ensure_mastio_identity`, before `LocalIssuer` construction. Every registered migration's `check()` runs; pending rows insert with `status='pending'`; the `cullis_pending_updates_total{status}` gauge refreshes; a `critical` migration whose `affects_enrollments` intersects `SELECT DISTINCT enrollment_method FROM internal_agents` flips the sign-halt flag.
3. **Admin apply/rollback** — `POST /v1/admin/updates/{id}/apply` runs `up()`, writes a snapshot to `migration_state_backups`, marks the row `applied`. `POST /v1/admin/updates/{id}/rollback` restores from the snapshot and marks the row `rolled_back`.

## Detect pending updates

### `/healthz`

```bash
curl -s https://mastio.example.com/healthz | jq
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

Alert on `pending_updates_total{status="pending"} > 0` for more than 24 hours in production.

### Admin API

```bash
curl -s https://mastio.example.com/v1/admin/updates \
    -H "X-Admin-Secret: $ADMIN" | jq
```

Example:

```json
[
  {
    "migration_id": "2026-04-23-org-ca-pathlen-1",
    "description": "Rotate Org CA to pathLen=1 so external OpenSSL / Go / webpki verifiers accept the three-tier chain.",
    "migration_type": "pki",
    "criticality": "critical",
    "affects_enrollments": ["connector"],
    "status": "pending",
    "detected_at": "2026-04-23T19:04:21Z"
  }
]
```

## Sign halt

If the boot detector sees a migration with `criticality == "critical"` and `affects_enrollments` that overlaps your proxy's active enrollment types, it engages a **sign halt**: every `countersign()` call raises `RuntimeError: signing halted — pending migration {id}`. Agents cannot mint Court tokens until you apply the update.

This is deliberate. The alternative is issuing tokens peers will 403 for reasons you can't diagnose from logs.

Indicators of a sign halt in progress:

- `ERROR cullis_proxy_sign_halt_pending_migration` in the logs with the `migration_id`
- `/healthz` returns 200 but every `/v1/auth/token` fails fast with a human-readable `503`
- `cullis_mastio_sign_halted` gauge = 1 (same surface the rotation halt uses — both are "do not sign until resolved")

## Apply an update

Review the migration first. Read the `description`, check the PR linked in the release notes, confirm the rollback snapshot behavior matches your recovery tolerance.

### From the admin API

```bash
MIGRATION_ID="2026-04-23-org-ca-pathlen-1"

curl -X POST "https://mastio.example.com/v1/admin/updates/$MIGRATION_ID/apply" \
    -H "X-Admin-Secret: $ADMIN" \
    -H "Content-Type: application/json" \
    -d '{"confirm": true}'
```

Expected:

```json
{"migration_id": "2026-04-23-org-ca-pathlen-1", "status": "applied", "applied_at": "2026-04-23T19:08:12Z"}
```

The migration runs idempotently: `check()` short-circuits to no-op if the state is already fixed. Re-applying is safe but the backup snapshot is overwritten.

### From the dashboard

> **Placeholder UI — finalizing in v0.2.0.** The admin dashboard is gaining a **Pending updates** tab that lists every registered migration with its description, criticality badge, and two buttons (**Apply** / **View rollback plan**). Until that lands, use the admin API above. The CLI flow is identical — this section will be updated when the UI ships.

## Roll back

Every successful apply writes a snapshot to `migration_state_backups` keyed by `migration_id`. Roll back with:

```bash
curl -X POST "https://mastio.example.com/v1/admin/updates/$MIGRATION_ID/rollback" \
    -H "X-Admin-Secret: $ADMIN" \
    -H "Content-Type: application/json" \
    -d '{"confirm": true}'
```

Expected: `{"migration_id": "...", "status": "rolled_back", "rolled_back_at": "..."}`.

A second rollback for the same `migration_id` fails with `404 no snapshot` — state has already moved. The row moves to `status='rolled_back'`; the boot detector won't re-propose it to `pending`. If you want the migration back in `pending`, drop the row manually:

```bash
docker compose exec proxy psql -U cullis -d cullis -c \
    "DELETE FROM pending_updates WHERE migration_id = '$MIGRATION_ID';"
```

The detector will re-insert it on next boot if `check()` still returns True.

## Worked example — Org CA pathLen=0

Migration id: `2026-04-23-org-ca-pathlen-1`. Shipped in v0.2.0.

**What it does**

- Detects `BasicConstraints(pathLen=0)` on the Org CA root.
- Generates a fresh RSA-4096 Org CA with `pathLen=1`, inheriting `notAfter` from the old CA.
- Re-signs every agent's leaf certificate, preserving subject, public key, SAN, and validity.
- Assigns fresh 128-bit leaf serials (RFC 5280 §4.1.2.2) to avoid stale-cache verifier conflicts.
- Writes the pre-apply state to `migration_state_backups` before mutating anything.

**Why agents don't re-enroll**

The migration preserves agent public keys. Agents keep signing with the private keys they already hold. Only the cert chain changes — Connectors and SDKs reload the Org CA bundle on the next call without any user-visible step.

**What is explicitly out of scope**

- **BYOCA agents**. The org holds their private keys, not the Mastio, so the auto-migrator can't re-sign leaves. BYOCA operators re-run `enroll_via_byoca` against the new Org CA. Tracked separately.
- **Expired Org CA**. The migration refuses to run if the current CA's `notAfter` is in the past — the repair would extend expiry silently. Use `POST /proxy/pki/rotate-ca` ([Rotate keys § 3](rotate-keys#3-rotate-the-org-ca)) instead.

## Verify after apply

- `cullis_pending_updates_total{status="pending"}` = 0 (for this migration)
- `/healthz` drops `org_ca_legacy_pathlen_zero` from the `warnings` array
- `cullis_mastio_sign_halted` = 0
- One agent call succeeds end-to-end; `./sandbox/smoke.sh full` passes on a staging copy

## Troubleshoot

**Apply returns `409 already applied`**
: The row is already `status='applied'`. Read `detected_at` + `applied_at` — someone else applied it (check the audit log, filter `event_type=admin.update_applied`). No action needed.

**Apply returns `412 sign halt mismatch`**
: Another migration is engaged on the halt flag. Apply that one first or drop it explicitly; `GET /v1/admin/updates?status=pending` lists them in order.

**`up()` raises mid-apply**
: The snapshot was written before the mutation — rollback is safe. Call `POST /v1/admin/updates/{id}/rollback`, inspect the logs (`cullis_proxy_update_apply_failed` with a traceback), then either fix the environment and retry, or escalate the migration as a defect.

**I want to disable a migration I consider incompatible**
: Set `status='rolled_back'` directly in `pending_updates` via SQL. The detector respects non-`pending` rows. This is a last resort — the migration shipped as `critical` for a reason, and the halt will re-engage on any subsequent `detected_at` if you delete the row.

## Next

- [Rotate keys](rotate-keys) — manual key rotation when a framework update isn't the right tool
- [Audit export](audit-export) — confirm apply events landed in the hash chain
- [Runbook § monitoring](runbook#monitoring) — where to point Prometheus at the new gauge
