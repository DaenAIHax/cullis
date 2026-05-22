---
title: "Audit export"
description: "Hash-chained audit log on the Mastio: view in the dashboard, verify the chain online, export to NDJSON for offline forensic review, and re-verify the chain with the standalone CLI."
category: "Operate"
order: 40
updated: "2026-05-22"
---

# Audit export

**Who this is for**: a compliance operator, security reviewer, or investigator who needs a tamper-evident record of what happened on the Mastio for a given time window. Every significant event — enrollment, session open, MCP tool call, key rotation, framework update apply — lands in an append-only, SHA-256 hash-chained table called `local_audit`.

## What's in the chain

The `local_audit` table has the following columns:

| Column | Meaning |
|---|---|
| `id` | Auto-increment primary key |
| `timestamp` | ISO 8601 UTC |
| `event_type` | e.g. `agent.enrolled`, `mcp.tool_call`, `admin.update_applied`, `pki.rotate_ca` |
| `agent_id` | Actor — agent URI when applicable |
| `session_id` | Session correlation when applicable |
| `org_id` | Org scope |
| `details` | Event-specific JSON payload |
| `result` | `ok` / `denied` / `error` |
| `entry_hash` | SHA-256 over canonical representation of the row |
| `previous_hash` | Link to the prior row's `entry_hash` (chain pointer) |
| `chain_seq` | Monotonic sequence within the chain |
| `peer_org_id`, `peer_row_hash` | Cross-org cross-reference fields (used when this Mastio is federated under a Court — empty in standalone deploys) |

The chain is **per-org** on the Mastio. A standalone Mastio (the default bundle deploy) writes a single per-org chain; federated deploys (Mastio attached to a Court) populate `peer_org_id` / `peer_row_hash` on cross-org events for later reconciliation.

Tamper-evidence properties:

- Append-only via SQLite triggers `local_audit_no_update` + `local_audit_no_delete` — even admin DB access cannot UPDATE / DELETE without dropping the triggers (an act that itself leaves audit trail).
- Each row's `entry_hash` covers a canonical serialization including `previous_hash`, so any modification of an earlier row breaks every subsequent hash.

## 1. View in the dashboard

The Mastio dashboard ships a unified audit log viewer:

```
https://mastio.example.com/proxy/audit
```

It merges two streams:

- Legacy admin events (auth, enrollment, agent CRUD, policy) from the older `audit_log` table.
- Hash-chained `local_audit` rows (MCP tool calls, A2A messages, sessions, key rotations).

Filters at the top let you narrow by `event_type`, `agent_id`, `session_id`, and time window. Each row is expandable to inspect the `details` JSON.

## 2. Verify chain integrity online

The dashboard exposes a **Verify chain** button that hits `POST /proxy/audit/verify` and renders the result inline:

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
CSRF="$(...)"  # extract from dashboard cookie / session

curl -sk -X POST "https://localhost:9443/proxy/audit/verify" \
     -H "Cookie: session=$DASHBOARD_SESSION" \
     -H "X-CSRF-Token: $CSRF"
```

The endpoint walks every `local_audit` row in `chain_seq` order, recomputes `entry_hash`, and confirms `previous_hash` links match. Response shape:

```json
{
  "ok": true,
  "entries": 8421,
  "agents": 12,
  "orgs": 1
}
```

On failure:

```json
{
  "ok": false,
  "failure": {
    "expected": "3f4a...2b1e",
    "observed": "9e0c...a55d",
    "scope": "agent-chain",
    "id": 4217
  }
}
```

A failure means the chain was tampered with after write (UPDATE / DELETE bypass, or storage corruption). Treat as a security incident: capture the full `local_audit` table to cold storage, identify the row range, then escalate.

## 3. Export for offline forensic review

The Mastio doesn't yet expose an HTTP export endpoint (it's on the roadmap; the chain-integrity verify endpoint above covers the most common online use case). For an offline NDJSON dump suitable for the standalone verifier or for handing to an auditor, query the database directly.

### SQLite (default bundle)

```bash
docker compose -p cullis-mastio exec mcp-proxy \
    sqlite3 /data/mcp_proxy.db \
    -cmd '.mode json' \
    "SELECT * FROM local_audit
     WHERE timestamp >= '2026-04-01T00:00:00Z'
       AND timestamp <  '2026-05-01T00:00:00Z'
     ORDER BY chain_seq;" \
    | python3 -c 'import sys, json; [print(json.dumps(r)) for r in json.load(sys.stdin)]' \
    > audit-april-2026.ndjson
```

### Postgres (opt-in)

```bash
psql -h "$PG_HOST" -U cullis -d cullis -A -t -c \
    "COPY (SELECT row_to_json(t) FROM (
       SELECT * FROM local_audit
       WHERE timestamp >= '2026-04-01T00:00:00Z'
         AND timestamp <  '2026-05-01T00:00:00Z'
       ORDER BY chain_seq) t) TO STDOUT;" \
    > audit-april-2026.ndjson
```

Store the resulting file in append-only cold storage (S3 Object Lock, WORM filesystem). The NDJSON is self-contained — no Mastio access needed for re-verification years later.

## 4. Verify offline with the standalone CLI

The repo ships `scripts/cullis-audit-verify.py` — a zero-network, offline verifier consumable by anyone holding the NDJSON dump (your compliance team, an external auditor, a federated peer reconciling cross-org events).

```bash
python scripts/cullis-audit-verify.py --bundle audit-april-2026.ndjson
```

Example output:

```
Bundle: audit-april-2026.ndjson
Per-org chains: 1
  acme: 8421 entries, chain_seq 1 → 8421, head 9e0c...a55d
✓ Per-org chain walk: entry_hash + previous_hash verified for all 8421 rows
✓ Legacy global chain (chain_seq IS NULL rows): no violations
✓ No TSA anchor rows present in this window
```

`cullis-audit-verify.py` exits with:

- `0` — all checks passed
- `2` — chain tamper detected (mismatch or break)
- `3` — TSA anchor mismatch (when applicable; the bundle includes RFC 3161 / mock TSA tokens and one doesn't match its row)
- `4` — cross-org reconciliation mismatch (when verifying two NDJSON bundles together)
- `5` — unrecognized TSA token format

### Cross-org reconciliation

If you operate two Mastios federated under a Court (enterprise path) and need to prove that cross-org events match on both sides:

```bash
python scripts/cullis-audit-verify.py \
    --bundle acme-april-2026.ndjson \
    --bundle bravo-april-2026.ndjson
```

The verifier matches rows by `peer_row_hash` and confirms `event_type` / `session_id` / `details` agree across the two bundles. Mismatches are surfaced with both row IDs and the divergence point.

## Troubleshoot

**Verify returns `ok: false` immediately**
: Someone wrote to `local_audit` with the triggers dropped, or the DB was restored from a backup older than the current chain head and a few rows got duplicated. Capture the full table for forensics, then run the verifier with `--bundle` on a SQL dump to identify the exact tamper window.

**Chain-integrity verify is slow on large deploys**
: The verify endpoint walks the whole chain. For deploys with millions of rows, run it during a maintenance window or rely on the offline verifier against a recent NDJSON dump. A streaming / incremental verifier is on the roadmap.

**Verifier reports "unrecognized TSA format"**
: The chain contains TSA anchor rows in a format the verifier doesn't know how to validate (e.g. a new RFC 3161 variant or a custom anchor). Update `cullis-audit-verify.py` to the latest from `scripts/` and retry. TSA anchors only land in chains produced by deploys with TSA wiring enabled — standalone bundle Mastios don't generate them by default.

**Export contains rows with `entry_hash=NULL`**
: Those are pre-chain rows from before hash chaining was enabled. The verifier accepts them as legacy and skips them. Modern installs (Mastio v0.5+) write every row with a chain entry from boot.

## Next

- [Disaster recovery](disaster-recovery) — back up the chain as part of the regular bundle backup
- [Rotate keys](rotate-keys) — rotate events land in the chain as `pki.rotate_ca` / `agent.cert_rotated`
- [Apply updates](apply-updates) — framework update events land as `admin.update_applied` / `admin.update_rolled_back`
- [Runbook § monitoring](runbook#monitoring) — Prometheus counters mirror the most common audit event types for live dashboards
