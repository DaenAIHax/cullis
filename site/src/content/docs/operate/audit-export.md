---
title: "Audit export"
description: "Hash-chain audit log: export to NDJSON/CSV, fetch a TSA-anchored bundle for a time window, and verify the chain locally with the CLI."
category: "Operate"
order: 40
updated: "2026-04-23"
---

# Audit export

**Who this is for**: a compliance operator, security reviewer, or investigator who needs a tamper-evident record of what happened on the Mastio or Court for a given time window. Every significant event — enrollment, session open, message send, binding approve, key rotation, framework update apply — lands in an append-only, SHA-256 hash-chained table.

## Prerequisites

- Admin secret (Mastio or Court, depending on which chain you're exporting)
- `curl`, `jq`, `python3` on the host
- Cullis CLI installed (`pip install cullis-sdk[cli]` or the Connector's bundled `cullis` binary)

## What's in the chain

Each row has:

- `id` (ULID, monotonic)
- `timestamp` (ISO 8601 UTC)
- `event_type` (e.g. `auth.token_issued`, `broker.session_created`, `admin.update_applied`)
- `actor` (agent URI, admin actor, or `system`)
- `details` (event-specific JSON)
- `prev_hash` (hex) + `hash` (hex) — SHA-256 over `(prev_hash || canonical_json(row_without_hash))`

The chain is **per-org** on the Mastio. When an event has cross-org impact (session open, cross-org A2A), the Mastio writes a local row *and* emits a dual-write to the Court so the Court's chain records the same event from its vantage point. The two chains cross-reference by ULID.

## 1. Export as NDJSON / CSV

### NDJSON (one JSON object per line, easy to pipe)

```bash
curl -s "https://mastio.example.com/v1/admin/audit/export?format=ndjson&start=2026-04-01T00:00:00Z&end=2026-04-30T23:59:59Z" \
    -H "X-Admin-Secret: $ADMIN" \
    -o audit-april-2026.ndjson
```

Expected: one line per event, newest last.

### CSV

```bash
curl -s "https://mastio.example.com/v1/admin/audit/export?format=csv&org_id=acme&event_type=broker.session_created" \
    -H "X-Admin-Secret: $ADMIN" \
    -o sessions-acme.csv
```

Query parameters:

| Parameter | Meaning |
|---|---|
| `format` | `ndjson` or `csv` |
| `start`, `end` | ISO 8601; end defaults to now |
| `org_id` | Filter by org (Court only) |
| `event_type` | Exact match on event type |
| `actor` | Exact match on actor URI |
| `limit` | Hard cap, default 10 000 |

The export streams — use `-N --no-buffer` with `curl` for large windows.

## 2. Fetch a TSA-anchored bundle

For legal-grade evidence, pair the chain with an RFC 3161 timestamp. The Mastio signs a manifest of the exported range + anchors it against a public TSA (the Mastio's configured `CULLIS_TSA_URL`, default `http://timestamp.digicert.com` — override in `proxy.env` for your org's preferred authority).

```bash
curl -s -X POST "https://mastio.example.com/v1/admin/audit/bundle" \
    -H "X-Admin-Secret: $ADMIN" \
    -H "Content-Type: application/json" \
    -d '{"start": "2026-04-01T00:00:00Z", "end": "2026-04-30T23:59:59Z"}' \
    -o audit-april-2026.bundle.tar.gz
```

The bundle contains:

```
manifest.json        # start, end, first_id, last_id, first_hash, last_hash, sha256 of events.ndjson
events.ndjson        # the raw events in chain order
chain-proof.json     # prev_hash pointers for external verification
tsa-reply.tsr        # RFC 3161 TimeStampResp from the TSA
signing-cert.pem     # the Mastio public key at the time of bundling
```

Store bundles in append-only cold storage (S3 Object Lock, WORM filesystem). A bundle plus its TSA reply is self-contained evidence — no Mastio access needed for re-verification years later.

## 3. Verify the chain locally

```bash
cullis audit verify ./audit-april-2026.bundle.tar.gz
```

Example output:

```
Bundle: audit-april-2026.bundle.tar.gz
Range: 2026-04-01T00:00:00Z → 2026-04-30T23:59:59Z
Events: 8 421
first_hash: 3f4a...2b1e
last_hash:  9e0c...a55d

✓ Manifest SHA-256 matches events.ndjson
✓ Chain walk: prev_hash → hash verified across all 8 421 events
✓ Chain head matches first_hash in manifest
✓ Chain tail matches last_hash in manifest
✓ TSA reply signature verified against embedded cert
✓ TSA timestamp (2026-05-01T03:11:42Z) is after last event
✓ Signing cert valid at TSA timestamp

Bundle is authentic.
```

`cullis audit verify` exits non-zero on any failure. The exact failure surface is in the last successful check — a broken chain reports which row's `hash` didn't match the next row's `prev_hash`.

Run the same verification against a bundle you received from another org (the Court's operator, for example) — the verifier doesn't need Mastio access, only the bundle itself and network access to the TSA.

## 4. Query the chain head without exporting

```bash
curl -s "https://mastio.example.com/v1/admin/audit/head" \
    -H "X-Admin-Secret: $ADMIN" | jq
```

```json
{"last_id": "01JXF...YZ", "last_hash": "9e0c...a55d", "last_timestamp": "2026-04-23T21:44:07Z"}
```

Use the head as a continuity check between periodic bundle exports. A monitoring job that pulls the head every 5 minutes and stores `(last_id, last_hash)` gives you an external witness of chain progression — if a future bundle doesn't continue from that witness, the chain was tampered with in the meantime.

## Troubleshoot

**Export returns `413 Payload Too Large`**
: The requested window exceeds `limit`. Page with narrower `start`/`end` ranges, or call in chunks. The default `limit` is a safety cap — raise it via `CULLIS_AUDIT_EXPORT_MAX` in `proxy.env` if your compliance regime requires single-window exports.

**Bundle verification fails on TSA check**
: The TSA reply expired or the TSA's cert chain no longer verifies from your trust store. Store the TSA's root cert alongside the bundle — long-term evidence needs the trust anchor captured at issuance time. `cullis audit verify --tsa-root ./digicert-root.pem bundle.tar.gz` pins a custom root.

**`cullis audit verify` reports "chain head mismatch"**
: Someone exported rows and edited the file, or an append-only violation happened on the database. Pull the current `/audit/head` from the Mastio and compare — if the head diverges from your external witness, treat as a security incident.

**Clock skew on TSA reply**
: Mastio clock drift over 30s will sometimes produce a TSA reply stamped *before* the last event's `timestamp`. Cullis rejects this out of an abundance of caution. Re-sync the host clock (`chronyc sources`, `timedatectl`) and re-request the bundle.

## Next

- [Rotate keys](rotate-keys) — rotate events land in the chain; compare the `admin.mastio_key_rotated` audit row against the Prometheus gauge history
- [Apply updates](apply-updates) — framework update apply/rollback events land as `admin.update_applied` / `admin.update_rolled_back`
- [Migration from direct login](../reference/migration-from-direct-login) — deprecated `auth.token_issued` rows carry `details.deprecated = true`; count them to size a migration
