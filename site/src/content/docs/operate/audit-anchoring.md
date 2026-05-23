---
title: "Audit chain TSA anchoring"
description: "Cullis periodically signs the audit log's hash chain head with a public RFC 3161 timestamp authority. The signed token proves the chain head existed at the TSA's witnessed time, even if the operator and the Cullis vendor collude."
category: "Operate"
order: 11
updated: "2026-05-24"
---

# Audit chain TSA anchoring

The Mastio's `audit_log` table is hash-chained: every row's `row_hash` is `sha256(row_data || previous_row_hash)`, and the `BEFORE UPDATE/DELETE` trigger (F-A-402) refuses mutation at the SQL layer. That makes the chain **internally consistent** — a tampered row breaks the hash linkage and the standalone verifier catches it.

It does **not** make the chain externally provable. An operator with database write access could rewrite history end-to-end and recompute every `row_hash` — `verify_audit_chain` would still pass because it has nothing to compare the chain against. The chain proves consistency, not provenance.

TSA anchoring closes that gap. The Mastio periodically asks a public RFC 3161 timestamp authority (default `http://timestamp.digicert.com`) to sign a timestamp over the current chain head's `row_hash`. The signed `TimeStampToken` is persisted in `audit_chain_anchors` and rides along in every audit export. A verifier replaying the chain re-checks the token's `messageImprint` against the reconstructed `row_hash` and walks the TSA's certificate chain back to a publicly-trusted root.

End-to-end: **forging the audit history now requires forging the TSA's signature**, which raises the cost from "DB write access" to "compromise the TSA's signing key + the certificate authorities the verifier trusts". The audit trail becomes tamper-evident even against an operator colluding with the Cullis vendor.

## What ships in the bundle

Two new components, no operator action required by default:

- **Lifespan watcher** `audit_anchor_watcher` — leader-elected, runs in one worker per Mastio process. Every hour by default it reads the latest `(chain_seq, row_hash)` from `audit_log`, calls the configured TSA, and inserts an `audit_chain_anchors` row with the signed token.
- **Storage table** `audit_chain_anchors` — append-only via the same `BEFORE UPDATE/DELETE` trigger pattern as `audit_log`. Columns: `anchored_at`, `org_id`, `chain_seq`, `row_hash`, `tsa_url`, `tsa_token` (raw bytes prefixed with `T1|` so the offline verifier routes them to the RFC 3161 ASN.1 decoder).

The TSA client lives at `mcp_proxy/audit/tsa_client.py`. It builds the `TimeStampReq` with `rfc3161-client`, POSTs over HTTP, and parses the response with `asn1crypto` (more lenient than `rfc3161-client`'s strict ASN.1 parser; real-world TSAs sometimes emit non-canonical SET ordering inside the SignedData cert bag).

## Configuration

Four env vars, all with sane defaults:

```env
# Default true. Set to false for air-gapped deployments that
# cannot reach a public TSA over HTTP.
MCP_PROXY_AUDIT_ANCHOR_ENABLED=true

# Public TSA URL. DigiCert is widely-used and free. Operators can
# swap to a CA they already trust on their PKI floor (Sectigo,
# GlobalSign, FreeTSA, an internal qualified TSP).
MCP_PROXY_AUDIT_ANCHOR_TSA_URL=http://timestamp.digicert.com

# Anchor cadence. Forensic, not real-time — one hour bounds the
# tamper window an attacker has between anchors while keeping the
# TSA query rate well below typical rate limits.
MCP_PROXY_AUDIT_ANCHOR_INTERVAL_SECONDS=3600

# Per-anchor HTTP timeout to the TSA. Short — a wedged TSA must
# not stall the watcher past the next tick.
MCP_PROXY_AUDIT_ANCHOR_TSA_TIMEOUT_SECONDS=10
```

## Verifier flow

The standalone `scripts/cullis-audit-verify.py` already understands the `T1|` token format. Run it offline against an NDJSON audit export:

```bash
python scripts/cullis-audit-verify.py audit-export.ndjson
```

For each anchor in the bundle:

1. The verifier looks up the chain entry at `(org_id, chain_seq)` and reconstructs the expected `row_hash`.
2. It strips the `T1|` prefix and parses the remaining bytes as an RFC 3161 `TimeStampToken` via `asn1crypto.tsp`.
3. It extracts the `messageImprint` from the inner `TSTInfo` and checks it equals `sha256(row_hash)`.
4. Optionally — with the `--verify-tsa-chain` flag — it walks the TSA's signing cert chain back to a root the verifier trusts. Out of scope for the default run; trust roots are operator-configured.

A mismatch exits the verifier with code 3 (chain tampering); a missing `rfc3161-client` library exits with code 5 (anchor unverifiable, install the library).

## Failure modes

- **TSA unreachable**: the watcher logs a warning each tick and the chain continues unanchored until the TSA comes back. The audit_log itself is unaffected. Operators monitoring `policy.audit_anchor_watcher_failed` audit rows can detect prolonged outages.
- **TSA refuses (status != granted)**: same as above — warning, retry next tick.
- **TSA token messageImprint mismatch**: the client raises `TSAAnchorError` before persisting; a rogue TSA cannot poison the local table. The audit chain stays consistent regardless.
- **Multi-worker deploy**: leader-elected via `mcp_proxy.lifespan.get_leader`, so only one worker per process runs the loop. Non-leaders skip silently.
- **No chain entries yet** (fresh install): watcher silent, no TSA call, no anchor row. Next tick after the first audited action picks up `chain_seq=1`.

## Differentiator

Most agent infrastructure products (OPA, agentgateway, MS Agent Governance Toolkit) ship a "tamper-evident audit log" claim backed by hash chains. The chain proves consistency to a regulator who already trusts the operator. **It does not protect against the operator**.

TSA anchoring is what closes that gap. The token's GenTime is asserted by a third-party CA the regulator can verify independently. A bank pilot whose CISO has read the Cullis threat model on day one will look for exactly this — the in-tree hash chain is necessary but not sufficient.

The bundle ships with anchoring on by default. The default TSA (DigiCert) is free and widely-trusted. The audit log becomes provable to a court that does not trust the operator, the vendor, or the cloud.
