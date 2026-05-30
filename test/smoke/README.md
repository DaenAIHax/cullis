# `test/smoke/` — Cullis Mastio + SDK smoke harness

End-to-end gate for the public repo, post the 2026-05-21 Portkey
pivot. Brings up a standalone Mastio + nginx TLS sidecar + redis +
mock TSA via `docker compose`, then walks 10 scenarios that exercise
the surfaces the public artifact ships: admin bootstrap, agent
enrollment, OPA Data API policy, AI-gateway chat, mTLS egress, audit
chain hashing, RFC 3161 TSA anchoring, offline verifier, multi-worker
chain integrity.

## Philosophy

- **One host dependency**: `docker compose`. No host `python`, no `jq`,
  no `gh`. The smoke image carries its own Python + crypto deps for
  the mock TSA and the OpenAI-compat chat stub.
- **No internet**: the mock TSA is a real RFC 3161 server backed by a
  self-issued ephemeral CA. The AI gateway is mocked. A full run
  completes air-gapped.
- **Built from the worktree**: `docker compose build` uses the repo
  root as context, so the smoke ALWAYS runs against the code the PR
  is about to land — never a stale GHCR pull.
- **Idempotent**: two consecutive `./smoke.sh` runs produce the same
  verdict. `./teardown.sh` is safe to run when nothing is up.
- **Auto-teardown**: `trap teardown EXIT INT TERM` on failure +
  success. `--keep` to disable for inspection.
- **Snapshot on fail**: every nonzero scenario exit dumps `docker
  compose logs`, `compose ps`, `state/`, and the last 50 audit rows
  into `.smoke-fail-<ts>-<scenario>/` BEFORE the teardown wipes the
  stack.

## Quick start

```bash
./test/smoke/smoke.sh                       # full run, sqlite, ~3-5 min
./test/smoke/smoke.sh --pg                  # postgres backend
./test/smoke/smoke.sh --scenario 70         # isolate one scenario (00..NN)
./test/smoke/smoke.sh --keep                # leave stack up after run
./test/smoke/smoke.sh --json out.json       # structured results
./test/smoke/teardown.sh                    # explicit cleanup
```

Pre-PR ritual:

```bash
./test/smoke/smoke.sh && echo OK
```

## Scenarios

| #  | File                          | What it covers |
|----|-------------------------------|----------------|
| 00 | `00_boot.sh`                  | `docker compose build + up --wait`, `/health` answers 200 |
| 10 | `10_admin_bootstrap.sh`       | seeded admin password works, Org CA + `org_id` materialised, `X-Admin-Secret` gate |
| 20 | `20_enroll_agent.sh`          | `POST /v1/admin/agents` mints 2 agent certs; duplicate → 409; wrong secret → 403 |
| 30 | `30_policy_rego.sh`           | `/v1/data/cullis/policy/session` default-allow; unknown OPA path → `{"result": null}`; Rego dashboard route mounted |
| 40 | `40_agent_llm_inference.sh`   | autonomous agent (`pitch-book-builder`) governed LLM inference via default `cullis_native` → native Anthropic dispatch → mock; 503 `provider_sdk_missing` hard-fails (#1005 guard); no-cert → 401 at nginx |
| 50 | `50_mcp_tool_call.sh`         | mTLS-authed `/v1/egress/peers` and `/agents/{id}/public-key`; foreign cert → 401 |
| 60 | `60_audit_chain.sh`           | `audit_log` non-empty, every row has `chain_seq`/`row_hash`, in-process `/proxy/audit/verify` returns `ok: true` |
| 70 | `70_tsa_anchor.sh`            | audit anchor watcher fires within 90 s, persisted token carries `T1\|` magic + sane shape |
| 80 | `80_audit_verify.sh`          | NDJSON export from `audit_log`, standalone `scripts/cullis-audit-verify.py` PASS |
| 90 | `90_multiworker.sh`           | restart with `MASTIO_WORKERS=4`, 50 concurrent admin reads, no `chain_seq` collisions |

Scenario contract:

- Every script is `set -euo pipefail` bash, sources `lib/_common.sh`,
  and exits `0` on PASS, `2` on intentional SKIP, anything else on FAIL.
- Logs go to stderr with the `[NN_what]` prefix.
- Cross-scenario state lives under `state/` (gitignored): admin
  password seed, agent cert PEMs, the exported Org CA, the NDJSON
  audit bundle.

## Adding a scenario

1. Create `scenarios/NN_short_name.sh` (two-digit numeric prefix
   determines order, matching the existing 00..90 cadence).
2. `set -euo pipefail` + `source ../lib/_common.sh` (or `_admin.sh` /
   `_agent.sh` if you need those helpers).
3. Use `log_info / log_pass / log_warn / log_fail` for output, `die
   "..."` for hard failures.
4. Store cross-scenario state via `state_put name value` +
   `state_get name`.
5. For mTLS calls use `curl_mtls <cert> <key> <METHOD> <path> [body]`.
6. For admin calls use `curl_admin <METHOD> <path> [body]` (sets
   `SMOKE_LAST_STATUS` for negative-case assertions).
7. Add at least one negative case where it makes sense (wrong cred,
   wrong shape, wrong cert).
8. Update the table above + the count in `smoke.sh`'s help.

## Backends

`compose.yml` is the base stack. Two overlays:

- `compose.sqlite.yml` — default. Empty file, exists for symmetry.
- `compose.postgres.yml` — `--pg`. Adds a `postgres:16-alpine`
  container, rewrites `MCP_PROXY_DATABASE_URL` + `PROXY_DB_URL` to
  asyncpg URLs.

Mastio's startup checks (orphan-SQLite-vs-Postgres guard, ADR-030
bind-dir chown via `init-permissions`) are exercised on both
backends.

## Mock TSA

`mock-tsa/` is a 200-LOC Python container with two HTTP servers:

- `:2560` — RFC 3161 TSA. Builds a fresh self-issued ECDSA P-256 CA
  at container start, signs a TSA leaf under it, signs every
  `TimeStampReq` with the leaf. The response token parses cleanly
  under `mcp_proxy.audit.tsa_client` and (modulo the open follow-up
  below) `scripts/cullis-audit-verify.py`.
- `:2561` — OpenAI-compatible `/v1/chat/completions` stub. Returns a
  fixed `"smoke-mock-ok"` completion so scenario 40 has a
  deterministic assertion target.

Both ports expose `/health` for compose healthcheck.

## Troubleshooting

**Compose build is slow on first run** — yes, ~2-5 min cold. Warm
rebuilds are <30 s because the cullis-mastio image's layer cache
covers `mcp_proxy/requirements-proxy.txt`.

**Port 19443 is in use** — change `MCP_PROXY_PORT` in `env.smoke`
(and `MCP_PROXY_PROXY_PUBLIC_URL` to match, otherwise DPoP `htu`
mismatch surfaces silently on `/v1/egress/*`).

**Stack starts but scenario fails on TLS** — make sure
`state/nginx-certs/org-ca.crt` was minted on this run; an old
`state/` from a different backend run can leave a stale cert that no
longer matches the new Mastio's Org CA. Run `./teardown.sh` then
retry.

**Scenario 70 times out** — the audit anchor watcher uses leader
election; if the Mastio came up on >1 worker, only one writes
anchors. Check `docker compose logs mcp-proxy | grep
audit_anchor_watcher`.

**Scenario 90 reports `chain_seq` collision** — that's a real bug,
not a smoke artefact. Save the snapshot under `.smoke-fail-*/` and
open an issue with the audit chain logs.

**`docker compose` says "no configuration file"** — you're running
the script with `bash` from the wrong cwd. Always invoke via the
absolute path (`./test/smoke/smoke.sh`) or `cd` to repo root first.

## Open follow-ups (found while writing this)

- `scripts/cullis-audit-verify.py` compares the TSA token's
  `messageImprint` against the bare `row_hash` hex string, but
  `mcp_proxy/audit/tsa_client.py` hashes the row_hash once more
  before sending (so the imprint is `sha256(row_hash)`). The verifier
  needs to mirror that step (or the client needs to drop the extra
  hash). Scenario 80 currently exports only entry rows + chain
  verification; anchor verification is asserted shape-only in
  scenario 70 until this is reconciled.
- The Mastio has no `/v1/admin/audit/export` HTTP endpoint yet —
  scenario 80 synthesizes the NDJSON directly from the database.
  Once an export endpoint lands, switch the scenario to hit it via
  the admin API so the smoke matches the auditor's real workflow.

## Why not `test/nightly/`?

`test/nightly/` predates the Portkey pivot and is wired to compose
services (`broker-ca-init`, `sandbox/proxy-init`) that moved to
`cullis-enterprise`. Refitting it to the public Mastio-only world is
a separate, larger workstream. `test/smoke/` is the green-field
replacement that fits the new shape (one binary, no Court, no
sandbox).
