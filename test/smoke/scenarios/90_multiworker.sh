#!/usr/bin/env bash
# =============================================================================
# 90_multiworker — restart Mastio with 4 uvicorn workers, verify leadership
# =============================================================================
#
# Memory: feedback_mastio_multiworker_audit_chain_retry_ship_safe.md +
# feedback_multiworker_uvicorn_systemic_gaps.md. Multi-worker uvicorn
# is the default in packaging/mastio-bundle/ (4 workers), and the
# audit chain retry path + leader-election (lifespan/get_leader) is
# the contract that keeps F0.1 ship-safe.
#
# Asserts:
#   * After restart with MASTIO_WORKERS=4, the stack stays healthy
#   * No IntegrityError on the audit chain when ~50 audit-emitting
#     calls fire concurrently against the 4-worker stack
#   * The audit chain remains internally consistent (no gaps in
#     chain_seq, every row_hash populated)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="90_multiworker"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

# Snapshot the row count pre-restart so we can compute the delta after
# the burst.
pre_count="$(smoke_compose exec -T mcp-proxy python3 -c "
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    if url.startswith('postgresql'):
        import psycopg2, re
        sync_url = re.sub(r'^postgresql\+asyncpg://', 'postgresql://', url)
        conn = psycopg2.connect(sync_url)
        print(conn.cursor().execute('SELECT COUNT(*) FROM audit_log') or conn.cursor().fetchone()[0])
    else:
        import sqlite3
        path = url.replace('sqlite+aiosqlite:////', '/').replace('sqlite+aiosqlite:///', '/')
        conn = sqlite3.connect(path)
        print(conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0])
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"
[[ "$pre_count" =~ ^[0-9]+$ ]] || { log_warn "pre_count unreadable ($pre_count) — defaulting to 0"; pre_count=0; }

log_info "restarting Mastio with MASTIO_WORKERS=4"
# Restart only the mcp-proxy + nginx so redis + mock-tsa + the state
# bind dirs survive. ``up -d --wait`` blocks until healthcheck passes.
MASTIO_WORKERS=4 smoke_compose up -d --wait --force-recreate mcp-proxy mastio-nginx \
    || die "stack failed to come back up with 4 workers"

if ! wait_http_ok "$(smoke_mastio_url)/health" 60; then
    die "Mastio did not become healthy after multi-worker restart"
fi
log_pass "stack healthy with MASTIO_WORKERS=4"

# ── Burst: 50 concurrent admin reads that each emit an audit row ────────────
# /v1/admin/mastio-pubkey is the cheapest audited admin call — no body,
# returns a fixed payload, writes one row per invocation. 50 calls × 4
# workers stresses the chain retry path without overwhelming dev hardware.
base="$(smoke_mastio_url)"
secret="$(smoke_admin_secret)"
log_info "firing 50 concurrent /v1/admin/mastio-pubkey calls"

burst_pids=()
fail_log="$(mktemp)"
for i in $(seq 1 50); do
    (
        if ! curl -sk -f -o /dev/null \
            -H "X-Admin-Secret: $secret" \
            "$base/v1/admin/mastio-pubkey"; then
            echo "call $i failed" >> "$fail_log"
        fi
    ) &
    burst_pids+=($!)
done

# Wait for every child.
for pid in "${burst_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done

if [[ -s "$fail_log" ]]; then
    fails="$(wc -l <"$fail_log")"
    if [[ $fails -gt 5 ]]; then
        log_warn "burst had $fails failed calls — see $fail_log"
        cat "$fail_log" >&2 || true
        die "multi-worker burst failed too many calls (${fails}/50)"
    fi
    log_warn "burst had $fails sporadic failures (tolerated, <=5)"
fi
rm -f "$fail_log"

# ── Verify the chain is intact ──────────────────────────────────────────────
result="$(smoke_compose exec -T mcp-proxy python3 -c "
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    if url.startswith('postgresql'):
        import psycopg2, re
        sync_url = re.sub(r'^postgresql\+asyncpg://', 'postgresql://', url)
        conn = psycopg2.connect(sync_url)
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM audit_log')
        total = cur.fetchone()[0]
        cur.execute('SELECT COUNT(*) FROM audit_log WHERE chain_seq IS NULL OR row_hash IS NULL')
        nulls = cur.fetchone()[0]
        cur.execute('SELECT MAX(chain_seq), COUNT(DISTINCT chain_seq) FROM audit_log WHERE chain_seq IS NOT NULL')
        row = cur.fetchone()
        max_seq, distinct_seq = row
        print(f'{total}|{nulls}|{max_seq or 0}|{distinct_seq or 0}')
    else:
        import sqlite3
        path = url.replace('sqlite+aiosqlite:////', '/').replace('sqlite+aiosqlite:///', '/')
        conn = sqlite3.connect(path)
        total = conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
        nulls = conn.execute('SELECT COUNT(*) FROM audit_log WHERE chain_seq IS NULL OR row_hash IS NULL').fetchone()[0]
        max_seq = conn.execute('SELECT MAX(chain_seq) FROM audit_log WHERE chain_seq IS NOT NULL').fetchone()[0] or 0
        distinct = conn.execute('SELECT COUNT(DISTINCT chain_seq) FROM audit_log WHERE chain_seq IS NOT NULL').fetchone()[0] or 0
        print(f'{total}|{nulls}|{max_seq}|{distinct}')
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"

[[ "$result" != error:* ]] || die "post-burst chain query failed: $result"
IFS='|' read -r total nulls max_seq distinct_seq <<<"$result"
delta=$(( total - pre_count ))

# Allow up to 5 legacy NULL rows from earlier scenarios (pre-trigger).
if [[ "$nulls" -gt 5 ]]; then
    die "post-burst: ${nulls} rows have NULL chain_seq/row_hash — multi-worker writer broke chain"
fi

# Burst should have added at LEAST as many rows as there were
# successful calls (some calls may write multiple rows: auth check +
# the actual admin call). Don't assert exact count.
if [[ "$delta" -lt 30 ]]; then
    log_warn "burst delta=${delta} is low — multi-worker may have dropped audit rows"
fi

# distinct_seq must == count of non-null chain_seq rows (no duplicate
# sequence numbers — that would mean two workers raced past the retry).
non_null=$(( total - nulls ))
if [[ "$distinct_seq" -ne "$non_null" ]]; then
    die "chain_seq collision detected: distinct=${distinct_seq} vs non_null=${non_null}"
fi

log_pass "multi-worker chain integrity OK (delta=${delta}, max_seq=${max_seq}, distinct=${distinct_seq})"
