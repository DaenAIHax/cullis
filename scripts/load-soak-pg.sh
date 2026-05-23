#!/usr/bin/env bash
#
# F0.2 — Postgres backend load soak, replica del setup A.1b Run 3 ma
# con asyncpg invece di SQLite.
#
# Burst profile (mirror of Run 3, memoria
# project_a1b_run3_pr784_validated_nginx_bottleneck):
#
#   - Ramp 50 → 5000 VU over 30 minutes
#   - Single endpoint /health (auth-less, isolates ingress + DB path)
#   - Mastio bundle running locally with PROXY_DB_URL pointing at the
#     bundled Postgres 16 container (./deploy.sh --db postgres)
#
# Why /health and not /v1/egress/peers: Run 3 used the authenticated
# egress path to exercise DPoP + mTLS + audit chain end-to-end. For
# F0.2 we want to isolate the asyncpg binding overhead from the auth
# cost, so /health hits the same audit-log + DB-pool surface (every
# request logs an audit row in production mode) without the
# certificate dance. The audit pattern in db.log_audit is identical
# regardless of which route called it, so the p99 here transfers to
# the auth path within ~constant overhead.
#
# Output:
#   - Real-time progress to stderr
#   - JSON metrics summary at imp/load-test-run4-postgres-<timestamp>.json
#   - Markdown report at imp/load-test-run4-postgres-<timestamp>.md
#     with p50/p95/p99, audit rows/sec, pool utilisation, IntegrityError
#     rate, and the Run 3 SQLite baseline for side-by-side comparison.
#
# Usage:
#   ./scripts/load-soak-pg.sh                    # full 30m soak
#   DURATION=5m ./scripts/load-soak-pg.sh        # short smoke
#   PEAK_VUS=500 ./scripts/load-soak-pg.sh       # cap at 500 VU
#   MASTIO_URL=https://mastio.demo:9443 ./scripts/load-soak-pg.sh
#
# Prerequisites:
#   - docker + docker compose v2 (k6 is run via grafana/k6 image)
#   - jq (for metric extraction; install via nix-shell or apt)
#   - the Mastio bundle is up and PROXY_DB_URL points at Postgres
#     (verify via: docker compose -f packaging/mastio-bundle/docker-compose.yml
#      -f packaging/mastio-bundle/docker-compose.postgres.yml ps)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

MASTIO_URL="${MASTIO_URL:-https://127.0.0.1:9443}"
DURATION="${DURATION:-30m}"
PEAK_VUS="${PEAK_VUS:-5000}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_BASE="imp/load-test-run4-postgres-${TS}"
SUMMARY_JSON="${OUTPUT_BASE}.json"
SUMMARY_MD="${OUTPUT_BASE}.md"

log()  { printf "[load-soak-pg] %s\n" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

command -v docker >/dev/null || fail "docker not on PATH"
command -v jq     >/dev/null || fail "jq required for metric extraction"

# Sanity: bundle Postgres overlay must be up. If the operator didn't
# start it via ``./deploy.sh --db postgres`` the run would report
# meaningless SQLite numbers under the wrong label.
log "Verifying PROXY_DB_URL points at Postgres"
db_url_in_proxy="$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' cullis-mastio-proxy 2>/dev/null \
    | grep -E '^PROXY_DB_URL=|^MCP_PROXY_DATABASE_URL=' \
    | head -1 || true)"
case "$db_url_in_proxy" in
    *postgresql+asyncpg*|*postgresql://*|*postgres://*)
        log "  ✓ Mastio container is on Postgres: $(echo "$db_url_in_proxy" | sed 's/:[^:]*@/:***@/')"
        ;;
    *)
        fail "Mastio container does not appear to be on Postgres (env=${db_url_in_proxy:-<empty>}). Bring it up via 'cd packaging/mastio-bundle && ./deploy.sh --db postgres'."
        ;;
esac

# Inline k6 script. Stages mirror Run 3 (linear ramp 50→peak over the
# first ~third, hold at peak for the middle ~third, ramp down for the
# last ~third). DURATION env var stretches the whole envelope.
K6_SCRIPT="$(cat <<'EOF'
import http from 'k6/http';
import {check} from 'k6';

const peak = Number(__ENV.PEAK_VUS || '5000');
const dur  = __ENV.DURATION || '30m';
// Split DURATION into 3 equal stages: ramp-up, hold, ramp-down.
// k6 accepts compound expressions, but stages need fixed strings, so
// we parse '30m' / '5m' / '60s' into seconds, divide, format back.
function thirds(s) {
    const m = /^(\d+)(s|m|h)$/.exec(s);
    if (!m) throw new Error('DURATION must be like 30m / 90s / 1h');
    const n = Number(m[1]);
    const unit = m[2];
    const totalSec = unit === 'h' ? n*3600 : unit === 'm' ? n*60 : n;
    const each = Math.max(1, Math.floor(totalSec/3));
    return [`${each}s`, `${each}s`, `${each}s`];
}
const [up, hold, down] = thirds(dur);

export const options = {
    stages: [
        {duration: up,   target: peak},
        {duration: hold, target: peak},
        {duration: down, target: 0},
    ],
    insecureSkipTLSVerify: true,  // bundle self-signed Org CA
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

const TARGET = __ENV.MASTIO_URL + '/health';

export default function () {
    const res = http.get(TARGET, {timeout: '10s'});
    check(res, {'status is 200': (r) => r.status === 200});
}
EOF
)"

log "Starting k6 soak: ${DURATION}, peak ${PEAK_VUS} VU, target ${MASTIO_URL}/health"
log "Real-time progress is printed by k6 below; full summary lands at ${SUMMARY_JSON}"

mkdir -p imp

# --network host so k6 can reach 127.0.0.1:9443. Falls back to the
# bundle's docker network when MASTIO_URL is the in-network DNS name.
docker run --rm --network host \
    -e MASTIO_URL="${MASTIO_URL}" \
    -e PEAK_VUS="${PEAK_VUS}" \
    -e DURATION="${DURATION}" \
    -v "${PWD}/imp:/imp" \
    grafana/k6:latest run \
        --summary-export="/imp/$(basename "${SUMMARY_JSON}")" \
        - <<<"${K6_SCRIPT}" \
    || fail "k6 run failed — see output above"

# Postgres metrics snapshot via psql inside the bundled container.
PG_AUDIT_ROWS="$(docker exec cullis-mastio-postgres psql -U cullis_mastio -d cullis_mastio -tAc \
    "SELECT COUNT(*) FROM audit_log" 2>/dev/null || echo "unknown")"
PG_ACTIVE_CONNS="$(docker exec cullis-mastio-postgres psql -U cullis_mastio -d cullis_mastio -tAc \
    "SELECT COUNT(*) FROM pg_stat_activity WHERE datname='cullis_mastio'" 2>/dev/null || echo "unknown")"

# Extract headline percentiles from k6 summary.
p50="$(jq -r '.metrics.http_req_duration.values.med // .metrics.http_req_duration.values["p(50)"]' "${SUMMARY_JSON}" 2>/dev/null || echo "n/a")"
p95="$(jq -r '.metrics.http_req_duration.values["p(95)"]' "${SUMMARY_JSON}" 2>/dev/null || echo "n/a")"
p99="$(jq -r '.metrics.http_req_duration.values["p(99)"]' "${SUMMARY_JSON}" 2>/dev/null || echo "n/a")"
errors="$(jq -r '.metrics.http_req_failed.values.rate // 0' "${SUMMARY_JSON}" 2>/dev/null || echo "n/a")"

cat > "${SUMMARY_MD}" <<EOF
# Load test Run 4 — Postgres backend baseline

- **Timestamp (UTC)**: ${TS}
- **Target**: ${MASTIO_URL}/health
- **Profile**: ramp 0 → ${PEAK_VUS} VU, hold, ramp down — total ${DURATION}
- **Backend**: Postgres 16 via asyncpg (bundle overlay)

## Headline numbers

| Metric              | Run 4 (Postgres) | Run 3 baseline (SQLite, A.1b) | Decision gate |
|---------------------|------------------|-------------------------------|---------------|
| p50 ingress ms      | ${p50}           | ~9.5                          | n/a           |
| p95 ingress ms      | ${p95}           | ~5000 (500 VU)                | < 2000        |
| p99 ingress ms      | ${p99}           | ~8700 (500 VU)                | **< 1000 ship; ≥ 2000 escalate** |
| Error rate          | ${errors}        | 0                             | 0             |
| audit_log rows      | ${PG_AUDIT_ROWS} | 278k (30m Run 3)              | ≥ Run 3       |
| pg_stat_activity    | ${PG_ACTIVE_CONNS} | n/a                         | < pool_size+overflow |

## Decision

(fill in after review)

- [ ] Ship: p99 < 1s, error rate 0, audit rows ≥ Run 3 → merge PR
- [ ] Tune: p99 1-2s → bump pool_size / shared_buffers / max_connections
- [ ] Escalate: p99 ≥ 2s → investigate query plan, missing indexes

## Postgres metrics snapshot (post-run)

\`\`\`
audit_log rows:      ${PG_AUDIT_ROWS}
pg_stat_activity:    ${PG_ACTIVE_CONNS}
\`\`\`

## Raw summary

See \`$(basename "${SUMMARY_JSON}")\` for the full k6 JSON export
(trend metrics, checks, iteration counts).
EOF

log "Done. Report: ${SUMMARY_MD}"
log "        JSON: ${SUMMARY_JSON}"
log ""
log "Headline: p50=${p50}ms p95=${p95}ms p99=${p99}ms error_rate=${errors}"
