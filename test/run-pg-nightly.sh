#!/usr/bin/env bash
#
# F0.2 — Postgres binding nightly gate.
#
# Boots the ephemeral Postgres 16 service defined in test/compose-pg.yml,
# exports the URL Cullis Mastio test fixtures consume, and runs the
# postgres-marked subset:
#
#   - test/integration/test_alembic_full_chain_postgres.py
#     (Alembic 0001 → head against asyncpg, append-only trigger,
#      UNIQUE(chain_seq) IntegrityError surface, advisory-lock observability)
#
#   - any future test in test/ that uses ``audit_test_env_pg``
#
# Teardown runs unconditionally (trap EXIT) so a Ctrl-C mid-suite still
# wipes the compose stack — the tmpfs volume in compose-pg.yml means
# state cannot leak into the next run.
#
# Usage:
#   ./test/run-pg-nightly.sh                    # full PG-marked suite
#   ./test/run-pg-nightly.sh -k advisory_lock   # filter
#   KEEP_POSTGRES=1 ./test/run-pg-nightly.sh    # leave service up for triage
#
# Exit codes:
#   0  — all postgres-marked tests passed
#   1  — pytest failure (or docker compose boot failure)
#   2  — environment precondition missing (docker, pytest)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PG_URL="postgresql+asyncpg://cullis:cullis@127.0.0.1:5544/cullis_test"
COMPOSE_FILE="test/compose-pg.yml"
KEEP_POSTGRES="${KEEP_POSTGRES:-0}"

log()  { printf "[run-pg-nightly] %s\n" "$*" >&2; }
fail() { log "ERROR: $*"; exit "${2:-1}"; }

command -v docker >/dev/null  || fail "docker not on PATH" 2
docker compose version >/dev/null 2>&1 || fail "docker compose v2 not available" 2
command -v pytest >/dev/null  || fail "pytest not on PATH" 2

cleanup() {
    if [[ "${KEEP_POSTGRES}" == "1" ]]; then
        log "KEEP_POSTGRES=1 — leaving compose stack up at ${PG_URL}"
        return
    fi
    log "Tearing down ephemeral Postgres"
    docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "Booting Postgres 16 (compose: ${COMPOSE_FILE})"
docker compose -f "${COMPOSE_FILE}" up -d --wait \
    || fail "compose up failed — see 'docker compose -f ${COMPOSE_FILE} logs'"

log "Exporting CULLIS_TEST_PG_URL=${PG_URL}"
export CULLIS_TEST_PG_URL="${PG_URL}"

log "Running postgres-marked subset"
# -n 0 because the integration tests recreate ``public`` between cases;
# parallel workers would race on schema cleanup. The audit_test_env_pg
# fixture uses worker-scoped SCHEMAs so unit tests can re-enable -n auto
# once they exist — gate this when adding them.
pytest -m postgres -n 0 -v "$@"
