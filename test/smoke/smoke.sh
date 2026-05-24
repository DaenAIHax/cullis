#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — entrypoint
# =============================================================================
#
# Pre-PR gate + HN signal for the public Mastio + SDK repo. Runs the
# canonical scenarios under scenarios/ against a freshly built Mastio +
# nginx sidecar + redis + mock TSA stack.
#
# One host dependency: ``docker compose``. No host python, no jq, no
# gh. The smoke image carries everything it needs (rfc3161-client,
# cryptography, asn1crypto) for the mock TSA + chat stub.
#
# Usage:
#   ./test/smoke/smoke.sh                  # full, sqlite, single worker
#   ./test/smoke/smoke.sh --pg             # postgres backend
#   ./test/smoke/smoke.sh --scenario 70    # isolate one scenario
#   ./test/smoke/smoke.sh --keep           # leave the stack up on exit
#   ./test/smoke/smoke.sh --json out.json  # write structured results
#   ./test/smoke/smoke.sh --help
#
# Exit codes:
#   0  — all scenarios pass
#   1  — at least one scenario failed (snapshot under .smoke-fail-*/)
#   2  — usage error
# =============================================================================
set -euo pipefail

SMOKE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/_common.sh
source "$SMOKE_ROOT/lib/_common.sh"

SCENARIO_TAG="smoke"

# ── arg parsing ─────────────────────────────────────────────────────────────

BACKEND="sqlite"
ONLY_SCENARIO=""
KEEP_STACK=0
JSON_OUT=""

print_help() {
    cat <<'EOF'
Usage: ./test/smoke/smoke.sh [OPTIONS]

Runs the canonical Cullis Mastio + SDK smoke scenarios end-to-end.

Options:
  --pg                 Use Postgres 16 instead of the default SQLite.
  --scenario <NN>      Run only scenarios/<NN>_*.sh (00..90).
                       Earlier scenarios still bring the stack up.
  --keep               Skip teardown on exit (stack stays up for inspection).
  --json <path>        Write a structured result array to <path>.
  --help, -h           Show this help.

Examples:
  ./test/smoke/smoke.sh                          # full run, sqlite
  ./test/smoke/smoke.sh --pg                     # postgres backend
  ./test/smoke/smoke.sh --scenario 70            # isolate TSA scenario
  ./test/smoke/smoke.sh --keep                   # leave stack up
  ./test/smoke/smoke.sh --json /tmp/smoke.json   # machine-readable output
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pg)         BACKEND="postgres"; shift ;;
        --scenario)   shift; ONLY_SCENARIO="$1"; shift ;;
        --scenario=*) ONLY_SCENARIO="${1#--scenario=}"; shift ;;
        --keep)       KEEP_STACK=1; shift ;;
        --json)       shift; JSON_OUT="$1"; shift ;;
        --json=*)     JSON_OUT="${1#--json=}"; shift ;;
        --help|-h)    print_help; exit 0 ;;
        *)
            echo "[smoke] unknown argument: $1" >&2
            print_help >&2
            exit 2
            ;;
    esac
done

# Backend → compose overlay path.
case "$BACKEND" in
    sqlite)   SMOKE_COMPOSE_OVERLAY="$SMOKE_ROOT/compose.sqlite.yml" ;;
    postgres) SMOKE_COMPOSE_OVERLAY="$SMOKE_ROOT/compose.postgres.yml" ;;
    *)
        echo "[smoke] unknown backend: $BACKEND" >&2
        exit 2
        ;;
esac
export SMOKE_BACKEND="$BACKEND"
export SMOKE_COMPOSE_OVERLAY

# ── teardown trap ───────────────────────────────────────────────────────────

_teardown_on_exit() {
    local rc=$?
    if [[ $KEEP_STACK -eq 1 ]]; then
        log_warn "--keep set — leaving stack up. tear down with: ./test/smoke/teardown.sh"
        exit $rc
    fi
    log_info "running teardown (exit_code=$rc)"
    bash "$SMOKE_ROOT/teardown.sh" >/dev/null 2>&1 || true
    exit $rc
}
trap _teardown_on_exit EXIT INT TERM

# ── locate scenarios ────────────────────────────────────────────────────────

mapfile -t ALL_SCENARIOS < <(
    find "$SMOKE_ROOT/scenarios" -maxdepth 1 -type f -name '[0-9][0-9]_*.sh' \
        | sort
)

if [[ ${#ALL_SCENARIOS[@]} -eq 0 ]]; then
    log_fail "no scenarios found under scenarios/"
    exit 1
fi

# Filter to a single scenario when --scenario is set. Upstream
# scenarios still run because most negative cases depend on the earlier
# state (admin password, enrolled agents). The filter only TRUNCATES
# the tail at the matching scenario — same shape as nightly's chaos
# profiles where ``light`` is a prefix of ``heavy``.
RUN_SCENARIOS=()
for f in "${ALL_SCENARIOS[@]}"; do
    RUN_SCENARIOS+=("$f")
    if [[ -n "$ONLY_SCENARIO" ]]; then
        cur_num="$(basename "$f" | cut -c1-2)"
        if [[ "$cur_num" == "$ONLY_SCENARIO" ]]; then
            break
        fi
    fi
done

if [[ -n "$ONLY_SCENARIO" ]]; then
    final_num="$(basename "${RUN_SCENARIOS[-1]}" | cut -c1-2)"
    if [[ "$final_num" != "$ONLY_SCENARIO" ]]; then
        echo "[smoke] no scenario matches --scenario ${ONLY_SCENARIO}" >&2
        exit 2
    fi
fi

# Always pre-create state dir + .gitkeep so the worktree stays clean.
mkdir -p "$SMOKE_ROOT/state"

# ── execute scenarios ──────────────────────────────────────────────────────

declare -a RESULT_JSON
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

START_WALL=$(date +%s)

for script in "${RUN_SCENARIOS[@]}"; do
    name="$(basename "$script" .sh)"
    log_info "──────────── scenario ${name} ────────────"
    scenario_start=$(date +%s%3N 2>/dev/null || date +%s000)

    set +e
    bash "$script"
    rc=$?
    set -e

    scenario_end=$(date +%s%3N 2>/dev/null || date +%s000)
    duration_ms=$(( scenario_end - scenario_start ))

    case $rc in
        0)
            PASS_COUNT=$(( PASS_COUNT + 1 ))
            status="pass"
            log_info "scenario ${name}: PASS (${duration_ms} ms)"
            ;;
        2)
            # Convention: exit 2 = scenario skipped a non-blocking
            # dependency. Counted as pass for the overall verdict.
            SKIP_COUNT=$(( SKIP_COUNT + 1 ))
            status="skip"
            log_warn "scenario ${name}: SKIP (${duration_ms} ms)"
            ;;
        *)
            FAIL_COUNT=$(( FAIL_COUNT + 1 ))
            status="fail"
            log_fail "scenario ${name}: FAIL rc=${rc} (${duration_ms} ms)"
            snapshot_on_fail "${name}"
            ;;
    esac

    RESULT_JSON+=("{\"scenario\":\"${name}\",\"status\":\"${status}\",\"duration_ms\":${duration_ms},\"rc\":${rc}}")

    # Bail on first failure when running all scenarios — downstream
    # scenarios depend on the earlier state and would all flap as a
    # cascading consequence. Negative cases that EXPECT to fail
    # should handle the failure internally and exit 0.
    if [[ $rc -ne 0 && $rc -ne 2 ]]; then
        break
    fi
done

END_WALL=$(date +%s)
WALL_SECONDS=$(( END_WALL - START_WALL ))

# ── summary ────────────────────────────────────────────────────────────────

echo
echo "──────────────────────────────────────────────────"
echo "  Backend:   ${BACKEND}"
echo "  Wall:      ${WALL_SECONDS}s"
echo "  Scenarios: ${#RUN_SCENARIOS[@]} (pass=${PASS_COUNT} skip=${SKIP_COUNT} fail=${FAIL_COUNT})"
echo "──────────────────────────────────────────────────"

if [[ -n "$JSON_OUT" ]]; then
    {
        printf '[\n'
        first=1
        for entry in "${RESULT_JSON[@]}"; do
            if [[ $first -eq 1 ]]; then
                printf '  %s' "$entry"
                first=0
            else
                printf ',\n  %s' "$entry"
            fi
        done
        printf '\n]\n'
    } > "$JSON_OUT"
    log_info "results JSON: ${JSON_OUT}"
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
