#!/usr/bin/env bash
# Nightly stress test driver. Entry point for the full | go | chaos | report cycle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

# shellcheck disable=SC1091
source ./config.env

COMPOSE="docker compose"

# Host-side Python used by smoke.py / workload drivers. Prefer the repo's
# .venv (where cullis_sdk is installed in editable mode) over the system
# python3/python.
pick_python() {
    if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
        echo "$REPO_ROOT/.venv/bin/python"; return
    fi
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$cmd"; return
        fi
    done
    echo "[nightly] no python interpreter found (looked for .venv, python3, python)" >&2
    exit 1
}
PY="$(pick_python)"

usage() {
    cat <<'EOF'
Usage: nightly.sh <command>

Commands:
  full      Bring the lean stack up (Court + 2 Mastio + bootstrap + BYOCA N agents).
  down      Tear down containers and volumes, wipe state/.
  status    docker compose ps for the stack.
  smoke     Run smoke.py to verify N/N agents can log in.
  logs [svc]  Tail compose logs (optionally for one service).
  go        [PR 2] Start workload drivers (spammer/sessionator/chatter).
  chaos     [PR 3] Run fault injection sequence.
  report    [PR 3] Render markdown report from collected metrics.

Env vars (see config.env):
  AGENTS_PER_ORG  (default 10)   ADMIN_SECRET
  PKI_KEY_TYPE    (default ec)   COURT_URL / MASTIO_A_URL / MASTIO_B_URL
EOF
}

cmd_full() {
    echo "[nightly] bringing up lean stack (agents_per_org=${AGENTS_PER_ORG})"
    mkdir -p state logs reports
    AGENTS_PER_ORG="$AGENTS_PER_ORG" \
    PKI_KEY_TYPE="$PKI_KEY_TYPE" \
    ADMIN_SECRET="$ADMIN_SECRET" \
    $COMPOSE up -d --wait

    # --wait only blocks on services with healthchecks. bootstrap-mastio is
    # restart:no with no healthcheck, so poll its exit code + the sentinel
    # file it leaves behind before handing back to the user.
    local deadline=$(( $(date +%s) + 180 ))
    while (( $(date +%s) < deadline )); do
        local state
        state="$($COMPOSE ps --format '{{.Service}} {{.State}} {{.ExitCode}}' \
                 | awk '$1=="bootstrap-mastio" {print $2,$3}')"
        if [[ "$state" == "exited 0" ]]; then
            break
        fi
        if [[ "$state" == "exited"* ]]; then
            echo "[nightly] bootstrap-mastio failed ($state) — check 'nightly.sh logs bootstrap-mastio'" >&2
            exit 1
        fi
        sleep 2
    done
    if [[ ! -f state/bootstrap.done ]]; then
        echo "[nightly] bootstrap.done sentinel missing after 180s" >&2
        exit 1
    fi
    echo "[nightly] stack up — run './nightly.sh smoke' to verify agents"
}

cmd_down() {
    echo "[nightly] tearing down stack + volumes + state"
    $COMPOSE down -v --remove-orphans
    rm -rf state/* logs/* 2>/dev/null || true
    echo "[nightly] clean"
}

cmd_status() {
    $COMPOSE ps
}

cmd_smoke() {
    if [[ ! -f state/bootstrap.done ]]; then
        echo "[nightly] state/bootstrap.done missing — run './nightly.sh full' first" >&2
        exit 1
    fi
    "$PY" "$SCRIPT_DIR/smoke.py"
}

cmd_logs() {
    if [[ $# -eq 0 ]]; then
        $COMPOSE logs --tail=200 -f
    else
        $COMPOSE logs --tail=200 -f "$@"
    fi
}

cmd_not_implemented() {
    local name="$1"; shift
    echo "[nightly] '$name' is not implemented in this PR — tracked for follow-up" >&2
    exit 2
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

sub="$1"; shift || true
case "$sub" in
    full)      cmd_full "$@" ;;
    down)      cmd_down "$@" ;;
    status)    cmd_status "$@" ;;
    smoke)     cmd_smoke "$@" ;;
    logs)      cmd_logs "$@" ;;
    go)        cmd_not_implemented "go" "$@" ;;
    chaos)     cmd_not_implemented "chaos" "$@" ;;
    report)    cmd_not_implemented "report" "$@" ;;
    -h|--help|help) usage ;;
    *) echo "unknown command: $sub" >&2; usage; exit 1 ;;
esac
