#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis demo — single-host stack + scripted conversation, ready for live demos
# ═══════════════════════════════════════════════════════════════════════════════
#
# Boots the full Cullis architecture (broker + 2 MCP proxies + postgres + redis),
# provisions two organizations and one agent each, and gives you a one-shot
# command to play the buyer→seller conversation back to an audience.
#
# Sub-commands:
#
#   ./deploy_demo.sh up       Build, start, and bootstrap the stack.
#                             After this returns, the demo is ready to run.
#
#   ./deploy_demo.sh send     Replay the buyer→seller "order check" conversation
#                             once. Safe to run repeatedly.
#
#   ./deploy_demo.sh status   Show container state.
#   ./deploy_demo.sh logs     Follow the broker + proxy logs.
#   ./deploy_demo.sh down     Stop everything AND remove volumes (demo is
#                             ephemeral, keeps host clean for other stacks).
#   ./deploy_demo.sh nuke     down + clear demo state file + fixtures.
#
# Endpoints exposed on the host:
#   broker dashboard       http://localhost:8800/dashboard
#                          First boot: you'll be asked to create a password
#                          (enter + confirm). No default credentials.
#   proxy alpha dashboard  http://localhost:9800/proxy
#   proxy beta  dashboard  http://localhost:9801/proxy
#                          Same first-boot password flow for each proxy.
#
# Ports are deliberately in the 88xx/98xx range so the demo never collides
# with the dev stack (8xxx/9xxx) or the e2e test stack (18xxx/19xxx).
#
# This is a DEMO stack — no TLS, no Vault, no production hardening. Do not
# expose any of these ports outside localhost.
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$SCRIPT_DIR/scripts/demo"
COMPOSE_FILE="$DEMO_DIR/docker-compose.demo.yml"

# Distinct compose project name isolates the demo stack from the broker
# (deploy_broker.sh → cullis-broker) and the proxy (deploy_proxy.sh →
# cullis-proxy). Without this, a fresh user running demo then broker on the
# same host collides on docker volumes like postgres_data (see shake-out
# finding P0-03): the broker inherits the demo's stale postgres password and
# crashes with an opaque asyncpg InvalidPasswordError. Exporting the variable
# also makes ad-hoc `docker compose -f ...` calls pick up the same project.
export COMPOSE_PROJECT_NAME="cullis-demo"
PROJECT_NAME="cullis-demo"
ORCHESTRATOR="$DEMO_DIR/orchestrate.py"

SENDER_SCRIPT="$DEMO_DIR/sender.py"
CHECKER_SCRIPT="$DEMO_DIR/checker.py"
CHECKER_PID_FILE="$DEMO_DIR/.checker.pid"
CHECKER_LOG_FILE="$DEMO_DIR/.checker.log"

# ── Colors ───────────────────────────────────────────────────────────────────
BOLD='\033[1m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
CYAN='\033[36m'
GRAY='\033[90m'
RESET='\033[0m'

ok()   { printf "  ${GREEN}✓${RESET}  %s\n" "$1"; }
warn() { printf "  ${YELLOW}!${RESET}  %s\n" "$1"; }
err()  { printf "  ${RED}✗${RESET}  %s\n" "$1"; }
die()  { err "$1"; exit 1; }
step() { printf "\n${BOLD}── %s ──${RESET}\n" "$1"; }

# ── Prerequisites ────────────────────────────────────────────────────────────
require_prereqs() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed"
    docker info >/dev/null 2>&1 || die "docker daemon is not reachable"

    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE="docker-compose"
    else
        die "neither 'docker compose' (plugin) nor 'docker-compose' is available"
    fi

    # Pick a Python: prefer the repo .venv so httpx is already there.
    if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
        PYTHON="$SCRIPT_DIR/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON="python"
    else
        die "python (3.x) is required for the demo orchestrator"
    fi

    if ! "$PYTHON" -c "import httpx" >/dev/null 2>&1; then
        die "python module 'httpx' is missing — install with: $PYTHON -m pip install httpx"
    fi
}

# Fail fast if any of the demo ports (8800 / 9800 / 9801) are already
# bound by something else — typically the developer's own dev compose
# stack. Without this check `docker compose up` half-creates the network
# and silently leaves a stack in a broken state.
require_demo_ports_free() {
    local conflicts=()
    for port in 8800 9800 9801; do
        # Look at containers from any project that publish this host port,
        # excluding our own demo project so re-running `up` is idempotent.
        local hit
        hit="$(docker ps --format '{{.Names}}\t{{.Ports}}' \
                 | awk -v p=":${port}->" '$0 ~ p {print $1}' \
                 | grep -v '^cullis-demo-' || true)"
        if [[ -n "$hit" ]]; then
            conflicts+=("$port → $hit")
        fi
    done
    if (( ${#conflicts[@]} > 0 )); then
        err "the following demo ports are already in use:"
        for c in "${conflicts[@]}"; do
            printf "    %s\n" "$c"
        done
        printf "  ${GRAY}stop the conflicting container(s), or run your dev stack down,${RESET}\n"
        printf "  ${GRAY}e.g.  docker stop <name>  /  docker compose down${RESET}\n"
        exit 1
    fi
}

compose() {
    $COMPOSE --project-name "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

orchestrate() {
    "$PYTHON" "$ORCHESTRATOR" "$@"
}

# ── Checker daemon lifecycle ─────────────────────────────────────────────────
#
# checker.py is a long-running Python script (NOT a docker container) that
# polls proxy-beta on the host. It runs in the background and writes its
# stdout to .checker.log. PID is tracked in .checker.pid so we can stop it
# cleanly on `down` / `nuke`.

checker_running() {
    if [[ -f "$CHECKER_PID_FILE" ]]; then
        local pid
        pid="$(cat "$CHECKER_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        rm -f "$CHECKER_PID_FILE"
    fi
    return 1
}

start_checker() {
    if checker_running; then
        ok "checker.py already running (pid $(cat "$CHECKER_PID_FILE"))"
        return 0
    fi
    : > "$CHECKER_LOG_FILE"
    nohup "$PYTHON" "$CHECKER_SCRIPT" >> "$CHECKER_LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$CHECKER_PID_FILE"
    # give the daemon a moment to fail fast (missing state file, syntax, ...)
    sleep 0.4
    if ! kill -0 "$pid" 2>/dev/null; then
        err "checker.py exited immediately — see $CHECKER_LOG_FILE"
        rm -f "$CHECKER_PID_FILE"
        return 1
    fi
    ok "checker.py started in background (pid $pid)"
    printf "  ${GRAY}log: tail -f scripts/demo/.checker.log${RESET}\n"
}

stop_checker() {
    if ! checker_running; then
        return 0
    fi
    local pid
    pid="$(cat "$CHECKER_PID_FILE")"
    kill "$pid" 2>/dev/null || true
    # wait up to 3s for graceful shutdown
    for _ in 1 2 3 4 5 6; do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$CHECKER_PID_FILE"
    ok "checker.py stopped"
}

# ── Sub-commands ─────────────────────────────────────────────────────────────

cmd_up() {
    require_prereqs
    require_demo_ports_free

    step "Preparing broker CA fixture"
    orchestrate fixture
    ok "broker CA copied into scripts/demo/.fixtures/broker_certs"

    step "Building images"
    compose build broker proxy-alpha proxy-beta

    step "Starting stack"
    compose up -d
    ok "containers started"

    step "Bootstrapping orgs and agents"
    # The orchestrator waits for /readyz, generates invite tokens, registers
    # both orgs, approves them, creates one agent per org with capability
    # 'order.check', and persists the API keys to scripts/demo/.state.json.
    orchestrate init

    step "Starting checker daemon"
    start_checker

    # Architecture tour: dashboards + credentials
    orchestrate info

    printf "  ${BOLD}Trigger the routing:${RESET}\n"
    printf "    ${CYAN}python scripts/demo/sender.py${RESET}      ${GRAY}# fires one check${RESET}\n"
    printf "    ${CYAN}./deploy_demo.sh send${RESET}              ${GRAY}# same thing, shorter${RESET}\n"
    printf "    ${CYAN}./deploy_demo.sh checker-log${RESET}       ${GRAY}# follow what the checker is hearing${RESET}\n\n"
}

cmd_send() {
    require_prereqs
    if ! checker_running; then
        warn "checker.py is NOT running — sender will time out at step 2"
        warn "  start it with: ./deploy_demo.sh up   (or run scripts/demo/checker.py by hand)"
    fi
    "$PYTHON" "$SENDER_SCRIPT"
}

cmd_checker_log() {
    if [[ ! -f "$CHECKER_LOG_FILE" ]]; then
        die "no checker log yet — run ./deploy_demo.sh up first"
    fi
    tail -f "$CHECKER_LOG_FILE"
}

cmd_info() {
    require_prereqs
    orchestrate info
}

cmd_status() {
    require_prereqs
    compose ps
}

cmd_logs() {
    require_prereqs
    compose logs -f --tail=100 broker proxy-alpha proxy-beta
}

cmd_down() {
    require_prereqs
    step "Stopping checker daemon"
    stop_checker
    # Demo is intentionally ephemeral: we remove the postgres/redis volumes on
    # `down` so a subsequent broker deploy on the same host can't inherit a
    # stale password from this stack (shake-out P0-03). For stop-without-wipe,
    # use `docker compose --project-name cullis-demo stop` directly.
    step "Stopping containers + removing volumes (demo is ephemeral)"
    compose down -v --remove-orphans
    ok "stack stopped and volumes removed"
    printf "  ${GRAY}demo state persists in scripts/demo/.state.json; use 'nuke' to clear it too${RESET}\n"
}

cmd_nuke() {
    require_prereqs
    step "Stopping checker daemon"
    stop_checker
    step "Removing containers + volumes + demo state"
    compose down -v --remove-orphans || true
    orchestrate reset
    rm -rf "$DEMO_DIR/.fixtures"
    rm -f "$CHECKER_LOG_FILE" "$CHECKER_PID_FILE"
    ok "demo nuked — next 'up' starts from a clean slate"
}

cmd_help() {
    cat <<EOF
Usage: ./deploy_demo.sh <command>

Commands:
  up           Build the stack, bootstrap orgs/agents, start checker daemon
  send         Run sender.py once → routes a check from sender to checker
  checker-log  Tail the background checker daemon log
  info         Print dashboard URLs + bootstrap credentials
  status       Show container state
  logs         Follow broker + proxy logs (Ctrl-C to stop)
  down         Stop containers + checker daemon + remove volumes (ephemeral)
  nuke         down + clear demo state + fixtures
  help         Show this help

Quick start:
  ./deploy_demo.sh up      # ~1 min on a clean host
  ./deploy_demo.sh send    # narrated conversation, ~1 sec round-trip
EOF
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

cmd="${1:-help}"
case "$cmd" in
    up)            cmd_up ;;
    send)          cmd_send ;;
    checker-log)   cmd_checker_log ;;
    info)          cmd_info ;;
    status)        cmd_status ;;
    logs)          cmd_logs ;;
    down)          cmd_down ;;
    nuke)          cmd_nuke ;;
    help|-h|--help) cmd_help ;;
    *)
        err "Unknown command: $cmd"
        cmd_help
        exit 2
        ;;
esac
