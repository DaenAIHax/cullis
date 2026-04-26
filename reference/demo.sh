#!/usr/bin/env bash
# Cullis Enterprise Sandbox — 3-mode driver (ADR-009 sandbox restructure).
#
#   demo.sh up        Tier 1: Court + Org B complete + Mastio A standalone
#                              (user completes Org A via the guided flow)
#   demo.sh full      Tier 2: everything wired — two orgs, three agents,
#                              two MCP servers, scenarios ready to replay
#   demo.sh down      Teardown (containers + volumes)
#   demo.sh status    List running services
#   demo.sh logs [S]  Tail compose logs
#   demo.sh dashboard Print dashboard URLs
#   demo.sh help      This message
#
set -euo pipefail
cd "$(dirname "$0")"

BOLD='\033[1m'
GREEN='\033[32m'
CYAN='\033[36m'
YELLOW='\033[33m'
RESET='\033[0m'

_header() { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"; }
_ok()     { echo -e "  ${GREEN}✓${RESET} $1"; }
_note()   { echo -e "  ${YELLOW}•${RESET} $1"; }

_court_bootstrap_token() {
    # One-shot token generated at broker startup (F-B-4). Used only on
    # the very first /dashboard/setup visit to pick the admin password.
    # Empty once consumed — that means an admin has already set the password.
    docker compose exec -T broker \
        sh -c 'cat /app/certs/.admin_bootstrap_token 2>/dev/null' \
        2>/dev/null | tr -d '[:space:]'
}

_print_dashboards() {
    _header "Dashboard URLs"
    echo -e "  ${GREEN}Court (broker)${RESET}      http://localhost:8000/dashboard/setup"
    local token
    token=$(_court_bootstrap_token || true)
    if [ -n "$token" ]; then
        echo -e "                       first visit → paste this bootstrap token and pick your password:"
        echo -e "                       ${BOLD}${token}${RESET}"
    else
        echo -e "                       (admin password already set — login at /dashboard/login)"
    fi
    echo -e "  ${GREEN}Mastio A (proxy-a)${RESET}  http://localhost:9100/proxy"
    echo -e "                       admin secret: sandbox-proxy-admin-a"
    echo -e "  ${GREEN}Mastio B (proxy-b)${RESET}  http://localhost:9200/proxy"
    echo -e "                       admin secret: sandbox-proxy-admin-b"
    echo -e "  ${GREEN}Keycloak A${RESET}          http://localhost:8180 (alice / alice-sandbox)"
    echo -e "  ${GREEN}Keycloak B${RESET}          http://localhost:8280 (bob / bob-sandbox)"
}

_print_scenarios() {
    _header "Try it — generate traffic for the Grafana dashboard"
    echo -e "  ${BOLD}${CYAN}┌─ open http://localhost:3000 first ─────────────────────┐${RESET}"
    echo -e "  ${BOLD}${CYAN}└────────────────────────────────────────────────────────┘${RESET}"
    echo
    echo -e "  ${GREEN}./scenarios/widget-hunt.sh${RESET}        kick-off prompt → multi-hop LLM chain"
    echo -e "  ${GREEN}./scenarios/inject.sh${RESET}             one mixed burst of fresh messages"
    echo -e "  ${GREEN}./scenarios/inject.sh -n 10${RESET}       ten back-to-back bursts"
    echo -e "  ${GREEN}./scenarios/inject.sh --loop${RESET}      continuous bursts ~every 8s (Ctrl-C to stop)"
    echo -e "  ${GREEN}./scenarios/inject.sh -c${RESET}          cross-org only (exercises ADR-009 counter-sig)"
}

_print_teardown() {
    _header "Teardown"
    echo -e "  ${GREEN}./demo.sh down${RESET}             stop everything + drop volumes"
}

case "${1:-help}" in
  up)
    _header "Enterprise Sandbox — Tier 1 (you onboard Org A)"
    _note "Org B (Globex Inc) is fully wired."
    _note "Org A (Acme Corp) has Mastio A running in standalone mode but"
    _note "is NOT registered on the Court — you will do that from the guide."
    export BOOTSTRAP_SCOPE=up
    docker compose build --quiet
    _note "booting services (this takes ~60s)…"
    docker compose --progress quiet up -d --wait --quiet-pull
    _header "Services Running"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    _print_dashboards
    _print_teardown
    echo ""
    _ok "Sandbox ready. Run ${BOLD}demo.sh help${RESET} to see commands."
    ;;

  full)
    _header "Enterprise Sandbox — Tier 2 (everything wired)"
    _note "Both orgs registered, three agents enrolled, two MCP servers online."
    export BOOTSTRAP_SCOPE=full
    docker compose --profile full build --quiet
    _note "booting services (this takes ~60s)…"
    docker compose --progress quiet --profile full up -d --wait --quiet-pull
    _header "Services Running"
    docker compose --profile full ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    _print_dashboards
    _print_scenarios
    _print_teardown
    echo ""
    _ok "Full sandbox ready."
    ;;

  down)
    _header "Enterprise Sandbox — Teardown"
    docker compose --profile full down -v --remove-orphans
    _ok "sandbox down"
    ;;

  status)
    _header "Enterprise Sandbox — Status"
    docker compose --profile full ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    ;;

  logs)
    shift
    docker compose --profile full logs "${@:---tail=50}"
    ;;

  dashboard)
    _print_dashboards
    ;;

  bootstrap-logs)
    docker compose logs bootstrap --no-log-prefix
    ;;

  widget-hunt)
    _header "Scenario — kick-off the multi-hop LLM chain on alice-byoca"
    bash scenarios/widget-hunt.sh
    ;;

  inject)
    shift
    _header "Scenario — inject fresh traffic"
    bash scenarios/inject.sh "$@"
    ;;

  help|*)
    cat <<EOF
Usage: demo.sh <command>

Lifecycle:
  up              Tier 1 — Court + Org B wired + Mastio A standalone.
                  Org A is left for you to onboard via the guided flow.
  full            Tier 2 — both orgs + all agents + MCP servers wired.
  down            Stop everything + drop volumes.

Inspection:
  status          List services + health.
  logs [svc]      Tail compose logs (default: --tail=50).
  dashboard       Print dashboard URLs + Court bootstrap token (first login).
  bootstrap-logs  Replay the verbose Phase 1-7 bootstrap output.

Demo (require 'full' mode + http://localhost:3000 open):
  widget-hunt     Restart the stack with the kick-off prompt baked in
                  (alice-byoca starts the multi-hop sourcing chain).
  inject [args]   Generate fresh traffic without restarting. Pass
                  -n N (N bursts), --loop (continuous), -c (cross-org
                  only). See ./scenarios/inject.sh -h for details.
EOF
    ;;
esac
