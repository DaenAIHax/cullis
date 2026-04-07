#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — MCP Proxy deployment (org-level gateway + built-in PDP)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Deploys the MCP Proxy for one organization. Includes a built-in Policy
# Decision Point (PDP) that the broker calls for authorization.
#
# Prerequisites:
#   - A Cullis broker running (deployed via deploy_broker.sh)
#   - An invite token from the broker admin
#
# Usage:
#   ./deploy_proxy.sh              # Build and start proxy + PDP
#   ./deploy_proxy.sh --down       # Stop and remove containers
#   ./deploy_proxy.sh --rebuild    # Rebuild and restart
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BOLD='\033[1m'
GRAY='\033[90m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

COMPOSE_FILE="-f docker-compose.proxy.yml"

# Accept either 'docker compose' (plugin) or 'docker-compose' (standalone)
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    die "docker compose is not installed"
fi

# ── Parse args ───────────────────────────────────────────────────────────────
ACTION="up"
for arg in "$@"; do
    case "$arg" in
        --down)    ACTION="down" ;;
        --rebuild) ACTION="rebuild" ;;
        --help|-h)
            echo "Usage: $0 [--down|--rebuild]"
            echo "  (none)     Build and start proxy + PDP"
            echo "  --rebuild  Rebuild images and restart"
            echo "  --down     Stop and remove containers"
            exit 0
            ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── Down ─────────────────────────────────────────────────────────────────────
if [[ "$ACTION" == "down" ]]; then
    step "Stopping MCP Proxy"
    $COMPOSE $COMPOSE_FILE down
    ok "Proxy stopped"
    exit 0
fi

# ── Build + Start ────────────────────────────────────────────────────────────
step "Deploying Cullis MCP Proxy"

if [[ "$ACTION" == "rebuild" ]]; then
    echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILE build --no-cache${RESET}"
    $COMPOSE $COMPOSE_FILE build --no-cache
    ok "Images rebuilt"
fi

echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILE up --build -d${RESET}"
$COMPOSE $COMPOSE_FILE up --build -d
ok "Containers started"

# ── Wait for health ──────────────────────────────────────────────────────────
step "Waiting for services"

PROXY_PORT="${MCP_PROXY_PORT:-9100}"

echo -n "  Proxy + PDP "
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${PROXY_PORT}/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo -e " ${RED}timeout${RESET}"
        warn "Proxy did not become healthy — check logs: $COMPOSE $COMPOSE_FILE logs mcp-proxy"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}MCP Proxy deployed!${RESET}"
echo ""
echo -e "  ${BOLD}Proxy Dashboard${RESET}  ${GRAY}http://localhost:${PROXY_PORT}/proxy/login${RESET}"
echo -e "  ${BOLD}Proxy API${RESET}        ${GRAY}http://localhost:${PROXY_PORT}/v1/egress/${RESET}"
echo -e "  ${BOLD}PDP Webhook${RESET}      ${GRAY}http://mcp-proxy:${PROXY_PORT}/pdp/policy  (Docker internal)${RESET}"
echo -e "  ${BOLD}Health${RESET}           ${GRAY}http://localhost:${PROXY_PORT}/health${RESET}"
echo ""
echo "  Next steps:"
echo "    1. Open the proxy dashboard at http://localhost:${PROXY_PORT}/proxy/login"
echo "    2. Broker URL: http://broker:8000 (same Docker network) + invite token"
echo "    3. Register your organization (certificates auto-generated)"
echo "    4. Wait for broker admin to approve your organization"
echo "    5. Create agents and start communicating"
echo ""
echo "  Useful commands:"
echo "    $COMPOSE $COMPOSE_FILE logs -f          # Follow logs"
echo "    $COMPOSE $COMPOSE_FILE ps               # Container status"
echo "    $COMPOSE $COMPOSE_FILE down              # Stop"
echo "    $COMPOSE $COMPOSE_FILE down -v           # Stop + delete data"
echo ""
