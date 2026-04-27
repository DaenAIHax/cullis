#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — MCP Proxy deployment (org-level gateway + built-in PDP)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Deploys the MCP Proxy for one organization.
#
# Four deploy modes (combinable):
#   (default)        dev on the same host as the broker
#   --prod           fail-fast on insecure defaults, prod overlay
#   --standalone     proxy on a different host than the broker (remote broker URL)
#   --down           stop + remove containers
#   --rebuild        rebuild images and restart
#
# Examples:
#   ./deploy_proxy.sh
#   ./deploy_proxy.sh --standalone
#   ./deploy_proxy.sh --prod --standalone
#   ./deploy_proxy.sh --down
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Distinct compose project name isolates the proxy stack from the broker
# (deploy_broker.sh → cullis-broker). Otherwise fresh clones named `cullis`
# would share docker volumes across stacks and a fresh user would hit
# opaque volume/password collisions (shake-out P0-03).
export COMPOSE_PROJECT_NAME="cullis-proxy"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

# ── docker compose binary ───────────────────────────────────────────────────
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    die "docker compose is not installed"
fi

# ── Parse args ──────────────────────────────────────────────────────────────
print_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Deploys the MCP Proxy for one organization. Combines with --down / --rebuild
for lifecycle management, and --standalone when the proxy runs on a different
host than the broker.

Options:
  (no flags)                  Dev mode, same host as the broker (default)
  --prod                      Production: fail-fast on insecure defaults,
                              requires proxy.env pre-provisioned
  --standalone                Proxy runs on a different host than the broker
                              (reads BROKER_URL from proxy.env)
  --down                      Stop and remove containers
  --rebuild                   Rebuild images and restart
  --help, -h                  Show this help and exit

Examples:
  ./deploy_proxy.sh                          # dev, same host as broker
  ./deploy_proxy.sh --standalone             # dev, proxy on its own host
  ./deploy_proxy.sh --prod --standalone      # prod, proxy on its own host
  ./deploy_proxy.sh --down                   # stop + remove containers
EOF
}

ACTION="up"
MODE="development"
STANDALONE=0
for arg in "$@"; do
    case "$arg" in
        --down)       ACTION="down" ;;
        --rebuild)    ACTION="rebuild" ;;
        --prod)       MODE="production" ;;
        --standalone) STANDALONE=1 ;;
        --help|-h)    print_help; exit 0 ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

# ── Compose file stacking ───────────────────────────────────────────────────
COMPOSE_FILES="-f docker-compose.proxy.yml"
[[ $STANDALONE -eq 1 ]]    && COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.proxy.standalone.yml"
[[ "$MODE" == "production" ]] && COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.proxy.prod.yml"

# ADR-006 Trojan Horse — flag --standalone selects the network override
# above AND tells the Mastio itself to run in mini-broker mode (derive
# Org CA at first boot, skip broker uplink). Both knobs were drifting
# apart — flag set the network but the Mastio still booted federated,
# never derived the Org CA, and the nginx sidecar (ADR-014) had no
# cert material to serve. Propagate the flag through the env so the
# container picks it up at lifespan startup.
if [[ $STANDALONE -eq 1 ]]; then
    export MCP_PROXY_STANDALONE=true
fi

# ── Down early-exit ─────────────────────────────────────────────────────────
if [[ "$ACTION" == "down" ]]; then
    step "Stopping MCP Proxy"
    $COMPOSE $COMPOSE_FILES --env-file proxy.env down 2>/dev/null \
        || $COMPOSE $COMPOSE_FILES down
    ok "Proxy stopped"
    exit 0
fi

# ── proxy.env — create if missing, validate in prod ─────────────────────────
step "Environment configuration (proxy.env)"

if [[ ! -f "$SCRIPT_DIR/proxy.env" ]]; then
    warn "proxy.env not found — generating one"
    if [[ "$MODE" == "production" ]]; then
        die "--prod requires proxy.env to exist with real values. Run: BROKER_URL=https://broker.example.com PROXY_PUBLIC_URL=https://proxy.myorg.example.com ./scripts/generate-proxy-env.sh --prod"
    fi
    bash "$SCRIPT_DIR/scripts/generate-proxy-env.sh" --defaults
fi

# ── Pre-flight validation for --prod ────────────────────────────────────────
if [[ "$MODE" == "production" ]]; then
    _errors=()
    _load_env() { grep -E "^$1=" "$SCRIPT_DIR/proxy.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

    _admin="$(_load_env MCP_PROXY_ADMIN_SECRET)"
    if [[ -z "$_admin" || "$_admin" == "change-me-in-production" ]]; then
        _errors+=("MCP_PROXY_ADMIN_SECRET is empty or still the dev default — regenerate proxy.env")
    fi

    _signing="$(_load_env MCP_PROXY_DASHBOARD_SIGNING_KEY)"
    if [[ -z "$_signing" ]]; then
        _errors+=("MCP_PROXY_DASHBOARD_SIGNING_KEY is empty — admin sessions will break on every restart")
    fi

    _broker="$(_load_env MCP_PROXY_BROKER_URL)"
    if [[ -z "$_broker" || "$_broker" == "http://broker:8000" ]]; then
        _errors+=("MCP_PROXY_BROKER_URL still points at the dev docker-compose name — set the public broker URL")
    fi
    if [[ "$_broker" == http://* ]]; then
        warn "MCP_PROXY_BROKER_URL uses plain HTTP — production brokers should be HTTPS"
    fi

    _public="$(_load_env MCP_PROXY_PROXY_PUBLIC_URL)"
    if [[ -z "$_public" || "$_public" == "http://localhost:9100" || "$_public" == "https://localhost:9443" ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL still localhost — set the public URL where internal agents reach this proxy")
    fi
    # ADR-014 — production must use HTTPS through the mastio-nginx sidecar.
    if [[ "$_public" == http://* ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL uses plain HTTP — ADR-014 requires HTTPS via the mastio-nginx sidecar (default port 9443)")
    fi

    if [[ ${#_errors[@]} -gt 0 ]]; then
        echo ""
        err "Production proxy.env is not safe to deploy:"
        for e in "${_errors[@]}"; do echo -e "    ${RED}✗${RESET} $e"; done
        echo ""
        die "Fix the issues above and rerun. Aborting before compose up."
    fi
    ok "proxy.env validated for production"
fi

# ── Build + Start ───────────────────────────────────────────────────────────
step "Deploying Cullis MCP Proxy (${MODE}, $([ $STANDALONE -eq 1 ] && echo standalone || echo shared-network))"

if [[ "$ACTION" == "rebuild" ]]; then
    echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file proxy.env build --no-cache${RESET}"
    $COMPOSE $COMPOSE_FILES --env-file proxy.env build --no-cache
    ok "Images rebuilt"
fi

# If shared-network, make sure the broker network exists; otherwise compose
# will fail with an obtuse "network cullis-broker_default not found".
# Network name derives from the broker's COMPOSE_PROJECT_NAME ("cullis-broker"
# pinned in deploy_broker.sh per shake-out P0-03).
if [[ $STANDALONE -eq 0 ]]; then
    if ! docker network inspect cullis-broker_default >/dev/null 2>&1; then
        die "Network 'cullis-broker_default' not found. Either start the broker first (./deploy_broker.sh --dev) or rerun with --standalone for a remote broker."
    fi
fi

echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file proxy.env up --build -d${RESET}"
$COMPOSE $COMPOSE_FILES --env-file proxy.env up --build -d
ok "Containers started"

# ── Wait for health ─────────────────────────────────────────────────────────
step "Waiting for services"

# ADR-014 — the Mastio listens behind the mastio-nginx sidecar on
# 9443 TLS. The sidecar healthcheck (in compose) waits for cert
# material to land on the shared volume, so by the time it's healthy
# the Mastio already booted, ran first-boot cert provisioning, and
# nginx is serving. We poll TLS here with -k because the cert is
# self-signed off the Org CA — operators who care about strict
# verification can extract /var/lib/mastio/nginx-certs/org-ca.crt
# from the mcp-proxy container and pass --cacert.
PROXY_PORT="$(grep -E '^MCP_PROXY_PORT=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"
PROXY_PORT="${PROXY_PORT:-9443}"

echo -n "  Proxy + nginx "
for i in $(seq 1 60); do
    if curl -skf "https://localhost:${PROXY_PORT}/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 60 ]]; then
        echo -e " ${RED}timeout${RESET}"
        warn "Proxy did not become healthy — check logs: $COMPOSE $COMPOSE_FILES logs mcp-proxy mastio-nginx"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────────
BROKER_URL="$(grep -E '^MCP_PROXY_BROKER_URL=' "$SCRIPT_DIR/proxy.env" | cut -d= -f2-)"
PUBLIC_URL="$(grep -E '^MCP_PROXY_PROXY_PUBLIC_URL=' "$SCRIPT_DIR/proxy.env" | cut -d= -f2-)"

echo ""
echo -e "${GREEN}${BOLD}MCP Proxy deployed (${MODE}).${RESET}"
echo ""
echo -e "  ${BOLD}Proxy dashboard${RESET}  ${GRAY}${PUBLIC_URL}/proxy/login${RESET}"
echo -e "  ${BOLD}Health${RESET}           ${GRAY}${PUBLIC_URL}/health${RESET}"
echo -e "  ${BOLD}Broker uplink${RESET}    ${GRAY}${BROKER_URL}${RESET}"
echo -e "  ${BOLD}PDP webhook${RESET}      ${GRAY}${PUBLIC_URL}/pdp/policy  (broker reaches this)${RESET}"
echo ""
if [[ "$MODE" == "development" ]]; then
    echo "  Next steps (development):"
    echo "    1. Open ${PUBLIC_URL}/proxy/login"
    echo "       (browser will warn — the TLS cert is signed by your local"
    echo "        Org CA, not a public CA. Accept the self-signed warning.)"
    echo "    2. Paste broker URL + invite token from the broker admin"
    echo "    3. Register your organization (certs auto-generated)"
    echo "    4. Wait for approval, then create agents"
else
    echo "  Next steps (production):"
    echo "    1. ADR-014 — the mastio-nginx sidecar terminates TLS on :${PROXY_PORT}"
    echo "       with a server cert signed by your Org CA. Front-door TLS for the"
    echo "       public hostname is up to your edge load-balancer (LB → sidecar :${PROXY_PORT})."
    echo "    2. DNS: ${PUBLIC_URL}  →  this host"
    echo "    3. Share the dashboard URL with your org admin (credentials in proxy.env)"
    echo "    4. Broker admin generates an attach-ca or join invite for you"
fi
echo ""
echo "  Useful commands:"
echo "    $COMPOSE $COMPOSE_FILES logs -f                # tail logs"
echo "    $COMPOSE $COMPOSE_FILES ps                     # container status"
echo "    $0 --down                                      # stop"
echo ""
