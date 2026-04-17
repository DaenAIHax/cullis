#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# ANSI
BOLD='\033[1m'
GREEN='\033[32m'
CYAN='\033[36m'
RESET='\033[0m'

_header() { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"; }

case "${1:-help}" in
  up)
    _header "Enterprise Sandbox — Starting"
    echo "Building and starting all services..."
    docker compose build --quiet
    docker compose up -d --wait
    echo ""
    _header "Services Running"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    _header "Dashboard URLs"
    echo -e "  ${GREEN}Court (broker)${RESET}     http://localhost:8000/dashboard/login"
    echo -e "                      admin / sandbox-admin-secret-change-me"
    echo -e "  ${GREEN}Mastio A (proxy-a)${RESET} http://localhost:9100/proxy"
    echo -e "                      admin secret: sandbox-proxy-admin-a"
    echo -e "  ${GREEN}Mastio B (proxy-b)${RESET} http://localhost:9200/proxy"
    echo -e "                      admin secret: sandbox-proxy-admin-b"
    echo -e "  ${GREEN}Keycloak A${RESET}         http://localhost:8180  (alice / alice-sandbox)"
    echo -e "  ${GREEN}Keycloak B${RESET}         http://localhost:8280  (bob / bob-sandbox)"
    echo ""
    echo -e "Bootstrap logs:  docker compose -f enterprise_sandbox/docker-compose.yml logs bootstrap"
    echo -e "Agent logs:      docker compose -f enterprise_sandbox/docker-compose.yml logs agent-a agent-b byoca-a"
    ;;

  down)
    _header "Enterprise Sandbox — Teardown"
    docker compose down -v --remove-orphans
    echo -e "${GREEN}✓ sandbox down${RESET}"
    ;;

  status)
    _header "Enterprise Sandbox — Status"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
    ;;

  logs)
    shift
    docker compose logs "${@:---tail=50}"
    ;;

  dashboard)
    _header "Dashboard URLs"
    echo -e "  Court (broker)     http://localhost:8000/dashboard/login"
    echo -e "  Mastio A (proxy-a) http://localhost:9100/proxy"
    echo -e "  Mastio B (proxy-b) http://localhost:9200/proxy"
    echo -e "  Keycloak A         http://localhost:8180"
    echo -e "  Keycloak B         http://localhost:8280"
    ;;

  bootstrap-logs)
    docker compose logs bootstrap --no-log-prefix
    ;;

  help|*)
    echo "Usage: demo.sh <command>"
    echo ""
    echo "Lifecycle:"
    echo "  up              Build + start all services, show dashboard URLs"
    echo "  down            Teardown (remove containers + volumes)"
    echo "  status          Show running services"
    echo "  logs [service]  Show logs (default: last 50 lines)"
    echo ""
    echo "Info:"
    echo "  dashboard       Print dashboard URLs"
    echo "  bootstrap-logs  Show bootstrap verbose output"
    ;;
esac
