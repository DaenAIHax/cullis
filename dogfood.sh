#!/usr/bin/env bash
# Cullis dogfood orchestrator.
#
# Wraps the modern dogfood stack (Court + 2 Mastio + 5 MCP mock servers +
# 4 reference agents + Frontdesk) that lives in the sibling
# cullis-enterprise/legacy/ checkout. Lets the founder run the full
# product surface against the current public mcp_proxy/ without copying
# enterprise sources into the public tree.
#
# The smoke stack builds the Mastio image with
#   build:  context: ..   dockerfile: mcp_proxy/Dockerfile
# inside the stack docker-compose.yml. Because legacy/mcp_proxy is a
# symlink to agent-trust/mcp_proxy, the built image always reflects the
# current public mcp_proxy/ working tree — that is the point.
#
# Usage:
#   ./dogfood.sh setup        symlink .dogfood/ -> ../cullis-enterprise/legacy/
#   ./dogfood.sh quick        up stack + healthcheck, no LLM scenarios (~30s)
#   ./dogfood.sh full         up stack + smoke E2E B1-B11 (~5min warm)
#   ./dogfood.sh pytest [...] legacy pytest suite (DOES NOT test mcp_proxy/,
#                             tests legacy/app/ — see warning at runtime)
#   ./dogfood.sh down         teardown + drop volumes
#   ./dogfood.sh status       service state + endpoints
#   ./dogfood.sh logs [svc]   tail logs (all services or one)
#
# Exit code: 0 if the requested action succeeded.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOGFOOD_DIR="$SCRIPT_DIR/.dogfood"
STACK_DIR="$DOGFOOD_DIR/stack"
SIBLING_DEFAULT="$SCRIPT_DIR/../cullis-enterprise/legacy"
SIBLING="${CULLIS_ENTERPRISE_LEGACY:-$SIBLING_DEFAULT}"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_NEU=$'\033[36m'
C_WARN=$'\033[33m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'

err()  { echo "${C_ERR}${C_BOLD}error:${C_RST} $*" >&2; }
warn() { echo "${C_WARN}${C_BOLD}warn:${C_RST}  $*" >&2; }
info() { echo "${C_NEU}$*${C_RST}" >&2; }
ok()   { echo "${C_OK}$*${C_RST}" >&2; }

banner() {
  echo "" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}  $*${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
}

require_setup() {
  if [[ ! -e "$DOGFOOD_DIR" ]]; then
    err ".dogfood/ not set up. Run: ./dogfood.sh setup"
    exit 1
  fi
  if [[ ! -d "$STACK_DIR" ]]; then
    err "$STACK_DIR not found. Sibling checkout may have moved. Re-run: ./dogfood.sh setup"
    exit 1
  fi
}

cmd_setup() {
  banner "Setup .dogfood/ symlink"

  if [[ -L "$DOGFOOD_DIR" ]]; then
    local current
    current="$(readlink "$DOGFOOD_DIR")"
    info "  .dogfood/ already symlink -> $current"
  elif [[ -e "$DOGFOOD_DIR" ]]; then
    err ".dogfood/ exists and is not a symlink. Inspect manually before removing."
    exit 1
  fi

  if [[ ! -d "$SIBLING" ]]; then
    err "Sibling enterprise checkout not found at:"
    err "  $SIBLING"
    err ""
    err "To populate it:"
    err "  cd $(dirname "$SCRIPT_DIR")"
    err "  git clone git@github.com:cullis-security/cullis-enterprise.git"
    err ""
    err "Or set CULLIS_ENTERPRISE_LEGACY=/path/to/cullis-enterprise/legacy"
    err "Then re-run: ./dogfood.sh setup"
    exit 1
  fi

  ln -sfn "$SIBLING" "$DOGFOOD_DIR"
  ok "  .dogfood/ -> $SIBLING"

  local missing=0
  for sub in stack tests sandbox/agents-demo; do
    if [[ ! -d "$DOGFOOD_DIR/$sub" ]]; then
      err "  missing $DOGFOOD_DIR/$sub"
      missing=$((missing+1))
    else
      ok "  found  $sub/"
    fi
  done
  if [[ $missing -gt 0 ]]; then
    err "Enterprise checkout incomplete. Check the sibling repo."
    exit 1
  fi

  banner "Setup OK"
  echo "  Next: ./dogfood.sh quick   (healthcheck-only)" >&2
  echo "        ./dogfood.sh full    (smoke E2E B1-B11)" >&2
}

cmd_quick() {
  require_setup
  banner "Quick: up stack + healthcheck (no LLM scenarios)"

  cd "$STACK_DIR"
  if ! ./up.sh; then
    err "up.sh failed"
    return 1
  fi

  banner "Healthcheck"
  local fail=0
  local svcs=(
    "Court:http://localhost:8000/health"
    "MastioA:http://localhost:9100/health"
    "MastioB:http://localhost:9200/health"
    "Frontdesk:http://localhost:7777/api/status"
  )
  for svc in "${svcs[@]}"; do
    local name="${svc%%:*}"
    local url="${svc#*:}"
    if curl -sf --max-time 3 "$url" >/dev/null 2>&1; then
      ok "  $name $url"
    else
      err "  $name $url"
      fail=$((fail+1))
    fi
  done

  if [[ $fail -eq 0 ]]; then
    banner "${C_OK}QUICK OK"
    echo "  Stack up + healthchecks green. Run ./dogfood.sh full for E2E." >&2
    return 0
  fi
  err "$fail healthcheck(s) failed"
  return 1
}

cmd_full() {
  require_setup
  banner "Full: up + smoke E2E (B1-B7 baseline + B8-B12 extras)"
  local baseline_rc=0 extras_rc=0
  "$STACK_DIR/demo.sh" || baseline_rc=$?
  "$SCRIPT_DIR/dogfood-scenarios.sh" || extras_rc=$?
  banner "Full summary"
  if [[ $baseline_rc -eq 0 ]]; then ok "  baseline B1-B7  PASS"; else err "  baseline B1-B7  FAIL (some scenarios failed; see above)"; fi
  if [[ $extras_rc -eq 0 ]];   then ok "  extras   B8-B12 PASS"; else err "  extras   B8-B12 FAIL (some scenarios failed; see above)"; fi
  return $(( baseline_rc | extras_rc ))
}

cmd_pytest() {
  require_setup
  banner "Pytest: tests/ suite"
  warn "This runs against legacy app/, NOT public mcp_proxy/."
  warn "Drift is possible. The real gate for mcp_proxy/ changes is"
  warn "  ./dogfood.sh full  (smoke E2E builds the image from public)."
  echo "" >&2

  if ! command -v pytest >/dev/null 2>&1; then
    err "pytest not in PATH. Activate venv first."
    exit 1
  fi

  cd "$DOGFOOD_DIR"
  exec pytest tests/ -n auto --dist=loadfile "$@"
}

cmd_down() {
  require_setup
  banner "Teardown"
  exec "$STACK_DIR/down.sh"
}

cmd_status() {
  require_setup
  exec "$STACK_DIR/demo.sh" status
}

cmd_logs() {
  require_setup
  exec "$STACK_DIR/demo.sh" logs "$@"
}

case "${1:-}" in
  setup)        shift; cmd_setup ;;
  quick)        shift; cmd_quick ;;
  full)         shift; cmd_full ;;
  pytest|test)  shift; cmd_pytest "$@" ;;
  down)         shift; cmd_down ;;
  status|ps)    shift; cmd_status ;;
  logs)         shift; cmd_logs "$@" ;;
  -h|--help|help|"")
    sed -n '/^# Usage:/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    err "unknown subcommand: $1"
    err "Try: $0 --help"
    exit 2 ;;
esac
