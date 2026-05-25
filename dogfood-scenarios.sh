#!/usr/bin/env bash
# Dogfood-extra scenarios: B8 (kyc stub), B9 (dora stub), B10 (pitchbook stub),
# B11 (capability_gate denial), B12 (release tarball cold-reader validation).
#
# Runs against a stack already brought up by ./dogfood.sh full (or
# `cd .dogfood/stack && ./demo.sh up`). Each scenario is a fixed sequence of
# MCP tool calls with no LLM involvement — pure capability + audit chain
# probe. Replaces the LLM-driven agent_*_smoke variant which would otherwise
# require Anthropic API key + flaky parsing.
#
# Usage:
#   ./dogfood-scenarios.sh                # run all extras (B8..B12)
#   ./dogfood-scenarios.sh B8 B11         # run a subset
#
# Exit code: 0 if every selected scenario PASSES, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB_PY="$SCRIPT_DIR/agent_smoke_stub.py"
STAGE_BUNDLE_SH="${STAGE_BUNDLE_SH:-/home/daenaihax/projects/agent-trust/scripts/stage-mastio-bundle.sh}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-cullis-stack}"
AGENT_CONTAINER="${AGENT_CONTAINER:-${COMPOSE_PROJECT}-agent-a-1}"
MASTIO_URL="${MASTIO_URL:-https://mastio-a-nginx:9443}"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_NEU=$'\033[36m'
C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_RST=$'\033[0m'

PASS=0
FAIL=0

run() {
  local name="$1"; shift
  echo "" >&2
  echo "${C_NEU}${C_BOLD}»${C_RST} ${name}" >&2
  if "$@"; then
    echo "  ${C_OK}${C_BOLD}PASS${C_RST}  ${name}" >&2
    PASS=$((PASS + 1))
  else
    echo "  ${C_ERR}${C_BOLD}FAIL${C_RST}  ${name}" >&2
    FAIL=$((FAIL + 1))
  fi
}

_require_stack_up() {
  if ! docker ps --format '{{.Names}}' | grep -q "^${AGENT_CONTAINER}$"; then
    echo "${C_ERR}error:${C_RST} container ${AGENT_CONTAINER} not running. Run ./dogfood.sh full first." >&2
    return 1
  fi
}

_ship_stub() {
  if ! docker cp "$STUB_PY" "${AGENT_CONTAINER}:/tmp/agent_smoke_stub.py" 2>/dev/null; then
    echo "${C_ERR}error:${C_RST} docker cp stub to ${AGENT_CONTAINER} failed" >&2
    return 1
  fi
}

# ── B8. kyc-screener stub ────────────────────────────────────────────────────

scenario_b8_kyc_stub() {
  _require_stack_up || return 1
  _ship_stub || return 1
  local out
  out="$(docker exec "$AGENT_CONTAINER" python3 /tmp/agent_smoke_stub.py \
    --agent-id orga::kyc-screener \
    --tools verify_identity,screen_sanctions,query_beneficial_owners,escalate_to_compliance \
    --mastio "$MASTIO_URL" \
    --scenario B8 2>&1)"
  echo "${C_DIM}$(echo "$out" | tail -n6)${C_RST}" >&2
  echo "$out" | grep -q "^RESULT: OK"
}

# ── B9. dora-reporter stub ───────────────────────────────────────────────────

scenario_b9_dora_stub() {
  _require_stack_up || return 1
  _ship_stub || return 1
  local out
  out="$(docker exec "$AGENT_CONTAINER" python3 /tmp/agent_smoke_stub.py \
    --agent-id orga::dora-reporter \
    --tools list_third_party_vendors,query_vendor_assessment,draft_dora_register_entry,submit_to_auditor_org \
    --mastio "$MASTIO_URL" \
    --scenario B9 2>&1)"
  echo "${C_DIM}$(echo "$out" | tail -n6)${C_RST}" >&2
  echo "$out" | grep -q "^RESULT: OK"
}

# ── B10. pitchbook-builder stub ──────────────────────────────────────────────

scenario_b10_pitchbook_stub() {
  _require_stack_up || return 1
  _ship_stub || return 1
  local out
  out="$(docker exec "$AGENT_CONTAINER" python3 /tmp/agent_smoke_stub.py \
    --agent-id orga::pitchbook-builder \
    --tools query_comps_db,read_internal_research,news_feed_query,generate_excel,generate_pptx \
    --mastio "$MASTIO_URL" \
    --scenario B10 2>&1)"
  echo "${C_DIM}$(echo "$out" | tail -n7)${C_RST}" >&2
  echo "$out" | grep -q "^RESULT: OK"
}

# ── B11. capability_gate denial (kyc-screener → portfolio tool) ──────────────

scenario_b11_capability_denial() {
  _require_stack_up || return 1
  _ship_stub || return 1
  # kyc-screener has NO binding for portfolio tools. Mastio must deny.
  local out
  out="$(docker exec "$AGENT_CONTAINER" python3 /tmp/agent_smoke_stub.py \
    --agent-id orga::kyc-screener \
    --tools get_market_data \
    --mastio "$MASTIO_URL" \
    --scenario B11 \
    --expect-denied 2>&1)"
  echo "${C_DIM}$(echo "$out" | tail -n4)${C_RST}" >&2
  echo "$out" | grep -q "^RESULT: B11 OK"
}

# ── B12. release tarball cold-reader validation ──────────────────────────────

scenario_b12_release_tarball() {
  if [[ ! -x "$STAGE_BUNDLE_SH" ]]; then
    echo "${C_DIM}    stage script not found: $STAGE_BUNDLE_SH${C_RST}" >&2
    echo "${C_DIM}    set STAGE_BUNDLE_SH=/path or wait PR #930 merge${C_RST}" >&2
    return 1
  fi
  local tmpout
  tmpout="$(mktemp -d /tmp/b12-dogfood-XXXXXX)"
  trap "rm -rf $tmpout" RETURN
  if ! "$STAGE_BUNDLE_SH" 0.0.0-smoke "$tmpout" >"$tmpout/log" 2>&1; then
    echo "${C_DIM}    stage script failed; tail:${C_RST}" >&2
    echo "${C_DIM}$(tail -n8 "$tmpout/log")${C_RST}" >&2
    return 1
  fi
  echo "${C_DIM}    $(grep -E 'SHA-256|Output|Stage OK' "$tmpout/log" | head -3 | tr '\n' ' ')${C_RST}" >&2
  return 0
}

# ── Driver ──────────────────────────────────────────────────────────────────

ALL=(B8 B9 B10 B11 B12)
SELECTED=("${@:-${ALL[@]}}")
if [[ $# -eq 0 ]]; then
  SELECTED=("${ALL[@]}")
fi

echo "" >&2
echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
echo "${C_NEU}${C_BOLD}  dogfood-scenarios: ${SELECTED[*]}${C_RST}" >&2
echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2

for s in "${SELECTED[@]}"; do
  case "$s" in
    B8)  run "B8.  kyc-screener stub (4 tools)"        scenario_b8_kyc_stub ;;
    B9)  run "B9.  dora-reporter stub (4 tools)"       scenario_b9_dora_stub ;;
    B10) run "B10. pitchbook-builder stub (5 tools)"   scenario_b10_pitchbook_stub ;;
    B11) run "B11. capability_gate denial probe"       scenario_b11_capability_denial ;;
    B12) run "B12. release tarball cold-reader test"   scenario_b12_release_tarball ;;
    *)   echo "${C_ERR}unknown scenario: $s${C_RST}" >&2; FAIL=$((FAIL+1)) ;;
  esac
done

echo "" >&2
echo "${C_BOLD}════════════════════════════════════════════════════════════════════${C_RST}" >&2
if [[ $FAIL -eq 0 ]]; then
  echo "  ${C_OK}${C_BOLD}[extras] PASS=$PASS FAIL=$FAIL${C_RST}" >&2
else
  echo "  ${C_ERR}${C_BOLD}[extras] PASS=$PASS FAIL=$FAIL${C_RST}" >&2
fi
echo "${C_BOLD}════════════════════════════════════════════════════════════════════${C_RST}" >&2

exit $((FAIL > 0 ? 1 : 0))
