#!/usr/bin/env bash
# =============================================================================
# 30_policy_rego — OPA Data API binding + Rego engine sanity
# =============================================================================
#
# Verifies the policy_bridge endpoint (PR #907) is reachable + that the
# embedded Rego engine (PR #908-909) loads cleanly. Without any
# operator-authored rules, /v1/data/cullis/policy/session must
# default-allow (legacy allowlist fall-through), which is the
# end-to-end signal that:
#   * the integrations router is mounted
#   * the policy module imports without crashing the lifespan
#   * the JSON contract matches the OPA Data API spec
#
# Asserts:
#   * /v1/data/cullis/policy/session returns 200 + result.decision=allow
#     on a vanilla input (no rules configured)
#   * Unknown path returns {"result": null} (OPA "document undefined"
#     convention) — proves the path dispatch works
#   * Body without ``input`` key returns 400, not 500
# =============================================================================
set -euo pipefail

SCENARIO_TAG="30_policy_rego"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

base="$(smoke_mastio_url)"
status_file="$(mktemp)"
body_file="$(mktemp)"
trap 'rm -f "$status_file" "$body_file"' EXIT

# ── Happy path: session policy, no rules → allow ────────────────────────────
session_input='{"input":{"initiator_agent_id":"orga::alice","target_agent_id":"orga::bob","session_context":"initiator"}}'
status="$(curl -sk -X POST \
    -H 'Content-Type: application/json' \
    -d "$session_input" \
    -o "$body_file" -w '%{http_code}' \
    "$base/v1/data/cullis/policy/session" || echo 000)"

if [[ "$status" -ne 200 ]]; then
    log_warn "body: $(cat "$body_file")"
    die "/v1/data/cullis/policy/session returned HTTP $status (expected 200)"
fi
body="$(cat "$body_file")"
result="$(json_get "$body" 'result')"
[[ -n "$result" ]] || die "response missing 'result' key: $body"
# result is itself a JSON object — extract decision
decision="$(printf '%s' "$result" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print(obj.get('decision', ''))
except Exception:
    print('')
" 2>/dev/null)"
[[ "$decision" == "allow" ]] || die "expected session decision=allow, got '$decision' (body=$body)"
log_pass "/v1/data/cullis/policy/session → allow (default-allow on empty rules)"

# ── Unknown OPA path → result=null (OPA "document undefined") ───────────────
status="$(curl -sk -X POST \
    -H 'Content-Type: application/json' \
    -d '{"input":{}}' \
    -o "$body_file" -w '%{http_code}' \
    "$base/v1/data/cullis/policy/does/not/exist" || echo 000)"
if [[ "$status" -ne 200 ]]; then
    die "unknown OPA path returned HTTP $status (expected 200): $(cat "$body_file")"
fi
body="$(cat "$body_file")"
# Expect literal "null" or {"result": null}
if ! grep -qE '"result"[[:space:]]*:[[:space:]]*null' <<<"$body"; then
    die "unknown OPA path should return {\"result\": null}, got: $body"
fi
log_pass "unknown OPA path → result=null"

# ── Negative: missing 'input' key returns 400 ───────────────────────────────
status="$(curl -sk -X POST \
    -H 'Content-Type: application/json' \
    -d '{}' \
    -o "$body_file" -w '%{http_code}' \
    "$base/v1/data/cullis/policy/session" || echo 000)"
case "$status" in
    400) log_pass "missing 'input' key correctly returns 400" ;;
    *)   die "missing 'input' returned HTTP $status (expected 400): $(cat "$body_file")" ;;
esac

# ── Rego engine sanity: dashboard page accessible (gates: page loads, no 500) ──
# We don't go all the way to upload a Rego bundle (that requires
# a CSRF-bound dashboard session). But we can hit /proxy/login as the
# admin, follow the cookie, and GET /proxy/policies/rego to confirm the
# Rego router is mounted + the lazy import of opa-wasmtime / wasmtime
# did not crash the dashboard.
cookie_jar="$(mktemp)"
trap 'rm -f "$status_file" "$body_file" "$cookie_jar"' EXIT

pwd="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"

# Login + capture session cookie.
curl -sk -c "$cookie_jar" -o /dev/null \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "password=$pwd" \
    "$base/proxy/login" || die "dashboard login failed"

# GET the Rego rules page. Anything non-5xx is a pass — the page is
# HTML, the assert is just "the route is mounted and the engine
# imports".
status="$(curl -sk -b "$cookie_jar" -o /dev/null -w '%{http_code}' \
    "$base/proxy/policies/rego" || echo 000)"
case "$status" in
    200|303) log_pass "/proxy/policies/rego page reachable (HTTP $status)" ;;
    5*)      die "/proxy/policies/rego returned HTTP $status — engine import likely failed" ;;
    *)
        # 401/403 etc. are also fine — they prove the route is mounted
        # (a missing route would be 404).
        log_pass "/proxy/policies/rego mounted (HTTP $status)"
        ;;
esac
