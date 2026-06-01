#!/usr/bin/env bash
# =============================================================================
# 35_rego_policy_deny — operator-authored Rego, loaded via the dashboard,
#                       actually denies a live PDP decision
# =============================================================================
#
# Scenario 30 proves the Rego engine is mounted and that an EMPTY policy
# default-allows the session surface. This scenario closes the other
# half: an operator pastes a Rego policy into the dashboard, the Mastio
# compiles it with the bundled ``opa build`` (the real compile path —
# only exercised here, not in the opa-mocked unit tests), persists the
# WASM bundle, and the very next /v1/data/cullis/policy/session call is
# decided by that bundle. This is the end-to-end "load a policy → see
# the deny" signal the unit suite cannot give (it mocks the opa binary).
#
# The policy is scoped so it only denies a sentinel initiator and
# default-allows everything else, so later scenarios (40 inference,
# 50 mcp tool call) are unaffected even before the explicit cleanup.
#
# Asserts:
#   * POST /proxy/policies/rego/save (admin session + CSRF) compiles the
#     Rego and returns 303 (success redirect), not 400 (compile error)
#   * /v1/data/cullis/policy/session with the sentinel initiator →
#     result.decision=deny (the loaded Rego flipped the default-allow)
#   * /v1/data/cullis/policy/session with a non-sentinel initiator →
#     result.decision=allow (the Rego's default-allow still passes the
#     traffic later scenarios depend on)
#   * after the cleanup delete, the sentinel goes back to allow (the
#     bundle was removed, no restart — the live-reload contract holds)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="35_rego_policy_deny"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

base="$(smoke_mastio_url)"
cookie_jar="$(mktemp)"
body_file="$(mktemp)"
trap 'rm -f "$cookie_jar" "$body_file"' EXIT

# ── Helper: extract result.decision from a bridge response body ─────────────
_bridge_decision() {
    local body="$1" result
    result="$(json_get "$body" 'result')"
    [[ -n "$result" ]] || { printf ''; return; }
    printf '%s' "$result" | python3 -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('decision', ''))
except Exception:
    print('')
" 2>/dev/null
}

# ── Helper: POST a session input to the bridge, echo the decision ───────────
_session_decision() {
    local initiator="$1" status
    local input="{\"input\":{\"initiator_agent_id\":\"$initiator\",\"target_agent_id\":\"orga::bob\",\"initiator_org_id\":\"orga\",\"target_org_id\":\"orga\",\"session_context\":\"initiator\"}}"
    status="$(curl -sk -X POST \
        -H 'Content-Type: application/json' \
        -d "$input" \
        -o "$body_file" -w '%{http_code}' \
        "$base/v1/data/cullis/policy/session" || echo 000)"
    [[ "$status" -eq 200 ]] || die "bridge session returned HTTP $status (expected 200): $(cat "$body_file")"
    _bridge_decision "$(cat "$body_file")"
}

# ── Admin login (seeded password) + capture session cookie ──────────────────
pwd="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"
[[ -n "$pwd" ]] || die "MCP_PROXY_INITIAL_ADMIN_PASSWORD not set in env.smoke"

curl -sk -c "$cookie_jar" -o /dev/null \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "password=$pwd" \
    "$base/proxy/login" || die "dashboard login failed"

# ── Extract the CSRF token rendered into the Rego editor form ───────────────
curl -sk -b "$cookie_jar" -o "$body_file" "$base/proxy/policies/rego" \
    || die "GET /proxy/policies/rego failed"
csrf="$(grep -oE 'name="csrf_token"[^>]*value="[a-f0-9]+"' "$body_file" \
    | grep -oE 'value="[a-f0-9]+"' | head -1 | cut -d'"' -f2)"
[[ -n "$csrf" ]] || die "could not extract csrf_token from /proxy/policies/rego (login may have failed)"
log_pass "admin session established + CSRF token extracted"

# ── Save an operator Rego: deny one sentinel initiator, allow the rest ──────
# Rego v1 syntax (``if {``), matching site/.../operate/rego-policies.md.
# ``default`` keeps every other principal (and the whole tool_call
# surface) on allow so scenarios 40/50 are not disturbed.
read -r -d '' rego_src <<'REGO' || true
package cullis.policy

default session := {"decision": "allow"}
default tool_call := {"decision": "allow"}

session := {"decision": "deny", "reason": "smoke35 sentinel deny"} if {
    input.initiator_agent_id == "smoketest::denied"
}
REGO

status="$(curl -sk -b "$cookie_jar" \
    -X POST \
    --data-urlencode "csrf_token=$csrf" \
    --data-urlencode "rego=$rego_src" \
    -o "$body_file" -w '%{http_code}' \
    "$base/proxy/policies/rego/save" || echo 000)"
case "$status" in
    303|200) log_pass "Rego compiled + persisted via dashboard (HTTP $status)" ;;
    400)     die "opa build rejected the Rego (HTTP 400): $(cat "$body_file" | head -c 400)" ;;
    *)       die "/proxy/policies/rego/save returned HTTP $status: $(cat "$body_file" | head -c 400)" ;;
esac

# ── The loaded Rego denies the sentinel on a live decision ──────────────────
decision="$(_session_decision 'smoketest::denied')"
[[ "$decision" == "deny" ]] \
    || die "expected sentinel session decision=deny after Rego load, got '$decision'"
log_pass "operator Rego enforced live → sentinel session DENY"

# ── …and default-allows the traffic later scenarios rely on ─────────────────
decision="$(_session_decision 'orga::alice')"
[[ "$decision" == "allow" ]] \
    || die "expected non-sentinel session decision=allow (Rego default), got '$decision'"
log_pass "non-sentinel session still ALLOW (Rego default-allow preserved)"

# ── Cleanup: delete the bundle, confirm live-reload reverts to allow ────────
status="$(curl -sk -b "$cookie_jar" \
    -X POST \
    --data-urlencode "csrf_token=$csrf" \
    -o /dev/null -w '%{http_code}' \
    "$base/proxy/policies/rego/delete" || echo 000)"
case "$status" in
    303|200) : ;;
    *)       die "/proxy/policies/rego/delete returned HTTP $status" ;;
esac

decision="$(_session_decision 'smoketest::denied')"
[[ "$decision" == "allow" ]] \
    || die "sentinel still '$decision' after Rego delete — live-reload/cleanup broken"
log_pass "Rego deleted → sentinel back to ALLOW (live-reload, no restart)"
