#!/usr/bin/env bash
# =============================================================================
# 40_chat_completion — agent → Mastio → AI gateway (mocked) round trip
# =============================================================================
#
# Posts an OpenAI-compatible chat completion to /v1/chat/completions
# with alice's client cert. The smoke runs the PRODUCT DEFAULT backend
# MCP_PROXY_AI_GATEWAY_BACKEND=cullis_native, so the Mastio dispatches
# through the native anthropic.AsyncAnthropic SDK (NOT the deprecated
# portkey path). We seed an ai_provider_credentials row whose api_base
# points the SDK at the in-stack mock (mock-tsa:2561, /v1/messages
# Anthropic shape) so the call stays offline + deterministic.
#
# This is the regression guard for packaging gaps like #1005: if the
# image ships without the anthropic SDK, the native adapter returns
# 503 provider_sdk_missing here — a failure the old portkey-only smoke
# could never surface. End-to-end signal:
#
#   * mTLS handshake succeeds (nginx 401 gate passes)
#   * cullis_native dispatch loads the native SDK + reaches the mock
#   * Anthropic Messages response → OpenAI shape (choices[0].message…)
#   * Audit row written (verified in 60_audit_chain)
#
# Asserts:
#   * 200 with stub's fixed content string in the response
#   * Negative: same call without a client cert returns 401 from nginx
# =============================================================================
set -euo pipefail

SCENARIO_TAG="40_chat_completion"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"
# shellcheck source=../lib/_admin.sh
source "$SMOKE_LIB_DIR/_admin.sh"

cert="$(agent_cert_path alice)"
key="$(agent_key_path alice)"
[[ -s "$cert" && -s "$key" ]] || die "alice cert/key missing — run 20_enroll_agent first"

base="$(smoke_mastio_url)"

# ── Seed the native anthropic provider creds → mock upstream ─────────────────
# cullis_native resolves the base_url from ai_provider_credentials, not
# from MCP_PROXY_AI_GATEWAY_URL. Point it at the mock so the SDK call
# stays in-stack. Without this row the native adapter would fall back to
# settings.anthropic_api_key with no base_url and dial api.anthropic.com.
if admin_seed_ai_provider_creds anthropic "http://mock-tsa:2561" >/dev/null; then
    log_pass "seeded anthropic provider creds (api_base → mock-tsa:2561)"
else
    die "failed to seed anthropic provider creds — cullis_native cannot reach the mock"
fi

# ── Happy path: mTLS chat completion ────────────────────────────────────────
# Use a recognised provider/model so parse_provider_from_model() in the
# Mastio doesn't reject the request before reaching the gateway. The
# stub doesn't care about the model name — it echoes whatever arrives.
body='{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"smoke ping"}]}'
resp_file="$(mktemp)"
trap 'rm -f "$resp_file"' EXIT

status="$(curl -sk \
    --cert "$cert" --key "$key" \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$body" \
    -o "$resp_file" -w '%{http_code}' \
    "$base/v1/chat/completions" || echo 000)"

case "$status" in
    200)
        resp="$(cat "$resp_file")"
        content="$(printf '%s' "$resp" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print(obj['choices'][0]['message']['content'])
except Exception as exc:
    print(f'parse-error:{exc}')
" 2>/dev/null)"
        if [[ "$content" == "smoke-mock-ok" ]]; then
            log_pass "chat completion → 200, content='smoke-mock-ok' (mock gateway reachable)"
        else
            die "unexpected content from mock gateway: '$content' (full: $resp)"
        fi
        ;;
    401|403)
        die "Mastio rejected mTLS chat call (HTTP $status). cert path: $cert. Response: $(cat "$resp_file")"
        ;;
    503)
        # Hard fail: under cullis_native with creds seeded + the mock
        # reachable, a 503 is a real defect — and provider_sdk_missing
        # is the #1005 packaging bug this scenario exists to catch. Do
        # NOT skip it (the old portkey smoke skipped 503, which is how
        # the missing anthropic/openai SDKs shipped unnoticed).
        body_text="$(cat "$resp_file")"
        die "/v1/chat/completions returned 503 under cullis_native: $body_text"
        ;;
    *)
        die "/v1/chat/completions returned HTTP $status: $(cat "$resp_file")"
        ;;
esac

# ── Negative: missing client cert → 401 at nginx ────────────────────────────
status="$(curl -sk \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$body" \
    -o /dev/null -w '%{http_code}' \
    "$base/v1/chat/completions" || echo 000)"
case "$status" in
    401|400) log_pass "no-cert call rejected at nginx with HTTP $status" ;;
    *)       die "no-cert chat call returned HTTP $status (expected 401)" ;;
esac
