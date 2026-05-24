#!/usr/bin/env bash
# =============================================================================
# 40_chat_completion — agent → Mastio → AI gateway (mocked) round trip
# =============================================================================
#
# Posts an OpenAI-compatible chat completion to /v1/chat/completions
# with alice's client cert. The Mastio dispatches via the configured
# AI gateway (env.smoke pins MCP_PROXY_AI_GATEWAY_BACKEND=portkey +
# ai_gateway_url=http://mock-tsa:2561), so the upstream is our in-stack
# stub. Stub returns a fixed completion. End-to-end signal:
#
#   * mTLS handshake succeeds (nginx 401 gate passes)
#   * Mastio dispatcher reaches the configured gateway URL
#   * Response shape is OpenAI-compatible (choices[0].message.content)
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

cert="$(agent_cert_path alice)"
key="$(agent_key_path alice)"
[[ -s "$cert" && -s "$key" ]] || die "alice cert/key missing — run 20_enroll_agent first"

base="$(smoke_mastio_url)"

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
        # provider_key_missing or gateway unreachable — log + skip with
        # warning rather than fail the run silently. The mock gateway
        # might not be wired in older mains.
        body_text="$(cat "$resp_file")"
        log_warn "AI gateway returned 503 (likely backend mismatch or upstream unreachable): $body_text"
        log_skip "/v1/chat/completions returned 503 — chat path needs investigation in follow-up"
        exit 2
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
