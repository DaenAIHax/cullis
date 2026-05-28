#!/usr/bin/env bash
# =============================================================================
# 41_chat_capability_denied — negative gate for #22 (Mastio v0.6.4)
# =============================================================================
#
# Enrolls a third agent with an empty capabilities list, runs the same
# OpenAI-compatible chat completion alice does in 40, and asserts the
# Mastio fails closed at the capability gate before reaching the AI
# gateway:
#
#   * HTTP 403 with detail.reason == "capability_missing"
#   * detail.required_capability == "llm.chat"
#   * No mock-gateway call (we know because the stub would have echoed
#     "smoke-mock-ok"; we never see that string)
#
# This is the defense-in-depth signal the HN narrative leans on: the
# capability isn't decorative, it's the first gate after DPoP+mTLS auth.
# =============================================================================
set -euo pipefail

SCENARIO_TAG="41_chat_capability_denied"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

# ── Enroll cap-less agent ───────────────────────────────────────────────────
nocap_id="$(agent_enroll nocap "No-Capability (smoke #41)" '[]')"
cert="$(agent_cert_path nocap)"
key="$(agent_key_path nocap)"
[[ -s "$cert" && -s "$key" ]] || die "nocap cert/key missing"
log_pass "enrolled $nocap_id with capabilities=[]"

base="$(smoke_mastio_url)"
body='{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"should be denied"}]}'

resp_file="$(mktemp)"
trap 'rm -f "$resp_file"' EXIT

status="$(curl -sk \
    --cert "$cert" --key "$key" \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$body" \
    -o "$resp_file" -w '%{http_code}' \
    "$base/v1/chat/completions" || echo 000)"

resp="$(cat "$resp_file")"

case "$status" in
    403)
        echo "$resp" | grep -q 'capability_missing' \
            || die "expected reason=capability_missing, got: $resp"
        echo "$resp" | grep -q 'llm.chat' \
            || die "expected required_capability=llm.chat, got: $resp"
        log_pass "cap-less agent denied at capability gate (HTTP 403, llm.chat)"
        ;;
    200)
        die "FAIL CLOSED VIOLATION — cap-less agent reached the gateway: $resp"
        ;;
    *)
        die "unexpected HTTP $status from cap-less chat call: $resp"
        ;;
esac

# ── Streaming branch must hit the same gate ─────────────────────────────────
stream_body='{"model":"anthropic/claude-haiku-4-5","stream":true,"messages":[{"role":"user","content":"stream-deny"}]}'
status="$(curl -sk \
    --cert "$cert" --key "$key" \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$stream_body" \
    -o "$resp_file" -w '%{http_code}' \
    "$base/v1/chat/completions" || echo 000)"
case "$status" in
    403) log_pass "cap-less agent denied on streaming path too (HTTP 403)" ;;
    *)   die "streaming chat returned HTTP $status (expected 403): $(cat "$resp_file")" ;;
esac
