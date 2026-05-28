#!/usr/bin/env bash
# =============================================================================
# 42_anthropic_capability_denied — negative gate for #22 / B1 (v0.6.4)
# =============================================================================
#
# Mirror of 41_chat_capability_denied for the Anthropic Messages API
# surface (POST /v1/messages). Pre-v0.6.4 the docstring claimed "Same
# security gates as /v1/chat/completions" but neither the capability
# gate nor scope_providers was actually applied; an agent without
# llm.chat could egress via the Anthropic shape unimpeded.
#
# Asserts:
#   * cap-less agent receives HTTP 403 with reason=capability_missing
#     and required_capability=llm.chat on POST /v1/messages.
#   * No body content from the upstream stub (which would echo
#     "smoke-mock-ok") — proves dispatch never ran.
#
# Reuses the ``nocap`` agent created by 41 to avoid re-enrolling.
# =============================================================================
set -euo pipefail

SCENARIO_TAG="42_anthropic_capability_denied"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

cert="$(agent_cert_path nocap)"
key="$(agent_key_path nocap)"
[[ -s "$cert" && -s "$key" ]] \
    || die "nocap cert/key missing — scenario 41 must run before 42"

base="$(smoke_mastio_url)"
body='{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"should be denied"}],"max_tokens":16}'

resp_file="$(mktemp)"
trap 'rm -f "$resp_file"' EXIT

status="$(curl -sk \
    --cert "$cert" --key "$key" \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$body" \
    -o "$resp_file" -w '%{http_code}' \
    "$base/v1/messages" || echo 000)"

resp="$(cat "$resp_file")"

case "$status" in
    403)
        echo "$resp" | grep -q 'capability_missing' \
            || die "expected reason=capability_missing on /v1/messages: $resp"
        echo "$resp" | grep -q 'llm.chat' \
            || die "expected required_capability=llm.chat: $resp"
        log_pass "cap-less agent denied at /v1/messages (HTTP 403, llm.chat)"
        ;;
    200)
        die "FAIL CLOSED VIOLATION — cap-less agent reached anthropic dispatch: $resp"
        ;;
    *)
        die "unexpected HTTP $status from /v1/messages: $resp"
        ;;
esac
