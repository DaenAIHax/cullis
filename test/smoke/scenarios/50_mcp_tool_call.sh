#!/usr/bin/env bash
# =============================================================================
# 50_mcp_tool_call — mTLS-authenticated egress: peer discovery + resolve
# =============================================================================
#
# The classic MCP tool-call path on the Mastio (``/v1/mcp`` → JSON-RPC
# tools/call) requires a federated JWT, which isn't available in a
# standalone smoke. We assert the equivalent contract — the egress
# router correctly identifies the mTLS caller as a typed principal
# and routes capability-gated reads — by exercising:
#
#   * GET /v1/egress/peers  — lists alice+bob (the only enrolled
#     agents), confirms typed-principal recognition + the per-principal
#     capability filter (PR #730 gate)
#   * GET /v1/egress/agents/{id}/public-key — fetches bob's cert via
#     alice's session; proves the egress identity model end-to-end
#
# Asserts:
#   * /v1/egress/peers returns alice + bob (or bob from alice's view)
#   * /v1/egress/agents/.../public-key returns bob's cert PEM
#   * Negative: a third agent's cert (not enrolled) → 401 at nginx
# =============================================================================
set -euo pipefail

SCENARIO_TAG="50_mcp_tool_call"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

alice_cert="$(agent_cert_path alice)"
alice_key="$(agent_key_path alice)"
[[ -s "$alice_cert" && -s "$alice_key" ]] || die "alice cert/key missing"

bob_id="$(state_get "agents/bob/id")"
[[ -n "$bob_id" ]] || die "bob agent_id not in state — run 20_enroll_agent first"

base="$(smoke_mastio_url)"

# ── /v1/egress/peers as alice ───────────────────────────────────────────────
resp="$(curl -sk --cert "$alice_cert" --key "$alice_key" \
    -H 'Accept: application/json' \
    "$base/v1/egress/peers" || die "peers fetch failed")"
peers_count="$(printf '%s' "$resp" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    print(len(obj.get('peers', [])))
except Exception:
    print('0')
" 2>/dev/null)"
# Alice's listing should NOT include alice (self-row excluded) but
# MUST include bob (the only other enrolled agent).
if [[ "$peers_count" -lt 1 ]]; then
    die "expected at least 1 peer (bob), got count=$peers_count. body=$resp"
fi
if ! printf '%s' "$resp" | grep -qE '::bob"'; then
    die "bob not in alice's peer listing: $resp"
fi
log_pass "/v1/egress/peers returns ${peers_count} peer(s) including bob"

# ── /v1/egress/agents/{id}/public-key ───────────────────────────────────────
encoded_id="${bob_id//::/%3A%3A}"
resp="$(curl -sk --cert "$alice_cert" --key "$alice_key" \
    -H 'Accept: application/json' \
    "$base/v1/egress/agents/${encoded_id}/public-key" || die "public-key fetch failed")"
if ! printf '%s' "$resp" | grep -q 'BEGIN CERTIFICATE'; then
    die "public-key response did not contain a PEM cert: $resp"
fi
log_pass "/v1/egress/agents/${bob_id}/public-key returns bob's cert"

# ── Negative: unknown cert at TLS handshake → nginx 401 ─────────────────────
# Generate a throwaway self-signed cert that is NOT signed by the Org
# CA. nginx's ``ssl_verify_client optional`` accepts the handshake but
# the location block requires ``$ssl_client_verify = SUCCESS``, so the
# return is 401.
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# OpenSSL is widely available; if absent we skip this negative case.
if ! command -v openssl >/dev/null 2>&1; then
    log_skip "openssl not on host — negative case (unknown cert) skipped"
    exit 0
fi

openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout "$tmpdir/foreign.key" -out "$tmpdir/foreign.crt" \
    -days 1 -nodes -subj "/CN=foreign" >/dev/null 2>&1 \
    || { log_skip "openssl genreq failed — negative case skipped"; exit 0; }

status="$(curl -sk \
    --cert "$tmpdir/foreign.crt" --key "$tmpdir/foreign.key" \
    -o /dev/null -w '%{http_code}' \
    "$base/v1/egress/peers" || echo 000)"
case "$status" in
    400|401|403)
        # nginx returns 400 when the cert doesn't chain to the
        # ``ssl_client_certificate`` Org CA (handshake completes but
        # validation fails), 401 when ``ssl_verify_client`` rejects
        # the cert outright. Both prove the gate is enforced.
        log_pass "foreign cert rejected with HTTP $status"
        ;;
    *)
        die "foreign cert returned HTTP $status (expected 400/401/403)"
        ;;
esac
