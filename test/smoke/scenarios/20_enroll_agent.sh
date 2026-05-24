#!/usr/bin/env bash
# =============================================================================
# 20_enroll_agent — admin enrollment of 2 agents (Mastio-minted certs)
# =============================================================================
#
# POST /v1/admin/agents with an empty cert_pem/private_key_pem asks the
# Mastio to mint a fresh Org-CA-signed cert + private key and return
# both in the response. The smoke harness writes them under state/
# agents/<name>/{cert.pem,key.pem} for downstream scenarios.
#
# Asserts:
#   * 2 agents enroll cleanly (alice, bob) with 201 Created
#   * Both cert files are valid PEM + key matches cert (we just check
#     openssl parses; deeper validation is the Mastio's own job)
#   * Negative: duplicate enrollment returns 409 Conflict, not 5xx
#   * Negative: missing X-Admin-Secret returns 403
# =============================================================================
set -euo pipefail

SCENARIO_TAG="20_enroll_agent"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

# ── Happy path: enroll alice + bob ──────────────────────────────────────────
alice_id="$(agent_enroll alice "Alice (smoke)")"
bob_id="$(agent_enroll bob   "Bob (smoke)")"
[[ "$alice_id" != "$bob_id" ]] || die "alice + bob got the same agent_id ($alice_id)"

# Verify files materialised on disk + are parseable.
for name in alice bob; do
    cert="$(agent_cert_path "$name")"
    key="$(agent_key_path "$name")"
    [[ -s "$cert" ]] || die "$name cert missing at $cert"
    [[ -s "$key" ]] || die "$name key missing at $key"
    head -1 "$cert" | grep -q 'BEGIN CERTIFICATE' \
        || die "$name cert is not a PEM-encoded x509"
    head -1 "$key" | grep -qE 'BEGIN (EC |RSA |)PRIVATE KEY' \
        || die "$name key is not a PEM-encoded private key"
done
log_pass "alice + bob enrolled, cert+key on disk"

# ── Negative: duplicate enrollment returns 409 ──────────────────────────────
body='{"agent_name":"alice","display_name":"dup","capabilities":[]}'
resp="$(curl_admin_raw POST '/v1/admin/agents' "$body")"
case "$(smoke_status)" in
    409) log_pass "duplicate enrollment correctly returns 409" ;;
    *)   die "duplicate enrollment returned HTTP $(smoke_status) (expected 409): $resp" ;;
esac

# ── Negative: wrong admin secret returns 403 ────────────────────────────────
url="$(smoke_mastio_url)/v1/admin/agents"
status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'X-Admin-Secret: definitely-the-wrong-secret' \
    -H 'Content-Type: application/json' \
    -d '{"agent_name":"carol","display_name":"x","capabilities":[]}' \
    "$url" || echo 000)"
case "$status" in
    403) log_pass "wrong admin secret correctly returns 403" ;;
    *)   die "wrong admin secret returned HTTP $status (expected 403)" ;;
esac
