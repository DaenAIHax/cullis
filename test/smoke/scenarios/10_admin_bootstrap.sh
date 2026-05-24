#!/usr/bin/env bash
# =============================================================================
# 10_admin_bootstrap — admin password seed + Org CA export + org_id readable
# =============================================================================
#
# Asserts:
#   * /proxy/login accepts the seeded MCP_PROXY_INITIAL_ADMIN_PASSWORD
#     and 303-redirects to the dashboard
#   * The Org CA has been minted (nginx-certs/org-ca.crt exists +
#     parses as PEM) and is reachable from the host bind dir
#   * org_id is present in proxy_config (16-char hex, the first-boot
#     marker)
#   * Negative: a wrong password returns 401, NOT 5xx
# =============================================================================
set -euo pipefail

SCENARIO_TAG="10_admin_bootstrap"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_admin.sh
source "$SMOKE_LIB_DIR/_admin.sh"

# ── Org CA exported to host bind dir ────────────────────────────────────────
if ! admin_export_org_ca; then
    die "org-ca.crt missing from state/nginx-certs/ — Mastio first-boot did not complete"
fi
ca_path="$(smoke_org_ca_path)"
head -1 "$ca_path" | grep -q 'BEGIN CERTIFICATE' \
    || die "exported org-ca is not a PEM-encoded x509 cert"
log_pass "Org CA exported to ${ca_path#$SMOKE_ROOT/}"

# ── org_id readable from proxy_config ───────────────────────────────────────
org_id="$(admin_read_org_id)"
[[ -n "$org_id" ]] || die "proxy_config.org_id is empty — first-boot derive failed"
# Expected format: 16-char lowercase hex (Mastio derives a SHA-256 prefix).
if ! [[ "$org_id" =~ ^[a-f0-9]{16}$ ]]; then
    log_warn "org_id has unexpected shape: '${org_id}' (expected 16-char hex)"
fi
state_put "org_id" "$org_id"
log_pass "org_id=${org_id}"

# ── Happy path: seeded admin password works ─────────────────────────────────
if ! admin_verify_seed_password; then
    die "seeded admin password did not authenticate (HTTP $(smoke_status))"
fi
log_pass "seeded admin password accepted (HTTP $(smoke_status))"

# ── Negative: wrong password returns 401, not 5xx ───────────────────────────
url="$(smoke_mastio_url)/proxy/login"
wrong_status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password=definitely-not-the-real-password' \
    "$url" || echo 000)"
case "$wrong_status" in
    401|429)
        # 429 is also acceptable (rate-limit kicked in after our happy-
        # path login a moment ago — H9 audit lockout).
        log_pass "wrong password rejected with HTTP $wrong_status"
        ;;
    *)
        die "wrong password returned HTTP $wrong_status (expected 401 or 429)"
        ;;
esac

# ── X-Admin-Secret on /v1/admin/mastio-pubkey works ─────────────────────────
# This is the canonical admin-secret-gated endpoint and proves the
# header path is healthy end-to-end (admin_secret env passed through
# compose → settings → header compare).
resp="$(curl_admin GET '/v1/admin/mastio-pubkey')" \
    || die "/v1/admin/mastio-pubkey rejected admin secret (HTTP $(smoke_status)): $resp"
returned_org_id="$(json_get "$resp" 'org_id')"
[[ "$returned_org_id" == "$org_id" ]] \
    || die "admin pubkey endpoint returned different org_id: '$returned_org_id' vs '$org_id'"
log_pass "X-Admin-Secret gate honoured + org_id consistent"
