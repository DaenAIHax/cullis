#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — admin bootstrap helpers
# =============================================================================
#
# First-boot admin password is seeded via MCP_PROXY_INITIAL_ADMIN_PASSWORD
# (env.smoke) so /proxy/register doesn't have to be driven by a browser.
# These helpers exist for:
#   * verify the seed actually landed (curl /proxy/login + expect 200)
#   * fetch the Org CA from the running Mastio for host-side trust
#   * read org_id out of the running container
#
# Auth model used by every /v1/admin/* call: X-Admin-Secret header,
# pinned to MCP_PROXY_ADMIN_SECRET. The dashboard cookie session is NOT
# used here — scenarios that need dashboard semantics would have to
# layer a separate login helper.
# =============================================================================

# Source guard — only source _common.sh once even if multiple scenarios
# pull both _admin.sh and _agent.sh.
if [[ -z "${_SMOKE_COMMON_SOURCED:-}" ]]; then
    # shellcheck source=./_common.sh
    source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
    _SMOKE_COMMON_SOURCED=1
fi

# Fetch the Org CA the Mastio minted at first boot. The host bind dir
# state/nginx-certs/ is owned by uid 10001 (the container user) and
# mode 0750, so the host invoker cannot read it directly. Use ``docker
# cp`` from inside the running mcp-proxy container — same pattern as
# packaging/mastio-bundle/deploy.sh:961.
admin_export_org_ca() {
    local dst="$(smoke_org_ca_path)"
    local cid
    cid="$(smoke_compose ps -q mcp-proxy 2>/dev/null | head -1)"
    if [[ -z "$cid" ]]; then
        log_warn "mcp-proxy container id not found — stack may not be up"
        return 1
    fi
    if docker cp "$cid:/var/lib/mastio/nginx-certs/org-ca.crt" "$dst" 2>/dev/null; then
        chmod 0644 "$dst"
        log_info "org CA exported to ${dst#$SMOKE_ROOT/}"
        return 0
    fi
    log_warn "docker cp org-ca.crt failed — mastio may not have first-booted yet"
    return 1
}

# Read org_id from the running Mastio's SQLite (or Postgres). Returns
# 16-char hex on stdout. Used by 10_admin_bootstrap to assert the
# Mastio actually completed first-boot.
admin_read_org_id() {
    local val=""
    val="$(smoke_compose exec -T mcp-proxy python3 -c "
import os
import sys
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    if url.startswith('postgresql'):
        import psycopg2  # type: ignore[import-not-found]
        # asyncpg → sync URL conversion: keep what's after :// but drop
        # the asyncpg dialect for the sync psycopg2 connect string.
        import re
        sync_url = re.sub(r'^postgresql\+asyncpg://', 'postgresql://', url)
        conn = psycopg2.connect(sync_url)
        cur = conn.cursor()
        cur.execute(\"SELECT value FROM proxy_config WHERE key='org_id'\")
        row = cur.fetchone()
    else:
        import sqlite3
        path = url.replace('sqlite+aiosqlite:////', '/').replace('sqlite+aiosqlite:///', '/')
        conn = sqlite3.connect(path)
        row = conn.execute(\"SELECT value FROM proxy_config WHERE key='org_id'\").fetchone()
    print(row[0] if row else '')
except Exception as exc:
    print('', end='')
    print(f'org-id-read-error: {exc}', file=sys.stderr)
" 2>/dev/null)"
    printf '%s' "$val"
}

# Verify the admin password seed was honoured. The Mastio writes the
# bcrypt hash on first boot if MCP_PROXY_INITIAL_ADMIN_PASSWORD is
# set; we hit /proxy/login with the seeded password and expect a 303
# redirect to the post-login page.
admin_verify_seed_password() {
    local pwd
    pwd="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"
    [[ -n "$pwd" ]] || die "MCP_PROXY_INITIAL_ADMIN_PASSWORD not set in env.smoke"

    local url status
    url="$(smoke_mastio_url)/proxy/login"
    # POST the form, do NOT follow redirects (we want to see the 303).
    # Login form expects ``password`` field; CSRF is form-token enforced
    # only when a session cookie is present, which we don't have yet.
    status="$(curl -sk -o /dev/null -w '%{http_code}' \
        -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "password=$pwd" \
        "$url" || echo 000)"
    _set_smoke_status "$status"
    case "$status" in
        303|302) return 0 ;;  # success → redirect
        *)
            log_warn "expected 303 on login submit, got HTTP $status"
            return 1
            ;;
    esac
}
