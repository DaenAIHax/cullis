#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — agent enrollment helpers
# =============================================================================
#
# The Mastio's POST /v1/admin/agents endpoint mints a fresh Org-CA-
# signed cert + private key when both fields are omitted in the
# request body. That's the path scenarios use — no host-side openssl
# required.
#
# The cert + key arrive in the JSON response; we write them under
# state/agents/<name>/{cert.pem,key.pem} so downstream scenarios can
# pass them to curl_mtls.
# =============================================================================

if [[ -z "${_SMOKE_COMMON_SOURCED:-}" ]]; then
    # shellcheck source=./_common.sh
    source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
    _SMOKE_COMMON_SOURCED=1
fi

# Enroll an agent via POST /v1/admin/agents. Args:
#   $1  agent_name (e.g. "alice")
#   $2  display_name (optional, defaults to agent_name)
#   $3  capabilities JSON array (optional, defaults to the standard
#       smoke set: ["llm.chat","mcp.tools.list"]). Pass "[]" for the
#       negative scenarios that exercise the capability gate.
#
# Side effects: writes state/agents/<name>/cert.pem +
# state/agents/<name>/key.pem with the minted material. Echoes the
# fully-qualified agent_id (<org>::<name>) on stdout.
agent_enroll() {
    local name="$1" display="${2:-$1}"
    local capabilities="${3:-[\"llm.chat\",\"mcp.tools.list\"]}"
    local body resp agent_dir agent_id

    body=$(printf '{"agent_name":"%s","display_name":"%s","capabilities":%s}' \
        "$name" "$display" "$capabilities")
    resp="$(curl_admin POST "/v1/admin/agents" "$body")" \
        || die "agent enrollment failed (HTTP $(smoke_status)): $resp"

    agent_id="$(json_get "$resp" 'agent_id')"
    [[ -n "$agent_id" ]] || die "enrollment response missing agent_id: $resp"

    agent_dir="$SMOKE_STATE_DIR/agents/$name"
    mkdir -p "$agent_dir"

    local cert_pem key_pem
    cert_pem="$(json_get "$resp" 'cert_pem')"
    key_pem="$(json_get "$resp" 'private_key_pem')"
    [[ -n "$cert_pem" && -n "$key_pem" ]] \
        || die "enrollment response missing cert_pem/private_key_pem"

    printf '%s\n' "$cert_pem" > "$agent_dir/cert.pem"
    printf '%s\n' "$key_pem" > "$agent_dir/key.pem"
    chmod 0600 "$agent_dir/key.pem"

    # Remember the agent_id for cross-scenario use.
    state_put "agents/$name/id" "$agent_id"

    log_info "enrolled $agent_id (cert + key in ${agent_dir#$SMOKE_ROOT/})"
    printf '%s' "$agent_id"
}

# Read back the cert path for an enrolled agent.
agent_cert_path() {
    printf '%s/agents/%s/cert.pem' "$SMOKE_STATE_DIR" "$1"
}
agent_key_path() {
    printf '%s/agents/%s/key.pem' "$SMOKE_STATE_DIR" "$1"
}

# Verify the cert file exists and is a syntactically valid x509 PEM.
# Useful for negative assertions (e.g. confirming a missing enroll
# really did not write a file).
agent_cert_exists() {
    local name="$1" path
    path="$(agent_cert_path "$name")"
    [[ -s "$path" ]] && head -1 "$path" | grep -q 'BEGIN CERTIFICATE'
}
