#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — shared bash helpers
# =============================================================================
#
# Sourced by every scenario script and by smoke.sh. Provides:
#   * compose wrapper bound to env.smoke + the active overlay
#   * logging primitives with [NN_what] scenario tag
#   * HTTP helpers (curl wrappers that honour the smoke env)
#   * state file paths (state/) and atomic write helpers
#   * snapshot_on_fail — captures logs + state on any nonzero exit
#
# Every helper is idempotent. No global side effects beyond sourcing.
# =============================================================================

# Resolve smoke root regardless of caller cwd (worktree, /tmp, anything).
# BASH_SOURCE[0] points at THIS file (lib/_common.sh) so its parent's
# parent is test/smoke/.
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_ROOT="$(cd "$SMOKE_LIB_DIR/.." && pwd)"
SMOKE_STATE_DIR="$SMOKE_ROOT/state"

# Scenario tag — set by smoke.sh per scenario, falls back to filename.
: "${SCENARIO_TAG:=$(basename "${BASH_SOURCE[1]:-smoke}" .sh)}"

# Backend (sqlite|postgres). smoke.sh exports this; scenarios consume.
: "${SMOKE_BACKEND:=sqlite}"

# Always defined so ``set -u`` callers can read it before the first
# curl_admin / curl_mtls call.
: "${SMOKE_LAST_STATUS:=}"

# Compose overlay path — default sqlite, swapped by smoke.sh on --pg.
: "${SMOKE_COMPOSE_OVERLAY:=$SMOKE_ROOT/compose.sqlite.yml}"

# ── Logging ─────────────────────────────────────────────────────────────────

# All logs go to stderr so scenarios can use stdout for structured data
# (rarely needed but keeps the contract clean).
_log() {
    local level="$1"; shift
    printf '[%s] %s %s\n' "$SCENARIO_TAG" "$level" "$*" >&2
}
log_info() { _log "INFO" "$@"; }
log_warn() { _log "WARN" "$@"; }
log_pass() { _log "PASS" "$@"; }
log_fail() { _log "FAIL" "$@"; }
log_skip() { _log "SKIP" "$@"; }

# Die with a fail log + nonzero exit. Captured by snapshot trap in smoke.sh.
die() {
    log_fail "$*"
    exit 1
}

# ── Compose wrapper ─────────────────────────────────────────────────────────

# Pick the docker compose flavour available on this host. Cached so
# downstream calls don't re-probe every invocation.
_compose_cmd() {
    if [[ -n "${_COMPOSE_CACHED:-}" ]]; then
        printf '%s' "$_COMPOSE_CACHED"
        return 0
    fi
    if docker compose version >/dev/null 2>&1; then
        _COMPOSE_CACHED="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        _COMPOSE_CACHED="docker-compose"
    else
        die "docker compose is not installed (need either 'docker compose' or 'docker-compose')"
    fi
    printf '%s' "$_COMPOSE_CACHED"
}

# ``smoke_compose <args...>`` — invoke compose with env.smoke + overlay.
# Always prints to stderr what it ran so failing runs are diagnosable.
smoke_compose() {
    local cmd
    cmd="$(_compose_cmd)"
    # Bind COMPOSE_PROJECT_NAME at the env-file level (env.smoke sets it)
    # so every compose call lands in the same project namespace.
    # shellcheck disable=SC2086
    $cmd \
        --project-directory "$SMOKE_ROOT" \
        --env-file "$SMOKE_ROOT/env.smoke" \
        -f "$SMOKE_ROOT/compose.yml" \
        -f "$SMOKE_COMPOSE_OVERLAY" \
        "$@"
}

# ── State files ─────────────────────────────────────────────────────────────

# state/ holds cross-scenario shared state (admin password, agent
# identities, etc.). Gitignored. Atomic writes via temp + mv.

smoke_state_init() {
    mkdir -p "$SMOKE_STATE_DIR"
}

# Write a value to state/<name> atomically.
state_put() {
    local name="$1" value="$2"
    smoke_state_init
    local target="$SMOKE_STATE_DIR/$name"
    local tmp="${target}.tmp.$$"
    printf '%s' "$value" > "$tmp"
    mv "$tmp" "$target"
}

# Read state/<name>; empty string when missing.
state_get() {
    local name="$1"
    local target="$SMOKE_STATE_DIR/$name"
    [[ -f "$target" ]] || { printf ''; return 0; }
    cat "$target"
}

# Require state/<name>; die when missing.
state_require() {
    local name="$1"
    local value
    value="$(state_get "$name")"
    [[ -n "$value" ]] || die "required state file missing: state/$name (run upstream scenario first)"
    printf '%s' "$value"
}

# ── HTTP helpers ────────────────────────────────────────────────────────────

# Mastio base URL on the host. The mastio-nginx sidecar publishes
# ${MCP_PROXY_PORT}:9443 — env.smoke pins 19444.
smoke_mastio_url() {
    local port
    port="$(grep -E '^MCP_PROXY_PORT=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"
    printf 'https://127.0.0.1:%s' "${port:-19444}"
}

# Admin secret pulled from env.smoke (consistent across all scenarios).
smoke_admin_secret() {
    grep -E '^MCP_PROXY_ADMIN_SECRET=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-
}

# Path to the host-side Org CA pem (exported by 00_boot after the
# Mastio mints it). Some scenarios use it as a trust anchor in curl.
smoke_org_ca_path() {
    printf '%s/org-ca.pem' "$SMOKE_STATE_DIR"
}

# Wait for an HTTP endpoint to return 200 (or any 2xx). Args: URL, timeout_s.
# Uses --insecure because the Mastio TLS cert is signed by its own Org CA.
wait_http_ok() {
    local url="$1" timeout="${2:-60}"
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if curl -sk -f -o /dev/null "$url" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Shared status file. The curl helpers run in command substitutions
# (`resp="$(curl_admin ...)"`) so any variable they set is lost when
# the subshell exits. We round-trip the HTTP status through a file
# next to the shared state dir; ``smoke_status`` reads + returns it.
_SMOKE_STATUS_FILE="${SMOKE_STATE_DIR}/.last_status"

# Read the HTTP status code from the most recent curl_admin /
# curl_admin_raw / curl_mtls call. Empty string when none has run
# yet. Compatible with old callers that read ``$SMOKE_LAST_STATUS``
# directly (the var is kept in sync as a bonus for in-process
# callers, but command-substituted scenarios MUST use this helper).
smoke_status() {
    if [[ -f "$_SMOKE_STATUS_FILE" ]]; then
        cat "$_SMOKE_STATUS_FILE"
    else
        printf ''
    fi
}

_set_smoke_status() {
    mkdir -p "$(dirname "$_SMOKE_STATUS_FILE")" 2>/dev/null || true
    printf '%s' "$1" > "$_SMOKE_STATUS_FILE"
    SMOKE_LAST_STATUS="$1"
}

# ``curl_admin <method> <path> [body-json]`` — calls Mastio with the
# pinned admin secret header. Returns body on stdout, returns nonzero
# on non-2xx. Status is captured via ``smoke_status`` (also mirrored
# to $SMOKE_LAST_STATUS for in-process callers).
curl_admin() {
    local method="$1" path="$2" body="${3:-}"
    local url status
    url="$(smoke_mastio_url)${path}"
    local resp_file
    resp_file="$(mktemp)"
    local curl_args=(
        -sk
        -X "$method"
        -H "X-Admin-Secret: $(smoke_admin_secret)"
        -H "Accept: application/json"
        -o "$resp_file"
        -w "%{http_code}"
    )
    if [[ -n "$body" ]]; then
        curl_args+=(-H "Content-Type: application/json" --data-binary "$body")
    fi
    status="$(curl "${curl_args[@]}" "$url" || echo 000)"
    _set_smoke_status "$status"
    cat "$resp_file"
    rm -f "$resp_file"
    if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
        return 1
    fi
    return 0
}

# Same as curl_admin but tolerates non-2xx (returns the body always +
# sets the status via the shared file). Use for negative cases.
curl_admin_raw() {
    local method="$1" path="$2" body="${3:-}"
    local url
    url="$(smoke_mastio_url)${path}"
    local resp_file
    resp_file="$(mktemp)"
    local curl_args=(
        -sk
        -X "$method"
        -H "X-Admin-Secret: $(smoke_admin_secret)"
        -H "Accept: application/json"
        -o "$resp_file"
        -w "%{http_code}"
    )
    if [[ -n "$body" ]]; then
        curl_args+=(-H "Content-Type: application/json" --data-binary "$body")
    fi
    local status
    status="$(curl "${curl_args[@]}" "$url" || echo 000)"
    _set_smoke_status "$status"
    cat "$resp_file"
    rm -f "$resp_file"
    return 0
}

# ``curl_mtls <cert> <key> <method> <path> [body-json]`` — present a
# client cert at the TLS handshake. Used by scenarios that exercise
# /v1/audit/* or /v1/egress/* as an enrolled agent.
curl_mtls() {
    local cert="$1" key="$2" method="$3" path="$4" body="${5:-}"
    local url status
    url="$(smoke_mastio_url)${path}"
    local resp_file
    resp_file="$(mktemp)"
    local curl_args=(
        -sk
        --cert "$cert" --key "$key"
        -X "$method"
        -H "Accept: application/json"
        -o "$resp_file"
        -w "%{http_code}"
    )
    if [[ -n "$body" ]]; then
        curl_args+=(-H "Content-Type: application/json" --data-binary "$body")
    fi
    status="$(curl "${curl_args[@]}" "$url" || echo 000)"
    _set_smoke_status "$status"
    cat "$resp_file"
    rm -f "$resp_file"
    if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
        return 1
    fi
    return 0
}

# ── JSON helpers ────────────────────────────────────────────────────────────

# Extract a top-level key from a JSON blob. Uses python3 inside the
# Mastio container so we don't require jq or python on the host.
# Usage: ``json_get '<json>' '<key>'``  -> stdout
json_get() {
    local json="$1" key="$2"
    # Pipe through docker run alpine python — but that's slow + adds a
    # dep. We expect docker compose to be present; use the Mastio
    # container's python instead. Falls back to a host python3 if one
    # exists (most NixOS / Linux laptops have it). Plain Python stdlib
    # only — no jq.
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$json" | python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    val = obj.get('$key', '')
    if isinstance(val, (dict, list)):
        print(json.dumps(val))
    else:
        print(val if val is not None else '')
except Exception:
    print('')
"
    else
        # Last-resort: use the Mastio container. Slow but always available.
        smoke_compose exec -T mcp-proxy python3 -c "
import sys, json
try:
    obj = json.loads(sys.stdin.read())
    val = obj.get('$key', '')
    if isinstance(val, (dict, list)):
        print(json.dumps(val))
    else:
        print(val if val is not None else '')
except Exception:
    print('')
" <<<"$json"
    fi
}

# ── Snapshot on fail ────────────────────────────────────────────────────────

# Capture compose logs + state for the failing scenario into
# .smoke-fail-<unix-ts>/. Called by smoke.sh on nonzero scenario exit
# BEFORE the teardown wipes everything.
snapshot_on_fail() {
    local tag="${1:-unknown}" ts
    ts="$(date +%s)"
    local dir="$SMOKE_ROOT/.smoke-fail-${ts}-${tag}"
    mkdir -p "$dir"
    log_warn "capturing snapshot to ${dir#$SMOKE_ROOT/}/"
    smoke_compose ps > "$dir/compose-ps.txt" 2>&1 || true
    smoke_compose logs --no-color > "$dir/compose-logs.txt" 2>&1 || true
    if [[ -d "$SMOKE_STATE_DIR" ]]; then
        # state/data + state/nginx-certs are owned by uid 10001; the
        # host invoker can't cp them directly. Use busybox root to
        # tar them out without losing perms.
        if command -v docker >/dev/null 2>&1; then
            docker run --rm \
                -v "$SMOKE_STATE_DIR:/state:ro" \
                -v "$dir:/out" \
                --user 0:0 \
                busybox:stable sh -c 'cp -a /state/* /out/ 2>/dev/null || true' \
                >/dev/null 2>&1 || true
        else
            cp -a "$SMOKE_STATE_DIR"/* "$dir/" 2>/dev/null || true
        fi
    fi
    # Audit chain dump (best-effort — fails silently if Mastio is down).
    smoke_compose exec -T mcp-proxy python3 -c "
import sqlite3, sys
try:
    c = sqlite3.connect('/data/mcp_proxy.db')
    rows = c.execute('SELECT id, timestamp, agent_id, action, status, chain_seq FROM audit_log ORDER BY id DESC LIMIT 50').fetchall()
    for r in rows:
        print(r)
except Exception as exc:
    print(f'no audit dump: {exc}', file=sys.stderr)
" > "$dir/audit-tail.txt" 2>&1 || true
    log_warn "snapshot ready: ${dir#$SMOKE_ROOT/}/"
}
