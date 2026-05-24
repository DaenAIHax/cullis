#!/usr/bin/env bash
# =============================================================================
# 00_boot — bring the stack up + wait for /health
# =============================================================================
#
# Pulls/builds the local image, brings up redis + mock-tsa + Mastio +
# nginx sidecar, blocks until /health answers 200 on the host port.
#
# Asserts:
#   * compose up exits 0
#   * https://127.0.0.1:${MCP_PROXY_PORT}/health returns 200 within 120s
#   * health response carries the expected shape (status, version)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="00_boot"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

smoke_state_init

log_info "compose build (this can take 2-5 min cold; <30s warm)"
if ! smoke_compose build --pull mock-tsa mcp-proxy >/tmp/smoke-build.log 2>&1; then
    log_warn "build log (last 80 lines):"
    tail -80 /tmp/smoke-build.log >&2 || true
    die "compose build failed"
fi

log_info "compose up -d --wait"
if ! smoke_compose up -d --wait; then
    log_warn "up failed — recent compose output:"
    smoke_compose logs --tail=80 >&2 || true
    die "compose up failed"
fi

log_info "waiting for /health on $(smoke_mastio_url)/health"
if ! wait_http_ok "$(smoke_mastio_url)/health" 120; then
    die "Mastio /health never returned 2xx within 120s"
fi

# Parse the health body — needs status=ok + a non-empty version field.
body="$(curl -sk -f "$(smoke_mastio_url)/health" || die "health fetch failed post-ready")"
status="$(json_get "$body" 'status')"
version="$(json_get "$body" 'version')"
[[ "$status" == "ok" ]] || die "/health status != ok: $body"
[[ -n "$version" ]]    || die "/health version is empty: $body"

log_pass "stack up — version=${version} status=${status}"
