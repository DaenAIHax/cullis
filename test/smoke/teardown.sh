#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — idempotent teardown
# =============================================================================
#
# Brings down the compose stack and wipes state/. Safe to run even when
# nothing is up (docker compose down returns 0 on a missing project).
#
# Run by:
#   * smoke.sh's EXIT trap (unless --keep was passed)
#   * by hand when an operator wants to recover from a wedged stack
#
# Does NOT wipe .smoke-fail-*/ snapshots — those are forensics; cleanup
# is the operator's call.
# =============================================================================
set -euo pipefail

SMOKE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/_common.sh
source "$SMOKE_ROOT/lib/_common.sh"

SCENARIO_TAG="teardown"

log_info "tearing down cullis-smoke stack"

# ``down -v --remove-orphans`` wipes the cullis-smoke named network +
# any leftover service containers. Bind dirs (state/data, state/
# nginx-certs, state/postgres-data) remain — they live outside docker
# volume semantics.
# Run both overlays' down in turn so a previous --pg run gets the
# postgres container cleaned up even if the current invocation defaults
# to sqlite. Suppress errors when an overlay is missing or compose
# reports nothing to do.
for overlay in compose.sqlite.yml compose.postgres.yml; do
    if [[ -f "$SMOKE_ROOT/$overlay" ]]; then
        SMOKE_COMPOSE_OVERLAY="$SMOKE_ROOT/$overlay" \
            smoke_compose down -v --remove-orphans 2>/dev/null || true
    fi
done

# Wipe state/ unless --keep-state was passed.
if [[ "${1:-}" != "--keep-state" ]]; then
    if [[ -d "$SMOKE_ROOT/state" ]]; then
        # state/data and state/nginx-certs are owned by uid 10001
        # (the Mastio container user) so the host invoker can't
        # rm them directly. Use a transient root busybox — same
        # pattern as packaging/mastio-bundle/deploy.sh --down -v.
        if command -v docker >/dev/null 2>&1; then
            docker run --rm \
                -v "$SMOKE_ROOT/state:/state" \
                --user 0:0 \
                busybox:stable sh -c 'rm -rf /state/*' >/dev/null 2>&1 || true
        else
            rm -rf "$SMOKE_ROOT/state"/* 2>/dev/null || true
        fi
        # Recreate empty marker so git status stays quiet on the
        # .gitkeep file we ship in state/.
        mkdir -p "$SMOKE_ROOT/state"
    fi
    log_info "state/ wiped"
fi

log_info "teardown complete"
