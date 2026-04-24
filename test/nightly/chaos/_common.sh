#!/usr/bin/env bash
# Chaos helpers — shared sourcing for individual fault scripts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIGHTLY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve the current run's log directory. Prefer NIGHTLY_RUN_TS env (set
# by the operator when coordinating with a specific go invocation);
# otherwise pick the newest logs/<ts>/ subdir. Fail fast if no run.
resolve_log_dir() {
    if [[ -n "${NIGHTLY_RUN_TS:-}" ]]; then
        echo "$NIGHTLY_DIR/logs/$NIGHTLY_RUN_TS"
        return
    fi
    local newest
    newest="$(ls -1t "$NIGHTLY_DIR/logs/" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' | head -n1 || true)"
    if [[ -z "$newest" ]]; then
        echo "[chaos] no active run found under $NIGHTLY_DIR/logs/ — start './nightly.sh go' first" >&2
        exit 1
    fi
    echo "$NIGHTLY_DIR/logs/$newest"
}

# Append a JSON record to chaos.jsonl. Call as: chaos_log <event> key1=v1 key2=v2
chaos_log() {
    local log_dir event
    log_dir="$(resolve_log_dir)"
    event="$1"; shift
    local ts
    ts="$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)"
    local extra=""
    for kv in "$@"; do
        local k="${kv%%=*}"
        local v="${kv#*=}"
        # Escape quotes + backslashes so JSON stays well-formed.
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        extra+=",\"$k\":\"$v\""
    done
    mkdir -p "$log_dir"
    echo "{\"ts\":$ts,\"event\":\"$event\"$extra}" >> "$log_dir/chaos.jsonl"
    echo "[chaos] $event${extra//,/  }" >&2
}

compose() {
    (cd "$NIGHTLY_DIR" && docker compose "$@")
}
