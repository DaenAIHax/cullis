#!/usr/bin/env bash
# Kill a compose service, hold it down for N seconds, then start it back.
# Simulates a crashed proxy/broker being restarted by an operator or k8s.
#
# Usage: kill.sh <service> [--down-seconds N]
# Example: chaos/kill.sh proxy-a --down-seconds 20
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

if [[ $# -lt 1 ]]; then
    echo "usage: kill.sh <service> [--down-seconds N]" >&2
    exit 1
fi

service="$1"; shift || true
down_s=15
while [[ $# -gt 0 ]]; do
    case "$1" in
        --down-seconds) down_s="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

chaos_log "kill_start" service="$service" down_seconds="$down_s"
compose kill "$service"
chaos_log "killed" service="$service"

sleep "$down_s"

# `compose start` only works on a cleanly stopped container — after `kill`
# the container is gone from `ps` altogether, so `up -d --no-deps` is the
# right recreate primitive. --no-deps avoids touching anything else.
compose up -d --no-deps "$service"
chaos_log "restarted" service="$service"

# Wait for the healthcheck to go green so downstream chaos steps don't
# pile on a still-booting container.
local_wait_start=$(date +%s)
deadline=$((local_wait_start + 60))
while (( $(date +%s) < deadline )); do
    state="$(compose ps --format '{{.Service}} {{.Health}}' \
             | awk -v s="$service" '$1==s {print $2}')"
    if [[ "$state" == "healthy" ]]; then
        chaos_log "healthy" service="$service" boot_seconds="$(( $(date +%s) - local_wait_start ))"
        exit 0
    fi
    sleep 2
done
chaos_log "healthy_timeout" service="$service"
exit 1
