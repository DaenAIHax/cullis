#!/usr/bin/env bash
# Network partition — disconnect a compose service from public-wan for
# a window, then reconnect. Useful to simulate broker unreachability
# or cross-org connectivity loss without killing the container state.
#
# Usage: partition.sh <service> [--duration N]
# Example: chaos/partition.sh broker --duration 30
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

NETWORK="cullis-nightly-wan"

if [[ $# -lt 1 ]]; then
    echo "usage: partition.sh <service> [--duration N]" >&2
    exit 1
fi

service="$1"; shift || true
duration=30
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) duration="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

container="$(compose ps -q "$service" | head -n1)"
if [[ -z "$container" ]]; then
    echo "[chaos] no running container for service '$service'" >&2
    exit 1
fi

chaos_log "partition_start" service="$service" duration_seconds="$duration" network="$NETWORK"
docker network disconnect "$NETWORK" "$container" >/dev/null
chaos_log "partitioned" service="$service"

sleep "$duration"

docker network connect "$NETWORK" "$container" >/dev/null
chaos_log "reconnected" service="$service"
