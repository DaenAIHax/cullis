#!/usr/bin/env bash
# Enterprise sandbox — down
set -euo pipefail

cd "$(dirname "$0")"

docker compose down -v --remove-orphans
