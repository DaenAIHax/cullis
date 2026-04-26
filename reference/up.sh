#!/usr/bin/env bash
# Cullis Reference Deployment — up
# Status: stub, populated per block in imp/sandbox_plan.md
set -euo pipefail

cd "$(dirname "$0")"

echo "[reference] docker compose config check"
docker compose config >/dev/null

echo "[reference] starting services"
docker compose up -d --wait

echo "[reference] status"
docker compose ps
