#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Generate proxy.env with secure random secrets (MCP Proxy)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/generate-proxy-env.sh              # Interactive
#   ./scripts/generate-proxy-env.sh --defaults   # Same-host localhost defaults
#   ./scripts/generate-proxy-env.sh --prod       # Needs BROKER_URL + PROXY_PUBLIC_URL env vars
#   ./scripts/generate-proxy-env.sh --force      # Overwrite existing proxy.env
#
# Environment variables (optional):
#   BROKER_URL         — required with --prod (e.g. https://broker.example.com)
#   PROXY_PUBLIC_URL   — required with --prod (e.g. https://proxy.myorg.example.com)
#   ORG_ADMIN_EMAIL    — informational, stored in MCP_PROXY_ALLOWED_ORIGINS hint
#   PROJECT_DIR        — override project root (default: parent of scripts/)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(dirname "$SCRIPT_DIR")}"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

MODE="interactive"
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --defaults) MODE="defaults" ;;
        --prod)     MODE="prod" ;;
        --force)    FORCE=1 ;;
        --help|-h)
            echo "Usage: $0 [--defaults|--prod] [--force]"
            exit 0
            ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

mkdir -p "$PROJECT_DIR/deploy/proxy"
OUT="$PROJECT_DIR/deploy/proxy/proxy.env"
if [[ -f "$OUT" && "$FORCE" -eq 0 ]]; then
    if [[ "$MODE" != "interactive" ]]; then
        ok "Keeping existing deploy/proxy/proxy.env (use --force to overwrite)"
        exit 0
    fi
    warn "deploy/proxy/proxy.env already exists"
    read -rp "  Overwrite with fresh secrets? [y/N]: " reply
    [[ "$reply" =~ ^[Yy] ]] || { ok "Keeping existing deploy/proxy/proxy.env"; exit 0; }
fi

command -v openssl >/dev/null || die "openssl is required"
[[ -f "$PROJECT_DIR/deploy/proxy/proxy.env.example" ]] || die "deploy/proxy/proxy.env.example not found"

if [[ "$MODE" == "prod" ]]; then
    [[ -n "${BROKER_URL:-}" ]]       || die "--prod requires BROKER_URL env var"
    [[ -n "${PROXY_PUBLIC_URL:-}" ]] || die "--prod requires PROXY_PUBLIC_URL env var"
fi

gen_secret() { openssl rand -base64 32 | tr -d '/+=' | head -c 32; }

ADMIN_SECRET="$(gen_secret)"
SIGNING_KEY="$(gen_secret)"
NONCE_SECRET="$(gen_secret)"

ok "Generated random admin secret + signing key + DPoP nonce secret"

case "$MODE" in
    prod)
        BROKER="${BROKER_URL}"
        PUBLIC="${PROXY_PUBLIC_URL}"
        JWKS="${BROKER_URL%/}/.well-known/jwks.json"
        ENVIRONMENT="production"
        ;;
    defaults)
        BROKER="${BROKER_URL:-http://broker:8000}"
        # Empty by default → settings.py falls back to ``request.url`` for
        # DPoP htu validation (auto-detect from the inbound Host header).
        # Hardcoding ``localhost`` broke every non-localhost deploy
        # (Docker, k8s, VM) because the agent's actual htu carried the
        # service name / ingress hostname / VM IP. Operators who front
        # the Mastio with a stable public hostname should still pass
        # ``PROXY_PUBLIC_URL=https://mastio.example.com`` explicitly.
        PUBLIC="${PROXY_PUBLIC_URL:-}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
    interactive)
        echo ""
        read -rp "  Broker URL [http://broker:8000]: " BROKER
        BROKER="${BROKER:-http://broker:8000}"
        read -rp "  Proxy public URL [empty = auto-detect from Host header]: " PUBLIC
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
esac

cp "$PROJECT_DIR/deploy/proxy/proxy.env.example" "$OUT"
sed -i "s|^MCP_PROXY_ENVIRONMENT=.*|MCP_PROXY_ENVIRONMENT=${ENVIRONMENT}|"           "$OUT"
sed -i "s|^MCP_PROXY_ADMIN_SECRET=.*|MCP_PROXY_ADMIN_SECRET=${ADMIN_SECRET}|"        "$OUT"
sed -i "s|^MCP_PROXY_DASHBOARD_SIGNING_KEY=.*|MCP_PROXY_DASHBOARD_SIGNING_KEY=${SIGNING_KEY}|" "$OUT"
sed -i "s|^MCP_PROXY_DPOP_NONCE_SECRET=.*|MCP_PROXY_DPOP_NONCE_SECRET=${NONCE_SECRET}|" "$OUT"
sed -i "s|^MCP_PROXY_BROKER_URL=.*|MCP_PROXY_BROKER_URL=${BROKER}|"                  "$OUT"
sed -i "s|^MCP_PROXY_BROKER_JWKS_URL=.*|MCP_PROXY_BROKER_JWKS_URL=${JWKS}|"          "$OUT"
sed -i "s|^MCP_PROXY_PROXY_PUBLIC_URL=.*|MCP_PROXY_PROXY_PUBLIC_URL=${PUBLIC}|"      "$OUT"

# S-1 (prod-shape stress test 2026-06-04) — production hardening secrets.
# validate_config(production) refuses to boot unless secret/KMS backend is
# vault and DB_ENCRYPTION_KEY + PDP_WEBHOOK_HMAC_SECRET + a WebAuthn posture
# are set. This script previously minted only admin/signing/nonce, so
# ``--prod`` set environment=production and then SystemExit'd on the first
# gate — production was unreachable without hand-editing proxy.env. Mint the
# rest (mirrors packaging/mastio-bundle/generate-proxy-env.sh). Vault addr +
# token still come from the operator (KMS custodies the Org CA private key).
if [[ "$MODE" == "prod" ]]; then
    _prod_set() {  # strip any existing line (commented or not), append uncommented
        sed -i.bak "/^#*[[:space:]]*${1%%=*}=/d" "$OUT"; rm -f "${OUT}.bak"
        echo "$1" >> "$OUT"
    }
    _prod_set "MCP_PROXY_SECRET_BACKEND=vault"
    _prod_set "MCP_PROXY_KMS_BACKEND=vault"
    _prod_set "MCP_PROXY_DB_ENCRYPTION_KEY=$(gen_secret)$(gen_secret)"   # 64 chars, over the >=32 floor
    _prod_set "MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET=$(gen_secret)$(gen_secret)"
    _prod_set "MCP_PROXY_EGRESS_DPOP_MODE=required"
    # Single-Mastio pilot WebAuthn posture: explicit opt-in to the warn
    # default (no IdP-backed user registration yet). Track a sunset date.
    _prod_set "MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK=true"
    ok "Production: minted DB_ENCRYPTION_KEY + PDP HMAC, secret/KMS backend=vault, DPoP=required, webauthn opt-in"
    warn "Production needs a Vault: set MCP_PROXY_VAULT_ADDR + MCP_PROXY_VAULT_TOKEN in ${OUT} before deploy (KMS custodies the Org CA key)."
fi

ok "Wrote ${OUT}"
echo ""
echo -e "  ${BOLD}MCP_PROXY_ADMIN_SECRET${RESET}      ${GRAY}${ADMIN_SECRET:0:8}...${RESET}"
echo -e "  ${BOLD}MCP_PROXY_BROKER_URL${RESET}        ${GRAY}${BROKER}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_PROXY_PUBLIC_URL${RESET}  ${GRAY}${PUBLIC}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_ENVIRONMENT${RESET}       ${GRAY}${ENVIRONMENT}${RESET}"
echo ""
