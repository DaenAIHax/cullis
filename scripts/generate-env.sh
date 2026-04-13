#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Generate .env with secure random secrets
# ═══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/generate-env.sh              # Interactive (asks BROKER_PUBLIC_URL)
#   ./scripts/generate-env.sh --defaults   # Non-interactive, localhost defaults
#   ./scripts/generate-env.sh --prod       # Non-interactive, requires DOMAIN env var
#   ./scripts/generate-env.sh --force      # Overwrite existing .env without asking
#
# Can be combined: --defaults --force
#
# Environment variables (optional):
#   DOMAIN          — required with --prod (e.g. broker.example.com)
#   PROJECT_DIR     — override project root (default: parent of scripts/)
#
set -euo pipefail

# ── Resolve project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(dirname "$SCRIPT_DIR")}"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BOLD='\033[1m'
GRAY='\033[90m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

# ── Parse args ──────────────────────────────────────────────────────────────
MODE="interactive"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --defaults) MODE="defaults" ;;
        --prod)     MODE="prod" ;;
        --force)    FORCE=1 ;;
        --help|-h)
            echo "Usage: $0 [--defaults|--prod] [--force]"
            echo "  --defaults   Non-interactive, localhost dev defaults"
            echo "  --prod       Non-interactive, requires DOMAIN env var"
            echo "  --force      Overwrite existing .env without asking"
            exit 0
            ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

# ── Check if .env exists ────────────────────────────────────────────────────
if [[ -f "$PROJECT_DIR/.env" && "$FORCE" -eq 0 ]]; then
    if [[ "$MODE" != "interactive" ]]; then
        ok "Keeping existing .env (use --force to overwrite)"
        exit 0
    fi
    warn ".env already exists"
    read -rp "  Overwrite with fresh secrets? [y/N]: " reply
    if [[ ! "$reply" =~ ^[Yy] ]]; then
        ok "Keeping existing .env"
        exit 0
    fi
fi

# ── Validate prerequisites ──────────────────────────────────────────────────
command -v openssl &>/dev/null || die "openssl is required (install it or use nix-shell)"

if [[ ! -f "$PROJECT_DIR/.env.example" ]]; then
    die ".env.example not found at $PROJECT_DIR/.env.example"
fi

if [[ "$MODE" == "prod" && -z "${DOMAIN:-}" ]]; then
    die "--prod requires DOMAIN env var (e.g. DOMAIN=broker.example.com $0 --prod)"
fi

# ── Generate secrets ────────────────────────────────────────────────────────
generate_secret() {
    openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

ADMIN_SECRET="$(generate_secret)"
COOKIE_SIGNING_KEY="$(generate_secret)"
PG_PASSWORD="$(generate_secret)"

ok "Generated random secrets"

# ── Generate broker signing key (RSA 4096) if missing ───────────────────────
BROKER_KEY_DIR="$PROJECT_DIR/.keys"
mkdir -p "$BROKER_KEY_DIR"
if [[ ! -f "$BROKER_KEY_DIR/broker-signing.pem" ]]; then
    openssl genrsa -out "$BROKER_KEY_DIR/broker-signing.pem" 4096 2>/dev/null
    chmod 600 "$BROKER_KEY_DIR/broker-signing.pem"
    ok "Generated RSA 4096 broker signing key"
else
    ok "Broker signing key already exists"
fi

# ── Determine BROKER_PUBLIC_URL ─────────────────────────────────────────────
if [[ "$MODE" == "prod" ]]; then
    BROKER_URL="https://${DOMAIN}"
    ALLOWED_ORIGINS="https://${DOMAIN}"
    ENV_VALUE="production"

elif [[ "$MODE" == "defaults" ]]; then
    BROKER_URL="https://localhost:8443"
    ALLOWED_ORIGINS="*"
    ENV_VALUE="development"

else
    # Interactive: detect LAN IP and ask
    _DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    if [[ -n "$_DETECTED_IP" && "$_DETECTED_IP" != "127.0.0.1" ]]; then
        echo ""
        echo "  Detected LAN IP: ${_DETECTED_IP}"
        echo "  Agents on other machines need BROKER_PUBLIC_URL to match their BROKER_URL."
        echo "  If you're just trying Cullis on this machine, press Enter to accept option 1."
        echo ""
        echo "  1) https://localhost:8443  (local only — agents on this machine) [default]"
        echo "  2) http://${_DETECTED_IP}:8000   (LAN — agents on other VMs, no TLS)"
        echo "  3) https://${_DETECTED_IP}:8443  (LAN — agents on other VMs, self-signed TLS)"
        read -rp "  Choose BROKER_PUBLIC_URL [1/2/3, default 1]: " _url_choice
        case "$_url_choice" in
            2) BROKER_URL="http://${_DETECTED_IP}:8000" ;;
            3) BROKER_URL="https://${_DETECTED_IP}:8443" ;;
            *) BROKER_URL="https://localhost:8443" ;;
        esac
    else
        BROKER_URL="https://localhost:8443"
    fi
    ALLOWED_ORIGINS="*"
    ENV_VALUE="development"
fi

ok "BROKER_PUBLIC_URL=${BROKER_URL}"

# ── Write .env ──────────────────────────────────────────────────────────────
cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"

# Replace values
sed -i "s|^ADMIN_SECRET=.*|ADMIN_SECRET=${ADMIN_SECRET}|" "$PROJECT_DIR/.env"
sed -i "s|^DASHBOARD_SIGNING_KEY=.*|DASHBOARD_SIGNING_KEY=${COOKIE_SIGNING_KEY}|" "$PROJECT_DIR/.env"
sed -i "s|^ALLOWED_ORIGINS=.*|ALLOWED_ORIGINS=${ALLOWED_ORIGINS}|" "$PROJECT_DIR/.env"
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://atn:${PG_PASSWORD}@postgres:5432/agent_trust|" "$PROJECT_DIR/.env"
sed -i "s|^BROKER_PUBLIC_URL=.*|BROKER_PUBLIC_URL=${BROKER_URL}|" "$PROJECT_DIR/.env"

# Remove any ENVIRONMENT line copied from .env.example — the tail block
# below is authoritative for this field (dev vs prod).
sed -i "/^ENVIRONMENT=/d" "$PROJECT_DIR/.env"

# Append env-specific tail block.
echo "" >> "$PROJECT_DIR/.env"
if [[ "$ENV_VALUE" == "production" ]]; then
    REDIS_PASSWORD="$(generate_secret)"
    cat >> "$PROJECT_DIR/.env" <<EOF
# ─── Production ───────────────────────────────────────────────────────────
ENVIRONMENT=production
POSTGRES_PASSWORD=${PG_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
TRUST_DOMAIN=${DOMAIN}

# Production hardening — docker-compose.prod.yml expects these flags.
VAULT_ALLOW_HTTP=false
POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=false

# VAULT_TOKEN is deliberately left as the dev-mode default below. Replace
# it BEFORE running deploy_broker.sh --prod-* by:
#   ./vault/init-vault.sh
#   sed -i "s|^VAULT_TOKEN=.*|VAULT_TOKEN=\$(cat vault/broker-token)|" .env
EOF
    ok "Generated REDIS_PASSWORD; remember to set VAULT_TOKEN (vault/init-vault.sh)"
else
    cat >> "$PROJECT_DIR/.env" <<EOF
# ─── Environment ────────────────────────────────────────────────────────────
ENVIRONMENT=development
POSTGRES_PASSWORD=${PG_PASSWORD}
EOF
fi

ok "Generated .env with fresh secrets"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}ADMIN_SECRET${RESET}        ${GRAY}${ADMIN_SECRET:0:8}...${RESET} (full value in .env)"
echo -e "  ${BOLD}POSTGRES_PASSWORD${RESET}   ${GRAY}${PG_PASSWORD:0:8}...${RESET}"
echo -e "  ${BOLD}BROKER_PUBLIC_URL${RESET}   ${GRAY}${BROKER_URL}${RESET}"
echo -e "  ${BOLD}ENVIRONMENT${RESET}         ${GRAY}${ENV_VALUE}${RESET}"
echo ""
