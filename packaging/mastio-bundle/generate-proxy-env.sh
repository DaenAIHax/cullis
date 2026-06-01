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
# Bundle layout — script lives at the bundle root next to
# proxy.env.example. The repo-side copy in scripts/ keeps its original
# parent-of-scripts default; PROJECT_DIR can still be overridden via env.
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR}"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

# Pick up _detect_default_public_host from the shared helpers. The file
# ships sibling inside the bundle tarball; in the repo it lives one dir
# up (``packaging/``). Tolerate both so the script works from either
# layout. See stage-mastio-bundle.sh for the tarball-staging contract.
# shellcheck source=../_common-deploy-helpers.sh
if [ -f "$SCRIPT_DIR/_common-deploy-helpers.sh" ]; then
    source "$SCRIPT_DIR/_common-deploy-helpers.sh"
elif [ -f "$SCRIPT_DIR/../_common-deploy-helpers.sh" ]; then
    source "$SCRIPT_DIR/../_common-deploy-helpers.sh"
fi

MODE="interactive"
FORCE=0
# Opt-in to auto-seed the first-boot admin password. Default behavior
# (off) leaves ``admin_password_hash`` NULL on first boot so the
# operator picks the password interactively at ``/proxy/register``.
# Power users who script the install (Ansible / Terraform / CI smoke)
# pass ``--auto-admin-pwd`` to retain the legacy seed-in-env flow.
# Memory-wise: the dashboard is never publicly exposed on Cullis's
# threat model (operator behind VPN / internal segment), so the
# /register race-window is not a concern; the gain is one fewer
# random-string-on-stdout to handle.
AUTO_ADMIN_PWD="${MASTIO_AUTO_ADMIN_PWD:-0}"
for arg in "$@"; do
    case "$arg" in
        --defaults)        MODE="defaults" ;;
        --prod)            MODE="prod" ;;
        --force)           FORCE=1 ;;
        --auto-admin-pwd)  AUTO_ADMIN_PWD=1 ;;
        --help|-h)
            cat <<'USAGE'
Usage: ./generate-proxy-env.sh [--defaults|--prod] [--force] [--auto-admin-pwd]

  --defaults         Same-host localhost defaults (no prompts).
  --prod             Needs BROKER_URL + PROXY_PUBLIC_URL env vars.
  --force            Overwrite existing proxy.env.
  --auto-admin-pwd   Auto-generate the first-boot admin password and
                     write it to MCP_PROXY_INITIAL_ADMIN_PASSWORD.
                     Default (without this flag) leaves the hash NULL
                     so the operator chooses the password at
                     /proxy/register on first sign-in.
                     Equivalent env: MASTIO_AUTO_ADMIN_PWD=1
USAGE
            exit 0
            ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

OUT="$PROJECT_DIR/proxy.env"
if [[ -f "$OUT" && "$FORCE" -eq 0 ]]; then
    if [[ "$MODE" != "interactive" ]]; then
        ok "Keeping existing proxy.env (use --force to overwrite)"
        exit 0
    fi
    warn "proxy.env already exists"
    read -rp "  Overwrite with fresh secrets? [y/N]: " reply
    [[ "$reply" =~ ^[Yy] ]] || { ok "Keeping existing proxy.env"; exit 0; }
fi

[[ -f "$PROJECT_DIR/proxy.env.example" ]] || die "proxy.env.example not found"

if [[ "$MODE" == "prod" ]]; then
    [[ -n "${BROKER_URL:-}" ]]       || die "--prod requires BROKER_URL env var"
    [[ -n "${PROXY_PUBLIC_URL:-}" ]] || die "--prod requires PROXY_PUBLIC_URL env var"
fi

# Prefer openssl when available (well-tested, fast); fall back to
# /dev/urandom + coreutils on hosts that ship without openssl —
# minimal NixOS, Alpine, distroless, WSL2 trimmed Ubuntu, etc. Issue
# #638: a customer on a Linux host without openssl pre-installed
# previously hit ``openssl is required`` on the very first deploy.
gen_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32
    else
        # 64 random bytes → base64 → strip non-alphanum → take 32 chars.
        # /dev/urandom + base64 + tr are coreutils, present on every
        # Linux a docker host can boot on.
        head -c 64 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32
    fi
}

ADMIN_SECRET="$(gen_secret)"
SIGNING_KEY="$(gen_secret)"
# First-boot admin password.
#
# Default (AUTO_ADMIN_PWD=0): leave INITIAL_ADMIN_PASSWORD empty so
# ``proxy.env`` does not seed the bcrypt hash at boot. The operator
# hits ``/proxy/login`` on first sign-in, the dashboard redirects to
# ``/proxy/register``, and the operator picks the password interactively
# (typed once, never on stdout). Threat model: dashboard is never
# publicly exposed (operator behind VPN / internal segment), so the
# first-POST-wins race on /register is bounded by network access
# control rather than internet exposure.
#
# Opt-in (--auto-admin-pwd | MASTIO_AUTO_ADMIN_PWD=1): keep the legacy
# behavior — generate a random secret, write it into proxy.env, the
# Mastio lifespan reads + hashes it on first boot. Use this for
# scripted provisioning (Ansible / Terraform / CI smoke) where a
# /register browser hop is not feasible.
if [[ "$AUTO_ADMIN_PWD" -eq 1 ]]; then
    INITIAL_ADMIN_PASSWORD="$(gen_secret)"
    ok "Generated random admin secret + signing key + first-boot password (--auto-admin-pwd)"
else
    INITIAL_ADMIN_PASSWORD=""
    ok "Generated random admin secret + signing key (admin password chosen interactively at /proxy/register on first sign-in)"
fi

case "$MODE" in
    prod)
        BROKER="${BROKER_URL}"
        PUBLIC="${PROXY_PUBLIC_URL}"
        JWKS="${BROKER_URL%/}/.well-known/jwks.json"
        ENVIRONMENT="production"
        ;;
    defaults)
        BROKER="${BROKER_URL:-http://broker:8000}"
        # Default URL is detected at boot rather than hardcoded so a
        # Linux pure host (no Docker Desktop) gets an IP reachable from
        # a remote agent SDK or LAN browser, while macOS/Windows or
        # Docker Desktop on Linux keep getting ``host.docker.internal``
        # (the historical default, still correct in those scenarios).
        # See _detect_default_public_host in _common-deploy-helpers.sh.
        # Emitting an explicit non-empty value keeps ``--defaults``
        # self-contained for CI / Ansible / quick-laptop boot and avoids
        # the 401 ``Invalid DPoP proof: htu mismatch`` on every agent
        # enrollment caused by an unset PROXY_PUBLIC_URL.
        _default_public_host="$(_detect_default_public_host 2>/dev/null || echo host.docker.internal)"
        PUBLIC="${PROXY_PUBLIC_URL:-https://${_default_public_host}:9443}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
    interactive)
        echo ""
        read -rp "  Broker URL [http://broker:8000]: " BROKER
        BROKER="${BROKER:-http://broker:8000}"
        # Same default the deploy.sh interactive prompt offers. Empty
        # input → detected default, never the empty string (MINOR-F:
        # empty triggers 401 htu mismatch on every agent enrollment
        # because the docker-compose ${VAR:-...} fallback does NOT
        # apply uniformly across all consumers of proxy.env).
        _default_public_host="$(_detect_default_public_host 2>/dev/null || echo host.docker.internal)"
        _default_public_url="https://${_default_public_host}:9443"
        read -rp "  Proxy public URL [${_default_public_url}]: " PUBLIC
        PUBLIC="${PUBLIC:-${_default_public_url}}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
esac

cp "$PROJECT_DIR/proxy.env.example" "$OUT"
sed -i "s|^MCP_PROXY_ENVIRONMENT=.*|MCP_PROXY_ENVIRONMENT=${ENVIRONMENT}|"           "$OUT"
sed -i "s|^MCP_PROXY_ADMIN_SECRET=.*|MCP_PROXY_ADMIN_SECRET=${ADMIN_SECRET}|"        "$OUT"
sed -i "s|^MCP_PROXY_DASHBOARD_SIGNING_KEY=.*|MCP_PROXY_DASHBOARD_SIGNING_KEY=${SIGNING_KEY}|" "$OUT"
sed -i "s|^MCP_PROXY_BROKER_URL=.*|MCP_PROXY_BROKER_URL=${BROKER}|"                  "$OUT"
sed -i "s|^MCP_PROXY_BROKER_JWKS_URL=.*|MCP_PROXY_BROKER_JWKS_URL=${JWKS}|"          "$OUT"

# MCP_PROXY_PROXY_PUBLIC_URL ships COMMENTED in proxy.env.example (the
# example carries a placeholder production hostname so operators see
# the shape, not a usable default). A plain sed-substitution on
# ``^MCP_PROXY_PROXY_PUBLIC_URL=`` therefore silently no-ops and the
# generated proxy.env ends up without an uncommented line, exactly
# the dogfood breakage MINOR-F pins (CI / Ansible / laptop boot with
# --defaults then ./deploy.sh up: every agent enrollment fails 401
# htu mismatch). Strip any pre-existing line (commented or not) and
# append the resolved value so the field always lands uncommented.
sed -i.bak '/^#*[[:space:]]*MCP_PROXY_PROXY_PUBLIC_URL=/d' "$OUT"
rm -f "${OUT}.bak"
echo "MCP_PROXY_PROXY_PUBLIC_URL=${PUBLIC}" >> "$OUT"

# ADR-030 — the bundle bind-mount paths default to ./data and ./nginx-certs.
# proxy.env.example ships them already, so no sed required here. The block
# is intentionally idempotent: re-running this script never clobbers an
# operator's custom path because the example carries the canonical value
# and any override survives via --force-only overwrite.
# proxy.env.example does not ship the seed line. Append only when the
# operator asked for the auto-seed path; otherwise omit so the Mastio
# main.py boot path correctly leaves the hash NULL and routes
# /proxy/login → /proxy/register for interactive setup.
if [[ -n "$INITIAL_ADMIN_PASSWORD" ]]; then
    echo "MCP_PROXY_INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}" >> "$OUT"
fi

# Stamp the bundle version into proxy.env so the running container can
# self-report and the dashboard update banner has a real baseline to
# compare against the GitHub releases API. Without this the compose
# fallback (``${CULLIS_MASTIO_VERSION:-unknown}``) bites: MCP_PROXY_VERSION
# arrives as "unknown" and version_check.py concludes "update available"
# against any non-empty latest. The VERSION file is written by
# ``scripts/stage-mastio-bundle.sh`` at release-staging time.
if [[ -f "$PROJECT_DIR/VERSION" ]]; then
    BUNDLE_VERSION="$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")"
    if [[ -n "$BUNDLE_VERSION" ]]; then
        # Strip any pre-existing line (comment or otherwise) before
        # appending so re-runs stay idempotent.
        sed -i.bak '/^#*[[:space:]]*CULLIS_MASTIO_VERSION=/d' "$OUT"
        rm -f "${OUT}.bak"
        echo "CULLIS_MASTIO_VERSION=${BUNDLE_VERSION}" >> "$OUT"
    fi
fi

# Production hardening secrets (--prod only). validate_config(production)
# refuses to boot unless secret_backend=vault, kms_backend=vault and a
# DB_ENCRYPTION_KEY are set (and webauthn is required or explicitly opted
# out). Until the bundle compose forwarded these (added alongside this
# change), ``./deploy.sh --prod`` set environment=production and then
# SystemExit'd on the first gate, so production mode was unreachable.
# WebAuthn posture for a single-Mastio pilot: explicit opt-in to the warn
# default (no IdP-backed user registration); track a sunset date.
if [[ "$MODE" == "prod" ]]; then
    DB_ENC_KEY="$(gen_secret)$(gen_secret)"   # 64 chars, comfortably over the >= 32 floor
    _prod_set() {  # strip any existing line (commented or not), append uncommented
        sed -i.bak "/^#*[[:space:]]*${1%%=*}=/d" "$OUT"; rm -f "${OUT}.bak"
        echo "$1" >> "$OUT"
    }
    _prod_set "MCP_PROXY_SECRET_BACKEND=vault"
    _prod_set "MCP_PROXY_KMS_BACKEND=vault"
    _prod_set "MCP_PROXY_DB_ENCRYPTION_KEY=${DB_ENC_KEY}"
    _prod_set "MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK=true"
    _prod_set "MCP_PROXY_EGRESS_DPOP_MODE=required"
    # F-A-202 — production refuses an empty PDP webhook HMAC secret
    # (inbound /pdp/policy + /v1/policy/tool-call would accept unsigned
    # calls). Mint one; an operator pairing with an external broker PDP
    # overwrites it to match the broker's POLICY_WEBHOOK_HMAC_SECRET.
    _prod_set "MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET=$(gen_secret)$(gen_secret)"
    if [[ -n "${VAULT_ADDR:-}" && -n "${VAULT_TOKEN:-}" ]]; then
        _prod_set "MCP_PROXY_VAULT_ADDR=${VAULT_ADDR}"
        _prod_set "MCP_PROXY_VAULT_TOKEN=${VAULT_TOKEN}"
        ok "Production: minted DB_ENCRYPTION_KEY, set KMS+secret backend=vault, DPoP=required, webauthn opt-in"
    else
        warn "Production needs a Vault: KMS_BACKEND=vault custodies the Org CA private key. Set MCP_PROXY_VAULT_ADDR + MCP_PROXY_VAULT_TOKEN in ${OUT} before ./deploy.sh --prod."
    fi
fi

ok "Wrote ${OUT}"
echo ""
echo -e "  ${BOLD}MCP_PROXY_ADMIN_SECRET${RESET}            ${GRAY}${ADMIN_SECRET:0:8}…${RESET}"
if [[ -n "$INITIAL_ADMIN_PASSWORD" ]]; then
    echo -e "  ${BOLD}MCP_PROXY_INITIAL_ADMIN_PASSWORD${RESET}  ${GRAY}${INITIAL_ADMIN_PASSWORD}${RESET}"
    echo -e "                                  ${GRAY}(login at /proxy/login as ``admin`` with this password, then rotate)${RESET}"
else
    echo -e "  ${BOLD}MCP_PROXY_INITIAL_ADMIN_PASSWORD${RESET}  ${GRAY}(unset — pick interactively at /proxy/register on first sign-in)${RESET}"
fi
echo -e "  ${BOLD}MCP_PROXY_BROKER_URL${RESET}              ${GRAY}${BROKER}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_PROXY_PUBLIC_URL${RESET}        ${GRAY}${PUBLIC}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_ENVIRONMENT${RESET}             ${GRAY}${ENVIRONMENT}${RESET}"
echo ""
