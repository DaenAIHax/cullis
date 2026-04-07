#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Agent Bootstrap
#
# Generates org CA + agent certificate, stores them in Vault (dev mode),
# and optionally registers the org on the broker.
#
# Usage:
#   ./bootstrap.sh                  # Generate certs + store in Vault
#   ./bootstrap.sh --register       # + register org on broker
#
# Environment:
#   BROKER_URL    — broker address (required for --register)
#   ORG_ID        — org identifier          (default: myorg)
#   AGENT_ID      — agent identifier        (default: myorg::agent)
#   DISPLAY_NAME  — org display name        (default: My Organization)
#   VAULT_ADDR    — Vault address           (default: http://127.0.0.1:8200)
#   VAULT_TOKEN   — Vault token             (default: demo-agent-token)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'
BOLD='\033[1m'; GRAY='\033[90m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

# ── Defaults ─────────────────────────────────────────────────────────────────
ORG_ID="${ORG_ID:-myorg}"
AGENT_ID="${AGENT_ID:-myorg::agent}"
DISPLAY_NAME="${DISPLAY_NAME:-My Organization}"
AGENT_DISPLAY_NAME="${AGENT_DISPLAY_NAME:-Agent}"
CAPABILITIES="${CAPABILITIES:-chat}"

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-demo-agent-token}"
BROKER_URL="${BROKER_URL:-}"
ORG_SECRET="${ORG_SECRET:-$(openssl rand -hex 16)}"

FLAG_REGISTER=false
for arg in "$@"; do
    case "$arg" in
        --register) FLAG_REGISTER=true ;;
        --help|-h)  echo "Usage: $0 [--register]"; exit 0 ;;
        *)          die "Unknown flag: $arg" ;;
    esac
done

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

echo -e "\n${BOLD}Cullis Agent Bootstrap — ${DISPLAY_NAME} (${ORG_ID})${RESET}"
echo -e "  Agent: ${AGENT_DISPLAY_NAME} (${AGENT_ID})"

# ═════════════════════════════════════════════════════════════════════════════
# 1. Check Vault
# ═════════════════════════════════════════════════════════════════════════════
step "Checking Vault"

for i in $(seq 1 10); do
    if curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1 || die "Vault not reachable at ${VAULT_ADDR}."
ok "Vault is ready at ${VAULT_ADDR}"

# Enable KV v2 (idempotent)
curl -sf -X POST "${VAULT_ADDR}/v1/sys/mounts/secret" \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d '{"type":"kv","options":{"version":"2"}}' 2>/dev/null || true

# ═════════════════════════════════════════════════════════════════════════════
# 2. Generate Org CA (EC P-256)
# ═════════════════════════════════════════════════════════════════════════════
step "Generating Org CA certificate"

openssl ecparam -genkey -name prime256v1 -noout \
  -out "${WORK_DIR}/ca-key.pem" 2>/dev/null

openssl req -new -x509 -key "${WORK_DIR}/ca-key.pem" \
  -out "${WORK_DIR}/ca-cert.pem" -days 365 \
  -subj "/O=${ORG_ID}/CN=${ORG_ID} CA" 2>/dev/null

ok "Org CA generated (EC P-256, CN=${ORG_ID} CA)"

# ═════════════════════════════════════════════════════════════════════════════
# 3. Generate Agent certificate (signed by org CA)
# ═════════════════════════════════════════════════════════════════════════════
step "Generating Agent certificate"

ORG_PART="${AGENT_ID%%::*}"
AGENT_PART="${AGENT_ID##*::}"

cat > "${WORK_DIR}/agent.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=URI:spiffe://atn.local/${ORG_PART}/${AGENT_PART}
EXTEOF

openssl ecparam -genkey -name prime256v1 -noout \
  -out "${WORK_DIR}/agent-key.pem" 2>/dev/null

openssl req -new -key "${WORK_DIR}/agent-key.pem" \
  -out "${WORK_DIR}/agent.csr" \
  -subj "/O=${ORG_ID}/CN=${AGENT_ID}" 2>/dev/null

openssl x509 -req -in "${WORK_DIR}/agent.csr" \
  -CA "${WORK_DIR}/ca-cert.pem" -CAkey "${WORK_DIR}/ca-key.pem" \
  -CAcreateserial -out "${WORK_DIR}/agent-cert.pem" \
  -days 365 -extfile "${WORK_DIR}/agent.ext" 2>/dev/null

ok "Agent cert generated (CN=${AGENT_ID}, SAN=spiffe://atn.local/${ORG_PART}/${AGENT_PART})"

# ═════════════════════════════════════════════════════════════════════════════
# 4. Store certificates in Vault
# ═════════════════════════════════════════════════════════════════════════════
step "Storing certificates in Vault"

CA_CERT_PEM=$(cat "${WORK_DIR}/ca-cert.pem")
CA_KEY_PEM=$(cat "${WORK_DIR}/ca-key.pem")
AGENT_CERT_PEM=$(cat "${WORK_DIR}/agent-cert.pem")
AGENT_KEY_PEM=$(cat "${WORK_DIR}/agent-key.pem")

curl -sf "${VAULT_ADDR}/v1/secret/data/org-ca" \
  -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg cert "$CA_CERT_PEM" --arg key "$CA_KEY_PEM" \
    '{"data": {"ca_cert_pem": $cert, "private_key_pem": $key}}')" > /dev/null

ok "Org CA stored at secret/org-ca"

curl -sf "${VAULT_ADDR}/v1/secret/data/agent" \
  -X POST \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg cert "$AGENT_CERT_PEM" --arg key "$AGENT_KEY_PEM" \
    '{"data": {"cert_pem": $cert, "private_key_pem": $key}}')" > /dev/null

ok "Agent cert stored at secret/agent"

# ═════════════════════════════════════════════════════════════════════════════
# 5. Register org on broker (--register)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$FLAG_REGISTER" == "true" ]]; then
    step "Registering org on broker"

    if [[ -z "${BROKER_URL}" ]]; then
        die "BROKER_URL is required for --register"
    fi

    JOIN_PAYLOAD=$(jq -n \
        --arg org_id "$ORG_ID" \
        --arg display_name "$DISPLAY_NAME" \
        --arg secret "$ORG_SECRET" \
        --arg ca_cert "$CA_CERT_PEM" \
        '{
            "org_id": $org_id,
            "display_name": $display_name,
            "secret": $secret,
            "ca_certificate": $ca_cert
        }')

    RESPONSE=$(curl -sf "${BROKER_URL}/v1/onboarding/join" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$JOIN_PAYLOAD" 2>&1) || {
        warn "Broker registration failed (org may already exist)"
        echo -e "  ${GRAY}Register manually via dashboard if needed${RESET}"
    }

    if [[ -n "${RESPONSE:-}" ]]; then
        ok "Org registration submitted"
    fi
    echo -e "  ${GRAY}Org secret: ${ORG_SECRET}${RESET}"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Done
# ═════════════════════════════════════════════════════════════════════════════
step "Bootstrap complete"
ok "Org:     ${ORG_ID} (${DISPLAY_NAME})"
ok "Agent:   ${AGENT_ID} (${AGENT_DISPLAY_NAME})"
ok "Vault:   ${VAULT_ADDR} (token: ${VAULT_TOKEN})"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  1. Approve org on broker dashboard"
echo -e "  2. Start agent: docker compose up agent"
echo ""
