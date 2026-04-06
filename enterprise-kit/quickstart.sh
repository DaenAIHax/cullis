#!/usr/bin/env bash
#
# Cullis Enterprise Kit — Quick Start
#
# This script helps you onboard your organization to a Cullis broker.
# It generates a CA, agent certificate, registers with the broker,
# and sets up the PDP webhook.
#
# Usage:
#   ./quickstart.sh
#
# Prerequisites:
#   - openssl
#   - curl
#   - A running Cullis broker (you need the URL)

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1" >&2; }

ask() {
    local prompt="$1" default="${2:-}"
    if [ -n "$default" ]; then
        read -rp "  ${prompt} [${default}]: " value
        echo "${value:-$default}"
    else
        read -rp "  ${prompt}: " value
        echo "$value"
    fi
}

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        Cullis — Enterprise Quickstart          ║${RESET}"
echo -e "${BOLD}╚═══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Collect info ─────────────────────────────────────────────────────────────
BROKER_URL=$(ask "Broker URL" "http://localhost:8000")
ORG_ID=$(ask "Your Organization ID (lowercase, no spaces)")
ORG_DISPLAY=$(ask "Display Name" "$ORG_ID")
ORG_SECRET=$(ask "Organization Secret (for API auth)")
AGENT_NAME=$(ask "Agent name (e.g. procurement-agent)")
CAPABILITIES=$(ask "Agent capabilities (comma-separated)" "order.read,order.write")
TRUST_DOMAIN=$(ask "Trust domain" "atn.local")
CONTACT_EMAIL=$(ask "Contact email" "")

AGENT_ID="${ORG_ID}::${AGENT_NAME}"
OUT_DIR="./atn-${ORG_ID}"
SPIFFE_ID="spiffe://${TRUST_DOMAIN}/${ORG_ID}/${AGENT_NAME}"

echo ""
echo -e "${BOLD}Configuration:${RESET}"
echo "  Broker:       $BROKER_URL"
echo "  Org:          $ORG_ID ($ORG_DISPLAY)"
echo "  Agent:        $AGENT_ID"
echo "  Capabilities: $CAPABILITIES"
echo "  SPIFFE:       $SPIFFE_ID"
echo "  Output:       $OUT_DIR/"
echo ""

# ── 1. Generate Org CA ──────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Generating Org CA${RESET}"
mkdir -p "$OUT_DIR"

if [ -f "$OUT_DIR/org-ca.pem" ]; then
    warn "CA already exists — skipping"
else
    openssl genrsa -out "$OUT_DIR/org-ca-key.pem" 4096 2>/dev/null
    openssl req -new -x509 -key "$OUT_DIR/org-ca-key.pem" -out "$OUT_DIR/org-ca.pem" \
        -days 3650 -subj "/CN=${ORG_ID} CA/O=${ORG_ID}" 2>/dev/null
    ok "CA generated: $OUT_DIR/org-ca.pem"
fi

# ── 2. Generate Agent Certificate ───────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Generating agent certificate${RESET}"

if [ -f "$OUT_DIR/agent.pem" ]; then
    warn "Agent cert already exists — skipping"
else
    openssl genrsa -out "$OUT_DIR/agent-key.pem" 2048 2>/dev/null
    openssl req -new -key "$OUT_DIR/agent-key.pem" -out "$OUT_DIR/agent.csr" \
        -subj "/CN=${AGENT_ID}/O=${ORG_ID}" 2>/dev/null

    # Create extension file for SAN
    echo "subjectAltName=URI:${SPIFFE_ID}" > "$OUT_DIR/san.ext"

    openssl x509 -req -in "$OUT_DIR/agent.csr" \
        -CA "$OUT_DIR/org-ca.pem" -CAkey "$OUT_DIR/org-ca-key.pem" \
        -CAcreateserial -out "$OUT_DIR/agent.pem" -days 365 \
        -extfile "$OUT_DIR/san.ext" 2>/dev/null

    rm -f "$OUT_DIR/agent.csr" "$OUT_DIR/san.ext" "$OUT_DIR/org-ca.srl"
    ok "Agent cert: $OUT_DIR/agent.pem"
fi

# ── 3. Register org with broker ─────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Registering organization${RESET}"

CA_PEM=$(cat "$OUT_DIR/org-ca.pem")
HTTP_CODE=$(curl -s -o /tmp/atn_response.json -w "%{http_code}" \
    -X POST "${BROKER_URL}/onboarding/join" \
    -H "Content-Type: application/json" \
    -d "$(cat <<EOF
{
    "org_id": "${ORG_ID}",
    "display_name": "${ORG_DISPLAY}",
    "secret": "${ORG_SECRET}",
    "ca_certificate": $(echo "$CA_PEM" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'),
    "contact_email": "${CONTACT_EMAIL}"
}
EOF
)")

if [ "$HTTP_CODE" = "202" ]; then
    ok "Join request sent — waiting for admin approval"
elif [ "$HTTP_CODE" = "409" ]; then
    warn "Org already registered"
else
    err "Registration failed (HTTP $HTTP_CODE): $(cat /tmp/atn_response.json)"
fi

# ── 4. Register agent ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Registering agent${RESET}"

IFS=',' read -ra CAPS_ARRAY <<< "$CAPABILITIES"
CAPS_JSON=$(printf '%s\n' "${CAPS_ARRAY[@]}" | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin.readlines()]))')

HTTP_CODE=$(curl -s -o /tmp/atn_response.json -w "%{http_code}" \
    -X POST "${BROKER_URL}/registry/agents" \
    -H "Content-Type: application/json" \
    -d "$(cat <<EOF
{
    "agent_id": "${AGENT_ID}",
    "org_id": "${ORG_ID}",
    "display_name": "${AGENT_ID}",
    "capabilities": ${CAPS_JSON}
}
EOF
)")

if [ "$HTTP_CODE" = "201" ]; then
    ok "Agent registered: $AGENT_ID"
elif [ "$HTTP_CODE" = "409" ]; then
    warn "Agent already registered"
else
    err "Agent registration failed (HTTP $HTTP_CODE): $(cat /tmp/atn_response.json)"
fi

# ── 5. Save agent config ────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Saving agent config${RESET}"

cat > "$OUT_DIR/agent.env" <<EOF
# Cullis Agent Config — generated by quickstart.sh
BROKER_URL=${BROKER_URL}
AGENT_ID=${AGENT_ID}
ORG_ID=${ORG_ID}
DISPLAY_NAME=${AGENT_ID}
AGENT_CERT_PATH=${OUT_DIR}/agent.pem
AGENT_KEY_PATH=${OUT_DIR}/agent-key.pem
ORG_SECRET=${ORG_SECRET}
CAPABILITIES=${CAPABILITIES}
POLL_INTERVAL=2
MAX_TURNS=20
EOF

ok "Config saved: $OUT_DIR/agent.env"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}Setup complete!${RESET}"
echo ""
echo "  Files in $OUT_DIR/:"
echo "    org-ca.pem       — Your CA public cert (shared with broker)"
echo "    org-ca-key.pem   — Your CA private key (KEEP SECRET)"
echo "    agent.pem        — Agent certificate"
echo "    agent-key.pem    — Agent private key (KEEP SECRET)"
echo "    agent.env        — Agent configuration"
echo ""
echo -e "${BOLD}Next steps:${RESET}"
echo "  1. Ask the broker admin to approve your org"
echo "  2. Create a binding:  curl -X POST \${BROKER_URL}/registry/bindings ..."
echo "  3. Create a session policy: python policy.py"
echo "  4. Deploy your PDP webhook (see pdp-template/)"
echo "  5. Start your agent with the env file"
echo ""
