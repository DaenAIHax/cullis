#!/usr/bin/env bash
# =============================================================================
# Cullis — Vault Production Initialization Script
# =============================================================================
#
# Run ONCE after the first production deploy to initialize and unseal Vault.
#
# Usage:
#   ./vault/init-vault.sh
#
# Prerequisites:
#   - Vault container running in production mode (not dev)
#   - VAULT_ADDR set (default: http://127.0.0.1:8200)
#   - vault CLI and jq installed
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

KEYS_FILE="$(dirname "$0")/vault-keys.json"

echo "==> Vault address: ${VAULT_ADDR}"

# ── Wait for Vault to be reachable ──────────────────────────────────────────
echo "==> Waiting for Vault to be ready..."
for i in $(seq 1 30); do
    if vault status -address="${VAULT_ADDR}" >/dev/null 2>&1; then
        break
    fi
    # Vault returns exit code 2 when sealed but reachable — that's fine
    if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q "Seal Type"; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Vault not reachable after 30 attempts"
        exit 1
    fi
    sleep 2
done
echo "==> Vault is reachable."

# ── Check if already initialized ────────────────────────────────────────────
if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q '"initialized": true\|Initialized.*true'; then
    echo "==> Vault is already initialized."

    # If sealed, try to unseal with existing keys file
    if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q '"sealed": true\|Sealed.*true'; then
        if [ -f "${KEYS_FILE}" ]; then
            echo "==> Vault is sealed — unsealing with saved keys..."
            for i in 0 1 2; do
                KEY=$(jq -r ".unseal_keys_b64[$i]" "${KEYS_FILE}")
                vault operator unseal -address="${VAULT_ADDR}" "${KEY}" >/dev/null
            done
            echo "==> Vault unsealed successfully."
        else
            echo "ERROR: Vault is sealed but no keys file found at ${KEYS_FILE}"
            echo "       Provide unseal keys manually: vault operator unseal"
            exit 1
        fi
    else
        echo "==> Vault is already unsealed. Nothing to do."
    fi
    exit 0
fi

# ── Initialize Vault ────────────────────────────────────────────────────────
echo "==> Initializing Vault (5 key shares, threshold 3)..."
vault operator init \
    -address="${VAULT_ADDR}" \
    -key-shares=5 \
    -key-threshold=3 \
    -format=json > "${KEYS_FILE}"

chmod 600 "${KEYS_FILE}"
echo "==> Keys saved to ${KEYS_FILE} (mode 600)"

# ── Unseal with 3 of 5 keys ────────────────────────────────────────────────
echo "==> Unsealing Vault..."
for i in 0 1 2; do
    KEY=$(jq -r ".unseal_keys_b64[$i]" "${KEYS_FILE}")
    vault operator unseal -address="${VAULT_ADDR}" "${KEY}" >/dev/null
done
echo "==> Vault unsealed successfully."

# ── Authenticate with root token ────────────────────────────────────────────
ROOT_TOKEN=$(jq -r ".root_token" "${KEYS_FILE}")
export VAULT_TOKEN="${ROOT_TOKEN}"

# ── Enable KV v2 secrets engine ─────────────────────────────────────────────
echo "==> Enabling KV v2 secrets engine at secret/..."
vault secrets enable -address="${VAULT_ADDR}" -path=secret kv-v2 2>/dev/null || \
    echo "    (secret/ engine already enabled)"

# ── Write broker policy (narrow: only secret/data/broker) ───────────────────
echo "==> Writing broker-policy (read+write on secret/data/broker only)..."
vault policy write -address="${VAULT_ADDR}" broker-policy - <<'POLICY'
path "secret/data/broker" {
    capabilities = ["create", "read", "update"]
}
path "secret/metadata/broker" {
    capabilities = ["read"]
}
POLICY

# ── Issue a scoped token for the broker ─────────────────────────────────────
# 30 days, renewable. The broker never gets the root token.
echo "==> Issuing scoped broker token (policy=broker-policy, ttl=720h, renewable)..."
BROKER_TOKEN=$(vault token create \
    -address="${VAULT_ADDR}" \
    -policy=broker-policy \
    -ttl=720h \
    -renewable=true \
    -display-name="cullis-broker" \
    -format=json | jq -r '.auth.client_token')

TOKEN_FILE="$(dirname "$0")/broker-token"
echo "${BROKER_TOKEN}" > "${TOKEN_FILE}"
chmod 600 "${TOKEN_FILE}"

echo ""
echo "============================================================"
echo "  Vault initialized, unsealed, and broker token issued."
echo "============================================================"
echo ""
echo "  Scoped broker token:  (saved to ${TOKEN_FILE}, mode 600)"
echo ""
echo "  Paste into your .env file:"
echo ""
echo "    VAULT_TOKEN=${BROKER_TOKEN}"
echo ""
echo "  Or to copy it into .env automatically:"
echo "    sed -i \"s|^VAULT_TOKEN=.*|VAULT_TOKEN=\$(cat ${TOKEN_FILE})|\" .env"
echo ""
echo "  Unseal keys + root token are in ${KEYS_FILE}."
echo "  Back them up to a password manager / cloud KMS and DELETE that file."
echo ""
echo "  Next step — store the broker CA key (use the scoped token, not root):"
echo "    VAULT_TOKEN=\$(cat ${TOKEN_FILE}) vault kv put secret/broker \\"
echo "      private_key_pem=@certs/broker-ca-key.pem \\"
echo "      public_key_pem=@certs/broker-ca.pem"
echo ""
echo "  Root token can be revoked after you've verified the broker boots:"
echo "    vault token revoke \$(jq -r .root_token ${KEYS_FILE})"
echo "============================================================"
