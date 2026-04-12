#!/usr/bin/env bash
# vault-init — runs after Vault is healthy. Does two things:
#
# 1. Creates a Vault policy that only allows read+write on the broker's
#    secret path (secret/data/broker), enables the kv-v2 engine if
#    missing, and issues a token scoped to that policy. The token is
#    written to /vault-token/broker-token — the broker reads it at
#    startup instead of the root token.
#
# 2. Remains a one-shot: exits 0 when done so dependents (broker-init,
#    broker) can gate on `service_completed_successfully`.
#
# Security posture for the smoke:
#   - Vault root token never leaves this container.
#   - Broker runs with a narrow-scoped token (not root).
#   - All Vault traffic is HTTPS (Vault cert signed by test CA, verified
#     via VAULT_CACERT=/certs/ca.crt).
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:?VAULT_ADDR not set}"
VAULT_CACERT="${VAULT_CACERT:?VAULT_CACERT not set}"
VAULT_ROOT_TOKEN="${VAULT_ROOT_TOKEN:?VAULT_ROOT_TOKEN not set}"
TOKEN_OUT_DIR="${TOKEN_OUT_DIR:-/vault-token}"

export VAULT_ADDR VAULT_CACERT

# ── Authenticate to Vault with root token (only here, never leaks out) ─────
export VAULT_TOKEN="$VAULT_ROOT_TOKEN"

# Wait for Vault to be fully ready (dev mode becomes ready almost instantly
# but we defensively retry auth for a few seconds).
for attempt in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then break; fi
    sleep 1
done

# kv-v2 is enabled by default in dev mode at "secret/". If someone uses a
# custom image variant we ensure it's there.
if ! vault secrets list -format=json | jq -e '."secret/"' >/dev/null 2>&1; then
    vault secrets enable -path=secret kv-v2
fi

# ── Define a narrow policy and issue a scoped token ─────────────────────────
vault policy write broker-policy - <<'POLICY'
# Broker needs read+write on its own secret path, nothing else.
path "secret/data/broker" {
    capabilities = ["create", "read", "update"]
}
# Metadata access is required by the kv-v2 helper in hvac; harmless.
path "secret/metadata/broker" {
    capabilities = ["read"]
}
POLICY
echo "vault-init: wrote broker-policy"

# Short TTL; the broker will renew or re-login. For the smoke's 60s cycle
# 24h is overkill but eliminates a renewal race on slow CI.
mkdir -p "$TOKEN_OUT_DIR"
vault token create -policy=broker-policy -ttl=24h -format=json \
    | jq -r '.auth.client_token' > "$TOKEN_OUT_DIR/broker-token"
chmod 644 "$TOKEN_OUT_DIR/broker-token"
echo "vault-init: issued broker-scoped token at $TOKEN_OUT_DIR/broker-token"

echo "vault-init: done"
