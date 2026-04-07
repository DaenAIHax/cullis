#!/usr/bin/env bash
set -euo pipefail

echo "==> Waiting for Vault at ${VAULT_ADDR} ..."
until curl -so /dev/null -w '%{http_code}' "${VAULT_ADDR}/v1/sys/health" 2>/dev/null | grep -qE '^(200|429|472|473|501|503)'; do
  sleep 1
done
echo "==> Vault is responding."

# -------------------------------------------------------------------
# Read agent cert + private key from Vault KV v2
# -------------------------------------------------------------------
echo "==> Reading agent credentials from Vault ..."
VAULT_RESP=$(curl -sf \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/secret/data/agent")

CERT_PEM=$(echo "${VAULT_RESP}" | jq -r '.data.data.cert_pem')
KEY_PEM=$(echo "${VAULT_RESP}"  | jq -r '.data.data.private_key_pem')

if [ -z "${CERT_PEM}" ] || [ "${CERT_PEM}" = "null" ]; then
  echo "ERROR: cert_pem not found in Vault at secret/data/agent"
  echo "       Run bootstrap.sh first to provision credentials."
  exit 1
fi

echo "${CERT_PEM}" > /tmp/agent-cert.pem
echo "${KEY_PEM}"  > /tmp/agent-key.pem
chmod 600 /tmp/agent-key.pem

echo "==> Credentials written to /tmp/agent-{cert,key}.pem"
echo "==> Starting agent console ..."
exec uvicorn agent_app:app --host 0.0.0.0 --port 8080
