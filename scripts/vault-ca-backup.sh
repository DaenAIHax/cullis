#!/usr/bin/env bash
# vault-ca-backup.sh — Back up the Cullis Mastio CA material from Vault.
#
# Exports BOTH crown-jewel secrets a production Mastio custodies in
# Vault: the Org Root CA (``org-ca``) and the Mastio Intermediate CA
# (``intermediate-ca``), each ``cert_pem`` + ``key_pem``. A Postgres
# backup alone (pg-backup.sh) does NOT capture these. A restore that is
# missing the ``intermediate-ca`` makes the Mastio mint a fresh
# Intermediate on next boot, which orphans every enrolled agent's mTLS
# cert (the DR-1 finding). ALWAYS pair this with pg-backup.sh. Full
# procedure + restore order: docs/operate/disaster-recovery.md.
#
# This is a LOGICAL export of the CA key material via the KV v2 API. In
# production your Vault's own ``vault operator raft snapshot`` remains
# the primary, operator-owned backup of the whole Vault; this script is
# the complementary, Mastio-scoped capture of just the CA secrets so a
# Cullis DR can be reasoned about and rehearsed on its own.
#
# Usage:
#   VAULT_ADDR=https://vault.internal:8200 VAULT_TOKEN=... \
#     BACKUP_ENCRYPT_KEY=... ./scripts/vault-ca-backup.sh
#
# Env:
#   VAULT_ADDR          Vault address (required)
#   VAULT_TOKEN         token with read on the mount (required)
#   VAULT_CACERT        CA bundle for Vault's TLS (set for https)
#   VAULT_KV_MOUNT      KV v2 mount (default secret)
#   VAULT_CA_PREFIX     path prefix (default cullis-mastio)
#   BACKUP_DIR          output dir (default <repo>/backups)
#   BACKUP_ENCRYPT_KEY  AES-256 passphrase; if unset the export is NOT encrypted

set -euo pipefail

command -v vault >/dev/null 2>&1 || { echo "ERROR: the 'vault' CLI is required (HashiCorp Vault)." >&2; exit 1; }
: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"
export VAULT_ADDR VAULT_TOKEN
[ -n "${VAULT_CACERT:-}" ] && export VAULT_CACERT

MOUNT="${VAULT_KV_MOUNT:-secret}"
PREFIX="${VAULT_CA_PREFIX:-cullis-mastio}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
TS="$(date +%Y-%m-%d_%H%M%S)"
OUT="${BACKUP_DIR}/cullis_ca_${TS}.json"
BACKUP_ENCRYPT_KEY="${BACKUP_ENCRYPT_KEY:-}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

fetch() {  # $1 = secret name; prints the inner data JSON, empty if absent
    vault kv get -mount="${MOUNT}" -format=json "${PREFIX}/$1" 2>/dev/null \
        | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['data']['data']))" 2>/dev/null || true
}

log "Exporting CA material from ${VAULT_ADDR} (${MOUNT}/${PREFIX}/{org-ca,intermediate-ca})"
ORG="$(fetch org-ca)"
[ -n "${ORG}" ] || { log "ERROR: cannot read ${PREFIX}/org-ca (check VAULT_ADDR/TOKEN/CACERT)"; exit 1; }
INT="$(fetch intermediate-ca)"
if [ -z "${INT}" ]; then
    log "WARNING: ${PREFIX}/intermediate-ca not found — exporting org-ca only."
    log "         If any agents are enrolled, this backup is INCOMPLETE and a"
    log "         restore from it would orphan their mTLS certs."
    INT="null"
fi

ORG="${ORG}" INT="${INT}" python3 - "$OUT" <<'PY'
import json, os, sys
out = sys.argv[1]
doc = {
    "org-ca": json.loads(os.environ["ORG"]),
    "intermediate-ca": (None if os.environ["INT"] == "null" else json.loads(os.environ["INT"])),
}
with open(out, "w") as f:
    json.dump(doc, f)
PY
chmod 600 "${OUT}"
log "Wrote ${OUT} (org-ca$( [ "${INT}" = "null" ] || printf ' + intermediate-ca' ))"

if [ -n "${BACKUP_ENCRYPT_KEY}" ]; then
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "${OUT}" -out "${OUT}.enc" -pass env:BACKUP_ENCRYPT_KEY
    rm -f "${OUT}"
    OUT="${OUT}.enc"
    log "Encrypted: ${OUT}"
else
    log "WARNING: BACKUP_ENCRYPT_KEY not set — this export contains CA PRIVATE KEYS and is NOT encrypted at rest. Set BACKUP_ENCRYPT_KEY."
fi
log "Done."
