#!/usr/bin/env bash
# pg-restore.sh — Restore a Cullis Mastio Postgres backup.
#
# Accepts a .sql.gz / .sql / .sql.gz.enc backup produced by
# pg-backup.sh and restores it into the running Postgres container.
#
# DR ORDER (production, Vault-custodied Mastio): restore the Vault CA
# material FIRST (vault-ca-restore.sh), restore Postgres here, and bring
# the Mastio container up LAST so it ADOPTS the restored Org CA +
# Intermediate instead of minting fresh ones. Minting fresh CA material
# while enrolled agents exist orphans every agent's mTLS cert; on a
# production Mastio the boot now refuses rather than doing that
# silently (see MCP_PROXY_ALLOW_PKI_REKEY). Full procedure:
# docs/operate/disaster-recovery.md.
#
# Usage:
#   ./scripts/pg-restore.sh backups/cullis_mastio_2026-06-01_120000.sql.gz
#
# Env (optional):
#   PG_CONTAINER        Postgres container (default cullis-mastio-postgres)
#   POSTGRES_USER       DB role  (default cullis_mastio)
#   POSTGRES_DB         DB name  (default cullis_mastio)
#   BACKUP_ENCRYPT_KEY  passphrase to decrypt a .enc backup

set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-cullis-mastio-postgres}"
PG_USER="${POSTGRES_USER:-cullis_mastio}"
PG_DB="${POSTGRES_DB:-cullis_mastio}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup-file>"
    echo "  e.g. $0 backups/cullis_mastio_2026-06-01_120000.sql.gz"
    exit 1
fi
BACKUP_FILE="$1"
[ -f "${BACKUP_FILE}" ] || { log "ERROR: File not found: ${BACKUP_FILE}"; exit 1; }

if ! docker ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
    log "ERROR: Postgres container '${PG_CONTAINER}' is not running (override with PG_CONTAINER=...)"
    exit 1
fi

log "WARNING: This restores into '${PG_DB}' on container '${PG_CONTAINER}'."
read -r -p "Continue? [y/N] " confirm
[[ "${confirm}" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }

# Decrypt first if the backup is encrypted.
SRC="${BACKUP_FILE}"
TMP_DECRYPTED=""
cleanup() { [ -n "${TMP_DECRYPTED}" ] && rm -f "${TMP_DECRYPTED}"; }
trap cleanup EXIT

if [[ "${BACKUP_FILE}" == *.enc ]]; then
    [ -n "${BACKUP_ENCRYPT_KEY:-}" ] || { log "ERROR: ${BACKUP_FILE} is encrypted but BACKUP_ENCRYPT_KEY is not set"; exit 1; }
    TMP_DECRYPTED="$(mktemp)"
    log "Decrypting ${BACKUP_FILE}..."
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
        -in "${BACKUP_FILE}" -out "${TMP_DECRYPTED}" -pass env:BACKUP_ENCRYPT_KEY
    SRC="${TMP_DECRYPTED}"
fi

stream() { if [[ "${SRC}" == *.gz ]]; then gunzip -c "${SRC}"; else cat "${SRC}"; fi; }

log "Restoring from ${BACKUP_FILE} into ${PG_DB}..."
if stream | docker exec -i "${PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" --single-transaction -v ON_ERROR_STOP=1; then
    log "Restore successful."
else
    log "ERROR: Restore failed!"
    exit 1
fi
