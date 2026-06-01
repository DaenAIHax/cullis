#!/usr/bin/env bash
# pg-backup.sh — PostgreSQL backup for the Cullis Mastio Postgres deploy.
#
# Dumps the database the Mastio runs against (the bundle's
# docker-compose.postgres.yml overlay), compresses, optionally encrypts,
# and prunes old backups. Runs pg_dump inside the running Postgres
# container by name, so it does not depend on a compose project / cwd.
#
# IMPORTANT: on a production (Vault-custodied) Mastio this is only HALF
# of a DR backup. The Org CA + Mastio Intermediate private keys live in
# Vault, not Postgres, so a Postgres-only backup cannot restore agent
# mTLS by itself. Pair this with vault-ca-backup.sh. See
# docs/operate/disaster-recovery.md.
#
# Usage:
#   ./scripts/pg-backup.sh
#
# Env (all optional; defaults match the bundle's docker-compose.postgres.yml):
#   PG_CONTAINER        Postgres container name (default cullis-mastio-postgres)
#   POSTGRES_USER       DB role   (default cullis_mastio)
#   POSTGRES_DB         DB name   (default cullis_mastio)
#   BACKUP_DIR          output dir (default <repo>/backups)
#   BACKUP_ENCRYPT_KEY  AES-256 passphrase; if unset the dump is NOT encrypted
#   KEEP_COUNT          backups to retain (default 30)

set -euo pipefail

PG_CONTAINER="${PG_CONTAINER:-cullis-mastio-postgres}"
PG_USER="${POSTGRES_USER:-cullis_mastio}"
PG_DB="${POSTGRES_DB:-cullis_mastio}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
BACKUP_FILE="cullis_mastio_${TIMESTAMP}.sql.gz"
ENCRYPTED_FILE="${BACKUP_FILE}.enc"
KEEP_COUNT="${KEEP_COUNT:-30}"
BACKUP_ENCRYPT_KEY="${BACKUP_ENCRYPT_KEY:-}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

# Fail clearly if the Postgres container is not running (e.g. an SQLite
# deploy, or the stack is down) rather than producing an empty file.
if ! docker ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
    log "ERROR: Postgres container '${PG_CONTAINER}' is not running."
    log "       Is this a Postgres deploy and is the stack up? Override the"
    log "       name with PG_CONTAINER=... if your project renames it."
    exit 1
fi

log "Backing up ${PG_DB} from container ${PG_CONTAINER} -> ${BACKUP_FILE}"
if docker exec "${PG_CONTAINER}" pg_dump -U "${PG_USER}" "${PG_DB}" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"; then
    SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    log "Backup successful: ${BACKUP_FILE} (${SIZE})"
else
    log "ERROR: Backup failed!"
    rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
    exit 1
fi

if [ ! -s "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
    log "ERROR: Backup file is empty, removing"
    rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
    exit 1
fi

# Encrypt the backup if a passphrase is set.
if [ -n "${BACKUP_ENCRYPT_KEY}" ]; then
    log "Encrypting backup with AES-256-CBC..."
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "${BACKUP_DIR}/${BACKUP_FILE}" \
        -out "${BACKUP_DIR}/${ENCRYPTED_FILE}" \
        -pass env:BACKUP_ENCRYPT_KEY
    rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
    BACKUP_FILE="${ENCRYPTED_FILE}"
    log "Backup encrypted: ${BACKUP_FILE}"
else
    log "WARNING: BACKUP_ENCRYPT_KEY not set — backup is NOT encrypted at rest"
fi

# Prune old backups — keep only the most recent $KEEP_COUNT.
BACKUP_COUNT=$(find "${BACKUP_DIR}" -maxdepth 1 -name 'cullis_mastio_*.sql.gz*' -type f | wc -l)
if [ "${BACKUP_COUNT}" -gt "${KEEP_COUNT}" ]; then
    DELETE_COUNT=$((BACKUP_COUNT - KEEP_COUNT))
    log "Pruning ${DELETE_COUNT} old backup(s) (keeping ${KEEP_COUNT})"
    find "${BACKUP_DIR}" -maxdepth 1 -name 'cullis_mastio_*.sql.gz*' -type f -printf '%T+ %p\n' \
        | sort | head -n "${DELETE_COUNT}" | awk '{print $2}' \
        | xargs rm -f
fi

log "Done. ${BACKUP_COUNT} backup(s) in ${BACKUP_DIR}"
