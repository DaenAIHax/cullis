#!/usr/bin/env bash
# vault-ca-restore.sh — Restore Cullis Mastio CA material into Vault.
#
# Reads a cullis_ca_*.json[.enc] produced by vault-ca-backup.sh and
# writes org-ca (+ intermediate-ca) back to the KV v2 mount.
#
# DR ORDER: run this BEFORE bringing the Mastio container up, so the
# Mastio finds its Org CA + Intermediate already in Vault and ADOPTS
# them instead of minting fresh material. Restoring Postgres
# (pg-restore.sh) but not the Intermediate, then booting, is exactly
# the DR-1 failure: the Mastio mints a new Intermediate and orphans
# every enrolled agent. See docs/operate/disaster-recovery.md.
#
# Usage:
#   VAULT_ADDR=https://vault.internal:8200 VAULT_TOKEN=... \
#     ./scripts/vault-ca-restore.sh backups/cullis_ca_2026-06-01_120000.json
#
# Env: same as vault-ca-backup.sh (VAULT_ADDR/TOKEN/CACERT, VAULT_KV_MOUNT,
#      VAULT_CA_PREFIX, BACKUP_ENCRYPT_KEY for .enc inputs).

set -euo pipefail

command -v vault >/dev/null 2>&1 || { echo "ERROR: the 'vault' CLI is required (HashiCorp Vault)." >&2; exit 1; }
: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"
export VAULT_ADDR VAULT_TOKEN
[ -n "${VAULT_CACERT:-}" ] && export VAULT_CACERT

MOUNT="${VAULT_KV_MOUNT:-secret}"
PREFIX="${VAULT_CA_PREFIX:-cullis-mastio}"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

[ $# -ge 1 ] || { echo "Usage: $0 <cullis_ca_*.json[.enc]>"; exit 1; }
SRC="$1"
[ -f "${SRC}" ] || { log "ERROR: not found: ${SRC}"; exit 1; }

# All transient files (decrypted JSON + the per-secret cert/key temp
# files) live under one mktemp -d that the EXIT trap always removes, so
# CA private-key material never lingers in /tmp even if a `vault kv put`
# fails mid-restore under `set -e`.
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT
if [[ "${SRC}" == *.enc ]]; then
    [ -n "${BACKUP_ENCRYPT_KEY:-}" ] || { log "ERROR: ${SRC} is encrypted but BACKUP_ENCRYPT_KEY is not set"; exit 1; }
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "${SRC}" -out "${WORKDIR}/decrypted.json" -pass env:BACKUP_ENCRYPT_KEY
    SRC="${WORKDIR}/decrypted.json"
fi

restore_one() {  # $1 = secret name (org-ca | intermediate-ca)
    local name="$1" cert key tmpc tmpk
    cert="$(SRC="${SRC}" python3 -c "import json,os;d=json.load(open(os.environ['SRC']))['$name'];print(d['cert_pem'] if d else '')")"
    key="$(SRC="${SRC}" python3 -c "import json,os;d=json.load(open(os.environ['SRC']))['$name'];print(d['key_pem'] if d else '')")"
    if [ -z "${cert}" ] || [ -z "${key}" ]; then
        log "skip ${name} (absent in backup)"
        return 0
    fi
    tmpc="$(mktemp -p "${WORKDIR}")"; tmpk="$(mktemp -p "${WORKDIR}")"
    printf '%s' "${cert}" > "${tmpc}"; printf '%s' "${key}" > "${tmpk}"
    vault kv put -mount="${MOUNT}" "${PREFIX}/${name}" cert_pem=@"${tmpc}" key_pem=@"${tmpk}" >/dev/null
    log "restored ${MOUNT}/${PREFIX}/${name}"
}

log "WARNING: this writes CA material into ${VAULT_ADDR} (${MOUNT}/${PREFIX}/*)."
read -r -p "Continue? [y/N] " c
[[ "${c}" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }

restore_one org-ca
restore_one intermediate-ca
log "Done. Bring the Mastio up now; it will adopt the restored CA (no fresh mint)."
