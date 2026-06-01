# Disaster recovery, Cullis Mastio (Postgres + Vault)

This is the DR procedure for a **production, standalone** Mastio that
runs against external Postgres and custodies its CA in HashiCorp Vault
(the pilot shape). For the default SQLite + file-KMS dev deploy, the
host bind dirs (`./data`, `./nginx-certs`) are the whole state and a
filesystem copy is enough; this page is about the Postgres + Vault
shape, where state is split across two systems.

## What a full backup must capture

A production Mastio's state lives in **two** places, and a backup of
only one is silently incomplete:

| State | Where | Backup |
|---|---|---|
| Audit chain, enrolled agents, config, policy | Postgres | `scripts/pg-backup.sh` |
| Org Root CA + Mastio Intermediate CA (cert + **private key**) | Vault (`secret/cullis-mastio/{org-ca,intermediate-ca}`) | `scripts/vault-ca-backup.sh` |

The CA material is the crown jewel, and there are **two** CA secrets,
not one: the Org Root (cold, 15y) and the Mastio Intermediate (hot
signer, 5y) that signs every agent leaf. **Both** must be in the
backup. A Postgres-only backup, or a CA backup that captures `org-ca`
but not `intermediate-ca`, will not restore agent mTLS. See "Why order
and completeness matter" below.

## Backup

```bash
# 1. Postgres (audit chain, agents, config)
BACKUP_ENCRYPT_KEY="<passphrase>" ./scripts/pg-backup.sh

# 2. Vault CA material (org-ca + intermediate-ca, contains private keys)
VAULT_ADDR=https://vault.internal:8200 VAULT_TOKEN=<token> \
  VAULT_CACERT=/path/to/vault-ca.pem \
  BACKUP_ENCRYPT_KEY="<passphrase>" ./scripts/vault-ca-backup.sh
```

Both land in `./backups/`. Set `BACKUP_ENCRYPT_KEY` on both: the CA
export contains private keys; without the passphrase it is written in
the clear. Take the two backups close together so they are consistent.

## Restore (order matters)

Restore **infrastructure first, the Mastio last**, so the Mastio boots
into an already-populated Vault + Postgres and adopts the existing CA
instead of minting a new one:

```bash
# 1. Bring up ONLY the infra (Vault + Postgres + Redis), NOT the Mastio
docker compose ... up -d vault postgres redis

# 2. Restore the Vault CA material FIRST
VAULT_ADDR=... VAULT_TOKEN=... VAULT_CACERT=... BACKUP_ENCRYPT_KEY=... \
  ./scripts/vault-ca-restore.sh backups/cullis_ca_<ts>.json.enc

# 3. Restore Postgres
BACKUP_ENCRYPT_KEY=... ./scripts/pg-restore.sh backups/cullis_mastio_<ts>.sql.gz.enc

# 4. Bring the Mastio (+ nginx) up LAST
docker compose ... up -d
```

After step 4, an agent enrolled *before* the disaster authenticates
again over mTLS with no re-enrollment: the Org CA and Intermediate are
byte-identical to the backup, so its leaf still chains.

## Why order and completeness matter

The Mastio generates an Org Root and mints a Mastio Intermediate when
it finds none at boot. That is correct on a first install, but on a
restore it is a trap:

- Bring the **Mastio up before restoring Vault** and it boots into an
  empty Vault and mints a brand-new CA. Every restored agent then fails
  mTLS (`nginx 400 SSL certificate error`).
- If the backup has **`org-ca` but not `intermediate-ca`**, the
  Intermediate is regenerated with a new key on boot. Agent leaf certs
  signed by the old Intermediate no longer verify, and the whole fleet
  is orphaned.

Since the relevant release, a **production Mastio refuses to boot** when
CA material is absent but enrolled agents exist, rather than silently
orphaning them: you get a `CRITICAL` log naming the missing secret and
a refuse-to-boot. To deliberately re-key (all agents re-enroll), set
`MCP_PROXY_ALLOW_PKI_REKEY=1`. First-time provisioning of a brand-new
production Org CA is also explicit: set `MCP_PROXY_ALLOW_CA_BOOTSTRAP=1`
for that first boot only.

## Known limitations

Stated plainly so they can go in the pilot's risk register:

- **Single instance.** No HA or multi-region failover. DR is
  restore-from-backup, with the downtime that implies; there is no hot
  standby.
- **Backup is operator-scheduled.** These scripts are manual / cron
  building blocks, not a managed backup service. RPO is whatever cadence
  you run them at; there is no built-in scheduler or retention beyond
  `KEEP_COUNT` pruning.
- **Vault snapshot is yours.** `vault-ca-backup.sh` is a logical,
  Mastio-scoped export of the CA secrets. Your Vault's own
  `vault operator raft snapshot` (or managed-Vault backup) remains the
  authoritative backup of Vault; the CA export complements it so a
  Cullis DR can be rehearsed independently.
- **Audit-chain throughput ceiling.** The hash-linked audit chain has a
  single-writer ceiling (~200 rows/s). A restore replays the dump; it
  does not change that envelope.
- **Consistency window.** Postgres and Vault are captured by separate
  commands; take them close together. CA material changes rarely (only
  on CA rotation), so a small skew is normally harmless.
```
