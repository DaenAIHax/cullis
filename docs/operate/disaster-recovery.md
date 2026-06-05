# Disaster recovery, Cullis Mastio (Postgres + Vault)

This is the DR procedure for a **production, standalone** Mastio that
runs against external Postgres and custodies its CA in HashiCorp Vault
(the pilot shape). For the default SQLite + file-KMS dev deploy, the
host bind dirs (`./data`, `./nginx-certs`) are the whole state and a
filesystem copy is enough; this page is about the Postgres + Vault
shape, where state is split across two systems.

## Prerequisite: the production Vault must be persistent

Everything below assumes the Vault custodying the CA survives a restart.
**It only does so if Vault runs with persistent storage.** A Vault
started in dev mode (`vault server -dev` / `-dev-tls`) keeps its entire
KV store **in memory**: on the first container restart, upgrade, or host
reboot, the Org CA and the Mastio Intermediate CA are gone. The Mastio
then refuses to boot (orphan guard, DR-1) or, if CA bootstrap is left
enabled, mints a **fresh** Intermediate that orphans every enrolled
agent's mTLS cert. No backup script can recover from this, because there
was never anything on disk to back up.

A production Vault must therefore run with:

- **Persistent storage** (`raft` integrated storage, or a `file` /
  managed backend), never the in-memory dev backend.
- **Auto-unseal** (a cloud KMS, an HSM, or Transit), so an unattended
  restart does not leave Vault sealed and the Mastio unable to read the
  CA. Manual unseal is acceptable only if an operator is always on hand
  for every restart.
- Its own backup of the whole store (`vault operator raft snapshot` or
  the managed-Vault equivalent), in addition to the Mastio-scoped CA
  export below.

The `-dev-tls` overlay used in the local dogfood stack is **dev-only**
for exactly this reason: it is convenient for a throwaway demo, but it
loses the CA on restart and must never back a real org. The CA and the
`DB_ENCRYPTION_KEY` are persistent for the life of the org and are never
regenerated; a version upgrade swaps only the image and bundle files,
never the Vault state or the CA. The Mastio integrates an
operator-owned Vault rather than shipping its own, so this persistence
contract is the operator's to satisfy.

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

## Upgrade and rollback

**Upgrade.** `./deploy.sh --upgrade-bundle <version>` backs up `proxy.env`
+ `./data/` + `./nginx-certs/` to `./backups/pre-upgrade-<ts>/`, bumps the
image, and restarts. Alembic migrations run at boot (`alembic upgrade
head`) and are additive: they add columns / tables / triggers, they do
not drop or rewrite existing data, so an upgrade preserves the audit
chain and the enrolled agents.

For the Postgres + Vault pilot shape the bundle's pre-upgrade backup does
NOT cover Postgres or Vault. Run `scripts/pg-backup.sh` and
`scripts/vault-ca-backup.sh` BEFORE the upgrade so you have a restore
point for both.

**Rollback.** The migrations are reversible on Postgres (drilled:
`downgrade` then `upgrade head` round-trips cleanly, and `audit_log` is
never dropped). But `downgrade` is NOT data-preserving: it drops what the
migration added (e.g. agent `capabilities` from `0045`, the TSA / Merkle
anchor tables from `0043`/`0044`). The anchors regenerate on their own;
the capability assignments do not. There are two rollback paths, and only
one is clean:

- **Restore from backup (recommended).** Restore the Postgres dump and
  the Vault CA material from the pre-upgrade backups (`pg-restore.sh`,
  `vault-ca-restore.sh`), then deploy the old image. Data-preserving;
  this is the supported rollback for the pilot.
- **Deploy the old image without restoring (last resort).** mTLS and the
  audit chain keep working (the schema stays ahead of the code, the
  migrations are additive, and `audit_log` was never dropped), but do NOT
  then run an explicit `alembic downgrade` expecting to keep data: it
  drops the columns / tables the newer version added.

## Vault token lifecycle

The Mastio authenticates to Vault with a single static token
(`MCP_PROXY_VAULT_TOKEN`). A non-root token has a finite TTL: once it
lapses, every CA load/store returns HTTP 403, so cert rotation **and any
restart** start failing. To make this safe:

- **Issue a periodic (or renewable) token.** A periodic token never hits
  a max-TTL and is the recommended shape:

  ```bash
  vault token create -policy=cullis-mastio -period=24h
  ```

- **The Mastio renews it for you.** When `kms_backend=vault` and the
  token is renewable/periodic, a leader-elected watcher calls
  `auth/token/renew-self` at roughly half the lease, so the token never
  lapses while the Mastio runs. No operator cron is needed. Disable with
  `MCP_PROXY_VAULT_TOKEN_RENEWAL_ENABLED=false`.

- **Boot refuses a doomed token.** In production, if you supply a
  **non-renewable** token with a finite TTL (which Mastio cannot keep
  alive), boot is refused with a clear log line rather than starting a
  Mastio that will silently break at the first rotation/restart after
  expiry. Override only if you accept manual token rotation:
  `MCP_PROXY_VAULT_TOKEN_ALLOW_NONRENEWABLE=true`.

- **Renewal has a ceiling.** A renewable non-periodic token can only be
  renewed up to its `explicit_max_ttl`; prefer `-period` for an
  always-on Mastio. If a renew ever fails (Vault sealed, network), the
  watcher logs and retries on a 30 s floor and emits a
  `kms.vault_token_renewed` audit row (`status=error`) so the failure is
  visible before the token actually expires.

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
