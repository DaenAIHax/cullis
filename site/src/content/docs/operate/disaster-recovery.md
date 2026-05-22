---
title: "Disaster recovery"
description: "Backup and restore for the Cullis Mastio bundle. Hot SQLite snapshot, encrypted tarball, full restore in ~15 min. Scenario walk-throughs for VM loss, ransomware, accidental wipe."
category: "Operate"
order: 6
updated: "2026-05-22"
---

# Disaster recovery

The Mastio is the trust root of your agent population: its Org CA signs every agent certificate, and its `mcp_proxy.db` carries every session, audit record, and user/agent enrollment. Losing it without a backup means re-enrolling everything from scratch with a new Org CA — every agent, every cert thumbprint pin. With the procedure below, recovery is a 15-minute job from any host that can read the encrypted backup file.

This guide covers the bundle deploy (single-host Docker Compose). For Kubernetes deployments, the Helm chart pairs with your cluster's existing backup tooling (Velero, etcd snapshots, Postgres backups) — out of scope here.

## What gets backed up

| Path | Contents | Why critical |
|---|---|---|
| `data/mcp_proxy.db` | SQLite: agents, sessions, audit log, users, config | Loss = full re-enrollment |
| `nginx-certs/org-ca.{crt,key}` | Org CA keypair (trust root) | Loss = every agent cert invalidated |
| `nginx-certs/mastio-server.{crt,key}` | Server cert for nginx sidecar | Loss = TLS termination broken |
| `certs/org-ca.pem` | Operator-readable copy of the Org CA cert | Loss = inconvenience only (regenerated from `nginx-certs/`) |
| `proxy.env` | Operator-side config (`PROXY_PUBLIC_URL`, admin secrets, plugin envs) | Loss = re-tuning from scratch |

What is **not** backed up:

- Plugin secrets stored in external systems (Vault, AWS Secrets Manager, etc.) — those have their own backup strategy.
- Cloud KMS Org CA key copy (if `MCP_PROXY_KMS_BACKEND` is set to `vault` / `aws` / `azure` / `gcp`) — the key lives in the KMS already, outside the bundle. Bundle backup snapshots only the Mastio's local view.

## Taking a backup

The bundle ships bind directories (`./data/`, `./nginx-certs/`, `./certs/`) on the host filesystem, so backup is a `sqlite3 .backup` + `tar` + `gpg` away. From inside the bundle dir:

```bash
# 1. Take a hot SQLite snapshot (no need to stop the running stack)
docker compose -p cullis-mastio exec -T mastio \
    sqlite3 /data/mcp_proxy.db ".backup /data/mcp_proxy.db.snapshot"

# 2. Tar the bind dirs + proxy.env into a single archive
TS=$(date -u +%Y%m%dT%H%M%SZ)
tar czf "cullis-mastio-backup-${TS}.tar.gz" \
    data/mcp_proxy.db.snapshot \
    nginx-certs/ \
    certs/ \
    proxy.env

# 3. Encrypt with a passphrase
gpg --symmetric --cipher-algo AES256 \
    --output "cullis-mastio-backup-${TS}.tar.gz.gpg" \
    "cullis-mastio-backup-${TS}.tar.gz"

# 4. Remove the unencrypted copies
rm "cullis-mastio-backup-${TS}.tar.gz" data/mcp_proxy.db.snapshot
```

The hot SQLite snapshot is consistent without stopping the running Mastio (uses SQLite's `.backup` command, which holds a read transaction). Cert files are copied as-is; they rarely change at runtime.

### Bundled upgrade backup (automatic)

`./deploy.sh --upgrade <version>` automatically writes a pre-upgrade backup to `./backups/pre-upgrade-<ts>/` before applying the upgrade. This is **not** a substitute for a regular off-host backup (it stays on the same disk), but it lets you roll back a botched upgrade without ceremony.

### Non-interactive (cron)

For scheduled backups, pre-place the passphrase in a `0400`-mode file:

```bash
echo 'your-strong-passphrase' > /etc/cullis/backup.pass
chmod 0400 /etc/cullis/backup.pass
chown root:root /etc/cullis/backup.pass
```

Then wrap the four-step procedure in a script and pass `--batch --passphrase-file` to gpg:

```bash
gpg --symmetric --cipher-algo AES256 --batch \
    --passphrase-file /etc/cullis/backup.pass \
    --output "${OUT_DIR}/cullis-mastio-backup-${TS}.tar.gz.gpg" \
    "${WORKDIR}/cullis-mastio-backup-${TS}.tar.gz"
```

Sample cron entry (daily 02:00, retain 30 days):

```cron
0 2 * * *  /opt/cullis-mastio-bundle/backup.sh \
           && find /var/backups/cullis -mtime +30 -name '*.tar.gz.gpg' -delete
```

A reference `backup.sh` wrapper that codifies the four steps above and respects `--passphrase-file` is on the bundle roadmap; until then, copy the snippet above into a script in your config-management repo.

### Off-host copy

The encrypted file is safe to transmit over untrusted channels. Pick one (or several):

```bash
# rsync to a separate host
rsync -a backups/cullis-mastio-backup-*.tar.gz.gpg \
      backup-host:/var/backups/cullis/

# S3
aws s3 cp backups/cullis-mastio-backup-*.tar.gz.gpg \
          s3://yourorg-cullis-backups/

# USB drive
cp backups/cullis-mastio-backup-*.tar.gz.gpg /mnt/usb/cullis/
```

**The passphrase is the only secret.** Store it in your password manager (Bitwarden, 1Password) under a different item from the backup itself. Both lost = data unrecoverable.

## Restoring

On a fresh host or after disaster:

1. Install Docker + Compose v2 (see [Mastio on Docker](../install/mastio-bundle) prerequisites).
2. Re-deploy the bundle into an empty directory:
   ```bash
   curl -L -o cullis-mastio-bundle.tar.gz \
       https://github.com/cullis-security/cullis/releases/latest/download/cullis-mastio-bundle.tar.gz
   tar xzf cullis-mastio-bundle.tar.gz
   cd cullis-mastio-bundle/
   ```
3. Decrypt and extract the backup over the bundle's bind dirs:
   ```bash
   gpg --decrypt /path/to/cullis-mastio-backup-*.tar.gz.gpg \
       | tar xzf - --overwrite
   # Rename the snapshot back to the live DB filename
   mv data/mcp_proxy.db.snapshot data/mcp_proxy.db
   ```
4. Sanity-check `proxy.env`:
   - `MCP_PROXY_PROXY_PUBLIC_URL` matches the hostname the new host will serve on. If you're moving to a new IP / DNS name, update it here and update `MCP_PROXY_NGINX_SAN` to include the new hostname.
   - Plugin secret references (Vault paths, KMS ARNs, API keys) are still resolvable from the new host.
5. Bring up the stack:
   ```bash
   ./deploy.sh
   ```
6. Verify post-boot:
   ```bash
   curl -k https://localhost:9443/healthz
   curl -k https://localhost:9443/readyz
   docker compose -p cullis-mastio logs mastio | tail -50
   ```
   `/readyz` should return `{"status":"ready",...}`. Logs should not show TLS handshake errors or Org CA mint warnings.

## Scenario walk-throughs

### VM disk failure (most common)

1. Provision new VM, install Docker.
2. Download bundle, `tar xz`, `cd cullis-mastio-bundle/`.
3. Decrypt the backup over the bind dirs (mount the off-host backup volume or copy via `scp` first).
4. Edit `proxy.env` if the public URL changes.
5. `./deploy.sh`.

Time: ~15 minutes including DNS update if `MCP_PROXY_PROXY_PUBLIC_URL` changes. Existing agents continue working as long as they can reach the new IP and the Org CA cert is restored (= preserves their thumbprint pin).

### Ransomware / host compromise

1. Quarantine the affected host (do not power it back on; preserve forensics).
2. Provision new VM as above.
3. Restore from the **last clean** backup (verify the timestamp pre-dates the suspected breach).
4. Rotate all secrets that could have leaked:
   - `MCP_PROXY_ADMIN_SECRET`, `MCP_PROXY_DASHBOARD_SIGNING_KEY` in `proxy.env` — regenerate with `openssl rand -hex 32`
   - Anthropic / OpenAI API keys in `proxy.env` — rotate at the provider
   - Cloud creds (`AWS_ACCESS_KEY_ID`, Azure SP, etc.) — rotate at IdP
   - Any Vault tokens — revoke + re-issue
5. Force agent cert re-issuance for any agent that could have had its private key exposed (dashboard → Agents → Rotate cert, or `POST /registry/agents/<id>/rotate-cert`).
6. Audit log review on the restored DB to identify the breach window.

### Accidental wipe (`rm -rf data/` on the wrong host)

1. Stop the stack: `./deploy.sh --down`.
2. Find the most recent backup: `ls -lt backups/ /var/backups/cullis/ | head -5`.
3. Decrypt and extract over the (now empty) bind dirs:
   ```bash
   gpg --decrypt /path/to/latest.tar.gz.gpg | tar xzf - --overwrite
   mv data/mcp_proxy.db.snapshot data/mcp_proxy.db
   ```
4. `./deploy.sh`.

Time: ~5 minutes since you're not provisioning a new host.

### Org CA key rotation after suspected compromise

The Org CA key is the most sensitive material in the deploy. If you suspect it leaked:

1. Take a backup first (audit trail).
2. Stop the stack.
3. **Rotate the Org CA**: this is intrusive. Every agent cert needs re-issuance under the new CA. See [Rotate keys](rotate-keys) for the full procedure.
4. Distribute the new CA cert to all agents via their next enrollment.

Backup helps here by giving you a known-good baseline to roll forward from, but the rotation itself is independent.

## Compliance mapping

The backup pattern aligns with these common controls:

| Control | What |
|---|---|
| SOC 2 CC9.2 (data backup) | Encrypted off-host backup with documented frequency |
| ISO 27001 A.8.13 (information backup) | Same |
| DORA Art. 12 (ICT business continuity) | RPO + RTO defined (24h / 15min) |
| EU AI Act Art. 12 (record-keeping) | Audit log preserved in `mcp_proxy.db` |
| ISO 22301 (BCMS) | DR runbook documented + tested |

Recommended cadence:

- **Backup**: daily for production, weekly for staging
- **Off-host copy**: every backup (no point keeping it on the same disk)
- **Restore drill**: quarterly on a non-prod host. Verify the procedure still works end-to-end. Document any drift in the runbook.

## Next

- [Runbook](runbook) — incident response and day-to-day operations
- [Rotate keys](rotate-keys) — key rotation procedures, including the Org CA
- [Vault as Org CA private key store](vault-org-ca) — move the Org CA root key out of the bundle entirely
- [Audit export](audit-export) — extract the tamper-evident audit log for forensic review
