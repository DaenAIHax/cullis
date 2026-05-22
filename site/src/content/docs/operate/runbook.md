---
title: "Runbook"
description: "Incident response and day-to-day operations for a Mastio deployment — the failures most likely to wake you up, plus the commands you reach for without thinking."
category: "Operate"
order: 10
updated: "2026-05-22"
---

# Runbook

**Who this is for**: an operator running a Cullis Mastio in production. Keep this page bookmarked.

This runbook assumes the [bundle deploy](../install/mastio-bundle) (single-host Docker Compose). For Kubernetes, the failure modes are the same but the commands are `kubectl` instead of `docker compose`; see [Mastio on Kubernetes](../install/mastio-kubernetes).

## Quick reference

| Action | Command |
|---|---|
| Start the stack | `./deploy.sh` |
| Stop the stack | `./deploy.sh --down` |
| Tail Mastio logs | `docker compose -p cullis-mastio logs -f mcp-proxy` |
| Tail nginx sidecar logs | `docker compose -p cullis-mastio logs -f mastio-nginx` |
| Liveness | `curl -sk https://localhost:9443/healthz` |
| Readiness | `curl -sk https://localhost:9443/readyz` |
| Pull a new image + restart | `./deploy.sh --pull` |
| Upgrade to a new bundle version | `./deploy.sh --upgrade <version>` |
| Backup the deploy | See [Disaster recovery](disaster-recovery) |
| Rotate signing key | See [Rotate keys](rotate-keys) |
| Export audit bundle | See [Audit export](audit-export) |

## Prerequisites

- Docker Engine ≥ 20.10 with Compose v2
- `curl`, `openssl` on the host
- Admin secret available (in your password manager, not on disk)

## 1. Mastio is down

**Symptoms**

- `curl https://mastio.example.com/healthz` → connection refused or 5xx
- Dashboard unreachable, agents cannot mint DPoP-bound calls

**Confirm**

```bash
docker compose -p cullis-mastio ps mcp-proxy
docker compose -p cullis-mastio logs --tail=200 mcp-proxy
docker inspect --format '{{.State.ExitCode}} {{.State.Error}}' \
    $(docker compose -p cullis-mastio ps -q mcp-proxy)
```

**Recover**

1. **Exit 3** (uvicorn told to shut down) — read the last `Waiting for application startup` log line; the failure on the next line is the real fault.
2. **Exit 137** (OOM killed) — raise `deploy.resources.limits.memory` in the bundle's `docker-compose.prod.yml`, then `./deploy.sh --pull`.
3. **Exit 1 / 2** (uncaught exception) — scan logs for the traceback. See sections 2–4 below for common root causes.
4. Restart: `docker compose -p cullis-mastio restart mcp-proxy`.

**Verify**

- `/healthz` → 200
- `/readyz` → 200 (checks DB + JWKS cache)

## 2. Database down or unreachable

The default backend is SQLite at `./data/mcp_proxy.db` (bind-mounted on the host). Postgres is an opt-in for hosts that need cross-host clustering or higher tier-2 throughput; see [Vault as Org CA private key store](vault-org-ca) and [Capacity planning](capacity-planning).

### SQLite (default)

**Symptoms**

- Mastio logs: `sqlite3.OperationalError: unable to open database file` or `database is locked`
- `/readyz` → 503 `database: error`

**Confirm**

```bash
ls -la data/
docker compose -p cullis-mastio exec mcp-proxy ls -la /data/
```

**Recover**

1. **Permission drift** — the bundle's `init-permissions` step chowns `./data/` to UID 10001 at every `compose up`. If something on the host changed the ownership: `./deploy.sh --pull` runs the init step again and fixes it.
2. **Disk full** — `df -h .`. The `local_audit` table is append-only; archive rows older than N days via [Audit export](audit-export) and `DELETE FROM local_audit WHERE ts < ...` (only the export tool should write to the chain; manual deletes break tamper-evidence — see audit-export for the supported archive path).
3. **Corruption** — restore from the most recent backup (see [Disaster recovery](disaster-recovery)). Data loss window = last successful backup.

### Postgres (opt-in)

**Symptoms**

- Mastio logs: `connection refused` on 5432 or `asyncpg.exceptions.ConnectionDoesNotExistError`
- `mcp-proxy` container cycles between `unhealthy` and `starting`

**Confirm**

```bash
# Replace <PG_HOST> with the value in proxy.env
psql -h <PG_HOST> -U cullis -d cullis -c 'SELECT 1;'
```

**Recover**

1. **DB host down** — restart it, then `docker compose -p cullis-mastio restart mcp-proxy` to refresh the connection pool.
2. **Network reachability** — verify the Mastio container can reach the Postgres host. Network policies, firewall, DNS.
3. **Corruption** — restore from your Postgres backup (`pg_restore` or the `scripts/pg-restore.sh` helper in the source repo).

**Prevent**

- Daily backups (see [Disaster recovery](disaster-recovery))
- Monitor `pg_stat_activity.count` for connection leaks

## 3. TLS cert expired

**Symptoms**

- External clients: `SSL_ERROR_CERT_DATE_INVALID`
- `openssl s_client -connect mastio.example.com:9443 </dev/null | openssl x509 -noout -dates` → `notAfter` in the past

**Recover**

The bundle's nginx sidecar serves TLS with a cert signed by the auto-generated Org CA. To re-mint:

```bash
# Remove the existing server cert (Org CA stays)
rm nginx-certs/mastio-server.crt nginx-certs/mastio-server.key

# Re-mint on next start
./deploy.sh --pull
```

For a publicly-trusted cert (Let's Encrypt, internal ACME), terminate TLS upstream of the bundle (load balancer, ingress controller, Caddy) and point the Mastio at its own self-signed cert internally. Cert auto-renewal lives at the load balancer level, not the bundle.

**Prevent**

- Self-signed Org-CA-issued cert: re-mint annually (default validity is 1 year).
- Public ACME upstream: standard ACME renewal cron at the load balancer.

## 4. Vault sealed or unreachable (opt-in)

Skip this section if your deploy uses the default filesystem KMS (`MCP_PROXY_KMS_BACKEND=filesystem`). Vault is only relevant if you moved the Org CA private key into HashiCorp Vault — see [Vault as Org CA private key store](vault-org-ca).

**Symptoms**

- Mastio logs: `503 Service Unavailable` from Vault or `Vault is sealed`
- On boot: `RuntimeError: Vault secret at 'secret/data/mastio' missing field 'org_ca_pem'`

**Confirm**

```bash
vault status -address=$MCP_PROXY_VAULT_ADDR
# Sealed: true → proceed
```

**Recover**

```bash
vault operator unseal -address=$MCP_PROXY_VAULT_ADDR <key1>
vault operator unseal -address=$MCP_PROXY_VAULT_ADDR <key2>
vault operator unseal -address=$MCP_PROXY_VAULT_ADDR <key3>

docker compose -p cullis-mastio restart mcp-proxy
```

**Prevent**

- Auto-unseal via cloud KMS (AWS KMS, Azure Key Vault, GCP CKMS) — see [Vault auto-unseal](vault-auto-unseal) for setup.

## 5. Redis down (opt-in)

Skip this section if your deploy is single-worker (default `MASTIO_WORKERS=4`, JTI store is per-worker). Redis is opt-in for cross-worker DPoP replay protection — see the multi-worker section of [Mastio on Docker](../install/mastio-bundle#tune-workers).

**Symptoms**

- Mastio logs: `redis.exceptions.ConnectionError` on DPoP replay checks
- Cross-worker replay protection silently degrades to per-worker

**Confirm**

```bash
redis-cli -u "$MCP_PROXY_REDIS_URL" ping
```

**Recover**

1. Restart Redis (managed by your infra team or your compose setup).
2. Mastio's Redis client auto-reconnects; no Mastio restart needed.

**Data loss expectations**

Redis is ephemeral. The DPoP JTI blacklist and rate-limit counters rebuild as traffic returns. Nothing permanent is lost.

## 6. Revoke a compromised agent

**Symptoms**

A specific agent's credentials are believed compromised: private key leaked, host pwned, ex-employee with copy of cert.

**Recover**

Two parts: revoke the cert thumbprint pin (immediate) and rotate the cert (re-issue clean material to the legitimate workload, if any).

```bash
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
MASTIO="https://localhost:9443"
AGENT_ID="orga::compromised-agent"

# 1. Revoke the agent (cert thumbprint pin removed; subsequent mTLS fails immediately)
curl -sk -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
     "$MASTIO/registry/agents/$AGENT_ID/revoke"

# 2. (Optional) Re-issue cert if the workload itself was not compromised
curl -sk -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
     "$MASTIO/registry/agents/$AGENT_ID/rotate-cert"
```

Any in-flight DPoP-bound tokens stay valid until their short TTL expires (typically 5 minutes). The cert thumbprint revocation kicks in immediately on the next mTLS handshake.

The dashboard exposes the same flow at `/proxy/agents/<id>` — useful when you don't want to script it.

**Verify**

- `curl ... /v1/auth/token` with the revoked cert → 401 `Certificate has been revoked`
- Audit log entry `agent.revoked` recorded for `$AGENT_ID` (see [Audit export](audit-export))

## 7. Admin lockout

**Symptoms**

- Dashboard rejects the known password
- `/proxy/admin/*` endpoints return 403

**Recover**

The admin password is stored as a hash in the Mastio's database. Reset it by rotating `MCP_PROXY_ADMIN_SECRET` in `proxy.env` and restarting; on next boot, the Mastio re-bootstraps the hash from the new env value.

```bash
NEW="$(openssl rand -hex 32)"
sed -i "s|^MCP_PROXY_ADMIN_SECRET=.*|MCP_PROXY_ADMIN_SECRET=$NEW|" proxy.env
./deploy.sh --pull
echo "New admin secret: $NEW"
```

**Verify**

- Dashboard login with the new secret → 200
- `curl -H "X-Admin-Secret: $NEW" https://localhost:9443/proxy/admin/agents` → 200

## 8. "It just doesn't work" — blanket triage

When the symptoms don't match anything above:

```bash
# 1. Full state snapshot
docker compose -p cullis-mastio ps -a
docker compose -p cullis-mastio logs --tail=50 mcp-proxy mastio-nginx

# 2. Quick smoke
curl -sk https://localhost:9443/healthz
curl -sk https://localhost:9443/readyz

# 3. Admin endpoint sanity check
ADMIN_SECRET="$(grep ^MCP_PROXY_ADMIN_SECRET proxy.env | cut -d= -f2)"
curl -sk -H "X-Admin-Secret: $ADMIN_SECRET" \
    https://localhost:9443/proxy/admin/agents
```

If those all return as expected but agents still fail: the issue is almost always client-side — public URL / SAN / DPoP `htu` mismatch. See [Troubleshoot](#troubleshoot) below.

## Monitoring

**Health endpoints**

- `GET /healthz` — liveness (200 if the process is up)
- `GET /readyz` — readiness (DB + JWKS cache)

**Metrics (OpenTelemetry counters)**

- `auth.success` / `auth.deny`
- `session.created` / `session.denied`
- `policy.allow` / `policy.deny`
- `rate_limit.reject`

**Logs**

Set `LOG_FORMAT=json` in `proxy.env` for SIEM-ready structured logging.

## Troubleshoot

**`Invalid DPoP proof: htu mismatch` 401s after deploy**
: `MCP_PROXY_PROXY_PUBLIC_URL` in `proxy.env` doesn't match the URL agents actually use. The DPoP proof carries the client's URL; the Mastio compares it to its configured public URL. Check with `docker compose -p cullis-mastio exec mcp-proxy env | grep PROXY_PUBLIC_URL` and compare to the URL the agent's SDK config uses. The Mastio also logs both values on mismatch.

**Self-signed cert rejected by the agent**
: All SDKs refuse self-signed certs by default. For agents talking to a self-hosted Mastio with an Org-CA-issued cert, distribute the Org CA cert (`./nginx-certs/org-ca.crt`) and point the SDK's `ca_chain_path` at it. Never disable TLS verification in production.

**Agent gets `getaddrinfo failed` connecting to the Mastio**
: The hostname in `MCP_PROXY_PROXY_PUBLIC_URL` must resolve from the agent's machine. Use corporate DNS, a public DNS A record, or `/etc/hosts` per-agent for small trials.

**`Bind for 0.0.0.0:9443 failed: port is already allocated`**
: Another service on the host owns 9443. Override `MCP_PROXY_PORT` in `proxy.env` and update `MCP_PROXY_PROXY_PUBLIC_URL` to use the same port — agents sign DPoP `htu` against that exact URL+port and a mismatch silently 401s.

## Next

- [Disaster recovery](disaster-recovery) — backup and restore procedures
- [Rotate keys](rotate-keys) — signing-key rotation without downtime
- [Apply updates](apply-updates) — framework updates with boot-time detector
- [Audit export](audit-export) — hash chain export, TSA bundle, CLI verifier
- [Capacity planning](capacity-planning) — throughput baseline and how to measure your own
