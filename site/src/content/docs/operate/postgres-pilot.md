---
title: "Postgres for production pilots"
description: "Move the Cullis Mastio backend from the default SQLite to a Postgres 16 instance — bundled overlay or managed cloud — and verify the binding is healthy before traffic ramps up."
category: "Operate"
order: 8
updated: "2026-05-23"
---

# Postgres for production pilots

The Cullis Mastio bundle ships with SQLite enabled by default. That is the right call for a single-host demo, a developer laptop, or the first 1–2 enrolled agents. As soon as you cross into "concurrent agents above 50 and audit retention longer than a week", switch the backend to Postgres 16. This page covers both deployment shapes — the **bundled Postgres** that ships next to the Mastio in the same compose project, and a **managed cloud Postgres** (RDS, Cloud SQL, Azure Database).

## When to switch

The default SQLite backend is single-writer with WAL mode enabled. It handles up to four uvicorn workers safely (audit chain stays consistent via the retry path), but the soak test at 500 concurrent virtual users shows p99 ingress latency around 8.7 seconds — well outside any pilot SLO. The same test on Postgres 16 stays under one second at the same concurrency.

Switch backends **before** the first agent is enrolled in production. Migrating data from a running SQLite Mastio to Postgres is not a first-class flow: the bundle has no `sqlite-to-postgres` dumper, and pointing the Mastio at an empty Postgres triggers a fresh Org CA mint that invalidates every Connector already enrolled. The `deploy.sh` script guards against this footgun (it refuses to start when it detects an orphan SQLite DB alongside a Postgres URL), but it is much easier to start on Postgres than to migrate later.

## Option A — bundled Postgres overlay

For a single-host pilot where the Mastio and the database live on the same VM, ship the bundled Postgres 16 container alongside the Mastio via the overlay compose file.

```bash
cd cullis-mastio-bundle/

# Generate a strong random POSTGRES_PASSWORD and add it to proxy.env
./generate-proxy-env.sh --db postgres

# Bring up Mastio + Postgres together
./deploy.sh --db postgres
```

The `--db postgres` flag layers `docker-compose.postgres.yml` on top of the base file: it starts a `postgres:16-alpine` container on the bundle's private network, binds `./postgres-data` as the data volume, and sets `PROXY_DB_URL` on the Mastio container to the asyncpg URL pointing at it. The `mcp-proxy` service waits for `pg_isready` before booting, so the Alembic upgrade chain runs against a healthy DB on first start.

Verify the binding landed:

```bash
docker exec cullis-mastio-postgres \
    psql -U cullis_mastio -d cullis_mastio \
    -c "SELECT COUNT(*) FROM audit_log"
# count = 1 or more (the first-boot audit row from the lifespan)

docker exec cullis-mastio-proxy env | grep -E 'PROXY_DB_URL|MCP_PROXY_DATABASE_URL'
# both should show postgresql+asyncpg://...@postgres:5432/cullis_mastio
```

## Option B — managed cloud Postgres

For a multi-host or HA pilot, the Mastio should point at a managed Postgres service the customer already operates. Do **not** layer the overlay — skip it entirely and put the canonical URL into `proxy.env`:

```env
# proxy.env
PROXY_DB_URL=postgresql+asyncpg://mastio:STRONG-RANDOM@db.internal:5432/cullis_mastio
```

Then bring the bundle up without `--db postgres`:

```bash
./deploy.sh
```

The base compose file picks up `PROXY_DB_URL` from `proxy.env` unchanged. Run the Alembic chain explicitly **before** the first Mastio boot if you want a controlled migration window:

```bash
docker run --rm \
    -e PROXY_DB_URL="$PROXY_DB_URL" \
    ghcr.io/cullis-security/cullis-mastio:latest \
    python -m alembic -c mcp_proxy/alembic.ini upgrade head
```

This applies migrations `0001_initial_snapshot` through head against the managed instance. On the next `./deploy.sh` the lifespan finds the schema at head and skips the upgrade.

### Required database privileges

The Mastio runtime needs `CREATE TABLE`, `CREATE INDEX`, and the ability to install the `BEFORE UPDATE/DELETE` trigger on `audit_log` (migration `0042_audit_log_v2`). Use a database role that owns the schema and grant nothing else — the Mastio process never needs `SUPERUSER` or `CREATE DATABASE`.

```sql
CREATE ROLE mastio LOGIN PASSWORD 'STRONG-RANDOM';
CREATE DATABASE cullis_mastio OWNER mastio;
```

## Verify the binding is healthy

Once the Mastio is up, run the integration suite against your live Postgres to assert the binding contract holds end-to-end. Clone the public repo, then:

```bash
export CULLIS_TEST_PG_URL="$PROXY_DB_URL"
./test/run-pg-nightly.sh
```

This walks all 43 Alembic migrations on a fresh `public` schema, pins that the append-only trigger refuses `UPDATE` and `DELETE` on `audit_log`, asserts the `UNIQUE(chain_seq)` constraint surfaces as `sqlalchemy.exc.IntegrityError` (the multi-worker retry path depends on this), and grep `pg_locks` for the documented Alembic advisory lock key `0xC0115A1E_EB1C0DE`. Five tests, ~4 seconds against a Postgres on the same host.

Run the soak baseline next:

```bash
DURATION=30m PEAK_VUS=500 ./scripts/load-soak-pg.sh
```

This produces a Markdown report under `imp/load-test-run4-postgres-<timestamp>.md` with p50/p95/p99 ingress, audit row count, and the `pg_stat_activity` connection snapshot. Compare to the Run 3 SQLite baseline (~8.7 s p99 at 500 VU) and decide whether to ship, tune, or escalate.

## Backup baseline

Once Postgres is the source of truth, the SQLite `pg-backup.sh` helper does not apply (that script is the broker / ATN ledger backup). For the Mastio Postgres take a logical dump on a cron:

```bash
docker exec cullis-mastio-postgres \
    pg_dump -U cullis_mastio -Fc cullis_mastio \
    > "mastio-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

`-Fc` (custom format) lets you restore selectively with `pg_restore --table=...` — handy when an operator only needs the `audit_log` table for a forensic copy without restoring the whole database. Run a real restore drill at least once before the pilot starts.

## Troubleshoot

`docker compose up` reports `POSTGRES_PASSWORD is required` — the overlay refuses to render without a password in `proxy.env`. Run `./generate-proxy-env.sh --db postgres` (which mints a strong random) or set `POSTGRES_PASSWORD=` manually.

`./deploy.sh --db postgres` reports `Orphan SQLite database found ... while MCP_PROXY_DATABASE_URL points at Postgres` — the bundle detected `./data/mcp_proxy.db` is non-empty and refuses to silently invalidate the agents enrolled against the old Org CA. Either roll back to SQLite (remove the Postgres URL from `proxy.env`), or pass `--accept-data-loss` after confirming you can re-enroll every agent.

Alembic upgrade hangs at "applying 0001_initial_snapshot" on a fresh Postgres — check `pg_locks` for entries with `locktype=advisory` and `objid` matching `0xC0115A1E_EB1C0DE`. A stuck worker holding the Mastio's Alembic advisory lock blocks every other worker from progressing. Kill the offending session and the others will retry the (idempotent) upgrade.
