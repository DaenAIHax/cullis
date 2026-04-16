"""
Seed an MCP proxy's SQLite config DB so it boots pre-configured.

Normally the setup wizard in the proxy dashboard writes these rows after
the admin pastes an invite token. For non-interactive smoke runs we just
insert them directly, using the org CA + secret that bootstrap.py already
generated on the shared /state volume.

ADR-007 Phase 1 PR #5b: this script now also applies the proxy's Alembic
migration chain before the legacy seed, so subsequent optional seeds
(MCP resources + bindings) can write into tables the proxy will load at
startup.

Env inputs:
  ORG_ID                   e.g. "demo-org-a"
  BROKER_URL               e.g. "https://broker.cullis.test:8443"
  PROXY_PUBLIC_URL         e.g. "https://proxy-a.cullis.test:8443"
  PROXY_DB_PATH            e.g. "/data/mcp_proxy.db"
  STATE_DIR                e.g. "/state"
  POLICY_RULES             optional JSON ruleset for the PDP webhook

  # ADR-007 Phase 1 optional seed:
  SEED_MCP_ECHO_RESOURCE       "1" to enable the mcp-echo resource seed
  SEED_MCP_ECHO_ENDPOINT       e.g. "http://mcp-echo:9200/"
  SEED_MCP_ECHO_BOUND_AGENT    agent_id to bind, e.g. "demo-org-a::sender"
  SEED_MCP_ECHO_NAME           optional, default "echo"
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone

import aiosqlite
from alembic import command
from alembic.config import Config as AlembicConfig

_ALEMBIC_INI = pathlib.Path("/app/mcp_proxy/alembic.ini")


def _run_alembic_upgrade(db_url: str) -> None:
    """Apply the full proxy migration chain so target tables exist."""
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")


async def _seed_proxy_config(db_path: str, org_id: str) -> None:
    broker_url = os.environ["BROKER_URL"]
    proxy_public = os.environ["PROXY_PUBLIC_URL"]
    state = pathlib.Path(os.environ.get("STATE_DIR", "/state"))
    org_dir = state / org_id
    ca_cert = (org_dir / "ca.pem").read_text()
    ca_key = (org_dir / "ca-key.pem").read_text()
    secret = (org_dir / "org_secret").read_text().strip()
    display = (org_dir / "display_name").read_text().strip()

    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        rows = {
            "broker_url":    broker_url,
            "org_id":        org_id,
            "org_secret":    secret,
            "org_ca_cert":   ca_cert,
            "org_ca_key":    ca_key,
            "display_name":  display,
            "contact_email": f"admin@{org_id}.test",
            "webhook_url":   f"{proxy_public}/pdp/policy",
            "org_status":    "active",
        }
        policy_rules = os.environ.get("POLICY_RULES", "").strip()
        if policy_rules:
            rows["policy_rules"] = policy_rules
        for k, v in rows.items():
            await db.execute(
                "INSERT INTO proxy_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, v),
            )
        await db.commit()
    print(f"proxy-init: seeded proxy_config for {org_id} (keys: {', '.join(rows.keys())})")


async def _seed_mcp_echo_resource(db_path: str, org_id: str) -> None:
    """Insert one local_mcp_resources row + one binding.

    ADR-007 Phase 1 PR #5b — lets the smoke sender exercise the
    aggregated /v1/mcp endpoint end-to-end against the mcp-echo
    container. ON CONFLICT preserves idempotency when proxy-init runs
    a second time (e.g. after `docker compose up` on a warm volume).
    """
    endpoint = os.environ["SEED_MCP_ECHO_ENDPOINT"]
    agent_id = os.environ["SEED_MCP_ECHO_BOUND_AGENT"]
    name = os.environ.get("SEED_MCP_ECHO_NAME", "echo")

    # WhitelistedTransport matches on request.url.host only (no port) —
    # the allowlist stores the compose DNS name of the mcp-echo service.
    allowed_domains_json = json.dumps(["mcp-echo"], separators=(",", ":"), sort_keys=True)
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """
            INSERT INTO local_mcp_resources (
                resource_id, org_id, name, description, endpoint_url,
                auth_type, auth_secret_ref, required_capability,
                allowed_domains, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'none', NULL, NULL, ?, 1, ?, ?)
            ON CONFLICT(org_id, name) DO UPDATE SET
                endpoint_url    = excluded.endpoint_url,
                allowed_domains = excluded.allowed_domains,
                enabled         = 1,
                updated_at      = excluded.updated_at
            """,
            (
                str(uuid.uuid4()), org_id, name,
                "ADR-007 Phase 1 smoke — mcp-echo fake server.",
                endpoint,
                allowed_domains_json,
                now, now,
            ),
        )
        # Re-read the canonical resource_id — ON CONFLICT leaves the
        # original row's id intact while the new uuid above is discarded.
        cursor = await db.execute(
            "SELECT resource_id FROM local_mcp_resources "
            "WHERE org_id = ? AND name = ?",
            (org_id, name),
        )
        row = await cursor.fetchone()
        if row is None:
            raise RuntimeError("seed: failed to locate the resource we just upserted")
        resource_id = row[0]

        await db.execute(
            """
            INSERT INTO local_agent_resource_bindings (
                binding_id, agent_id, resource_id, org_id,
                granted_by, granted_at, revoked_at
            ) VALUES (?, ?, ?, ?, 'proxy-init-seed', ?, NULL)
            ON CONFLICT(agent_id, resource_id) DO UPDATE SET
                revoked_at = NULL
            """,
            (str(uuid.uuid4()), agent_id, resource_id, org_id, now),
        )
        await db.commit()

    print(
        f"proxy-init: seeded MCP resource name={name} endpoint={endpoint} "
        f"bound_agent={agent_id}"
    )


async def _async_main(db_file: pathlib.Path, org_id: str) -> int:
    await _seed_proxy_config(str(db_file), org_id)
    if os.environ.get("SEED_MCP_ECHO_RESOURCE") == "1":
        await _seed_mcp_echo_resource(str(db_file), org_id)
    return 0


def main() -> int:
    org_id = os.environ["ORG_ID"]
    db_path = os.environ.get("PROXY_DB_PATH", "/data/mcp_proxy.db")

    db_file = pathlib.Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    # Run Alembic SYNCHRONOUSLY at module top — mcp_proxy/alembic/env.py
    # spins up its own asyncio.run() for the async engine migrations,
    # and Python forbids nested event loops. Do the migration chain
    # first, then fire up our own loop for the row seeds.
    db_url = f"sqlite+aiosqlite:///{db_path}"
    _run_alembic_upgrade(db_url)

    rc = asyncio.run(_async_main(db_file, org_id))

    db_file.chmod(0o666)
    return rc


if __name__ == "__main__":
    sys.exit(main())
