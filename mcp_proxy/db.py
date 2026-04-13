"""
MCP Proxy database — async SQLAlchemy 2.x Core over aiosqlite / asyncpg.

Tables:
  - internal_agents: locally registered agents (for egress API key auth)
  - audit_log: append-only immutable audit trail
  - proxy_config: key-value store for broker uplink config from setup wizard

Design choices:
  - SQLAlchemy Core with AsyncEngine — single async driver, portable SQLite/Postgres
  - audit_log is append-only: no UPDATE or DELETE operations exposed
  - WAL mode enabled on SQLite for concurrent readers (no-op on Postgres)
  - get_db() yields an AsyncConnection already inside engine.begin(): callers no
    longer call db.commit(), transactions commit on context exit.
"""
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from mcp_proxy.db_models import metadata

_log = logging.getLogger("mcp_proxy")

# Module-level engine — set by init_db()
_engine: AsyncEngine | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_url(db_url: str) -> str:
    """Accept a SQLAlchemy URL or a raw SQLite path; return a SQLAlchemy URL."""
    if "://" in db_url:
        return db_url
    # Raw filesystem path — wrap as sqlite+aiosqlite
    return f"sqlite+aiosqlite:///{db_url}"


def _sqlite_path(db_url: str) -> str | None:
    """Extract the filesystem path from a sqlite URL, or None if not SQLite."""
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if db_url.startswith(prefix):
            return db_url[len(prefix):]
    return None


async def init_db(db_url: str) -> None:
    """Initialize the module-level AsyncEngine and ensure schema exists.

    Accepts either a SQLAlchemy URL (``sqlite+aiosqlite:///path``) or a raw
    filesystem path for backward compatibility.

    Schema bootstrap still uses ``metadata.create_all`` — callers that want
    Alembic-managed upgrades should run ``alembic upgrade head`` out of band.
    """
    global _engine

    url = _normalize_url(db_url)

    # Ensure parent directory exists for SQLite file DBs
    sqlite_path = _sqlite_path(url)
    if sqlite_path:
        parent = Path(sqlite_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)

    _engine = create_async_engine(url, echo=False, future=True)

    async with _engine.begin() as conn:
        if _engine.dialect.name == "sqlite":
            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(metadata.create_all)

    _log.info("Database initialized: %s", url)


async def dispose_db() -> None:
    """Dispose the module-level engine (shutdown hook)."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


def _require_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _engine


@asynccontextmanager
async def get_db() -> AsyncIterator[AsyncConnection]:
    """Yield an AsyncConnection inside an active transaction.

    The transaction auto-commits when the context exits cleanly and rolls
    back on exception. Callers MUST NOT call ``await conn.commit()``.

    Usage::

        async with get_db() as conn:
            result = await conn.execute(text("SELECT ..."), {"param": value})
            row = result.mappings().first()
    """
    engine = _require_engine()
    async with engine.begin() as conn:
        yield conn


# ─────────────────────────────────────────────────────────────────────────────
# Audit log — APPEND-ONLY (no update, no delete)
# ─────────────────────────────────────────────────────────────────────────────

async def log_audit(
    agent_id: str,
    action: str,
    status: str,
    *,
    tool_name: str | None = None,
    detail: str | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None,
) -> None:
    """Insert an immutable audit log entry."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO audit_log (timestamp, agent_id, action, tool_name, status, detail, request_id, duration_ms)
                   VALUES (:timestamp, :agent_id, :action, :tool_name, :status, :detail, :request_id, :duration_ms)"""
            ),
            {
                "timestamp": ts,
                "agent_id": agent_id,
                "action": action,
                "tool_name": tool_name,
                "status": status,
                "detail": detail,
                "request_id": request_id,
                "duration_ms": duration_ms,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Internal agents
# ─────────────────────────────────────────────────────────────────────────────

async def create_agent(
    agent_id: str,
    display_name: str,
    capabilities: list[str],
    api_key_hash: str,
    cert_pem: str | None = None,
) -> None:
    """Register a new internal agent."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO internal_agents (agent_id, display_name, capabilities, api_key_hash, cert_pem, created_at)
                   VALUES (:agent_id, :display_name, :capabilities, :api_key_hash, :cert_pem, :created_at)"""
            ),
            {
                "agent_id": agent_id,
                "display_name": display_name,
                "capabilities": json.dumps(capabilities),
                "api_key_hash": api_key_hash,
                "cert_pem": cert_pem,
                "created_at": ts,
            },
        )


async def get_agent(agent_id: str) -> dict | None:
    """Fetch a single agent by ID."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return _agent_row_to_dict(row)


async def get_agent_by_key_hash(raw_api_key: str) -> dict | None:
    """Look up an active agent by verifying a raw API key against stored bcrypt hashes.

    Since bcrypt hashes are non-deterministic (salted), we cannot do a direct
    SQL lookup. Instead we fetch all active agents and verify against each hash.
    For efficiency with many agents, consider a prefix index approach.
    This is acceptable for the expected scale (tens to low hundreds of agents).
    """
    import bcrypt

    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents WHERE is_active = 1")
        )
        rows = result.mappings().all()
        for row in rows:
            stored_hash = row["api_key_hash"]
            if bcrypt.checkpw(raw_api_key.encode(), stored_hash.encode()):
                return _agent_row_to_dict(row)
    return None


async def list_agents() -> list[dict]:
    """List all internal agents."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT * FROM internal_agents ORDER BY created_at DESC")
        )
        return [_agent_row_to_dict(row) for row in result.mappings().all()]


async def deactivate_agent(agent_id: str) -> bool:
    """Soft-delete an agent by setting is_active = 0. Returns True if found."""
    async with get_db() as conn:
        result = await conn.execute(
            text("UPDATE internal_agents SET is_active = 0 WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        return result.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Proxy config (key-value)
# ─────────────────────────────────────────────────────────────────────────────

async def get_config(key: str) -> str | None:
    """Get a config value by key."""
    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT value FROM proxy_config WHERE key = :key"),
            {"key": key},
        )
        row = result.mappings().first()
        return row["value"] if row else None


async def set_config(key: str, value: str) -> None:
    """Set a config value (upsert).

    SQLite and PostgreSQL both support ON CONFLICT ... DO UPDATE with the
    same syntax, so a raw text() upsert stays portable.
    """
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO proxy_config (key, value) VALUES (:key, :value)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value"""
            ),
            {"key": key, "value": value},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _agent_row_to_dict(row: RowMapping) -> dict:
    """Convert a RowMapping to a plain dict with parsed capabilities."""
    return {
        "agent_id": row["agent_id"],
        "display_name": row["display_name"],
        "capabilities": json.loads(row["capabilities"]),
        "api_key_hash": row["api_key_hash"],
        "cert_pem": row["cert_pem"],
        "created_at": row["created_at"],
        "is_active": bool(row["is_active"]),
    }
