"""Shared fixtures for the public Mastio test surface.

The public repo does not host the full Mastio test suite (that lives in
``cullis-enterprise/legacy/tests/`` per CLAUDE.md), but feature PRs that
touch ``mcp_proxy/`` ship targeted tests next to the change so the
public diff carries its own verification. This file provides the
minimal scaffolding (file-backed SQLite engine, migration skip via
``metadata.create_all``, audit chain singleton reset) shared by those
tests.

F0.2 — the same scaffolding is also exposed as a Postgres variant
(``audit_test_env_pg``) so the asyncpg binding is validated by the same
test bodies. Opt-in via ``CULLIS_TEST_PG_URL``; the lifecycle helpers
and marker registration live in ``test/conftest.py`` (root conftest),
and the ephemeral Postgres service is defined in ``test/compose-pg.yml``.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def audit_test_env(monkeypatch, tmp_path):
    """Initialise a fresh file-backed SQLite + audit chain for one test.

    Forces ``PROXY_SKIP_MIGRATIONS=1`` so the engine builds the schema
    from ``metadata.create_all`` (alembic chain not needed for the
    audit_log table verification — see ``db_models.AuditLogEntry`` which
    declares ``dpop_jkt`` / ``on_behalf_of_user_id`` / ``hash_format``
    so the metadata-built schema matches the production INSERT shape
    introduced by migrations 0031, 0033, 0034, 0042). Skipping alembic
    keeps the test suite cheap and removes the cross-env behaviour drift
    the old (inconsistent) docstring documented.

    The batched audit chain singleton is forced off so ``log_audit``
    writes synchronously into the same transaction the test inspects,
    instead of being queued behind a background flush task the test
    would have to wait on.
    """
    # File-backed sqlite so multiple connections inside the test see the
    # same data (the in-memory ``:memory:`` URL creates a per-connection
    # DB).
    db_path = tmp_path / "audit_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    # Skip the alembic upgrade chain — ``metadata.create_all`` now covers
    # every column ``log_audit`` references on INSERT (audit_log columns
    # added by migrations 0031/0033/0034/0042 are mirrored on
    # ``db_models.AuditLogEntry``). This makes the test deterministic
    # across local + CI and shaves the per-test cold-start time.
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    # Force the legacy per-row path so each log_audit call lands before
    # the assertion that follows it.
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    # Avoid the validate_config insecure-default refusal in dev.
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    # Reset the lru_cache so the new env vars take effect.
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    yield db_url
    get_settings.cache_clear()


@pytest.fixture
def audit_test_env_pg(monkeypatch, pg_url):
    """Postgres variant of ``audit_test_env`` for the asyncpg binding gate.

    Mirrors the SQLite fixture above but targets the live Postgres 16
    instance pointed at by ``CULLIS_TEST_PG_URL`` (skipped when unset; see
    ``test/conftest.py::pg_url``). The schema is recreated per test under
    a worker-scoped Postgres ``SCHEMA`` so pytest-xdist parallel workers
    cannot collide on the same ``audit_log`` table, and dropped on
    teardown so no state leaks between runs.

    Why ``PROXY_SKIP_MIGRATIONS=1`` here too: the audit-row shape pinned
    by ``test_audit_success_detail`` is fully expressed on
    ``db_models.AuditLogEntry`` (see the parent fixture docstring); the
    full 0001→head asyncpg chain walk lives in
    ``test/integration/test_alembic_full_chain_postgres.py`` so this
    happy-path fixture stays cheap.
    """
    import os
    import re
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    # ``PYTEST_XDIST_WORKER`` is injected by pytest-xdist; the serial
    # invocation defaults to ``master`` so the schema name is always
    # defined. Sanitised because Postgres identifiers reject hyphens
    # outside double quotes and we want to ``SET search_path`` cleanly.
    worker = os.environ.get("PYTEST_XDIST_WORKER", "master")
    schema = "test_" + re.sub(r"[^a-z0-9_]", "_", worker.lower())

    # Rewrite the URL so SQLAlchemy hands asyncpg a connection that lives
    # in the worker schema for the duration of the test.
    db_url = pg_url
    if "options=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}options=-csearch_path%3D{schema}"

    async def _reset_schema() -> None:
        admin = create_async_engine(pg_url, future=True, isolation_level="AUTOCOMMIT")
        try:
            async with admin.connect() as conn:
                await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
                await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        finally:
            await admin.dispose()

    # pytest-asyncio's loop isn't running yet at fixture-setup time, so
    # ``asyncio.run`` is correct here and keeps the fixture synchronous
    # (slot-compatible with the SQLite sibling above).
    import asyncio
    asyncio.run(_reset_schema())

    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        yield db_url
    finally:
        get_settings.cache_clear()
        # Drop the worker schema so the next test gets a clean slate even
        # if the previous one crashed mid-INSERT.
        async def _drop() -> None:
            admin = create_async_engine(pg_url, future=True, isolation_level="AUTOCOMMIT")
            try:
                async with admin.connect() as conn:
                    await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            finally:
                await admin.dispose()
        asyncio.run(_drop())
