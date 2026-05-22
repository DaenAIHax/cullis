"""Shared fixtures for the public Mastio test surface.

The public repo does not host the full Mastio test suite (that lives in
``cullis-enterprise/legacy/tests/`` per CLAUDE.md), but feature PRs that
touch ``mcp_proxy/`` ship targeted tests next to the change so the
public diff carries its own verification. This file provides the
minimal scaffolding (file-backed SQLite engine, migration skip via
``metadata.create_all``, audit chain singleton reset) shared by those
tests.
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
