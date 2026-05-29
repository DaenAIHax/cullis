"""Alembic 0019 + CRUD tests for the ``pending_updates`` table.

Uses a throwaway SQLite file per test so the Alembic upgrade chain
runs end-to-end (not just ``create_all``) — that way the migration is
exercised for real, including its idempotency branch. Matches the
``mgr`` fixture pattern in ``test_proxy_mastio_rotation_concurrency``.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import inspect

from mcp_proxy.db import (
    dispose_db,
    get_db,
    get_pending_updates,
    init_db,
    insert_pending_update,
    update_pending_update_status,
)


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    """Fresh proxy DB migrated through the full Alembic chain."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()


async def _inspect_table_exists(table: str) -> bool:
    async with get_db() as conn:
        names = await conn.run_sync(
            lambda sync_conn: set(inspect(sync_conn).get_table_names())
        )
    return table in names


async def _inspect_index_exists(index: str, table: str) -> bool:
    async with get_db() as conn:
        idx_names = await conn.run_sync(
            lambda sync_conn: {
                i["name"] for i in inspect(sync_conn).get_indexes(table)
            }
        )
    return index in idx_names


@pytest.mark.asyncio
async def test_alembic_upgrade_creates_table(fresh_db):
    assert await _inspect_table_exists("pending_updates")
    assert await _inspect_index_exists(
        "idx_pending_updates_status", "pending_updates",
    )


@pytest.mark.asyncio
async def test_insert_pending_update_idempotent(fresh_db):
    first = await insert_pending_update(
        migration_id="2099-01-01-idem",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    assert first == 1
    # Second call with same id is a no-op (ON CONFLICT / INSERT OR IGNORE)
    second = await insert_pending_update(
        migration_id="2099-01-01-idem",
        detected_at="2099-01-02T00:00:00+00:00",
    )
    assert second == 0
    # Row persisted exactly once with the *first* detected_at.
    rows = await get_pending_updates()
    assert len(rows) == 1
    assert rows[0]["detected_at"] == "2099-01-01T00:00:00+00:00"
    assert rows[0]["status"] == "pending"


@pytest.mark.asyncio
async def test_update_status_sets_applied_at(fresh_db):
    await insert_pending_update(
        migration_id="2099-01-01-apply",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    rowcount = await update_pending_update_status(
        migration_id="2099-01-01-apply",
        status="applied",
        applied_at="2099-01-01T01:00:00+00:00",
    )
    assert rowcount == 1

    rows = await get_pending_updates(status="applied")
    assert len(rows) == 1
    assert rows[0]["status"] == "applied"
    assert rows[0]["applied_at"] == "2099-01-01T01:00:00+00:00"
    assert rows[0]["error"] is None


@pytest.mark.asyncio
async def test_update_status_failed_records_error(fresh_db):
    await insert_pending_update(
        migration_id="2099-01-01-fail",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    rowcount = await update_pending_update_status(
        migration_id="2099-01-01-fail",
        status="failed",
        error="DB unreachable during up()",
    )
    assert rowcount == 1
    rows = await get_pending_updates(status="failed")
    assert len(rows) == 1
    assert rows[0]["error"] == "DB unreachable during up()"
    assert rows[0]["applied_at"] is None


@pytest.mark.asyncio
async def test_update_status_missing_row_returns_zero(fresh_db):
    rowcount = await update_pending_update_status(
        migration_id="2099-01-01-ghost",
        status="applied",
    )
    assert rowcount == 0


@pytest.mark.asyncio
async def test_get_pending_updates_sorted_by_id(fresh_db):
    await insert_pending_update(
        migration_id="2099-06-01-beta",
        detected_at="2099-06-01T00:00:00+00:00",
    )
    await insert_pending_update(
        migration_id="2099-01-01-alpha",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    await insert_pending_update(
        migration_id="2099-12-01-gamma",
        detected_at="2099-12-01T00:00:00+00:00",
    )

    rows = await get_pending_updates()
    assert [r["migration_id"] for r in rows] == [
        "2099-01-01-alpha",
        "2099-06-01-beta",
        "2099-12-01-gamma",
    ]


@pytest.mark.asyncio
async def test_insert_rejects_unknown_status(fresh_db):
    with pytest.raises(ValueError, match="status"):
        await insert_pending_update(
            migration_id="2099-01-01-bad",
            detected_at="2099-01-01T00:00:00+00:00",
            status="maybe",
        )


@pytest.mark.asyncio
async def test_update_rejects_unknown_status(fresh_db):
    await insert_pending_update(
        migration_id="2099-01-01-u",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="status"):
        await update_pending_update_status(
            migration_id="2099-01-01-u",
            status="done",
        )


@pytest.mark.asyncio
async def test_get_pending_updates_rejects_unknown_status_filter(fresh_db):
    with pytest.raises(ValueError, match="status"):
        await get_pending_updates(status="queued")


@pytest.mark.asyncio
async def test_get_pending_updates_filter_status_no_match(fresh_db):
    await insert_pending_update(
        migration_id="2099-01-01-nofilter",
        detected_at="2099-01-01T00:00:00+00:00",
    )
    rows = await get_pending_updates(status="applied")
    assert rows == []


def test_alembic_revision_metadata():
    """0019 chains to 0018 and its id stays within the Postgres limit.

    ``alembic_version.version_num`` is ``VARCHAR(32)`` on Postgres; a
    revision string longer than that ships a migration that CI smoke
    fails on import (see memory ``feedback_alembic_revision_length``).
    """
    import importlib
    mig = importlib.import_module(
        "mcp_proxy.alembic.versions.0019_pending_updates",
    )
    assert mig.revision == "0019_pending_updates"
    assert mig.down_revision == "0018_mastio_keys"
    assert len(mig.revision) <= 32
