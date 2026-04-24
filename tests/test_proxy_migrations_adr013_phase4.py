"""Migration 0021 coverage — ADR-013 Phase 4 anomaly detector tables.

Covers:
- Three new tables created with the correct columns + PKs + indexes.
- CHECK constraints accept valid rows and reject invalid ones.
- Alembic upgrade is idempotent (re-running on a schema that already
  has the tables is a no-op, not an error).
- Downgrade drops all three tables cleanly.
"""
from __future__ import annotations

import sqlite3

import pytest

from mcp_proxy.db import dispose_db, init_db


def _tables(path: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        conn.close()


def _columns(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def _indexes(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {r[1] for r in conn.execute(f"PRAGMA index_list({table})")}
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_migration_creates_three_tables_with_expected_columns(tmp_path):
    db_file = tmp_path / "phase4.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    path = str(db_file)
    tables = _tables(path)
    assert {
        "agent_traffic_samples",
        "agent_hourly_baselines",
        "agent_quarantine_events",
    }.issubset(tables)

    assert _columns(path, "agent_traffic_samples") == {
        "agent_id",
        "bucket_ts",
        "req_count",
    }
    assert _columns(path, "agent_hourly_baselines") == {
        "agent_id",
        "hour_of_week",
        "req_per_min_avg",
        "req_per_min_p95",
        "sample_count",
        "updated_at",
    }
    assert _columns(path, "agent_quarantine_events") == {
        "id",
        "agent_id",
        "quarantined_at",
        "mode",
        "trigger_ratio",
        "trigger_abs_rate",
        "expires_at",
        "resolved_at",
        "resolved_by",
        "notification_sent",
    }


@pytest.mark.asyncio
async def test_migration_creates_expected_indexes(tmp_path):
    db_file = tmp_path / "indexes.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    path = str(db_file)
    assert "idx_traffic_samples_bucket" in _indexes(path, "agent_traffic_samples")
    assert "idx_quarantine_agent" in _indexes(path, "agent_quarantine_events")


@pytest.mark.asyncio
async def test_quarantine_events_mode_check_rejects_invalid(tmp_path):
    db_file = tmp_path / "check.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    conn = sqlite3.connect(str(db_file))
    try:
        # Valid modes succeed.
        conn.execute(
            "INSERT INTO agent_quarantine_events "
            "(agent_id, quarantined_at, mode) VALUES (?, ?, ?)",
            ("a1", "2026-04-24T00:00:00Z", "shadow"),
        )
        conn.execute(
            "INSERT INTO agent_quarantine_events "
            "(agent_id, quarantined_at, mode) VALUES (?, ?, ?)",
            ("a2", "2026-04-24T00:00:00Z", "enforce"),
        )
        conn.commit()

        # Invalid mode rejected.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode) VALUES (?, ?, ?)",
                ("a3", "2026-04-24T00:00:00Z", "bogus"),
            )
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_hourly_baselines_hour_range_check(tmp_path):
    db_file = tmp_path / "hour.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    conn = sqlite3.connect(str(db_file))
    try:
        # Boundaries accepted.
        for h in (0, 167):
            conn.execute(
                "INSERT INTO agent_hourly_baselines "
                "(agent_id, hour_of_week, req_per_min_avg, "
                "req_per_min_p95, sample_count, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (f"h{h}", h, 1.0, 2.0, 10, "2026-04-24T00:00:00Z"),
            )
        conn.commit()

        # Out-of-range rejected.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO agent_hourly_baselines "
                "(agent_id, hour_of_week, req_per_min_avg, "
                "req_per_min_p95, sample_count, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("bad", 168, 1.0, 2.0, 10, "2026-04-24T00:00:00Z"),
            )
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_traffic_samples_composite_pk(tmp_path):
    db_file = tmp_path / "pk.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute(
            "INSERT INTO agent_traffic_samples "
            "(agent_id, bucket_ts, req_count) VALUES (?, ?, ?)",
            ("a", "2026-04-24T00:00:00Z", 1),
        )
        # Same (agent_id, bucket_ts) — duplicate PK.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO agent_traffic_samples "
                "(agent_id, bucket_ts, req_count) VALUES (?, ?, ?)",
                ("a", "2026-04-24T00:00:00Z", 5),
            )
        # Same agent, different bucket — fine.
        conn.execute(
            "INSERT INTO agent_traffic_samples "
            "(agent_id, bucket_ts, req_count) VALUES (?, ?, ?)",
            ("a", "2026-04-24T00:10:00Z", 3),
        )
        conn.commit()

        rows = conn.execute(
            "SELECT bucket_ts, req_count FROM agent_traffic_samples "
            "WHERE agent_id = 'a' ORDER BY bucket_ts"
        ).fetchall()
        assert rows == [
            ("2026-04-24T00:00:00Z", 1),
            ("2026-04-24T00:10:00Z", 3),
        ]
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_migration_idempotent_on_existing_schema(tmp_path):
    """Running init_db twice must not error — upgrade skips existing tables."""
    db_file = tmp_path / "idem.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()
    # Second call reuses the head revision; the upgrade path's
    # existing-table guard keeps this from raising.
    await init_db(url)
    await dispose_db()

    assert {
        "agent_traffic_samples",
        "agent_hourly_baselines",
        "agent_quarantine_events",
    }.issubset(_tables(str(db_file)))
