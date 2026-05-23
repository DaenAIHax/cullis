"""Tests for the audit chain TSA anchor watcher.

The watcher is two parts:

  * ``_tick`` — orchestration: read chain head, skip if already
    anchored, call TSA, persist. The TSA call is the I/O boundary;
    these tests monkey-patch ``anchor_row_hash`` (the synchronous
    TSA client) so they don't need network.

  * ``audit_anchor_watcher_loop`` — the long-running loop with
    early-exit on stop_event. Tested separately to verify SIGTERM
    teardown wakes within tick_seconds.

The DB layer reuses the existing ``audit_test_env`` fixture from the
unit conftest — file-backed SQLite under
``PROXY_SKIP_MIGRATIONS=1`` + ``metadata.create_all`` which now
includes ``audit_chain_anchors`` (the table is declared on
``db_models.AuditChainAnchor``).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import text


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def db_with_chain(audit_test_env):
    """Yield a connection to a fresh test DB with two audit_log rows.

    The watcher reads the chain head from audit_log; the fixture
    seeds two rows so the head is well-defined.
    """
    from mcp_proxy.db import get_db, init_db
    await init_db(audit_test_env)
    async with get_db() as conn:
        for seq, agent, h in [
            (1, "orga::a", "hash-aaaaaaaaaaaaaaaaaaa1"),
            (2, "orga::b", "hash-bbbbbbbbbbbbbbbbbbb2"),
        ]:
            await conn.execute(text(
                "INSERT INTO audit_log "
                "(timestamp, agent_id, action, status, chain_seq, "
                " prev_hash, row_hash, hash_format) "
                "VALUES (:ts, :a, :act, :s, :seq, :ph, :rh, :hf)"
            ), {
                "ts": datetime.now(timezone.utc).isoformat(),
                "a": agent, "act": "test", "s": "ok",
                "seq": seq,
                "ph": "genesis" if seq == 1 else "hash-aaaaaaaaaaaaaaaaaaa1",
                "rh": h,
                "hf": "v2",
            })
    yield audit_test_env


# ── _tick ────────────────────────────────────────────────────────────────


async def test_tick_anchors_latest_chain_head(monkeypatch, db_with_chain):
    """The watcher reads chain_seq=2 and persists one anchor row."""
    from mcp_proxy.lifespan import audit_anchor_watcher as watcher
    from mcp_proxy.audit.tsa_client import AnchorResult

    captured: dict = {}

    def _fake_anchor(row_hash, *, tsa_url, timeout_seconds):
        captured["row_hash"] = row_hash
        captured["tsa_url"] = tsa_url
        return AnchorResult(
            digest_hex="aa" * 32,
            tsa_url=tsa_url,
            token_bytes=b"T1|" + b"FAKE-TOKEN-BYTES-NOT-A-REAL-TST",
        )

    monkeypatch.setattr(watcher, "anchor_row_hash", _fake_anchor)

    await watcher._tick(
        tsa_url="http://tsa.example/timestamp",
        org_id="orga",
        tsa_timeout=5.0,
    )

    assert captured["row_hash"] == "hash-bbbbbbbbbbbbbbbbbbb2"
    assert captured["tsa_url"] == "http://tsa.example/timestamp"

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(text(
            "SELECT chain_seq, row_hash, tsa_url, tsa_token "
            "FROM audit_chain_anchors ORDER BY id"
        ))).all()
    assert len(rows) == 1
    seq, rh, tsa, tok = rows[0]
    assert int(seq) == 2
    assert rh == "hash-bbbbbbbbbbbbbbbbbbb2"
    assert tsa == "http://tsa.example/timestamp"
    assert bytes(tok).startswith(b"T1|")


async def test_tick_skips_when_already_anchored(monkeypatch, db_with_chain):
    """Second tick with no new chain entries → no new anchor row."""
    from mcp_proxy.lifespan import audit_anchor_watcher as watcher
    from mcp_proxy.audit.tsa_client import AnchorResult

    call_count = {"n": 0}

    def _fake_anchor(row_hash, *, tsa_url, timeout_seconds):
        call_count["n"] += 1
        return AnchorResult(
            digest_hex="aa" * 32, tsa_url=tsa_url,
            token_bytes=b"T1|FAKE",
        )

    monkeypatch.setattr(watcher, "anchor_row_hash", _fake_anchor)

    # First tick — anchors chain_seq=2.
    await watcher._tick(
        tsa_url="http://tsa.example/timestamp",
        org_id="orga", tsa_timeout=5.0,
    )
    # Second tick — head still chain_seq=2 → skip.
    await watcher._tick(
        tsa_url="http://tsa.example/timestamp",
        org_id="orga", tsa_timeout=5.0,
    )
    assert call_count["n"] == 1, (
        f"second tick should not call TSA, got {call_count['n']} calls"
    )


async def test_tick_tsa_failure_does_not_persist(monkeypatch, db_with_chain):
    """TSA call raises → no anchor row written, loop continues."""
    from mcp_proxy.lifespan import audit_anchor_watcher as watcher
    from mcp_proxy.audit.tsa_client import TSAAnchorError

    def _raise(*_args, **_kwargs):
        raise TSAAnchorError("simulated TSA outage")

    monkeypatch.setattr(watcher, "anchor_row_hash", _raise)

    await watcher._tick(
        tsa_url="http://tsa.example/timestamp",
        org_id="orga", tsa_timeout=5.0,
    )

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        count = (await conn.execute(text(
            "SELECT COUNT(*) FROM audit_chain_anchors"
        ))).scalar()
    assert count == 0, "TSA failure must not leave a half-anchor"


async def test_tick_empty_chain_no_op(monkeypatch, audit_test_env):
    """No chain entries yet → watcher silent, no anchor row."""
    from mcp_proxy.db import get_db, init_db
    from mcp_proxy.lifespan import audit_anchor_watcher as watcher

    await init_db(audit_test_env)

    # Patch TSA client to ensure it's not called when chain is empty.
    monkeypatch.setattr(
        watcher, "anchor_row_hash",
        lambda *a, **kw: pytest.fail(
            "TSA should not be called on empty chain"
        ),
    )

    await watcher._tick(
        tsa_url="http://tsa.example/timestamp",
        org_id="orga", tsa_timeout=5.0,
    )

    async with get_db() as conn:
        count = (await conn.execute(text(
            "SELECT COUNT(*) FROM audit_chain_anchors"
        ))).scalar()
    assert count == 0


# ── loop termination ─────────────────────────────────────────────────────


async def test_loop_exits_on_stop_event(monkeypatch, audit_test_env):
    """SIGTERM-style ``stop_event.set()`` wakes the loop before tick."""
    from mcp_proxy.db import init_db
    from mcp_proxy.lifespan import audit_anchor_watcher as watcher

    await init_db(audit_test_env)

    # Make the TSA client a no-op so the first tick completes quickly.
    monkeypatch.setattr(
        watcher, "anchor_row_hash",
        MagicMock(side_effect=lambda *a, **kw: pytest.fail(
            "no chain head to anchor in this fixture"
        )),
    )

    stop = asyncio.Event()

    # Long tick (would block 60s without early-exit on stop_event).
    loop_task = asyncio.create_task(
        watcher.audit_anchor_watcher_loop(
            org_id="orga",
            stop_event=stop,
            tsa_url="http://tsa.example/timestamp",
            tick_seconds=60,
        ),
    )

    # Yield once so the loop enters wait_for, then signal stop.
    await asyncio.sleep(0.05)
    stop.set()

    # Loop must terminate within a couple of asyncio iterations after stop.
    await asyncio.wait_for(loop_task, timeout=5.0)
    assert loop_task.done()
