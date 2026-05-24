"""Unit tests for ``mcp_proxy.lifespan.merkle_anchor_watcher``.

The watcher's interesting properties are around batch boundary
math: which chain_seq range gets emitted, when the loop defers
for under-sized batches, idempotency on restart. We exercise
``_tick`` directly with an ephemeral SQLite DB so the assertions
are end-to-end against the real persistence layer (init_db +
get_db) without touching the lifespan / leader_election layers,
which are mirrored from audit_anchor_watcher and already covered
upstream.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.audit.merkle import compute_merkle_root, verify_inclusion
from mcp_proxy.audit.merkle import inclusion_proof
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.lifespan import merkle_anchor_watcher as mw


@pytest_asyncio.fixture
async def proxy_db(tmp_path):
    db_path = tmp_path / "merkle_watcher.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()


async def _seed_audit_log(rows: list[tuple[int, str]]) -> None:
    """Bypass the F-A-402 hash-chain trigger for test convenience:
    insert rows with pre-computed chain_seq + row_hash so the
    watcher has a deterministic chain to walk. The trigger only
    forbids UPDATE/DELETE, not INSERT, so this is allowed."""
    async with get_db() as conn:
        for chain_seq, row_hash in rows:
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(timestamp, agent_id, action, status, chain_seq, "
                    " row_hash, prev_hash) "
                    "VALUES ('2026-05-24T00:00:00Z', 'test::agent', "
                    "'test_action', 'ok', :chain_seq, :row_hash, '')"
                ),
                {"chain_seq": chain_seq, "row_hash": row_hash},
            )


def _hex_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _seed_payloads(start: int, count: int) -> list[tuple[int, str]]:
    return [
        (start + i, _hex_hash(f"row-{start + i}".encode()))
        for i in range(count)
    ]


# ── Tick behaviour ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_defers_when_chain_empty(proxy_db):
    """Empty audit_log → no rows to batch → no anchor written."""
    await mw._tick(
        org_id="acme",
        batch_size=4,
        min_batch=2,
        tsa_enabled=False,
        tsa_url="http://unused",
        tsa_timeout=1.0,
    )
    async with get_db() as conn:
        count = (await conn.execute(text(
            "SELECT COUNT(*) FROM audit_merkle_anchors"
        ))).scalar()
    assert count == 0


@pytest.mark.asyncio
async def test_tick_defers_under_min_batch(proxy_db):
    """Only 3 rows present but min_batch=5 → defer, no anchor row."""
    await _seed_audit_log(_seed_payloads(start=1, count=3))
    await mw._tick(
        org_id="acme",
        batch_size=8,
        min_batch=5,
        tsa_enabled=False,
        tsa_url="http://unused",
        tsa_timeout=1.0,
    )
    async with get_db() as conn:
        count = (await conn.execute(text(
            "SELECT COUNT(*) FROM audit_merkle_anchors"
        ))).scalar()
    assert count == 0


@pytest.mark.asyncio
async def test_tick_emits_anchor_when_min_reached(proxy_db):
    """Min satisfied → one anchor row, root matches independent
    computation, range is [1, count]."""
    rows = _seed_payloads(start=1, count=8)
    await _seed_audit_log(rows)

    await mw._tick(
        org_id="acme",
        batch_size=8,
        min_batch=4,
        tsa_enabled=False,
        tsa_url="http://unused",
        tsa_timeout=1.0,
    )

    async with get_db() as conn:
        anchors = (await conn.execute(text(
            "SELECT chain_seq_start, chain_seq_end, leaf_count, "
            "       merkle_root, tsa_token "
            "FROM audit_merkle_anchors"
        ))).all()
    assert len(anchors) == 1
    start, end, count, root_hex, tsa_token = anchors[0]
    assert start == 1
    assert end == 8
    assert count == 8
    assert tsa_token is None  # TSA disabled
    expected_root = compute_merkle_root(
        [bytes.fromhex(rh) for _, rh in rows]
    ).hex()
    assert root_hex == expected_root


@pytest.mark.asyncio
async def test_tick_caps_at_batch_size(proxy_db):
    """100 rows available, batch_size=4 → first anchor covers
    [1, 4] only, leaves the remaining 96 for subsequent ticks."""
    rows = _seed_payloads(start=1, count=100)
    await _seed_audit_log(rows)

    await mw._tick(
        org_id="acme",
        batch_size=4,
        min_batch=2,
        tsa_enabled=False,
        tsa_url="http://unused",
        tsa_timeout=1.0,
    )

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT chain_seq_start, chain_seq_end, leaf_count "
            "FROM audit_merkle_anchors ORDER BY id ASC LIMIT 1"
        ))).first()
    assert row == (1, 4, 4)


@pytest.mark.asyncio
async def test_consecutive_ticks_advance_contiguously(proxy_db):
    """Three ticks against a 12-row chain with batch_size=4 produce
    three anchors at [1,4], [5,8], [9,12]. No gaps, no overlaps."""
    rows = _seed_payloads(start=1, count=12)
    await _seed_audit_log(rows)

    for _ in range(3):
        await mw._tick(
            org_id="acme",
            batch_size=4,
            min_batch=2,
            tsa_enabled=False,
            tsa_url="http://unused",
            tsa_timeout=1.0,
        )

    async with get_db() as conn:
        anchors = (await conn.execute(text(
            "SELECT chain_seq_start, chain_seq_end "
            "FROM audit_merkle_anchors ORDER BY id ASC"
        ))).all()
    assert anchors == [(1, 4), (5, 8), (9, 12)]


@pytest.mark.asyncio
async def test_tick_resumes_after_partial_chain_growth(proxy_db):
    """First tick anchors [1, 4]. New rows arrive. Second tick
    picks up at chain_seq=5 without re-anchoring [1, 4]."""
    await _seed_audit_log(_seed_payloads(start=1, count=4))
    await mw._tick(
        org_id="acme", batch_size=4, min_batch=2,
        tsa_enabled=False, tsa_url="http://unused", tsa_timeout=1.0,
    )

    await _seed_audit_log(_seed_payloads(start=5, count=4))
    await mw._tick(
        org_id="acme", batch_size=4, min_batch=2,
        tsa_enabled=False, tsa_url="http://unused", tsa_timeout=1.0,
    )

    async with get_db() as conn:
        anchors = (await conn.execute(text(
            "SELECT chain_seq_start, chain_seq_end "
            "FROM audit_merkle_anchors ORDER BY id ASC"
        ))).all()
    assert anchors == [(1, 4), (5, 8)]


@pytest.mark.asyncio
async def test_tick_handles_tsa_failure_persists_anchor(
    proxy_db, monkeypatch,
):
    """TSA call fails → the Merkle anchor row is still written
    (tsa_token NULL); next tick will retry on the next batch.
    The local chain math is sound without the TSA."""
    rows = _seed_payloads(start=1, count=4)
    await _seed_audit_log(rows)

    def _boom(*_args, **_kwargs):
        from mcp_proxy.audit.tsa_client import TSAAnchorError
        raise TSAAnchorError("TSA unreachable")
    monkeypatch.setattr(mw, "anchor_row_hash", _boom)

    await mw._tick(
        org_id="acme", batch_size=4, min_batch=2,
        tsa_enabled=True, tsa_url="http://no-such-tsa",
        tsa_timeout=1.0,
    )

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT leaf_count, tsa_token "
            "FROM audit_merkle_anchors"
        ))).first()
    assert row[0] == 4
    assert row[1] is None  # No token persisted on TSA failure.


@pytest.mark.asyncio
async def test_anchored_root_admits_inclusion_proof_for_every_leaf(
    proxy_db,
):
    """End-to-end check that the anchored root is the same root the
    Phase 0 math would produce, by exercising the inclusion proof
    path for every leaf in the batch."""
    rows = _seed_payloads(start=1, count=8)
    await _seed_audit_log(rows)
    await mw._tick(
        org_id="acme", batch_size=8, min_batch=4,
        tsa_enabled=False, tsa_url="http://unused", tsa_timeout=1.0,
    )

    async with get_db() as conn:
        root_hex = (await conn.execute(text(
            "SELECT merkle_root FROM audit_merkle_anchors"
        ))).scalar()

    leaves = [bytes.fromhex(rh) for _, rh in rows]
    root = bytes.fromhex(root_hex)
    for i, leaf in enumerate(leaves):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(leaf, proof, root), (
            f"inclusion failed for leaf {i}"
        )


# ── _last_anchored_seq helper ───────────────────────────────────────


@pytest.mark.asyncio
async def test_last_anchored_seq_empty_returns_zero(proxy_db):
    assert await mw._last_anchored_seq() == 0


@pytest.mark.asyncio
async def test_last_anchored_seq_returns_latest_end(proxy_db):
    """When multiple anchors exist, the helper returns the highest
    chain_seq_end so the next batch starts at end + 1."""
    rows = _seed_payloads(start=1, count=12)
    await _seed_audit_log(rows)
    for _ in range(3):
        await mw._tick(
            org_id="acme", batch_size=4, min_batch=2,
            tsa_enabled=False, tsa_url="http://unused", tsa_timeout=1.0,
        )
    assert await mw._last_anchored_seq() == 12
