"""F-A-403 parity for the batched audit chain (audit 2026-06-02).

The batched flush is the *default* production write path
(``audit_chain_batch_size=100``, ``audit_chain_disabled=False``). A
regression had it call ``compute_audit_row_hash`` in the v1 form — no
``hash_format``, no ``dpop_jkt``, no ``on_behalf_of_user_id`` — and the
INSERT omitted the ``on_behalf_of_user_id`` / ``hash_format`` columns
entirely. Result: every row written under the default prod path stored
``hash_format=NULL`` and left the ADR-014 DPoP binding and ADR-032 OBO
attribution OUT of the row hash, silently reopening F-A-403 (which the
legacy per-row path closes).

These tests exercise ``BatchedAuditChain`` directly (it had zero unit
coverage) and assert that a batched row binds both fields under the v2
canonical, exactly like the legacy ``log_audit`` path. Pre-fix they fail
(stored hash is v1, columns NULL, tampering dpop_jkt/obo leaves the hash
unchanged); post-fix they pass.
"""

import pytest

from mcp_proxy import db as _db
from mcp_proxy.audit_chain import BatchedAuditChain
from mcp_proxy.db import (
    compute_audit_row_hash,
    dispose_db,
    get_db,
    init_db,
    verify_audit_chain,
)
from sqlalchemy import text


_TS = "2026-06-02T12:00:00+00:00"
_AGENT = "acme::dora"
_JKT = "kid-dpop-thumbprint-abc123"
_OBO = "user-principal-7f3a"


@pytest.mark.asyncio
async def test_batched_row_binds_dpop_jkt_and_obo_under_v2(tmp_path):
    """A row written through BatchedAuditChain must persist
    ``hash_format='v2'`` + populated ``dpop_jkt`` / ``on_behalf_of_user_id``
    columns, the chain must verify, and the stored row_hash must be the
    v2 hash that binds both fields (so changing either is tamper-evident)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'batched_v2.sqlite'}"
    await init_db(url)
    try:
        chain = BatchedAuditChain(batch_size=10, flush_interval_s=60.0)
        await chain.append({
            "timestamp": _TS,
            "agent_id": _AGENT,
            "action": "egress_llm_chat",
            "tool_name": None,
            "status": "ok",
            "detail": None,
            "request_id": "req-1",
            "duration_ms": 12,
            "dpop_jkt": _JKT,
            "on_behalf_of_user_id": _OBO,
        })
        written = await chain.flush_now(propagate=True)
        assert written == 1

        async with get_db() as conn:
            row = (await conn.execute(text(
                "SELECT chain_seq, prev_hash, row_hash, dpop_jkt, "
                "on_behalf_of_user_id, hash_format FROM audit_log "
                "WHERE chain_seq = 1"
            ))).first()
        assert row is not None
        chain_seq, prev_hash, stored_hash, dpop_jkt, obo, hash_format = row

        # Columns actually persisted (pre-fix: obo + hash_format were NULL).
        assert hash_format == "v2", "batched row must be tagged v2"
        assert dpop_jkt == _JKT
        assert obo == _OBO

        # Chain verifies end-to-end through the real verifier.
        ok, broken_seq, reason = await verify_audit_chain()
        assert ok, f"chain broke at seq={broken_seq}: {reason}"

        # The stored hash is the v2 hash binding both fields.
        expected = compute_audit_row_hash(
            chain_seq=int(chain_seq),
            timestamp=_TS,
            agent_id=_AGENT,
            action="egress_llm_chat",
            tool_name=None,
            status="ok",
            detail=None,
            request_id="req-1",
            prev_hash=str(prev_hash),
            dpop_jkt=_JKT,
            on_behalf_of_user_id=_OBO,
            hash_format="v2",
        )
        assert stored_hash == expected

        # Tamper-evidence: flipping either bound field changes the hash,
        # so an attacker who rewrites the column cannot keep the row_hash.
        tampered_jkt = compute_audit_row_hash(
            chain_seq=int(chain_seq), timestamp=_TS, agent_id=_AGENT,
            action="egress_llm_chat", tool_name=None, status="ok",
            detail=None, request_id="req-1", prev_hash=str(prev_hash),
            dpop_jkt="attacker-jkt", on_behalf_of_user_id=_OBO,
            hash_format="v2",
        )
        assert stored_hash != tampered_jkt, "dpop_jkt must be bound to the hash"

        tampered_obo = compute_audit_row_hash(
            chain_seq=int(chain_seq), timestamp=_TS, agent_id=_AGENT,
            action="egress_llm_chat", tool_name=None, status="ok",
            detail=None, request_id="req-1", prev_hash=str(prev_hash),
            dpop_jkt=_JKT, on_behalf_of_user_id="victim-user",
            hash_format="v2",
        )
        assert stored_hash != tampered_obo, "obo must be bound to the hash"
    finally:
        await dispose_db()


@pytest.mark.asyncio
async def test_batched_and_legacy_paths_produce_identical_row_hash(tmp_path):
    """Parity guard: the batched flush and the legacy per-row path must
    produce the SAME row_hash for identical input. Pre-fix the batched
    path wrote v1 while the legacy path wrote v2, so the hashes diverged
    on any row carrying dpop_jkt/obo."""
    # Legacy per-row path: the batched singleton is NOT registered in
    # unit tests, so log_audit() takes the legacy branch (db.py:670+),
    # which writes v2. We pass dpop_jkt/obo explicitly as kwargs.
    legacy_url = f"sqlite+aiosqlite:///{tmp_path / 'legacy.sqlite'}"
    await init_db(legacy_url)
    try:
        await _db.log_audit(
            agent_id=_AGENT,
            action="egress_llm_chat",
            status="ok",
            request_id="req-1",
            dpop_jkt=_JKT,
            on_behalf_of_user_id=_OBO,
        )
        async with get_db() as conn:
            legacy = (await conn.execute(text(
                "SELECT timestamp, prev_hash, row_hash FROM audit_log "
                "WHERE chain_seq = 1"
            ))).first()
        legacy_ts, legacy_prev, legacy_hash = legacy
    finally:
        await dispose_db()

    # Batched path: same identity inputs, reuse the legacy timestamp +
    # prev_hash (both chains start from genesis at chain_seq=1) so the
    # only variable left is the canonical/format the path chose.
    batched_url = f"sqlite+aiosqlite:///{tmp_path / 'batched.sqlite'}"
    await init_db(batched_url)
    try:
        chain = BatchedAuditChain(batch_size=10, flush_interval_s=60.0)
        await chain.append({
            "timestamp": legacy_ts,
            "agent_id": _AGENT,
            "action": "egress_llm_chat",
            "tool_name": None,
            "status": "ok",
            "detail": None,
            "request_id": "req-1",
            "duration_ms": None,
            "dpop_jkt": _JKT,
            "on_behalf_of_user_id": _OBO,
        })
        await chain.flush_now(propagate=True)
        async with get_db() as conn:
            batched = (await conn.execute(text(
                "SELECT prev_hash, row_hash FROM audit_log WHERE chain_seq = 1"
            ))).first()
        batched_prev, batched_hash = batched
    finally:
        await dispose_db()

    assert batched_prev == legacy_prev  # both start from genesis
    assert batched_hash == legacy_hash, (
        "batched and legacy paths must hash identically; a mismatch means "
        "the batched flush is using a different canonical (the F-A-403 "
        "regression)."
    )
