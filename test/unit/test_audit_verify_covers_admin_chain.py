"""C1 (public security audit 2026-06-02) — the dashboard "Verify chain
integrity" button must cover BOTH audit chains, not just ``local_audit``.

The Mastio keeps two independent append-only hash chains:

  * ``audit_log`` — the *admin* stream: ``auth.*``, ``enroll.*``,
    ``agent.cert.rotate``, ``policy.*`` (schema ``action`` / ``row_hash``
    / ``prev_hash``). The highest-value security events.
  * ``local_audit`` — the *traffic* stream: oneshot, MCP tool execute,
    session send (schema ``event_type`` / ``entry_hash`` /
    ``previous_hash``).

Before the fix, ``POST /proxy/audit/verify`` only walked
``local_audit``. An operator who tampered an ``audit_log`` row — e.g.
flipped an ``enroll.deny`` to ``enroll.approve``, rewrote an
``agent.cert.rotate``, or deleted the ``auth.login`` that preceded an
exfil — clicked "Verify chain integrity" and got a GREEN verdict. The
admin chain has its own authoritative walker (``db.verify_audit_chain``,
exercised by smoke 80) but no operator-clickable surface invoked it.

These tests pin the post-fix contract of
``_verify_both_audit_chains``: ``ok`` is the AND of both chains, an
``audit_log`` tamper is reported with ``scope == "audit_log"``, and the
pre-existing ``local_audit`` coverage is preserved.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.dashboard.audit_routes import _verify_both_audit_chains
from mcp_proxy.db import dispose_db, get_db, init_db, log_audit
from mcp_proxy.local.audit import append_local_audit


@pytest_asyncio.fixture
async def both_chains_db(monkeypatch, tmp_path):
    """Fresh DB with the FULL migration chain applied.

    Unlike ``audit_test_env`` (which skips migrations and builds from
    ``metadata.create_all``), this runs the alembic chain so the
    ``local_audit`` table carries every migration-added column
    (``hash_format`` etc.) that ``append_local_audit`` writes. The
    batched audit chain is disabled so ``log_audit`` lands each admin
    row synchronously, and a non-default admin secret keeps
    ``ProxySettings`` from refusing to construct (F-A-507).
    """
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default",
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    db_file = tmp_path / "both_chains.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    yield url
    await dispose_db()
    get_settings.cache_clear()


async def _seed_admin_chain() -> None:
    """Two ``audit_log`` rows: an auth event and an enrollment decision."""
    await log_audit(
        agent_id="acme::alice",
        action="auth.login",
        status="success",
        request_id="login-1",
    )
    await log_audit(
        agent_id="acme::bob",
        action="enroll.approve",
        status="success",
        request_id="enroll-1",
    )


async def _drop_append_only_triggers(db) -> None:
    """Model an attacker who bypassed the DB-level append-only guard.

    ``audit_log`` and ``local_audit`` carry append-only triggers
    (F-A-402 / CRIT-3) that refuse UPDATE/DELETE, so the tamper here
    drops them first — standing in for the real bypass routes: a direct
    SQLite-file edit, a DBA dropping the trigger, a Postgres superuser,
    or a doctored backup restore. The hash chain is the independent
    second line of defence, and verifying it is exactly what this
    surface is for.
    """
    for trig in (
        "audit_log_no_update", "audit_log_no_delete",
        "local_audit_no_update", "local_audit_no_delete",
    ):
        await db.execute(text(f"DROP TRIGGER IF EXISTS {trig}"))


async def _seed_traffic_chain() -> None:
    """Two ``local_audit`` rows on one org's per-org chain."""
    await append_local_audit(
        event_type="session_opened", org_id="acme", agent_id="acme::alice",
    )
    await append_local_audit(
        event_type="tool_execute", org_id="acme", agent_id="acme::alice",
        details={"tool": "payments.transfer"},
    )


@pytest.mark.asyncio
async def test_clean_both_chains_verifies_ok(both_chains_db):
    """Clean admin + traffic chains → ok:true, with the admin chain row
    count surfaced so the operator sees audit_log was actually covered."""
    await _seed_admin_chain()
    await _seed_traffic_chain()

    verdict = await _verify_both_audit_chains()

    assert verdict["ok"] is True
    # The admin chain (audit_log) is now part of the verdict — the field
    # the front-end renders as "N admin" rows.
    assert verdict["admin_chain_rows"] == 2
    assert verdict["per_org_chain_rows"] == 2
    assert verdict["entries"] == 2


@pytest.mark.asyncio
async def test_tampered_audit_log_row_is_detected(both_chains_db):
    """THE C1 REGRESSION. Tamper an ``audit_log`` row while leaving the
    ``local_audit`` chain pristine. Pre-fix this returned ok:true (the
    false-green); post-fix it must return ok:false scoped to audit_log."""
    await _seed_admin_chain()
    await _seed_traffic_chain()

    # Attacker with DB access flips the enrollment decision from approve
    # to deny on the chained admin row — the row_hash no longer matches.
    async with get_db() as db:
        await _drop_append_only_triggers(db)
        await db.execute(text(
            "UPDATE audit_log SET status = 'denied' WHERE request_id = :rid"
        ), {"rid": "enroll-1"})

    verdict = await _verify_both_audit_chains()

    assert verdict["ok"] is False, (
        "audit_log tamper passed verification — the false-green C1 bug is back"
    )
    assert verdict["failure"]["scope"] == "audit_log"
    assert verdict["failure"]["kind"] == "mismatch"
    assert verdict["failure"]["chain_seq"] == 2
    assert "row_hash mismatch" in (verdict["failure"]["reason"] or "")


@pytest.mark.asyncio
async def test_admin_chain_break_is_detected(both_chains_db):
    """Deleting a middle admin row breaks the chain_seq linkage — the
    walker reports a break, not a content mismatch."""
    # Three rows so deleting the middle one leaves a verifiable gap.
    await _seed_admin_chain()
    await log_audit(
        agent_id="acme::carol",
        action="agent.cert.rotate",
        status="success",
        request_id="rotate-1",
    )

    async with get_db() as db:
        await _drop_append_only_triggers(db)
        await db.execute(text(
            "DELETE FROM audit_log WHERE request_id = :rid"
        ), {"rid": "enroll-1"})  # chain_seq=2, the middle row

    verdict = await _verify_both_audit_chains()

    assert verdict["ok"] is False
    assert verdict["failure"]["scope"] == "audit_log"
    assert verdict["failure"]["kind"] == "break"


@pytest.mark.asyncio
async def test_tampered_local_audit_row_still_detected(both_chains_db):
    """Pre-existing coverage preserved: a ``local_audit`` tamper with a
    clean admin chain is still caught, scoped to the per-org chain."""
    await _seed_admin_chain()
    await _seed_traffic_chain()

    async with get_db() as db:
        await _drop_append_only_triggers(db)
        await db.execute(text(
            "UPDATE local_audit SET result = 'denied' WHERE chain_seq = 1 "
            "AND org_id = 'acme'"
        ))

    verdict = await _verify_both_audit_chains()

    assert verdict["ok"] is False
    assert verdict["failure"]["scope"] == "per_org"
    assert verdict["failure"]["org_id"] == "acme"


@pytest.mark.asyncio
async def test_admin_chain_checked_first_when_both_broken(both_chains_db):
    """When both chains are tampered, the admin chain (higher-value
    security events) surfaces first so it is never masked by a traffic
    failure."""
    await _seed_admin_chain()
    await _seed_traffic_chain()

    async with get_db() as db:
        await _drop_append_only_triggers(db)
        await db.execute(text(
            "UPDATE audit_log SET status = 'denied' WHERE request_id = 'enroll-1'"
        ))
        await db.execute(text(
            "UPDATE local_audit SET result = 'denied' WHERE chain_seq = 1 "
            "AND org_id = 'acme'"
        ))

    verdict = await _verify_both_audit_chains()

    assert verdict["ok"] is False
    assert verdict["failure"]["scope"] == "audit_log"
