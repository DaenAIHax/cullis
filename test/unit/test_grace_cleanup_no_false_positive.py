"""A-3 — agent_cert_grace_cleanup must not emit false-positive audits.

Cold-reader dogfood session 3 (2026-05-25, kyc-screener + pitchbook-builder
sample agents) surfaced ``agent.cert_grace_period_expired`` audit rows at
boot on agents whose real leaf cert was valid for another 18 months. The
operator on the dogfood VM read the audit action name as "the agent's
cert expired" rather than "the stashed *previous* cert's grace window
expired" and assumed rotation was failing.

The cleanup loop already filters on
``previous_grace_period_expires_at IS NOT NULL`` in both the SELECT and
the UPDATE so a fresh agent (never rotated → column NULL) is silently
skipped. These tests PIN that contract so a future refactor cannot
relax the guard and reintroduce the false-positive signal.

Three invariants, one test each:

* ``test_cleanup_skips_agents_without_previous_grace`` — fresh agent
  with NULL grace column: zero audit rows, row unchanged.
* ``test_cleanup_clears_expired_grace`` — agent past its grace window:
  exactly one ``agent.cert_grace_period_expired`` audit row, all three
  previous_* columns reset to NULL.
* ``test_cleanup_keeps_active_grace`` — agent inside its grace window:
  zero audit rows, row unchanged.

The fixture seeds ``internal_agents`` directly (no enrollment flow) so
the test isolates the sweep's read+write contract from the writer side.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text


pytestmark = pytest.mark.asyncio


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest_asyncio.fixture
async def db_ready(audit_test_env):
    """Initialise the schema; tests seed rows themselves."""
    from mcp_proxy.db import init_db
    await init_db(audit_test_env)
    yield audit_test_env


async def _insert_agent(
    agent_id: str,
    *,
    previous_grace_period_expires_at: str | None,
    previous_cert_pem: str | None = None,
    previous_dpop_jkt: str | None = None,
) -> None:
    """Seed one ``internal_agents`` row with the given grace state.

    Other columns get the minimum the schema requires; the cleanup
    sweep only reads ``agent_id`` and ``previous_grace_period_expires_at``
    so the rest are placeholders.
    """
    from mcp_proxy.db import get_db
    now = _iso(datetime.now(timezone.utc))
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO internal_agents
                       (agent_id, display_name, capabilities, cert_pem,
                        created_at, is_active,
                        previous_cert_pem, previous_dpop_jkt,
                        previous_grace_period_expires_at)
                   VALUES (:aid, :dn, :caps, :cert,
                           :created, 1,
                           :prev_cert, :prev_jkt,
                           :grace)"""
            ),
            {
                "aid": agent_id,
                "dn": agent_id.split("::", 1)[-1] if "::" in agent_id else agent_id,
                "caps": "[]",
                "cert": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
                "created": now,
                "prev_cert": previous_cert_pem,
                "prev_jkt": previous_dpop_jkt,
                "grace": previous_grace_period_expires_at,
            },
        )


async def _audit_rows_for(agent_id: str, action: str) -> list[dict]:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT agent_id, action, status, detail FROM audit_log "
                "WHERE agent_id = :aid AND action = :act"
            ),
            {"aid": agent_id, "act": action},
        )).mappings().all()
    return [dict(r) for r in rows]


async def _agent_row(agent_id: str) -> dict | None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT previous_cert_pem, previous_dpop_jkt, "
                "previous_grace_period_expires_at "
                "FROM internal_agents WHERE agent_id = :aid"
            ),
            {"aid": agent_id},
        )).mappings().first()
    return dict(row) if row else None


# ── Tests ───────────────────────────────────────────────────────────────


async def test_cleanup_skips_agents_without_previous_grace(db_ready):
    """A-3 root cause pin: NULL grace column → no audit, no UPDATE.

    A fresh agent (never re-enrolled, never rotated) has
    ``previous_grace_period_expires_at = NULL``. The sweep must NOT
    emit ``agent.cert_grace_period_expired`` for it and must NOT touch
    the row. This is the regression that A-3 fixes: a false-positive
    audit on the kyc-screener / pitchbook-builder sample agents whose
    actual leaf cert was valid until 2027-05-21.
    """
    from mcp_proxy.lifespan.agent_cert_grace_cleanup import _sweep_once

    await _insert_agent(
        "orga::kyc-screener",
        previous_grace_period_expires_at=None,
    )

    cleared = await _sweep_once()

    assert cleared == 0, (
        f"sweep cleared {cleared} rows but agent had NULL grace column — "
        "this is the A-3 false-positive regression"
    )
    audit = await _audit_rows_for(
        "orga::kyc-screener", "agent.cert_grace_period_expired",
    )
    assert audit == [], (
        f"sweep emitted {len(audit)} audit rows for agent with no rotation "
        "history; the operator-facing audit chain must stay silent"
    )
    row = await _agent_row("orga::kyc-screener")
    assert row is not None
    assert row["previous_grace_period_expires_at"] is None
    assert row["previous_cert_pem"] is None
    assert row["previous_dpop_jkt"] is None


async def test_cleanup_clears_expired_grace(db_ready):
    """Expired grace window → audit row + all three previous_* set NULL.

    An agent that re-enrolled an hour ago but whose grace window has
    already passed (operator set a 0-hour grace, or the row was
    seeded by a migration) must be swept: one audit row pinning the
    expiry time, and the previous_* columns reset to NULL so the
    pinning verifiers stop falling back to the stale credential.
    """
    from mcp_proxy.lifespan.agent_cert_grace_cleanup import _sweep_once

    expired_at = _iso(datetime.now(timezone.utc) - timedelta(hours=2))
    await _insert_agent(
        "orga::pitchbook-builder",
        previous_grace_period_expires_at=expired_at,
        previous_cert_pem="-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n",
        previous_dpop_jkt="OLD-JKT-aaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    cleared = await _sweep_once()

    assert cleared == 1, (
        f"sweep cleared {cleared} rows but exactly one expired row was "
        "seeded"
    )
    audit = await _audit_rows_for(
        "orga::pitchbook-builder", "agent.cert_grace_period_expired",
    )
    assert len(audit) == 1, (
        f"expected exactly one audit row, got {len(audit)}"
    )
    assert audit[0]["status"] == "success"
    assert "grace_expired_at" in (audit[0]["detail"] or "")
    row = await _agent_row("orga::pitchbook-builder")
    assert row is not None
    assert row["previous_grace_period_expires_at"] is None, (
        "expired grace column must be reset to NULL after sweep"
    )
    assert row["previous_cert_pem"] is None
    assert row["previous_dpop_jkt"] is None


async def test_cleanup_keeps_active_grace(db_ready):
    """Active (future) grace window → no audit, no UPDATE.

    An agent that re-enrolled recently and is inside the configured
    grace window MUST keep its previous_* stash so the pinning
    verifiers can still fall back during mid-flight requests signed
    with the old keypair. The sweep is a no-op on this row until the
    expiry passes.
    """
    from mcp_proxy.lifespan.agent_cert_grace_cleanup import _sweep_once

    future = _iso(datetime.now(timezone.utc) + timedelta(hours=24))
    prev_cert = "-----BEGIN CERTIFICATE-----\nKEEP\n-----END CERTIFICATE-----\n"
    prev_jkt = "KEEP-JKT-bbbbbbbbbbbbbbbbbbbbbbbbb"
    await _insert_agent(
        "orga::recent-rotator",
        previous_grace_period_expires_at=future,
        previous_cert_pem=prev_cert,
        previous_dpop_jkt=prev_jkt,
    )

    cleared = await _sweep_once()

    assert cleared == 0, (
        f"sweep cleared {cleared} rows but the only seeded row has a "
        "future grace expiry"
    )
    audit = await _audit_rows_for(
        "orga::recent-rotator", "agent.cert_grace_period_expired",
    )
    assert audit == [], (
        "active grace window must not emit any audit row"
    )
    row = await _agent_row("orga::recent-rotator")
    assert row is not None
    assert row["previous_grace_period_expires_at"] == future
    assert row["previous_cert_pem"] == prev_cert
    assert row["previous_dpop_jkt"] == prev_jkt
