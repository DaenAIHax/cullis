"""Tests for the 4-eyes approval data model.

Covers:
  * submit/get/list pending approvals
  * status transitions: pending -> approved/rejected/expired/executed
  * signoff insertion and duplicate prevention
  * TTL expiry sweep
"""
from __future__ import annotations

import importlib.util
import time
from typing import AsyncIterator

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run rbac_multi_admin tests",
        allow_module_level=True,
    )

import pytest_asyncio


# ── shared fixture: isolated SQLite + ensured tables ──────────────────


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch) -> AsyncIterator[None]:
    db_url = f"sqlite+aiosqlite:///{tmp_path}/approvals.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, get_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.rbac_multi_admin import models
    async with get_db() as conn:
        await conn.run_sync(models.metadata.create_all, checkfirst=True)

    yield

    await dispose_db()
    get_settings.cache_clear()


# ── helpers ───────────────────────────────────────────────────────────


async def _seed_user(username: str, role: str) -> int:
    from cullis_enterprise.mastio.rbac_multi_admin import models
    return await models.insert_user(
        username=username, password_hash="x", role=role,
    )


# ── submit / get / list ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_returns_approval_id(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    submitter = await _seed_user("alice", "compliance_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save",
        action_payload={"rules": "{}"},
        submitter_user_id=submitter,
    )
    assert approval_id
    assert len(approval_id) == 32  # uuid4 hex

    row = await models.get_approval(approval_id)
    assert row is not None
    assert row["action_type"] == "policies.save"
    assert row["action_payload"] == {"rules": "{}"}
    assert row["submitted_by"] == submitter
    assert row["status"] == models.STATUS_PENDING
    assert row["expires_at"] > row["submitted_at"]


@pytest.mark.asyncio
async def test_submit_enforces_minimum_ttl(db):
    """TTL clamped to 60s minimum to prevent immediate-expiry traps."""
    from cullis_enterprise.mastio.rbac_multi_admin import models
    submitter = await _seed_user("alice", "compliance_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save",
        action_payload={},
        submitter_user_id=submitter,
        ttl_seconds=1,
    )
    row = await models.get_approval(approval_id)
    assert row["expires_at"] - row["submitted_at"] >= 60


@pytest.mark.asyncio
async def test_get_unknown_returns_none(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    assert await models.get_approval("does-not-exist") is None


@pytest.mark.asyncio
async def test_list_pending_filters_by_action_and_submitter(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")

    a1 = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    a2 = await models.submit_approval(
        action_type="pki.rotate_ca", action_payload={}, submitter_user_id=alice,
    )
    a3 = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=bob,
    )

    # All pending
    all_pending = await models.list_pending_approvals()
    assert {a["approval_id"] for a in all_pending} == {a1, a2, a3}

    # By action_type
    policies = await models.list_pending_approvals(action_type="policies.save")
    assert {a["approval_id"] for a in policies} == {a1, a3}

    # By submitter
    alices = await models.list_pending_approvals(submitter_user_id=alice)
    assert {a["approval_id"] for a in alices} == {a1, a2}

    # Combined
    alices_policies = await models.list_pending_approvals(
        action_type="policies.save", submitter_user_id=alice,
    )
    assert {a["approval_id"] for a in alices_policies} == {a1}


# ── status transitions ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reject_transitions_to_rejected(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    assert await models.reject_approval(
        approval_id=approval_id, rejecter_user_id=bob, reason="not ready",
    )

    row = await models.get_approval(approval_id)
    assert row["status"] == models.STATUS_REJECTED
    assert row["rejected_by"] == bob
    assert row["rejected_reason"] == "not ready"
    assert row["rejected_at"] is not None


@pytest.mark.asyncio
async def test_reject_non_pending_is_noop(db):
    """Rejecting an already-rejected (or executed) approval returns False."""
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    assert await models.reject_approval(
        approval_id=approval_id, rejecter_user_id=alice, reason="first",
    )
    # Second reject is a no-op.
    assert not await models.reject_approval(
        approval_id=approval_id, rejecter_user_id=alice, reason="second",
    )


@pytest.mark.asyncio
async def test_mark_approved_then_executed(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    assert await models.mark_approved(approval_id)
    row = await models.get_approval(approval_id)
    assert row["status"] == models.STATUS_APPROVED

    assert await models.mark_executed(approval_id)
    row = await models.get_approval(approval_id)
    assert row["status"] == models.STATUS_EXECUTED
    assert row["executed_at"] is not None

    # mark_executed is now a no-op (already executed).
    assert not await models.mark_executed(approval_id)


@pytest.mark.asyncio
async def test_mark_approved_not_callable_on_rejected(db):
    """Once rejected, a row cannot be approved."""
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    await models.reject_approval(
        approval_id=approval_id, rejecter_user_id=bob, reason="vetoed",
    )
    assert not await models.mark_approved(approval_id)


@pytest.mark.asyncio
async def test_expire_overdue_sweeps_past_ttl(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")

    fresh = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    stale = await models.submit_approval(
        action_type="pki.rotate_ca", action_payload={}, submitter_user_id=alice,
    )

    # Force the second row's expires_at into the past.
    from mcp_proxy.db import get_db
    from sqlalchemy import update
    async with get_db() as conn:
        await conn.execute(
            update(models.pending_admin_approvals)
            .where(models.pending_admin_approvals.c.approval_id == stale)
            .values(expires_at=int(time.time()) - 1)
        )

    swept = await models.expire_overdue()
    assert swept == 1

    fresh_row = await models.get_approval(fresh)
    stale_row = await models.get_approval(stale)
    assert fresh_row["status"] == models.STATUS_PENDING
    assert stale_row["status"] == models.STATUS_EXPIRED


# ── signoffs ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signoff_insert_and_list(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    assert await models.add_signoff(
        approval_id=approval_id, signer_user_id=bob,
        signature_role="technical_admin",
    )
    signs = await models.list_signoffs(approval_id)
    assert len(signs) == 1
    assert signs[0]["signed_by"] == bob
    assert signs[0]["signature_role"] == "technical_admin"


@pytest.mark.asyncio
async def test_duplicate_signoff_returns_false(db):
    """Same user signing the same approval twice = False (PK violation)."""
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    assert await models.add_signoff(
        approval_id=approval_id, signer_user_id=bob,
        signature_role="technical_admin",
    )
    assert not await models.add_signoff(
        approval_id=approval_id, signer_user_id=bob,
        signature_role="technical_admin",
    )

    signs = await models.list_signoffs(approval_id)
    assert len(signs) == 1  # not doubled


@pytest.mark.asyncio
async def test_signoffs_ordered_by_signed_at(db):
    from cullis_enterprise.mastio.rbac_multi_admin import models
    alice = await _seed_user("alice", "compliance_admin")
    bob = await _seed_user("bob", "technical_admin")
    carol = await _seed_user("carol", "super_admin")

    approval_id = await models.submit_approval(
        action_type="policies.save", action_payload={}, submitter_user_id=alice,
    )
    await models.add_signoff(
        approval_id=approval_id, signer_user_id=bob,
        signature_role="technical_admin",
    )
    # Force a later timestamp for carol so the ordering is deterministic.
    import asyncio
    await asyncio.sleep(1.05)
    await models.add_signoff(
        approval_id=approval_id, signer_user_id=carol,
        signature_role="super_admin",
    )

    signs = await models.list_signoffs(approval_id)
    assert [s["signed_by"] for s in signs] == [bob, carol]
