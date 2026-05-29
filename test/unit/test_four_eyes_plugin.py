"""Tests for the RbacMultiAdminPlugin hooks added for 4-eyes wire-up.

DB-touching paths (full submit_approval persisting a row) are covered
by ``test_approval_models.py``. Here we focus on:

* ``approval_required`` matches the quorum policy matrix.
* ``submit_approval`` rejects role-only submitter ids (the open-core
  hook is supposed to pass ``str(session.user_id)``; a role-only
  fallback is a misconfiguration).
* ``is_internal_replay`` delegates to the replay module.
"""
from __future__ import annotations

import importlib.util
from typing import AsyncIterator
from unittest.mock import MagicMock

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run rbac_multi_admin tests",
        allow_module_level=True,
    )

import pytest_asyncio


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch) -> AsyncIterator[None]:
    db_url = f"sqlite+aiosqlite:///{tmp_path}/four_eyes_plugin.db"
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


from cullis_enterprise.mastio.rbac_multi_admin.plugin import (
    RbacMultiAdminPlugin,
)


# ── approval_required matches the quorum matrix ───────────────────────


def test_approval_required_true_for_gated_actions():
    p = RbacMultiAdminPlugin()
    for action in (
        "policies.save",
        "pki.rotate_ca",
        "mastio_key.rotate",
        "vault.migrate_keys",
        "users.delete",
        "agents.delete",
    ):
        assert p.approval_required(action) is True, action


def test_approval_required_false_for_unknown_action():
    p = RbacMultiAdminPlugin()
    assert p.approval_required("something.unrelated") is False
    assert p.approval_required("") is False


# ── submit_approval input validation ──────────────────────────────────


@pytest.mark.asyncio
async def test_submit_approval_persists_with_int_submitter(db):
    """Happy path: user_id passed as stringified int round-trips."""
    p = RbacMultiAdminPlugin()
    approval_id = await p.submit_approval(
        action_type="policies.save",
        payload={"rules_json": "{}", "tab": "rules"},
        submitter_id="7",
    )
    assert len(approval_id) == 32  # uuid4().hex

    from cullis_enterprise.mastio.rbac_multi_admin import models
    row = await models.get_approval(approval_id)
    assert row is not None
    assert row["action_type"] == "policies.save"
    assert row["submitted_by"] == 7
    assert row["status"] == models.STATUS_PENDING


@pytest.mark.asyncio
async def test_submit_approval_rejects_role_only_submitter(db):
    """Role names (the legacy fallback) cannot persist as submitted_by."""
    p = RbacMultiAdminPlugin()
    with pytest.raises(ValueError, match="session.user_id"):
        await p.submit_approval(
            action_type="policies.save",
            payload={},
            submitter_id="technical_admin",
        )


@pytest.mark.asyncio
async def test_submit_approval_rejects_empty_submitter(db):
    p = RbacMultiAdminPlugin()
    with pytest.raises(ValueError, match="session.user_id"):
        await p.submit_approval(
            action_type="agents.delete",
            payload={"agent_id": "x"},
            submitter_id="",
        )


# ── is_internal_replay delegates to replay module ─────────────────────


@pytest.mark.asyncio
async def test_is_internal_replay_no_header_returns_false():
    p = RbacMultiAdminPlugin()
    req = MagicMock()
    req.headers = {}
    assert await p.is_internal_replay(req, "policies.save") is False


@pytest.mark.asyncio
async def test_is_internal_replay_invalid_header_returns_false():
    """Garbage headers do not raise; they yield False."""
    p = RbacMultiAdminPlugin()
    req = MagicMock()
    req.headers = {
        "X-Cullis-Approval-Replay": "garbage",
        "X-Cullis-Approval-Replay-Sig": "00",
    }
    assert await p.is_internal_replay(req, "policies.save") is False
