"""Tests for the Connector audit API — ``GET /v1/audit/session/{session_id}``.

Covers:
  * 200 + ordering when the caller is a peer of the session
  * 403 when the caller has no entries linking them to the session
  * 404 when no entries exist for the session_id at all
  * 401 when the X-API-Key header is missing
  * Response cap at _MAX_ENTRIES (smoke, not a full stress test)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.audit.router import _MAX_ENTRIES
from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
from mcp_proxy.db import create_agent, dispose_db, get_db, init_db, log_audit


_SESSION_A = "sess-aaaa-1111"
_SESSION_B = "sess-bbbb-2222"


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def seeded_agents(proxy_app):
    """Register two agents and seed audit rows for two sessions.

    Layout:
      * agent_alice → participated in _SESSION_A (two entries, increasing ts)
      * agent_bob   → participated in _SESSION_B (one entry)
      * _SESSION_A also has one row from a ``system`` actor to exercise the
        non-caller ``agent_id`` path
    """
    alice_key = generate_api_key("alice")
    bob_key = generate_api_key("bob")
    await create_agent(
        agent_id="alice",
        display_name="Alice",
        capabilities=["chat"],
        api_key_hash=hash_api_key(alice_key),
    )
    await create_agent(
        agent_id="bob",
        display_name="Bob",
        capabilities=["chat"],
        api_key_hash=hash_api_key(bob_key),
    )

    base = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)

    # Helper: log then manually overwrite the timestamp so we can test
    # ordering without sleeping.
    async def _seed(ts, agent_id, action, request_id, *, tool=None, detail=None,
                    duration=None, status="ok"):
        await log_audit(
            agent_id=agent_id,
            action=action,
            status=status,
            tool_name=tool,
            detail=detail,
            request_id=request_id,
            duration_ms=duration,
        )
        async with get_db() as conn:
            await conn.execute(
                text(
                    "UPDATE audit_log SET timestamp = :ts "
                    "WHERE id = (SELECT MAX(id) FROM audit_log)"
                ),
                {"ts": ts.isoformat()},
            )

    await _seed(base + timedelta(seconds=1), "alice", "session.open",
                _SESSION_A, tool="open_session", duration=12.5)
    await _seed(base + timedelta(seconds=2), "system", "policy.evaluate",
                _SESSION_A, detail="allow", duration=3.0)
    await _seed(base + timedelta(seconds=3), "alice", "session.send",
                _SESSION_A, tool="send_message", duration=7.0)
    await _seed(base + timedelta(seconds=1), "bob", "session.open",
                _SESSION_B, tool="open_session", duration=11.0)

    return {"alice_key": alice_key, "bob_key": bob_key}


@pytest.mark.asyncio
async def test_audit_returns_entries_for_peer(proxy_app, seeded_agents):
    _, client = proxy_app
    headers = {"X-API-Key": seeded_agents["alice_key"]}
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}", headers=headers,
    )
    assert resp.status_code == 200, resp.text
    entries = resp.json()
    # 3 rows for session A (two alice + one system).
    assert len(entries) == 3
    # Ordering is ascending by timestamp.
    ts_list = [e["timestamp"] for e in entries]
    assert ts_list == sorted(ts_list)
    # Schema sanity.
    first = entries[0]
    assert first["agent_id"] == "alice"
    assert first["action"] == "session.open"
    assert first["tool_name"] == "open_session"
    assert first["status"] == "ok"
    assert first["duration_ms"] == pytest.approx(12.5)


@pytest.mark.asyncio
async def test_audit_forbids_non_peer(proxy_app, seeded_agents):
    _, client = proxy_app
    # bob never touched session A → 403.
    headers = {"X-API-Key": seeded_agents["bob_key"]}
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}", headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_404_on_unknown_session(proxy_app, seeded_agents):
    _, client = proxy_app
    headers = {"X-API-Key": seeded_agents["alice_key"]}
    resp = await client.get(
        "/v1/audit/session/sess-does-not-exist", headers=headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_audit_requires_api_key(proxy_app, seeded_agents):
    _, client = proxy_app
    resp = await client.get(f"/v1/audit/session/{_SESSION_A}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_audit_rejects_bad_api_key(proxy_app, seeded_agents):
    _, client = proxy_app
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}",
        headers={"X-API-Key": "sk_local_nobody_deadbeef"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_audit_caps_response_length(tmp_path, monkeypatch):
    """Insert more than _MAX_ENTRIES rows for a single session and confirm
    the response is capped. Uses a fresh DB to avoid coupling to the other
    seeded fixtures."""
    db_file = tmp_path / "audit_cap.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    try:
        agent_key = generate_api_key("capper")
        await create_agent(
            agent_id="capper",
            display_name="Capper",
            capabilities=["chat"],
            api_key_hash=hash_api_key(agent_key),
        )
        sid = "sess-cap-9999"
        insert_count = _MAX_ENTRIES + 25
        for i in range(insert_count):
            await log_audit(
                agent_id="capper",
                action=f"action.{i}",
                status="ok",
                request_id=sid,
            )

        from mcp_proxy.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            async with app.router.lifespan_context(app):
                resp = await client.get(
                    f"/v1/audit/session/{sid}",
                    headers={"X-API-Key": agent_key},
                )
        assert resp.status_code == 200, resp.text
        entries = resp.json()
        assert len(entries) == _MAX_ENTRIES
    finally:
        await dispose_db()
        get_settings.cache_clear()
