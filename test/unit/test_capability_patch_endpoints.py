"""PATCH /v1/admin/{agents,users,workloads}/{id}/capabilities (#21).

The admin PATCH surfaces let an operator rotate capabilities without
re-enrolling. Three symmetric endpoints, same shape:

  * accepts ``{"capabilities": [...]}`` with the ``Capability``
    constraint (pattern + per-item + list-length caps);
  * replaces the set (not delta) and bumps audit;
  * 404 on unknown id;
  * 422 on shape violation.

Tests use SQLite + the FastAPI ``app`` directly (no nginx in front).
The ``X-Admin-Secret`` header authenticates the admin secret check;
the agent_manager is stubbed so create_agent can run without the
PKI subsystem being loaded.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.admin.agents import router as agents_router
from mcp_proxy.admin.users import router as users_router
from mcp_proxy.admin.workloads import router as workloads_router
from mcp_proxy.db import dispose_db, get_db, init_db


ADMIN_SECRET = "test-admin-secret-not-default"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "patch_caps.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_DPOP_JTI_SECRET", "test-dpop-jti-secret")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(agents_router)
    app.include_router(users_router)
    app.include_router(workloads_router)
    return app


async def _seed_agent(agent_id: str, caps: list[str]) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents ("
                "  agent_id, display_name, capabilities, is_active, "
                "  created_at, federated, federation_revision"
                ") VALUES (:aid, 'A', :caps, 1, '2026-05-28T00:00:00Z', 0, 0)"
            ),
            {"aid": agent_id, "caps": json.dumps(caps)},
        )


async def _seed_user(principal_id: str, caps: list[str]) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_user_principals ("
                "  principal_id, user_name, display_name, reach, surface, "
                "  capabilities, created_at"
                ") VALUES (:pid, 'mario', 'Mario', 'intra', NULL, "
                "          :caps, '2026-05-28T00:00:00Z')"
            ),
            {"pid": principal_id, "caps": json.dumps(caps)},
        )


async def _seed_workload(principal_id: str, caps: list[str]) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_workload_principals ("
                "  principal_id, workload_name, display_name, "
                "  image_digest, runtime_status, capabilities, created_at"
                ") VALUES (:pid, 'ingest', 'Ingest', NULL, 'unknown', "
                "          :caps, '2026-05-28T00:00:00Z')"
            ),
            {"pid": principal_id, "caps": json.dumps(caps)},
        )


# ── PATCH /v1/admin/agents/{id}/capabilities ───────────────────────


@pytest.mark.asyncio
async def test_patch_agent_capabilities_replaces_set(proxy_db):
    await _seed_agent("acme::alice", ["llm.chat"])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/agents/acme::alice/capabilities",
            json={"capabilities": ["llm.chat", "mcp.tools.list"]},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["capabilities"]) == {"llm.chat", "mcp.tools.list"}
    assert body["federation_revision"] == 1  # bumped


@pytest.mark.asyncio
async def test_patch_agent_capabilities_404_when_missing(proxy_db):
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/agents/acme::ghost/capabilities",
            json={"capabilities": ["llm.chat"]},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_patch_agent_capabilities_422_on_bad_pattern(proxy_db):
    await _seed_agent("acme::alice", [])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/agents/acme::alice/capabilities",
            json={"capabilities": ["LLM.CHAT"]},  # uppercase
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_agent_capabilities_422_on_too_many(proxy_db):
    await _seed_agent("acme::alice", [])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/agents/acme::alice/capabilities",
            json={"capabilities": [f"cap{i}" for i in range(100)]},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_agent_capabilities_403_without_admin_secret(proxy_db):
    await _seed_agent("acme::alice", [])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/agents/acme::alice/capabilities",
            json={"capabilities": ["llm.chat"]},
            headers={"X-Admin-Secret": "wrong"},
        )
    assert r.status_code == 403


# ── PATCH /v1/admin/users/{id}/capabilities ────────────────────────


@pytest.mark.asyncio
async def test_patch_user_capabilities_replaces_set(proxy_db):
    await _seed_user("acme::user::mario", [])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/users/acme::user::mario/capabilities",
            json={"capabilities": ["mcp.tools.list"]},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 200, r.text
    assert r.json()["capabilities"] == ["mcp.tools.list"]


@pytest.mark.asyncio
async def test_patch_user_capabilities_404_when_missing(proxy_db):
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/users/acme::user::ghost/capabilities",
            json={"capabilities": []},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 404


# ── PATCH /v1/admin/workloads/{id}/capabilities ────────────────────


@pytest.mark.asyncio
async def test_patch_workload_capabilities_replaces_set(proxy_db):
    await _seed_workload("acme::workload::ingest", [])

    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/workloads/acme::workload::ingest/capabilities",
            json={"capabilities": ["mcp.tools.list", "ingest.write"]},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 200, r.text
    assert set(r.json()["capabilities"]) == {"mcp.tools.list", "ingest.write"}


@pytest.mark.asyncio
async def test_patch_workload_capabilities_404_when_missing(proxy_db):
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.patch(
            "/v1/admin/workloads/acme::workload::ghost/capabilities",
            json={"capabilities": []},
            headers={"X-Admin-Secret": ADMIN_SECRET},
        )
    assert r.status_code == 404
