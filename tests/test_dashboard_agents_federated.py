"""ADR-010 Phase 5 — dashboard /proxy/agents/{id}/federate toggle.

Covers:
  - POST flips the flag 0 → 1 and bumps federation_revision
  - Second POST flips back 1 → 0 and bumps the revision again
  - Unknown agent → 404
  - Login required (303 to /login without session)
  - CSRF required (403 without token)
"""
from __future__ import annotations

import json
import re

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


async def _spin(tmp_path, monkeypatch, org_id: str = "pd-org"):
    db_file = tmp_path / "p.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _seed_agent(
    agent_id: str = "pd-org::alice", federated: bool = False,
) -> None:
    """Minimal row insert — bypasses the admin API so we can exercise
    just the dashboard flip without the cert-mint machinery."""
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO internal_agents (
                    agent_id, display_name, capabilities, api_key_hash,
                    cert_pem, created_at, is_active,
                    federated, federation_revision, last_pushed_revision
                ) VALUES (
                    :aid, :name, :caps, :hash,
                    NULL, :now, 1,
                    :fed, 1, 0
                )
                """
            ),
            {
                "aid": agent_id,
                "name": agent_id.split("::", 1)[-1],
                "caps": json.dumps([]),
                "hash": "$2b$12$placeholder",
                "now": "2026-04-17T00:00:00+00:00",
                "fed": 1 if federated else 0,
            },
        )


async def _login(cli: AsyncClient) -> None:
    """Set admin password directly + submit login form."""
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")
    r = await cli.post(
        "/proxy/login",
        data={"password": "test-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text


async def _csrf(cli: AsyncClient) -> str:
    """Scrape CSRF token from the agents page."""
    r = await cli.get("/proxy/agents")
    assert r.status_code == 200, r.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m, "csrf_token not found in /proxy/agents page"
    return m.group(1)


async def _fetch_flags(agent_id: str) -> dict:
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                """
                SELECT federated, federation_revision
                  FROM internal_agents WHERE agent_id = :aid
                """
            ),
            {"aid": agent_id},
        )).mappings().first()
        return dict(row) if row else {}


# ── tests ──────────────────────────────────────────────────────────────

async def test_toggle_flips_and_bumps_revision(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            await _login(cli)
            csrf = await _csrf(cli)

            r = await cli.post(
                "/proxy/agents/pd-org::alice/federate",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text

            state = await _fetch_flags("pd-org::alice")
            assert bool(state["federated"]) is True
            assert int(state["federation_revision"]) == 2

            r = await cli.post(
                "/proxy/agents/pd-org::alice/federate",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303
            state = await _fetch_flags("pd-org::alice")
            assert bool(state["federated"]) is False
            assert int(state["federation_revision"]) == 3

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_toggle_unknown_agent_returns_404(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/agents/pd-org::ghost/federate",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 404

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_toggle_requires_login(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            # No login — should redirect to /proxy/login.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/federate",
                follow_redirects=False,
            )
            assert r.status_code in (302, 303, 401, 403)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_toggle_requires_csrf(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            await _login(cli)
            # No csrf_token in body.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/federate",
                follow_redirects=False,
            )
            assert r.status_code == 403

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
