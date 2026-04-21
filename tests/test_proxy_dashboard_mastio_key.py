"""ADR-012 Phase 2.1 UX — ``/proxy/mastio-key`` dashboard.

Exercises the three routes added for operator-driven key rotation:

* ``GET /proxy/mastio-key`` — renders the page, shows the active
  signer, lists any deprecated-in-grace keys, reads the configured
  grace_days, and flags standalone mode when no broker is attached.
* ``POST /proxy/mastio-key/grace-days`` — persists the preference
  under ``proxy_config.rotation_grace_days`` and clamps to 1..90.
* ``POST /proxy/mastio-key/rotate`` — drives
  ``AgentManager.rotate_mastio_key`` with a stub propagator (so no
  network call leaves the test), audits the transition, and
  redirects with a ``?rotated=1`` flash so the UI renders a toast.

A cross-cutting render-time test asserts the key visual affordances
(active kid, grace row, confirm modal) are in the DOM so a regression
in the template surfaces quickly.
"""
from __future__ import annotations

import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_logged_in(tmp_path, monkeypatch):
    """Standalone proxy booted with admin login + Org CA so the Mastio
    identity auto-provisions during lifespan."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            await client.post(
                "/proxy/login",
                data={"password": "test-password-1234"},
                follow_redirects=False,
            )
            yield app, client
    get_settings.cache_clear()


async def _csrf(client: AsyncClient) -> str:
    page = await client.get("/proxy/mastio-key")
    assert page.status_code == 200, page.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found in rendered page"
    return m.group(1)


# ── Render ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_page_renders_active_signer_and_controls(proxy_logged_in):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/mastio-key")
    assert resp.status_code == 200
    html = resp.text
    # Hero + heading text
    assert "Mastio signing identity" in html
    # Active signer block with kid + algorithm hints
    assert "Active signer" in html
    assert "ES256 · P-256" in html
    assert "mastio-" in html  # the kid prefix should leak out somewhere
    # Rotation controls — grace-days form + rotate button
    assert 'name="grace_days"' in html
    assert "Rotate signing key" in html
    # Modal skeleton present
    assert 'id="rotate-mastio-modal"' in html
    assert "Type ROTATE to confirm" in html
    # Standalone banner present because the fixture sets STANDALONE=true
    assert "Standalone mode" in html


@pytest.mark.asyncio
async def test_nav_highlights_mastio_key_entry(proxy_logged_in):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/mastio-key")
    assert resp.status_code == 200
    # The base.html nav renders ``nav-active`` when ``active == 'mastio_key'``.
    assert 'href="/proxy/mastio-key"' in resp.text
    # Check that the active nav marker is present on the Signing Key link.
    nav_block = re.search(
        r'href="/proxy/mastio-key"[^>]*class="[^"]*nav-active',
        resp.text,
    )
    assert nav_block, "Signing Key nav entry is not marked active"


# ── Grace-days preference ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_grace_days_save_persists_valid_value(proxy_logged_in):
    _, client = proxy_logged_in
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/mastio-key/grace-days",
        data={"csrf_token": csrf, "grace_days": "14"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/proxy/mastio-key"

    from mcp_proxy.db import get_config
    assert await get_config("rotation_grace_days") == "14"


@pytest.mark.asyncio
async def test_grace_days_save_rejects_out_of_range(proxy_logged_in):
    _, client = proxy_logged_in
    csrf = await _csrf(client)
    # Below MIN (1)
    resp = await client.post(
        "/proxy/mastio-key/grace-days",
        data={"csrf_token": csrf, "grace_days": "0"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    # Above MAX (90)
    resp = await client.post(
        "/proxy/mastio-key/grace-days",
        data={"csrf_token": csrf, "grace_days": "365"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_grace_days_save_rejects_non_numeric(proxy_logged_in):
    _, client = proxy_logged_in
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/mastio-key/grace-days",
        data={"csrf_token": csrf, "grace_days": "soon"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


# ── Rotation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rotate_requires_confirm_text(proxy_logged_in):
    _, client = proxy_logged_in
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/mastio-key/rotate",
        data={"csrf_token": csrf, "confirm_text": "nope"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "Confirmation text mismatch" in resp.text


@pytest.mark.asyncio
async def test_rotate_swaps_active_signer_and_flashes(proxy_logged_in):
    app, client = proxy_logged_in
    # Capture the kid in use before we trigger rotation.
    mgr = app.state.agent_manager
    assert mgr.mastio_loaded, "fixture is expected to bootstrap Mastio identity"
    old_kid = mgr._active_key.kid

    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/mastio-key/rotate",
        data={"csrf_token": csrf, "confirm_text": "ROTATE"},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    location = resp.headers["location"]
    assert location.startswith("/proxy/mastio-key?rotated=1"), location
    assert f"old_kid={old_kid}" in location

    new_kid = mgr._active_key.kid
    assert new_kid != old_kid
    assert f"new_kid={new_kid}" in location

    # The rendered page after redirect should display both kids in the flash.
    flash_page = await client.get(location)
    assert flash_page.status_code == 200
    assert "Rotation complete" in flash_page.text
    assert old_kid in flash_page.text
    assert new_kid in flash_page.text

    # LocalIssuer was rebuilt so subsequent JWTs sign under the new kid.
    issuer = app.state.local_issuer
    assert issuer is not None
    assert issuer.kid == new_kid


@pytest.mark.asyncio
async def test_rotate_grace_row_appears_after_rotation(proxy_logged_in):
    _, client = proxy_logged_in
    csrf = await _csrf(client)
    # Pre-set a short grace so the UI row has a stable countdown target.
    await client.post(
        "/proxy/mastio-key/grace-days",
        data={"csrf_token": csrf, "grace_days": "1"},
        follow_redirects=False,
    )
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/mastio-key/rotate",
        data={"csrf_token": csrf, "confirm_text": "ROTATE"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = await client.get("/proxy/mastio-key")
    assert page.status_code == 200
    # Grace window section should now carry "1 deprecated · still verifier-valid"
    assert "deprecated · still verifier-valid" in page.text
    # And a countdown data-attribute.
    assert "data-countdown-to=" in page.text
