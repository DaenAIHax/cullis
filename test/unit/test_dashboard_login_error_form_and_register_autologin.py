"""Dashboard auth UX fixes (2026-06-03).

Two bugs surfaced by Daniele while bootstrapping the admin for the bank
sim (org d1b4):

Bug 2 — the login form vanished on every POST error re-render. The
``login.html`` template gates the whole password ``<form>`` behind
``{% if password_enabled %}``. The GET ``login_page`` passes
``password_enabled``/``oidc_enabled``/``display_name`` so the form
shows, but the POST ``login_submit`` error branches re-rendered the
template WITHOUT them → undefined → falsy → the form block was skipped →
the user saw the error with no field to retry (browser "back" only).
The fix computes those three flags once at the top of ``login_submit``
and threads them through every error ``TemplateResponse``.

Bug 1 — ``register_submit`` forced a clean re-login after
``set_admin_password`` (redirect to ``/proxy/login``). The fix
auto-authenticates the very first session (mirror the ``login_submit``
success path), so the operator lands on the dashboard.

The tests drive the auth router via httpx's ASGITransport on the same
event loop pytest-asyncio runs on, so the SQLAlchemy + aiosqlite engine
stays bound to the loop that created it (mirrors
``test_agent_identity_bundle_download``).
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard import session as session_module
from mcp_proxy.dashboard.auth_routes import router as auth_router
from mcp_proxy.db import dispose_db, init_db


_ADMIN_SECRET = "test-admin-secret-login-error-form"
_ADMIN_PASSWORD = "correct-horse-battery-staple"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite with the full schema for the auth routes.

    Audit chain is forced off so ``log_audit`` writes inline (the
    error paths audit denied/error events). Deterministic signing key
    so the auto-login session cookie round-trips the secret
    ``require_login`` verifies against.
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "a" * 64)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "login_error_form.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _make_app() -> FastAPI:
    app = FastAPI()
    # The auth router mounts at ``/proxy`` in production (the prefix
    # lives on the parent include). Replicate so URLs match the browser.
    app.include_router(auth_router, prefix="/proxy")
    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── Bug 2: error re-render keeps the password form ──────────────────


@pytest.mark.asyncio
async def test_invalid_password_response_still_renders_the_form(proxy_db):
    """A 401 (wrong password) re-renders login.html WITH the password
    form so the user can retry inline — no browser back button.
    """
    from mcp_proxy.dashboard.session import set_admin_password

    await set_admin_password(_ADMIN_PASSWORD)

    app = _make_app()
    async with _client(app) as client:
        resp = await client.post(
            "/proxy/login", data={"password": "WRONGPASS123"},
        )

    assert resp.status_code == 401, resp.text
    body = resp.text
    assert "Invalid password." in body
    # The bug: before the fix the form block was skipped because
    # password_enabled was undefined. These assertions pin its presence.
    assert 'name="password"' in body, (
        "password input must survive the error re-render"
    )
    assert 'action="/proxy/login"' in body, (
        "the retry form must POST back to /proxy/login"
    )


@pytest.mark.asyncio
async def test_password_required_response_still_renders_the_form(proxy_db):
    """The 400 "Password is required." branch must also keep the form."""
    from mcp_proxy.dashboard.session import set_admin_password

    await set_admin_password(_ADMIN_PASSWORD)

    app = _make_app()
    async with _client(app) as client:
        resp = await client.post("/proxy/login", data={"password": ""})

    assert resp.status_code == 400, resp.text
    body = resp.text
    assert "Password is required." in body
    assert 'name="password"' in body
    assert 'action="/proxy/login"' in body


@pytest.mark.asyncio
async def test_get_login_page_renders_form_baseline(proxy_db):
    """Sanity: the GET form is present (so the POST assertions above
    are testing parity, not a template that never shows a form)."""
    from mcp_proxy.dashboard.session import set_admin_password

    await set_admin_password(_ADMIN_PASSWORD)

    app = _make_app()
    async with _client(app) as client:
        resp = await client.get("/proxy/login")

    assert resp.status_code == 200, resp.text
    assert 'name="password"' in resp.text


# ── Bug 1: register auto-logs-in instead of forcing re-login ────────


@pytest.mark.asyncio
async def test_register_auto_logs_in_and_redirects_to_dashboard(proxy_db):
    """POST /proxy/register on a pristine Mastio (no admin yet) sets a
    session cookie (auto-login) and redirects to the dashboard, NOT
    back to /proxy/login.
    """
    from mcp_proxy.dashboard.session import is_admin_password_set

    assert await is_admin_password_set() is False

    app = _make_app()
    async with _client(app) as client:
        resp = await client.post(
            "/proxy/register",
            data={
                "password": _ADMIN_PASSWORD,
                "confirm_password": _ADMIN_PASSWORD,
            },
            follow_redirects=False,
        )

    assert resp.status_code == 303, resp.text
    # Not bounced back to the login form.
    location = resp.headers.get("location", "")
    assert location != "/proxy/login", (
        "register must auto-login, not force a re-login"
    )
    assert location in ("/proxy/overview", "/proxy/setup"), location
    # The session cookie was minted on the redirect response.
    assert session_module._COOKIE_NAME in resp.cookies, (
        "register must set a session cookie (auto-login)"
    )
    # Password was actually persisted.
    assert await is_admin_password_set() is True
