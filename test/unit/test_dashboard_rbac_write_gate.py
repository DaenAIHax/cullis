"""DASH-3 (blind-spot audit 2026-06-10) — central dashboard write gate.

Every mutating dashboard route goes through ``require_login``, but role
enforcement used to exist only on the bundle-download route: with the
enterprise ``rbac_multi_admin`` plugin a *viewer* session could reset
an admin's password, change KMS/OIDC config or apply migrations.
``require_login`` now denies write methods (POST/PUT/PATCH/DELETE) to
any session without a writer role (``admin`` / ``operator``), so the
denial is the default for every current and future mutation route —
a forgotten per-route ``require_role`` fails closed, not open.

Pinned here:
1. viewer POST → 403 ``role_required`` before the route body runs;
2. operator + admin POST pass the gate (admin implicit, community
   single-admin sessions keep working unchanged);
3. GET stays role-agnostic (viewer dashboards keep rendering);
4. legacy single-role cookies (``roles`` filled from ``role``) pass;
5. logged-out behaviour is unchanged (303 to /proxy/login);
6. end-to-end: a real route (API-token mint) rejects a viewer cookie
   with 403 and never mints.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from starlette.datastructures import URL
from starlette.responses import RedirectResponse

import mcp_proxy.dashboard.session as session_module
from mcp_proxy.dashboard.session import ProxyDashboardSession, require_login


class _Req:
    def __init__(self, method: str = "POST", path: str = "/proxy/test"):
        self.method = method
        self.url = URL(f"http://t{path}")


def _session(*roles: str) -> ProxyDashboardSession:
    return ProxyDashboardSession(
        role=roles[0] if roles else "",
        csrf_token="tok",
        logged_in=True,
        roles=tuple(roles),
    )


def _patch_session(monkeypatch, session: ProxyDashboardSession) -> None:
    monkeypatch.setattr(session_module, "get_session", lambda request: session)


# ── unit: the gate itself ─────────────────────────────────────────────


def test_viewer_post_denied_403(monkeypatch):
    _patch_session(monkeypatch, _session("viewer"))
    with pytest.raises(HTTPException) as exc_info:
        require_login(_Req("POST"))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["error"] == "role_required"


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_viewer_other_write_methods_denied(monkeypatch, method):
    _patch_session(monkeypatch, _session("viewer"))
    with pytest.raises(HTTPException):
        require_login(_Req(method))


def test_operator_post_passes(monkeypatch):
    operator = _session("operator")
    _patch_session(monkeypatch, operator)
    assert require_login(_Req("POST")) is operator


def test_admin_post_passes(monkeypatch):
    admin = _session("admin")
    _patch_session(monkeypatch, admin)
    assert require_login(_Req("POST")) is admin


def test_viewer_get_passes(monkeypatch):
    """Read access stays role-agnostic — the viewer role exists to view."""
    viewer = _session("viewer")
    _patch_session(monkeypatch, viewer)
    assert require_login(_Req("GET")) is viewer


def test_legacy_single_role_cookie_passes(monkeypatch):
    """Pre-multi-role cookies carry only ``role``; ``__post_init__``
    fills ``roles=(role,)`` and the community admin keeps writing."""
    legacy = ProxyDashboardSession(role="admin", csrf_token="tok", logged_in=True)
    _patch_session(monkeypatch, legacy)
    assert require_login(_Req("POST")) is legacy


def test_logged_out_still_redirects(monkeypatch):
    _patch_session(
        monkeypatch,
        ProxyDashboardSession(role="none", csrf_token="", logged_in=False, roles=()),
    )
    resp = require_login(_Req("POST"))
    assert isinstance(resp, RedirectResponse)
    assert resp.headers["location"] == "/proxy/login"


def test_multi_role_with_writer_passes(monkeypatch):
    """A plugin-minted session with (viewer, operator) carries a writer
    role and must pass — the gate is any-of, like ``require_role``."""
    s = _session("viewer", "operator")
    _patch_session(monkeypatch, s)
    assert require_login(_Req("POST")) is s


# ── end-to-end: a real mutation route rejects a viewer cookie ─────────


@pytest.mark.asyncio
async def test_viewer_cookie_cannot_mint_api_token(monkeypatch, tmp_path):
    from httpx import ASGITransport, AsyncClient

    from mcp_proxy.db import dispose_db, init_db

    url = f"sqlite+aiosqlite:///{tmp_path / 'rbac.db'}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-default")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    try:
        from mcp_proxy.dashboard.api_tokens import router as tokens_router

        app = FastAPI()
        app.include_router(tokens_router)

        # The route module imported ``require_login`` by name; patch the
        # session resolution underneath it so the real gate runs against
        # a viewer session.
        _patch_session(monkeypatch, _session("viewer"))

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t",
        ) as c:
            r = await c.post(
                "/proxy/users/acme::user::alice/api-tokens/create",
                data={"label": "evil", "csrf_token": "tok"},
            )

        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "role_required"

        from sqlalchemy import text

        from mcp_proxy.db import get_db

        async with get_db() as conn:
            result = await conn.execute(
                text("SELECT COUNT(*) AS n FROM user_api_tokens"),
            )
            assert result.scalar() == 0, "the mint body must never run"
    finally:
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]
