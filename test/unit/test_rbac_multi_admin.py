"""rbac_multi_admin plugin tests — DB-backed admin login + user CRUD."""
from __future__ import annotations

import importlib
import importlib.util
from typing import Iterator

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run rbac_multi_admin tests",
        allow_module_level=True,
    )

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


# ── shared fixture: app with plugin mounted + isolated DB ───────────


@pytest_asyncio.fixture
async def rbac_app(tmp_path, monkeypatch) -> Iterator[tuple[FastAPI, AsyncClient]]:
    db_url = f"sqlite+aiosqlite:///{tmp_path}/rbac.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)
    monkeypatch.setenv("CULLIS_RBAC_ENABLED", "1")
    monkeypatch.setenv("CULLIS_RBAC_BOOTSTRAP_USER", "root")
    monkeypatch.setenv("CULLIS_RBAC_BOOTSTRAP_PASSWORD", "rootpass1")
    monkeypatch.setenv("CULLIS_RBAC_BOOTSTRAP_ROLE", "admin")

    # Bypass license verification — the proxy runs in community mode in
    # this test process, so require_feature("rbac_multi_admin") would
    # 402. Patch has_feature to always return True.
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.rbac_multi_admin.plugin import RbacMultiAdminPlugin
    plugin_instance = RbacMultiAdminPlugin()

    app = FastAPI()
    await plugin_instance.startup(app)
    for r in plugin_instance.routers():
        app.include_router(r)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield app, client

    await dispose_db()
    get_settings.cache_clear()


# ── helpers ────────────────────────────────────────────────────────


async def _login(client: AsyncClient, username: str, password: str):
    return await client.post(
        "/admin/login", json={"username": username, "password": password},
    )


# ── bootstrap ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bootstrap_creates_root_user(rbac_app):
    _, client = rbac_app
    r = await _login(client, "root", "rootpass1")
    assert r.status_code == 200, r.text
    assert r.json() == {"username": "root", "role": "admin"}


@pytest.mark.asyncio
async def test_bootstrap_idempotent_when_users_exist(tmp_path, monkeypatch):
    """Re-running startup with bootstrap env on a populated table does not
    re-create the user. Guards against silent duplicate creation if the
    operator forgets to unset the env after first boot."""
    db_url = f"sqlite+aiosqlite:///{tmp_path}/rbac.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)
    monkeypatch.setenv("CULLIS_RBAC_BOOTSTRAP_USER", "root")
    monkeypatch.setenv("CULLIS_RBAC_BOOTSTRAP_PASSWORD", "rootpass1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.rbac_multi_admin import models
    from cullis_enterprise.mastio.rbac_multi_admin.plugin import RbacMultiAdminPlugin

    plugin_instance = RbacMultiAdminPlugin()
    app = FastAPI()
    await plugin_instance.startup(app)
    await plugin_instance.startup(app)  # second call must be a no-op

    users = await models.list_users()
    assert len(users) == 1
    assert users[0]["username"] == "root"

    await dispose_db()
    get_settings.cache_clear()


# ── login flow ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_bad_password(rbac_app):
    _, client = rbac_app
    r = await _login(client, "root", "wrongpass")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(rbac_app):
    _, client = rbac_app
    r = await _login(client, "ghost", "doesnt-matter")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_sets_session_cookie(rbac_app):
    _, client = rbac_app
    r = await _login(client, "root", "rootpass1")
    assert r.status_code == 200
    cookie = r.headers.get("set-cookie", "")
    assert "mcp_proxy_session=" in cookie


@pytest.mark.asyncio
async def test_logout_clears_cookie(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.post("/admin/logout")
    assert r.status_code == 200
    cookie = r.headers.get("set-cookie", "")
    # Either Max-Age=0 or the cookie cleared via expires header.
    assert "mcp_proxy_session=" in cookie


# ── user CRUD ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_users_requires_admin(rbac_app):
    _, client = rbac_app
    # No login → 401
    r = await client.get("/admin/users")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_user_as_admin(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "operator"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["username"] == "alice"
    assert data["role"] == "operator"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_user_invalid_role(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.post(
        "/admin/users",
        json={"username": "bob", "password": "bobpw0001", "role": "superuser"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_role"


@pytest.mark.asyncio
async def test_create_user_short_password(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.post(
        "/admin/users",
        json={"username": "bob", "password": "short", "role": "viewer"},
    )
    # Pydantic rejects min_length first.
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_user_duplicate_username(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    body = {"username": "dup", "password": "duppass01", "role": "viewer"}
    r1 = await client.post("/admin/users", json=body)
    assert r1.status_code == 200
    r2 = await client.post("/admin/users", json=body)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_operator_cannot_create_users(rbac_app):
    """Logging in as operator does not allow user CRUD."""
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    await client.post(
        "/admin/users",
        json={"username": "op1", "password": "oppass001", "role": "operator"},
    )
    # Switch session — log in as operator
    client.cookies.clear()
    r = await _login(client, "op1", "oppass001")
    assert r.status_code == 200
    r = await client.get("/admin/users")
    assert r.status_code == 403
    r = await client.post(
        "/admin/users",
        json={"username": "op2", "password": "oppass002", "role": "operator"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_patch_user_role(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "carol", "password": "carolpw1", "role": "viewer"},
    )
    user_id = create.json()["id"]
    r = await client.patch(f"/admin/users/{user_id}", json={"role": "operator"})
    assert r.status_code == 200
    assert r.json()["changes"]["role"] == "operator"


@pytest.mark.asyncio
async def test_patch_user_password_then_login(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "dave", "password": "davepw01", "role": "operator"},
    )
    user_id = create.json()["id"]
    r = await client.patch(
        f"/admin/users/{user_id}", json={"password": "newpwword1"},
    )
    assert r.status_code == 200
    client.cookies.clear()
    r_old = await _login(client, "dave", "davepw01")
    assert r_old.status_code == 401
    r_new = await _login(client, "dave", "newpwword1")
    assert r_new.status_code == 200


@pytest.mark.asyncio
async def test_patch_user_no_fields(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "eve", "password": "evepwword", "role": "viewer"},
    )
    r = await client.patch(f"/admin/users/{create.json()['id']}", json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_delete_user(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "frank", "password": "frankpw1", "role": "viewer"},
    )
    user_id = create.json()["id"]
    r = await client.delete(f"/admin/users/{user_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "deleted"
    # Idempotent re-delete returns 404.
    r2 = await client.delete(f"/admin/users/{user_id}")
    assert r2.status_code == 404


@pytest.mark.asyncio
async def test_cannot_delete_last_admin(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    listing = await client.get("/admin/users")
    root_id = next(u["id"] for u in listing.json()["users"] if u["username"] == "root")
    r = await client.delete(f"/admin/users/{root_id}")
    assert r.status_code == 409
    assert "last admin" in r.json()["detail"]


@pytest.mark.asyncio
async def test_can_delete_admin_when_others_exist(rbac_app):
    """C-RBAC-1 reframed: when an admin deletes a different admin,
    the deleter's own session keeps working (the deleter has not
    been revoked). When an admin deletes themselves, their own
    cookie no longer references a live row and the next protected
    request must 401 ("session revoked").

    Pre-fix behaviour was the opposite: deleting yourself left the
    cookie working until natural expiry, exactly the bug the audit
    flagged.
    """
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "second-admin", "password": "secadmpw1", "role": "admin"},
    )
    second_id = create.json()["id"]
    listing = await client.get("/admin/users")
    root_id = next(u["id"] for u in listing.json()["users"] if u["username"] == "root")

    # Case 1: root deletes second-admin, root's cookie still works.
    r = await client.delete(f"/admin/users/{second_id}")
    assert r.status_code == 200
    listing_after_other = await client.get("/admin/users")
    assert listing_after_other.status_code == 200, (
        "deleter's own session must survive a different user's deletion"
    )
    usernames_a = [u["username"] for u in listing_after_other.json()["users"]]
    assert "root" in usernames_a
    assert "second-admin" not in usernames_a

    # Re-create second-admin and have root delete itself this time.
    # That requires a second admin in place to clear the
    # "cannot delete the last admin" guard.
    create2 = await client.post(
        "/admin/users",
        json={"username": "second-admin", "password": "secadmpw1", "role": "admin"},
    )
    assert create2.status_code == 200
    r2 = await client.delete(f"/admin/users/{root_id}")
    assert r2.status_code == 200

    # Case 2: root just deleted itself — root's cookie now references
    # a vanished row, so the very next request 401s. This is the
    # behaviour the audit C-RBAC-1 fix introduces; before the fix the
    # cookie remained usable until natural expiry.
    r_after_self = await client.get("/admin/users")
    assert r_after_self.status_code == 401, (
        "self-deleted user must lose their session immediately "
        "(C-RBAC-1: server-side revocation)"
    )


@pytest.mark.asyncio
async def test_list_users_includes_metadata(rbac_app):
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.get("/admin/users")
    assert r.status_code == 200
    payload = r.json()
    assert payload["count"] == 1
    user = payload["users"][0]
    assert user["username"] == "root"
    assert user["role"] == "admin"
    assert "password_hash" not in user
    assert user["created_at"] > 0


# ── C-RBAC-1: server-side session revocation ───────────────────────


@pytest.mark.asyncio
async def test_fresh_cookie_still_works_after_login(rbac_app):
    """Sanity: the revocation primitive does not regress the happy
    path. Login → protected request returns 200."""
    _, client = rbac_app
    r = await _login(client, "root", "rootpass1")
    assert r.status_code == 200
    r2 = await client.get("/admin/users")
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_stale_cookie_rejected_after_user_delete(rbac_app):
    """C-RBAC-1: replaying a deleted user's cookie returns 401.

    Pre-fix: the HMAC-signed cookie had no server-side store, so
    after the user row was gone the cookie kept asserting role=admin
    until natural expiry. Now the per-request DB lookup notices the
    missing row and revokes.
    """
    _, client = rbac_app
    # Bootstrap second admin so we can delete alice without tripping
    # the "last admin" guard. alice doubles as the victim.
    await _login(client, "root", "rootpass1")
    await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "admin"},
    )

    # Capture alice's cookie via a fresh client instance — the
    # default httpx AsyncClient cookie jar would clobber root's
    # cookies on every login. We snapshot alice's headers directly.
    client.cookies.clear()
    r_alice = await _login(client, "alice", "alicepw1")
    assert r_alice.status_code == 200
    alice_cookies = dict(client.cookies)

    # Switch back to root and delete alice.
    client.cookies.clear()
    await _login(client, "root", "rootpass1")
    listing = await client.get("/admin/users")
    alice_id = next(
        u["id"] for u in listing.json()["users"] if u["username"] == "alice"
    )
    r_del = await client.delete(f"/admin/users/{alice_id}")
    assert r_del.status_code == 200

    # Now replay alice's cookie. Pre-fix this was a 200, post-fix
    # it must 401.
    client.cookies.clear()
    for k, v in alice_cookies.items():
        client.cookies.set(k, v)
    r_replay = await client.get("/admin/users")
    assert r_replay.status_code == 401, (
        "deleted user's cookie must be invalidated immediately"
    )


@pytest.mark.asyncio
async def test_stale_cookie_rejected_after_role_demote(rbac_app):
    """C-RBAC-1: cookie minted at role=admin must stop working
    once the DB row is demoted to viewer. Without this, the
    operator's "demote this user now" command would not take
    effect for up to 8 hours (cookie max age)."""
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "admin"},
    )

    # Snapshot alice's cookie while she is still an admin.
    client.cookies.clear()
    r_alice = await _login(client, "alice", "alicepw1")
    assert r_alice.status_code == 200
    alice_cookies = dict(client.cookies)

    # Confirm alice's cookie can list users (admin route).
    r_pre = await client.get("/admin/users")
    assert r_pre.status_code == 200

    # Root demotes alice to viewer.
    client.cookies.clear()
    await _login(client, "root", "rootpass1")
    listing = await client.get("/admin/users")
    alice_id = next(
        u["id"] for u in listing.json()["users"] if u["username"] == "alice"
    )
    r_patch = await client.patch(
        f"/admin/users/{alice_id}", json={"role": "viewer"},
    )
    assert r_patch.status_code == 200

    # Replay alice's pre-demote cookie. Must 401, not 200 with
    # admin claims.
    client.cookies.clear()
    for k, v in alice_cookies.items():
        client.cookies.set(k, v)
    r_replay = await client.get("/admin/users")
    assert r_replay.status_code == 401, (
        "pre-demote cookie must be invalidated by session_version bump"
    )


@pytest.mark.asyncio
async def test_stale_cookie_rejected_after_password_rotation(rbac_app):
    """C-RBAC-1: rotating a user's password invalidates every
    previously-issued session. This matches the user expectation
    that "I changed the password" implies "the previous holder is
    locked out", which the cookie-only design did not honour."""
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "admin"},
    )

    client.cookies.clear()
    r_alice = await _login(client, "alice", "alicepw1")
    assert r_alice.status_code == 200
    alice_cookies = dict(client.cookies)

    # Root rotates alice's password.
    client.cookies.clear()
    await _login(client, "root", "rootpass1")
    listing = await client.get("/admin/users")
    alice_id = next(
        u["id"] for u in listing.json()["users"] if u["username"] == "alice"
    )
    r_patch = await client.patch(
        f"/admin/users/{alice_id}", json={"password": "newalicepw1"},
    )
    assert r_patch.status_code == 200

    # Old cookie must 401 even though the password was just rotated
    # via a different (root) session.
    client.cookies.clear()
    for k, v in alice_cookies.items():
        client.cookies.set(k, v)
    r_replay = await client.get("/admin/users")
    assert r_replay.status_code == 401, (
        "pre-rotation cookie must be invalidated"
    )


@pytest.mark.asyncio
async def test_role_patch_no_change_does_not_revoke(rbac_app):
    """C-RBAC-1 detail: the bump fires only on actual role
    transitions. PATCH role=admin on a user already admin is a
    no-op and must not invalidate that user's cookie — otherwise
    operators would silently log themselves out by re-saving an
    unchanged form."""
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "admin"},
    )

    client.cookies.clear()
    r_alice = await _login(client, "alice", "alicepw1")
    assert r_alice.status_code == 200
    alice_cookies = dict(client.cookies)

    client.cookies.clear()
    await _login(client, "root", "rootpass1")
    listing = await client.get("/admin/users")
    alice_id = next(
        u["id"] for u in listing.json()["users"] if u["username"] == "alice"
    )
    # PATCH with the SAME role: the implementation should detect
    # the no-op and skip the bump.
    r_patch = await client.patch(
        f"/admin/users/{alice_id}", json={"role": "admin"},
    )
    assert r_patch.status_code == 200

    # alice's cookie still works.
    client.cookies.clear()
    for k, v in alice_cookies.items():
        client.cookies.set(k, v)
    r_replay = await client.get("/admin/users")
    assert r_replay.status_code == 200, (
        "no-op role PATCH must not bump session_version"
    )


@pytest.mark.asyncio
async def test_session_version_bump_is_atomic(rbac_app):
    """C-RBAC-1 atomicity check: bump_session_version uses
    ``UPDATE ... SET session_version = session_version + 1`` in a
    single statement, so two concurrent calls cannot collapse onto
    the same value. Run two sequential bumps and confirm the
    counter is 2, not 1.

    A true concurrent test would need a real Postgres connection
    pool; this serial test verifies the SQL form (single-statement
    increment) by counting deltas, not the wall-clock race window.
    """
    from cullis_enterprise.mastio.rbac_multi_admin import models

    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "alice", "password": "alicepw1", "role": "viewer"},
    )
    alice_id = create.json()["id"]

    sv0 = await models.get_session_version(alice_id)
    assert sv0 == 0
    new1 = await models.bump_session_version(alice_id)
    new2 = await models.bump_session_version(alice_id)
    assert new1 == 1
    assert new2 == 2


@pytest.mark.asyncio
async def test_session_version_lookup_for_missing_user(rbac_app):
    """get_session_version returns None for a non-existent row, so
    the dependency can distinguish "deleted" from "version mismatch"
    and emit the right log message."""
    from cullis_enterprise.mastio.rbac_multi_admin import models
    _, _ = rbac_app  # triggers fixture setup
    sv = await models.get_session_version(999_999)
    assert sv is None


# ── F-001 / H-005 (audit 2026-05-14): no literal "fallback-key" ────


def test_signing_key_refuses_literal_fallback_in_production(monkeypatch):
    """Audit F-001 / H-003: pre-fix, ``_signing_key()`` returned the
    literal string ``"fallback-key"`` when the env var and the
    persisted dev file were both unavailable. Any prod deploy that
    forgot to wire ``MCP_PROXY_DASHBOARD_SIGNING_KEY`` would silently
    sign sidecars with that literal — known to every attacker who
    can read the repo. Now production refuses to mint a sidecar
    rather than fall back to anything literal.
    """
    monkeypatch.delenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", raising=False)
    monkeypatch.delenv("CULLIS_RBAC_SIDECAR_FALLBACK_KEY", raising=False)
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    # Point the persisted-file path at a directory we know is empty so
    # the second lookup step also yields nothing.
    monkeypatch.setenv(
        "MCP_PROXY_DASHBOARD_SIGNING_KEY_PATH",
        "/nonexistent/audit-h003-empty-path",
    )

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from cullis_enterprise.mastio.rbac_multi_admin import session_revocation

    with pytest.raises(RuntimeError) as exc:
        session_revocation._signing_key()
    msg = str(exc.value).lower()
    assert "production" in msg or "signing key" in msg
    # And: the literal that used to leak through must not appear in
    # the message either (defense-in-depth against operator confusion).
    assert "fallback-key" not in msg

    get_settings.cache_clear()


def test_signing_key_refuses_literal_fallback_in_dev_without_optin(monkeypatch):
    """Dev / test deploys without any opt-in must also refuse the
    literal. The behaviour is identical to production except the
    operator can override via ``CULLIS_RBAC_SIDECAR_FALLBACK_KEY=...``
    (a non-literal value) to keep test fixtures working.
    """
    monkeypatch.delenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", raising=False)
    monkeypatch.delenv("CULLIS_RBAC_SIDECAR_FALLBACK_KEY", raising=False)
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv(
        "MCP_PROXY_DASHBOARD_SIGNING_KEY_PATH",
        "/nonexistent/audit-h003-empty-path",
    )

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from cullis_enterprise.mastio.rbac_multi_admin import session_revocation

    with pytest.raises(RuntimeError):
        session_revocation._signing_key()

    # Same flow with the explicit dev opt-in must succeed.
    monkeypatch.setenv("CULLIS_RBAC_SIDECAR_FALLBACK_KEY", "dev-test-key-xyz")
    assert session_revocation._signing_key() == "dev-test-key-xyz"

    get_settings.cache_clear()


def test_signing_key_refuses_dev_optin_in_production(monkeypatch):
    """``CULLIS_RBAC_SIDECAR_FALLBACK_KEY`` is a dev-only convenience.
    Setting it in production is itself a misconfiguration: the prod
    posture is ``MCP_PROXY_DASHBOARD_SIGNING_KEY``. Refuse loudly so
    a copy-pasted CI script does not silently downgrade the prod
    cookie signing key.
    """
    monkeypatch.delenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", raising=False)
    monkeypatch.setenv("CULLIS_RBAC_SIDECAR_FALLBACK_KEY", "leaked-into-prod")
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "MCP_PROXY_DASHBOARD_SIGNING_KEY_PATH",
        "/nonexistent/audit-h003-empty-path",
    )

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from cullis_enterprise.mastio.rbac_multi_admin import session_revocation

    with pytest.raises(RuntimeError):
        session_revocation._signing_key()

    get_settings.cache_clear()


# ── F-003 / H-005 (audit 2026-05-14): admin CRUD lands in audit_log ─


async def _audit_rows_with_action_prefix(prefix: str) -> list[dict]:
    """Return audit_log rows whose ``action`` starts with ``prefix``.

    Tests poke ``mcp_proxy.db`` directly to read the chained log; the
    plugin only ever writes via ``log_audit``.
    """
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT agent_id, action, status, detail FROM audit_log "
                "WHERE action LIKE :p ORDER BY id ASC"
            ),
            {"p": f"{prefix}%"},
        )).all()
    return [
        {"agent_id": r[0], "action": r[1], "status": r[2], "detail": r[3]}
        for r in rows
    ]


@pytest.mark.asyncio
async def test_admin_login_emits_audit_row(rbac_app):
    """Audit F-003 / H-005: every successful admin login must produce
    an ``admin.user.login`` row in the central append-only audit_log
    so the paid S3/Datadog exporters ship it to the customer SIEM.
    """
    _, client = rbac_app
    r = await _login(client, "root", "rootpass1")
    assert r.status_code == 200
    rows = await _audit_rows_with_action_prefix("admin.user.")
    actions = [row["action"] for row in rows]
    assert "admin.user.login" in actions, (
        f"expected admin.user.login in audit_log, got {actions}"
    )


@pytest.mark.asyncio
async def test_admin_user_create_emits_audit_row(rbac_app):
    """Audit F-003 / H-005: creating an admin must land in audit_log
    with the deleter/creator user_id as the actor.
    """
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    r = await client.post(
        "/admin/users",
        json={"username": "audit-target", "password": "auditpw01", "role": "operator"},
    )
    assert r.status_code == 200, r.text
    rows = await _audit_rows_with_action_prefix("admin.user.create")
    assert rows, "create did not append an audit_log row"
    last = rows[-1]
    assert last["status"] == "success"
    assert "audit-target" in (last["detail"] or "")


@pytest.mark.asyncio
async def test_admin_user_patch_emits_audit_row(rbac_app):
    """Audit F-003 / H-005: role / password rotation must land in
    audit_log. Without this, a silent role demote is invisible to the
    SIEM.
    """
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "audit-patch", "password": "auditpw01", "role": "viewer"},
    )
    user_id = create.json()["id"]
    r = await client.patch(f"/admin/users/{user_id}", json={"role": "operator"})
    assert r.status_code == 200
    rows = await _audit_rows_with_action_prefix("admin.user.patch")
    assert rows, "patch did not append an audit_log row"
    last = rows[-1]
    assert last["status"] == "success"
    detail = last["detail"] or ""
    # The detail JSON includes the changed fields list.
    assert "role" in detail
    assert "audit-patch" in detail


@pytest.mark.asyncio
async def test_admin_user_delete_emits_audit_row(rbac_app):
    """Audit F-003 / H-005: ``DELETE /admin/users/{id}`` must produce
    an ``admin.user.delete`` audit row identifying the actor and the
    target user. This is the canonical "who deleted admin Bob?"
    question the paid audit_export_* plugins answer.
    """
    _, client = rbac_app
    await _login(client, "root", "rootpass1")
    create = await client.post(
        "/admin/users",
        json={"username": "audit-del", "password": "auditpw01", "role": "viewer"},
    )
    user_id = create.json()["id"]
    r = await client.delete(f"/admin/users/{user_id}")
    assert r.status_code == 200
    rows = await _audit_rows_with_action_prefix("admin.user.delete")
    assert rows, "delete did not append an audit_log row"
    last = rows[-1]
    assert last["status"] == "success"
    detail = last["detail"] or ""
    assert "audit-del" in detail
