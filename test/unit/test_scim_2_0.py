"""scim_2_0 plugin tests — Bearer-auth SCIM 2.0 SP for Users + Groups."""
from __future__ import annotations

import importlib
import importlib.util
from typing import Iterator

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style "
        "to run scim_2_0 tests",
        allow_module_level=True,
    )

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


SCIM_TOKEN = "test-scim-token-fixed"


@pytest_asyncio.fixture
async def scim_app(tmp_path, monkeypatch) -> Iterator[tuple[FastAPI, AsyncClient]]:
    db_url = f"sqlite+aiosqlite:///{tmp_path}/scim.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)
    monkeypatch.setenv("CULLIS_SCIM_ENABLED", "1")
    monkeypatch.setenv("CULLIS_SCIM_BEARER_TOKEN", SCIM_TOKEN)
    monkeypatch.setenv("CULLIS_SCIM_DEFAULT_ROLE", "viewer")

    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.scim_2_0.plugin import Scim20Plugin
    plugin = Scim20Plugin()

    app = FastAPI()
    await plugin.startup(app)
    for r in plugin.routers():
        app.include_router(r)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.headers["Authorization"] = f"Bearer {SCIM_TOKEN}"
        yield app, client

    await dispose_db()
    get_settings.cache_clear()


# ── auth ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_bearer_returns_401(scim_app):
    _, client = scim_app
    client.headers.pop("Authorization", None)
    r = await client.get("/scim/v2/Users")
    assert r.status_code == 401
    body = r.json()
    assert body["detail"]["status"] == "401"


@pytest.mark.asyncio
async def test_wrong_bearer_returns_401(scim_app):
    _, client = scim_app
    client.headers["Authorization"] = "Bearer not-the-real-token"
    r = await client.get("/scim/v2/Users")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_unconfigured_token_returns_503(tmp_path, monkeypatch):
    db_url = f"sqlite+aiosqlite:///{tmp_path}/scim_unconf.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)
    monkeypatch.setenv("CULLIS_SCIM_ENABLED", "1")
    monkeypatch.delenv("CULLIS_SCIM_BEARER_TOKEN", raising=False)

    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.scim_2_0.plugin import Scim20Plugin
    plugin = Scim20Plugin()
    app = FastAPI()
    await plugin.startup(app)
    for r in plugin.routers():
        app.include_router(r)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        client.headers["Authorization"] = "Bearer anything"
        r = await client.get("/scim/v2/Users")
        assert r.status_code == 503
    await dispose_db()
    get_settings.cache_clear()


# ── ServiceProviderConfig ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_service_provider_config(scim_app):
    _, client = scim_app
    r = await client.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 200
    body = r.json()
    assert body["patch"]["supported"] is True
    assert body["bulk"]["supported"] is False
    assert body["authenticationSchemes"][0]["type"] == "oauthbearertoken"


# ── Users ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_and_list_users(scim_app):
    _, client = scim_app
    create = await client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "active": True,
        },
    )
    assert create.status_code == 201
    body = create.json()
    assert body["userName"] == "alice@example.com"
    assert body["meta"]["resourceType"] == "User"
    user_id = body["id"]

    listing = await client.get("/scim/v2/Users")
    assert listing.status_code == 200
    payload = listing.json()
    assert payload["totalResults"] == 1
    assert payload["Resources"][0]["id"] == user_id


@pytest.mark.asyncio
async def test_create_user_missing_username(scim_app):
    _, client = scim_app
    r = await client.post("/scim/v2/Users", json={"active": True})
    assert r.status_code == 400
    assert r.json()["detail"]["scimType"] == "invalidValue"


@pytest.mark.asyncio
async def test_create_duplicate_user(scim_app):
    _, client = scim_app
    body = {"userName": "dup@example.com"}
    r1 = await client.post("/scim/v2/Users", json=body)
    assert r1.status_code == 201
    r2 = await client.post("/scim/v2/Users", json=body)
    assert r2.status_code == 409
    assert r2.json()["detail"]["scimType"] == "uniqueness"


@pytest.mark.asyncio
async def test_get_user_by_id(scim_app):
    _, client = scim_app
    create = await client.post("/scim/v2/Users", json={"userName": "bob@example.com"})
    user_id = create.json()["id"]
    r = await client.get(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 200
    assert r.json()["userName"] == "bob@example.com"


@pytest.mark.asyncio
async def test_get_unknown_user_returns_404(scim_app):
    _, client = scim_app
    r = await client.get("/scim/v2/Users/9999")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_users_filter_username_eq(scim_app):
    _, client = scim_app
    await client.post("/scim/v2/Users", json={"userName": "first@x.com"})
    await client.post("/scim/v2/Users", json={"userName": "second@x.com"})
    r = await client.get(
        "/scim/v2/Users", params={"filter": 'userName eq "second@x.com"'},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "second@x.com"


@pytest.mark.asyncio
async def test_list_users_pagination(scim_app):
    _, client = scim_app
    for i in range(5):
        await client.post("/scim/v2/Users", json={"userName": f"u{i}@x.com"})
    r = await client.get("/scim/v2/Users", params={"startIndex": 2, "count": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["totalResults"] == 5
    assert body["startIndex"] == 2
    assert body["itemsPerPage"] == 2
    assert len(body["Resources"]) == 2


@pytest.mark.asyncio
async def test_delete_user(scim_app):
    _, client = scim_app
    create = await client.post("/scim/v2/Users", json={"userName": "del@x.com"})
    user_id = create.json()["id"]
    r = await client.delete(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 204
    r2 = await client.get(f"/scim/v2/Users/{user_id}")
    assert r2.status_code == 404


# ── Groups ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_group_empty(scim_app):
    _, client = scim_app
    r = await client.post(
        "/scim/v2/Groups",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["displayName"] == "Engineering"
    assert body["members"] == []


@pytest.mark.asyncio
async def test_create_group_with_members(scim_app):
    _, client = scim_app
    u1 = (await client.post("/scim/v2/Users", json={"userName": "g1@x.com"})).json()
    u2 = (await client.post("/scim/v2/Users", json={"userName": "g2@x.com"})).json()
    r = await client.post(
        "/scim/v2/Groups",
        json={
            "displayName": "Ops",
            "members": [
                {"value": u1["id"]},
                {"value": u2["id"]},
            ],
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert len(body["members"]) == 2
    member_ids = {m["value"] for m in body["members"]}
    assert member_ids == {u1["id"], u2["id"]}


@pytest.mark.asyncio
async def test_create_duplicate_group(scim_app):
    _, client = scim_app
    body = {"displayName": "Dup"}
    r1 = await client.post("/scim/v2/Groups", json=body)
    assert r1.status_code == 201
    r2 = await client.post("/scim/v2/Groups", json=body)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_patch_group_add_remove_members(scim_app):
    _, client = scim_app
    u = (await client.post("/scim/v2/Users", json={"userName": "p@x.com"})).json()
    g = (await client.post("/scim/v2/Groups", json={"displayName": "Patch"})).json()

    add = await client.patch(
        f"/scim/v2/Groups/{g['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": u["id"]}]},
            ],
        },
    )
    assert add.status_code == 200
    assert len(add.json()["members"]) == 1

    remove = await client.patch(
        f"/scim/v2/Groups/{g['id']}",
        json={
            "Operations": [
                {"op": "remove", "path": "members", "value": [{"value": u["id"]}]},
            ],
        },
    )
    assert remove.status_code == 200
    assert remove.json()["members"] == []


@pytest.mark.asyncio
async def test_patch_group_unsupported_path_returns_501(scim_app):
    _, client = scim_app
    g = (await client.post("/scim/v2/Groups", json={"displayName": "X"})).json()
    r = await client.patch(
        f"/scim/v2/Groups/{g['id']}",
        json={
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "Y"},
            ],
        },
    )
    assert r.status_code == 501
    assert "displayname" in r.json()["detail"]["detail"].lower()


@pytest.mark.asyncio
async def test_delete_group(scim_app):
    _, client = scim_app
    g = (await client.post("/scim/v2/Groups", json={"displayName": "Bye"})).json()
    r = await client.delete(f"/scim/v2/Groups/{g['id']}")
    assert r.status_code == 204
    r2 = await client.get(f"/scim/v2/Groups/{g['id']}")
    assert r2.status_code == 404


@pytest.mark.asyncio
async def test_create_user_uses_default_role(tmp_path, monkeypatch):
    """SCIM-provisioned user gets the configured CULLIS_SCIM_DEFAULT_ROLE."""
    db_url = f"sqlite+aiosqlite:///{tmp_path}/scim_role.db"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "k" * 64)
    monkeypatch.setenv("CULLIS_SCIM_BEARER_TOKEN", SCIM_TOKEN)
    monkeypatch.setenv("CULLIS_SCIM_DEFAULT_ROLE", "operator")

    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(db_url)

    from cullis_enterprise.mastio.scim_2_0.plugin import Scim20Plugin
    plugin = Scim20Plugin()
    app = FastAPI()
    await plugin.startup(app)
    for r in plugin.routers():
        app.include_router(r)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        client.headers["Authorization"] = f"Bearer {SCIM_TOKEN}"
        await client.post("/scim/v2/Users", json={"userName": "op@x.com"})

    from cullis_enterprise.mastio.rbac_multi_admin import models as rbac_models
    user = await rbac_models.get_user_by_username("op@x.com")
    assert user is not None
    assert user["role"] == "operator"

    await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_delete_last_admin_blocked(scim_app):
    """SCIM provisioner cannot lock the org out of its own admin."""
    _, client = scim_app
    # Promote a user to admin via the rbac models layer (simulating the
    # operator manually setting admin role through the dashboard).
    create = await client.post("/scim/v2/Users", json={"userName": "lone-admin@x.com"})
    user_id = int(create.json()["id"])
    from cullis_enterprise.mastio.rbac_multi_admin import models as rbac_models
    await rbac_models.update_role(user_id, "admin")
    r = await client.delete(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 409


# ── F-003 / H-005 (audit 2026-05-14): SCIM lifecycle hits audit_log ─


async def _scim_audit_rows() -> list[dict]:
    """Return audit_log rows with action prefix ``scim.``."""
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT agent_id, action, status, detail FROM audit_log "
                "WHERE action LIKE 'scim.%' ORDER BY id ASC"
            ),
        )).all()
    return [
        {"agent_id": r[0], "action": r[1], "status": r[2], "detail": r[3]}
        for r in rows
    ]


@pytest.mark.asyncio
async def test_scim_user_provision_emits_audit_row(scim_app):
    """Audit F-003 / H-005: an IdP-pushed user create must land in
    audit_log with the canonical ``scim_provisioner`` actor so the
    paid audit_export_* plugins ship the event to the customer SIEM.
    Pre-fix the event existed only in container stdout and was lost
    on restart.
    """
    _, client = scim_app
    r = await client.post(
        "/scim/v2/Users", json={"userName": "scim-audit-create@x.com"},
    )
    assert r.status_code == 201, r.text
    rows = await _scim_audit_rows()
    actions = [row["action"] for row in rows]
    assert "scim.user.provision" in actions, (
        f"expected scim.user.provision in audit_log, got {actions}"
    )
    last_provision = [row for row in rows if row["action"] == "scim.user.provision"][-1]
    assert last_provision["agent_id"] == "scim_provisioner"
    assert "scim-audit-create@x.com" in (last_provision["detail"] or "")


@pytest.mark.asyncio
async def test_scim_user_deprovision_emits_audit_row(scim_app):
    """Audit F-003 / H-005: SCIM-driven user delete must produce an
    ``scim.user.deprovision`` audit row. This is the canonical "which
    IdP push removed user X?" question the SIEM has to answer.
    """
    _, client = scim_app
    create = await client.post(
        "/scim/v2/Users", json={"userName": "scim-audit-del@x.com"},
    )
    user_id = int(create.json()["id"])
    r = await client.delete(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 204
    rows = await _scim_audit_rows()
    actions = [row["action"] for row in rows]
    assert "scim.user.deprovision" in actions, (
        f"expected scim.user.deprovision in audit_log, got {actions}"
    )


@pytest.mark.asyncio
async def test_scim_group_membership_change_emits_audit_row(scim_app):
    """Audit F-003 / H-005: group membership changes must land in
    audit_log. Without this, an IdP that pulls a user out of a
    security group is invisible to the SIEM.
    """
    _, client = scim_app
    user = (await client.post(
        "/scim/v2/Users", json={"userName": "scim-group-member@x.com"},
    )).json()
    group = (await client.post(
        "/scim/v2/Groups", json={"displayName": "audit-group"},
    )).json()
    r = await client.patch(
        f"/scim/v2/Groups/{group['id']}",
        json={
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": user["id"]}]},
            ],
        },
    )
    assert r.status_code == 200, r.text
    rows = await _scim_audit_rows()
    actions = [row["action"] for row in rows]
    assert "scim.group.create" in actions
    assert "scim.group.members.add" in actions, (
        f"expected scim.group.members.add in audit_log, got {actions}"
    )
