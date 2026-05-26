"""D-14 tests, admin identity-bundle download endpoint.

Cold-reader dogfood (2026-05-26) revealed that the dashboard Create
Agent flow mints a TLS client cert plus private key, persists them,
and shows a banner instructing the admin to "Open the agent's detail
page to download cert + key" — but the only download endpoint shipped
was ``/env-download`` which returned a config-only ``.env`` with no
credential material. Admins had no way to deliver the minted identity
to the agent host.

The fix adds ``GET /proxy/agents/{id}/identity-bundle.zip`` which
returns a zip containing the four-file identity-dir layout the SDK
``CullisClient.from_identity_dir`` consumes (agent.crt, agent.key,
ca-chain.pem, meta.json). The tests below pin:

* the happy path: admin downloads, zip carries the expected files,
* the audit invariant: a download writes one
  ``agent.identity_bundle_downloaded`` row (the private key just left
  the server, the trail is non-negotiable),
* the 404 path: unknown agent_id,
* the 409 path: agent enrolled via BYOCA / SDK enrollment where the
  private key never reached the Mastio (no key to ship),
* the auth gate: unauthenticated requests get a 303 to /proxy/login.

The tests drive the dashboard router via httpx's ASGITransport inside
the same event loop pytest-asyncio runs on, so the SQLAlchemy +
aiosqlite engine stays bound to the loop that created it (the sync
``TestClient`` shim spins a worker thread with its own loop and the
engine refuses to share connections across loops).
"""
from __future__ import annotations

import io
import json
import time
import zipfile

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard import session as session_module
from mcp_proxy.dashboard.agents_routes import router as agents_router
from mcp_proxy.db import (
    create_agent as db_create_agent,
    dispose_db,
    get_db,
    init_db,
    set_config,
)


_ADMIN_SECRET = "test-admin-secret-identity-bundle"


def _build_signed_session_cookie(role: str = "admin") -> str:
    """Forge a valid dashboard session cookie for the test client.

    Uses the production ``_sign`` helper so the cookie carries the
    same HMAC the live ``require_login`` path verifies. Lets us drive
    admin-gated routes without going through /proxy/login (which is
    rate-limited + bcrypt-bound and would slow every test).
    """
    payload = json.dumps({
        "role": role,
        "roles": [role],
        "csrf_token": "test-csrf-token",
        "exp": int(time.time()) + 3600,
    })
    return session_module._sign(payload)


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite + full alembic chain for the dashboard route.

    Mirrors ``test_admin_agents_atomic_enroll.proxy_db`` so we get a
    realistic ``internal_agents`` schema (the dashboard route reads
    ``cert_pem`` and the resolver dict). Audit chain is forced off so
    ``log_audit`` writes inline (no background flush race).
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    # Deterministic session signing key so the cookie we forge round-trips
    # the same secret ``require_login`` verifies against.
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "a" * 64)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "identity_bundle.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _make_app() -> FastAPI:
    app = FastAPI()
    # The dashboard router mounts at ``/proxy`` in production via
    # ``mcp_proxy.dashboard.router.router`` (prefix lives on the
    # parent include). Replicate that here so the URL the tests hit
    # matches what the browser sees.
    app.include_router(agents_router, prefix="/proxy")
    return app


def _admin_client(app: FastAPI) -> AsyncClient:
    """ASGI-transport httpx client carrying a forged admin cookie."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={session_module._COOKIE_NAME: _build_signed_session_cookie("admin")},
    )


# ── Test 1: happy path ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_admin_downloads_identity_bundle_zip_with_expected_files(
    proxy_db,
):
    """Admin GET on /identity-bundle.zip returns a zip carrying
    agent.crt + agent.key + ca-chain.pem + meta.json. The four-file
    layout matches what ``CullisClient.from_identity_dir`` consumes.
    """
    agent_id = "test-org::alice"
    cert_pem = "-----BEGIN CERTIFICATE-----\nstub-cert\n-----END CERTIFICATE-----\n"
    key_pem = "-----BEGIN PRIVATE KEY-----\nstub-key\n-----END PRIVATE KEY-----\n"

    await db_create_agent(
        agent_id=agent_id,
        display_name="Alice",
        capabilities=["chat"],
        cert_pem=cert_pem,
    )
    # Stash the private key in the proxy_config fallback location the
    # AgentManager checks when Vault is not configured.
    await set_config(f"agent_key:{agent_id}", key_pem)
    await set_config(
        "mastio_ca_cert",
        "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----",
    )
    await set_config(
        "org_ca_cert",
        "-----BEGIN CERTIFICATE-----\norg-root\n-----END CERTIFICATE-----",
    )
    await set_config("org_id", "test-org")

    app = _make_app()
    async with _admin_client(app) as client:
        resp = await client.get(
            f"/proxy/agents/{agent_id}/identity-bundle.zip",
        )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "alice-identity.zip" in resp.headers["content-disposition"]
    assert resp.headers.get("x-content-type-options") == "nosniff"

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    assert {"agent.crt", "agent.key", "ca-chain.pem", "meta.json"}.issubset(names), names
    assert zf.read("agent.crt").decode() == cert_pem
    assert zf.read("agent.key").decode() == key_pem
    chain = zf.read("ca-chain.pem").decode()
    assert "intermediate" in chain and "org-root" in chain, (
        "ca-chain.pem must concatenate Mastio Intermediate || Org Root "
        f"so the SDK trust-store wires both, got: {chain!r}"
    )
    meta = json.loads(zf.read("meta.json"))
    assert meta["agent_id"] == agent_id
    assert meta["org_id"] == "test-org"
    assert meta["capabilities"] == ["chat"]


# ── Test 2: audit invariant ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_identity_bundle_emits_audit_row(proxy_db):
    """A successful download writes exactly one
    ``agent.identity_bundle_downloaded`` row. The private key just left
    the server, the trail must exist.
    """
    from sqlalchemy import text as _text

    agent_id = "test-org::bob"
    await db_create_agent(
        agent_id=agent_id,
        display_name="Bob",
        capabilities=[],
        cert_pem="-----BEGIN CERTIFICATE-----\nbob-cert\n-----END CERTIFICATE-----\n",
    )
    await set_config(
        f"agent_key:{agent_id}",
        "-----BEGIN PRIVATE KEY-----\nbob-key\n-----END PRIVATE KEY-----\n",
    )

    app = _make_app()
    async with _admin_client(app) as client:
        resp = await client.get(
            f"/proxy/agents/{agent_id}/identity-bundle.zip",
        )
    assert resp.status_code == 200, resp.text

    async with get_db() as conn:
        rows = (
            await conn.execute(
                _text(
                    "SELECT action, status FROM audit_log "
                    "WHERE agent_id = :aid "
                    "  AND action = 'agent.identity_bundle_downloaded'"
                ),
                {"aid": agent_id},
            )
        ).mappings().all()
    assert len(rows) == 1, (
        f"expected one identity_bundle_downloaded audit row, got {len(rows)}"
    )
    assert rows[0]["status"] == "success"


# ── Test 3: 404 on unknown agent ─────────────────────────────────────


@pytest.mark.asyncio
async def test_identity_bundle_404_for_unknown_agent(proxy_db):
    """Unknown agent_id resolves to a clean 404 (the route resolves the
    agent before any credential lookup so the operator gets a precise
    error instead of an opaque 409).
    """
    app = _make_app()
    async with _admin_client(app) as client:
        resp = await client.get(
            "/proxy/agents/test-org::ghost/identity-bundle.zip",
        )
    assert resp.status_code == 404, resp.text
    assert "not found" in resp.text.lower()


# ── Test 4: 409 when no private key is server-side ───────────────────


@pytest.mark.asyncio
async def test_identity_bundle_409_when_agent_has_no_private_key(proxy_db):
    """BYOCA / SDK-enrolled agents have a cert on the Mastio but the
    private key never touched the server. The endpoint must refuse
    with a 409 and a message pointing at the SDK enrol factory, never
    a 500 and never a zip carrying empty bytes for agent.key.
    """
    agent_id = "test-org::byoca"
    await db_create_agent(
        agent_id=agent_id,
        display_name="BYOCA",
        capabilities=[],
        cert_pem="-----BEGIN CERTIFICATE-----\nbyoca-cert\n-----END CERTIFICATE-----\n",
    )
    # Deliberately do NOT seed agent_key:{id} in proxy_config and do
    # NOT configure Vault. ``AgentManager.get_agent_credentials`` will
    # raise, the handler maps that to a 409.

    app = _make_app()
    async with _admin_client(app) as client:
        resp = await client.get(
            f"/proxy/agents/{agent_id}/identity-bundle.zip",
        )
    assert resp.status_code == 409, resp.text
    body = resp.text.lower()
    assert "private key" in body or "byoca" in body or "enroll" in body, (
        f"409 message should hint at the SDK enrol path, got: {resp.text!r}"
    )


# ── Test 5: auth gate ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_identity_bundle_requires_login(proxy_db):
    """No session cookie: the route redirects to /proxy/login (303),
    matching the ``require_login`` contract every other dashboard
    route honours.
    """
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        # ``follow_redirects=False`` (httpx default) so we see the 303
        # directly instead of chasing it into a 404 — the test app does
        # not mount the login router.
        resp = await client.get(
            "/proxy/agents/test-org::alice/identity-bundle.zip",
        )
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/proxy/login"
