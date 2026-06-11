"""Dashboard secret-exposure fixes — blind-spot audit 2026-06-10.

DASH-1: ``POST /proxy/pki/rotate-ca`` must route the freshly minted Org
Root CA private key through the KMS provider (Fernet at-rest in
``pki_key_store`` when the master key is configured) instead of a
plaintext ``proxy_config`` upsert — a ``pg_dump`` between rotation and
the next boot-time legacy wipe would otherwise capture the root key
forever. Only the public cert may stay in ``proxy_config`` (the legacy
``/pki/ca.crt`` readers consume it).

DASH-2: the API-token mint POST must render the one-time ``culk_``
cleartext banner directly in its response body, never as a
``?new_token=`` redirect query param (nginx access logs ship to the
SIEM, plus browser history and Referer). The GET page must ignore the
legacy query param entirely.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from starlette.datastructures import QueryParams
from starlette.responses import RedirectResponse, Response

from mcp_proxy.db import dispose_db, get_config, init_db, set_config

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


class _Req:
    """Minimal request stand-in; every auth/CSRF consumer is patched."""

    def __init__(self, query: str = ""):
        self.query_params = QueryParams(query)


def _patch_dashboard_auth(monkeypatch, module):
    """Bypass the cookie-session + CSRF gates of a dashboard module."""
    session = object()
    monkeypatch.setattr(module, "require_login", lambda request: session)

    async def _csrf_ok(request, sess):
        return True

    monkeypatch.setattr(module, "verify_csrf", _csrf_ok)
    return session


# ── DASH-1: rotate-ca through the KMS provider ───────────────────────


@pytest_asyncio.fixture
async def rotate_env(fresh_db, monkeypatch):
    """Org configured + approval hook bypassed + fresh KMS resolution."""
    import mcp_proxy.dashboard.pki_routes as pki_routes
    from mcp_proxy.kms.factory import reset_kms_provider

    await set_config("org_id", "testorg0123456789")
    _patch_dashboard_auth(monkeypatch, pki_routes)

    async def _no_intercept(**kwargs):
        return None

    monkeypatch.setattr(
        pki_routes, "maybe_intercept_for_approval", _no_intercept,
    )
    reset_kms_provider()
    try:
        yield pki_routes
    finally:
        reset_kms_provider()


async def test_rotate_ca_encrypted_store_no_plaintext_key(
    rotate_env, monkeypatch,
):
    """With the at-rest master key set, the rotated private key lands
    Fernet-encrypted in ``pki_key_store`` and any stale plaintext
    ``org_ca_key`` row is dropped; ``proxy_config`` keeps only the cert."""
    monkeypatch.setenv("MCP_PROXY_DB_ENCRYPTION_KEY", "test-rotate-master-key")
    # Simulate a pre-hardening deploy that still carries a plaintext row.
    await set_config("org_ca_key", "-----BEGIN EC PRIVATE KEY-----stale")
    await set_config("org_ca_cert", "-----BEGIN CERTIFICATE-----stale")

    resp = await rotate_env.pki_rotate_ca(_Req())
    assert isinstance(resp, RedirectResponse)
    assert resp.headers["location"] == "/proxy/pki"

    assert await get_config("org_ca_key") is None, (
        "private key must never sit in plaintext proxy_config after rotate"
    )
    new_cert = await get_config("org_ca_cert")
    assert new_cert and "stale" not in new_cert
    assert "BEGIN CERTIFICATE" in new_cert

    from mcp_proxy.db import get_active_pki_key
    from mcp_proxy.kms.pki_at_rest import decrypt_pki_payload

    row = await get_active_pki_key("org_ca")
    assert row is not None, "rotated key must land in pki_key_store"
    key_pem, cert_pem = decrypt_pki_payload(row["ciphertext"])
    assert "PRIVATE KEY" in key_pem and "stale" not in key_pem
    assert cert_pem == new_cert


async def test_rotate_ca_dev_fallback_unchanged(rotate_env, monkeypatch):
    """Without the master key (dev/test only) the provider keeps the
    legacy plaintext rows so the next boot still finds the pair."""
    monkeypatch.delenv("MCP_PROXY_DB_ENCRYPTION_KEY", raising=False)

    resp = await rotate_env.pki_rotate_ca(_Req())
    assert isinstance(resp, RedirectResponse)

    key_pem = await get_config("org_ca_key")
    cert_pem = await get_config("org_ca_cert")
    assert key_pem and "PRIVATE KEY" in key_pem
    assert cert_pem and "BEGIN CERTIFICATE" in cert_pem


# ── DASH-2: mint renders the token in the body, never in the URL ─────


async def test_mint_renders_token_in_response_body_not_redirect(
    fresh_db, monkeypatch,
):
    import mcp_proxy.dashboard.api_tokens as api_tokens
    import mcp_proxy.dashboard.users_routes as users_routes

    from _token_test_helpers import seed_default_test_principals
    await seed_default_test_principals()

    _patch_dashboard_auth(monkeypatch, api_tokens)

    captured: dict = {}
    sentinel = Response(content="rendered", media_type="text/html")

    async def _fake_render(request, session, principal_id, **kwargs):
        captured["principal_id"] = principal_id
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(users_routes, "render_user_detail", _fake_render)

    resp = await api_tokens.create_api_token(
        "acme::user::alice", _Req(), label="ci-token",
        expires_at="", never_expires="on", scope_providers=None,
    )

    assert resp is sentinel, (
        "success path must render the page, not redirect with the token"
    )
    assert captured["principal_id"] == "acme::user::alice"
    assert captured["new_api_token"].startswith("culk_")
    assert captured["new_api_token_label"] == "ci-token"


async def test_mint_error_paths_still_redirect_without_secrets(
    fresh_db, monkeypatch,
):
    import mcp_proxy.dashboard.api_tokens as api_tokens

    _patch_dashboard_auth(monkeypatch, api_tokens)

    resp = await api_tokens.create_api_token(
        "acme::user::alice", _Req(), label="",
        expires_at="", never_expires="", scope_providers=None,
    )
    assert isinstance(resp, RedirectResponse)
    assert "token_error" in resp.headers["location"]
    assert "culk_" not in resp.headers["location"]


async def test_user_detail_get_ignores_legacy_new_token_param(
    fresh_db, monkeypatch,
):
    import mcp_proxy.dashboard.users_routes as users_routes

    monkeypatch.setattr(
        users_routes, "require_login", lambda request: object(),
    )

    async def _fake_view():
        return [{"principal_id": "acme::user::alice", "user_name": "alice"}], False

    monkeypatch.setattr(users_routes, "_build_user_view", _fake_view)
    monkeypatch.setattr(
        users_routes, "_ctx", lambda request, session, **kw: kw,
    )
    monkeypatch.setattr(
        users_routes.templates, "TemplateResponse", lambda name, ctx: ctx,
    )

    ctx = await users_routes.user_detail_page(
        "acme::user::alice",
        _Req("new_token=culk_leaked&new_token_label=x"),
    )

    assert ctx["new_api_token"] is None, (
        "a stale bookmarked ?new_token= URL must not re-render the banner"
    )
    assert ctx["new_api_token_label"] is None
