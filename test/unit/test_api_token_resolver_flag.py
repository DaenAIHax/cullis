"""F-B-15 — the culk_ resolver honours ``user_api_tokens_enabled``.

The boot gate (test_user_api_tokens_prod_gate.py) keeps production
honest at startup; these tests pin the runtime half: with the flag off
the resolver declines every request BEFORE any DB lookup, so tokens
already in the database stop authenticating immediately and the auth
chain falls through to the cert+DPoP path (whose 401 is the final
answer for a culk_-only client).
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from starlette.requests import Request

from mcp_proxy.db import dispose_db, init_db, mint_user_api_token

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    from _token_test_helpers import seed_default_test_principals
    await seed_default_test_principals()
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


def _request(token: str | None, path: str = "/v1/chat/completions") -> Request:
    from types import SimpleNamespace

    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "headers": headers,
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("mastio.test", 9443),
        "scheme": "https",
        # ``_maybe_local_internal_agent`` (step 1 of the chain) reads
        # ``request.app.state.local_issuer``; an empty state means "no
        # local issuer" and the chain proceeds to the cert path.
        "app": SimpleNamespace(state=SimpleNamespace()),
    }
    return Request(scope)


async def _mint(label: str = "resolver-test") -> str:
    minted = await mint_user_api_token(
        principal_id="acme::user::alice",
        label=label,
        created_by="acme::admin",
    )
    return minted["token"]


def _set_flag(monkeypatch, value: str) -> None:
    from mcp_proxy.config import get_settings

    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", value)
    get_settings.cache_clear()


async def test_flag_on_valid_token_resolves_principal(
    fresh_db, monkeypatch,
):
    _set_flag(monkeypatch, "true")
    token = await _mint()

    from mcp_proxy.auth.api_token import _maybe_api_token_principal

    agent = await _maybe_api_token_principal(_request(token))
    assert agent is not None
    assert agent.agent_id == "acme::user::alice"
    assert agent.principal_type == "user"
    assert agent.cert_pem is None and agent.dpop_jkt is None


async def test_flag_off_declines_without_db_lookup(fresh_db, monkeypatch):
    """The decline happens before the bcrypt verify: no DB round-trip,
    no timing surface, and tokens already minted stop working."""
    _set_flag(monkeypatch, "true")
    token = await _mint()
    _set_flag(monkeypatch, "false")

    import mcp_proxy.auth.api_token as api_token_mod

    calls = {"n": 0}

    async def _counting_verify(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("verify_user_api_token must not be called")

    monkeypatch.setattr(
        api_token_mod, "verify_user_api_token", _counting_verify,
    )

    agent = await api_token_mod._maybe_api_token_principal(_request(token))
    assert agent is None
    assert calls["n"] == 0


async def test_flag_off_chain_ends_in_401_for_culk_only_client(
    fresh_db, monkeypatch,
):
    """End-to-end through ``get_agent_from_dpop_client_cert``: a client
    that only has a culk_ token (no cert) gets a 401/403, not silent
    acceptance."""
    from fastapi import HTTPException

    _set_flag(monkeypatch, "true")
    token = await _mint(label="e2e")
    _set_flag(monkeypatch, "false")

    from mcp_proxy.auth.dpop_client_cert import (
        get_agent_from_dpop_client_cert,
    )

    with pytest.raises(HTTPException) as excinfo:
        await get_agent_from_dpop_client_cert(_request(token))
    assert excinfo.value.status_code in (401, 403)
