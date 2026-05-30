"""Capability enforcement gates introduced in Mastio v0.6.4 (#22, #23).

Validates:

  * ``/v1/chat/completions`` and ``/v1/llm/chat`` require ``llm.chat`` in
    ``InternalAgent.capabilities``; missing -> 403 + audit denied.
  * ``POST /v1/mcp`` ``tools/list`` requires ``mcp.tools.list`` in the
    token ``scope``; missing -> JSON-RPC error -32005 + audit denied.

The router is exercised with the auth dep overridden so we never need a
real DPoP+mTLS handshake. The LiteLLM dispatcher is patched on
``mcp_proxy.egress.llm_chat_router.dispatch`` so we never touch the
network. Mirrors the fixture shape used by the enterprise legacy tests
in ``cullis-enterprise/legacy/tests/test_proxy_llm_chat_router.py``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.ai_gateway import GatewayResult
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router
from mcp_proxy.egress.schemas import (
    ChatCompletionChoice,
    ChatCompletionResponse,
    ChatCompletionUsage,
    ChatMessage,
)
from mcp_proxy.egress import anthropic_messages_router as anthropic_module
from mcp_proxy.egress.anthropic_messages_router import router as anthropic_router
from mcp_proxy.ingress.mcp_aggregator import router as mcp_router
from mcp_proxy.models import InternalAgent, TokenPayload


# ── helpers ───────────────────────────────────────────────────────────


async def _audit_rows(action: str, status: str | None = None) -> list[dict]:
    sql = "SELECT agent_id, action, status, detail FROM audit_log WHERE action = :a"
    params: dict[str, object] = {"a": action}
    if status is not None:
        sql += " AND status = :s"
        params["s"] = status
    sql += " ORDER BY chain_seq ASC"
    async with get_db() as conn:
        result = await conn.execute(text(sql), params)
        return [dict(r._mapping) for r in result.fetchall()]


async def _local_audit_rows(event_type: str, result: str | None = None) -> list[dict]:
    sql = (
        "SELECT agent_id, event_type, result, details FROM local_audit "
        "WHERE event_type = :e"
    )
    params: dict[str, object] = {"e": event_type}
    if result is not None:
        sql += " AND result = :r"
        params["r"] = result
    sql += " ORDER BY chain_seq ASC"
    async with get_db() as conn:
        rows = await conn.execute(text(sql), params)
        return [dict(r._mapping) for r in rows.fetchall()]


def _agent(capabilities: list[str]) -> InternalAgent:
    return InternalAgent(
        agent_id="acme::alice",
        display_name="alice",
        capabilities=capabilities,
        created_at="2026-05-29T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-test",
        reach="both",
    )


def _token(scope: list[str]) -> TokenPayload:
    return TokenPayload(
        sub="spiffe://cullis.test/acme::alice",
        agent_id="acme::alice",
        org="acme",
        exp=9_999_999_999,
        iat=0,
        jti="jti-alice",
        scope=scope,
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


def _chat_body() -> dict:
    return {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }


def _gateway_result() -> GatewayResult:
    response = ChatCompletionResponse(
        id="chatcmpl-test",
        created=1_700_000_000,
        model="claude-haiku-4-5",
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content="pong"),
                finish_reason="stop",
            )
        ],
        usage=ChatCompletionUsage(
            prompt_tokens=12, completion_tokens=3, total_tokens=15,
        ),
        cullis_trace_id="trace_test",
    )
    return GatewayResult(
        response=response,
        latency_ms=42,
        upstream_request_id="req_abc",
        backend="litellm_embedded",
        provider="anthropic",
        prompt_tokens=12,
        completion_tokens=3,
        cost_usd=0.0001,
    )


# ── fixtures ──────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "capability.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-default")
    monkeypatch.setenv("MCP_PROXY_DPOP_JTI_SECRET", "test-dpop-jti-secret")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(llm_chat_router)
    app.include_router(anthropic_router)
    app.include_router(mcp_router)
    return app


# ── #22 — /v1/chat/completions + /v1/llm/chat require llm.chat ──────


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/llm/chat"])
async def test_chat_completion_denied_when_llm_chat_missing(
    proxy_db, monkeypatch, path
):
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent([])
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(side_effect=AssertionError("dispatch must not be called")),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(path, json=_chat_body())

    assert r.status_code == 403, r.text
    body = r.json()
    assert body["detail"]["reason"] == "capability_missing"
    assert body["detail"]["required_capability"] == "llm.chat"

    rows = await _audit_rows("egress_llm_chat", "denied")
    assert rows, "expected one denied audit row"
    import json as _json
    detail = _json.loads(rows[-1]["detail"])
    assert detail["reason"] == "capability_missing"
    assert detail["required_capability"] == "llm.chat"


@pytest.mark.asyncio
async def test_chat_completion_denied_when_wrong_capability(
    proxy_db, monkeypatch
):
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = (
        lambda: _agent(["mcp.tools.list"])
    )
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(side_effect=AssertionError("dispatch must not be called")),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "capability_missing"


@pytest.mark.asyncio
async def test_chat_completion_allowed_when_llm_chat_present(
    proxy_db, monkeypatch
):
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = (
        lambda: _agent(["llm.chat"])
    )
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["choices"][0]["message"]["content"] == "pong"

    denied = await _audit_rows("egress_llm_chat", "denied")
    assert not denied, "happy path must not emit a denied audit row"


@pytest.mark.asyncio
async def test_chat_completion_stream_denied_when_llm_chat_missing(
    proxy_db, monkeypatch
):
    """Stream branch must hit the same gate; dispatch_stream never runs."""
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent([])
    monkeypatch.setattr(
        router_module, "dispatch_stream",
        AsyncMock(side_effect=AssertionError("dispatch_stream must not be called")),
    )

    body = _chat_body() | {"stream": True}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=body)

    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "capability_missing"


# ── #23 — POST /v1/mcp tools/list requires mcp.tools.list ───────────


@pytest.mark.asyncio
async def test_mcp_tools_list_denied_when_capability_missing(proxy_db):
    app = _build_app()
    app.dependency_overrides[get_authenticated_agent] = lambda: _token([])

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/mcp", json=payload)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("error"), f"expected JSON-RPC error, got {body}"
    assert body["error"]["code"] == -32005
    assert "mcp.tools.list" in body["error"]["message"]
    assert body["error"]["data"]["required_capability"] == "mcp.tools.list"

    rows = await _local_audit_rows("mcp_tools_list", "denied")
    assert rows, "expected one denied local_audit row"


@pytest.mark.asyncio
async def test_mcp_tools_list_denied_when_wrong_capability(proxy_db):
    app = _build_app()
    app.dependency_overrides[get_authenticated_agent] = (
        lambda: _token(["llm.chat"])
    )

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/mcp", json=payload)

    body = r.json()
    assert body.get("error", {}).get("code") == -32005


# ── #22 (B1) — /v1/messages Anthropic shape requires llm.chat ────────


@pytest.mark.asyncio
async def test_anthropic_messages_denied_when_llm_chat_missing(
    proxy_db, monkeypatch
):
    """B1: /v1/messages was a documented mirror of /v1/chat/completions
    but pre-v0.6.4 did not enforce the capability gate."""
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent([])
    monkeypatch.setattr(
        anthropic_module, "dispatch",
        AsyncMock(side_effect=AssertionError("dispatch must not be called")),
    )

    body = {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/messages", json=body)

    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["reason"] == "capability_missing"
    assert detail["required_capability"] == "llm.chat"

    rows = await _audit_rows("egress_llm_chat", "denied")
    assert rows, "expected denied audit row from anthropic surface"
    import json as _json
    last = _json.loads(rows[-1]["detail"])
    assert last["surface"] == "anthropic_messages"
    assert last["reason"] == "capability_missing"


@pytest.mark.asyncio
async def test_anthropic_messages_allowed_when_llm_chat_present(
    proxy_db, monkeypatch
):
    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = (
        lambda: _agent(["llm.chat"])
    )
    monkeypatch.setattr(
        anthropic_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    body = {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/messages", json=body)

    assert r.status_code == 200, r.text
    payload = r.json()
    # Anthropic shape: content is a list with text blocks
    assert payload["content"][0]["text"] == "pong"


# ── #23 typed principal capability storage (migration 0045) ──────────


@pytest.mark.asyncio
async def test_typed_user_principal_denied_when_capability_missing(proxy_db):
    """User principal with empty capabilities (default post-migration)
    is denied on tools/list, same as an agent."""
    app = _build_app()
    app.dependency_overrides[get_authenticated_agent] = lambda: TokenPayload(
        sub="spiffe://cullis.test/acme::user::mario",
        agent_id="acme::user::mario",
        org="acme",
        exp=9_999_999_999,
        iat=0,
        jti="jti-mario",
        scope=[],  # post-migration default — admin grants explicit caps
        cnf={"jkt": "fake-jkt"},
        principal_type="user",
    )

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/mcp", json=payload)

    body = r.json()
    assert body["error"]["code"] == -32005
    assert "mcp.tools.list" in body["error"]["message"]


@pytest.mark.asyncio
async def test_typed_user_principal_allowed_when_capability_granted(
    proxy_db,
):
    """User principal with capabilities=['mcp.tools.list'] passes the
    method-level gate (binding remains the per-tool gate)."""
    app = _build_app()
    app.dependency_overrides[get_authenticated_agent] = lambda: TokenPayload(
        sub="spiffe://cullis.test/acme::user::anna",
        agent_id="acme::user::anna",
        org="acme",
        exp=9_999_999_999,
        iat=0,
        jti="jti-anna",
        scope=["mcp.tools.list"],
        cnf={"jkt": "fake-jkt"},
        principal_type="user",
    )

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/mcp", json=payload)

    body = r.json()
    assert "error" not in body, f"unexpected error: {body}"
    assert isinstance(body["result"]["tools"], list)


@pytest.mark.asyncio
async def test_get_principal_capabilities_round_trip(proxy_db):
    """Migration 0045 + db helper: capabilities are persisted and read
    back through ``get_principal_capabilities``."""
    from mcp_proxy.db import get_principal_capabilities

    # Insert a user row directly to bypass the admin API surface.
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_user_principals ("
                "  principal_id, user_name, display_name, reach, surface, "
                "  capabilities, created_at"
                ") VALUES ("
                "  :pid, 'mario', 'Mario', 'intra', NULL, :caps, '2026-05-28T00:00:00Z'"
                ")"
            ),
            {
                "pid": "acme::user::mario",
                "caps": '["mcp.tools.list","custom.read"]',
            },
        )

    caps = await get_principal_capabilities("acme::user::mario", "user")
    assert set(caps) == {"mcp.tools.list", "custom.read"}

    # Missing row -> []
    caps = await get_principal_capabilities("acme::user::ghost", "user")
    assert caps == []

    # Wrong type -> []
    caps = await get_principal_capabilities("acme::user::mario", "agent")
    assert caps == []


@pytest.mark.asyncio
async def test_mcp_tools_list_allowed_when_capability_present(proxy_db):
    """Capability passes the method-level gate; tools list may be empty
    (no bindings seeded) but no JSON-RPC error is returned."""
    app = _build_app()
    app.dependency_overrides[get_authenticated_agent] = (
        lambda: _token(["mcp.tools.list"])
    )

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/mcp", json=payload)

    body = r.json()
    assert "error" not in body, f"unexpected JSON-RPC error: {body}"
    assert "tools" in body["result"]
    assert isinstance(body["result"]["tools"], list)
