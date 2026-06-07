"""Per-agent cumulative LLM token budget — counter, resolution, enforcement.

PR follow-up to the usage dashboard (#1073). The display reads the audit
chain; this is the enforcement half. Pins:

1. ``sum_principal_tokens_since`` sums an agent's egress tokens over a
   window (the seed-from-chain input for the counter);
2. the in-memory counter seeds from the chain on a cold key and advances
   on ``add`` (Redis-less fallback path);
3. ``effective_budget`` resolves per-agent-override > global default, and
   a disabled row falls back to the default;
4. the egress router blocks an over-budget call with 429 +
   ``daily``/``monthly_budget_exceeded`` and a ``denied`` audit row,
   without calling dispatch; an under-budget / unbudgeted call passes and
   advances the counter.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import (
    dispose_db,
    get_agent_budget,
    get_db,
    init_db,
    sum_principal_tokens_since,
    upsert_agent_budget,
)
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.ai_gateway import GatewayResult
from mcp_proxy.egress.budget import (
    effective_budget,
    get_budget_counter,
    reset_budget_counter,
)
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router
from mcp_proxy.egress.schemas import (
    ChatCompletionChoice,
    ChatCompletionResponse,
    ChatCompletionUsage,
    ChatMessage,
)
from mcp_proxy.models import InternalAgent


# ── helpers ───────────────────────────────────────────────────────────


async def _insert_egress(rows: list[dict]) -> None:
    payload = [
        {
            "ts": r["ts"],
            "aid": r["aid"],
            "act": r.get("act", "egress_llm_chat"),
            "detail": json.dumps(r["detail"]) if r.get("detail") is not None else None,
        }
        for r in rows
    ]
    async with get_db() as db:
        await db.execute(
            text(
                "INSERT INTO audit_log (timestamp, agent_id, action, status, detail) "
                "VALUES (:ts, :aid, :act, 'success', :detail)"
            ),
            payload,
        )
        await db.commit()


async def _audit_rows(action: str, status: str) -> list[dict]:
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT agent_id, action, status, detail FROM audit_log "
                "WHERE action = :a AND status = :s ORDER BY id ASC"
            ),
            {"a": action, "s": status},
        )
        return [dict(r._mapping) for r in result.fetchall()]


def _agent(capabilities: list[str], agent_id: str = "acme::alice") -> InternalAgent:
    return InternalAgent(
        agent_id=agent_id,
        display_name="alice",
        capabilities=capabilities,
        created_at="2026-05-29T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-test",
        reach="both",
    )


def _chat_body() -> dict:
    return {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }


def _gateway_result(prompt: int = 12, completion: int = 3) -> GatewayResult:
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
            prompt_tokens=prompt, completion_tokens=completion,
            total_tokens=prompt + completion,
        ),
        cullis_trace_id="trace_test",
    )
    return GatewayResult(
        response=response,
        latency_ms=42,
        upstream_request_id="req_abc",
        backend="litellm_embedded",
        provider="anthropic",
        prompt_tokens=prompt,
        completion_tokens=completion,
        cost_usd=0.0001,
    )


def _today(hour: int = 10) -> str:
    return datetime.now(timezone.utc).replace(
        hour=hour, minute=0, second=0, microsecond=0
    ).isoformat()


# ── fixtures ──────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "budget.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-default")
    monkeypatch.setenv("MCP_PROXY_DPOP_JTI_SECRET", "test-dpop-jti-secret")
    monkeypatch.delenv("MCP_PROXY_REDIS_URL", raising=False)
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    # Redis-less + clean counter so each test starts from the chain.
    from mcp_proxy.redis.pool import reset_redis_for_tests

    reset_redis_for_tests()
    reset_budget_counter()
    try:
        yield url
    finally:
        await dispose_db()
        reset_budget_counter()
        get_settings.cache_clear()  # type: ignore[attr-defined]


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(llm_chat_router)
    return app


# ── 1. sum-tokens helper (seed-from-chain input) ────────────────────────


@pytest.mark.asyncio
async def test_sum_principal_tokens_scopes_agent_and_window(proxy_db):
    await _insert_egress(
        [
            {"ts": _today(), "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 40, "completion_tokens": 10}},
            {"ts": _today(11), "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 5, "completion_tokens": 5}},
            # Different agent — must not bleed in.
            {"ts": _today(), "aid": "acme::bob",
             "detail": {"provider": "anthropic", "prompt_tokens": 999, "completion_tokens": 999}},
            # Old row — excluded by the window.
            {"ts": "2020-01-01T00:00:00+00:00", "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 1000, "completion_tokens": 0}},
        ]
    )

    since = "2026-01-01T00:00:00+00:00"
    assert await sum_principal_tokens_since("acme::alice", since) == 60
    assert await sum_principal_tokens_since("acme::alice", None) == 1060
    assert await sum_principal_tokens_since("acme::nobody", None) == 0


# ── 2. in-memory counter seeds from the chain + advances ────────────────


@pytest.mark.asyncio
async def test_counter_seeds_from_chain_then_advances(proxy_db):
    await _insert_egress(
        [
            {"ts": _today(), "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 70, "completion_tokens": 30}},
        ]
    )
    now = datetime.now(timezone.utc)
    counter = get_budget_counter()

    day, month = await counter.current("acme::alice", now)
    assert day == 100, "cold key seeds from the chain's day sum"
    assert month == 100

    await counter.add("acme::alice", 25, now)
    day2, month2 = await counter.current("acme::alice", now)
    assert day2 == 125
    assert month2 == 125


# ── 3. effective_budget resolution ──────────────────────────────────────


@pytest.mark.asyncio
async def test_effective_budget_override_and_fallback(proxy_db, monkeypatch):
    from mcp_proxy.config import get_settings

    monkeypatch.setenv("MCP_PROXY_LLM_TOKENS_PER_DAY", "7000")
    monkeypatch.setenv("MCP_PROXY_LLM_TOKENS_PER_MONTH", "200000")
    get_settings.cache_clear()  # type: ignore[attr-defined]
    settings = get_settings()

    # No row → global default.
    assert await effective_budget("acme::alice", settings) == (7000, 200000)

    # Enabled row → override wins.
    await upsert_agent_budget(
        "acme::alice", tokens_per_day=10, tokens_per_month=0, enabled=True,
    )
    assert await effective_budget("acme::alice", settings) == (10, 0)

    # Disabled row → falls back to the global default.
    await upsert_agent_budget(
        "acme::alice", tokens_per_day=10, tokens_per_month=0, enabled=False,
    )
    assert await effective_budget("acme::alice", settings) == (7000, 200000)


# ── 4. router enforcement ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_over_daily_budget_blocks_with_429_and_audits_denied(proxy_db, monkeypatch):
    # Prior usage today already exceeds the tiny daily ceiling.
    await _insert_egress(
        [
            {"ts": _today(), "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 60, "completion_tokens": 40}},
        ]
    )
    await upsert_agent_budget("acme::alice", tokens_per_day=10, tokens_per_month=0)

    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent(["llm.chat"])
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(side_effect=AssertionError("dispatch must not run when over budget")),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 429, r.text
    assert r.json()["detail"]["reason"] == "daily_budget_exceeded"

    denied = await _audit_rows("egress_llm_chat", "denied")
    assert len(denied) == 1
    detail = json.loads(denied[0]["detail"])
    assert detail["reason"] == "daily_budget_exceeded"
    assert detail["budget_tokens_per_day"] == 10


@pytest.mark.asyncio
async def test_over_monthly_budget_blocks_with_429(proxy_db, monkeypatch):
    await _insert_egress(
        [
            {"ts": _today(), "aid": "acme::alice",
             "detail": {"provider": "anthropic", "prompt_tokens": 500, "completion_tokens": 0}},
        ]
    )
    # No daily ceiling (0), tight monthly ceiling.
    await upsert_agent_budget("acme::alice", tokens_per_day=0, tokens_per_month=100)

    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent(["llm.chat"])
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(side_effect=AssertionError("dispatch must not run when over budget")),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 429, r.text
    assert r.json()["detail"]["reason"] == "monthly_budget_exceeded"


@pytest.mark.asyncio
async def test_under_budget_passes_and_advances_counter(proxy_db, monkeypatch):
    await upsert_agent_budget("acme::alice", tokens_per_day=1_000_000, tokens_per_month=0)

    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent(["llm.chat"])
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result(prompt=12, completion=3)),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 200, r.text
    assert not await _audit_rows("egress_llm_chat", "denied")

    # The 15 tokens of this call advanced the counter.
    day, _ = await get_budget_counter().current("acme::alice", datetime.now(timezone.utc))
    assert day == 15


@pytest.mark.asyncio
async def test_no_budget_configured_skips_enforcement(proxy_db, monkeypatch):
    # No per-agent row, global defaults are 0 → budget path is a no-op.
    assert await get_agent_budget("acme::alice") is None

    app = _build_app()
    app.dependency_overrides[get_agent_from_dpop_client_cert] = lambda: _agent(["llm.chat"])
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/chat/completions", json=_chat_body())

    assert r.status_code == 200, r.text
