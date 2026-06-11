"""Budget hardening — EG-1 / EG-2 / EG-3 from the 2026-06-10 blind-spot audit.

EG-1: a client disconnect on ``/v1/chat/completions`` (stream) used to
land in the success branch with the adapter's drain-time token counts
still 0/0 — no budget charge and a ``success`` audit row claiming 0
tokens (indefinite evasion of the #1074 ceiling + falsified chain that
also poisons the seed-from-chain rebuild). A mid-stream GatewayError
never charged at all. Now: partial drains settle the budget from the
adapter's incremental counts or a char-count estimate, and write an
honest ``truncated`` (or ``error``) row.

EG-2: admission was check-then-spend with no reservation, so N
concurrent requests at 95% of the ceiling all passed. Now admission
posts an optimistic reservation that every terminal path settles
against actual usage.

EG-3: ``add`` could *create* a cold Redis key via INCRBY, making the
chain seed's ``SET NX`` lose — the whole period sum silently vanished.
Now the write path only adjusts keys the seed path created (both the
Redis Lua and the in-memory fallback enforce it), and refunds clamp
at 0.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import (
    dispose_db,
    get_db,
    init_db,
    sum_principal_tokens_since,
    upsert_agent_budget,
)
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.ai_gateway import GatewayError, StreamingDispatch
from mcp_proxy.egress.budget import get_budget_counter, reset_budget_counter
from mcp_proxy.egress.schemas import ChatCompletionRequest
from mcp_proxy.models import InternalAgent

pytestmark = pytest.mark.asyncio

AGENT_ID = "acme::alice"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "budget-hardening.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-default")
    monkeypatch.setenv("MCP_PROXY_DPOP_JTI_SECRET", "test-dpop-jti-secret")
    monkeypatch.delenv("MCP_PROXY_REDIS_URL", raising=False)
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    from mcp_proxy.redis.pool import reset_redis_for_tests

    reset_redis_for_tests()
    reset_budget_counter()
    try:
        yield url
    finally:
        await dispose_db()
        reset_budget_counter()
        get_settings.cache_clear()  # type: ignore[attr-defined]


async def _insert_egress(rows: list[dict]) -> None:
    payload = [
        {
            "ts": r["ts"],
            "aid": r["aid"],
            "act": r.get("act", "egress_llm_chat"),
            "status": r.get("status", "success"),
            "detail": json.dumps(r["detail"]) if r.get("detail") is not None else None,
        }
        for r in rows
    ]
    async with get_db() as db:
        await db.execute(
            text(
                "INSERT INTO audit_log (timestamp, agent_id, action, status, detail) "
                "VALUES (:ts, :aid, :act, :status, :detail)"
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


def _agent() -> InternalAgent:
    return InternalAgent(
        agent_id=AGENT_ID,
        display_name="alice",
        capabilities=["llm.chat"],
        created_at="2026-05-29T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-test",
        reach="both",
    )


def _today(hour: int = 10) -> str:
    return datetime.now(timezone.utc).replace(
        hour=hour, minute=0, second=0, microsecond=0
    ).isoformat()


def _stream_req(content: str = "ping") -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="claude-haiku-4-5",
        messages=[{"role": "user", "content": content}],
        max_tokens=16,
        stream=True,
    )


def _fake_streamer(chunks: list[dict], *, final_tokens: tuple[int, int] | None = None,
                   midstream_error: GatewayError | None = None) -> StreamingDispatch:
    """Streamer stand-in: yields ``chunks``; optionally raises mid-stream
    or reports drain-time usage like the real adapters do."""
    dispatch_obj = StreamingDispatch(
        backend="cullis_native",
        provider="anthropic",
        model="claude-haiku-4-5",
        trace_id="trace_test",
    )

    async def _aiter():
        for c in chunks:
            yield c
        if midstream_error is not None:
            raise midstream_error
        if final_tokens is not None:
            dispatch_obj.prompt_tokens, dispatch_obj.completion_tokens = final_tokens

    dispatch_obj._aiter_factory = _aiter
    return dispatch_obj


def _content_chunk(text_piece: str) -> dict:
    return {"choices": [{"delta": {"content": text_piece}}]}


# ── EG-3: the write path never creates a cold key ─────────────────────


async def test_add_delta_on_cold_key_is_dropped_not_created(proxy_db):
    """An adjustment racing the seed must not shadow the chain sum: the
    delta on an unseeded key is dropped and the next ``current`` seeds
    the full chain-derived total (which already includes that call's
    audit row)."""
    await _insert_egress(
        [{"ts": _today(), "aid": AGENT_ID,
          "detail": {"provider": "anthropic", "prompt_tokens": 70, "completion_tokens": 30}}]
    )
    now = datetime.now(timezone.utc)
    counter = get_budget_counter()

    # Write WITHOUT the mandatory prior ``current`` — pre-fix this
    # created the key with just 5 tokens and the 100-token chain seed
    # was lost to SET NX.
    await counter.add_delta(AGENT_ID, 5, now)

    day, month = await counter.current(AGENT_ID, now)
    assert day == 100, "chain seed must win over a racing increment"
    assert month == 100


async def test_refund_clamps_at_zero(proxy_db):
    now = datetime.now(timezone.utc)
    counter = get_budget_counter()

    day, _ = await counter.current(AGENT_ID, now)  # seeds 0 (empty chain)
    assert day == 0
    await counter.add(AGENT_ID, 10, now)
    await counter.add_delta(AGENT_ID, -50, now)

    day, month = await counter.current(AGENT_ID, now)
    assert day == 0, "an over-refund must clamp at 0, never go negative"
    assert month == 0


async def test_truncated_rows_feed_the_chain_seed(proxy_db):
    """``sum_principal_tokens_since`` filters on action only — the new
    ``truncated`` rows must keep feeding the budget seed."""
    await _insert_egress(
        [
            {"ts": _today(), "aid": AGENT_ID, "status": "success",
             "detail": {"prompt_tokens": 60, "completion_tokens": 0}},
            {"ts": _today(11), "aid": AGENT_ID, "status": "truncated",
             "detail": {"prompt_tokens": 30, "completion_tokens": 10, "tokens_estimated": True}},
        ]
    )
    assert await sum_principal_tokens_since(AGENT_ID, None) == 100


# ── EG-1: stream terminal accounting ──────────────────────────────────


async def _run_stream(streamer, *, reserve_tokens: int, consume_frames: int | None):
    """Drive ``_handle_stream``'s SSE generator; ``consume_frames=None``
    drains it fully, an int consumes that many frames then closes the
    generator (= client disconnect)."""
    from mcp_proxy.config import get_settings

    resp = await router_module._handle_stream(
        req=_stream_req(),
        agent=_agent(),
        settings=get_settings(),
        trace_id="trace_test",
        enforce_budget=True,
        reserve_tokens=reserve_tokens,
    )
    gen = resp.body_iterator
    if consume_frames is None:
        async for _ in gen:
            pass
        return
    consumed = 0
    async for _ in gen:
        consumed += 1
        if consumed >= consume_frames:
            break
    await gen.aclose()


async def _admit(reserve: int) -> None:
    """Simulate the admission step: seed via ``current`` + post the
    EG-2 reservation, exactly like the route does."""
    now = datetime.now(timezone.utc)
    counter = get_budget_counter()
    await counter.current(AGENT_ID, now)
    await counter.add_delta(AGENT_ID, reserve, now)


async def test_stream_disconnect_writes_truncated_and_charges_estimate(
    proxy_db, monkeypatch,
):
    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    # 2 content chunks × 20 chars observed before the disconnect; the
    # adapter (OpenAI-style) reports usage only at full drain → 0/0.
    streamer = _fake_streamer(
        [_content_chunk("x" * 20), _content_chunk("y" * 20), _content_chunk("z" * 20)],
    )
    monkeypatch.setattr(
        router_module, "dispatch_stream", AsyncMock(return_value=streamer),
    )

    reserve = 17  # prompt "ping" → 1 + max_tokens 16
    await _admit(reserve)
    await _run_stream(streamer, reserve_tokens=reserve, consume_frames=2)

    truncated = await _audit_rows("egress_llm_chat", "truncated")
    assert len(truncated) == 1, "a cut stream must not produce a success row"
    detail = json.loads(truncated[0]["detail"])
    assert detail["reason"] == "stream_not_drained"
    assert detail["tokens_estimated"] is True
    # prompt estimate ("ping" → 1) + observed 40 chars // 4 = 10.
    assert detail["prompt_tokens"] == 1
    assert detail["completion_tokens"] == 10
    assert not await _audit_rows("egress_llm_chat", "success")

    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 11, "the estimate must be charged (reservation settled)"


async def test_stream_disconnect_with_partial_report_estimates_completion(
    proxy_db, monkeypatch,
):
    """Anthropic-style: the adapter knows the prompt from message_start
    but never sees the final message_delta on a disconnect. The reported
    prompt must be kept and only the completion estimated."""
    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    streamer = _fake_streamer(
        [_content_chunk("x" * 20), _content_chunk("y" * 20), _content_chunk("z" * 20)],
    )
    streamer.prompt_tokens = 50  # incremental report (message_start)
    monkeypatch.setattr(
        router_module, "dispatch_stream", AsyncMock(return_value=streamer),
    )

    reserve = 17
    await _admit(reserve)
    await _run_stream(streamer, reserve_tokens=reserve, consume_frames=2)

    truncated = await _audit_rows("egress_llm_chat", "truncated")
    assert len(truncated) == 1
    detail = json.loads(truncated[0]["detail"])
    assert detail["prompt_tokens"] == 50, "reported prompt must win over the estimate"
    assert detail["completion_tokens"] == 10, "observed 40 chars // 4"
    assert detail["tokens_estimated"] is True

    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 60


async def test_stream_full_drain_success_charges_reported(proxy_db, monkeypatch):
    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    streamer = _fake_streamer(
        [_content_chunk("hello")], final_tokens=(70, 30),
    )
    monkeypatch.setattr(
        router_module, "dispatch_stream", AsyncMock(return_value=streamer),
    )

    reserve = 17
    await _admit(reserve)
    await _run_stream(streamer, reserve_tokens=reserve, consume_frames=None)

    success = await _audit_rows("egress_llm_chat", "success")
    assert len(success) == 1
    detail = json.loads(success[0]["detail"])
    assert detail["prompt_tokens"] == 70
    assert detail["completion_tokens"] == 30
    assert "tokens_estimated" not in detail
    assert not await _audit_rows("egress_llm_chat", "truncated")

    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 100, "reported usage charged, reservation refunded"


async def test_stream_midstream_error_charges_observed(proxy_db, monkeypatch):
    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    streamer = _fake_streamer(
        [_content_chunk("w" * 40)],
        midstream_error=GatewayError(502, "provider_unreachable", detail="boom"),
    )
    monkeypatch.setattr(
        router_module, "dispatch_stream", AsyncMock(return_value=streamer),
    )

    reserve = 17
    await _admit(reserve)
    await _run_stream(streamer, reserve_tokens=reserve, consume_frames=None)

    errors = await _audit_rows("egress_llm_chat", "error")
    assert len(errors) == 1
    detail = json.loads(errors[0]["detail"])
    assert detail["reason"] == "provider_unreachable"
    assert detail["tokens_estimated"] is True
    assert detail["prompt_tokens"] == 1
    assert detail["completion_tokens"] == 10

    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 11, "mid-stream errors must charge what was observed"


async def test_stream_error_before_first_byte_refunds_everything(
    proxy_db, monkeypatch,
):
    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    streamer = _fake_streamer(
        [], midstream_error=GatewayError(502, "provider_unreachable", detail="boom"),
    )
    monkeypatch.setattr(
        router_module, "dispatch_stream", AsyncMock(return_value=streamer),
    )

    reserve = 17
    await _admit(reserve)
    await _run_stream(streamer, reserve_tokens=reserve, consume_frames=None)

    errors = await _audit_rows("egress_llm_chat", "error")
    assert len(errors) == 1
    detail = json.loads(errors[0]["detail"])
    assert detail["prompt_tokens"] == 0
    assert detail["completion_tokens"] == 0

    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 0, "nothing observed → full reservation refund"


# ── EG-2: admission reservation visible to concurrent requests ────────


async def test_reservation_is_posted_before_dispatch(proxy_db, monkeypatch):
    """While a request is in flight, its reservation must already count
    against the budget a concurrent admission reads."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
    from mcp_proxy.egress.llm_chat_router import router as llm_chat_router

    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)

    seen: dict = {}

    async def _probe_dispatch(**kwargs):
        day, _ = await get_budget_counter().current(
            AGENT_ID, datetime.now(timezone.utc),
        )
        seen["mid_flight_day"] = day
        # Reuse the shape helpers from the sibling budget test module.
        from test_agent_llm_budget import _gateway_result

        return _gateway_result(prompt=12, completion=3)

    monkeypatch.setattr(router_module, "dispatch", _probe_dispatch)

    app = FastAPI()
    app.include_router(llm_chat_router)
    app.dependency_overrides[get_agent_from_dpop_client_cert] = _agent

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/v1/chat/completions",
            json={
                "model": "claude-haiku-4-5",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 16,
            },
        )

    assert r.status_code == 200, r.text
    # Reservation = prompt estimate ("ping" → 1) + max_tokens 16.
    assert seen["mid_flight_day"] == 17, (
        "a concurrent admission must see this request's reservation"
    )
    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 15, "settled to actual usage at end of request"


async def test_nonstream_gateway_error_refunds_reservation(proxy_db, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
    from mcp_proxy.egress.llm_chat_router import router as llm_chat_router

    await upsert_agent_budget(AGENT_ID, tokens_per_day=1_000_000, tokens_per_month=0)
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(side_effect=GatewayError(502, "provider_unreachable", detail="boom")),
    )

    app = FastAPI()
    app.include_router(llm_chat_router)
    app.dependency_overrides[get_agent_from_dpop_client_cert] = _agent

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/v1/chat/completions",
            json={
                "model": "claude-haiku-4-5",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 16,
            },
        )

    assert r.status_code == 502
    day, _ = await get_budget_counter().current(
        AGENT_ID, datetime.now(timezone.utc),
    )
    assert day == 0, "pre-response failure must refund the full reservation"
