"""LLM usage metering — aggregation + dashboard view.

The usage page derives per-provider and per-agent token totals read-time
from the audit chain (``aggregate_llm_usage`` in :mod:`mcp_proxy.db`):
every ``egress_llm_chat`` row carries ``prompt_tokens`` /
``completion_tokens`` / ``cost_usd`` / ``provider`` in its JSON ``detail``.
These tests pin:

1. tokens aggregate correctly per provider and per agent, with grand totals;
2. non-``egress_llm_chat`` rows and rows with missing token fields don't
   inflate the totals (missing → 0);
3. the ``window_start`` cutoff scopes the sum to the time window;
4. ``cost_usd`` is summed only where the provider reported it (best-effort);
5. the route wiring maps GET /usage to ``usage_page`` and threads the
   aggregates into the template context.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import text
from starlette.datastructures import QueryParams

from mcp_proxy.db import aggregate_llm_usage, dispose_db, get_db, init_db


async def _insert_egress(rows: list[dict]) -> None:
    """Insert ``egress_llm_chat`` audit rows with a JSON ``detail``."""
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


@pytest.fixture
async def usage_db(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-usage")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    url = f"sqlite+aiosqlite:///{tmp_path / 'usage.db'}"
    await init_db(url)
    yield url
    await dispose_db()
    get_settings.cache_clear()


def _by_key(rows: list[dict]) -> dict[str, dict]:
    return {r["key"]: r for r in rows}


@pytest.mark.asyncio
async def test_aggregates_per_provider_and_per_agent(usage_db):
    await _insert_egress(
        [
            {"ts": "2026-06-07T10:00:00+00:00", "aid": "acme::kyc",
             "detail": {"provider": "anthropic", "prompt_tokens": 100, "completion_tokens": 20}},
            {"ts": "2026-06-07T10:01:00+00:00", "aid": "acme::kyc",
             "detail": {"provider": "anthropic", "prompt_tokens": 50, "completion_tokens": 10}},
            {"ts": "2026-06-07T10:02:00+00:00", "aid": "acme::rebalance",
             "detail": {"provider": "openai", "prompt_tokens": 200, "completion_tokens": 100}},
        ]
    )

    out = await aggregate_llm_usage(None)

    prov = _by_key(out["by_provider"])
    assert prov["anthropic"]["calls"] == 2
    assert prov["anthropic"]["prompt_tokens"] == 150
    assert prov["anthropic"]["completion_tokens"] == 30
    assert prov["anthropic"]["total_tokens"] == 180
    assert prov["openai"]["total_tokens"] == 300

    agent = _by_key(out["by_agent"])
    assert agent["acme::kyc"]["total_tokens"] == 180
    assert agent["acme::rebalance"]["total_tokens"] == 300

    assert out["totals"]["calls"] == 3
    assert out["totals"]["total_tokens"] == 480
    # Descending by total tokens: openai (300) before anthropic (180).
    assert out["by_provider"][0]["key"] == "openai"


@pytest.mark.asyncio
async def test_non_egress_and_missing_tokens_do_not_inflate(usage_db):
    await _insert_egress(
        [
            # A real egress row.
            {"ts": "2026-06-07T10:00:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic", "prompt_tokens": 10, "completion_tokens": 5}},
            # Wrong action — must be ignored entirely.
            {"ts": "2026-06-07T10:01:00+00:00", "aid": "acme::a", "act": "auth.login",
             "detail": {"provider": "anthropic", "prompt_tokens": 9999, "completion_tokens": 9999}},
            # egress but no token fields — counts as a call, 0 tokens.
            {"ts": "2026-06-07T10:02:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic"}},
            # egress with null detail — skipped (no payload).
            {"ts": "2026-06-07T10:03:00+00:00", "aid": "acme::a", "detail": None},
        ]
    )

    out = await aggregate_llm_usage(None)

    assert out["totals"]["total_tokens"] == 15, "only the real egress tokens count"
    # The no-token egress row still counts as a call; the null-detail row does not.
    assert out["totals"]["calls"] == 2
    prov = _by_key(out["by_provider"])
    assert prov["anthropic"]["total_tokens"] == 15


@pytest.mark.asyncio
async def test_window_start_scopes_the_sum(usage_db):
    await _insert_egress(
        [
            {"ts": "2020-01-01T00:00:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic", "prompt_tokens": 1000, "completion_tokens": 0}},
            {"ts": "2026-06-07T10:00:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic", "prompt_tokens": 7, "completion_tokens": 0}},
        ]
    )

    all_time = await aggregate_llm_usage(None)
    assert all_time["totals"]["total_tokens"] == 1007

    windowed = await aggregate_llm_usage("2026-01-01T00:00:00+00:00")
    assert windowed["totals"]["total_tokens"] == 7, "old row is outside the window"


@pytest.mark.asyncio
async def test_cost_summed_only_where_present(usage_db):
    await _insert_egress(
        [
            {"ts": "2026-06-07T10:00:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic", "prompt_tokens": 10, "completion_tokens": 0,
                        "cost_usd": 0.25}},
            {"ts": "2026-06-07T10:01:00+00:00", "aid": "acme::a",
             "detail": {"provider": "anthropic", "prompt_tokens": 10, "completion_tokens": 0,
                        "cost_usd": None}},
        ]
    )

    out = await aggregate_llm_usage(None)
    assert out["totals"]["has_cost"] is True
    assert out["totals"]["cost_usd"] == pytest.approx(0.25)


def test_usage_route_maps_to_usage_page():
    """GET /usage must decorate ``usage_page`` — guards against a misplaced
    decorator (the class of bug that turned GET /audit into a 422)."""
    import mcp_proxy.dashboard.usage_routes as ur

    routes = [
        r for r in ur.router.routes
        if getattr(r, "path", None) == "/usage"
        and "GET" in getattr(r, "methods", set())
    ]
    assert routes, "GET /usage route not registered"
    assert routes[0].endpoint is ur.usage_page


@pytest.mark.asyncio
async def test_usage_page_threads_aggregates_into_context(usage_db):
    await _insert_egress(
        [
            {"ts": "2026-06-07T10:00:00+00:00", "aid": "acme::kyc",
             "detail": {"provider": "anthropic", "prompt_tokens": 100, "completion_tokens": 20}},
        ]
    )

    import mcp_proxy.dashboard.usage_routes as ur

    class _Req:
        query_params = QueryParams("window=all")

    orig_login = ur.require_login
    orig_ctx = ur._ctx
    orig_tr = ur.templates.TemplateResponse
    ur.require_login = lambda request: {"username": "admin"}
    ur._ctx = lambda request, session, **kw: kw
    ur.templates.TemplateResponse = lambda name, ctx: ctx
    try:
        ctx = await ur.usage_page(_Req())
    finally:
        ur.require_login = orig_login
        ur._ctx = orig_ctx
        ur.templates.TemplateResponse = orig_tr

    assert ctx["active"] == "usage"
    assert ctx["window"] == "all"
    assert ctx["totals"]["total_tokens"] == 120
    assert _by_key(ctx["by_provider"])["anthropic"]["total_tokens"] == 120
    assert _by_key(ctx["by_agent"])["acme::kyc"]["total_tokens"] == 120


@pytest.mark.asyncio
async def test_usage_page_defaults_invalid_window(usage_db):
    import mcp_proxy.dashboard.usage_routes as ur

    class _Req:
        query_params = QueryParams("window=bogus")

    orig_login = ur.require_login
    orig_ctx = ur._ctx
    orig_tr = ur.templates.TemplateResponse
    ur.require_login = lambda request: {"username": "admin"}
    ur._ctx = lambda request, session, **kw: kw
    ur.templates.TemplateResponse = lambda name, ctx: ctx
    try:
        ctx = await ur.usage_page(_Req())
    finally:
        ur.require_login = orig_login
        ur._ctx = orig_ctx
        ur.templates.TemplateResponse = orig_tr

    assert ctx["window"] == "30d", "unknown window falls back to the default"
