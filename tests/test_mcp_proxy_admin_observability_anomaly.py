"""GET /v1/admin/observability/anomaly-detector — ADR-013 Phase 4 c6.

Covers:
- Auth: wrong admin secret → 403.
- Detector not wired (startup race / mode=off): deterministic zero-ish
  payload with config reflected from settings.
- DB-backed 24h counts are returned even when the evaluator is absent.
- When evaluator + recorder are present, their counters flow through.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

pytestmark = pytest.mark.asyncio


async def _spin_proxy(tmp_path, monkeypatch, org_id: str = "anomaly-obs"):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    from mcp_proxy.main import app

    return app


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _headers():
    from mcp_proxy.config import get_settings

    return {"X-Admin-Secret": get_settings().admin_secret}


async def _seed_event(app, *, agent_id: str, mode: str, offset: timedelta) -> None:
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode) VALUES (:a, :t, :m)"
            ),
            {
                "a": agent_id,
                "t": _iso(datetime.now(timezone.utc) - offset),
                "m": mode,
            },
        )


async def test_requires_admin_secret(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers={"X-Admin-Secret": "wrong"},
            )
    assert r.status_code == 403


async def test_mode_off_returns_default_shape(tmp_path, monkeypatch):
    """With ``anomaly_quarantine_mode=off`` the lifespan skips wiring
    the evaluator, and the endpoint falls back to a deterministic
    settings-only snapshot so dashboards don't 500 when the detector
    is intentionally disabled.
    """
    monkeypatch.setenv("MCP_PROXY_ANOMALY_QUARANTINE_MODE", "off")
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers=await _headers(),
            )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "off"
    assert body["startup_ts"] is None
    assert body["cycles_run"] == 0
    assert body["quarantines_last_24h"] == 0
    assert body["config"]["ratio_threshold"] == 10.0
    assert body["config"]["abs_threshold_rps"] == 100.0
    assert body["config"]["ceiling_per_min"] == 3


async def test_shadow_mode_default_wires_evaluator(tmp_path, monkeypatch):
    """Default config → lifespan wires detector in shadow mode.

    Validates the commit 7 wiring: evaluator + recorder land on
    app.state, the endpoint reports their state, cycles_run is a
    real live counter rather than the fallback zero.
    """
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            # Detector is wired: attributes exist on app.state.
            assert hasattr(app.state, "anomaly_evaluator")
            assert hasattr(app.state, "traffic_recorder")
            assert hasattr(app.state, "baseline_rollup")
            assert hasattr(app.state, "quarantine_expiry")

            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers=await _headers(),
            )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "shadow"
    assert body["startup_ts"] is not None


async def test_24h_counts_reflect_db_events(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            # Inside window: 2 enforce + 1 shadow.
            await _seed_event(app, agent_id="a", mode="enforce", offset=timedelta(hours=1))
            await _seed_event(app, agent_id="b", mode="enforce", offset=timedelta(hours=12))
            await _seed_event(app, agent_id="c", mode="shadow", offset=timedelta(hours=2))
            # Outside window: ignored.
            await _seed_event(app, agent_id="d", mode="enforce", offset=timedelta(hours=30))

            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers=await _headers(),
            )
    assert r.status_code == 200
    body = r.json()
    assert body["quarantines_last_24h"] == 2
    assert body["quarantines_last_24h_shadow_only"] == 1


async def test_evaluator_wired_flows_through_counters(tmp_path, monkeypatch):
    """When app.state.anomaly_evaluator is set, the endpoint reports its
    counters instead of the fallback zeros."""
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.db import _require_engine
            from mcp_proxy.observability.anomaly_evaluator import AnomalyEvaluator

            engine = _require_engine()
            ev = AnomalyEvaluator(
                engine, mode="enforce", ratio_threshold=42.0
            )
            ev.cycles_run = 17
            ev.quarantines_enforce_total = 3
            ev.quarantines_shadow_total = 0
            ev.meta_breaker.ceiling_trips_total = 1
            app.state.anomaly_evaluator = ev

            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers=await _headers(),
            )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "enforce"
    assert body["cycles_run"] == 17
    assert body["quarantines_enforce_total"] == 3
    assert body["meta_ceiling_trips_total"] == 1
    assert body["config"]["ratio_threshold"] == 42.0
