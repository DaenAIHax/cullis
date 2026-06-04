"""Issue #1055 — /readyz reflects the Redis backing store.

/health is liveness (process up) and stays 200 during a backing-store
outage so a transient blip doesn't restart-loop the pod. /readyz is
readiness: it already checked the DB; this adds the Redis check so that
when Redis is the configured backing (production, multi-worker) a Redis
outage — which makes the DPoP JTI / login-challenge path fail closed
(issue #1054) — reports not-ready and lets a load balancer drain the
worker, then re-admit it automatically when Redis recovers.

  Redis configured + reachable     → ready (200), redis: ok
  Redis configured + down          → not_ready (503), redis: error
  Redis not configured (dev/opt-in)→ ready (200), redis: not_configured
"""
from __future__ import annotations

import json

import pytest


@pytest.fixture
async def readyz_env(tmp_path, monkeypatch):
    """Clean-boot, healthy-chain, DB-up environment so readyz reaches the
    Redis check (everything before it must pass)."""
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-secret-not-the-default")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy import boot_state
    boot_state.reset_boot_refusal()
    from mcp_proxy.audit_chain import _reset_unhealthy_for_tests
    _reset_unhealthy_for_tests()

    from mcp_proxy.db import init_db, dispose_db
    db_file = tmp_path / "readyz.sqlite"
    await init_db(f"sqlite+aiosqlite:///{db_file}")
    yield
    await dispose_db()
    get_settings.cache_clear()


class _OkRedis:
    async def ping(self):
        return True


class _DownRedis:
    async def ping(self):
        raise ConnectionError("connection refused")


@pytest.mark.asyncio
async def test_readyz_ready_when_redis_reachable(readyz_env, monkeypatch):
    monkeypatch.setattr("mcp_proxy.redis.pool.get_redis", lambda: _OkRedis())
    from mcp_proxy.main import readyz

    result = await readyz()
    # Clean path returns a plain dict → 200.
    assert isinstance(result, dict)
    assert result["status"] == "ready"
    assert result["checks"]["redis"] == "ok"


@pytest.mark.asyncio
async def test_readyz_503_when_redis_down(readyz_env, monkeypatch):
    monkeypatch.setattr("mcp_proxy.redis.pool.get_redis", lambda: _DownRedis())
    from mcp_proxy.main import readyz

    resp = await readyz()
    assert resp.status_code == 503
    body = json.loads(bytes(resp.body))
    assert body["status"] == "not_ready"
    assert "redis" in body["checks"]
    # No leak — the class name, not the raw "connection refused" message.
    assert "connection refused" not in json.dumps(body)


@pytest.mark.asyncio
async def test_readyz_ready_when_redis_not_configured(readyz_env, monkeypatch):
    # Dev / single-worker in-memory opt-in: get_redis() returns None.
    monkeypatch.setattr("mcp_proxy.redis.pool.get_redis", lambda: None)
    from mcp_proxy.main import readyz

    result = await readyz()
    assert isinstance(result, dict)
    assert result["status"] == "ready"
    assert result["checks"]["redis"] == "not_configured"
