"""Issue #1054 — hard-dependency outage at runtime returns 503 + Retry-After.

When Redis or Postgres drops *after* a clean boot, the request path fails
closed (correct), but a bare 500 (Redis) or a hung worker (Postgres) is not
graceful. main.py reshapes the relevant exceptions into a fast 503 +
Retry-After so an SDK / agent loop backs off and a load balancer can retry —
without granting the action (fail-closed stays fail-closed) and without
leaking the exception detail (H-IO-2).

These tests pin:
  1. the redis / sqlalchemy exception types are registered on the app, and
  2. the 503 response carries Retry-After + a generic body that does NOT echo
     the underlying exception message.
"""
from __future__ import annotations

import json

import pytest
from starlette.requests import Request


@pytest.fixture
def main_mod(monkeypatch):
    """Import mcp_proxy.main with the minimum env it needs to construct
    ProxySettings (admin secret gate) and skip the migration boot path."""
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-secret-not-the-default")
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    import mcp_proxy.main as m
    return m


def test_dependency_exception_handlers_registered(main_mod):
    from redis.exceptions import RedisError
    from sqlalchemy.exc import (
        InterfaceError,
        OperationalError,
        TimeoutError as SATimeoutError,
    )

    handlers = main_mod.app.exception_handlers
    # The four runtime-dependency exception types map to a 503 handler...
    assert RedisError in handlers
    assert OperationalError in handlers
    assert InterfaceError in handlers
    assert SATimeoutError in handlers
    # ...and the generic 500 fallback is still present for everything else.
    assert Exception in handlers


def _fake_request() -> Request:
    return Request({
        "type": "http", "method": "POST", "path": "/v1/llm/chat", "headers": [],
    })


def test_503_carries_retry_after_and_no_leak(main_mod):
    """The 503 body is generic; the exception message must not leak (it could
    carry a connection string)."""
    secret_looking = "postgresql://user:SUPERSECRET@db:5432/x command failed"
    resp = main_mod._dependency_unavailable(
        _fake_request(), RuntimeError(secret_looking), "Database",
    )
    assert resp.status_code == 503
    assert resp.headers["Retry-After"] == str(main_mod._DEPENDENCY_RETRY_AFTER_S)
    body = json.loads(bytes(resp.body))
    assert "temporarily unavailable" in body["detail"]
    # H-IO-2 — the raw exception text (and any secret in it) must NOT appear.
    assert "SUPERSECRET" not in bytes(resp.body).decode()
    assert secret_looking not in bytes(resp.body).decode()


def test_redis_and_db_dependency_labels(main_mod):
    redis_resp = main_mod._dependency_unavailable(
        _fake_request(), RuntimeError("x"), "Security store",
    )
    db_resp = main_mod._dependency_unavailable(
        _fake_request(), RuntimeError("x"), "Database",
    )
    assert redis_resp.status_code == db_resp.status_code == 503
    assert "Security store" in json.loads(bytes(redis_resp.body))["detail"]
    assert "Database" in json.loads(bytes(db_resp.body))["detail"]
