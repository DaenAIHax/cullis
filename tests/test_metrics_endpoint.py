"""
Tests for the /metrics Prometheus endpoint (Item 2 in plan.md).

The endpoint is opt-in via PROMETHEUS_ENABLED. When disabled the broker
returns 404 so external scrapers fail fast and operators notice the
misconfiguration.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_metrics_endpoint_returns_404_when_disabled(client: AsyncClient):
    """When PROMETHEUS_ENABLED=false (default in tests), /metrics is 404."""
    resp = await client.get("/metrics")
    assert resp.status_code == 404
    assert b"disabled" in resp.content.lower() or b"not found" in resp.content.lower()


async def test_metrics_endpoint_does_not_require_auth(client: AsyncClient):
    """The endpoint must be reachable without auth (Prometheus has no creds)."""
    resp = await client.get("/metrics")
    # 404 (disabled) or 200 (enabled), never 401/403
    assert resp.status_code in (404, 200)


async def test_metrics_endpoint_when_enabled(client: AsyncClient, monkeypatch):
    """When PROMETHEUS_ENABLED=true, /metrics returns the Prometheus text format."""
    from app.config import get_settings

    # Patch the cached settings to enable Prometheus for this test only.
    s = get_settings()
    monkeypatch.setattr(s, "prometheus_enabled", True)

    resp = await client.get("/metrics")
    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    # The Prometheus client uses "text/plain; version=0.0.4" or similar
    assert "text/plain" in content_type
    # The response should be the standard Prometheus exposition format
    body = resp.content.decode()
    # Even with no metrics yet collected, the endpoint should at least
    # return a valid (possibly empty) exposition. python_gc_objects etc.
    # come from the default REGISTRY.
    assert isinstance(body, str)
