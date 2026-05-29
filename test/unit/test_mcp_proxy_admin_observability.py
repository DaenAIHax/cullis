"""Tests for the circuit-breaker admin observability endpoint."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.admin.observability import router as obs_router
from mcp_proxy.config import get_settings
from mcp_proxy.middleware.db_latency_circuit_breaker import CircuitBreakerState


_ADMIN = "test-admin-secret-for-obs"


class _FakeTracker:
    def __init__(self, probe: float | None, passive: float | None,
                 probe_samples: int = 10, passive_samples: int = 10) -> None:
        self.probe = probe
        self.passive = passive
        self.probe_samples = probe_samples
        self.passive_samples = passive_samples

    def p99_ms(self):
        ready = [v for v in (self.probe, self.passive) if v is not None]
        effective = max(ready) if ready else None
        return (self.probe, self.passive, effective)

    def sample_counts(self):
        return (self.probe_samples, self.passive_samples)


@pytest.fixture(autouse=True)
def _pin_admin_secret(monkeypatch):
    """The endpoint reads the live settings; pin admin_secret for tests."""
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _build_app(tracker=None, state=None) -> FastAPI:
    app = FastAPI()
    app.include_router(obs_router)
    if tracker is not None:
        app.state.db_latency_tracker = tracker
    if state is not None:
        app.state.db_latency_cb_state = state
    return app


def test_endpoint_requires_admin_secret():
    app = _build_app()
    with TestClient(app) as client:
        r = client.get("/v1/admin/observability/circuit-breaker")
        assert r.status_code == 422 or r.status_code == 403
        # missing header → FastAPI returns 422 on the Header dep
        # (or 403 if the dep runs first). Either is an auth failure.


def test_endpoint_rejects_wrong_admin_secret():
    app = _build_app()
    with TestClient(app) as client:
        r = client.get(
            "/v1/admin/observability/circuit-breaker",
            headers={"X-Admin-Secret": "wrong"},
        )
        assert r.status_code == 403


def test_endpoint_returns_not_configured_payload_when_tracker_missing():
    """Before the lifespan wires the tracker + state the endpoint must
    return a deterministic payload, not 500."""
    app = _build_app()
    with TestClient(app) as client:
        r = client.get(
            "/v1/admin/observability/circuit-breaker",
            headers={"X-Admin-Secret": _ADMIN},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["probe_ready"] is False
        assert body["p99_ms_effective"] is None
        assert body["is_shedding"] is False
        assert body["shed_count_total"] == 0


def test_endpoint_surfaces_tracker_readings():
    tracker = _FakeTracker(probe=120.5, passive=340.9)
    state = CircuitBreakerState(
        activation_ms=500, deactivation_ms=350, max_shed_fraction=0.95,
    )
    app = _build_app(tracker=tracker, state=state)

    with TestClient(app) as client:
        r = client.get(
            "/v1/admin/observability/circuit-breaker",
            headers={"X-Admin-Secret": _ADMIN},
        )
        assert r.status_code == 200
        body = r.json()

    assert body["probe_ready"] is True
    assert body["p99_ms_probe"] == 120.5
    assert body["p99_ms_passive"] == 340.9
    assert body["p99_ms_effective"] == 340.9    # max(120.5, 340.9)
    assert body["probe_samples_in_window"] == 10
    assert body["passive_samples_in_window"] == 10
    assert body["is_shedding"] is False
    assert body["shed_fraction"] == 0.0
    assert body["activation_threshold_ms"] == 500.0
    assert body["deactivation_threshold_ms"] == 350.0
    assert body["max_shed_fraction"] == 0.95


def test_endpoint_reports_active_shedding_fraction():
    tracker = _FakeTracker(probe=1000.0, passive=900.0)
    state = CircuitBreakerState(
        activation_ms=500, deactivation_ms=350, max_shed_fraction=0.95,
    )
    # Manually open the breaker + record some sheds.
    state.update_state(1000.0)
    assert state.is_shedding is True
    for _ in range(7):
        state.record_shed()

    app = _build_app(tracker=tracker, state=state)
    with TestClient(app) as client:
        r = client.get(
            "/v1/admin/observability/circuit-breaker",
            headers={"X-Admin-Secret": _ADMIN},
        )

    body = r.json()
    assert body["is_shedding"] is True
    # effective p99 is max(1000, 900) = 1000 → halfway up the lerp
    # from 10% at 500 ms to 95% at 1500 ms: expected ≈ 0.525.
    assert 0.4 < body["shed_fraction"] < 0.65
    assert body["shed_count_total"] == 7
    assert body["shed_count_last_60s"] == 7
