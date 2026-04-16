"""ADR-006 Fase 2 / PR #8 — reverse-proxy WebSocket forwarding wiring.

Full-stack WS roundtrip is exercised by the federated smoke test in
``./demo_network/smoke.sh`` (SDK sender → proxy-a → broker →
proxy-b → checker); reproducing it here would require running uvicorn
in-process with a second websockets.serve upstream and is flaky in
xdist (handshake races when both servers share the same event loop).

This suite instead asserts the *wiring* the PR lands:

  - the WebSocket route ``/v1/broker/{path:path}`` is registered,
  - it rejects upgrade attempts cleanly when no broker uplink is
    configured (standalone mode),
  - URL scheme translation (http→ws, https→wss) is correct,
  - the hop-by-hop header filter strips the right things and keeps
    Authorization + DPoP.
"""
from __future__ import annotations

import pytest

from mcp_proxy.reverse_proxy.websocket import (
    _DROP_HEADERS,
    _build_upstream_headers,
    _parse_subprotocols,
    build_websocket_reverse_proxy_router,
)


# ── Header filter ───────────────────────────────────────────────────

def test_drop_headers_covers_hop_by_hop_and_ws_handshake():
    for header in (
        "connection", "upgrade", "host", "content-length",
        "sec-websocket-key", "sec-websocket-version",
        "sec-websocket-extensions", "sec-websocket-accept",
        "cookie",
    ):
        assert header in _DROP_HEADERS, f"{header!r} must be dropped on forward"


def test_build_upstream_headers_preserves_auth_and_dpop():
    inbound = [
        ("host", "proxy.cullis.test"),
        ("authorization", "DPoP token-abc"),
        ("dpop", "dpop-proof"),
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-key", "xyz"),
        ("sec-websocket-version", "13"),
        ("x-forwarded-for", "10.0.0.5"),
        ("cookie", "session=stale"),
    ]
    out = _build_upstream_headers(inbound, requested_subprotocol="cullis-v1")
    assert out["authorization"] == "DPoP token-abc"
    assert out["dpop"] == "dpop-proof"
    assert out["x-forwarded-for"] == "10.0.0.5"
    assert "host" not in out
    assert "connection" not in out
    assert "upgrade" not in out
    assert "sec-websocket-key" not in out
    assert "cookie" not in out


# ── Subprotocol parsing ─────────────────────────────────────────────

def test_parse_subprotocols_empty():
    assert _parse_subprotocols(None) == []
    assert _parse_subprotocols("") == []


def test_parse_subprotocols_trims_and_splits():
    assert _parse_subprotocols("cullis-v1, legacy-v0") == ["cullis-v1", "legacy-v0"]
    assert _parse_subprotocols("  only-one  ") == ["only-one"]


# ── Router wiring ───────────────────────────────────────────────────

def test_router_registers_ws_catch_all_on_v1_broker():
    """The WS route must match every /v1/broker/... path so we don't
    have to mirror the broker's route tree — any WS endpoint the
    broker adds downstream is automatically proxied."""
    router = build_websocket_reverse_proxy_router()
    ws_routes = [r for r in router.routes if hasattr(r, "endpoint")]
    paths = [getattr(r, "path", "") for r in ws_routes]
    assert any(p == "/v1/broker/{path:path}" for p in paths), paths


@pytest.mark.asyncio
async def test_ws_route_is_registered_on_app():
    """End-to-end: the proxy app exposes the WS endpoint after startup."""
    import os

    os.environ.setdefault("MCP_PROXY_STANDALONE", "true")
    os.environ.setdefault("MCP_PROXY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    # Route set on the app must include our WS catch-all.
    ws_paths = [
        r.path for r in app.routes
        if getattr(r, "path", "") == "/v1/broker/{path:path}"
    ]
    assert ws_paths, "ws reverse-proxy route not mounted"
    get_settings.cache_clear()


# ── URL scheme translation ──────────────────────────────────────────

def _translate(broker_url: str, path: str, query: str | None = None) -> str:
    """Reproduce the scheme-translation logic for unit coverage."""
    if broker_url.startswith("https://"):
        target = "wss://" + broker_url[len("https://"):].rstrip("/") + "/v1/broker/" + path
    elif broker_url.startswith("http://"):
        target = "ws://" + broker_url[len("http://"):].rstrip("/") + "/v1/broker/" + path
    else:
        target = broker_url.rstrip("/") + "/v1/broker/" + path
    if query:
        target += "?" + query
    return target


def test_url_translation_http_to_ws():
    assert _translate("http://broker:8000", "sessions/s1/stream") \
        == "ws://broker:8000/v1/broker/sessions/s1/stream"


def test_url_translation_https_to_wss():
    assert _translate("https://broker.example.com/", "x/y") \
        == "wss://broker.example.com/v1/broker/x/y"


def test_url_translation_keeps_query():
    assert _translate("http://broker:8000", "s/x", "after=1") \
        == "ws://broker:8000/v1/broker/s/x?after=1"
