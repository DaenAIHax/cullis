"""SSRF rebinding pin — remaining callers (audit 2026-06-02).

Extends the H8/M7/M8 pin to the other outbound paths that validated but
didn't pin: federation peer PDP, MCP startup schema fetch, Ollama model
catalog, the Anthropic adapter (which didn't even validate), and the TSA
anchor POST (sync client). These tests cover the new sync transport, the
Anthropic adapter wiring, and the Ollama-catalog wiring as representative
of the async-inline call-sites.
"""
import httpx
import pytest

from mcp_proxy.utils.ssrf_transport import (
    SSRFPinnedSyncTransport,
    SSRFPinnedTransport,
)
from mcp_proxy.utils.url_safety import UnsafeUrlError


def test_sync_transport_pins_to_validated_ip(monkeypatch):
    monkeypatch.setattr(
        "mcp_proxy.utils.ssrf_transport.assert_safe_outbound_url",
        lambda url, allow_private=False: "93.184.216.34",
    )
    captured: dict = {}

    def fake_super(self, request):
        captured["request"] = request
        return httpx.Response(200)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_super)
    t = SSRFPinnedSyncTransport(allow_private=False)
    t.handle_request(httpx.Request("POST", "https://tsa.example/tsr"))

    assert captured["request"].url.host == "93.184.216.34"
    assert captured["request"].headers["Host"] == "tsa.example"
    assert captured["request"].extensions.get("sni_hostname") == "tsa.example"


def test_sync_transport_refuses_unsafe_before_connect(monkeypatch):
    def _refuse(url, allow_private=False):
        raise UnsafeUrlError("resolves to 169.254.169.254")

    monkeypatch.setattr(
        "mcp_proxy.utils.ssrf_transport.assert_safe_outbound_url", _refuse,
    )
    reached = {"super": False}

    def fake_super(self, request):
        reached["super"] = True
        return httpx.Response(200)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_super)
    t = SSRFPinnedSyncTransport()
    with pytest.raises(UnsafeUrlError):
        t.handle_request(httpx.Request("POST", "https://evil.example/x"))
    assert reached["super"] is False


def test_anthropic_client_installs_pinned_transport(monkeypatch):
    import anthropic

    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.adapters import anthropic as anthropic_adapter

    captured: dict = {}

    class _FakeAnthropic:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(anthropic, "AsyncAnthropic", _FakeAnthropic)
    anthropic_adapter._CLIENT_CACHE.clear()

    anthropic_adapter._client(
        {"api_key": "sk-ant-test", "base_url": "https://api.anthropic.com"},
        get_settings(),
    )
    assert "http_client" in captured
    assert isinstance(captured["http_client"]._transport, SSRFPinnedTransport)


@pytest.mark.asyncio
async def test_fetch_ollama_models_installs_pinned_transport(monkeypatch):
    from mcp_proxy.egress import provider_catalog

    captured: dict = {}

    class _FakeResp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"models": []}

    class _FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _FakeResp()

    monkeypatch.setattr(provider_catalog.httpx, "AsyncClient", _FakeClient)
    # Public IP literal → passes the real SSRF guard without DNS / network.
    await provider_catalog.fetch_ollama_models("http://1.1.1.1:11434")
    assert isinstance(captured.get("transport"), SSRFPinnedTransport)
