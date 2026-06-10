"""M7/M8 (audit 2026-06-02) — SSRF rebinding pin on the egress LLM adapters.

H8 fixed the MCP forwarder; M7 (OpenAI base_url) and M8 (Ollama api_base)
computed-but-discarded the validated IP and let httpx re-resolve at connect
time. SSRFPinnedTransport closes it for both: validate + pin, Host/SNI on
the real hostname. These tests assert the transport pins and that both
adapters install it.
"""
import httpx
import pytest

from mcp_proxy.utils.ssrf_transport import SSRFPinnedTransport
from mcp_proxy.utils.url_safety import UnsafeUrlError


@pytest.mark.asyncio
async def test_transport_pins_to_validated_ip(monkeypatch):
    # P2 (2026-06-10): the transport now validates through the async
    # wrapper (assert_safe_outbound_url_async, DNS off the event loop),
    # which calls the sync validator in its OWN module namespace — the
    # patch target moves from ssrf_transport to url_safety. Patching
    # the old name silently stopped intercepting and the test resolved
    # api.openai.com against live DNS.
    monkeypatch.setattr(
        "mcp_proxy.utils.url_safety.assert_safe_outbound_url",
        lambda url, allow_private=False: "93.184.216.34",
    )
    captured: dict = {}

    async def fake_super(self, request):
        captured["request"] = request
        return httpx.Response(200)

    monkeypatch.setattr(
        httpx.AsyncHTTPTransport, "handle_async_request", fake_super,
    )
    t = SSRFPinnedTransport(allow_private=False)
    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    resp = await t.handle_async_request(req)

    assert resp.status_code == 200
    pinned = captured["request"]
    assert pinned.url.host == "93.184.216.34"          # connect → validated IP
    assert pinned.headers["Host"] == "api.openai.com"  # routing → hostname
    assert pinned.extensions.get("sni_hostname") == "api.openai.com"  # TLS → hostname


@pytest.mark.asyncio
async def test_transport_refuses_unsafe_before_connect(monkeypatch):
    def _refuse(url, allow_private=False):
        raise UnsafeUrlError("resolves to 169.254.169.254 (metadata)")

    # Same namespace move as above (P2 async wrapper).
    monkeypatch.setattr(
        "mcp_proxy.utils.url_safety.assert_safe_outbound_url", _refuse,
    )
    reached = {"super": False}

    async def fake_super(self, request):
        reached["super"] = True
        return httpx.Response(200)

    monkeypatch.setattr(
        httpx.AsyncHTTPTransport, "handle_async_request", fake_super,
    )
    t = SSRFPinnedTransport(allow_private=False)
    with pytest.raises(UnsafeUrlError):
        await t.handle_async_request(httpx.Request("POST", "https://evil.example/x"))
    assert reached["super"] is False  # never connected


def test_ollama_client_installs_pinned_transport():
    from mcp_proxy.egress.adapters import ollama
    # Fresh cache key so we build a new client.
    client = ollama._get_http_client("http://ollama.local:11434", 30.0)
    assert isinstance(client._transport, SSRFPinnedTransport)


def test_openai_client_installs_pinned_transport(monkeypatch):
    import openai
    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.adapters import openai as openai_adapter

    captured: dict = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(openai, "AsyncOpenAI", _FakeOpenAI)
    # Avoid cache hits from other tests.
    openai_adapter._CLIENT_CACHE.clear()

    openai_adapter._client(
        {"api_key": "sk-test", "base_url": "https://api.openai.com/v1"},
        get_settings(),
    )
    assert "http_client" in captured
    assert isinstance(captured["http_client"]._transport, SSRFPinnedTransport)
