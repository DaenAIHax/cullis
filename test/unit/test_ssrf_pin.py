"""H8 (audit 2026-06-02) — SSRF DNS-rebinding pin.

assert_safe_outbound_url validates a resolved IP and returns it so the
socket connect can be pinned. The WhitelistedTransport (MCP forwarder)
used to discard it and let httpx re-resolve at connect time — a TOCTOU a
rebinding record could exploit. These tests assert the request is pinned
to the validated IP while Host + TLS SNI stay on the real hostname.
"""
import httpx
import pytest

from mcp_proxy.utils.url_safety import pin_request_to_ip


def test_pin_rewrites_host_preserves_sni_and_host_header():
    req = httpx.Request("GET", "https://example.com:8443/path?q=1")
    pin_request_to_ip(req, "93.184.216.34")
    # Socket connects to the validated IP...
    assert req.url.host == "93.184.216.34"
    assert req.url.port == 8443
    # ...but HTTP routing and TLS cert verification stay on the hostname.
    assert req.headers["Host"] == "example.com:8443"
    assert req.extensions["sni_hostname"] == "example.com"


def test_pin_noop_on_ip_literal():
    req = httpx.Request("GET", "http://10.0.0.5/x")
    pin_request_to_ip(req, "10.0.0.5")
    assert req.url.host == "10.0.0.5"
    # No hostname was resolved → no rebinding window → no SNI override.
    assert "sni_hostname" not in req.extensions


@pytest.mark.asyncio
async def test_transport_pins_to_validated_ip(monkeypatch):
    """The forwarder transport connects to the IP assert_safe_outbound_url
    validated, not whatever the hostname re-resolves to at connect time."""
    import mcp_proxy.utils.url_safety as us
    from mcp_proxy.tools.http_whitelist import WhitelistedTransport

    # Simulate validation resolving example.com to a public IP.
    monkeypatch.setattr(
        us, "assert_safe_outbound_url",
        lambda url, allow_private=False: "93.184.216.34",
    )

    captured: dict = {}

    async def fake_super(self, request):
        captured["request"] = request
        return httpx.Response(200)

    monkeypatch.setattr(
        httpx.AsyncHTTPTransport, "handle_async_request", fake_super,
    )

    transport = WhitelistedTransport(allowed_domains=["example.com"])
    req = httpx.Request("GET", "https://example.com/v1/tools/call")
    resp = await transport.handle_async_request(req)

    assert resp.status_code == 200
    pinned = captured["request"]
    assert pinned.url.host == "93.184.216.34"  # connect goes to validated IP
    assert pinned.headers["Host"] == "example.com"
    assert pinned.extensions.get("sni_hostname") == "example.com"


@pytest.mark.asyncio
async def test_transport_still_rejects_unsafe_url(monkeypatch):
    """Pinning is additive — an unsafe URL is still refused before connect."""
    import mcp_proxy.utils.url_safety as us
    from mcp_proxy.tools.http_whitelist import WhitelistedTransport, ToolExecutionError

    def _refuse(url, allow_private=False):
        raise us.UnsafeUrlError("resolves to 169.254.169.254 (metadata)")

    monkeypatch.setattr(us, "assert_safe_outbound_url", _refuse)

    called = {"super": False}

    async def fake_super(self, request):
        called["super"] = True
        return httpx.Response(200)

    monkeypatch.setattr(
        httpx.AsyncHTTPTransport, "handle_async_request", fake_super,
    )

    transport = WhitelistedTransport(allowed_domains=["example.com"])
    req = httpx.Request("GET", "https://example.com/x")
    with pytest.raises(ToolExecutionError):
        await transport.handle_async_request(req)
    assert called["super"] is False  # never reached the connect
