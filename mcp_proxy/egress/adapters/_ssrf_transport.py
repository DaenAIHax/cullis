"""SSRF-pinned httpx transport for the egress LLM adapters.

M7/M8 follow-up to H8 (audit 2026-06-02). The OpenAI (base_url) and
Ollama (api_base) adapters reach an operator-configured provider URL.
H8 fixed the MCP forwarder by pinning the connect to the IP that
``assert_safe_outbound_url`` validated; the LLM adapters validated (Ollama)
or didn't (OpenAI) and in both cases let httpx re-resolve the hostname at
connect time — the same DNS-rebinding TOCTOU, here with the provider API
key on the wire.

This transport closes it for both adapters: it validates every outbound
request against the SSRF guard and pins the socket to the validated IP,
while ``pin_request_to_ip`` keeps the Host header + TLS SNI on the real
hostname (so api.openai.com / a real Ollama host still verify normally).
``allow_private`` follows ``policy_webhook_allow_private_ips`` so dev /
sandbox stacks reaching a daemon on the compose network keep working.
"""
from __future__ import annotations

import httpx

from mcp_proxy.utils.url_safety import (
    assert_safe_outbound_url,
    pin_request_to_ip,
)


class SSRFPinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that validates the outbound URL and pins the
    connect to the validated IP (defends against DNS rebinding)."""

    def __init__(self, *, allow_private: bool = False, **kwargs) -> None:
        self._allow_private = allow_private
        super().__init__(**kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Raises UnsafeUrlError (a ValueError) on a blocked/unresolvable
        # host — fail closed; the adapter surfaces it as a gateway error.
        pinned_ip = assert_safe_outbound_url(
            str(request.url), allow_private=self._allow_private,
        )
        pin_request_to_ip(request, pinned_ip)
        return await super().handle_async_request(request)


def allow_private_from_settings(settings) -> bool:
    """Mirror the knob the rest of the SSRF surface uses."""
    return bool(getattr(settings, "policy_webhook_allow_private_ips", False))
