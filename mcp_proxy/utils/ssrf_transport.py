"""SSRF-pinned httpx transports (async + sync).

H8 + M7/M8 + remaining-callers follow-up (audit 2026-06-02). Several
outbound paths reach an operator-configured URL (LLM provider base_url,
federation peer PDP, MCP schema fetch, Ollama tag list, TSA anchor) and
used to validate the URL with ``assert_safe_outbound_url`` but then let
httpx re-resolve the hostname at connect time — a DNS-rebinding TOCTOU
(public IP at validation, internal/IMDS IP at connect), sometimes with a
credential on the wire.

These transports close it everywhere: validate every outbound request
against the SSRF guard and pin the socket to the validated IP, while
``pin_request_to_ip`` keeps the Host header + TLS SNI on the real hostname
(so api.openai.com / a real Ollama host / a real TSA still verify
normally). ``allow_private`` follows ``policy_webhook_allow_private_ips``
so dev / sandbox stacks reaching a daemon on the compose network keep
working; the ``MCP_PROXY_INTERNAL_HOST_ALLOWLIST`` env is honoured by the
guard for explicit internal hosts.

Two variants because the codebase mixes async clients (LLM adapters,
federation, schema fetch, model catalog) and one sync client (the TSA
anchor POST in ``audit/tsa_client.py``).
"""
from __future__ import annotations

import httpx

from mcp_proxy.utils.url_safety import (
    assert_safe_outbound_url,
    pin_request_to_ip,
)


class SSRFPinnedTransport(httpx.AsyncHTTPTransport):
    """Async httpx transport that validates the outbound URL and pins the
    connect to the validated IP (defends against DNS rebinding)."""

    def __init__(self, *, allow_private: bool = False, **kwargs) -> None:
        self._allow_private = allow_private
        super().__init__(**kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Raises UnsafeUrlError (a ValueError) on a blocked/unresolvable
        # host — fail closed; the caller surfaces it as an error.
        pinned_ip = assert_safe_outbound_url(
            str(request.url), allow_private=self._allow_private,
        )
        pin_request_to_ip(request, pinned_ip)
        return await super().handle_async_request(request)


class SSRFPinnedSyncTransport(httpx.HTTPTransport):
    """Sync counterpart of :class:`SSRFPinnedTransport` for the one sync
    httpx.Client in the codebase (TSA anchor POST)."""

    def __init__(self, *, allow_private: bool = False, **kwargs) -> None:
        self._allow_private = allow_private
        super().__init__(**kwargs)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        pinned_ip = assert_safe_outbound_url(
            str(request.url), allow_private=self._allow_private,
        )
        pin_request_to_ip(request, pinned_ip)
        return super().handle_request(request)


def allow_private_from_settings(settings) -> bool:
    """Mirror the knob the rest of the SSRF surface uses."""
    return bool(getattr(settings, "policy_webhook_allow_private_ips", False))
