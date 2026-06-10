"""Tests for ``assert_safe_outbound_url_async`` (P2, review 2026-06-10).

The SSRF validation resolves DNS with a blocking ``socket.getaddrinfo``;
inline in a coroutine it stalled the event loop on every outbound LLM /
tool / federation call. The async wrapper runs the SAME code path on
the default thread pool — these tests pin the parity (same accept /
same reject, same exception type) so the wrapper can never drift into
a second, weaker validator.
"""
from __future__ import annotations

import pytest

from mcp_proxy.utils.url_safety import (
    UnsafeUrlError,
    assert_safe_outbound_url,
    assert_safe_outbound_url_async,
)

pytestmark = pytest.mark.asyncio


async def test_async_wrapper_accepts_what_sync_accepts():
    """IP-literal path needs no DNS — deterministic in CI."""
    sync_ip = assert_safe_outbound_url("https://8.8.8.8/x")
    async_ip = await assert_safe_outbound_url_async("https://8.8.8.8/x")
    assert async_ip == sync_ip == "8.8.8.8"


async def test_async_wrapper_rejects_private_ip():
    with pytest.raises(UnsafeUrlError):
        await assert_safe_outbound_url_async("http://169.254.169.254/iam")


async def test_async_wrapper_rejects_loopback_hostname():
    with pytest.raises(UnsafeUrlError):
        await assert_safe_outbound_url_async("http://localhost:11434/api")


async def test_async_wrapper_allow_private_passthrough():
    ip = await assert_safe_outbound_url_async(
        "http://127.0.0.1:11434/api", allow_private=True,
    )
    assert ip == "127.0.0.1"


async def test_async_wrapper_rejects_bad_scheme():
    with pytest.raises(UnsafeUrlError):
        await assert_safe_outbound_url_async("ftp://example.com/x")
