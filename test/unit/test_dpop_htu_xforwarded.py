"""Tests for D-12 X-Forwarded-* candidate assembly in ``_build_htu``.

Root cause: D-11 v2 (PR #939) widened the server-side htu acceptable
set to include ``str(request.url)``, the pinned proxy_public_url, and
the Host-header URL. The dogfood VM 2026-05-26 then revealed that
``str(request.url)`` itself was wrong: nginx forwarded ``Host:
192.168.122.62`` (with the ``$host`` variable stripping the ``:9443``
port the client actually dialled), so uvicorn reconstructed
``request.url`` without the port and none of the v2 candidates matched
the client-signed htu (which carries ``:9443``).

D-12 ships two coordinated changes:

  * nginx now forwards ``Host: $http_host`` (port preserved) and
    publishes the explicit ``X-Forwarded-{Host,Port,Proto}`` triplet.
  * ``_build_htu`` assembles an additional candidate URL from the
    triplet directly — belt-and-suspenders so the htu set still
    matches even if a future middleware ordering regression leaves
    ``request.url`` pointed at the upstream socket again.

This file pins the Python half (the candidate-assembly logic). The
nginx half lives in ``packaging/mastio-bundle/nginx/mastio/mastio.conf``
and is exercised via the bundle dogfood smoke; nginx config tests in
pytest would require booting the container which is the smoke gate's
job, not unit-test scope.

Invariants pinned:

1. ``_build_htu`` includes the URL implied by the X-Forwarded-* triplet
   when both ``X-Forwarded-Host`` (carrying port) and
   ``X-Forwarded-Proto`` are present.
2. When ``X-Forwarded-Host`` lacks a port and ``X-Forwarded-Port`` is
   set, the two are combined into ``host:port``.
3. When the X-Forwarded-* triplet is absent the candidate set still
   contains the Host-header URL (backward-compat with D-11 v2).
4. Bracketed IPv6 forwarded-host values keep their brackets and only
   combine with ``X-Forwarded-Port`` when the port is outside the
   brackets (``[::1]`` has no port, ``[::1]:9443`` already does).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _config_env(monkeypatch):
    """Reset settings + provide an admin secret so ``get_settings`` succeeds.

    ``_build_htu`` reads ``settings.proxy_public_url`` and the dev
    insecure-default refusal in ``validate_config`` would otherwise
    raise on the very first cache miss.
    """
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET",
        "test-admin-secret-not-the-default",
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _make_request(
    *,
    path: str = "/v1/llm/chat",
    request_url: str = "https://192.168.122.62/v1/llm/chat",
    request_scheme: str = "https",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Build a minimal ``Request`` mock for ``_build_htu``.

    The function only touches ``request.url.path``, ``request.url.scheme``,
    ``str(request.url)``, and ``request.headers.get(<name>)`` — no need
    to spin a real starlette Request.
    """
    request = MagicMock()
    request.url = MagicMock()
    request.url.path = path
    request.url.scheme = request_scheme
    request.url.__str__ = lambda self=None, _u=request_url: _u
    request.headers = headers or {}
    return request


def test_build_htu_includes_xforwarded_host_with_port(monkeypatch):
    """Forwarded-Host carrying its own port: candidate uses it verbatim.

    Scenario: nginx publishes ``X-Forwarded-Host: localhost:9443`` (the
    client-supplied Host with the port intact, courtesy of the D-12
    ``$http_host`` substitution), plus ``X-Forwarded-Port: 9443`` and
    ``X-Forwarded-Proto: https``. The assembled candidate must be
    ``https://localhost:9443/v1/llm/chat`` (no double-port).
    """
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.auth.dpop_client_cert import _build_htu

    request = _make_request(
        request_url="https://localhost/v1/llm/chat",  # uvicorn dropped port
        headers={
            "host": "localhost",
            "x-forwarded-host": "localhost:9443",
            "x-forwarded-port": "9443",
            "x-forwarded-proto": "https",
        },
    )

    result = _build_htu(request)

    assert isinstance(result, tuple)
    assert "https://localhost:9443/v1/llm/chat" in result, (
        "X-Forwarded triplet candidate missing; got "
        f"{result!r}"
    )
    # No double-port; the triplet candidate was assembled from the
    # already-portful Forwarded-Host and not appended with Port again.
    assert "https://localhost:9443:9443/v1/llm/chat" not in result


def test_build_htu_combines_host_and_port_when_host_lacks_port(monkeypatch):
    """Forwarded-Host has no port: combine with X-Forwarded-Port.

    Scenario: a proxy further upstream propagated ``X-Forwarded-Host:
    192.168.122.62`` (port stripped) but kept ``X-Forwarded-Port:
    9443``. The candidate must combine the two into
    ``https://192.168.122.62:9443/v1/llm/chat`` so the client-signed
    htu (which carries :9443) matches.
    """
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.auth.dpop_client_cert import _build_htu

    request = _make_request(
        request_url="https://192.168.122.62/v1/llm/chat",
        headers={
            "host": "192.168.122.62",
            "x-forwarded-host": "192.168.122.62",
            "x-forwarded-port": "9443",
            "x-forwarded-proto": "https",
        },
    )

    result = _build_htu(request)

    assert isinstance(result, tuple)
    assert "https://192.168.122.62:9443/v1/llm/chat" in result, (
        "combined Forwarded-Host + Forwarded-Port candidate missing; "
        f"got {result!r}"
    )


def test_build_htu_fallback_to_host_header_when_xforwarded_missing(monkeypatch):
    """No X-Forwarded-* headers: fall back to Host header (D-11 v2 path).

    Pure backward-compat pin: D-11 v2 already includes the Host-header
    URL in the candidate set, and the D-12 patch must not regress that
    behaviour for deploys where nginx hasn't been re-rolled yet.
    """
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.auth.dpop_client_cert import _build_htu

    request = _make_request(
        request_url="https://localhost:9443/v1/llm/chat",
        headers={"host": "localhost:9443"},
    )

    result = _build_htu(request)

    assert isinstance(result, tuple)
    # Host-header URL must still be reconstructed even without a
    # forwarded-host (the D-11 v2 candidate).
    assert "https://localhost:9443/v1/llm/chat" in result
    # And no X-Forwarded-* candidate is emitted when the headers are
    # absent (we don't fabricate one out of the Host header alone — the
    # Host-header branch already covers that shape).
    assert len(result) == len(set(result))


def test_build_htu_ipv6_forwarded_host_preserves_brackets(monkeypatch):
    """Bracketed IPv6 X-Forwarded-Host keeps brackets, port appends OUTSIDE.

    ``[::1]`` carries no port; combine with ``X-Forwarded-Port`` to
    yield ``https://[::1]:9443/...``. ``[::1]:9443`` already has the
    port outside the brackets so it must pass through verbatim.
    """
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.auth.dpop_client_cert import _build_htu

    # No port outside brackets → append Forwarded-Port.
    request_a = _make_request(
        request_url="https://[::1]/v1/llm/chat",
        headers={
            "host": "[::1]",
            "x-forwarded-host": "[::1]",
            "x-forwarded-port": "9443",
            "x-forwarded-proto": "https",
        },
    )
    result_a = _build_htu(request_a)
    assert "https://[::1]:9443/v1/llm/chat" in result_a, (
        f"bracketed-IPv6 + port-append missing; got {result_a!r}"
    )

    # Already has port outside brackets → pass through, do NOT append.
    request_b = _make_request(
        request_url="https://[::1]:9443/v1/llm/chat",
        headers={
            "host": "[::1]:9443",
            "x-forwarded-host": "[::1]:9443",
            "x-forwarded-port": "9443",
            "x-forwarded-proto": "https",
        },
    )
    result_b = _build_htu(request_b)
    assert "https://[::1]:9443/v1/llm/chat" in result_b
    # No double-port appended.
    assert "https://[::1]:9443:9443/v1/llm/chat" not in result_b
