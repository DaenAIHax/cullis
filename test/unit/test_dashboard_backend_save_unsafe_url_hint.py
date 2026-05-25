"""C-3 dogfood fix tests — ``_validate_endpoint_url`` operator hint.

When an operator saved an MCP backend whose endpoint URL pointed at a
private (RFC 1918) / loopback / cloud-metadata address, the dashboard
returned HTTP 400 with a bare ``endpoint_url: hostname '…' resolves to
… which is blocked: …`` detail. The two legitimate escape knobs
(``MCP_PROXY_INTERNAL_HOST_ALLOWLIST`` — FQDN-scoped, recommended;
``MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS`` — global dev/sandbox)
existed only in the source: every cold-reader operator hit the wall
silently. The bundle dogfood on 2026-05-25 (`mcp-pitchbook` on
172.18.0.3) surfaced this as finding C-3.

The fix preserves the default-deny posture (no change in *which* URLs
are accepted) and only stylises the 400 detail so the two escape paths
+ runbook are inline. These tests pin that contract.

The sister test pinning the same hint contract in the SDK enrollment
flow lives in ``test_enrollment_status_hint_on_missing_proof.py``
(PR #934). Keep them in sync if the hint copy ever changes.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard.mcp_resources import _validate_endpoint_url


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch):
    """Provide ``MCP_PROXY_ADMIN_SECRET`` so the lazy ``get_settings()``
    call inside ``_validate_endpoint_url`` can instantiate
    ``ProxySettings`` without tripping the F-A-507 boot gate. The hint
    logic itself does not depend on the secret value; we only need
    Pydantic settings to construct."""
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-c3-hint-secret-do-not-use")
    monkeypatch.delenv("MCP_PROXY_INTERNAL_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", raising=False)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    yield
    get_settings.cache_clear()  # type: ignore[attr-defined]


# Stable strings the dashboard error must surface. Lifted as constants
# so a copy edit in mcp_resources.py shows up here as a single failing
# assertion instead of five.
_HINT_ALLOWLIST_ENV = "MCP_PROXY_INTERNAL_HOST_ALLOWLIST"
_HINT_GLOBAL_ENV = "MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS"
_HINT_DOCS_PATH = "/docs/operate/internal-mcp-backends"


def _detail_of(exc: HTTPException) -> str:
    """Detail is built as a single multi-line string by the fix."""
    assert isinstance(exc.detail, str), (
        "detail must stay a plain str (HTMX dashboard renders it as-is); "
        f"got {type(exc.detail).__name__}"
    )
    return exc.detail


def test_blocked_rfc1918_ip_literal_surfaces_full_hint() -> None:
    """The bundle-dogfood path: an IP literal in the RFC 1918 range
    (e.g. a docker-bridge sibling) must return 400 with both escape
    knobs + the runbook URL inline."""
    with pytest.raises(HTTPException) as ei:
        _validate_endpoint_url("http://172.18.0.3:8080")

    assert ei.value.status_code == 400
    detail = _detail_of(ei.value)

    # Root cause from the SSRF guard is preserved verbatim.
    assert "172.18.0.3" in detail
    assert "private" in detail.lower() or "blocked" in detail.lower()

    # Both escape knobs are named with their exact env var spellings —
    # an operator must be able to grep --color the detail and copy the
    # variable name straight into proxy.env.
    assert _HINT_ALLOWLIST_ENV in detail
    assert _HINT_GLOBAL_ENV in detail

    # The runbook URL is linkable. Match the path (not the full URL)
    # so a docs hostname change does not break the test.
    assert _HINT_DOCS_PATH in detail


def test_blocked_hostname_quotes_the_fqdn_in_allowlist_suggestion() -> None:
    """When the URL has a resolvable hostname, the allowlist hint must
    quote the exact FQDN so the operator can paste it directly into
    ``MCP_PROXY_INTERNAL_HOST_ALLOWLIST=...``. The hostname must be
    one the platform resolves to an RFC 1918 address; we use a literal
    inside the loopback range (``127.0.0.1``) via the ``localhost``
    alias to keep the test offline."""
    with pytest.raises(HTTPException) as ei:
        _validate_endpoint_url("http://localhost:8080")

    detail = _detail_of(ei.value)
    # The hostname appears in single-quotes inside the hint.
    assert "'localhost'" in detail
    assert _HINT_ALLOWLIST_ENV in detail


def test_blocked_invalid_scheme_still_surfaces_hint() -> None:
    """A non-http(s) scheme (``file://``) is also rejected by the
    guard. The hint must still surface — an operator who fat-fingered
    the scheme deserves the same actionable detail."""
    with pytest.raises(HTTPException) as ei:
        _validate_endpoint_url("file:///etc/passwd")

    assert ei.value.status_code == 400
    detail = _detail_of(ei.value)
    # The original UnsafeUrlError message is preserved.
    assert "scheme" in detail.lower()
    # Hint stays attached even on non-private-IP rejections.
    assert _HINT_ALLOWLIST_ENV in detail
    assert _HINT_DOCS_PATH in detail


def test_blocked_empty_url_uses_placeholder_fqdn() -> None:
    """An empty URL triggers the guard early and has no hostname to
    suggest. The hint must still be coherent — a placeholder FQDN
    keeps the allowlist sentence readable instead of leaking a stray
    empty-quote ``''``."""
    with pytest.raises(HTTPException) as ei:
        _validate_endpoint_url("")

    detail = _detail_of(ei.value)
    assert "<your-mcp-fqdn>" in detail
    assert _HINT_ALLOWLIST_ENV in detail


def test_public_ip_literal_passes_without_exception() -> None:
    """Sanity: a globally-routable IP literal (1.1.1.1) bypasses the
    block path cleanly. Without this, a regression that always raises
    (e.g. someone moves the hint *outside* the except branch) would go
    unnoticed."""
    out = _validate_endpoint_url("http://1.1.1.1:8080")
    assert out == "http://1.1.1.1:8080"
