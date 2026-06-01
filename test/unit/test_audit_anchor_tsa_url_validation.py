"""Production validator rejects mock-equivalent TSA anchor configurations.

Audit finding F-A-406 (2026-05-20) — the legacy ``app/config.py`` shipped
``audit_tsa_backend="mock"`` whose ``MockTsaClient`` returned an opaque
blob that was operationally "trust-equivalent to the broker database
itself". Production must declare intent (real RFC 3161 TSA or anchoring
disabled outright).

The current ``mcp_proxy`` audit-anchor implementation is RFC 3161-only,
so the operator-reachable mock-equivalent vector is pointing
``MCP_PROXY_AUDIT_ANCHOR_TSA_URL`` at a localhost / private-IP service
the operator (or an attacker on the LAN) controls. ``validate_config``
must refuse such configurations in production with a critical log and
``SystemExit(1)`` so the boot fails loudly rather than silently
collapsing the dispute-grade claim.

These tests pin the H4 sweep recurrence: production + private-IP TSA →
raise, production + real TSA URL → ok, non-production + private TSA → ok
(dev / sandbox stacks may run a local mock TSA on purpose).
"""
from __future__ import annotations

import pytest


_ADMIN_OK = "test-admin-secret-not-the-default"
_DB_ENC_OK = "0" * 64
_DASHBOARD_KEY_OK = "1" * 64
_PDP_HMAC_OK = "2" * 64
_VAULT_ADDR_OK = "https://vault.test.example:8200"
_VAULT_TOKEN_OK = "s.test-token"
_REAL_TSA_URL = "http://timestamp.digicert.com"
_PRIVATE_TSA_URL = "http://127.0.0.1:8080/tsr"


def _production_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the minimum production env vars so ``validate_config`` reaches
    the F-A-406 gate. Each individual H4 gate refuses earlier without
    these — the test is targeted at the audit-anchor URL gate alone.
    """
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", _DASHBOARD_KEY_OK)
    monkeypatch.setenv("MCP_PROXY_SECRET_BACKEND", "vault")
    monkeypatch.setenv("MCP_PROXY_VAULT_ADDR", _VAULT_ADDR_OK)
    monkeypatch.setenv("MCP_PROXY_VAULT_TOKEN", _VAULT_TOKEN_OK)
    monkeypatch.setenv("MCP_PROXY_VAULT_VERIFY_TLS", "true")
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "vault")
    monkeypatch.setenv("MCP_PROXY_DB_ENCRYPTION_KEY", _DB_ENC_OK)
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_ENFORCEMENT", "required")
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_RP_ID", "mastio.example")
    monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "required")  # F-B-11
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", _PDP_HMAC_OK)
    monkeypatch.setenv("MCP_PROXY_AUDIT_FAIL_DENY", "true")
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "false")


def _fresh_settings():
    """Return a fresh ``ProxySettings`` snapshot bypassing the lru_cache.

    ``get_settings`` is cached so a previous test (or the import-time
    boot) would otherwise pin a stale snapshot for the lifetime of the
    process.
    """
    from mcp_proxy.config import ProxySettings, get_settings

    get_settings.cache_clear()
    return ProxySettings()


@pytest.fixture(autouse=True)
def _require_webauthn(monkeypatch: pytest.MonkeyPatch):
    """Skip the test silently if the optional webauthn extra isn't
    installed in the runner — ``validate_config`` refuses to start with
    ``WEBAUTHN_ENFORCEMENT=required`` when the library is missing, which
    would mask the F-A-406 gate under test.
    """
    pytest.importorskip("webauthn")
    yield


def test_production_rejects_loopback_tsa_url(monkeypatch: pytest.MonkeyPatch):
    """Production + loopback TSA URL → SystemExit(1) with F-A-406 in log.

    A loopback / private-IP TSA is the operator-reachable
    mock-equivalent vector: the broker writes signed-looking tokens
    whose signer the operator (or an attacker on the same host)
    controls outright. The dispute-grade claim of the audit chain
    collapses silently. ``validate_config`` must refuse to start.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_TSA_URL", _PRIVATE_TSA_URL)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_rejects_empty_tsa_url_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + enabled anchoring + empty URL → SystemExit(1).

    The default ``MCP_PROXY_AUDIT_ANCHOR_TSA_URL`` is the real DigiCert
    public TSA, so an empty value is an explicit operator opt-out that
    contradicts ``AUDIT_ANCHOR_ENABLED=true``. Surface the contradiction
    at startup rather than booting clean with no anchoring target.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_accepts_real_public_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + DigiCert public TSA URL → no raise.

    The default ``http://timestamp.digicert.com`` resolves to a public
    IP and is the documented production target. The gate must not fire
    on the happy path or the bundle compose would fail to boot.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_TSA_URL", _REAL_TSA_URL)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_production_accepts_anchoring_disabled(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + ``AUDIT_ANCHOR_ENABLED=false`` → URL irrelevant.

    Air-gapped deploys disable anchoring outright; the gate must not
    inspect the URL in that case (operators may legitimately leave the
    URL pointing anywhere — even a private placeholder — when the
    feature is off).
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "false")
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_TSA_URL", _PRIVATE_TSA_URL)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_development_accepts_loopback_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Non-production + loopback TSA URL → no raise.

    Dev / sandbox stacks may run a local mock TSA on purpose (offline
    end-to-end tests, docker compose with a fake TSA service). The H4
    pattern only refuses in production — dev keeps the convenience.
    """
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_TSA_URL", _PRIVATE_TSA_URL)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_production_rejects_private_ip_literal_tsa(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + RFC 1918 private-IP literal TSA URL → SystemExit(1).

    Covers the alternate vector where the operator points the TSA URL
    at a private network range (192.168.0.0/16 / 10.0.0.0/8 / 172.16/12)
    instead of literal loopback — the trust model is the same: an
    attacker on the same LAN can spin up a fake TSA on that address and
    fabricate signed-looking tokens for any digest.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "http://192.168.42.7/tsr",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_rejects_ipv6_loopback_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + IPv6 loopback literal TSA URL → SystemExit(1).

    Same trust collapse as the IPv4 loopback case, exercised via the
    IPv6 literal ``::1``. ``mcp_proxy/utils/url_safety.py`` blocks this
    via ``IPv6Address.is_loopback``; this test pins the F-A-406 gate so
    a regression in ``url_safety.py`` would not slip past the 6
    pre-existing IPv4-only cases.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "http://[::1]/tsr",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_rejects_ipv6_link_local_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + IPv6 link-local TSA URL → SystemExit(1).

    ``fe80::/10`` is the IPv6 equivalent of the IPv4 ``169.254.0.0/16``
    surface that fronts cloud metadata IMDS endpoints. A TSA URL
    pointing there in production is operator-reachable mock-equivalent
    and trivially spoofable by anything on the same link.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "http://[fe80::1]/tsr",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_rejects_ipv6_ula_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + IPv6 ULA TSA URL → SystemExit(1).

    ``fc00::/7`` (RFC 4193 Unique Local Addresses) is the IPv6 analogue
    of RFC 1918 — a private range any LAN attacker can claim. The gate
    must refuse to anchor against an address in that range.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "http://[fd00::1]/tsr",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_rejects_localhost_hostname_tsa_url(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production + ``localhost`` hostname literal TSA URL → SystemExit(1).

    ``url_safety.py:155`` blocks the bare ``localhost`` string
    explicitly (separately from the ``127.0.0.1`` IPv4 literal already
    covered by ``test_production_rejects_loopback_tsa_url``). Pin the
    F-A-406 gate so a regression in that hostname allowlist would not
    pass the existing IP-only cases.
    """
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_ANCHOR_ENABLED", "true")
    monkeypatch.setenv(
        "MCP_PROXY_AUDIT_ANCHOR_TSA_URL", "http://localhost/tsr",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1
