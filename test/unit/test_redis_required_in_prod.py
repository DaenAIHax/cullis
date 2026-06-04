"""S-4 — production refuses to boot without a shared security store.

Prod-shape stress test (2026-06-04) found that a ``deploy --prod`` bundle
booted green and then crashed the *first* agent login with HTTP 500:
``RuntimeError: DPoP JTI store requires Redis in production``. The DPoP JTI
store and the login-challenge store both raise at first use when Redis is
absent and in-memory stores aren't explicitly allowed
(``mcp_proxy/auth/dpop_jti_store.py`` / ``challenge_store.py``). The boot
validator only guarded the ``allow_inmemory=true`` branch (F-A-502); the
*default* (no Redis, no opt-in) wasn't gated, so the failure surfaced at
runtime instead of at boot.

These tests pin the boot gate that fails closed early:

  prod + no Redis + no opt-in                       → SystemExit(1)
  prod + Redis URL                                  → ok
  prod + in-memory opt-in + single-worker-vertical  → ok
  development + no Redis                            → ok (dev not gated)
"""
from __future__ import annotations

import pytest


_ADMIN_OK = "test-admin-secret-not-the-default"
_DB_ENC_OK = "0" * 64
_DASHBOARD_KEY_OK = "1" * 64
_PDP_HMAC_OK = "2" * 64
_VAULT_ADDR_OK = "https://vault.test.example:8200"
_VAULT_TOKEN_OK = "s.test-token"


def _production_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the production env vars that gate *before* the S-4 Redis gate so
    the test reaches it. Redis / in-memory opt-in are left to each test."""
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
    monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "required")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", _PDP_HMAC_OK)
    monkeypatch.setenv("MCP_PROXY_AUDIT_FAIL_DENY", "true")


def _fresh_settings():
    from mcp_proxy.config import ProxySettings, get_settings

    get_settings.cache_clear()
    return ProxySettings()


@pytest.fixture(autouse=True)
def _require_webauthn():
    """Production pins WEBAUTHN_ENFORCEMENT=required; skip if the optional
    extra is missing so the webauthn gate doesn't mask the S-4 gate."""
    pytest.importorskip("webauthn")
    yield


def test_production_without_redis_or_optin_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch,
):
    """The default prod posture (no Redis, no in-memory opt-in) must
    SystemExit at boot — otherwise the first agent login crashes 500."""
    _production_env(monkeypatch)
    monkeypatch.delenv("MCP_PROXY_REDIS_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "false")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_production_with_redis_url_boots(monkeypatch: pytest.MonkeyPatch):
    """A shared Redis is the recommended, multi-worker-safe posture."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "false")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_production_inmemory_optin_single_worker_boots(
    monkeypatch: pytest.MonkeyPatch,
):
    """Single-worker deploys may run Redis-free, but only with the explicit
    in-memory opt-in + single-worker-vertical topology (F-A-502)."""
    _production_env(monkeypatch)
    monkeypatch.delenv("MCP_PROXY_REDIS_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "true")
    monkeypatch.setenv(
        "MCP_PROXY_DEPLOYMENT_TOPOLOGY", "single-worker-vertical",
    )

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_development_without_redis_boots(monkeypatch: pytest.MonkeyPatch):
    """Dev mode is not gated — local stacks run Redis-free for convenience."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.delenv("MCP_PROXY_REDIS_URL", raising=False)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise
