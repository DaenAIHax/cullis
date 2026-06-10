"""F-B-15 — production gates the culk_ user API token surface.

Claim-alignment review (2026-06-10): a ``culk_*`` token is a plain
Bearer credential — no mTLS client cert, no RFC 9449 key-possession
proof — accepted as step 0 of ``get_agent_from_dpop_client_cert`` on
the OpenAI-compat surface. Strong (256-bit, bcrypt at rest, scoped,
revocable) but replayable until expiry/revocation, and the surface was
enabled unconditionally with no production gate, while README and
threat-model claimed "refuses plain Bearer outright".

The fix mirrors F-B-11/F-B-14: ``user_api_tokens_enabled`` controls the
surface (resolver + minting), and ``validate_config`` refuses a
production boot while it is enabled unless the operator explicitly
accepts the risk via ``MCP_PROXY_USER_API_TOKENS_INSECURE_OK=true``.
No auto-flip: silently disabling would 401 every existing LibreChat /
Cursor integration after an upgrade — a loud boot refusal is honest,
a silent 401 is a support ticket.

  prod + default (enabled) + no opt-in   → SystemExit(1)
  prod + explicit enabled + no opt-in    → SystemExit(1)
  prod + enabled + INSECURE_OK=true      → boots
  prod + disabled                        → boots (gate n/a)
  dev  + enabled                         → not gated
  empty MCP_PROXY_USER_API_TOKENS_ENABLED= → loud ValidationError
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
    """Satisfy every production gate before and after F-B-15 so each
    test reaches it cleanly. The user-api-token posture is left to the
    individual test."""
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
    monkeypatch.setenv("MCP_PROXY_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "true")
    # Default the override OFF; the opt-in test sets it explicitly.
    monkeypatch.delenv("MCP_PROXY_USER_API_TOKENS_INSECURE_OK", raising=False)


def _fresh_settings():
    from mcp_proxy.config import ProxySettings, get_settings

    get_settings.cache_clear()
    return ProxySettings()


@pytest.fixture(autouse=True)
def _require_webauthn():
    """Production pins WEBAUTHN_ENFORCEMENT=required; skip if the optional
    extra is missing so the webauthn gate doesn't mask the F-B-15 gate."""
    pytest.importorskip("webauthn")
    yield


def test_prod_default_enabled_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch,
):
    """THE GATE. The surface defaults to enabled, so an un-configured
    production boot must stop and force the operator to choose."""
    _production_env(monkeypatch)
    monkeypatch.delenv("MCP_PROXY_USER_API_TOKENS_ENABLED", raising=False)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.user_api_tokens_enabled is True
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_prod_explicit_enabled_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch,
):
    """An explicit enable without risk acceptance is refused the same
    way — explicitness about the feature is not risk acceptance."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "true")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_prod_insecure_optin_boots(monkeypatch: pytest.MonkeyPatch):
    """The documented OpenAI-compat deployment posture is reachable:
    enabled + explicit risk acceptance boots."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_INSECURE_OK", "true")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_prod_disabled_boots(monkeypatch: pytest.MonkeyPatch):
    """Disabling the surface satisfies the gate without the opt-in."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "false")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.user_api_tokens_enabled is False
    validate_config(settings)  # must not raise


def test_dev_enabled_is_not_gated(monkeypatch: pytest.MonkeyPatch):
    """Development keeps the permissive default for local iteration —
    only production is hardened."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.delenv("MCP_PROXY_USER_API_TOKENS_ENABLED", raising=False)
    monkeypatch.delenv("MCP_PROXY_USER_API_TOKENS_INSECURE_OK", raising=False)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.user_api_tokens_enabled is True
    validate_config(settings)  # must not raise


def test_empty_enabled_env_fails_loud(monkeypatch: pytest.MonkeyPatch):
    """An EMPTY ``MCP_PROXY_USER_API_TOKENS_ENABLED`` (manual ``=`` in
    proxy.env) is rejected by pydantic bool-parsing — a loud boot crash,
    never a silent posture."""
    import pydantic

    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "")

    with pytest.raises(pydantic.ValidationError):
        _fresh_settings()


def test_default_ttl_days_env_wired(monkeypatch: pytest.MonkeyPatch):
    """MCP_PROXY_USER_API_TOKEN_DEFAULT_TTL_DAYS reaches the setting."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKEN_DEFAULT_TTL_DAYS", "30")

    settings = _fresh_settings()
    assert settings.user_api_token_default_ttl_days == 30
