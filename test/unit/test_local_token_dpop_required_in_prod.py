"""F-B-14 — production refuses plain-Bearer LOCAL_TOKENs.

Adversarial panel (2026-06-05) confirmed the finding: when
``local_auth_enabled`` is on (auto-flipped on in every standalone deploy)
and ``local_token_require_dpop`` is false (the historical default), a
LOCAL_TOKEN minted without a DPoP proof carries no ``cnf.jkt`` and is
accepted as a plain Bearer on every later request
(``local_agent_dep.py``: WARN + accept). That violates the non-negotiable
"never accept plain Bearer" invariant: an exfiltrated token replays with
no RFC 9449 key-possession proof.

The fix is two complementary pieces, mirroring the egress F-B-11 pattern:

  1. Auto-flip ``local_token_require_dpop`` on in standalone *production*
     when the operator hasn't chosen a posture explicitly (companion to
     the existing ``local_auth_enabled`` standalone auto-flip). The SDK
     always sends a DPoP proof at mint, so this is secure-by-default with
     no boot break on upgrade.
  2. A ``validate_config`` boot gate that refuses production when
     ``local_auth_enabled`` is on but ``local_token_require_dpop`` was
     *explicitly* set false — unless the operator declares the SDK-rollout
     migration window via ``MCP_PROXY_LOCAL_TOKEN_DPOP_INSECURE_OK=true``.

These tests pin both pieces:

  standalone prod, no explicit require_dpop      → auto-flip True
  standalone prod, explicit require_dpop=false   → stays False (gate fires)
  standalone dev,  no explicit require_dpop      → stays False (not gated)
  prod + local_auth on + explicit false          → SystemExit(1)
  prod + local_auth on + explicit false + opt-in → boots
  prod + local_auth on + require_dpop true        → boots
  prod + local_auth off + explicit false          → boots (gate n/a)
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
    """Set every production gate that sits *before* and *after* F-B-14 so
    each test reaches it cleanly. local_auth / require_dpop are left to the
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
    # F-B-15 — disable the culk_ surface so the SystemExit in these
    # F-B-14-focused tests isolates the knob under test.
    monkeypatch.setenv("MCP_PROXY_USER_API_TOKENS_ENABLED", "false")
    # Default the override OFF; the opt-in test sets it explicitly.
    monkeypatch.delenv("MCP_PROXY_LOCAL_TOKEN_DPOP_INSECURE_OK", raising=False)


def _fresh_settings():
    from mcp_proxy.config import ProxySettings, get_settings

    get_settings.cache_clear()
    return ProxySettings()


@pytest.fixture(autouse=True)
def _require_webauthn():
    """Production pins WEBAUTHN_ENFORCEMENT=required; skip if the optional
    extra is missing so the webauthn gate doesn't mask the F-B-14 gate."""
    pytest.importorskip("webauthn")
    yield


# ── standalone auto-flip (model validator) ──────────────────────────


def test_standalone_prod_autoflips_require_dpop_on(
    monkeypatch: pytest.MonkeyPatch,
):
    """The default standalone prod posture must be secure: require_dpop
    flips on when the operator hasn't chosen explicitly, so a fresh /
    upgraded bundle never accepts a plain-Bearer LOCAL_TOKEN."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.delenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", raising=False)

    settings = _fresh_settings()
    assert settings.local_auth_enabled is True  # standalone auto-flip
    assert settings.local_token_require_dpop is True  # F-B-14 auto-flip


def test_empty_require_dpop_env_fails_loud_never_plain_bearer(
    monkeypatch: pytest.MonkeyPatch,
):
    """An EMPTY ``MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP`` (e.g. a manual
    ``=`` in proxy.env) is rejected by pydantic bool-parsing *before* the
    model validator runs, so it crashes the boot loudly rather than
    silently degrading to plain Bearer. No compose passes this var, so the
    bundle path sees it unset (→ field default → auto-flip); this test
    pins that the empty edge can never become a silent Bearer acceptance.
    """
    import pydantic

    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "")

    with pytest.raises(pydantic.ValidationError):
        _fresh_settings()


def test_standalone_prod_explicit_false_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
):
    """An explicit operator downgrade is NOT silently overridden — it is
    preserved so the validate_config gate can catch it loudly."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "false")

    settings = _fresh_settings()
    assert settings.local_token_require_dpop is False


def test_standalone_dev_stays_permissive(monkeypatch: pytest.MonkeyPatch):
    """Dev standalone keeps the permissive default for local iteration —
    only production is hardened."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_OK)
    monkeypatch.delenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", raising=False)

    settings = _fresh_settings()
    assert settings.local_token_require_dpop is False


# ── validate_config boot gate (F-B-14) ──────────────────────────────


def test_prod_local_auth_explicit_false_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch,
):
    """THE GATE. local_auth on + an explicit require_dpop=false in
    production must SystemExit at boot — plain-Bearer LOCAL_TOKENs would
    otherwise be accepted."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "false")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.local_auth_enabled is True
    assert settings.local_token_require_dpop is False
    with pytest.raises(SystemExit) as excinfo:
        validate_config(settings)
    assert excinfo.value.code == 1


def test_prod_migration_window_optin_boots(monkeypatch: pytest.MonkeyPatch):
    """The SDK-rollout migration window is reachable: explicit
    require_dpop=false + the insecure opt-in boots (with a sunset date the
    operator owns)."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "false")
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_DPOP_INSECURE_OK", "true")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_prod_require_dpop_true_boots(monkeypatch: pytest.MonkeyPatch):
    """The secure posture (require_dpop=true) boots cleanly."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "true")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    validate_config(settings)  # must not raise


def test_prod_autoflip_default_boots(monkeypatch: pytest.MonkeyPatch):
    """The default standalone prod path (no explicit require_dpop) boots:
    the auto-flip makes it secure before the gate is reached."""
    _production_env(monkeypatch)
    monkeypatch.delenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", raising=False)

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.local_token_require_dpop is True
    validate_config(settings)  # must not raise


def test_prod_local_auth_off_is_not_gated(monkeypatch: pytest.MonkeyPatch):
    """When local_auth is explicitly off the local-token router is never
    mounted, so require_dpop=false is irrelevant and must not block boot."""
    _production_env(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "false")
    monkeypatch.setenv("MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP", "false")

    from mcp_proxy.config import validate_config

    settings = _fresh_settings()
    assert settings.local_auth_enabled is False
    validate_config(settings)  # must not raise
