"""Audit F-E-03 + F-E-04 — startup refuses insecure secret backends in prod.

These tests lock in the post-fix behaviour:

1. Broker ``validate_config`` refuses ``environment=production`` when
   ``KMS_BACKEND`` is not ``vault`` (F-E-03) or when ``REDIS_URL`` is
   empty (F-E-04). Development mode keeps tolerating both for local
   workflows.
2. Proxy ``validate_config`` refuses ``environment=production`` when
   ``secret_backend`` is not ``vault`` (F-E-03 proxy analogue).
3. The DPoP JTI store runtime fallback raises in production when Redis
   is unavailable instead of silently dropping to the per-process
   in-memory store (F-E-04 defense in depth).
"""
from __future__ import annotations

import pytest

from app.config import Settings, validate_config
from mcp_proxy.config import ProxySettings, validate_config as proxy_validate_config


# ── Broker: F-E-03 KMS_BACKEND ──────────────────────────────────────

def _prod_broker_settings(**overrides) -> Settings:
    """Build broker Settings that would otherwise pass production validation.

    Uses bind-mount-style paths that exist in the test checkout (certs/ is
    created by generate_certs.py / tests fixtures). We only care about the
    production branch raising SystemExit for the specific knob under test,
    so callers flip the knob they want.
    """
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        database_url="postgresql+asyncpg://u:p@db/cullis",
        broker_ca_key_path="certs/broker-ca-key.pem",
        dashboard_signing_key="strong-random-dashboard-key",
        redis_url="redis://redis:6379/0",
        kms_backend="vault",
    )
    base.update(overrides)
    return Settings(**base)


def test_validate_config_rejects_prod_with_kms_backend_local(tmp_path, monkeypatch):
    # Create a placeholder CA key file so the pre-existing CA-path check
    # does not preempt the KMS check.
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    settings = _prod_broker_settings(
        kms_backend="local",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_rejects_prod_with_unknown_kms_backend(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(
        kms_backend="aws-kms",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_dev_tolerates_kms_backend_local():
    """Development mode keeps KMS_BACKEND=local working for fixtures / CI."""
    settings = Settings(
        environment="development",
        admin_secret="strong-random-admin-secret",
        kms_backend="local",
        redis_url="",
    )
    # Must not raise.
    validate_config(settings)


# ── Broker: F-E-04 REDIS_URL ────────────────────────────────────────

def test_validate_config_rejects_prod_with_empty_redis_url(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(
        redis_url="",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_prod_passes_with_vault_and_redis(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(broker_ca_key_path=str(ca_key))
    # Must not raise.
    validate_config(settings)


# ── Proxy: F-E-03 secret_backend ────────────────────────────────────

def _prod_proxy_settings(**overrides) -> ProxySettings:
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        broker_jwks_url="https://broker.example.com/.well-known/jwks.json",
        standalone=False,
        broker_verify_tls=True,
        secret_backend="vault",
        vault_verify_tls=True,
    )
    base.update(overrides)
    return ProxySettings(**base)


def test_proxy_validate_config_rejects_prod_with_secret_backend_env():
    settings = _prod_proxy_settings(secret_backend="env")
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


def test_proxy_validate_config_dev_tolerates_secret_backend_env():
    settings = ProxySettings(
        environment="development",
        secret_backend="env",
    )
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_prod_allows_vault_backend():
    settings = _prod_proxy_settings()
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_rejects_standalone_prod_with_env_backend():
    """Standalone mode skips broker checks but the secret backend refusal
    still applies — agent keys live in the proxy regardless of uplink."""
    settings = ProxySettings(
        environment="production",
        admin_secret="strong-random-admin-secret",
        standalone=True,
        secret_backend="env",
        vault_verify_tls=True,
    )
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


# ── F-E-04 runtime: DPoP JTI store refuses in-memory in prod ────────

def test_dpop_jti_init_refuses_in_memory_in_production(monkeypatch):
    """``_init_store`` must not silently return InMemoryDpopJtiStore in
    production when Redis is unreachable — the replay window across
    workers is unacceptable."""
    from app.auth import dpop_jti_store as jti_mod
    from app.redis import pool as redis_pool

    # Force "no redis available".
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)

    # Force production env via the cached settings.
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "production")
    # Other prod-required knobs not relevant here: _init_store only reads
    # settings.environment.

    jti_mod.reset_dpop_jti_store()
    try:
        with pytest.raises(RuntimeError):
            jti_mod._init_store()
    finally:
        # Leave the cache and state clean for sibling tests.
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


def test_dpop_jti_init_uses_in_memory_in_development(monkeypatch):
    from app.auth import dpop_jti_store as jti_mod
    from app.redis import pool as redis_pool

    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)

    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "development")

    jti_mod.reset_dpop_jti_store()
    try:
        store = jti_mod._init_store()
        assert isinstance(store, jti_mod.InMemoryDpopJtiStore)
    finally:
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


# ── F-B-12: Mastio Redis warning (not a hard refusal) ──────────────
#
# Unlike the broker, Mastio has a legitimate single-instance production
# mode (single-tenant intra-org). validate_config warns rather than
# refusing when REDIS_URL is empty in production — operators deploying
# multi-worker/HA must set it to avoid the cross-worker DPoP replay +
# rate-limit budget multiplication.
#
# The proxy configures the "mcp_proxy" logger with ``propagate=False``
# at startup (``mcp_proxy/logging_setup.py``), so pytest's caplog —
# which attaches to root by default — does not see the records. Capture
# via a dedicated handler on the target logger instead.

import logging as _logging


class _ListHandler(_logging.Handler):
    def __init__(self):
        super().__init__(level=_logging.WARNING)
        self.records: list[_logging.LogRecord] = []

    def emit(self, record: _logging.LogRecord) -> None:
        self.records.append(record)


def _capture_mcp_proxy_warnings():
    handler = _ListHandler()
    logger = _logging.getLogger("mcp_proxy")
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(_logging.WARNING)
    return handler, logger, previous_level


def _restore_mcp_proxy_logger(handler, logger, previous_level):
    logger.removeHandler(handler)
    logger.setLevel(previous_level)


def test_proxy_validate_config_warns_on_prod_without_redis():
    settings = _prod_proxy_settings(redis_url="")
    handler, logger, prev = _capture_mcp_proxy_warnings()
    try:
        # Must NOT raise — single-instance Mastio prod is supported.
        proxy_validate_config(settings)
    finally:
        _restore_mcp_proxy_logger(handler, logger, prev)
    messages = " ".join(r.getMessage() for r in handler.records)
    assert "MCP_PROXY_REDIS_URL" in messages
    assert "single-instance" in messages or "multi-worker" in messages
    assert "F-B-12" in messages


def test_proxy_validate_config_prod_with_redis_no_warning():
    settings = _prod_proxy_settings(redis_url="redis://redis:6379/0")
    handler, logger, prev = _capture_mcp_proxy_warnings()
    try:
        proxy_validate_config(settings)
    finally:
        _restore_mcp_proxy_logger(handler, logger, prev)
    messages = " ".join(r.getMessage() for r in handler.records)
    assert "F-B-12" not in messages


def test_proxy_validate_config_dev_without_redis_no_warning():
    settings = ProxySettings(environment="development", redis_url="")
    handler, logger, prev = _capture_mcp_proxy_warnings()
    try:
        proxy_validate_config(settings)
    finally:
        _restore_mcp_proxy_logger(handler, logger, prev)
    messages = " ".join(r.getMessage() for r in handler.records)
    assert "F-B-12" not in messages
