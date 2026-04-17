"""Regression tests for the SDK TLS-verify opt-out guard.

Audit follow-up (post PR #159 / F-E-01/F-E-02): make sure the Python
SDK does not silently accept ``verify_tls=False`` in production and at
least warns in development. TS SDK equivalent lives in
``sdk-ts/src/client.ts`` (construction-time throw).
"""
from __future__ import annotations

import warnings

import pytest

from cullis_sdk.client import (
    CullisClient,
    InsecureTLSWarning,
    _check_insecure_tls,
)


# ── Helper-level tests ───────────────────────────────────────────────

def test_check_insecure_tls_is_noop_when_verify_true():
    """Happy path: verify=True never warns, never raises."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning would fail
        _check_insecure_tls(True)


def test_check_insecure_tls_warns_when_verify_false_in_dev(monkeypatch):
    """Dev flow: verify=False is tolerated but must warn loudly."""
    monkeypatch.delenv("CULLIS_ENV", raising=False)
    monkeypatch.delenv("CULLIS_SDK_ALLOW_INSECURE_TLS", raising=False)
    with pytest.warns(InsecureTLSWarning):
        _check_insecure_tls(False)


def test_check_insecure_tls_refuses_in_production(monkeypatch):
    """Prod default: verify=False without explicit opt-in must raise."""
    monkeypatch.setenv("CULLIS_ENV", "production")
    monkeypatch.delenv("CULLIS_SDK_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="production"):
        _check_insecure_tls(False)


def test_check_insecure_tls_respects_production_opt_in(monkeypatch):
    """Two-key rule: admin can override the prod block but takes a warning."""
    monkeypatch.setenv("CULLIS_ENV", "production")
    monkeypatch.setenv("CULLIS_SDK_ALLOW_INSECURE_TLS", "1")
    with pytest.warns(InsecureTLSWarning):
        _check_insecure_tls(False)


def test_check_insecure_tls_production_case_insensitive(monkeypatch):
    """CULLIS_ENV matching must tolerate casing variations."""
    monkeypatch.setenv("CULLIS_ENV", "Production")
    monkeypatch.delenv("CULLIS_SDK_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _check_insecure_tls(False)


# ── Constructor-level tests ─────────────────────────────────────────

def test_cullis_client_warns_on_verify_tls_false(monkeypatch):
    """The main constructor must route through _check_insecure_tls."""
    monkeypatch.delenv("CULLIS_ENV", raising=False)
    with pytest.warns(InsecureTLSWarning):
        CullisClient("https://dev.broker.local", verify_tls=False)


def test_cullis_client_refuses_prod_without_opt_in(monkeypatch):
    monkeypatch.setenv("CULLIS_ENV", "production")
    monkeypatch.delenv("CULLIS_SDK_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        CullisClient("https://broker.example.com", verify_tls=False)


def test_cullis_client_default_is_secure(monkeypatch):
    """Default-constructed client must NOT trigger the guard."""
    monkeypatch.delenv("CULLIS_ENV", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error", InsecureTLSWarning)
        client = CullisClient("https://broker.example.com")
        assert client._verify_tls is True
        client.close()


def test_join_network_refuses_insecure_in_prod(monkeypatch):
    """Network-onboarding helper shares the same guard."""
    monkeypatch.setenv("CULLIS_ENV", "production")
    monkeypatch.delenv("CULLIS_SDK_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        CullisClient.join_network(
            broker_url="https://broker.example.com",
            org_id="orga",
            display_name="Org A",
            secret="s",
            ca_certificate="pem",
            invite_token="invite",
            verify_tls=False,
        )
