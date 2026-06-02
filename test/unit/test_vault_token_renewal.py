"""Vault KMS token renewal — boot guard + renewal watcher (2026-06-02).

VaultKMSProvider authenticates with a single static token and had no
renewal: a finite-TTL token lapses under a long-running Mastio and then
every CA load/store returns HTTP 403, breaking cert rotation and any
restart. The 60-min soak used an infinite root token so never exercised
this. These tests pin:

  * ``classify_token`` / ``boot_decision`` — the pure decision matrix.
  * ``lookup_token`` / ``renew_token`` — the provider HTTP calls
    (hermetic via httpx.MockTransport).
  * ``evaluate_vault_token_at_boot`` — production refuses a non-renewable
    finite token (override opt-in), hands a renewable token to the loop.
  * ``vault_token_renewal_watcher_loop`` — renews once and survives a
    renew failure without dying.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from mcp_proxy.kms.vault import VaultKMSProvider
from mcp_proxy.kms.vault_token import boot_decision, classify_token
from mcp_proxy.lifespan.vault_token_renewal_watcher import (
    _next_interval,
    evaluate_vault_token_at_boot,
    vault_token_renewal_watcher_loop,
)


_VAULT_ADDR = "https://vault.example:8200"
_TOKEN = "hvs.test-token-1234567890"
_PATH = "secret/data/cullis-mastio/org-ca"


def _client_patch(monkeypatch, transport: httpx.MockTransport):
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)


def _make_provider() -> VaultKMSProvider:
    return VaultKMSProvider(
        vault_addr=_VAULT_ADDR,
        vault_token=_TOKEN,
        org_ca_path=_PATH,
        verify_tls=True,
        ca_cert_path="",
    )


# ── classify_token ─────────────────────────────────────────────────────
def test_classify_root_token_does_not_expire():
    c = classify_token({"ttl": 0, "renewable": False, "period": 0,
                        "expire_time": None})
    assert c["expires"] is False
    assert c["renewable"] is False


def test_classify_renewable_finite_token():
    c = classify_token({"ttl": 3600, "renewable": True, "period": 0,
                        "expire_time": "2026-06-03T00:00:00Z"})
    assert c == {"ttl": 3600, "period": 0, "renewable": True, "expires": True}


def test_classify_periodic_token():
    c = classify_token({"ttl": 1800, "renewable": True, "period": 86400,
                        "expire_time": "2026-06-03T00:00:00Z"})
    assert c["period"] == 86400
    assert c["expires"] is True


def test_classify_non_renewable_finite_token():
    c = classify_token({"ttl": 7200, "renewable": False, "period": 0,
                        "expire_time": "2026-06-03T00:00:00Z"})
    assert c["expires"] is True
    assert c["renewable"] is False
    assert c["period"] == 0


# ── boot_decision matrix ───────────────────────────────────────────────
def test_boot_decision_non_expiring_is_ok():
    level, _ = boot_decision(
        classify_token({"ttl": 0, "expire_time": None}), is_production=True,
    )
    assert level == "ok"


def test_boot_decision_renewable_is_ok():
    level, _ = boot_decision(
        {"ttl": 3600, "period": 0, "renewable": True, "expires": True},
        is_production=True,
    )
    assert level == "ok"


def test_boot_decision_periodic_is_ok():
    level, _ = boot_decision(
        {"ttl": 1800, "period": 86400, "renewable": False, "expires": True},
        is_production=True,
    )
    assert level == "ok"


def test_boot_decision_nonrenewable_finite_refuses_in_production():
    level, msg = boot_decision(
        {"ttl": 7200, "period": 0, "renewable": False, "expires": True},
        is_production=True,
    )
    assert level == "refuse"
    assert "non-renewable" in msg


def test_boot_decision_nonrenewable_finite_only_warns_in_dev():
    level, _ = boot_decision(
        {"ttl": 7200, "period": 0, "renewable": False, "expires": True},
        is_production=False,
    )
    assert level == "warn"


# ── provider HTTP calls ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_token_parses_data_block(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/auth/token/lookup-self"
        assert request.headers["X-Vault-Token"] == _TOKEN
        return httpx.Response(200, json={"data": {
            "ttl": 3600, "renewable": True, "period": 0,
            "expire_time": "2026-06-03T00:00:00Z",
        }})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    data = await _make_provider().lookup_token()
    assert data["ttl"] == 3600
    assert data["renewable"] is True


@pytest.mark.asyncio
async def test_lookup_token_raises_on_403(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="permission denied")

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    with pytest.raises(RuntimeError):
        await _make_provider().lookup_token()


@pytest.mark.asyncio
async def test_renew_token_returns_auth_block(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/auth/token/renew-self"
        return httpx.Response(200, json={"auth": {
            "lease_duration": 86400, "renewable": True,
        }})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    auth = await _make_provider().renew_token()
    assert auth["lease_duration"] == 86400


@pytest.mark.asyncio
async def test_renew_token_raises_on_403(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="lease is not renewable")

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    with pytest.raises(RuntimeError):
        await _make_provider().renew_token()


# ── evaluate_vault_token_at_boot ───────────────────────────────────────
class _FakeProvider:
    def __init__(self, lookup_data):
        self._lookup_data = lookup_data

    async def lookup_token(self):
        return self._lookup_data


def _patch_provider(monkeypatch, lookup_data):
    monkeypatch.setattr(
        "mcp_proxy.kms.get_kms_provider",
        lambda: _FakeProvider(lookup_data),
    )


def _settings(**over):
    base = {
        "kms_backend": "vault",
        "environment": "production",
        "vault_token_allow_nonrenewable": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_boot_skips_when_backend_not_vault(monkeypatch):
    assert await evaluate_vault_token_at_boot(
        _settings(kms_backend="local"),
    ) is None


@pytest.mark.asyncio
async def test_boot_refuses_nonrenewable_finite_in_production(monkeypatch):
    _patch_provider(monkeypatch, {"ttl": 7200, "renewable": False,
                                  "period": 0, "expire_time": "x"})
    with pytest.raises(SystemExit):
        await evaluate_vault_token_at_boot(_settings())


@pytest.mark.asyncio
async def test_boot_override_allows_nonrenewable_but_returns_none(monkeypatch):
    _patch_provider(monkeypatch, {"ttl": 7200, "renewable": False,
                                  "period": 0, "expire_time": "x"})
    # Override active → no SystemExit, but the loop must NOT run (the
    # token cannot be renewed).
    result = await evaluate_vault_token_at_boot(
        _settings(vault_token_allow_nonrenewable=True),
    )
    assert result is None


@pytest.mark.asyncio
async def test_boot_returns_classified_for_renewable_token(monkeypatch):
    _patch_provider(monkeypatch, {"ttl": 3600, "renewable": True,
                                  "period": 0, "expire_time": "x"})
    result = await evaluate_vault_token_at_boot(_settings())
    assert result is not None
    assert result["ttl"] == 3600 and result["renewable"] is True


@pytest.mark.asyncio
async def test_boot_root_token_runs_no_loop(monkeypatch):
    _patch_provider(monkeypatch, {"ttl": 0, "renewable": False,
                                  "period": 0, "expire_time": None})
    assert await evaluate_vault_token_at_boot(_settings()) is None


@pytest.mark.asyncio
async def test_boot_lookup_failure_does_not_block_boot(monkeypatch):
    class _Boom:
        async def lookup_token(self):
            raise RuntimeError("vault sealed")

    monkeypatch.setattr("mcp_proxy.kms.get_kms_provider", lambda: _Boom())
    # A lookup blip returns None (continue without renewal), never raises.
    assert await evaluate_vault_token_at_boot(_settings()) is None


# ── _next_interval ─────────────────────────────────────────────────────
def test_next_interval_uses_half_life_and_floor():
    # period wins when present; half of 86400 = 43200, clamped to max 12h.
    assert _next_interval(1800, 86400, 60) == 12 * 60 * 60
    # ttl half-life above the floor.
    assert _next_interval(3600, 0, 60) == 1800.0
    # tiny ttl clamps up to the floor.
    assert _next_interval(10, 0, 60) == 60.0


# ── renewal loop ───────────────────────────────────────────────────────
class _RecordingProvider:
    def __init__(self, *, fail: bool = False):
        self.calls = 0
        self._fail = fail

    async def renew_token(self, increment_seconds=None):
        self.calls += 1
        if self._fail:
            raise RuntimeError("renew refused")
        return {"lease_duration": 3600, "renewable": True}


@pytest.mark.asyncio
async def test_loop_renews_once_then_stops(monkeypatch):
    monkeypatch.setattr(
        "mcp_proxy.lifespan.vault_token_renewal_watcher._audit",
        _noop_audit,
    )
    provider = _RecordingProvider()
    stop = asyncio.Event()

    # Wrap renew so the first success stops the loop deterministically.
    orig = provider.renew_token

    async def _renew_and_stop(increment_seconds=None):
        result = await orig(increment_seconds)
        stop.set()
        return result

    provider.renew_token = _renew_and_stop

    # initial_ttl=1 + min_interval=0 → first interval 0.0 → immediate renew.
    await asyncio.wait_for(
        vault_token_renewal_watcher_loop(
            provider, initial_ttl=1, period=0, min_interval_seconds=0,
            stop_event=stop,
        ),
        timeout=5.0,
    )
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_loop_survives_renew_failure(monkeypatch):
    monkeypatch.setattr(
        "mcp_proxy.lifespan.vault_token_renewal_watcher._audit",
        _noop_audit,
    )
    provider = _RecordingProvider(fail=True)
    stop = asyncio.Event()

    orig = provider.renew_token

    async def _renew_and_stop(increment_seconds=None):
        stop.set()  # break the loop after this attempt
        return await orig(increment_seconds)  # raises

    provider.renew_token = _renew_and_stop

    # Must return (not propagate the RuntimeError) — the loop swallows
    # renew failures and keeps going until stop_event.
    await asyncio.wait_for(
        vault_token_renewal_watcher_loop(
            provider, initial_ttl=1, period=0, min_interval_seconds=0,
            stop_event=stop,
        ),
        timeout=5.0,
    )
    assert provider.calls == 1


async def _noop_audit(*, status: str, detail: str) -> None:
    return None
