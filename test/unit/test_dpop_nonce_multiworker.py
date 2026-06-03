"""Tests for the multi-worker DPoP server-nonce fix (RFC 9449 §8).

Root cause confirmed empirically by the 40-agent bank soak 2026-06-03: the
bundle runs 4 uvicorn workers, and the nonce was seeded with a per-process
``os.urandom`` at boot. ``/v1/llm/chat`` requires the nonce
(``get_agent_from_dpop_client_cert``, ``require_nonce=True``), so a nonce
minted by worker A was rejected by workers B/C/D. nginx round-robins, so
~40% of chat proofs 401'd with ``use_dpop_nonce`` on the first hop and were
only recovered when the SDK's retry happened to land on the minting worker
(keep-alive). ``/v1/mcp`` was unaffected (``require_nonce=False``).

The fix derives the nonce statelessly as ``HMAC(secret, time_window)`` over
a 5-minute window, keyed with a secret shared across workers (env →
persisted file → per-process fallback). Every worker with the same secret
produces the same nonce, so cross-worker validation succeeds without Redis.
Same class as the dashboard signing key (audit F-B-10).

Invariants pinned:

1. Two "workers" sharing a secret derive the SAME current nonce, and each
   validates the other's nonce (the core regression).
2. The previous window's nonce is still accepted (rotation tolerance);
   a two-windows-old nonce is rejected.
3. An empty nonce is rejected.
4. A nonce minted under a different secret is rejected (models the old
   per-process bug — proves it can no longer validate cross-worker).
5. ``MCP_PROXY_DPOP_NONCE_SECRET`` (env) wins over the file path.
6. With only the file path set, two workers pointed at the same file
   converge on the same secret (and thus the same nonce).
"""
from __future__ import annotations

import importlib

import pytest

import mcp_proxy.auth.dpop as dpop


class _FakeSettings:
    def __init__(self, secret: str = "", path: str = ""):
        self.dpop_nonce_secret = secret
        self.dpop_nonce_secret_path = path


@pytest.fixture(autouse=True)
def _reset_nonce_cache():
    """Each test starts from a cold module cache (a fresh-booted worker)."""
    dpop._nonce_secret_cache = b""
    yield
    dpop._nonce_secret_cache = b""


def _set_secret(monkeypatch, *, secret: str = "", path: str = ""):
    monkeypatch.setattr(
        dpop, "get_settings", lambda: _FakeSettings(secret=secret, path=path)
    )


def test_two_workers_same_secret_agree_on_nonce(monkeypatch):
    _set_secret(monkeypatch, secret="env-shared-secret")
    # Worker A mints.
    nonce_a = dpop.get_current_dpop_nonce()
    # Worker B: cold cache, same shared secret (env).
    dpop._nonce_secret_cache = b""
    nonce_b = dpop.get_current_dpop_nonce()
    assert nonce_a == nonce_b
    # Worker B accepts the nonce worker A minted — the regression.
    assert dpop._is_valid_nonce(nonce_a)


def test_previous_window_tolerated_but_stale_rejected(monkeypatch):
    _set_secret(monkeypatch, secret="env-shared-secret")
    window = dpop._current_window()
    assert dpop._is_valid_nonce(dpop._nonce_for_window(window))
    assert dpop._is_valid_nonce(dpop._nonce_for_window(window - 1))
    assert not dpop._is_valid_nonce(dpop._nonce_for_window(window - 2))


def test_empty_nonce_rejected(monkeypatch):
    _set_secret(monkeypatch, secret="env-shared-secret")
    assert not dpop._is_valid_nonce("")


def test_cross_secret_nonce_rejected(monkeypatch):
    """The old per-process bug: a nonce from a worker with a different
    secret must not validate."""
    _set_secret(monkeypatch, secret="env-shared-secret")
    other_worker_nonce = dpop._hmac.new(
        b"some-other-process-secret",
        str(dpop._current_window()).encode(),
        dpop.hashlib.sha256,
    ).hexdigest()[:32]
    assert not dpop._is_valid_nonce(other_worker_nonce)


def test_env_secret_wins_over_file(monkeypatch, tmp_path):
    secret_file = tmp_path / "nonce_secret"
    secret_file.write_text("file-secret-should-be-ignored")
    _set_secret(monkeypatch, secret="env-secret-wins", path=str(secret_file))
    assert dpop._nonce_secret() == b"env-secret-wins"


def test_file_fallback_shared_across_workers(monkeypatch, tmp_path):
    secret_path = str(tmp_path / "sub" / "nonce_secret")
    _set_secret(monkeypatch, path=secret_path)
    # Worker A creates the file and derives a nonce.
    nonce_a = dpop.get_current_dpop_nonce()
    secret_a = dpop._nonce_secret_cache
    # Worker B: cold cache, same path → reads the file A created.
    dpop._nonce_secret_cache = b""
    nonce_b = dpop.get_current_dpop_nonce()
    assert dpop._nonce_secret_cache == secret_a
    assert nonce_a == nonce_b
    assert dpop._is_valid_nonce(nonce_a)


def test_module_reimport_keeps_callable_aliases():
    """``generate_dpop_nonce`` stays callable (boot warm-up call in main)."""
    importlib.reload(dpop)
    assert callable(dpop.generate_dpop_nonce)
    assert callable(dpop.get_current_dpop_nonce)
