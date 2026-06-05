"""F5 step 1 (panel 2026-06-05) — SDK DPoP key encrypted at rest.

The agent's DPoP private JWK (``dpop.jwk``) shipped as a plaintext file
protected only by ``chmod 0600``. This wraps it in the ``enc:sec:v1:``
envelope (format-compatible with the Mastio's ``pki_at_rest``, per-domain
salt) when a root passphrase is configured, with a plaintext fallback for
dev / back-compat. Root-of-trust is a pluggable ladder; step 1 wires the
``CULLIS_IDENTITY_PASSPHRASE`` env provider.

key.pem at rest is deliberately out of scope here: the mTLS path loads the
key file by path into an ssl context (stdlib ssl cannot load a key from
memory), so an encrypted key.pem needs decrypt-to-tempfile / in-memory-ssl
handling — a separate step. The DPoP key is in-memory only (signing happens
in-process), so it has no such constraint.
"""
from __future__ import annotations

import json

import pytest

from cullis_sdk import _keystore as ks

_PASS = "correct horse battery staple ----- 32+ chars"


def _set_pass(monkeypatch, value=_PASS):
    monkeypatch.setenv("CULLIS_IDENTITY_PASSPHRASE", value)


def _unset_pass(monkeypatch):
    monkeypatch.delenv("CULLIS_IDENTITY_PASSPHRASE", raising=False)


# ── envelope primitives ─────────────────────────────────────────────


def test_envelope_roundtrip():
    env = ks.encrypt_secret("top-secret", _PASS)
    assert env.startswith("enc:sec:v1:")
    assert ks.is_secret_envelope(env)
    assert ks.decrypt_secret(env, _PASS) == "top-secret"


def test_decrypt_refuses_plaintext():
    with pytest.raises(ValueError):
        ks.decrypt_secret('{"private_jwk": {}}', _PASS)


def test_wrong_passphrase_fails_loud():
    env = ks.encrypt_secret("x", _PASS)
    with pytest.raises(ks.IdentityKeyLockedError):
        ks.decrypt_secret(env, "a different passphrase entirely")


# ── root ladder ─────────────────────────────────────────────────────


def test_root_ladder_env_provider(monkeypatch):
    _set_pass(monkeypatch)
    assert ks.resolve_root_passphrase() == _PASS
    _unset_pass(monkeypatch)
    assert ks.resolve_root_passphrase() is None


def test_wrap_encrypts_with_root_plaintext_without(monkeypatch):
    _set_pass(monkeypatch)
    assert ks.is_secret_envelope(ks.wrap_identity_secret("data"))
    _unset_pass(monkeypatch)
    assert ks.wrap_identity_secret("data") == "data"  # dev fallback


def test_unwrap_envelope_without_root_raises(monkeypatch):
    _set_pass(monkeypatch)
    env = ks.wrap_identity_secret("data")
    _unset_pass(monkeypatch)
    with pytest.raises(ks.IdentityKeyLockedError):
        ks.unwrap_identity_secret(env)


def test_unwrap_passes_plaintext_through(monkeypatch):
    _unset_pass(monkeypatch)
    assert ks.unwrap_identity_secret('{"private_jwk": {}}') == '{"private_jwk": {}}'


# ── DpopKey save/load end-to-end ────────────────────────────────────


def test_dpop_key_encrypted_at_rest_roundtrip(tmp_path, monkeypatch):
    from cullis_sdk.dpop import DpopKey

    _set_pass(monkeypatch)
    path = tmp_path / "dpop.jwk"
    key = DpopKey.generate(path=path)
    key.save(path)

    # On disk: an envelope, NOT a plaintext JWK.
    raw = path.read_text()
    assert raw.startswith("enc:sec:v1:")
    assert '"private_jwk"' not in raw
    assert '"d"' not in raw

    # Reloads to the same key (private 'd' matches through decryption).
    reloaded = DpopKey.load(path)
    assert reloaded.private_jwk()["d"] == key.private_jwk()["d"]
    assert reloaded.public_jwk == key.public_jwk


def test_dpop_key_plaintext_without_root(tmp_path, monkeypatch):
    from cullis_sdk.dpop import DpopKey

    _unset_pass(monkeypatch)
    path = tmp_path / "dpop.jwk"
    key = DpopKey.generate(path=path)
    key.save(path)

    raw = path.read_text()
    assert not ks.is_secret_envelope(raw)
    blob = json.loads(raw)  # legacy plaintext JWK
    assert "private_jwk" in blob
    # Loads back fine.
    assert DpopKey.load(path).private_jwk()["d"] == key.private_jwk()["d"]


def test_dpop_key_legacy_plaintext_loads_with_root_set(tmp_path, monkeypatch):
    """A pre-F5 plaintext dpop.jwk must still load after the operator turns
    on a passphrase (back-compat read of unencrypted files)."""
    from cullis_sdk.dpop import DpopKey

    # Write plaintext first (no root).
    _unset_pass(monkeypatch)
    path = tmp_path / "dpop.jwk"
    key = DpopKey.generate(path=path)
    key.save(path)
    assert not ks.is_secret_envelope(path.read_text())

    # Now a root is configured; the legacy plaintext file still loads.
    _set_pass(monkeypatch)
    assert DpopKey.load(path).private_jwk()["d"] == key.private_jwk()["d"]
