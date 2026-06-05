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


# ── key.pem (mTLS) at rest — PKCS#8 encrypted-PEM ───────────────────


def _fresh_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_wrap_key_pem_produces_encrypted_pem(monkeypatch):
    _set_pass(monkeypatch)
    enc = ks.wrap_key_pem(_fresh_key_pem())
    assert enc.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert ks.is_encrypted_pem(enc)


def test_wrap_key_pem_plaintext_without_root(monkeypatch):
    _unset_pass(monkeypatch)
    pem = _fresh_key_pem()
    assert ks.wrap_key_pem(pem) == pem  # dev fallback, unchanged


def test_unwrap_key_pem_roundtrip(monkeypatch):
    _set_pass(monkeypatch)
    pem = _fresh_key_pem()
    enc = ks.wrap_key_pem(pem)
    out = ks.unwrap_key_pem(enc)
    assert not ks.is_encrypted_pem(out)
    assert "BEGIN PRIVATE KEY" in out


def test_unwrap_key_pem_encrypted_without_root_raises(monkeypatch):
    _set_pass(monkeypatch)
    enc = ks.wrap_key_pem(_fresh_key_pem())
    _unset_pass(monkeypatch)
    with pytest.raises(ks.IdentityKeyLockedError):
        ks.unwrap_key_pem(enc)


def test_ssl_load_cert_chain_accepts_encrypted_key(tmp_path, monkeypatch):
    """THE CORE mTLS DE-RISK: ssl must natively load our encrypted-PEM
    key.pem via the password argument. If this breaks, agent mTLS breaks."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    _set_pass(monkeypatch)
    key = ec.generate_private_key(ec.SECP256R1())
    plain_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2027, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    cp = tmp_path / "cert.pem"
    kp = tmp_path / "key.pem"
    cp.write_text(cert_pem)
    kp.write_text(ks.wrap_key_pem(plain_pem))  # encrypted-PEM on disk
    assert ks.is_encrypted_pem(kp.read_text())

    ctx = ssl.create_default_context()
    # Must not raise: ssl decrypts the key with the ladder passphrase.
    ctx.load_cert_chain(
        certfile=str(cp), keyfile=str(kp),
        password=ks.key_pem_load_password(),
    )


def test_load_cert_chain_plaintext_key_with_root_set(tmp_path, monkeypatch):
    """Back-compat lock: a root is configured but the on-disk key.pem is a
    legacy PLAINTEXT PEM. ssl must still load it — the password is passed
    (non-None) but ignored for an unencrypted key. Mirrors a deploy that
    turned on a passphrase before re-writing existing identities."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    _set_pass(monkeypatch)  # root IS set
    key = ec.generate_private_key(ec.SECP256R1())
    plain_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2027, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cp = tmp_path / "cert.pem"
    kp = tmp_path / "key.pem"
    cp.write_text(cert.public_bytes(serialization.Encoding.PEM).decode())
    kp.write_text(plain_pem)  # PLAINTEXT key on disk
    assert not ks.is_encrypted_pem(kp.read_text())

    ssl.create_default_context().load_cert_chain(
        certfile=str(cp), keyfile=str(kp),
        password=ks.key_pem_load_password(),  # non-None, ignored for plaintext
    )
