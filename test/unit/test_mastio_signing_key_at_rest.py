"""F4 (panel 2026-06-05) — the Mastio signing key is encrypted at rest.

``mastio_keys.privkey_pem`` historically stored a plaintext PEM. On a
production ``kms=vault`` deploy (verified live on mastio-demo) the CA was
in Vault but this row was plaintext, so a DB read (backup, replica, dump)
yielded the LocalIssuer signing key and let anyone forge LOCAL_TOKEN/JWT
for any agent.

The fix wraps the key in the ``enc:sec:v1:`` envelope (same Fernet master
as the CA at-rest path) at the ``db.py`` boundary: encrypt on write,
decrypt on read, transparently for ``LocalKeyStore``/``LocalIssuer``. A
boot-time backfill re-wraps legacy plaintext rows. Dev/sandbox without a
master keeps plaintext (mirrors the CA path); production requires the
master, so there the key is always encrypted.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text

from mcp_proxy.db import (
    get_db,
    get_mastio_keys_active,
    insert_mastio_key,
    reencrypt_plaintext_mastio_keys,
)
from mcp_proxy.kms import pki_at_rest

_MASTER = "0" * 64  # >= 16 chars, the at-rest passphrase


def _fresh_keypair() -> tuple[str, str, str]:
    from mcp_proxy.auth.local_keystore import compute_kid

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return compute_kid(pub_pem), pub_pem, priv_pem


def _set_master(monkeypatch) -> None:
    monkeypatch.setenv("MCP_PROXY_DB_ENCRYPTION_KEY", _MASTER)
    pki_at_rest._reset_cache_for_tests()


def _unset_master(monkeypatch) -> None:
    monkeypatch.delenv("MCP_PROXY_DB_ENCRYPTION_KEY", raising=False)
    pki_at_rest._reset_cache_for_tests()


async def _raw_privkey(kid: str) -> str:
    """Read the stored (possibly-enveloped) privkey_pem straight from the DB."""
    async with get_db() as conn:
        r = await conn.execute(
            text("SELECT privkey_pem FROM mastio_keys WHERE kid = :k"),
            {"k": kid},
        )
        return r.scalar_one()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import dispose_db, init_db
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()
    pki_at_rest._reset_cache_for_tests()


# ── pure envelope primitives ────────────────────────────────────────


def test_encrypt_secret_roundtrip(monkeypatch):
    _set_master(monkeypatch)
    env = pki_at_rest.encrypt_secret("hello-secret")
    assert env.startswith("enc:sec:v1:")
    assert pki_at_rest.is_secret_envelope(env)
    assert pki_at_rest.decrypt_secret(env) == "hello-secret"


def test_decrypt_secret_refuses_plaintext(monkeypatch):
    _set_master(monkeypatch)
    with pytest.raises(ValueError):
        pki_at_rest.decrypt_secret("-----BEGIN PRIVATE KEY-----")


def test_encrypt_secret_requires_master(monkeypatch):
    _unset_master(monkeypatch)
    with pytest.raises(pki_at_rest.PKIKeyMissingError):
        pki_at_rest.encrypt_secret("x")


# ── write encrypts / read decrypts ──────────────────────────────────


@pytest.mark.asyncio
async def test_insert_stores_encrypted_reads_plaintext(proxy_db, monkeypatch):
    _set_master(monkeypatch)
    kid, pub, priv = _fresh_keypair()
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_now(), activated_at=_now(),
    )

    # At rest: enveloped, NOT a plaintext PEM.
    raw = await _raw_privkey(kid)
    assert raw.startswith("enc:sec:v1:")
    assert "BEGIN" not in raw

    # Through the reader: transparent plaintext for LocalIssuer.
    rows = await get_mastio_keys_active()
    assert len(rows) == 1
    assert rows[0]["privkey_pem"] == priv


@pytest.mark.asyncio
async def test_dev_without_master_stores_plaintext(proxy_db, monkeypatch):
    _unset_master(monkeypatch)
    kid, pub, priv = _fresh_keypair()
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_now(), activated_at=_now(),
    )
    raw = await _raw_privkey(kid)
    assert raw == priv  # dev fallback: plaintext, mirrors the CA path
    rows = await get_mastio_keys_active()
    assert rows[0]["privkey_pem"] == priv  # read still works


# ── backfill ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_backfill_reencrypts_and_is_idempotent(proxy_db, monkeypatch):
    # Seed a legacy plaintext row (no master at insert time).
    _unset_master(monkeypatch)
    kid, pub, priv = _fresh_keypair()
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_now(), activated_at=_now(),
    )
    assert await _raw_privkey(kid) == priv  # plaintext on disk

    # Configure the master and run the boot backfill.
    _set_master(monkeypatch)
    n = await reencrypt_plaintext_mastio_keys()
    assert n == 1
    assert (await _raw_privkey(kid)).startswith("enc:sec:v1:")
    # Read still returns the original plaintext.
    rows = await get_mastio_keys_active()
    assert rows[0]["privkey_pem"] == priv

    # Idempotent: a second run touches nothing.
    assert await reencrypt_plaintext_mastio_keys() == 0


@pytest.mark.asyncio
async def test_backfill_noop_without_master(proxy_db, monkeypatch):
    _unset_master(monkeypatch)
    kid, pub, priv = _fresh_keypair()
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_now(), activated_at=_now(),
    )
    assert await reencrypt_plaintext_mastio_keys() == 0
    assert await _raw_privkey(kid) == priv  # untouched


# ── end-to-end through the keystore ─────────────────────────────────


@pytest.mark.asyncio
async def test_signer_usable_through_keystore_after_encryption(proxy_db, monkeypatch):
    """The decrypted key round-trips into a usable EC private key, so
    LocalIssuer signing is unaffected by the at-rest wrap."""
    _set_master(monkeypatch)
    kid, pub, priv = _fresh_keypair()
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_now(), activated_at=_now(),
    )
    from mcp_proxy.auth.local_keystore import LocalKeyStore

    signer = await LocalKeyStore().current_signer()
    assert signer.kid == kid
    # load_private_key() deserialises the decrypted PEM into a real EC key.
    key = signer.load_private_key()
    sig = key.sign(b"payload", ec.ECDSA(hashes.SHA256()))
    assert sig  # signing works through the decrypt path
