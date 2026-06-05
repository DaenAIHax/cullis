"""Master-key rotation rewrap (F4 follow-up).

Rotating ``MCP_PROXY_DB_ENCRYPTION_KEY`` without re-encrypting makes every
at-rest row (mastio_keys signing key, pki_key_store CA) undecryptable — the
verifier/issuer fail closed and signing halts. ``rewrap_at_rest_master_key``
decrypts every row under the OLD passphrase and re-encrypts under the NEW
one in a single transaction, so an operator can rotate the master cleanly.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.kms import pki_at_rest as p

_OLD = "old-master-passphrase-32-chars-xxxx"
_NEW = "new-master-passphrase-32-chars-yyyy"


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
    p._reset_cache_for_tests()


# ── explicit-passphrase variants ────────────────────────────────────


def test_secret_variant_roundtrip_and_wrong_pass():
    env = p.encrypt_secret_with("sign-key", _OLD)
    assert p.decrypt_secret_with(env, _OLD) == "sign-key"
    with pytest.raises(RuntimeError):
        p.decrypt_secret_with(env, _NEW)


def test_pki_variant_roundtrip_and_wrong_pass():
    env = p.encrypt_pki_payload_with(key_pem="KEY", cert_pem="CERT", passphrase=_OLD)
    assert p.decrypt_pki_payload_with(env, _OLD) == ("KEY", "CERT")
    with pytest.raises(RuntimeError):
        p.decrypt_pki_payload_with(env, _NEW)


# ── full rewrap over both stores ────────────────────────────────────


async def _seed(conn):
    """Insert one mastio_keys row + one pki_key_store row, both encrypted
    under _OLD."""
    await conn.execute(
        text(
            "INSERT INTO mastio_keys (kid, pubkey_pem, privkey_pem, cert_pem, "
            "created_at, activated_at) VALUES (:k, :pub, :priv, NULL, :c, :c)"
        ),
        {
            "k": "mastio-abc",
            "pub": "PUBKEY",
            "priv": p.encrypt_secret_with("PRIVKEY-PEM", _OLD),
            "c": "2026-06-05T00:00:00Z",
        },
    )
    await conn.execute(
        text(
            "INSERT INTO pki_key_store (key_id, key_type, ciphertext, cert_pem, "
            "created_at) VALUES (:id, :t, :ct, :cert, :c)"
        ),
        {
            "id": "intermediate-ca",
            "t": "intermediate_ca",
            "ct": p.encrypt_pki_payload_with(
                key_pem="CA-KEY", cert_pem="CA-CERT", passphrase=_OLD,
            ),
            "cert": "CA-CERT",
            "c": "2026-06-05T00:00:00Z",
        },
    )


@pytest.mark.asyncio
async def test_rewrap_rotates_both_stores(proxy_db):
    from mcp_proxy.db import get_db, rewrap_at_rest_master_key

    async with get_db() as conn:
        await _seed(conn)

    counts = await rewrap_at_rest_master_key(_OLD, _NEW)
    assert counts == {"mastio_keys": 1, "pki_key_store": 1}

    async with get_db() as conn:
        mk = (await conn.execute(
            text("SELECT privkey_pem FROM mastio_keys WHERE kid = 'mastio-abc'")
        )).scalar_one()
        ca = (await conn.execute(
            text("SELECT ciphertext FROM pki_key_store WHERE key_id = 'intermediate-ca'")
        )).scalar_one()

    # Now decrypts under NEW, and NOT under OLD.
    assert p.decrypt_secret_with(mk, _NEW) == "PRIVKEY-PEM"
    assert p.decrypt_pki_payload_with(ca, _NEW) == ("CA-KEY", "CA-CERT")
    with pytest.raises(RuntimeError):
        p.decrypt_secret_with(mk, _OLD)


@pytest.mark.asyncio
async def test_rewrap_wrong_old_aborts_without_writing(proxy_db):
    from mcp_proxy.db import get_db, rewrap_at_rest_master_key

    async with get_db() as conn:
        await _seed(conn)

    with pytest.raises(RuntimeError):
        await rewrap_at_rest_master_key("wrong-old-passphrase-32-chars-zzz", _NEW)

    # Untouched: still decrypts under the real OLD.
    async with get_db() as conn:
        mk = (await conn.execute(
            text("SELECT privkey_pem FROM mastio_keys WHERE kid = 'mastio-abc'")
        )).scalar_one()
    assert p.decrypt_secret_with(mk, _OLD) == "PRIVKEY-PEM"
