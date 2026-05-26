"""D-9 cold-reader dogfood (2026-05-25) tests — PKI bootstrap multi-worker
race-free guarantee.

Pre-fix ``AgentManager.generate_org_ca`` had no atomic-persistence
gate. Under ``MASTIO_WORKERS=4`` (Mastio bundle default) every uvicorn
worker ran the lifespan in parallel and called this function
independently, each generating a fresh EC P-256 keypair + a self-
signed Org CA cert from it. The legacy plaintext path (``set_config``)
upserted whichever worker landed last; the resulting on-disk
``proxy_config.org_ca_{key,cert}`` rows came from one worker while
the ``derive_org_id`` value came from yet another, and the in-memory
``self._org_ca_key`` of each worker pointed at its own candidate key
— diverging from the persisted pair the nginx sidecar exported as
the trust bundle.

Downstream effect: the Mastio Intermediate CA gets minted by a worker
signing with key A; the nginx ``org-ca.crt`` is from worker B's key.
Any agent leaf signed by the Intermediate (chain leaf || intermediate)
fails ``openssl verify -CAfile org-ca.crt agent.crt`` with::

    error 7 at 1 depth lookup: certificate signature failure
    ECDSA digest_verify_final:provider signature failure

The cold-reader chat smoke fails at the mTLS handshake: nginx returns
``400 Bad Request — The SSL certificate error`` before the request
ever reaches uvicorn.

The fix mirrors the pre-existing ``_mint_mastio_ca`` winner-election
pattern (see ``_persist_intermediate_ca`` line 1770+): persist the
new pair via ``set_config_if_absent`` (the dev fallback) or via the
provider-level ``store_org_ca`` (encrypted path); on a lost race
re-read the winning pair from the source-of-truth and adopt it into
the worker's in-memory state before any signing happens. These tests
pin the invariants.

Sister atomic-enrollment tests live in
``test_admin_agents_atomic_enroll.py`` (PR #928 pattern). Keep the
fixture shape aligned so the two test files exercise the same race-
serialization primitive.
"""
from __future__ import annotations

import asyncio
import hashlib

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, get_config, init_db
from mcp_proxy.egress.agent_manager import AgentManager


_ADMIN_SECRET = "test-pki-bootstrap-concurrent-secret"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite + audit chain disabled. Skipping migrations is
    safe here — ``generate_org_ca`` only touches ``proxy_config`` (the
    metadata-defined rows ``org_id`` / ``org_ca_key`` / ``org_ca_cert``)
    and the legacy fallback path that ``set_config_if_absent`` operates
    on, so the migration chain that adds ``internal_agents.federated``
    is not needed for this test.
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    # Force the dev fallback path: no PKI master key → set_config_if_absent
    # branch. The encrypted KMS path (provider.store_org_ca + atomic
    # insert under pki_key_store) is provider-level and tested
    # separately when the provider plugin is exercised.
    monkeypatch.delenv("MCP_PROXY_DB_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "pki_bootstrap.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _pubkey_der(key_or_cert) -> bytes:
    return key_or_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) if hasattr(key_or_cert, "public_key") else key_or_cert.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.mark.asyncio
async def test_concurrent_generate_org_ca_converges_single_persisted_pair(proxy_db):
    """N parallel workers calling ``generate_org_ca(derive_org_id=True)``
    must converge on exactly one persisted Org CA pair, and every
    worker's in-memory state must point at that same pair after the
    gather completes. The placeholder org_id passed to each manager
    is replaced by the winner-derived value during the call."""
    placeholder_org_id = "placeholder-pre-derive"
    managers = [AgentManager(placeholder_org_id) for _ in range(5)]

    # Race the lifespan-equivalent boot path: every "worker" enters
    # generate_org_ca concurrently with the same DB underneath.
    await asyncio.gather(*(
        m.generate_org_ca(derive_org_id=True) for m in managers
    ))

    # Exactly one org_id row persisted (the winner's derivation; losers
    # must NOT have stamped over it).
    persisted_org_id = await get_config("org_id")
    assert persisted_org_id is not None
    assert persisted_org_id != placeholder_org_id

    # Every worker converged on the persisted org_id (no split-brain
    # where some workers keep their own derivation).
    in_memory_ids = [m._org_id for m in managers]
    assert all(oid == persisted_org_id for oid in in_memory_ids), (
        f"divergent org_ids across workers: {in_memory_ids}"
    )

    # Exactly one cert + one key pair persisted.
    persisted_cert_pem = await get_config("org_ca_cert")
    persisted_key_pem = await get_config("org_ca_key")
    assert persisted_cert_pem is not None
    assert persisted_key_pem is not None

    # Every worker's in-memory cert is byte-identical to the persisted
    # cert (the SHA-256 fingerprint roundtrips). This is the
    # invariant that, when violated, causes the nginx mTLS chain
    # failure observed in the dogfood.
    persisted_cert = x509.load_pem_x509_certificate(persisted_cert_pem.encode())
    persisted_fp = persisted_cert.fingerprint(hashes.SHA256()).hex()
    in_memory_fps = [
        m._org_ca_cert.fingerprint(hashes.SHA256()).hex()
        for m in managers
    ]
    assert all(fp == persisted_fp for fp in in_memory_fps), (
        f"divergent cert fingerprints across workers — D-9 race not "
        f"closed. persisted={persisted_fp[:16]}…, workers="
        f"{[fp[:16] + '…' for fp in in_memory_fps]}"
    )


@pytest.mark.asyncio
async def test_concurrent_generate_org_ca_persisted_key_matches_cert(proxy_db):
    """The winning persisted pair must be internally consistent: the
    private key's public component matches the cert's subject pubkey.
    A split-brain (key from worker A, cert from worker B) would let
    nginx mTLS accept the chain on file but fail the actual signing
    check — exactly the D-9 dogfood symptom. Eight workers, more
    racy than the four-worker production default."""
    placeholder_org_id = "ph"
    managers = [AgentManager(placeholder_org_id) for _ in range(8)]
    await asyncio.gather(*(
        m.generate_org_ca(derive_org_id=True) for m in managers
    ))

    persisted_key_pem = await get_config("org_ca_key")
    persisted_cert_pem = await get_config("org_ca_cert")
    assert persisted_key_pem and persisted_cert_pem

    key = serialization.load_pem_private_key(
        persisted_key_pem.encode(), password=None,
    )
    cert = x509.load_pem_x509_certificate(persisted_cert_pem.encode())

    key_pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pub_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert key_pub_der == cert_pub_der, (
        "split-brain: persisted private key does NOT match persisted "
        "cert pubkey. The on-disk pair would fail any chain that signs "
        "off it (D-9 dogfood symptom)."
    )

    # Persisted org_id must derive from the persisted cert pubkey
    # (closes the loop: org_id, key, cert all from the same winning
    # worker, no straddling).
    derived = hashlib.sha256(cert_pub_der).hexdigest()[:16]
    persisted_org_id = await get_config("org_id")
    assert derived == persisted_org_id, (
        f"persisted org_id={persisted_org_id} does NOT derive from "
        f"persisted cert pubkey={derived} — split-brain between the "
        f"derivation step and the cert persistence step."
    )


@pytest.mark.asyncio
async def test_concurrent_generate_org_ca_every_worker_can_sign(proxy_db):
    """After the race, every worker must be able to use its
    ``self._org_ca_key`` to sign material that verifies against the
    persisted ``org_ca_cert``. Without the winner-adoption step a
    losing worker would still hold its discarded candidate key and
    produce signatures the nginx trust bundle rejects."""
    placeholder_org_id = "ph"
    managers = [AgentManager(placeholder_org_id) for _ in range(4)]
    await asyncio.gather(*(
        m.generate_org_ca(derive_org_id=True) for m in managers
    ))

    persisted_cert_pem = await get_config("org_ca_cert")
    persisted_cert = x509.load_pem_x509_certificate(persisted_cert_pem.encode())
    cert_pub_der = persisted_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    for i, m in enumerate(managers):
        worker_pub_der = m._org_ca_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert worker_pub_der == cert_pub_der, (
            f"worker {i} holds a private key whose pubkey does not "
            f"match the persisted cert pubkey. Any leaf signed by "
            f"this worker would fail ``openssl verify`` against the "
            f"nginx-exported org-ca.crt — exactly the D-9 symptom."
        )
