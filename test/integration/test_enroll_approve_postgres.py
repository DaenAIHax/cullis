"""S-2 regression — enroll → approve survives a live Postgres 16.

The dashboard-approval enroll path (``enrollment.service.approve``) issues
an ``INSERT INTO internal_agents`` whose bind parameters are type-permissive
on SQLite but strict on asyncpg. Two defects shipped in the soak image and
crashed the *first* agent approval on Postgres (the recommended pilot /
production backend) with HTTP 500, while the whole SQLite-backed unit +
integration suite stayed green:

1. ``federated`` was the integer literal ``1`` on a BOOLEAN column →
   ``asyncpg.exceptions.DatatypeMismatchError``.
2. ``federated_at`` reused the ``:created`` text bind (ISO string) on a
   ``TIMESTAMP WITH TIME ZONE`` column. Because ``:created`` also feeds the
   text ``created_at`` / ``enrolled_at`` columns, asyncpg could not deduce a
   single type for the parameter →
   ``asyncpg.exceptions.AmbiguousParameterError``.

Fixed in commit 44ed2632 (``federated=false``, ``federated_at=NULL``). This
test runs the real ``start_enrollment`` → ``approve`` pair against asyncpg so
a future edit that reintroduces an int-on-boolean or an ambiguously-typed
timestamp bind fails here instead of in a prod-shape dogfood.

Run::

    docker compose -f test/compose-pg.yml up -d --wait
    export CULLIS_TEST_PG_URL=postgresql+asyncpg://cullis:cullis@127.0.0.1:5544/cullis_test
    pytest test/integration/test_enroll_approve_postgres.py -m postgres -v

Gated behind ``@pytest.mark.postgres`` so laptops without Docker stay green.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.postgres


@pytest.fixture
def pg_test_url(pg_url, monkeypatch) -> str:
    """Hand back the live PG URL and stamp the env vars the proxy reads.

    Mirrors ``test_alembic_full_chain_postgres.py`` so ``init_db`` / the
    cached ``get_settings`` resolve to Postgres, not the SQLite default.
    """
    monkeypatch.setenv("PROXY_DB_URL", pg_url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    yield pg_url
    get_settings.cache_clear()


async def _reset_public_schema(url: str) -> None:
    """Drop + recreate ``public`` so the Alembic chain runs against a clean DB."""
    admin = create_async_engine(url, future=True, isolation_level="AUTOCOMMIT")
    try:
        async with admin.connect() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("SET search_path TO public"))
    finally:
        await admin.dispose()


class _FakeAgentManager:
    """Minimal stand-in for AgentManager — ``approve`` only reads
    ``ca_loaded`` / ``org_id`` / ``trust_domain`` and awaits
    ``sign_external_pubkey``. No real CA needed: the INSERT just stores the
    returned PEM, and this test is about the column *types*, not the cert.
    """

    ca_loaded = True
    org_id = "testorg"
    trust_domain = "testorg.test"

    async def sign_external_pubkey(self, *, pubkey_pem: str, agent_name: str) -> str:
        return f"-----BEGIN CERTIFICATE-----\nstub-{agent_name}\n-----END CERTIFICATE-----\n"


def _fresh_pop_kwargs() -> dict[str, str]:
    """Real ECDSA P-256 keypair + pop_signature that satisfies
    ``start_enrollment``'s fingerprint parse and H-csr-pop verify."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()
    canonical = f"enrollment-pop:v1|{fp}".encode("utf-8")
    sig = priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
    pop = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return {"pubkey_pem": pem, "pop_signature": pop}


def test_enroll_approve_inserts_clean_on_postgres(pg_test_url):
    """``approve`` must complete on asyncpg and land a row with the
    fixed boolean/timestamp columns. Pre-fix this raised
    DatatypeMismatchError / AmbiguousParameterError → HTTP 500."""
    from mcp_proxy import db as db_module
    from mcp_proxy.enrollment.service import start_enrollment, approve

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        await db_module.init_db(pg_test_url)
        try:
            async with db_module.get_db() as conn:
                started = await start_enrollment(
                    conn,
                    **_fresh_pop_kwargs(),
                    requester_name="alice",
                    requester_email="alice@example.com",
                    reason=None,
                    device_info=json.dumps({"os": "linux", "hostname": "pg-box"}),
                )

            # The statement under test. On the buggy revision this awaits
            # straight into an asyncpg type error.
            async with db_module.get_db() as conn:
                await approve(
                    conn,
                    session_id=started.session_id,
                    agent_id="testorg::alice",
                    capabilities=["llm.chat"],
                    groups=[],
                    admin_name="admin",
                    agent_manager=_FakeAgentManager(),
                )

            # Row landed with the corrected column types.
            from mcp_proxy.db import get_agent
            row = await get_agent("testorg::alice")
            assert row is not None, "approve did not persist the agent row"
            # federated is a real BOOLEAN on Postgres → Python False, never 1.
            assert row["federated"] is False, (
                f"federated should be boolean False, got {row['federated']!r}"
            )
            # federated_at is NULL for a non-federated agent (no ambiguous
            # text-on-timestamptz bind).
            assert row["federated_at"] is None, (
                f"federated_at should be NULL, got {row['federated_at']!r}"
            )
            # Sanity: the integer columns the same INSERT carries stayed
            # well-typed (is_active=1, federation_revision=1 are Integer,
            # not Boolean — a guard against a future over-eager "fix").
            assert row["is_active"]
            assert row["reach"] == "both"
        finally:
            await db_module.dispose_db()

    asyncio.run(_run())
