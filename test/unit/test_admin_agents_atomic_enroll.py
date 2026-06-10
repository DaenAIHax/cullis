"""Bug #6 tactical fix tests — atomic agent enrollment transaction.

The pre-fix POST ``/v1/admin/agents`` handler ran the key write
(``set_config('agent_key:<id>', key_pem)``) BEFORE the
``INSERT INTO internal_agents``. Two failure modes:

A. Multi-worker race: two workers concurrent on the same ``agent_id``
   land both ``set_config`` upserts (last write wins on the key) and
   then race the INSERT. The winner ships back a 201 with a key that
   already belongs to the loser, the loser hits the UNIQUE constraint
   and 409s, but proxy_config now holds the wrong key for the
   surviving row.

B. Single-worker overwrite-on-duplicate: admin tries to enroll an
   ``agent_id`` that already exists (typo, demo reset, recovery
   retry). ``set_config`` upserts the NEW key over the EXISTING agent's
   key. The INSERT then raises ``IntegrityError`` and the handler
   returns 409, but the existing agent's signing key has already been
   clobbered. That agent can no longer authenticate (its cert is
   pinned to the lost key).

The fix wraps INSERT + key-store in a single ``async with get_db()``
transaction and ORDERS the INSERT FIRST so the UNIQUE constraint
serialises duplicates BEFORE any key material is exposed. The two
tests below pin both invariants:

* ``test_duplicate_enrollment_does_not_clobber_existing_key`` covers (B):
  pre-existing key in ``proxy_config`` survives a failed duplicate
  enrollment attempt unchanged.
* ``test_concurrent_enrollment_serializes_on_unique_constraint`` covers
  (A): two ``asyncio.gather``-ed enrollments on the same agent_id end
  with exactly one row in ``internal_agents``, exactly one matching
  ``agent_key:<id>`` in ``proxy_config``, and one 201 / one 409.

A third test pins back-compat for ``set_config(key, value)`` without
the new ``conn`` kwarg — every existing call site in the codebase
must keep working.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.admin.agents import router as admin_agents_router
from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, get_config, get_db, init_db, set_config


_ADMIN_SECRET = "test-admin-secret-atomic-enroll"


# ── Stub AgentManager ──────────────────────────────────────────────────
#
# The real ``mcp_proxy.egress.agent_manager.AgentManager`` requires the
# Org CA loaded in memory. For this test we only need three surface
# members the handler touches:
#   * ``ca_loaded`` (truthy → request passes the ``_require_agent_mgr``
#     gate)
#   * ``org_id`` (used to compose ``agent_id``)
#   * ``_generate_agent_cert(agent_name)`` (returns a (cert_pem,
#     key_pem) pair; opaque to the handler, just stored as-is)
#   * ``_store_key_vault(agent_id, key_pem)`` (raises so the handler
#     falls through to the ``set_config`` fallback path, which is the
#     path we want to exercise — Vault success path doesn't touch
#     ``proxy_config`` at all and is covered by the third test)


class _StubAgentManager:
    ca_loaded = True

    def __init__(self, org_id: str, *, vault_succeeds: bool = False):
        self.org_id = org_id
        self._vault_succeeds = vault_succeeds
        self._mint_counter = 0

    async def _generate_agent_cert(self, agent_name: str) -> tuple[str, str]:
        # Unique per-mint output so the test can tell a stale key from a
        # fresh one byte-perfect.
        self._mint_counter += 1
        cert = (
            f"-----BEGIN CERTIFICATE-----\nstub-cert-{agent_name}-"
            f"{self._mint_counter}\n-----END CERTIFICATE-----\n"
        )
        key = (
            f"-----BEGIN PRIVATE KEY-----\nstub-key-{agent_name}-"
            f"{self._mint_counter}\n-----END PRIVATE KEY-----\n"
        )
        return cert, key

    async def _store_key_vault(self, agent_id: str, key_pem: str) -> None:
        if not self._vault_succeeds:
            raise RuntimeError("Vault backend not configured")
        # Silent success: a real Vault store would write to KV v2 here.
        # The handler must NOT fall back to proxy_config on success, and
        # the third test asserts that.
        return None


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    # NOTE: we run the full alembic chain here (no PROXY_SKIP_MIGRATIONS)
    # because the ``internal_agents.federated`` column lives only in a
    # migration, not in ``db_models.metadata``. ``metadata.create_all``
    # would build a schema missing that column and the INSERT in the
    # handler would fail with "no such column".
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "atomic_enroll.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _make_app(mgr: _StubAgentManager) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_agents_router)
    app.state.agent_manager = mgr
    return app


def _post_enroll(client: TestClient, agent_name: str) -> Any:
    return client.post(
        "/v1/admin/agents",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
        json={"agent_name": agent_name},
    )


# ── (B) single-worker overwrite-on-duplicate ───────────────────────────


def test_duplicate_enrollment_does_not_clobber_existing_key(proxy_db):
    """First enroll succeeds, second enroll on the same ``agent_id``
    returns 409 AND leaves the original agent's key in proxy_config
    unchanged.

    Pre-fix behaviour: the second ``set_config`` upserts the new key
    over the existing entry BEFORE the INSERT raises IntegrityError.
    The handler returns 409 but the original agent's authentication is
    silently broken.
    """
    mgr = _StubAgentManager("test-org")
    app = _make_app(mgr)
    client = TestClient(app)

    r1 = _post_enroll(client, "alice")
    assert r1.status_code == 201, r1.text
    first_key = r1.json()["private_key_pem"]
    assert first_key  # minted_locally → echoed

    # Snapshot the key stashed in proxy_config (Vault path raises in the
    # stub so the handler falls back to set_config).
    async def _read() -> str | None:
        return await get_config("agent_key:test-org::alice")

    stored_first = asyncio.run(_read())
    assert stored_first == first_key, (
        "first enroll must persist the minted key in proxy_config"
    )

    # Second enrollment with the same agent_name. Pre-fix this would
    # have minted a NEW keypair, upserted it over the existing
    # ``agent_key:test-org::alice`` row, then 409'd on the INSERT.
    r2 = _post_enroll(client, "alice")
    assert r2.status_code == 409, r2.text
    assert "already registered" in r2.text

    stored_after = asyncio.run(_read())
    assert stored_after == first_key, (
        "duplicate enrollment must NOT overwrite the existing agent's "
        "private key in proxy_config — pre-fix the upsert clobbered it "
        "before the INSERT raised IntegrityError"
    )


# ── (A) multi-worker race ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_enrollment_serializes_on_unique_constraint(proxy_db):
    """Two concurrent enrollments on the same agent_id end with:
      * exactly one 201 + one 409,
      * exactly one row in ``internal_agents``,
      * exactly one ``agent_key:<id>`` row in ``proxy_config``
        matching the winner's minted key.

    The PRIMARY KEY on ``internal_agents.agent_id`` serialises the
    INSERT, the IntegrityError rolls back the loser's transaction
    (including its ``set_config`` fallback in the same tx), and the
    winner's key is the one that survives.
    """
    mgr = _StubAgentManager("test-org")
    app = _make_app(mgr)

    # Drive the handler concurrently via the ASGI transport — TestClient
    # is sync so we use httpx ASGITransport instead. Two coroutines
    # racing on the same agent_name exercise the UNIQUE constraint.
    from httpx import ASGITransport, AsyncClient
    transport = ASGITransport(app=app)
    h = {"X-Admin-Secret": _ADMIN_SECRET}
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        r1, r2 = await asyncio.gather(
            cli.post("/v1/admin/agents", headers=h, json={"agent_name": "bob"}),
            cli.post("/v1/admin/agents", headers=h, json={"agent_name": "bob"}),
        )

    codes = sorted([r1.status_code, r2.status_code])
    assert codes == [201, 409], (
        f"expected one winner one loser, got {codes}: "
        f"{r1.text!r} / {r2.text!r}"
    )

    winner = r1 if r1.status_code == 201 else r2
    winning_key = winner.json()["private_key_pem"]

    async with get_db() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT agent_id FROM internal_agents "
                    "WHERE agent_id = :aid"
                ),
                {"aid": "test-org::bob"},
            )
        ).all()
    assert len(rows) == 1, (
        "exactly one internal_agents row expected for the duplicated "
        f"agent_id; got {len(rows)}"
    )

    stored_key = await get_config("agent_key:test-org::bob")
    assert stored_key == winning_key, (
        "proxy_config must hold the winner's key — the loser's "
        "set_config write should have rolled back with the failed "
        "INSERT (it runs on the same conn inside the same transaction)"
    )


# ── Vault-success path: no proxy_config write ────────────────────────


def test_vault_success_path_does_not_touch_proxy_config(proxy_db):
    """When ``_store_key_vault`` succeeds, the handler must NOT write
    the key into ``proxy_config`` as a fallback. Asserts the
    Vault-preferred path stays clean.
    """
    mgr = _StubAgentManager("test-org", vault_succeeds=True)
    app = _make_app(mgr)
    client = TestClient(app)

    r = _post_enroll(client, "carol")
    assert r.status_code == 201, r.text

    async def _read() -> str | None:
        return await get_config("agent_key:test-org::carol")

    assert asyncio.run(_read()) is None, (
        "Vault-success path must not fall back to proxy_config; the "
        "agent_key entry should be absent"
    )


# ── set_config back-compat ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_set_config_backward_compat_without_conn_kwarg(proxy_db):
    """The new ``conn`` keyword on ``set_config`` is optional. Every
    pre-existing call site in the codebase invokes ``set_config(key,
    value)`` positionally and must keep working. This pins that
    behaviour explicitly so a future refactor cannot break it.
    """
    await set_config("compat-test-key", "value-A")
    assert await get_config("compat-test-key") == "value-A"

    # Upsert path: same call, different value.
    await set_config("compat-test-key", "value-B")
    assert await get_config("compat-test-key") == "value-B"


@pytest.mark.asyncio
async def test_set_config_with_explicit_conn_writes_on_same_tx(proxy_db):
    """When ``conn`` is provided, the upsert runs on the open
    connection — verified by ensuring the write is visible inside the
    same ``get_db()`` block before commit.
    """
    async with get_db() as conn:
        await set_config("tx-test-key", "value-in-tx", conn=conn)
        # Same connection sees the row inside the open tx.
        row = (
            await conn.execute(
                text("SELECT value FROM proxy_config WHERE key = :k"),
                {"k": "tx-test-key"},
            )
        ).mappings().first()
        assert row is not None and row["value"] == "value-in-tx"

    # And the value survives commit.
    assert await get_config("tx-test-key") == "value-in-tx"
