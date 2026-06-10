"""Regression tests for issue cullis#997.

Before this fix, ``AgentManager._mint_mastio_leaf`` had no cross-worker
guard: the N uvicorn workers at lifespan startup each generated their
own EC keypair and INSERTed an active ``mastio_keys`` row. With N>1
active rows, ``LocalKeyStore.current_signer()`` raised
``RuntimeError("N active mastio keys")``, ``app.state.local_issuer``
stayed None, and ``/v1/auth/token`` returned 503 "local issuer not
initialized" for the rest of the deploy.

These tests pin the fix:

  - ``deprecate_mastio_keys_by_kids`` only touches active rows whose
    kid is in the supplied list and idempotently no-ops on rows
    already deprecated.
  - ``AgentManager._mint_mastio_leaf`` invoked against a DB that
    already carries N>1 active rows (the in-the-wild leftover from
    pre-fix boots) repairs the invariant: the newest row by
    ``activated_at`` survives, the older ones get a non-NULL
    ``deprecated_at``, ``current_signer()`` returns the survivor, and
    no additional row is inserted.
  - ``AgentManager._mint_mastio_leaf`` invoked against a DB with
    exactly 1 active row adopts it without inserting a duplicate.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text


async def _insert_active_row(db_url: str, kid: str, activated_at: str) -> None:
    """Bypass ``insert_mastio_key`` so the test can seed multiple
    active rows (which the production helper does not prevent today
    but the new flock guard avoids producing).
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(db_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO mastio_keys
                        (kid, pubkey_pem, privkey_pem, cert_pem,
                         created_at, activated_at, deprecated_at, expires_at)
                    VALUES
                        (:kid, :pub, :priv, NULL, :created, :activated,
                         NULL, NULL)
                    """
                ),
                {
                    "kid": kid,
                    "pub": f"PUB-{kid}",
                    "priv": f"PRIV-{kid}",
                    "created": activated_at,
                    "activated": activated_at,
                },
            )
    finally:
        await engine.dispose()


async def _count_active(db_url: str) -> int:
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(db_url, future=True)
    try:
        async with engine.begin() as conn:
            result = await conn.execute(
                text(
                    """
                    SELECT COUNT(*) FROM mastio_keys
                     WHERE activated_at IS NOT NULL
                       AND deprecated_at IS NULL
                    """
                )
            )
            return result.scalar() or 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_deprecate_mastio_keys_by_kids_only_touches_listed_active_rows(
    audit_test_env,
):
    """``deprecate_mastio_keys_by_kids`` deprecates exactly the kids
    supplied that are still active. Already-deprecated rows and
    rows not in the list are left alone.
    """
    from mcp_proxy.db import (
        deprecate_mastio_keys_by_kids,
        init_db,
        get_mastio_keys_active,
    )

    db_url = audit_test_env
    await init_db(db_url)

    # 3 active rows + 1 already deprecated (out of scope).
    now = datetime.now(timezone.utc).isoformat()
    await _insert_active_row(db_url, "k1", now)
    await _insert_active_row(db_url, "k2", now)
    await _insert_active_row(db_url, "k3", now)
    # Insert a row then manually mark it deprecated.
    await _insert_active_row(db_url, "k4-deprecated", now)
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(db_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE mastio_keys SET deprecated_at = :d "
                    "WHERE kid = :k"
                ),
                {"d": now, "k": "k4-deprecated"},
            )
    finally:
        await engine.dispose()

    assert await _count_active(db_url) == 3

    # Deprecate k1 and k2 only; k3 stays; k4-deprecated stays deprecated.
    updated = await deprecate_mastio_keys_by_kids(
        ["k1", "k2", "k4-deprecated"], now,
    )
    # k4 was already deprecated; the WHERE clause excludes it.
    assert updated == 2

    remaining_active = {row["kid"] for row in await get_mastio_keys_active()}
    assert remaining_active == {"k3"}

    # Idempotency: a repeat call updates 0 rows.
    updated_again = await deprecate_mastio_keys_by_kids(
        ["k1", "k2", "k4-deprecated"], now,
    )
    assert updated_again == 0


@pytest.mark.asyncio
async def test_deprecate_mastio_keys_by_kids_empty_list_noop(audit_test_env):
    from mcp_proxy.db import deprecate_mastio_keys_by_kids, init_db

    db_url = audit_test_env
    await init_db(db_url)

    assert await deprecate_mastio_keys_by_kids([], "any") == 0


@pytest.mark.asyncio
async def test_mint_mastio_leaf_repairs_pre_existing_invariant_violation(
    audit_test_env, monkeypatch,
):
    """When the DB carries N>1 active rows (the in-the-wild leftover
    from pre-fix multi-worker boots), ``_mint_mastio_leaf`` keeps the
    newest by ``activated_at`` and deprecates the older ones instead
    of inserting yet another fresh row.
    """
    from mcp_proxy.db import init_db
    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.config import get_settings

    db_url = audit_test_env
    await init_db(db_url)

    # Seed 4 active rows, newest is k-newest.
    older = "2026-05-01T00:00:00+00:00"
    newer = "2026-05-28T00:00:00+00:00"
    await _insert_active_row(db_url, "k-old-1", older)
    await _insert_active_row(db_url, "k-old-2", older)
    await _insert_active_row(db_url, "k-old-3", older)
    await _insert_active_row(db_url, "k-newest", newer)
    assert await _count_active(db_url) == 4

    # Boot a fresh AgentManager with the org_id derived from the
    # cached Org CA (we mint one through the manager so the leaf-mint
    # path can sign against it). Standalone proxy.
    settings = get_settings()
    mgr = AgentManager(
        org_id="test-org-997",
        trust_domain=settings.trust_domain,
    )
    # Mint the Org CA (idempotent on a fresh DB).
    await mgr.generate_org_ca(derive_org_id=False)
    # The CA loader caches; load it into the manager so the leaf-mint
    # path has a parent to sign against.
    await mgr.load_org_ca_from_config()

    # Boot identity. The mint path acquires the flock, finds 4 active
    # rows, keeps k-newest, deprecates the rest.
    await mgr.ensure_mastio_identity()

    assert await _count_active(db_url) == 1
    # The survivor is k-newest, the newest by activated_at.
    from mcp_proxy.db import get_mastio_keys_active
    survivors = await get_mastio_keys_active()
    assert len(survivors) == 1
    assert survivors[0]["kid"] == "k-newest"


@pytest.mark.asyncio
async def test_mint_mastio_leaf_adopts_singleton_without_dup(
    audit_test_env, monkeypatch,
):
    """When the DB carries exactly 1 active row (the happy steady
    state), ``_mint_mastio_leaf`` adopts it without inserting a new
    keypair.
    """
    from mcp_proxy.db import init_db
    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.config import get_settings

    db_url = audit_test_env
    await init_db(db_url)

    now = datetime.now(timezone.utc).isoformat()
    await _insert_active_row(db_url, "k-singleton", now)
    assert await _count_active(db_url) == 1

    settings = get_settings()
    mgr = AgentManager(
        org_id="test-org-997-singleton",
        trust_domain=settings.trust_domain,
    )
    await mgr.generate_org_ca(derive_org_id=False)
    await mgr.load_org_ca_from_config()
    await mgr.ensure_mastio_identity()

    # Still exactly 1 active row, the seeded one.
    assert await _count_active(db_url) == 1
    from mcp_proxy.db import get_mastio_keys_active
    survivors = await get_mastio_keys_active()
    assert len(survivors) == 1
    assert survivors[0]["kid"] == "k-singleton"
