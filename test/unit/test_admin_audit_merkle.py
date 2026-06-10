"""Unit tests for ``mcp_proxy.admin.audit_merkle`` — the two
read-only admin endpoints that expose ``audit_merkle_anchors``
rows and inclusion proofs.

Exercises the endpoints via the FastAPI TestClient against an
ephemeral SQLite DB seeded with audit_log rows and one Merkle
anchor produced by the Phase 1 watcher. Validates: auth gate,
proof shape, root replay against the Phase 0 verifier, 404 on
unanchored chain_seq, 409 on chain_count drift.
"""
from __future__ import annotations

import hashlib

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.admin.audit_merkle import router as admin_merkle_router
from mcp_proxy.audit.merkle import verify_inclusion
from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.lifespan import merkle_anchor_watcher as mw


_ADMIN_SECRET = "test-admin-secret-merkle"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "admin_merkle.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


@pytest.fixture
def app(proxy_db) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_merkle_router)
    return app


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


def _h(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


async def _seed_audit_log(start: int, count: int) -> list[tuple[int, str]]:
    rows = [
        (start + i, _h(f"row-{start + i}".encode()))
        for i in range(count)
    ]
    async with get_db() as conn:
        for chain_seq, row_hash in rows:
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(timestamp, agent_id, action, status, chain_seq, "
                    " row_hash, prev_hash) "
                    "VALUES ('2026-05-24T00:00:00Z', 'test::agent', "
                    "'test_action', 'ok', :chain_seq, :row_hash, '')"
                ),
                {"chain_seq": chain_seq, "row_hash": row_hash},
            )
    return rows


async def _emit_anchor(batch_size: int = 8, min_batch: int = 4) -> None:
    await mw._tick(
        org_id="acme",
        batch_size=batch_size,
        min_batch=min_batch,
        tsa_enabled=False,
        tsa_url="http://unused",
        tsa_timeout=1.0,
    )


# ── Auth gate ───────────────────────────────────────────────────────


def test_anchors_requires_admin_secret(client):
    resp = client.get("/v1/admin/audit/merkle/anchors")
    assert resp.status_code == 422  # missing header


def test_anchors_rejects_wrong_secret(client):
    resp = client.get(
        "/v1/admin/audit/merkle/anchors",
        headers={"X-Admin-Secret": "wrong"},
    )
    assert resp.status_code == 403


def test_proof_requires_admin_secret(client):
    resp = client.get("/v1/admin/audit/merkle/proof/1")
    assert resp.status_code == 422


def test_proof_rejects_wrong_secret(client):
    resp = client.get(
        "/v1/admin/audit/merkle/proof/1",
        headers={"X-Admin-Secret": "wrong"},
    )
    assert resp.status_code == 403


# ── /anchors ────────────────────────────────────────────────────────


def test_anchors_empty_returns_empty_list(client):
    resp = client.get(
        "/v1/admin/audit/merkle/anchors",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"anchors": [], "count": 0}


@pytest.mark.asyncio
async def test_anchors_lists_recent_first(client):
    """Three batches emitted; the endpoint returns them DESC by id."""
    await _seed_audit_log(start=1, count=24)
    for _ in range(3):
        await _emit_anchor(batch_size=8, min_batch=4)

    resp = client.get(
        "/v1/admin/audit/merkle/anchors",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 3
    ranges = [
        (a["chain_seq_start"], a["chain_seq_end"])
        for a in body["anchors"]
    ]
    # Most recent (highest id) first.
    assert ranges == [(17, 24), (9, 16), (1, 8)]
    # Sanity on the rest of the schema for the most recent anchor.
    most_recent = body["anchors"][0]
    assert most_recent["leaf_count"] == 8
    assert most_recent["org_id"] == "acme"
    assert len(most_recent["merkle_root"]) == 64  # sha256 hex
    assert most_recent["tsa_token_b64"] is None  # TSA disabled in fixture


@pytest.mark.asyncio
async def test_anchors_filters_by_org_id(client):
    """Inserting a hand-crafted anchor for a second org and filtering."""
    await _seed_audit_log(start=1, count=8)
    await _emit_anchor()
    # Hand-craft a second-org anchor directly.
    async with get_db() as conn:
        await conn.execute(text(
            "INSERT INTO audit_merkle_anchors "
            "(created_at, org_id, chain_seq_start, chain_seq_end, "
            " leaf_count, merkle_root, tsa_url, tsa_token) "
            "VALUES ('2026-05-24T00:00:00Z', 'other-org', 100, 107, 8, "
            "'00'*32, NULL, NULL)"
        ))

    resp = client.get(
        "/v1/admin/audit/merkle/anchors?org_id=acme",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["anchors"][0]["org_id"] == "acme"


@pytest.mark.asyncio
async def test_anchors_limit_caps_output(client):
    await _seed_audit_log(start=1, count=24)
    for _ in range(3):
        await _emit_anchor(batch_size=8, min_batch=4)
    resp = client.get(
        "/v1/admin/audit/merkle/anchors?limit=2",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.json()["count"] == 2


def test_anchors_limit_validation(client):
    resp = client.get(
        "/v1/admin/audit/merkle/anchors?limit=0",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 422
    resp = client.get(
        "/v1/admin/audit/merkle/anchors?limit=10000",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 422


# ── /proof/{chain_seq} ──────────────────────────────────────────────


def test_proof_404_when_no_anchor_exists(client):
    resp = client.get(
        "/v1/admin/audit/merkle/proof/1",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_proof_404_when_chain_seq_outside_anchored_range(client):
    """chain_seq 9 is outside the [1,8] anchor."""
    await _seed_audit_log(start=1, count=8)
    await _emit_anchor()
    resp = client.get(
        "/v1/admin/audit/merkle/proof/9",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_proof_returns_valid_inclusion_for_anchored_seq(client):
    """End-to-end: emit an anchor, fetch the proof for any leaf in
    range, replay verify_inclusion against the returned root."""
    rows = await _seed_audit_log(start=1, count=8)
    await _emit_anchor()

    # Pick an arbitrary middle leaf to exercise non-edge proof shape.
    target_seq = 5
    resp = client.get(
        f"/v1/admin/audit/merkle/proof/{target_seq}",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["chain_seq"] == target_seq
    assert body["chain_seq_start"] == 1
    assert body["chain_seq_end"] == 8
    assert body["leaf_count"] == 8

    # Replay the math via the Phase 0 verifier — independent of any
    # server-side trust.
    leaf = bytes.fromhex(body["leaf_hex"])
    root = bytes.fromhex(body["merkle_root"])
    proof = [
        (bytes.fromhex(step["sibling_hex"]), step["position"])
        for step in body["proof"]
    ]
    assert verify_inclusion(leaf, proof, root), (
        "server-returned proof must verify against server-returned root"
    )

    # The leaf the server returned must match the audit_log row_hash
    # we seeded — otherwise the SELECT order disagreed with the
    # anchor's leaf ordering at emission time.
    expected_leaf_hex = rows[target_seq - 1][1]
    assert body["leaf_hex"] == expected_leaf_hex


@pytest.mark.asyncio
async def test_proof_for_every_leaf_in_anchor(client):
    """Every leaf in the anchored range must yield a valid proof
    against the anchor's root. Catches off-by-one errors in the
    server-side leaf index derivation."""
    rows = await _seed_audit_log(start=1, count=8)
    await _emit_anchor()
    for chain_seq, expected_row_hash in rows:
        resp = client.get(
            f"/v1/admin/audit/merkle/proof/{chain_seq}",
            headers={"X-Admin-Secret": _ADMIN_SECRET},
        )
        assert resp.status_code == 200, (
            f"chain_seq={chain_seq} returned {resp.status_code}: "
            f"{resp.text}"
        )
        body = resp.json()
        assert body["leaf_hex"] == expected_row_hash
        leaf = bytes.fromhex(body["leaf_hex"])
        root = bytes.fromhex(body["merkle_root"])
        proof = [
            (bytes.fromhex(s["sibling_hex"]), s["position"])
            for s in body["proof"]
        ]
        assert verify_inclusion(leaf, proof, root)


@pytest.mark.asyncio
async def test_proof_409_when_audit_log_disagrees_with_leaf_count(client):
    """Hand-craft an anchor that claims leaf_count=8 but only 4
    audit_log rows exist in its range. The endpoint refuses to
    emit a proof against a known-inconsistent state."""
    await _seed_audit_log(start=1, count=4)
    async with get_db() as conn:
        await conn.execute(text(
            "INSERT INTO audit_merkle_anchors "
            "(created_at, org_id, chain_seq_start, chain_seq_end, "
            " leaf_count, merkle_root, tsa_url, tsa_token) "
            "VALUES ('2026-05-24T00:00:00Z', 'acme', 1, 4, 8, "
            "'00'*32, NULL, NULL)"
        ))
    resp = client.get(
        "/v1/admin/audit/merkle/proof/1",
        headers={"X-Admin-Secret": _ADMIN_SECRET},
    )
    assert resp.status_code == 409
