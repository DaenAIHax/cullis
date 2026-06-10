"""Tests for ``GET /v1/admin/audit/export`` (offline-verification export).

The endpoint streams the audit store as the NDJSON bundle shape
``scripts/cullis-audit-verify.py`` consumes. Pins: the admin-secret
auth gate, the per-row ``kind``/``chain`` tagging, the chain /
``org_id`` / seq-window filters, keyset multi-batch streaming
completeness, anchor inclusion, and — the point of the whole PR — the
round trip: seed → export → run the offline verifier on the body →
exit 0; tamper the body → exit 2.

Pattern: FastAPI TestClient against an ephemeral SQLite DB
(``test_admin_audit_merkle.py``), verifier loaded via importlib
(``test_cullis_audit_verify_*.py``).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.admin.audit_export import router as admin_export_router
from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    compute_audit_row_hash,
    dispose_db,
    get_db,
    init_db,
)
from mcp_proxy.local.audit_chain import compute_entry_hash_v2

_ADMIN_SECRET = "test-admin-secret-export"

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "cullis-audit-verify.py"
)


def _load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "cullis_audit_verify_cli_export_roundtrip", str(_SCRIPT_PATH),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load_cli_module()


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    get_settings.cache_clear()
    db_path = tmp_path / "audit_export.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.fixture
def client(proxy_db) -> TestClient:
    app = FastAPI()
    app.include_router(admin_export_router)
    return TestClient(app)


def _auth() -> dict[str, str]:
    return {"X-Admin-Secret": _ADMIN_SECRET}


async def _seed_audit_log(count: int, *, start: int = 1) -> list[str]:
    """Insert ``count`` chained audit_log v2 rows; returns row hashes."""
    hashes: list[str] = []
    prev = "genesis"
    rows = []
    for i in range(start, start + count):
        row_hash = compute_audit_row_hash(
            chain_seq=i,
            timestamp="2026-06-10T00:00:00+00:00",
            agent_id="acme::trader-1",
            action="egress_llm_chat",
            tool_name=None,
            status="success",
            detail=f"row {i}",
            request_id=None,
            prev_hash=prev,
            dpop_jkt="jkt-test",
            on_behalf_of_user_id=None,
            hash_format="v2",
        )
        rows.append({
            "ts": "2026-06-10T00:00:00+00:00",
            "agent": "acme::trader-1",
            "action": "egress_llm_chat",
            "status": "success",
            "detail": f"row {i}",
            "seq": i,
            "prev": prev,
            "rh": row_hash,
        })
        hashes.append(row_hash)
        prev = row_hash
    async with get_db() as conn:
        for r in rows:
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(timestamp, agent_id, action, status, detail, "
                    " chain_seq, prev_hash, row_hash, hash_format, "
                    " dpop_jkt) "
                    "VALUES (:ts, :agent, :action, :status, :detail, "
                    " :seq, :prev, :rh, 'v2', 'jkt-test')"
                ),
                r,
            )
    return hashes


async def _seed_local_audit(count: int, org: str = "acme") -> None:
    prev = None
    async with get_db() as conn:
        for i in range(1, count + 1):
            from datetime import datetime, timezone
            ts = datetime(2026, 6, 10, 1, 0, i, tzinfo=timezone.utc)
            entry_hash = compute_entry_hash_v2(
                timestamp=ts,
                event_type="oneshot",
                agent_id=f"{org}::alice",
                session_id=None,
                org_id=org,
                result="success",
                details="",
                previous_hash=prev,
                chain_seq=i,
                peer_org_id=None,
            )
            await conn.execute(
                text(
                    "INSERT INTO local_audit "
                    "(timestamp, event_type, agent_id, session_id, org_id, "
                    " details, result, entry_hash, previous_hash, chain_seq, "
                    " hash_format) "
                    "VALUES (:ts, 'oneshot', :agent, NULL, :org, '', "
                    " 'success', :eh, :prev, :seq, 'v2')"
                ),
                {
                    "ts": ts.isoformat(),
                    "agent": f"{org}::alice",
                    "org": org,
                    "eh": entry_hash,
                    "prev": prev,
                    "seq": i,
                },
            )
            prev = entry_hash


async def _seed_anchor(chain_seq: int, row_hash: str) -> None:
    import base64
    import hashlib

    digest_hex = hashlib.sha256(row_hash.encode("ascii")).hexdigest()
    token = b"MK|" + digest_hex.encode("ascii") + b"|test"
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_chain_anchors "
                "(anchored_at, org_id, chain_seq, row_hash, tsa_url, "
                " tsa_token) "
                "VALUES ('2026-06-10T02:00:00Z', 'acme', :seq, :rh, "
                " 'mock://tsa', :token)"
            ),
            {"seq": chain_seq, "rh": row_hash, "token": token},
        )
    _ = base64  # imported for symmetry with the verifier fixtures


def _lines(resp) -> list[dict]:
    return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]


# ── auth ────────────────────────────────────────────────────────────


def test_export_requires_admin_secret(client):
    assert client.get("/v1/admin/audit/export").status_code == 422
    resp = client.get(
        "/v1/admin/audit/export", headers={"X-Admin-Secret": "wrong"},
    )
    assert resp.status_code == 403


# ── shape + filters ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_shape_and_chain_tagging(client):
    await _seed_audit_log(3)
    await _seed_local_audit(2)
    resp = client.get(
        "/v1/admin/audit/export", params={"chain": "both"}, headers=_auth(),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    rows = _lines(resp)
    audit = [r for r in rows if r["chain"] == "audit_log" and r["kind"] == "entry"]
    local = [r for r in rows if r["chain"] == "local_audit"]
    assert len(audit) == 3 and len(local) == 2
    assert [r["chain_seq"] for r in audit] == [1, 2, 3]
    # The v2 binding fields must survive the export verbatim.
    assert audit[0]["dpop_jkt"] == "jkt-test"
    assert audit[0]["row_hash"] and audit[0]["prev_hash"] == "genesis"
    assert local[0]["entry_hash"] and local[0]["event_type"] == "oneshot"


@pytest.mark.asyncio
async def test_export_chain_filter(client):
    await _seed_audit_log(2)
    await _seed_local_audit(2)
    only_audit = _lines(client.get(
        "/v1/admin/audit/export", params={"chain": "audit_log"},
        headers=_auth(),
    ))
    assert {r["chain"] for r in only_audit} == {"audit_log"}
    only_local = _lines(client.get(
        "/v1/admin/audit/export", params={"chain": "local_audit"},
        headers=_auth(),
    ))
    assert {r["chain"] for r in only_local} == {"local_audit"}


@pytest.mark.asyncio
async def test_export_org_filter_on_local_audit(client):
    await _seed_local_audit(2, org="acme")
    rows = _lines(client.get(
        "/v1/admin/audit/export",
        params={"chain": "local_audit", "org_id": "acme"},
        headers=_auth(),
    ))
    assert len(rows) == 2
    none_rows = _lines(client.get(
        "/v1/admin/audit/export",
        params={"chain": "local_audit", "org_id": "other"},
        headers=_auth(),
    ))
    assert none_rows == []


def test_export_org_with_audit_log_is_400(client):
    resp = client.get(
        "/v1/admin/audit/export",
        params={"chain": "audit_log", "org_id": "acme"},
        headers=_auth(),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_seq_window(client):
    await _seed_audit_log(10)
    rows = _lines(client.get(
        "/v1/admin/audit/export",
        params={"chain": "audit_log", "since_seq": 4, "until_seq": 7},
        headers=_auth(),
    ))
    entries = [r for r in rows if r["kind"] == "entry"]
    assert [r["chain_seq"] for r in entries] == [4, 5, 6, 7]


def test_export_inverted_window_is_400(client):
    resp = client.get(
        "/v1/admin/audit/export",
        params={"since_seq": 9, "until_seq": 2},
        headers=_auth(),
    )
    assert resp.status_code == 400


# ── streaming completeness over multiple keyset batches ─────────────


@pytest.mark.asyncio
async def test_export_multi_batch_complete(client):
    """2500 rows > 2× batch size (1000): every row must arrive, in
    chain_seq order, exactly once."""
    await _seed_audit_log(2500)
    rows = _lines(client.get(
        "/v1/admin/audit/export", params={"chain": "audit_log"},
        headers=_auth(),
    ))
    entries = [r for r in rows if r["kind"] == "entry"]
    assert len(entries) == 2500
    assert [r["chain_seq"] for r in entries] == list(range(1, 2501))


# ── anchors ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_includes_anchors_tagged_audit_log(client):
    hashes = await _seed_audit_log(3)
    await _seed_anchor(3, hashes[-1])
    rows = _lines(client.get(
        "/v1/admin/audit/export", headers=_auth(),
    ))
    anchors = [r for r in rows if r["kind"] == "anchor"]
    assert len(anchors) == 1
    assert anchors[0]["chain"] == "audit_log"
    assert anchors[0]["chain_seq"] == 3
    assert anchors[0]["tsa_token_b64"]


@pytest.mark.asyncio
async def test_export_exclude_anchors(client):
    hashes = await _seed_audit_log(2)
    await _seed_anchor(2, hashes[-1])
    rows = _lines(client.get(
        "/v1/admin/audit/export", params={"include_anchors": "false"},
        headers=_auth(),
    ))
    assert [r for r in rows if r["kind"] == "anchor"] == []


# ── the round trip: export → offline verifier ───────────────────────


@pytest.mark.asyncio
async def test_roundtrip_export_verifies_offline(
    client, tmp_path, monkeypatch, capsys,
):
    """The claim this PR makes true: seed both chains + an anchor,
    export over HTTP, hand the body to the stdlib-only verifier, get
    a green dispute-traceable verdict with zero Mastio access."""
    hashes = await _seed_audit_log(8)
    await _seed_local_audit(3)
    await _seed_anchor(8, hashes[-1])

    resp = client.get(
        "/v1/admin/audit/export", params={"chain": "both"}, headers=_auth(),
    )
    bundle = tmp_path / "export.ndjson"
    bundle.write_text(resp.text)

    monkeypatch.setattr(
        sys, "argv", ["cullis-audit-verify", "--bundle", str(bundle)],
    )
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert "CHAIN VERIFIED" in out
    assert "8 audit_log (global)" in out
    assert "3 per-org" in out
    assert "1 TSA anchor" in out


@pytest.mark.asyncio
async def test_roundtrip_tampered_export_exits_2(
    client, tmp_path, monkeypatch,
):
    await _seed_audit_log(5)
    resp = client.get(
        "/v1/admin/audit/export", params={"chain": "audit_log"},
        headers=_auth(),
    )
    lines = resp.text.splitlines()
    row = json.loads(lines[2])
    row["detail"] = "history, rewritten"
    lines[2] = json.dumps(row)
    bundle = tmp_path / "tampered.ndjson"
    bundle.write_text("\n".join(lines) + "\n")

    monkeypatch.setattr(
        sys, "argv", ["cullis-audit-verify", "--bundle", str(bundle)],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 2
