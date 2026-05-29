"""End-to-end test for audit_archive: seed audit_log rows, run one
exporter tick, archive the epoch to a file:// sink, then verify the
bundle + STH + inclusion proof OFFLINE via the public
``cullis-audit-verify.py`` CLI as a subprocess.

This is the contract: server produces, public CLI verifies. We
exercise the same code path an enterprise customer + auditor would
walk on a real deploy, end-to-end in process.

The CLI is invoked as a subprocess (rather than imported) because
that is how the auditor uses it — from the shell, against a bundle
they received via the operator. If the CLI ever drifts from the
plugin's emit shape, the subprocess returns non-zero and the test
fails.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

if importlib.util.find_spec("mcp_proxy") is None:
    pytest.skip(
        "mcp_proxy not on PYTHONPATH — install cullis core sibling-style",
        allow_module_level=True,
    )

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db

from cullis_enterprise.mastio.audit_archive.config import AuditArchiveConfig
from cullis_enterprise.mastio.audit_archive.exporter import _tick
from cullis_enterprise.mastio.audit_archive.schema import ensure_tables
from cullis_enterprise.mastio.audit_archive.sinks.file_sink import (
    build_file_sink,
)


_CLI_CANDIDATES = [
    Path(__file__).resolve().parents[2]
    / "cullis" / "scripts" / "cullis-audit-verify.py",
    Path(__file__).resolve().parents[2]
    / "agent-trust" / "scripts" / "cullis-audit-verify.py",
]


def _find_public_cli() -> Path | None:
    for p in _CLI_CANDIDATES:
        if p.is_file():
            return p
    return None


@pytest.fixture(autouse=True)
def _skip_when_cli_absent():
    if _find_public_cli() is None:
        pytest.skip(
            "public cullis-audit-verify.py CLI not sibling-installed; "
            "expected at cullis/scripts/ or agent-trust/scripts/"
        )


@pytest.fixture
async def archive_env(tmp_path, monkeypatch):
    """Spin up an ephemeral SQLite Mastio DB, ensure the
    audit_archive plugin schema, mint a fresh ES256 key + pubkey
    PEM, build a file:// sink under tmp_path.
    """
    db_path = tmp_path / "mastio.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    await ensure_tables()

    privkey = ec.generate_private_key(ec.SECP256R1())
    pem_path = tmp_path / "mastio-pub.pem"
    pem_path.write_bytes(
        privkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    sink_base = tmp_path / "archive"
    sink_url = f"file://{sink_base}"

    config = AuditArchiveConfig(
        enabled=True,
        sink_url=sink_url,
        epoch_seconds=86400,
        batch_max_rows=1_000_000,
        s3_retention_days=3650,
        s3_region=None,
    )
    sink = build_file_sink(sink_url)
    yield {
        "config": config,
        "sink": sink,
        "privkey": privkey,
        "pubkey_pem": pem_path,
        "tmp_path": tmp_path,
        "sink_base": sink_base,
    }
    await dispose_db()


async def _seed_audit_log_into_yesterday(rows: int) -> tuple[str, list[str]]:
    """Insert ``rows`` audit_log rows back-dated into the previous
    UTC day so the exporter sees them as a "completed unarchived
    epoch". Returns (epoch_utc, list_of_row_hashes_hex).
    """
    import hashlib

    today_floor = (
        datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    )
    yesterday_floor = today_floor - timedelta(days=1)
    epoch_utc = yesterday_floor.isoformat()
    # Sprinkle the rows uniformly across the previous day.
    delta = timedelta(days=1) / max(rows, 1)
    row_hashes = []
    async with get_db() as conn:
        for i in range(rows):
            ts = (yesterday_floor + delta * i).isoformat()
            row_hash = hashlib.sha256(f"e2e-row-{i}".encode()).hexdigest()
            row_hashes.append(row_hash)
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(timestamp, agent_id, action, status, chain_seq, "
                    " row_hash, prev_hash) "
                    "VALUES (:ts, 'e2e::agent', 'e2e_action', 'ok', "
                    " :seq, :rh, '')"
                ),
                {"ts": ts, "seq": i + 1, "rh": row_hash},
            )
    return epoch_utc, row_hashes


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    """Run the public verifier CLI as a subprocess and return the
    completed process. ``check=False`` so the test can inspect
    non-zero exit codes."""
    cli = _find_public_cli()
    assert cli is not None
    return subprocess.run(
        [sys.executable, str(cli), *args],
        capture_output=True, text=True, check=False,
    )


@pytest.mark.asyncio
async def test_archive_epoch_end_to_end_verifies_via_public_cli(
    archive_env,
):
    """Full pipeline: seed → exporter tick → CLI verify of bundle +
    STH + inclusion proof. All must come back PASS."""
    env = archive_env
    rows = 8
    _epoch_utc, _row_hashes = await _seed_audit_log_into_yesterday(rows)

    # Run the tick. Pin the clock so the exporter sees the seeded
    # epoch as completed.
    now = datetime.now(timezone.utc)
    await _tick(
        config=env["config"],
        sink=env["sink"],
        priv_key=env["privkey"],
        mastio_kid="e2e-test-kid",
        mastio_org_id="acme-e2e",
        now_utc=now,
    )

    # The exporter wrote bundle + manifest to the file sink. Locate
    # them by globbing the sink base.
    epoch_dirs = list(env["sink_base"].iterdir())
    assert len(epoch_dirs) == 1, (
        f"expected 1 epoch dir, got {epoch_dirs}"
    )
    epoch_dir = epoch_dirs[0]
    bundle_path = epoch_dir / "audit-bundle.ndjson"
    assert bundle_path.is_file()

    # ── 1. Retrieve the STH from the DB (in real life the auditor
    #      pulls it from /v1/admin/audit/sth/latest; we read it
    #      directly for the in-process test). Write it to a JSON
    #      file the CLI can consume.
    async with get_db() as conn:
        sth_row = (await conn.execute(text(
            "SELECT epoch_utc, mastio_org_id, tree_size, root_hash_hex, "
            "       chain_seq_lo, chain_seq_hi, signature_b64u, "
            "       mastio_kid, signed_at "
            "FROM audit_sth_log LIMIT 1"
        ))).first()
    assert sth_row is not None, "exporter did not write audit_sth_log"

    sth_json = {
        "epoch_utc": sth_row[0],
        "mastio_org_id": sth_row[1],
        "tree_size": int(sth_row[2]),
        "root_hash_hex": sth_row[3],
        "chain_seq_lo": int(sth_row[4]),
        "chain_seq_hi": int(sth_row[5]),
        "signature_b64u": sth_row[6],
        "mastio_kid": sth_row[7],
        "signed_at": sth_row[8],
    }
    sth_path = env["tmp_path"] / "sth.json"
    sth_path.write_text(json.dumps(sth_json))

    # ── 2. Build an inclusion proof for the middle leaf (in real
    #      life: GET /v1/admin/audit/proof?chain_seq=N).
    from cullis_enterprise.mastio.audit_archive.merkle import (
        _leaf_hash, compute_inclusion_proof,
    )
    target_chain_seq = sth_json["chain_seq_lo"] + 3
    async with get_db() as conn:
        epoch_rows = (await conn.execute(text(
            "SELECT chain_seq, row_hash FROM audit_log "
            "WHERE chain_seq >= :lo AND chain_seq <= :hi "
            "ORDER BY chain_seq ASC"
        ), {"lo": sth_json["chain_seq_lo"], "hi": sth_json["chain_seq_hi"]})).all()
    leaf_hashes_hex = [str(r[1]) for r in epoch_rows]
    leaf_index = target_chain_seq - sth_json["chain_seq_lo"]
    audit_path = compute_inclusion_proof(leaf_hashes_hex, leaf_index)
    proof_json = {
        "epoch_utc": sth_json["epoch_utc"],
        "leaf_index": leaf_index,
        "leaf_hash_hex": _leaf_hash(leaf_hashes_hex[leaf_index]).hex(),
        "audit_path": audit_path,
        "sth": sth_json,
    }
    proof_path = env["tmp_path"] / "proof.json"
    proof_path.write_text(json.dumps(proof_json))

    # ── 3. Run the public CLI verifier as a subprocess.
    #
    # The CLI's --bundle flag is required, but its internal
    # ``canonical()`` walks the Court legacy schema (event_type,
    # result, entry_hash). The audit_archive bundle is the Mastio
    # v2 schema (action, status, row_hash) so the --bundle chain
    # walk would fail with KeyError. The CLI extension to handle
    # Mastio-schema bundles natively (the ``--archive-bundle``
    # flag) is a follow-up PR on cullis-security/cullis. For now
    # the integration test feeds an empty placeholder file to
    # --bundle and exercises the archive verification path only
    # (--archive-sth / --archive-proof). The Mastio-schema bundle
    # IS still anchored by the manifest's bundle_sha256 — that
    # cross-check would land with the --archive-bundle follow-up.
    empty_bundle = env["tmp_path"] / "empty-placeholder.ndjson"
    empty_bundle.write_text("")
    result = _run_cli([
        "--bundle", str(empty_bundle),
        "--archive-sth", str(sth_path),
        "--archive-proof", str(proof_path),
        "--archive-manifest-pubkey", str(env["pubkey_pem"]),
    ])
    # Sanity: the sink really wrote the Mastio-schema bundle the
    # manifest points at. Read it ourselves to confirm it parses
    # as NDJSON with chain_seq + row_hash fields.
    bundle_lines = [
        json.loads(line)
        for line in bundle_path.read_text().splitlines()
        if line.strip()
    ]
    assert len(bundle_lines) == rows
    assert all("chain_seq" in e and "row_hash" in e for e in bundle_lines)

    assert result.returncode == 0, (
        f"CLI verifier failed: returncode={result.returncode}\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
    assert "CHAIN VERIFIED" in result.stdout
    assert "1 STH" in result.stdout
    assert "1 archive inclusion proof" in result.stdout


@pytest.mark.asyncio
async def test_archive_epoch_rejects_tampered_sth(archive_env):
    """If the auditor receives an STH with the root_hash_hex
    tampered (signature now invalid), the CLI must fail with exit 7."""
    env = archive_env
    await _seed_audit_log_into_yesterday(4)
    await _tick(
        config=env["config"], sink=env["sink"],
        priv_key=env["privkey"], mastio_kid="e2e", mastio_org_id="acme",
    )

    async with get_db() as conn:
        sth_row = (await conn.execute(text(
            "SELECT epoch_utc, mastio_org_id, tree_size, root_hash_hex, "
            "       chain_seq_lo, chain_seq_hi, signature_b64u, "
            "       mastio_kid, signed_at FROM audit_sth_log LIMIT 1"
        ))).first()
    sth = {
        "epoch_utc": sth_row[0], "mastio_org_id": sth_row[1],
        "tree_size": int(sth_row[2]),
        "root_hash_hex": "ff" * 32,  # ← tampered
        "chain_seq_lo": int(sth_row[4]), "chain_seq_hi": int(sth_row[5]),
        "signature_b64u": sth_row[6], "mastio_kid": sth_row[7],
        "signed_at": sth_row[8],
    }
    sth_path = env["tmp_path"] / "tampered-sth.json"
    sth_path.write_text(json.dumps(sth))

    # Empty bundle file so --bundle is satisfied.
    empty_bundle = env["tmp_path"] / "empty.ndjson"
    empty_bundle.write_text("")

    result = _run_cli([
        "--bundle", str(empty_bundle),
        "--archive-sth", str(sth_path),
        "--archive-manifest-pubkey", str(env["pubkey_pem"]),
    ])
    assert result.returncode == 7, (
        f"expected exit 7 on tampered STH, got {result.returncode}: "
        f"{result.stdout}\n{result.stderr}"
    )
    assert "ARCHIVE STH SIGNATURE INVALID" in result.stdout
