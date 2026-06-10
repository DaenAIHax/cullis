"""Unit tests for the audit_log support in ``cullis-audit-verify.py``.

Before this fix the verifier's ``canonical()`` was hard-coded to the
``local_audit`` schema, so the PRIMARY ``audit_log`` chain (the one
carrying every egress LLM/tool event, with the v2 dpop_jkt +
on_behalf_of_user_id binding, and the one the RFC 3161 / Merkle anchor
watchers actually run over) was not recomputable offline — only the
Merkle inclusion of opaque hashes could be checked. The "external
auditor can verify offline" claim only covered local_audit.

These tests pin:

  - canonical parity verifier ↔ producer (``compute_audit_row_hash``),
    randomized, v1 and v2 — the anti-drift net for the duplicated
    canonical (the CLI must stay stdlib-only, so it cannot import the
    producer at runtime);
  - the audit_log chain walk: genesis, v1→v2 transition, tamper
    detection on content / dpop binding / gaps / duplicates, NULL-seq
    pre-migration skips, partial (since_seq) forward-verification;
  - schema auto-detect (explicit ``chain`` key wins; heuristic on
    action+status vs event_type+result; exit 9 on ambiguity and on
    ``--chain`` contradictions);
  - mixed both-chains bundles, including anchors routed to the
    audit_log chain.

The CLI is loaded as a module via importlib (its filename is
dash-named and not importable directly), mirroring the existing
verifier tests.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import random
import string
import sys
from pathlib import Path

import pytest

from mcp_proxy.db import compute_audit_row_hash

# ── Load the dash-named script as a module ──────────────────────────

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "cullis-audit-verify.py"
)


def _load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "cullis_audit_verify_cli_audit_log", str(_SCRIPT_PATH),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load_cli_module()


# ── Helpers ─────────────────────────────────────────────────────────


def _audit_row(
    seq: int,
    prev_hash: str,
    *,
    hash_format: str | None = "v2",
    **overrides,
) -> dict:
    row = {
        "id": seq,
        "timestamp": f"2026-06-10T00:00:{seq:02d}+00:00",
        "agent_id": "acme::trader-1",
        "action": "egress_llm_chat",
        "tool_name": None,
        "status": "success",
        "detail": f"completion {seq}",
        "request_id": f"req-{seq}",
        "duration_ms": "12.5",
        "chain_seq": seq,
        "prev_hash": prev_hash,
        "hash_format": hash_format,
        "dpop_jkt": "jkt-" + "a" * 39,
        "on_behalf_of_user_id": None,
    }
    row.update(overrides)
    row["row_hash"] = compute_audit_row_hash(
        chain_seq=row["chain_seq"],
        timestamp=row["timestamp"],
        agent_id=row["agent_id"],
        action=row["action"],
        tool_name=row["tool_name"],
        status=row["status"],
        detail=row["detail"],
        request_id=row["request_id"],
        prev_hash=row["prev_hash"],
        dpop_jkt=row["dpop_jkt"],
        on_behalf_of_user_id=row["on_behalf_of_user_id"],
        hash_format=row["hash_format"],
    )
    return row


def _audit_chain(n: int, *, start_format: str | None = "v2") -> list[dict]:
    rows = []
    prev = "genesis"
    for i in range(1, n + 1):
        row = _audit_row(i, prev, hash_format=start_format)
        rows.append(row)
        prev = row["row_hash"]
    return rows


def _local_row(seq: int, prev: str | None) -> dict:
    entry = {
        "id": 1000 + seq,
        "timestamp": "2026-06-10T01:00:00Z",
        "event_type": "oneshot",
        "agent_id": "acme::alice",
        "org_id": "acme",
        "session_id": None,
        "result": "success",
        "details": "",
        "previous_hash": prev,
        "chain_seq": seq,
        "hash_format": "v2",
    }
    entry["entry_hash"] = hashlib.sha256(
        cli.canonical(entry, prev).encode("utf-8")
    ).hexdigest()
    return entry


def _write_bundle(tmp_path, rows: list[dict], name="bundle.ndjson") -> str:
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(path)


def _run_main(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["cullis-audit-verify", *argv])
    return cli.main()


# ── Canonical parity verifier ↔ producer (anti-drift) ───────────────


def _rand(n: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


@pytest.mark.parametrize("hash_format", ["v2", "v1", None])
def test_canonical_parity_with_producer_randomized(hash_format):
    """The CLI's canonical_audit_log must reproduce the producer's hash
    for arbitrary field content, including None-vs-'' sentinels."""
    random.seed(f"parity-{hash_format}")
    for _ in range(50):
        fields = {
            "chain_seq": random.randint(1, 10_000),
            "timestamp": f"2026-06-10T{random.randint(0,23):02d}:00:00Z",
            "agent_id": _rand(12),
            "action": _rand(8),
            "tool_name": random.choice([None, _rand(6)]),
            "status": random.choice(["success", "denied", "error"]),
            "detail": random.choice([None, _rand(40)]),
            "request_id": random.choice([None, _rand(10)]),
            "dpop_jkt": random.choice([None, _rand(43)]),
            "on_behalf_of_user_id": random.choice([None, _rand(20)]),
        }
        prev = random.choice(["genesis", _rand(64)])
        produced = compute_audit_row_hash(
            prev_hash=prev, hash_format=hash_format, **fields,
        )
        entry = {**fields, "hash_format": hash_format}
        recomputed = hashlib.sha256(
            cli.canonical_audit_log(entry, prev).encode("utf-8")
        ).hexdigest()
        assert recomputed == produced


# ── audit_log chain walk ────────────────────────────────────────────


def test_valid_v2_chain_passes(tmp_path, monkeypatch, capsys):
    path = _write_bundle(tmp_path, _audit_chain(5))
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "CHAIN VERIFIED" in out
    assert "5 audit_log (global)" in out


def test_v1_to_v2_transition_passes(tmp_path, monkeypatch):
    """Chains migrated at 0042 carry v1 rows followed by v2 rows."""
    rows = []
    prev = "genesis"
    for i in range(1, 4):
        row = _audit_row(i, prev, hash_format=None)
        rows.append(row)
        prev = row["row_hash"]
    for i in range(4, 7):
        row = _audit_row(i, prev, hash_format="v2")
        rows.append(row)
        prev = row["row_hash"]
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0


def test_tampered_detail_exits_2(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(4)
    rows[2]["detail"] = "rewritten by operator"
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2
    assert "row_hash" in capsys.readouterr().out


def test_tampered_dpop_jkt_exits_2(tmp_path, monkeypatch):
    """The v2 binding is load-bearing: altering dpop_jkt must break the
    chain — this is exactly what v2 added over v1."""
    rows = _audit_chain(4)
    rows[1]["dpop_jkt"] = "jkt-" + "b" * 39
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2


def test_deleted_row_gap_exits_2(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(5)
    del rows[2]  # seq 3 vanishes → gap 2→4
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2
    assert "missing" in capsys.readouterr().out


def test_duplicate_chain_seq_exits_2(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(3)
    rows.append(dict(rows[-1], detail="forged twin"))
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2
    assert "DUPLICATE" in capsys.readouterr().out


def test_null_seq_premigration_rows_skipped(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(3)
    rows.insert(0, {
        "id": 0,
        "timestamp": "2026-01-01T00:00:00Z",
        "agent_id": "acme::old",
        "action": "legacy_event",
        "status": "success",
        "chain_seq": None,
        "prev_hash": None,
        "row_hash": None,
    })
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "pre-migration audit_log row" in out


def test_partial_export_forward_verifies_with_note(
    tmp_path, monkeypatch, capsys,
):
    """A since_seq window cannot reach the genesis: the verifier trusts
    the first row's prev_hash and says so explicitly."""
    rows = _audit_chain(6)[3:]  # seq 4..6
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "partial audit_log export" in out
    assert "from seq=4" in out


def test_partial_export_verdict_is_qualified(tmp_path, monkeypatch, capsys):
    """Crypto-review 2026-06-10: an unqualified 'intact end-to-end' on a
    windowed export would also bless a truncated history."""
    rows = _audit_chain(6)[3:]
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "intact FROM audit_log seq=4" in out
    assert "intact end-to-end" not in out


def test_require_genesis_refuses_partial_export(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(6)[3:]
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path, "--require-genesis")
    assert exc_info.value.code == 10
    assert "GENESIS REQUIREMENT NOT MET" in capsys.readouterr().out


def test_require_genesis_accepts_full_chain(tmp_path, monkeypatch):
    path = _write_bundle(tmp_path, _audit_chain(4))
    assert _run_main(
        monkeypatch, "--bundle", path, "--require-genesis",
    ) == 0


def test_non_numeric_chain_seq_exits_9(tmp_path, monkeypatch, capsys):
    """Hostile bundles must fail loudly (exit 9), not crash with a
    traceback (exit 1)."""
    rows = _audit_chain(2)
    rows.append(dict(rows[-1], chain_seq="not-a-number"))
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 9
    assert "non-numeric" in capsys.readouterr().out


def test_unknown_kind_lines_are_surfaced(tmp_path, monkeypatch, capsys):
    """load_bundle drops kinds it doesn't know — but never silently."""
    rows = _audit_chain(2)
    rows.append({"kind": "hologram", "chain_seq": 99})
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "unknown kind='hologram'" in out
    assert "NOT covered" in out


def test_partial_export_tamper_still_caught(tmp_path, monkeypatch):
    rows = _audit_chain(6)[3:]
    rows[1]["status"] = "denied"
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2


# ── schema detection / --chain override ─────────────────────────────


def test_detect_chain_explicit_key_wins():
    row = {"chain": "audit_log", "event_type": "x", "result": "ok"}
    assert cli.detect_chain(row) == "audit_log"


def test_detect_chain_heuristics():
    assert cli.detect_chain({"action": "a", "status": "s"}) == "audit_log"
    assert cli.detect_chain({"event_type": "e", "result": "r"}) == "local_audit"
    assert cli.detect_chain({"row_hash": "deadbeef"}) is None
    assert cli.detect_chain(
        {"action": "a", "status": "s", "event_type": "e", "result": "r"},
    ) is None


def test_unrecognized_row_exits_9(tmp_path, monkeypatch, capsys):
    path = _write_bundle(tmp_path, [{"id": 1, "row_hash": "ff" * 32}])
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 9
    assert "UNRECOGNIZED" in capsys.readouterr().out


def test_forced_chain_conflict_exits_9(tmp_path, monkeypatch, capsys):
    path = _write_bundle(tmp_path, _audit_chain(2))
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path, "--chain", "local_audit")
    assert exc_info.value.code == 9
    assert "CONFLICT" in capsys.readouterr().out


def test_forced_chain_matching_passes(tmp_path, monkeypatch):
    path = _write_bundle(tmp_path, _audit_chain(2))
    assert _run_main(monkeypatch, "--bundle", path, "--chain", "audit_log") == 0


# ── mixed bundles (chain=both export) ───────────────────────────────


def _mixed_rows() -> list[dict]:
    audit = _audit_chain(3)
    prev = None
    local = []
    for i in range(1, 3):
        row = _local_row(i, prev)
        local.append(row)
        prev = row["entry_hash"]
    return audit + local


def test_mixed_bundle_both_chains_verify(tmp_path, monkeypatch, capsys):
    path = _write_bundle(tmp_path, _mixed_rows())
    assert _run_main(monkeypatch, "--bundle", path) == 0
    out = capsys.readouterr().out
    assert "3 audit_log (global)" in out
    assert "2 per-org" in out


def test_mixed_bundle_tamper_in_audit_log_exits_2(tmp_path, monkeypatch):
    rows = _mixed_rows()
    rows[1]["detail"] = "tampered"  # audit_log row seq 2
    path = _write_bundle(tmp_path, rows)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 2


def test_mixed_bundle_seq_collision_is_harmless(tmp_path, monkeypatch):
    """audit_log seq 1..3 and local_audit seq 1..2 overlap numerically —
    the chains are independent and must verify independently."""
    rows = _mixed_rows()
    assert {r["chain_seq"] for r in rows[:3]} & {
        r["chain_seq"] for r in rows[3:]
    }, "fixture must actually overlap to exercise the collision"
    path = _write_bundle(tmp_path, rows)
    assert _run_main(monkeypatch, "--bundle", path) == 0


# ── anchors on the audit_log chain ──────────────────────────────────


def _mock_anchor_for(row: dict, *, chain: str | None = "audit_log") -> dict:
    digest_hex = hashlib.sha256(
        row["row_hash"].encode("ascii"),
    ).hexdigest()
    token = b"MK|" + digest_hex.encode("ascii") + b"|test"
    anchor = {
        "kind": "anchor",
        "org_id": "acme",
        "chain_seq": row["chain_seq"],
        "row_hash": row["row_hash"],
        "tsa_token_b64": base64.b64encode(token).decode("ascii"),
    }
    if chain is not None:
        anchor["chain"] = chain
    return anchor


def test_audit_log_anchor_verifies(tmp_path, monkeypatch, capsys):
    rows = _audit_chain(3)
    bundle = rows + [_mock_anchor_for(rows[-1])]
    path = _write_bundle(tmp_path, bundle)
    assert _run_main(monkeypatch, "--bundle", path) == 0
    assert "1 TSA anchor" in capsys.readouterr().out


def test_audit_log_anchor_untagged_matches_by_seq(tmp_path, monkeypatch):
    """Anchors without the explicit chain key (older export) still find
    the audit_log row when no local_audit row claims the seq."""
    rows = _audit_chain(3)
    bundle = rows + [_mock_anchor_for(rows[-1], chain=None)]
    path = _write_bundle(tmp_path, bundle)
    assert _run_main(monkeypatch, "--bundle", path) == 0


def test_audit_log_anchor_mismatch_exits_3(tmp_path, monkeypatch):
    rows = _audit_chain(3)
    anchor = _mock_anchor_for(rows[-1])
    anchor["row_hash"] = "0" * 64  # claims a head the chain never had
    path = _write_bundle(tmp_path, rows + [anchor])
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, "--bundle", path)
    assert exc_info.value.code == 3


def test_merkle_anchor_rows_are_ignored_by_load_bundle(tmp_path, monkeypatch):
    """kind="merkle_anchor" lines (new export) must not break older
    consumers of load_bundle — unknown kinds are skipped."""
    rows = _audit_chain(2)
    bundle = rows + [{
        "kind": "merkle_anchor",
        "chain": "audit_log",
        "chain_seq_start": 1,
        "chain_seq_end": 2,
        "merkle_root": "ab" * 32,
    }]
    path = _write_bundle(tmp_path, bundle)
    assert _run_main(monkeypatch, "--bundle", path) == 0
