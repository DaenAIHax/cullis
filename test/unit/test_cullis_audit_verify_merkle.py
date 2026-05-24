"""Unit tests for ``scripts/cullis-audit-verify.py --merkle-proof``
(ADR-037 Phase 3).

The CLI is a standalone script the offline auditor runs from a
shell. These tests import the script as a module (renamed from
``cullis-audit-verify.py`` to a Python-importable path via
``importlib``) and exercise the Merkle helpers + the
``verify_merkle_proofs`` driver. We do NOT spawn a subprocess for
every case — the helpers are pure functions and a SystemExit-based
failure path is captured with ``pytest.raises(SystemExit)``.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


# ── Load the dash-named script as a module ──────────────────────────


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "cullis-audit-verify.py"
)


def _load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "cullis_audit_verify_cli", str(_SCRIPT_PATH),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load_cli_module()


# ── Helpers ─────────────────────────────────────────────────────────


def _h(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def _build_proof(leaves: list[bytes], target_index: int) -> dict:
    """Compute a Merkle root + inclusion proof using the same math
    as the in-tree ``mcp_proxy.audit.merkle`` module (which the
    CLI inlines). Returns a dict shaped like the
    /v1/admin/audit/merkle/proof/{chain_seq} response."""
    # Mirror compute + build from the script's inlined math via the
    # _merkle_verify_inclusion → instead we use the in-tree module
    # to construct expected, and verify the CLI agrees.
    from mcp_proxy.audit.merkle import (
        compute_merkle_root, inclusion_proof,
    )
    root = compute_merkle_root(leaves)
    steps = inclusion_proof(leaves, target_index)
    return {
        "anchor_id": 42,
        "chain_seq": target_index + 1,  # caller adjusts
        "chain_seq_start": 1,
        "chain_seq_end": len(leaves),
        "leaf_count": len(leaves),
        "merkle_root": root.hex(),
        "leaf_hex": leaves[target_index].hex(),
        "proof": [
            {"sibling_hex": sib.hex(), "position": pos}
            for sib, pos in steps
        ],
    }


def _make_bundle(leaves: list[bytes]) -> list[tuple[str, list[dict]]]:
    """Build the ``bundles`` shape verify_merkle_proofs expects:
    one (path, entries) tuple, entries carrying chain_seq +
    row_hash matching the leaves."""
    entries = [
        {"chain_seq": i + 1, "row_hash": leaf.hex(), "kind": "entry"}
        for i, leaf in enumerate(leaves)
    ]
    return [("/dev/null", entries)]


# ── _merkle_verify_inclusion (the inlined math) ─────────────────────


def test_verify_inclusion_accepts_valid_proof():
    leaves = [_h(f"r{i}".encode()) for i in range(8)]
    proof = _build_proof(leaves, target_index=3)
    leaf = bytes.fromhex(proof["leaf_hex"])
    root = bytes.fromhex(proof["merkle_root"])
    steps = [
        (bytes.fromhex(s["sibling_hex"]), s["position"])
        for s in proof["proof"]
    ]
    assert cli._merkle_verify_inclusion(leaf, steps, root) is True


def test_verify_inclusion_rejects_forged_leaf():
    leaves = [_h(f"r{i}".encode()) for i in range(8)]
    proof = _build_proof(leaves, target_index=3)
    forged = _h(b"not-real")
    root = bytes.fromhex(proof["merkle_root"])
    steps = [
        (bytes.fromhex(s["sibling_hex"]), s["position"])
        for s in proof["proof"]
    ]
    assert cli._merkle_verify_inclusion(forged, steps, root) is False


def test_verify_inclusion_rejects_wrong_position_marker():
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    proof = _build_proof(leaves, target_index=0)
    leaf = bytes.fromhex(proof["leaf_hex"])
    root = bytes.fromhex(proof["merkle_root"])
    bad_steps = [
        (bytes.fromhex(s["sibling_hex"]), "X")  # invalid marker
        for s in proof["proof"]
    ]
    assert cli._merkle_verify_inclusion(leaf, bad_steps, root) is False


def test_verify_inclusion_rejects_malformed_inputs():
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    proof = _build_proof(leaves, target_index=0)
    leaf = bytes.fromhex(proof["leaf_hex"])
    root = bytes.fromhex(proof["merkle_root"])
    steps = [
        (bytes.fromhex(s["sibling_hex"]), s["position"])
        for s in proof["proof"]
    ]
    # Short leaf.
    assert cli._merkle_verify_inclusion(b"short", steps, root) is False
    # Short root.
    assert cli._merkle_verify_inclusion(leaf, steps, b"short") is False
    # Short sibling.
    bad_steps = [(b"short", "L")]
    assert cli._merkle_verify_inclusion(leaf, bad_steps, root) is False


# ── verify_merkle_proofs driver ─────────────────────────────────────


def test_verify_merkle_proofs_empty_returns_zero():
    assert cli.verify_merkle_proofs([], []) == 0


def test_verify_merkle_proofs_valid_path_returns_count(tmp_path):
    leaves = [_h(f"r{i}".encode()) for i in range(8)]
    bundles = _make_bundle(leaves)
    proof = _build_proof(leaves, target_index=4)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    assert cli.verify_merkle_proofs([str(proof_path)], bundles) == 1


def test_verify_merkle_proofs_multiple_files(tmp_path):
    leaves = [_h(f"r{i}".encode()) for i in range(8)]
    bundles = _make_bundle(leaves)
    paths = []
    for i in [0, 3, 7]:
        proof = _build_proof(leaves, target_index=i)
        p = tmp_path / f"proof_{i}.json"
        p.write_text(json.dumps(proof))
        paths.append(str(p))
    assert cli.verify_merkle_proofs(paths, bundles) == 3


def test_verify_merkle_proofs_unmatched_chain_seq_exits_6(tmp_path):
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    bundles = _make_bundle(leaves)  # chain_seq 1..4
    proof = _build_proof(leaves, target_index=0)
    proof["chain_seq"] = 999  # not in bundle
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs([str(proof_path)], bundles)
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_leaf_disagreement_exits_6(tmp_path):
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    bundles = _make_bundle(leaves)
    proof = _build_proof(leaves, target_index=1)
    # Tamper: forge the leaf_hex (no longer matches bundle row_hash).
    proof["leaf_hex"] = _h(b"tampered").hex()
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs([str(proof_path)], bundles)
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_wrong_root_exits_6(tmp_path):
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    bundles = _make_bundle(leaves)
    proof = _build_proof(leaves, target_index=1)
    # Tamper: replace root with something unrelated.
    proof["merkle_root"] = _h(b"other-tree").hex()
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs([str(proof_path)], bundles)
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_unreadable_file_exits_6():
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs(
            ["/nonexistent/path/proof.json"], [],
        )
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_malformed_json_exits_6(tmp_path):
    proof_path = tmp_path / "bad.json"
    proof_path.write_text("{not valid json")
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs([str(proof_path)], [])
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_missing_required_field_exits_6(tmp_path):
    proof_path = tmp_path / "incomplete.json"
    proof_path.write_text(json.dumps({"chain_seq": 1}))  # no leaf_hex/root/proof
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_merkle_proofs([str(proof_path)], [])
    assert exc_info.value.code == 6


def test_verify_merkle_proofs_accepts_legacy_entry_hash_field(tmp_path):
    """Legacy Court bundles carry ``entry_hash`` instead of
    ``row_hash``. The Merkle path must accept either as long as the
    bytes agree with the proof's leaf_hex."""
    leaves = [_h(f"r{i}".encode()) for i in range(4)]
    legacy_entries = [
        {"chain_seq": i + 1, "entry_hash": leaf.hex()}
        for i, leaf in enumerate(leaves)
    ]
    bundles = [("/dev/null", legacy_entries)]
    proof = _build_proof(leaves, target_index=2)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    assert cli.verify_merkle_proofs([str(proof_path)], bundles) == 1
