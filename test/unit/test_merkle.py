"""Unit tests for ``mcp_proxy.audit.merkle`` — the pure tree math
that powers batch audit anchoring (ADR-037).

These are pure-function tests: no DB, no network, no fixtures beyond
``pytest`` and ``hashlib``. The math is the only invariant under
test; integration with the audit_log schema lands in the follow-up
PR alongside the lifespan worker.
"""
from __future__ import annotations

import hashlib

import pytest

from mcp_proxy.audit.merkle import (
    build_merkle_tree,
    compute_merkle_root,
    inclusion_proof,
    verify_inclusion,
)


def _h(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def _leaves(n: int) -> list[bytes]:
    return [_h(f"audit-row-{i}".encode("ascii")) for i in range(n)]


# ── Root computation ────────────────────────────────────────────────


def test_single_leaf_is_the_root():
    """RFC 6962 canonical: a one-leaf tree's root is the leaf itself."""
    leaf = _h(b"only-row")
    assert compute_merkle_root([leaf]) == leaf


def test_two_leaves_root_is_concat_hash():
    """sha256(L || R) for the simplest non-trivial tree."""
    left, right = _h(b"a"), _h(b"b")
    expected = hashlib.sha256(left + right).digest()
    assert compute_merkle_root([left, right]) == expected


def test_three_leaves_odd_duplicates_last():
    """Odd-length levels duplicate the trailing node bottom-up,
    matching the Bitcoin / RFC 6962 odd-handling convention."""
    a, b, c = _h(b"a"), _h(b"b"), _h(b"c")
    expected_left = hashlib.sha256(a + b).digest()
    expected_right = hashlib.sha256(c + c).digest()
    expected_root = hashlib.sha256(expected_left + expected_right).digest()
    assert compute_merkle_root([a, b, c]) == expected_root


def test_root_is_deterministic_across_calls():
    """Stable input → stable root. Order matters; same set in a
    different order is a different root by design."""
    leaves = _leaves(8)
    assert compute_merkle_root(leaves) == compute_merkle_root(leaves)


def test_root_changes_when_any_leaf_changes():
    """Tamper with one leaf → root diverges (the whole point of the
    construction). Verifies the per-row binding integrity."""
    leaves = _leaves(8)
    original_root = compute_merkle_root(leaves)
    tampered = list(leaves)
    tampered[3] = _h(b"forged")
    assert compute_merkle_root(tampered) != original_root


def test_root_changes_when_leaf_order_changes():
    """Order is part of the binding. Swapping two leaves changes the
    root, which is what we want for audit log semantics where row N
    came strictly before row N+1."""
    leaves = _leaves(4)
    swapped = [leaves[0], leaves[2], leaves[1], leaves[3]]
    assert compute_merkle_root(leaves) != compute_merkle_root(swapped)


# ── Build tree shape ────────────────────────────────────────────────


def test_build_tree_levels_for_power_of_two():
    leaves = _leaves(8)
    tree = build_merkle_tree(leaves)
    assert [len(level) for level in tree] == [8, 4, 2, 1]
    assert tree[-1][0] == compute_merkle_root(leaves)


def test_build_tree_levels_for_odd_count():
    """7 leaves → 8 after dup → 4 → 2 → 1. Each odd level extends."""
    leaves = _leaves(7)
    tree = build_merkle_tree(leaves)
    assert [len(level) for level in tree] == [8, 4, 2, 1]


def test_build_tree_single_leaf_no_levels_above():
    leaves = _leaves(1)
    tree = build_merkle_tree(leaves)
    assert len(tree) == 1
    assert tree[0] == leaves


# ── Inclusion proofs ────────────────────────────────────────────────


@pytest.mark.parametrize("size", [1, 2, 3, 4, 7, 8, 16, 17, 100])
@pytest.mark.parametrize("index", [0, -1])
def test_inclusion_proof_verifies_for_every_leaf(size: int, index: int):
    """Every leaf in a tree of size N must produce a valid proof
    that verifies against the root. ``index=-1`` exercises the
    trailing-leaf path that hits the odd-duplication branch."""
    leaves = _leaves(size)
    real_index = index if index >= 0 else size + index
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, real_index)
    assert verify_inclusion(leaves[real_index], proof, root)


def test_inclusion_proof_for_single_leaf_is_empty():
    leaves = _leaves(1)
    root = compute_merkle_root(leaves)
    assert inclusion_proof(leaves, 0) == []
    # And empty-proof verify still works.
    assert verify_inclusion(leaves[0], [], root)


def test_inclusion_proof_rejects_forged_leaf():
    leaves = _leaves(8)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    forged = _h(b"not-the-real-row")
    assert not verify_inclusion(forged, proof, root)


def test_inclusion_proof_rejects_tampered_sibling():
    leaves = _leaves(8)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    bad_proof = list(proof)
    sibling, position = bad_proof[0]
    bad_proof[0] = (_h(b"tampered-sibling"), position)
    assert not verify_inclusion(leaves[3], bad_proof, root)


def test_inclusion_proof_rejects_swapped_position():
    """Flipping L↔R in the proof must fail. Encodes the directional
    binding that protects against a malicious aggregator swapping
    siblings."""
    leaves = _leaves(8)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    flipped = [(sib, "R" if pos == "L" else "L") for sib, pos in proof]
    assert not verify_inclusion(leaves[3], flipped, root)


def test_inclusion_proof_rejects_wrong_root():
    leaves = _leaves(8)
    proof = inclusion_proof(leaves, 3)
    other_root = _h(b"some-other-tree-root")
    assert not verify_inclusion(leaves[3], proof, other_root)


# ── Input validation ────────────────────────────────────────────────


def test_empty_leaves_raises():
    with pytest.raises(ValueError, match="at least one leaf"):
        compute_merkle_root([])


def test_non_bytes_leaf_raises():
    with pytest.raises(TypeError, match="must be bytes"):
        compute_merkle_root([_h(b"a"), "not-bytes"])  # type: ignore[list-item]


def test_short_leaf_raises():
    with pytest.raises(ValueError, match="32 bytes"):
        compute_merkle_root([b"short"])


def test_inclusion_proof_index_out_of_range_raises():
    leaves = _leaves(4)
    with pytest.raises(IndexError):
        inclusion_proof(leaves, 99)


def test_verify_rejects_malformed_leaf_silently():
    """The verifier returns False (does not raise) for malformed
    inputs — the offline auditor path must never crash on hostile
    bundle content, just refuse to verify."""
    leaves = _leaves(4)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    assert not verify_inclusion(b"short", proof, root)
    assert not verify_inclusion(leaves[0], proof, b"short-root")


def test_verify_rejects_malformed_sibling_silently():
    leaves = _leaves(4)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    bad_proof = list(proof)
    bad_proof[0] = (b"too-short", "R")
    assert not verify_inclusion(leaves[0], bad_proof, root)


def test_verify_rejects_unknown_position_marker():
    leaves = _leaves(4)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    bad_proof = [(sib, "X") for sib, _ in proof]
    assert not verify_inclusion(leaves[0], bad_proof, root)


# ── Large-N smoke ──────────────────────────────────────────────────


def test_large_tree_proof_remains_log_depth():
    """A 1024-leaf tree produces a 10-step proof (log2(1024) = 10).
    Confirms the O(log n) scaling property the design relies on."""
    leaves = _leaves(1024)
    root = compute_merkle_root(leaves)
    proof = inclusion_proof(leaves, 777)
    assert len(proof) == 10
    assert verify_inclusion(leaves[777], proof, root)
