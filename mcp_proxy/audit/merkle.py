"""Binary Merkle tree over SHA-256, used to batch-anchor audit_log
hash-chain segments.

Why this exists: the per-row hash chain (``audit_log.row_hash`` +
``prev_hash``, F-A-402 trigger) proves consistency in O(n) walks.
Verifying that row N belongs to a chain with M rows requires
recomputing every row's hash from genesis to N. At 1M rows that is
~1M SHA-256 ops per inclusion check. The TSA anchor lifespan worker
(``audit_anchor_watcher``) makes that walk tamper-evident against the
operator, but it still pays the linear cost.

A Merkle tree turns one O(n) walk into one O(log n) inclusion proof:
the leaves are the row hashes (already in audit_log), the root binds
the whole batch with a single 32-byte digest, and verifying that row
N is in the batch costs ~log2(batch_size) SHA-256 ops + comparing the
recomputed root against the stored anchor root. Combined with the TSA
anchor of the root (one TSA call per batch instead of one per row),
this is the scaling property that lets us run forensic verification
across years of audit history without DB walks.

Phase 0 scope (this module): the pure tree math. No DB schema, no
lifespan worker, no endpoints. Those land in follow-up PRs once the
math is reviewed in isolation. The math is small, self-contained,
zero-dep (stdlib ``hashlib`` only), and unit-testable end-to-end.

Conventions:

  * Leaves are 32-byte SHA-256 digests (``bytes``). Callers feed
    ``bytes.fromhex(audit_log.row_hash)`` directly. We do NOT re-hash
    the leaf — that would double-hash the canonical row form the
    chain already commits to and would make the inclusion proof
    awkward to verify against an existing ``row_hash`` column.
  * Odd-length levels duplicate the last node (Bitcoin's CVE-2012-2459
    fix is documented but does NOT apply here: this tree is built
    server-side from append-only DB rows the operator cannot inject,
    so the malleability vector is closed by the schema boundary).
  * Internal nodes are ``sha256(left || right)``, 32 bytes each.
  * The proof carries siblings bottom-up, paired with a position
    marker ('L' the sibling is on the left, 'R' on the right). The
    verifier walks the proof from leaf upward, hashing in the
    documented order, and asserts the resulting root equals the
    stored anchor root.

References:

  * RFC 6962 §2 (Certificate Transparency Merkle Tree) — same
    construction, different leaf domain. We do NOT prepend the RFC
    6962 leaf/node prefix bytes (0x00, 0x01); those exist to
    domain-separate from arbitrary CT inputs, and our leaves are
    already domain-separated by being SHA-256 outputs of the
    canonical audit row form.
"""
from __future__ import annotations

import hashlib
from typing import Sequence


_DIGEST_BYTES = 32


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _validate_leaves(leaves: Sequence[bytes]) -> None:
    if not leaves:
        raise ValueError("Merkle tree requires at least one leaf")
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)):
            raise TypeError(
                f"leaf {i} must be bytes (got {type(leaf).__name__})"
            )
        if len(leaf) != _DIGEST_BYTES:
            raise ValueError(
                f"leaf {i} must be exactly {_DIGEST_BYTES} bytes "
                f"(got {len(leaf)})"
            )


def compute_merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Return the Merkle root digest binding ``leaves``.

    Single-leaf trees return the leaf itself (canonical RFC 6962
    behaviour). Empty input raises ``ValueError`` — callers MUST
    decide whether an empty batch is a no-op (skip the anchor) or an
    error.
    """
    _validate_leaves(leaves)
    current: list[bytes] = list(leaves)
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])  # duplicate-last for odd levels
        current = [
            _sha256(current[i] + current[i + 1])
            for i in range(0, len(current), 2)
        ]
    return current[0]


def build_merkle_tree(leaves: Sequence[bytes]) -> list[list[bytes]]:
    """Return the full tree as a list of levels, bottom-up.

    ``tree[0]`` is the leaves (after odd-duplication if needed at
    that level), ``tree[-1]`` is the single-element root list. Used
    by ``inclusion_proof`` to walk siblings without re-hashing.
    """
    _validate_leaves(leaves)
    levels: list[list[bytes]] = [list(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]
            levels[-1] = level
        next_level = [
            _sha256(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]
        levels.append(next_level)
    return levels


def inclusion_proof(
    leaves: Sequence[bytes], index: int,
) -> list[tuple[bytes, str]]:
    """Return the bottom-up inclusion proof for ``leaves[index]``.

    Each step is ``(sibling_hash, position)`` where ``position`` is
    ``'L'`` if the sibling sits on the left of the current node (so
    the verifier hashes ``sibling || current``) and ``'R'`` if on the
    right (``current || sibling``).

    A tree with a single leaf returns an empty proof: the leaf IS the
    root, no sibling exists.
    """
    _validate_leaves(leaves)
    if not 0 <= index < len(leaves):
        raise IndexError(
            f"index {index} out of range for {len(leaves)} leaves"
        )
    tree = build_merkle_tree(leaves)
    proof: list[tuple[bytes, str]] = []
    cursor = index
    for level in tree[:-1]:
        sibling_idx = cursor ^ 1  # XOR 1 flips the last bit
        sibling = level[sibling_idx]
        position = "L" if sibling_idx < cursor else "R"
        proof.append((sibling, position))
        cursor //= 2
    return proof


def verify_inclusion(
    leaf: bytes,
    proof: Sequence[tuple[bytes, str]],
    expected_root: bytes,
) -> bool:
    """Reconstruct the root from ``leaf`` + ``proof`` and compare to
    ``expected_root``. Returns True iff the leaf is provably included
    in the tree rooted at ``expected_root``.

    This is the offline verifier path: an auditor with the row hash
    + the proof + the anchored root can independently confirm
    inclusion without DB access, without trusting the Mastio.
    """
    if len(leaf) != _DIGEST_BYTES:
        return False
    if len(expected_root) != _DIGEST_BYTES:
        return False
    current = bytes(leaf)
    for sibling, position in proof:
        if not isinstance(sibling, (bytes, bytearray)):
            return False
        if len(sibling) != _DIGEST_BYTES:
            return False
        if position == "L":
            current = _sha256(bytes(sibling) + current)
        elif position == "R":
            current = _sha256(current + bytes(sibling))
        else:
            return False
    return current == expected_root
