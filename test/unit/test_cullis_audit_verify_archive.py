"""Unit tests for ``scripts/cullis-audit-verify.py`` Enterprise
audit_archive verification flags: ``--archive-sth``,
``--archive-proof``, ``--archive-manifest``.

The CLI math (RFC 6962 prefix bytes, ES256 over canonical JSON) is
pure and inlined; we exercise it here by generating valid STH /
proof / manifest artefacts with a freshly-minted EC P-256 key and
asserting the verifier accepts them, then perturb each field and
assert it refuses with exit code 7.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)


# ── Load the dash-named CLI as a module ─────────────────────────────


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


# ── Crypto helpers (server-side equivalent) ─────────────────────────


@pytest.fixture
def mastio_key(tmp_path) -> tuple[ec.EllipticCurvePrivateKey, Path]:
    """Mint a fresh ES256 key, write the PEM, return both."""
    privkey = ec.generate_private_key(ec.SECP256R1())
    pubkey_pem = privkey.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "mastio.pub.pem"
    path.write_bytes(pubkey_pem)
    return privkey, path


def _sign_b64u(privkey: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    """Sign ``payload`` with ES256 and return JOSE flat b64url(r||s)."""
    der_sig = privkey.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _h(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# ── RFC 6962 tree builder (server-side equivalent) ──────────────────


def _build_rfc6962_tree(row_hashes_hex: list[str]) -> tuple[bytes, list[list[bytes]]]:
    """Build an RFC 6962 binary Merkle tree using the audit_archive
    plugin's "promote unpaired" construction (matches
    ``compute_merkle_root`` in the patch):

      * Leaves: sha256(0x00 || row_hash_raw)
      * Internal: sha256(0x01 || left || right)
      * Trailing unpaired node at each level is PROMOTED unchanged
        to the next level (NOT duplicate-last)

    Returns (root, levels_bottom_up).
    """
    leaves = [
        hashlib.sha256(b"\x00" + bytes.fromhex(rh)).digest()
        for rh in row_hashes_hex
    ]
    levels: list[list[bytes]] = [leaves]
    while len(levels[-1]) > 1:
        layer = levels[-1]
        next_layer: list[bytes] = []
        for i in range(0, len(layer) - 1, 2):
            next_layer.append(
                hashlib.sha256(b"\x01" + layer[i] + layer[i + 1]).digest()
            )
        if len(layer) % 2 == 1:
            next_layer.append(layer[-1])  # promote unpaired
        levels.append(next_layer)
    return levels[-1][0], levels


def _audit_path(levels: list[list[bytes]], index: int) -> list[str]:
    """Bottom-up audit path. Each level emits the sibling hex string,
    or "" when the cursor sits on a trailing unpaired (promoted) node
    and there is no sibling at that level. Matches what
    ``compute_inclusion_proof`` in the patch produces.
    """
    path: list[str] = []
    cursor = index
    for level in levels[:-1]:
        if cursor == len(level) - 1 and len(level) % 2 == 1:
            path.append("")  # promote-unpaired, no sibling
        else:
            sibling_idx = cursor ^ 1
            path.append(level[sibling_idx].hex())
        cursor //= 2
    return path


# ── Bundle + artefact builders ──────────────────────────────────────


def _make_bundle_entries(start_seq: int, count: int) -> list[dict]:
    """Generate audit bundle entries with predictable row_hashes."""
    return [
        {
            "kind": "entry",
            "chain_seq": start_seq + i,
            "row_hash": _h(f"r{start_seq + i}".encode()),
        }
        for i in range(count)
    ]


def _sth_dict(
    privkey: ec.EllipticCurvePrivateKey,
    *,
    epoch_utc: str = "2026-05-24T00:00:00Z",
    org_id: str = "acme",
    tree_size: int,
    root_hash_hex: str,
    chain_seq_lo: int,
    chain_seq_hi: int,
    kid: str = "mastio-test-kid",
    signed_at: str = "2026-05-24T00:00:01Z",
) -> dict:
    sth = {
        "mastio_org_id": org_id,
        "epoch_utc": epoch_utc,
        "tree_size": tree_size,
        "root_hash_hex": root_hash_hex,
        "chain_seq_lo": chain_seq_lo,
        "chain_seq_hi": chain_seq_hi,
        "mastio_kid": kid,
        "signed_at": signed_at,
    }
    payload = cli._sth_canonical_payload(sth)
    sth["signature_b64u"] = _sign_b64u(privkey, payload)
    return sth


def _manifest_dict(
    privkey: ec.EllipticCurvePrivateKey,
    *,
    epoch_utc: str = "2026-05-24T00:00:00Z",
    chain_seq_lo: int,
    chain_seq_hi: int,
    row_count: int,
    sink_url: str = "s3://test/audit-bundle.ndjson",
    bundle_sha256: str = "00" * 32,
) -> dict:
    manifest = {
        "epoch_utc": epoch_utc,
        "mastio_org_id": "acme",
        "chain_seq_lo": chain_seq_lo,
        "chain_seq_hi": chain_seq_hi,
        "row_count": row_count,
        "sink_url": sink_url,
        "bundle_sha256": bundle_sha256,
    }
    payload = cli._manifest_canonical_payload(manifest)
    manifest["signature_b64u"] = _sign_b64u(privkey, payload)
    return manifest


# ── RFC 6962 math ───────────────────────────────────────────────────


def test_leaf_hash_prefixes_with_zero_byte():
    row_hash = _h(b"row-1")
    leaf = cli._rfc6962_leaf_hash(row_hash)
    expected = hashlib.sha256(b"\x00" + bytes.fromhex(row_hash)).digest()
    assert leaf == expected


def test_node_hash_prefixes_with_one_byte():
    left = b"\x01" * 32
    right = b"\x02" * 32
    node = cli._rfc6962_node_hash(left, right)
    expected = hashlib.sha256(b"\x01" + left + right).digest()
    assert node == expected


@pytest.mark.parametrize("size", [1, 2, 3, 4, 7, 8, 16, 17, 32])
def test_verify_audit_path_accepts_every_leaf(size: int):
    row_hashes = [_h(f"r{i}".encode()) for i in range(size)]
    root, levels = _build_rfc6962_tree(row_hashes)
    for i, rh in enumerate(row_hashes):
        leaf_hash = cli._rfc6962_leaf_hash(rh)
        path = _audit_path(levels, i)
        assert cli._rfc6962_verify_audit_path(
            leaf_hash, path, i, size, root,
        ), f"size={size} leaf={i} failed"


def test_verify_audit_path_rejects_wrong_root():
    row_hashes = [_h(f"r{i}".encode()) for i in range(8)]
    _, levels = _build_rfc6962_tree(row_hashes)
    leaf_hash = cli._rfc6962_leaf_hash(row_hashes[3])
    path = _audit_path(levels, 3)
    wrong_root = b"\xff" * 32
    assert not cli._rfc6962_verify_audit_path(
        leaf_hash, path, 3, 8, wrong_root,
    )


def test_verify_audit_path_rejects_tampered_sibling():
    row_hashes = [_h(f"r{i}".encode()) for i in range(4)]
    root, levels = _build_rfc6962_tree(row_hashes)
    leaf_hash = cli._rfc6962_leaf_hash(row_hashes[1])
    path = _audit_path(levels, 1)
    path[0] = "ff" * 32  # tampered hex sibling
    assert not cli._rfc6962_verify_audit_path(
        leaf_hash, path, 1, 4, root,
    )


# ── ES256 signature verification ────────────────────────────────────


def test_verify_es256_accepts_valid_signature(mastio_key):
    privkey, pem_path = mastio_key
    payload = b"hello-world"
    sig = _sign_b64u(privkey, payload)
    assert cli._verify_es256_signature(payload, sig, pem_path.read_bytes())


def test_verify_es256_rejects_tampered_payload(mastio_key):
    privkey, pem_path = mastio_key
    sig = _sign_b64u(privkey, b"hello-world")
    assert not cli._verify_es256_signature(
        b"tampered", sig, pem_path.read_bytes(),
    )


def test_verify_es256_rejects_malformed_b64u(mastio_key):
    _, pem_path = mastio_key
    assert not cli._verify_es256_signature(
        b"hello", "not-base64!", pem_path.read_bytes(),
    )


def test_verify_es256_rejects_wrong_curve_pubkey(tmp_path):
    wrong = ec.generate_private_key(ec.SECP384R1())
    pem = wrong.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "wrong.pem"
    path.write_bytes(pem)
    # Build any P-384 signature; verifier must refuse on wrong curve.
    sig_der = wrong.sign(b"hello", ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    sig_b64u = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert not cli._verify_es256_signature(b"hello", sig_b64u, pem)


# ── verify_archive_proofs driver: STH only ──────────────────────────


def test_archive_sth_valid_returns_count(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(4)]
    root, _ = _build_rfc6962_tree(rh)
    sth = _sth_dict(
        privkey, tree_size=4, root_hash_hex=root.hex(),
        chain_seq_lo=1, chain_seq_hi=4,
    )
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth))
    s, m, p = cli.verify_archive_proofs(
        [str(sth_path)], [], [], str(pem_path), [],
    )
    assert (s, m, p) == (1, 0, 0)


def test_archive_sth_invalid_signature_exits_7(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(4)]
    root, _ = _build_rfc6962_tree(rh)
    sth = _sth_dict(
        privkey, tree_size=4, root_hash_hex=root.hex(),
        chain_seq_lo=1, chain_seq_hi=4,
    )
    sth["root_hash_hex"] = "ff" * 32  # tamper after signing
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(json.dumps(sth))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [str(sth_path)], [], [], str(pem_path), [],
        )
    assert exc_info.value.code == 7


# ── Manifest verification ───────────────────────────────────────────


def test_archive_manifest_valid_returns_count(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    manifest = _manifest_dict(
        privkey, chain_seq_lo=1, chain_seq_hi=100, row_count=100,
        bundle_sha256=_h(b"fake-bundle"),
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    s, m, p = cli.verify_archive_proofs(
        [], [], [str(path)], str(pem_path), [],
    )
    assert (s, m, p) == (0, 1, 0)


def test_archive_manifest_tampered_sink_url_exits_7(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    manifest = _manifest_dict(
        privkey, chain_seq_lo=1, chain_seq_hi=100, row_count=100,
    )
    manifest["sink_url"] = "s3://attacker/forged.ndjson"  # tamper
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [], [], [str(path)], str(pem_path), [],
        )
    assert exc_info.value.code == 7


# ── Inclusion proof verification ────────────────────────────────────


def _make_proof(
    privkey: ec.EllipticCurvePrivateKey,
    row_hashes: list[str],
    leaf_index: int,
    *,
    chain_seq_lo: int = 1,
) -> dict:
    root, levels = _build_rfc6962_tree(row_hashes)
    sth = _sth_dict(
        privkey, tree_size=len(row_hashes), root_hash_hex=root.hex(),
        chain_seq_lo=chain_seq_lo,
        chain_seq_hi=chain_seq_lo + len(row_hashes) - 1,
    )
    return {
        "epoch_utc": sth["epoch_utc"],
        "leaf_index": leaf_index,
        "leaf_hash_hex": cli._rfc6962_leaf_hash(row_hashes[leaf_index]).hex(),
        "audit_path": _audit_path(levels, leaf_index),
        "sth": sth,
    }


def test_archive_proof_valid_returns_count(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(8)]
    proof = _make_proof(privkey, rh, leaf_index=3)
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof))
    s, m, p = cli.verify_archive_proofs(
        [], [str(path)], [], str(pem_path), [],
    )
    assert (s, m, p) == (0, 0, 1)


def test_archive_proof_validates_against_bundle_row_hash(mastio_key, tmp_path):
    """When the bundle is supplied alongside the proof, the verifier
    cross-checks: bundle row_hash → leaf hash → must match proof's
    leaf_hash_hex. Disagreement is a hard fail."""
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(4)]
    proof = _make_proof(privkey, rh, leaf_index=2, chain_seq_lo=1)
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof))

    # Build a bundle that agrees: chain_seq=3 corresponds to leaf_index=2
    # (chain_seq_lo=1 + leaf_index=2 == 3).
    bundle = [(
        "/dev/null",
        [{"chain_seq": 1 + i, "row_hash": rh[i]} for i in range(4)],
    )]
    s, m, p = cli.verify_archive_proofs(
        [], [str(path)], [], str(pem_path), bundle,
    )
    assert p == 1


def test_archive_proof_bundle_mismatch_exits_7(mastio_key, tmp_path):
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(4)]
    proof = _make_proof(privkey, rh, leaf_index=1, chain_seq_lo=1)
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof))

    # Bundle row_hash for chain_seq=2 has been tampered (does not match
    # what the proof was computed against). The verifier must refuse.
    tampered = [
        {"chain_seq": 1, "row_hash": rh[0]},
        {"chain_seq": 2, "row_hash": _h(b"forged")},
        {"chain_seq": 3, "row_hash": rh[2]},
        {"chain_seq": 4, "row_hash": rh[3]},
    ]
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [], [str(path)], [], str(pem_path), [("/dev/null", tampered)],
        )
    assert exc_info.value.code == 7


def test_archive_proof_inclusion_fail_exits_7(mastio_key, tmp_path):
    """Tamper with the audit_path after signing the STH — the
    reconstructed root will no longer match the anchored one."""
    privkey, pem_path = mastio_key
    rh = [_h(f"r{i}".encode()) for i in range(8)]
    proof = _make_proof(privkey, rh, leaf_index=3)
    proof["audit_path"][0] = "ff" * 32  # tamper path
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof))
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [], [str(path)], [], str(pem_path), [],
        )
    assert exc_info.value.code == 7


# ── CLI guard rails ─────────────────────────────────────────────────


def test_archive_without_pubkey_exits_7(tmp_path):
    """Setting --archive-sth (etc.) without --archive-manifest-pubkey
    is a CLI usage error → exit 7, no signature math attempted."""
    sth_path = tmp_path / "sth.json"
    sth_path.write_text("{}")
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [str(sth_path)], [], [], None, [],
        )
    assert exc_info.value.code == 7


def test_no_archive_flags_returns_zeros():
    s, m, p = cli.verify_archive_proofs([], [], [], None, [])
    assert (s, m, p) == (0, 0, 0)


def test_archive_pubkey_unreadable_exits_7(tmp_path):
    sth_path = tmp_path / "sth.json"
    sth_path.write_text("{}")
    with pytest.raises(SystemExit) as exc_info:
        cli.verify_archive_proofs(
            [str(sth_path)], [], [], "/nonexistent.pem", [],
        )
    assert exc_info.value.code == 7
