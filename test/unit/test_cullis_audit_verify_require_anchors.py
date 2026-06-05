"""Unit tests for ``scripts/cullis-audit-verify.py --require-anchors``.

A SHA-256 hash chain is *self-asserted*: ``verify_chains`` proves it is
internally consistent, but an operator with write access to the audit
store can recompute every ``row_hash`` and forge a chain that still
verifies. The RFC 3161 TSA anchors are the only provenance binding the
chain to an external, independently-trusted timestamp.

Before this fix the verifier printed "✓ CHAIN VERIFIED" and exited 0 even
when the bundle carried ZERO anchors — a green verdict an operator could
hand a regulator after rewriting the database. ``--require-anchors`` adds
a dispute-grade floor (exit 8) without changing the permissive default
(chain-only verification stays exit 0 for dev / integrity-only callers).

The CLI is loaded as a module via importlib (its filename is dash-named
and not importable directly), mirroring the existing verifier tests.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


# ── Load the dash-named script as a module ──────────────────────────


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "cullis-audit-verify.py"
)


def _load_cli_module():
    spec = importlib.util.spec_from_file_location(
        "cullis_audit_verify_cli_require_anchors", str(_SCRIPT_PATH),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load_cli_module()


# ── Helpers ─────────────────────────────────────────────────────────


def _valid_legacy_bundle(tmp_path) -> str:
    """Write a one-row, anchor-free NDJSON bundle whose entry_hash is
    computed with the verifier's own ``canonical`` so it passes
    ``verify_chains`` cleanly. ``kind`` is absent → load_bundle treats it
    as a legacy entry; no ``anchor`` line → total_anchors == 0."""
    entry = {
        "id": 1,
        "timestamp": "2026-06-05T00:00:00Z",
        "event_type": "oneshot",
        "agent_id": "acme::alice",
        "org_id": "acme",
        "result": "success",
        "details": "",
        "previous_hash": None,
    }
    entry["entry_hash"] = hashlib.sha256(
        cli.canonical(entry, None).encode("utf-8")
    ).hexdigest()
    path = tmp_path / "bundle.ndjson"
    path.write_text(json.dumps(entry) + "\n")
    return str(path)


def _mock_anchored_bundle(tmp_path) -> str:
    """Write a one-row per-org bundle anchored with a forgeable ``MK|``
    mock token. The chain verifies (verify_chains green) and the anchor
    verifies (backend label ``mock``) — so the bundle carries ONE
    verified TSA anchor but ZERO dispute-grade anchors. An operator with
    write access can recompute the row and mint the matching mock token
    at will, which is exactly why ``--require-anchors`` must reject this."""
    entry = {
        "id": 1,
        "timestamp": "2026-06-05T00:00:00Z",
        "event_type": "oneshot",
        "agent_id": "acme::alice",
        "org_id": "acme",
        "result": "success",
        "details": "",
        "previous_hash": None,
        "chain_seq": 1,
    }
    entry_hash = hashlib.sha256(
        cli.canonical(entry, None).encode("utf-8")
    ).hexdigest()
    entry["entry_hash"] = entry_hash

    # The verifier digests the anchor's row_hash (= entry_hash) and
    # matches it against the MK| token's embedded digest.
    digest_hex = hashlib.sha256(entry_hash.encode("ascii")).hexdigest()
    mock_token = b"MK|" + digest_hex.encode("ascii") + b"|forged-by-operator"
    anchor = {
        "kind": "anchor",
        "org_id": "acme",
        "chain_seq": 1,
        "row_hash": entry_hash,
        "tsa_token_b64": base64.b64encode(mock_token).decode("ascii"),
    }
    path = tmp_path / "bundle.ndjson"
    path.write_text(json.dumps(entry) + "\n" + json.dumps(anchor) + "\n")
    return str(path)


# ── enforce_anchor_floor (the pure gate) ────────────────────────────


def test_floor_off_allows_zero_anchors():
    # No flag → never raises, regardless of anchor count.
    assert cli.enforce_anchor_floor(False, 0) is None


def test_floor_on_with_anchors_allows():
    # Flag set but anchors present → passes.
    assert cli.enforce_anchor_floor(True, 3) is None


def test_floor_on_zero_anchors_exits_8():
    with pytest.raises(SystemExit) as exc_info:
        cli.enforce_anchor_floor(True, 0)
    assert exc_info.value.code == 8


# ── main() end-to-end ───────────────────────────────────────────────


def test_main_zero_anchors_passes_without_flag(tmp_path, monkeypatch, capsys):
    """Default behaviour preserved: an anchor-free but intact chain still
    verifies green. This is the pre-fix contract we must NOT break."""
    path = _valid_legacy_bundle(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["cullis-audit-verify", "--bundle", path],
    )
    rc = cli.main()
    assert rc == 0
    assert "CHAIN VERIFIED" in capsys.readouterr().out


def test_main_zero_anchors_fails_with_require(tmp_path, monkeypatch, capsys):
    """THE FIX. Same intact, anchor-free bundle + --require-anchors must
    exit 8 and NOT print the green verdict."""
    path = _valid_legacy_bundle(tmp_path)
    monkeypatch.setattr(
        sys, "argv",
        ["cullis-audit-verify", "--bundle", path, "--require-anchors"],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 8
    out = capsys.readouterr().out
    assert "ANCHOR REQUIREMENT NOT MET" in out
    assert "CHAIN VERIFIED" not in out


# ── mock anchors are NOT dispute-grade (the tightening) ──────────────


def test_main_mock_anchor_passes_without_flag(tmp_path, monkeypatch, capsys):
    """A mock-anchored bundle still verifies green by default, and the
    summary surfaces that the lone anchor is NOT dispute-grade."""
    path = _mock_anchored_bundle(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["cullis-audit-verify", "--bundle", path],
    )
    rc = cli.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "CHAIN VERIFIED" in out
    # One verified anchor, zero dispute-grade → breakdown is shown.
    assert "1 TSA anchor" in out
    assert "0 dispute-grade" in out


def test_main_mock_anchor_fails_with_require(tmp_path, monkeypatch, capsys):
    """THE TIGHTENING. A forgeable MK| mock anchor must NOT satisfy
    --require-anchors: an operator who can rewrite the store can mint it,
    so it proves nothing against the operator. Exit 8, no green verdict."""
    path = _mock_anchored_bundle(tmp_path)
    monkeypatch.setattr(
        sys, "argv",
        ["cullis-audit-verify", "--bundle", path, "--require-anchors"],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 8
    out = capsys.readouterr().out
    assert "ANCHOR REQUIREMENT NOT MET" in out
    assert "CHAIN VERIFIED" not in out


def test_verify_anchors_returns_mock_as_non_dispute_grade(tmp_path):
    """verify_anchors counts a mock anchor toward the total but not
    toward the dispute-grade subset (the second tuple element)."""
    path = _mock_anchored_bundle(tmp_path)
    entries, anchors = cli.load_bundle(path)
    verified, dispute_grade = cli.verify_anchors(entries, anchors)
    assert verified == 1
    assert dispute_grade == 0
