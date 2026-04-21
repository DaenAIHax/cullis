"""ADR-012 Phase 2.1 — Court-side verification of Mastio key-continuity
proofs.

This module verifies a proof produced by
``mcp_proxy.auth.mastio_rotation.build_proof``. It intentionally
duplicates the ``ContinuityProof`` dataclass and the canonical payload
function rather than importing them from ``mcp_proxy``: the broker
runtime ships without the proxy package and the two codebases are
kept import-isolated on purpose (``app/`` never depends on
``mcp_proxy/``).

If the proof format changes, update **both** modules in lockstep. The
happy-path round-trip test in
``tests/test_broker_mastio_pubkey_rotate.py`` catches mismatches
because it imports the *mcp_proxy* ``build_proof`` and then drives
this module's ``verify_proof``.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


PROOF_FRESHNESS_SECONDS = 600


@dataclass(frozen=True)
class ContinuityProof:
    old_kid: str
    new_kid: str
    new_pubkey_pem: str
    issued_at: str
    signature_b64u: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContinuityProof":
        required = {"old_kid", "new_kid", "new_pubkey_pem", "issued_at", "signature_b64u"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"continuity proof missing fields: {sorted(missing)}")
        for key in required:
            if not isinstance(data[key], str) or not data[key]:
                raise ValueError(
                    f"continuity proof field {key!r} must be a non-empty string",
                )
        return cls(
            old_kid=data["old_kid"],
            new_kid=data["new_kid"],
            new_pubkey_pem=data["new_pubkey_pem"],
            issued_at=data["issued_at"],
            signature_b64u=data["signature_b64u"],
        )


class ContinuityProofError(Exception):
    """Raised when a continuity proof fails any validation step."""


def _canonical_payload(
    *, old_kid: str, new_kid: str, new_pubkey_pem: str, issued_at: str,
) -> bytes:
    return json.dumps(
        {
            "issued_at": issued_at,
            "new_kid": new_kid,
            "new_pubkey_pem": new_pubkey_pem,
            "old_kid": old_kid,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def verify_proof(
    proof: ContinuityProof,
    *,
    expected_old_pubkey_pem: str,
    expected_old_kid: str | None = None,
    now: datetime | None = None,
    freshness_seconds: int = PROOF_FRESHNESS_SECONDS,
) -> None:
    """Verify a continuity proof against the pinned old pubkey.

    Raises :class:`ContinuityProofError` on any validation failure.
    """
    if expected_old_kid is not None and proof.old_kid != expected_old_kid:
        raise ContinuityProofError(
            f"old_kid mismatch: proof carries {proof.old_kid!r}, "
            f"Court has {expected_old_kid!r} pinned",
        )

    try:
        issued = datetime.fromisoformat(proof.issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityProofError(f"invalid issued_at: {exc}") from exc
    if issued.tzinfo is None:
        raise ContinuityProofError("issued_at is not timezone-aware")
    reference = now or datetime.now(timezone.utc)
    delta = abs((reference - issued).total_seconds())
    if delta > freshness_seconds:
        raise ContinuityProofError(
            f"issued_at is outside the freshness window "
            f"({int(delta)}s > {freshness_seconds}s)",
        )

    try:
        pub_key = serialization.load_pem_public_key(expected_old_pubkey_pem.encode())
    except ValueError as exc:
        raise ContinuityProofError(
            f"malformed expected_old_pubkey_pem: {exc}",
        ) from exc
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ContinuityProofError("expected_old_pubkey is not an EC key")

    try:
        raw_sig = base64.urlsafe_b64decode(
            proof.signature_b64u + "=" * (-len(proof.signature_b64u) % 4),
        )
    except (ValueError, binascii.Error) as exc:
        raise ContinuityProofError(f"malformed signature_b64u: {exc}") from exc
    if len(raw_sig) != 64:
        raise ContinuityProofError(
            f"signature must be 64 bytes (r||s), got {len(raw_sig)}",
        )
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s)

    payload = _canonical_payload(
        old_kid=proof.old_kid,
        new_kid=proof.new_kid,
        new_pubkey_pem=proof.new_pubkey_pem,
        issued_at=proof.issued_at,
    )
    try:
        pub_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ContinuityProofError("signature verification failed") from exc


def compute_kid_from_pubkey_pem(pubkey_pem: str) -> str:
    """Reproduce the Mastio kid derivation locally so the Court can
    assert ``proof.old_kid`` matches the currently-pinned pubkey."""
    import hashlib
    return "mastio-" + hashlib.sha256(pubkey_pem.encode()).hexdigest()[:16]


__all__ = [
    "ContinuityProof",
    "ContinuityProofError",
    "PROOF_FRESHNESS_SECONDS",
    "compute_kid_from_pubkey_pem",
    "verify_proof",
]
