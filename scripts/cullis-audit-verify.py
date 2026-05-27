#!/usr/bin/env python3
"""Standalone offline verifier for Cullis audit exports (issue #75).

Consumes the NDJSON bundle produced by `GET /v1/admin/audit/export`
and verifies, with zero network calls:

  1. Each per-org hash chain is internally consistent (every entry's
     `entry_hash` is the sha256 of its canonical string, and
     `previous_hash` links to the prior entry in the same org).
  2. The residual legacy global chain (rows with `chain_seq is None`)
     is intact under the pre-per-org rules.
  3. Every TSA anchor row matches a real chain head + the TSA token
     cryptographically binds the recorded `row_hash` (mock tokens are
     verified by prefix matching; RFC 3161 tokens are verified via
     the `rfc3161-client` library if installed, otherwise flagged).
  4. Cross-org reconciliation (optional): when two bundles from two
     orgs are supplied, rows with `peer_org_id` + `peer_row_hash`
     must point at the counterpart row in the other bundle and the
     two rows must agree on event_type / session_id / details.

For RFC 3161 anchors, the verifier validates:
  - CMS SignerInfo signature against the embedded signing cert
    (the TSA put it in ``SignedData.certificates`` because the
    Mastio's TSA client requests ``cert_request=True``).
  - Cert chain walked from signer leaf to an operator-supplied
    trust anchor (``--tsa-trust-store PEM_BUNDLE``).
  - Signer cert ``extKeyUsage`` includes ``id-kp-timeStamping``.
  - TSTInfo ``messageImprint`` matches sha256(row_hash).
  - TSTInfo ``genTime`` is not in the future (with a small skew) and
    not absurdly old (``--tsa-max-age-days``, default 3650 = 10y).

Without ``--tsa-trust-store`` the verifier fails closed on RFC 3161
anchors (exit 5). Pass ``--tsa-allow-unverified-signature`` to fall
back to the legacy messageImprint-only check (F-A-405 pre-fix
behaviour) — useful for dispute-side parties who do not control the
Mastio's TSA roster yet, but they must understand the anchor is then
no stronger than the broker's own DB.

Usage:
  # Verify one org's bundle (TSA anchors signature-verified):
  python cullis-audit-verify.py --bundle acme.ndjson \\
      --tsa-trust-store /etc/cullis/tsa-roots.pem

  # Cross-verify two orgs for dispute resolution:
  python cullis-audit-verify.py --bundle acme.ndjson --bundle bravo.ndjson \\
      --tsa-trust-store /etc/cullis/tsa-roots.pem

Exit codes:
  0  — all checks passed
  2  — chain tamper detected (mismatch or break)
  3  — TSA anchor mismatch (row_hash disagreement, signature invalid,
       chain does not lead to trust store, or genTime out of range)
  4  — cross-org reconciliation mismatch
  5  — unrecognized TSA format that cannot be verified, or RFC 3161
       anchor seen without ``--tsa-trust-store`` and
       ``--tsa-allow-unverified-signature`` not set
  6  — Merkle inclusion proof failure (proof file unreadable or
       malformed, no matching chain_seq entry in bundle, bundle
       row_hash disagrees with proof leaf_hex, or reconstructed root
       does not match anchored root) — ADR-037 Phase 3
  7  — Enterprise audit_archive verification failure (STH ES256
       signature invalid, manifest signature invalid, RFC 6962 audit
       path does not reconstruct the anchored root, bundle row_hash
       disagrees with proof leaf_hash, or --archive-manifest-pubkey
       missing when archive flags are set)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


_MOCK_MAGIC = b"MK"
_RFC3161_MAGIC = b"T1"

# RFC 5280 ExtendedKeyUsage OID for id-kp-timeStamping (RFC 3161 §2.3).
# Required on the TSA's signing cert; rejecting tokens whose signer
# cert is missing this EKU stops a non-TSA cert from masquerading as a
# timestamp authority signer.
_OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"


def canonical(entry: dict[str, Any], previous_hash: str | None) -> str:
    """Reconstruct the canonical string used to compute ``entry_hash``.

    Wave B PR5 (audit 2026-05-11 CRIT-3 Court) — dispatches on
    ``hash_format``:
      - NULL or 'v1' → legacy entry_id-bound canonical (unchanged)
      - 'v2' → entry_id-free canonical, prefixed with literal ``v2|``;
        chain_seq required (atomic-insert form, no back-fill UPDATE)

    Both forms also append ``|pt=<x>`` when a non-default
    ``principal_type`` is present (ADR-020 marker).
    """
    fmt = (entry.get("hash_format") or "v1").lower()
    chain_seq = entry.get("chain_seq")

    if fmt == "v2":
        if chain_seq is None:
            # v2 always uses chain_seq; refuse a malformed bundle
            # explicitly so the verifier doesn't silently agree.
            return "INVALID-V2-WITHOUT-CHAIN-SEQ"
        canonical_str = "|".join([
            "v2",
            entry["timestamp"] or "",
            entry["event_type"],
            entry.get("agent_id") or "",
            entry.get("session_id") or "",
            entry.get("org_id") or "",
            entry["result"],
            entry.get("details") or "",
            previous_hash or "genesis",
            f"seq={chain_seq}",
            f"peer={entry.get('peer_org_id') or ''}",
        ])
    else:
        base = "|".join([
            str(entry["id"]),
            entry["timestamp"] or "",
            entry["event_type"],
            entry.get("agent_id") or "",
            entry.get("session_id") or "",
            entry.get("org_id") or "",
            entry["result"],
            entry.get("details") or "",
            previous_hash or "genesis",
        ])
        if chain_seq is None:
            canonical_str = base
        else:
            canonical_str = (
                f"{base}|seq={chain_seq}|peer={entry.get('peer_org_id') or ''}"
            )

    pt = entry.get("principal_type")
    if pt and pt != "agent":
        canonical_str = f"{canonical_str}|pt={pt}"
    return canonical_str


def _chain_reaches_trust_store(
    leaf,
    embedded_certs: list,
    trust_roots: list,
    *,
    verification_time: datetime,
) -> bool:
    """Return True when ``leaf`` chains up to ANY cert in ``trust_roots``
    using ``embedded_certs`` as intermediates.

    ``rfc3161-client`` folds embedded SignedData.certificates into the
    same set it passes to OpenSSL's PKCS7_verify alongside the operator
    trust roots — which means an attacker who embeds their own self-
    signed cert chain in the TST can satisfy the chain walk regardless
    of what the operator pinned as trust roots. We pre-check here that
    a chain actually leads to the operator's trust store before
    delegating signature verification to the library, so the operator's
    pin is enforced.

    Verifies issuer/subject linkage AND that each parent's signature
    over the child cert is valid AND that each cert is within its
    validity window at ``verification_time``. Detects a forged self-
    signed cert in the embedded set that an attacker could otherwise
    use to bypass the trust store.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    def _is_valid_intermediate(cand) -> bool:
        """Defense-in-depth RFC 5280 §6.1.4 checks on a candidate
        intermediate cert. ``rfc3161-client`` already does most of this
        in its own chain walk, but the operator-pin pre-check has been
        delegating signature + linkage verification only. Adding these
        keeps a forged intermediate (whose subject/issuer linkage and
        signature happen to look right but whose extensions don't
        authorise it to issue subordinate certs) from satisfying the
        pre-check.

        Required:

        - ``BasicConstraints(ca=True)`` — the cert must self-declare as
          a CA. A leaf cert (``ca=False`` or extension absent) cannot
          legitimately sit between the TSA signer and a trust root.
        - ``KeyUsage.key_cert_sign=True`` (when the KeyUsage extension
          is present). RFC 5280 §4.2.1.3 requires this bit on any cert
          that signs other certs; we treat its absence as fatal.

        ``path_length`` is enforced separately in the BFS loop because
        it depends on how many intermediates were walked, not just on
        the candidate cert itself.
        """
        try:
            bc = cand.extensions.get_extension_for_class(
                x509.BasicConstraints,
            ).value
            if not bc.ca:
                return False
        except x509.ExtensionNotFound:
            # No BasicConstraints → can't authoritatively assert CA
            # status. Refuse rather than infer.
            return False
        try:
            ku = cand.extensions.get_extension_for_class(
                x509.KeyUsage,
            ).value
            if not ku.key_cert_sign:
                return False
        except x509.ExtensionNotFound:
            # KeyUsage is optional in RFC 5280, but when present on a
            # CA cert ``key_cert_sign`` MUST be true. When absent we
            # tolerate it for backwards compatibility with older roots
            # in the wild that omit KeyUsage entirely.
            pass
        return True

    def _candidate_path_length(cand) -> int | None:
        """Return the ``pathLenConstraint`` of the candidate cert, or
        ``None`` when unconstrained / extension absent. RFC 5280
        §6.1.4 item (i): the number of certificates in the chain
        following this cert must not exceed ``pathLenConstraint + 1``.
        """
        try:
            bc = cand.extensions.get_extension_for_class(
                x509.BasicConstraints,
            ).value
            return bc.path_length
        except x509.ExtensionNotFound:
            return None

    def _is_within_validity(cert) -> bool:
        nvb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        nva = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        return nvb <= verification_time <= nva

    def _verify_signed_by(child, parent) -> bool:
        """True when ``parent``'s public key validates ``child``'s
        signature. Supports RSA-PKCS#1v1.5, RSA-PSS, and ECDSA.

        Public TSAs in production today (DigiCert / GlobalSign /
        Sectigo / Apple) emit RSA-PKCS#1v1.5 or ECDSA, but EJBCA
        defaults to RSA-PSS — without the PSS branch a valid PSS-signed
        intermediate would be rejected as ``rfc3161-untrusted-chain``,
        confusing the auditor between a real trust mismatch and a
        plain "we don't speak this algorithm" gap.
        """
        try:
            pub = parent.public_key()
            sig = child.signature
            tbs = child.tbs_certificate_bytes
            hash_alg = child.signature_hash_algorithm
            if hash_alg is None:
                return False
            if isinstance(pub, rsa.RSAPublicKey):
                # cryptography exposes the parsed signature_algorithm_
                # parameters as either a ``padding.PSS`` instance (when
                # the cert was signed with RSASSA-PSS, OID 1.2.840.
                # 113549.1.1.10) or ``None`` for PKCS#1v1.5. Prefer the
                # PSS path when available.
                sig_params = getattr(child, "signature_algorithm_parameters", None)
                if isinstance(sig_params, padding.PSS):
                    pub.verify(sig, tbs, sig_params, hash_alg)
                else:
                    pub.verify(sig, tbs, padding.PKCS1v15(), hash_alg)
                return True
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(sig, tbs, ec.ECDSA(hash_alg))
                return True
            return False
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001
            return False

    # BFS up the chain: at each step, find a parent whose subject
    # matches the current node's issuer and whose key validates the
    # current node's signature. Stop when the parent is in the trust
    # store. Bound by the total cert population to avoid loops.
    #
    # Frontier holds tuples of ``(cert, intermediates_below)`` —
    # ``intermediates_below`` counts how many embedded intermediates
    # have been walked through to reach this node (the leaf starts at
    # 0). Used to enforce RFC 5280 §6.1.4 ``pathLenConstraint``.
    visited: set[bytes] = set()
    frontier: list = [(leaf, 0)]
    max_steps = len(embedded_certs) + len(trust_roots) + 2
    for _ in range(max_steps):
        if not frontier:
            return False
        nxt = []
        for node, intermediates_below in frontier:
            if not _is_within_validity(node):
                continue
            fp = node.fingerprint(hashes.SHA256())
            if fp in visited:
                continue
            visited.add(fp)
            # Trust-anchor check: does ANY trust root validate this
            # node? (Self-signed roots validate themselves; subordinate
            # nodes are validated by a root cert.) ``pathLenConstraint``
            # on the root is not checked: by RFC 5280 the constraint
            # applies to the root's authorisation over the rest of the
            # chain, but as the trust anchor it is the boundary itself.
            for root in trust_roots:
                if (
                    node.issuer == root.subject
                    and _verify_signed_by(node, root)
                    and _is_within_validity(root)
                ):
                    return True
            # Otherwise, hunt for a parent in embedded_certs that
            # signs this node, AND that is allowed by its own
            # extensions to issue subordinate certs at this depth.
            for cand in embedded_certs:
                if cand.fingerprint(hashes.SHA256()) in visited:
                    continue
                if (
                    node.issuer == cand.subject
                    and _verify_signed_by(node, cand)
                    and _is_valid_intermediate(cand)
                ):
                    # Enforce pathLenConstraint on ``cand``: the cert
                    # authorises at most ``pathLenConstraint``
                    # intermediates below it. We've already walked
                    # ``intermediates_below`` intermediates between the
                    # leaf and ``cand``; that must not exceed ``cand``'s
                    # constraint, otherwise ``cand`` was not minted with
                    # authority to certify the present chain shape.
                    cand_pathlen = _candidate_path_length(cand)
                    if (
                        cand_pathlen is not None
                        and intermediates_below > cand_pathlen
                    ):
                        continue
                    # ``cand`` has one more intermediate below it than
                    # ``node`` did, UNLESS ``node`` is the leaf
                    # (intermediates_below stays 0 for the first hop).
                    new_below = (
                        intermediates_below
                        if node is leaf
                        else intermediates_below + 1
                    )
                    nxt.append((cand, new_below))
        frontier = nxt
    return False


def _load_trust_store(path: str) -> list:
    """Load PEM-encoded trust anchors as a list of cryptography x509
    objects. Each PEM block in the bundle is a separate trust root.

    The bundle is expected to contain the TSA's CA chain root(s), not
    the leaf signing cert (the leaf rides inside the TimeStampToken
    itself thanks to ``cert_request=True`` on the TSA request).
    """
    from cryptography import x509
    with open(path, "rb") as f:
        pem_data = f.read()
    roots: list = []
    # Split on PEM markers so a single bundle with multiple CERTIFICATE
    # blocks loads cleanly. x509.load_pem_x509_certificates is the
    # cryptography>=42 helper; fall back to a manual split for older
    # installs that ship cryptography<42 alongside the Mastio image.
    if hasattr(x509, "load_pem_x509_certificates"):
        roots = list(x509.load_pem_x509_certificates(pem_data))
    else:
        marker = b"-----BEGIN CERTIFICATE-----"
        end = b"-----END CERTIFICATE-----"
        i = 0
        while True:
            start = pem_data.find(marker, i)
            if start == -1:
                break
            stop = pem_data.find(end, start)
            if stop == -1:
                break
            block = pem_data[start:stop + len(end)]
            roots.append(x509.load_pem_x509_certificate(block))
            i = stop + len(end)
    if not roots:
        raise ValueError(
            f"trust store {path!r} contains no PEM CERTIFICATE blocks",
        )
    return roots


def verify_token_against_digest(
    token_bytes: bytes,
    digest_hex: str,
    *,
    row_hash: str | None = None,
    trust_store_path: str | None = None,
    allow_unverified_signature: bool = False,
    max_age_days: int = 3650,
    skew_seconds: int = 300,
) -> tuple[bool, str]:
    """Return (verified, backend_label).

    Mock tokens (legacy / tests) are verified by embedded digest match.

    RFC 3161 tokens are verified end-to-end against an operator-supplied
    trust store: the CMS SignerInfo signature is checked against the
    signing cert embedded in the token (the TSA included it because
    ``cert_request=True`` was set on the request), the chain is walked
    to one of the PEM roots in ``trust_store_path``, the signing cert
    is required to carry the ``id-kp-timeStamping`` extKeyUsage, the
    TSTInfo ``messageImprint`` must match ``sha256(row_hash)``, and
    ``genTime`` must not be in the future or absurdly old.

    Args:
        token_bytes: raw stored token (``MK|…`` or ``T1|…`` prefixed).
        digest_hex: hex SHA-256 of the original message (= ``sha256(row_hash)``).
        row_hash: the audit chain head's row_hash hex string. Required
            for RFC 3161 verification because the signature is computed
            over the original message (``row_hash.encode("ascii")``),
            not the precomputed digest.
        trust_store_path: PEM bundle of TSA root certs. When ``None``
            the verifier refuses RFC 3161 tokens (returns ``False`` with
            backend label ``rfc3161-no-trust-store``) unless
            ``allow_unverified_signature`` is set.
        allow_unverified_signature: when True, falls back to the
            messageImprint-only check the verifier did before F-A-405
            was fixed. Useful for dispute-side parties that do not yet
            have the Mastio's TSA roster on hand but want a partial
            check. The token is **not** dispute-grade in this mode.
        max_age_days: reject tokens with ``genTime`` older than this.
            Default 10 years — anchors are forensic and long-lived.
        skew_seconds: tolerate ``genTime`` ahead of the verifier's
            wall clock by this much before flagging it as future.

    Returns:
        ``(verified, backend_label)``. Caller routes exit codes off
        the label so unverifiable-vs-tampered failures are
        distinguishable.
    """
    if token_bytes.startswith(_MOCK_MAGIC + b"|"):
        try:
            remainder = token_bytes[len(_MOCK_MAGIC) + 1:].decode("utf-8")
        except UnicodeDecodeError:
            return (False, "mock-malformed")
        parts = remainder.split("|", 1)
        if len(parts) != 2:
            return (False, "mock-malformed")
        return (parts[0] == digest_hex, "mock")

    if token_bytes.startswith(_RFC3161_MAGIC + b"|"):
        raw = token_bytes[len(_RFC3161_MAGIC) + 1:]
        if row_hash is None:
            # Without the original message the signature path is not
            # reachable. Imprint-only check is still doable and matches
            # the pre-F-A-405 behaviour the verifier shipped with.
            return _verify_rfc3161_imprint_only(raw, digest_hex)
        return _verify_rfc3161_full(
            raw,
            digest_hex=digest_hex,
            row_hash=row_hash,
            trust_store_path=trust_store_path,
            allow_unverified_signature=allow_unverified_signature,
            max_age_days=max_age_days,
            skew_seconds=skew_seconds,
        )

    return (False, "unrecognized")


def _verify_rfc3161_imprint_only(raw_token: bytes, digest_hex: str) -> tuple[bool, str]:
    """Legacy F-A-405 fallback path — messageImprint match only.

    Kept available for callers that have a stored token but no row_hash
    handy (the new full-verify path needs row_hash to reconstruct the
    original message for the signature check). This path is NOT
    dispute-grade: an attacker with row_hash can fabricate a TST whose
    imprint matches.
    """
    try:
        from asn1crypto import cms  # type: ignore[import-not-found]
    except ImportError:
        return (False, "rfc3161-lib-missing")
    try:
        # The stored TST is the ``time_stamp_token`` field of a
        # TimeStampResp, which is a CMS ``ContentInfo`` of type
        # ``signed_data``. Parse it as such.
        tst = cms.ContentInfo.load(raw_token)
        content = tst["content"]
        mi = content["encap_content_info"]["content"].parsed["message_imprint"]
        imprint_digest = mi["hashed_message"].native.hex()
        return (imprint_digest == digest_hex, "rfc3161-imprint-only")
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 parse error: {exc}", file=sys.stderr)
        return (False, "rfc3161-parse-error")


def _verify_rfc3161_full(
    raw_token: bytes,
    *,
    digest_hex: str,
    row_hash: str,
    trust_store_path: str | None,
    allow_unverified_signature: bool,
    max_age_days: int,
    skew_seconds: int,
) -> tuple[bool, str]:
    """Full RFC 3161 verification: CMS sig + chain + EKU + imprint + genTime.

    See module docstring for the dispute-grade rationale. Returns
    ``(False, backend_label)`` on every failure mode so the caller can
    pick the right exit code (anchor-mismatch vs unverifiable).
    """
    try:
        from asn1crypto import cms as _asn1_cms  # type: ignore[import-not-found]
        from asn1crypto import tsp as _asn1_tsp  # type: ignore[import-not-found]
    except ImportError:
        return (False, "rfc3161-lib-missing")
    try:
        # Stored token = CMS ContentInfo (type signed_data) carrying
        # the TSTInfo. Same shape the TSA emits in the TimeStampResp's
        # ``time_stamp_token`` field. asn1crypto does not expose a
        # standalone ``TimeStampToken`` class — the wire format IS a
        # ContentInfo, so parse it as one.
        tst = _asn1_cms.ContentInfo.load(raw_token)
        encap = tst["content"]["encap_content_info"]["content"].parsed
        imprint = encap["message_imprint"]["hashed_message"].native
        imprint_alg_oid = (
            encap["message_imprint"]["hash_algorithm"]["algorithm"].dotted
        )
        gen_time = encap["gen_time"].native
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 parse error: {exc}", file=sys.stderr)
        return (False, "rfc3161-parse-error")

    # Hash-algorithm-aware imprint pre-check. ``digest_hex`` is
    # precomputed by the caller as SHA-256 of the row_hash, which
    # matches today's producer (``mcp_proxy/audit/tsa_client.py``
    # hardcoded SHA-256), but the TSA itself could emit SHA-384 / 512
    # tokens. The downstream ``verifier.verify_message`` already
    # dispatches on the declared algorithm; this pre-check has to
    # follow suit or it would short-circuit a valid SHA-384/512 token
    # as ``rfc3161-imprint-mismatch``.
    _OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    _OID_SHA384 = "2.16.840.1.101.3.4.2.2"
    _OID_SHA512 = "2.16.840.1.101.3.4.2.3"
    if imprint_alg_oid == _OID_SHA256:
        expected_imprint_hex = digest_hex
    elif imprint_alg_oid in (_OID_SHA384, _OID_SHA512):
        import hashlib

        hasher = (
            hashlib.sha384
            if imprint_alg_oid == _OID_SHA384
            else hashlib.sha512
        )
        expected_imprint_hex = hasher(row_hash.encode("ascii")).hexdigest()
    else:
        print(
            f"  rfc3161 unsupported imprint hash algorithm OID "
            f"{imprint_alg_oid}",
            file=sys.stderr,
        )
        return (False, "rfc3161-unsupported-imprint-alg")
    if imprint.hex() != expected_imprint_hex:
        return (False, "rfc3161-imprint-mismatch")

    now = datetime.now(timezone.utc)
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    if gen_time > now + timedelta(seconds=skew_seconds):
        print(
            f"  rfc3161 genTime {gen_time.isoformat()} is in the future "
            f"(>{skew_seconds}s skew vs {now.isoformat()})",
            file=sys.stderr,
        )
        return (False, "rfc3161-gentime-future")
    if gen_time < now - timedelta(days=max_age_days):
        print(
            f"  rfc3161 genTime {gen_time.isoformat()} is older than "
            f"{max_age_days} days",
            file=sys.stderr,
        )
        return (False, "rfc3161-gentime-stale")

    # EKU check on the embedded signer cert. RFC 3161 §2.3 mandates
    # id-kp-timeStamping on the signing cert; a CA cert without this
    # EKU must not be accepted as a TSA signer.
    try:
        from cryptography import x509
        certs_field = tst["content"]["certificates"]
        if certs_field is None:
            return (False, "rfc3161-no-embedded-cert")
        signer_eku_ok = False
        for choice in certs_field:
            if choice.name != "certificate":
                continue
            cert = x509.load_der_x509_certificate(choice.chosen.dump())
            try:
                eku = cert.extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage,
                ).value
            except x509.ExtensionNotFound:
                continue
            for usage in eku:
                if usage.dotted_string == _OID_KP_TIME_STAMPING:
                    signer_eku_ok = True
                    break
            if signer_eku_ok:
                break
        if not signer_eku_ok:
            return (False, "rfc3161-no-timestamping-eku")
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 cert inspection failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-cert-parse-error")

    if trust_store_path is None:
        if allow_unverified_signature:
            print(
                "  WARNING: --tsa-allow-unverified-signature in effect — "
                "anchor not dispute-grade",
                file=sys.stderr,
            )
            return (True, "rfc3161-imprint-eku-only")
        return (False, "rfc3161-no-trust-store")

    try:
        from rfc3161_client import (  # type: ignore[import-not-found]
            VerifierBuilder,
            decode_timestamp_response,
        )
    except ImportError:
        return (False, "rfc3161-lib-missing")

    try:
        roots = _load_trust_store(trust_store_path)
    except Exception as exc:  # noqa: BLE001
        print(f"  trust store load failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-trust-store-bad")

    # Strict chain-walk: rfc3161-client folds embedded
    # SignedData.certificates into the same set it hands to
    # PKCS7_verify alongside the operator's trust roots, which lets a
    # token that embeds a self-signed cert chain bypass the operator's
    # trust pin. Walk the chain here from the SignerInfo's leaf up to
    # one of the operator-pinned trust roots; if no such chain exists
    # we reject before the library can spuriously accept.
    try:
        from cryptography import x509 as _x509
        certs_field = tst["content"]["certificates"]
        embedded_x509: list = []
        for choice in (certs_field or []):
            if choice.name == "certificate":
                embedded_x509.append(
                    _x509.load_der_x509_certificate(choice.chosen.dump()),
                )

        # Identify the leaf via the SignerInfo's issuerAndSerialNumber
        # (sid) — same logic rfc3161-client uses internally. Compare
        # Name values via DER bytes so we are robust to encoding /
        # canonicalisation drift between asn1crypto and cryptography.
        signer_infos = tst["content"]["signer_infos"]
        if len(signer_infos) != 1:
            return (False, "rfc3161-multi-signer")
        si = signer_infos[0]
        sid = si["sid"]
        if sid.name != "issuer_and_serial_number":
            return (False, "rfc3161-unsupported-sid")
        sid_issuer_der = sid.chosen["issuer"].dump()
        sid_serial = sid.chosen["serial_number"].native
        leaf_cert = None
        for cand in embedded_x509:
            if (
                cand.issuer.public_bytes() == sid_issuer_der
                and cand.serial_number == sid_serial
            ):
                leaf_cert = cand
                break
        if leaf_cert is None:
            return (False, "rfc3161-no-matching-signer-cert")

        if not _chain_reaches_trust_store(
            leaf_cert,
            embedded_x509,
            roots,
            verification_time=gen_time,
        ):
            print(
                "  rfc3161 chain does not reach any operator trust root",
                file=sys.stderr,
            )
            return (False, "rfc3161-untrusted-chain")
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 chain walk failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-chain-walk-error")

    # rfc3161-client only decodes TimeStampResp envelopes, not bare
    # TSTs. Wrap our stored TST in a synthetic status=granted
    # response (we already parsed it as ``tst`` above, reuse it),
    # feed it through the library, then run the Verifier against the
    # original message bytes.
    try:
        synthetic_resp = _asn1_tsp.TimeStampResp({
            "status": _asn1_tsp.PKIStatusInfo({"status": 0}),
            "time_stamp_token": tst,
        }).dump()
        decoded = decode_timestamp_response(synthetic_resp)
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 decode failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-decode-error")

    builder = VerifierBuilder()
    for root in roots:
        builder = builder.add_root_certificate(root)
    try:
        verifier = builder.build()
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 verifier build failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-verifier-build-error")

    # verify_message re-hashes the message with SHA-256 and compares
    # to the TST's messageImprint, then walks the cert chain and
    # checks the CMS signature.
    try:
        verifier.verify_message(decoded, row_hash.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        print(f"  rfc3161 signature verify failed: {exc}", file=sys.stderr)
        return (False, "rfc3161-signature-invalid")

    return (True, "rfc3161-verified")


def load_bundle(path: str) -> tuple[list[dict], list[dict]]:
    """Return (entries, anchors). Lines missing the "kind" key are
    treated as legacy (entry) format for backward compatibility."""
    entries: list[dict] = []
    anchors: list[dict] = []
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            kind = obj.get("kind", "entry")
            if kind == "entry":
                entries.append(obj)
            elif kind == "anchor":
                anchors.append(obj)
    return entries, anchors


def _print_tamper_detail(
    *,
    kind: str,
    e: dict,
    computed: str | None = None,
    declared_prev: str | None = None,
    expected_prev: str | None = None,
) -> None:
    """Print a CISO-readable explanation of a chain failure.

    Two failure modes:
      * ``MISMATCH`` — the row's content does not produce the
        ``entry_hash`` it carries. Someone altered a field after
        the row was written. Show computed vs declared hash so the
        auditor can pin the row.
      * ``BREAK`` — the row's ``previous_hash`` does not point at
        the prior row's ``entry_hash``. Either a row was deleted, or
        the linkage was tampered. Show declared vs expected prev.
    """
    print("")
    print("✗ CHAIN TAMPER DETECTED")
    print("")
    where = (
        f"  org={e.get('org_id', '?')}"
        f" · chain_seq={e.get('chain_seq', '-')}"
        f" · id={e['id']}"
    )
    print(where)
    print(f"  timestamp={e.get('timestamp', '-')}")
    print(f"  event_type={e.get('event_type', '-')}")
    print(f"  agent_id={e.get('agent_id', '-')}")
    print("")
    if kind == "MISMATCH":
        print("  The row's content does not produce the entry_hash it carries.")
        print("  A field on this row was altered after the chain was written.")
        print("")
        print(f"    expected entry_hash (computed from row): {computed}")
        print(f"    observed entry_hash (recorded on row):   {e['entry_hash']}")
    else:  # BREAK
        print("  The row's previous_hash does not point at the prior row's entry_hash.")
        print("  A row was deleted, reordered, or the linkage was rewritten.")
        print("")
        print(f"    declared previous_hash: {declared_prev}")
        print(f"    expected previous_hash: {expected_prev}")
    print("")
    print(f"  Rows after seq={e.get('chain_seq', '?')} cannot be trusted.")
    print("")


def verify_chains(entries: list[dict]) -> tuple[int, int, int]:
    """Verify all chains in a single bundle.

    Returns (legacy_n, per_org_n, agent_count). Exits 2 on any
    tamper. The agent count is surfaced so the PASS output can
    say "X entries · Y agents" without the caller re-scanning.
    """
    # Legacy
    prev: str | None = None
    legacy_n = 0
    agents_seen: set[str] = set()
    for e in entries:
        if e.get("agent_id"):
            agents_seen.add(e["agent_id"])
        if e.get("chain_seq") is not None:
            continue
        if e.get("entry_hash") is None:
            continue
        expected = canonical(e, prev)
        computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if computed != e["entry_hash"]:
            _print_tamper_detail(kind="MISMATCH", e=e, computed=computed)
            sys.exit(2)
        if e.get("previous_hash") != prev:
            _print_tamper_detail(
                kind="BREAK", e=e,
                declared_prev=e.get("previous_hash"),
                expected_prev=prev,
            )
            sys.exit(2)
        prev = e["entry_hash"]
        legacy_n += 1

    # Per-org
    last_legacy: dict[str, str] = {}
    for e in entries:
        if e.get("chain_seq") is None and e.get("entry_hash") is not None:
            last_legacy[e.get("org_id") or ""] = e["entry_hash"]

    per_org: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("chain_seq") is not None:
            per_org[e.get("org_id") or ""].append(e)

    per_org_n = 0
    for org, rows in per_org.items():
        rows.sort(key=lambda r: r["chain_seq"])
        expected_prev = last_legacy.get(org)
        for e in rows:
            expected = canonical(e, expected_prev)
            computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
            if computed != e["entry_hash"]:
                _print_tamper_detail(kind="MISMATCH", e=e, computed=computed)
                sys.exit(2)
            if e.get("previous_hash") != expected_prev:
                _print_tamper_detail(
                    kind="BREAK", e=e,
                    declared_prev=e.get("previous_hash"),
                    expected_prev=expected_prev,
                )
                sys.exit(2)
            expected_prev = e["entry_hash"]
            per_org_n += 1

    return (legacy_n, per_org_n, len(agents_seen))


def verify_anchors(
    entries: list[dict],
    anchors: list[dict],
    *,
    trust_store_path: str | None = None,
    allow_unverified_signature: bool = False,
    max_age_days: int = 3650,
    skew_seconds: int = 300,
) -> int:
    """For each anchor, recompute the expected row_hash at the anchor's
    chain_seq and cross-check against the anchor's claim + TSA token.

    For RFC 3161 anchors the TSA token's CMS signature is verified
    against ``trust_store_path`` (a PEM bundle of TSA root certs).
    Without a trust store the verifier fails closed (exit 5) on
    RFC 3161 anchors unless ``allow_unverified_signature`` is set —
    in that mode the anchor is downgraded to the F-A-405 pre-fix
    behaviour and a warning is emitted.

    Returns count of verified anchors. Exits 3 on mismatch, 5 on
    unverifiable token."""
    # Map (org_id, chain_seq) -> entry.entry_hash for quick lookup.
    head_hash: dict[tuple[str, int], str] = {}
    for e in entries:
        seq = e.get("chain_seq")
        if seq is not None:
            head_hash[(e.get("org_id") or "", seq)] = e["entry_hash"]

    verified = 0
    for a in anchors:
        key = (a["org_id"], a["chain_seq"])
        actual_head = head_hash.get(key)
        if actual_head is None:
            print(f"ANCHOR ORPHAN org={a['org_id']} seq={a['chain_seq']} — "
                  f"no matching chain entry in bundle")
            sys.exit(3)
        if actual_head != a["row_hash"]:
            print(f"ANCHOR MISMATCH org={a['org_id']} seq={a['chain_seq']}: "
                  f"anchor row_hash={a['row_hash']} but chain head={actual_head}")
            sys.exit(3)
        token = base64.b64decode(a["tsa_token_b64"])
        # The Mastio TSA client sends sha256(row_hash.encode("ascii"))
        # as the messageImprint. Recompute that digest so the verifier
        # can match the TST's imprint without trusting the anchor's
        # claim.
        digest_hex = hashlib.sha256(a["row_hash"].encode("ascii")).hexdigest()
        ok, backend = verify_token_against_digest(
            token,
            digest_hex,
            row_hash=a["row_hash"],
            trust_store_path=trust_store_path,
            allow_unverified_signature=allow_unverified_signature,
            max_age_days=max_age_days,
            skew_seconds=skew_seconds,
        )
        if not ok:
            if backend in (
                "rfc3161-lib-missing",
                "rfc3161-unverified",
                "rfc3161-no-trust-store",
                "rfc3161-trust-store-bad",
            ):
                print(f"ANCHOR UNVERIFIABLE org={a['org_id']} seq={a['chain_seq']}: "
                      f"TSA backend {backend} "
                      f"(pass --tsa-trust-store with a PEM bundle of TSA roots, "
                      f"or --tsa-allow-unverified-signature to downgrade)")
                sys.exit(5)
            print(f"ANCHOR INVALID org={a['org_id']} seq={a['chain_seq']}: "
                  f"token backend={backend} failed verification")
            sys.exit(3)
        verified += 1
    return verified


def cross_reconcile(bundles: list[tuple[str, list[dict]]]) -> int:
    """When two bundles are provided, check every row in bundle A that
    declares peer_org_id matching bundle B's org has a counterpart in
    B with the same peer_row_hash linkage. Returns count of cross-
    verified rows. Exits 4 on mismatch."""
    if len(bundles) < 2:
        return 0

    # Index entries by (org_id, entry_hash) for reverse lookup.
    by_hash: dict[tuple[str, str], dict] = {}
    for _path, entries in bundles:
        for e in entries:
            if e.get("entry_hash") and e.get("org_id"):
                by_hash[(e["org_id"], e["entry_hash"])] = e

    verified = 0
    for _path, entries in bundles:
        for e in entries:
            peer_org = e.get("peer_org_id")
            peer_hash = e.get("peer_row_hash")
            if not peer_org or not peer_hash:
                continue
            counterpart = by_hash.get((peer_org, peer_hash))
            if counterpart is None:
                print(f"CROSS-REF MISSING id={e['id']} org={e['org_id']}: "
                      f"peer_row {peer_hash} on org {peer_org} not in bundles")
                sys.exit(4)
            # Content agreement
            for field in ("event_type", "result", "session_id", "details"):
                if e.get(field) != counterpart.get(field):
                    print(f"CROSS-REF DISAGREE id={e['id']} vs id={counterpart['id']}: "
                          f"field={field} diverges "
                          f"({e.get(field)!r} != {counterpart.get(field)!r})")
                    sys.exit(4)
            verified += 1
    return verified


# ── Merkle inclusion proof (ADR-037 Phase 3, offline path) ──────────
#
# The Mastio's /v1/admin/audit/merkle/proof/{chain_seq} endpoint
# returns a JSON object with the shape:
#
#   {"anchor_id": int,
#    "chain_seq": int,
#    "chain_seq_start": int, "chain_seq_end": int, "leaf_count": int,
#    "merkle_root": "<64 hex chars>",
#    "leaf_hex": "<64 hex chars>",
#    "proof": [{"sibling_hex": "<64 hex chars>", "position": "L"|"R"},
#              ...]}
#
# An auditor with a bundle export + one or more such proof files can
# replay this verifier offline (no Mastio access) and assert that the
# row at ``chain_seq`` was included in the anchored Merkle root. The
# math is inlined here so the CLI stays a single-file self-contained
# script — the same math lives in ``mcp_proxy.audit.merkle`` for the
# in-process path.


def _merkle_verify_inclusion(
    leaf: bytes, proof: list[tuple[bytes, str]], expected_root: bytes,
) -> bool:
    """Reconstruct the root from leaf + proof and compare to
    ``expected_root``. Never raises on malformed input: returns False.
    Mirrors ``mcp_proxy.audit.merkle.verify_inclusion`` byte-for-byte.
    """
    if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
        return False
    if not isinstance(expected_root, (bytes, bytearray)) or len(expected_root) != 32:
        return False
    current = bytes(leaf)
    for step in proof:
        if not isinstance(step, tuple) or len(step) != 2:
            return False
        sibling, position = step
        if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != 32:
            return False
        if position == "L":
            current = hashlib.sha256(bytes(sibling) + current).digest()
        elif position == "R":
            current = hashlib.sha256(current + bytes(sibling)).digest()
        else:
            return False
    return current == expected_root


def verify_merkle_proofs(
    proof_paths: list[str],
    bundles: list[tuple[str, list[dict]]],
) -> int:
    """Verify each inclusion proof JSON against the bundle entries.

    For every proof file the verifier:
      1. Loads the JSON and validates shape
      2. Finds the matching ``chain_seq`` entry in the loaded bundles
      3. Asserts the bundle's row_hash (or entry_hash legacy field)
         equals the proof's ``leaf_hex``
      4. Replays ``_merkle_verify_inclusion`` against the proof's root

    Exit code 6 on any failure mode (no matching entry, leaf
    disagreement, math fails). Distinct from chain (2) / anchor (3,5)
    / cross (4) exit codes so an operator can wire the Merkle path
    into a separate alarm without polluting the existing forensic
    classifiers.

    Returns the count of proofs verified successfully.
    """
    if not proof_paths:
        return 0

    # Flatten bundle entries into a single chain_seq → entry lookup.
    by_seq: dict[int, dict] = {}
    for _path, entries in bundles:
        for e in entries:
            seq = e.get("chain_seq")
            if seq is None:
                continue
            try:
                by_seq[int(seq)] = e
            except (TypeError, ValueError):
                continue

    verified = 0
    for path in proof_paths:
        try:
            with open(path) as f:
                proof = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"MERKLE PROOF UNREADABLE path={path}: {exc}")
            sys.exit(6)

        try:
            chain_seq = int(proof["chain_seq"])
            leaf_hex = str(proof["leaf_hex"])
            root_hex = str(proof["merkle_root"])
            steps = proof["proof"]
            if not isinstance(steps, list):
                raise TypeError("proof.proof must be a list")
        except (KeyError, TypeError, ValueError) as exc:
            print(f"MERKLE PROOF MALFORMED path={path}: {exc}")
            sys.exit(6)

        entry = by_seq.get(chain_seq)
        if entry is None:
            print(
                f"MERKLE PROOF UNMATCHED chain_seq={chain_seq}: "
                f"no entry with that chain_seq in the loaded bundle(s) "
                f"(path={path})"
            )
            sys.exit(6)

        # Mastio bundles carry row_hash; legacy Court bundles may
        # carry entry_hash. Accept either as long as it matches the
        # proof's leaf_hex.
        bundle_leaf = entry.get("row_hash") or entry.get("entry_hash")
        if bundle_leaf is None:
            print(
                f"MERKLE PROOF UNMATCHED chain_seq={chain_seq}: "
                f"bundle entry has no row_hash/entry_hash field"
            )
            sys.exit(6)
        if str(bundle_leaf) != leaf_hex:
            print(
                f"MERKLE PROOF LEAF MISMATCH chain_seq={chain_seq}: "
                f"bundle row_hash={bundle_leaf[:16]}... but proof "
                f"leaf_hex={leaf_hex[:16]}... — either the proof was "
                f"computed against a different audit_log or the bundle "
                f"row has been tampered"
            )
            sys.exit(6)

        try:
            leaf_bytes = bytes.fromhex(leaf_hex)
            root_bytes = bytes.fromhex(root_hex)
            proof_steps = [
                (bytes.fromhex(str(s["sibling_hex"])), str(s["position"]))
                for s in steps
            ]
        except (KeyError, TypeError, ValueError) as exc:
            print(f"MERKLE PROOF MALFORMED hex content: {exc}")
            sys.exit(6)

        if not _merkle_verify_inclusion(leaf_bytes, proof_steps, root_bytes):
            print(
                f"MERKLE PROOF FAIL chain_seq={chain_seq}: the proof "
                f"reconstructed root does NOT match the anchored root "
                f"{root_hex[:16]}... — either the proof, the leaf, or "
                f"the anchored root has been tampered"
            )
            sys.exit(6)

        verified += 1

    return verified


# ── Enterprise archive verification (audit_archive plugin) ──────────
#
# Operators on the Enterprise edition run the ``audit_archive`` plugin
# (cullis-security/cullis-enterprise) which exports the per-epoch
# audit chain to a WORM-sealed sink (S3 Object Lock COMPLIANCE, file://,
# Azure Blob immutable on roadmap), computes an RFC 6962 Merkle root
# over the row_hash leaves, and signs the root with the active Mastio
# ES256 identity key as a Signed Tree Head (STH).
#
# An auditor receiving the NDJSON bundle + STH JSON + inclusion proof
# JSON + the Mastio's ES256 public key can verify the whole envelope
# offline with this CLI — no Mastio access, no Cullis vendor trust.
# That is the open-core line: the WORM sink + STH generation are
# Enterprise (per-deployment integration), the math + the verifier
# are public so the auditor's check is vendor-independent.
#
# Three artefact shapes (matching the audit_archive plugin output):
#
#   STH JSON (per epoch):
#     {"epoch_utc": "2026-05-24T00:00:00Z",
#      "mastio_org_id": "acme",
#      "tree_size": 1234,
#      "root_hash_hex": "<64 hex>",
#      "chain_seq_lo": 1, "chain_seq_hi": 1234,
#      "signature_b64u": "<base64url ECDSA sig over canonical JSON>",
#      "mastio_kid": "mastio-<id>",
#      "signed_at": "<RFC 3339>"}
#
#   Inclusion proof JSON (per row):
#     {"epoch_utc": "...",
#      "leaf_index": 567,
#      "leaf_hash_hex": "<64 hex>",
#      "audit_path": ["<64 hex>", ...],     # RFC 6962 sibling list, no positions
#      "sth": { ... STH inlined for self-contained verify ... }}
#
#   Manifest JSON (per bundle export):
#     {"epoch_utc": "...",
#      "chain_seq_lo": 1, "chain_seq_hi": 1234, "row_count": 1234,
#      "sink_url": "s3://.../audit-2026-05-24.ndjson.zst",
#      "bundle_sha256": "<64 hex>",
#      "signature_b64u": "<base64url ECDSA sig over canonical JSON>"}
#
# The math is inlined here so the CLI stays a single-file
# self-contained tool, but it follows RFC 6962 §2.1 byte-for-byte
# (leaf prefix 0x00, internal prefix 0x01) so a third-party CT
# library would compute the same root.


_RFC6962_LEAF_PREFIX = b"\x00"
_RFC6962_NODE_PREFIX = b"\x01"


def _rfc6962_leaf_hash(row_hash_hex: str) -> bytes:
    """RFC 6962 §2.1: leaf hash = sha256(0x00 || raw_leaf_bytes).

    The Mastio's row_hash is already a SHA-256 hex digest, but RFC 6962
    treats THAT as the leaf content; we prepend the leaf prefix and
    rehash, matching what the audit_archive STH builder does
    server-side.
    """
    raw = bytes.fromhex(row_hash_hex)
    return hashlib.sha256(_RFC6962_LEAF_PREFIX + raw).digest()


def _rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: internal node = sha256(0x01 || left || right)."""
    return hashlib.sha256(_RFC6962_NODE_PREFIX + left + right).digest()


def _rfc6962_verify_audit_path(
    leaf_hash: bytes,
    audit_path: list[str],
    leaf_index: int,
    tree_size: int,
    expected_root: bytes,
) -> bool:
    """Verify an RFC 6962 audit path under the "promote unpaired"
    construction used by the audit_archive plugin.

    The plugin builds the tree with ``compute_merkle_root``:
    pairwise hashing within each layer, trailing unpaired nodes are
    PROMOTED to the next layer unchanged (not duplicated). The
    matching ``compute_inclusion_proof`` emits an empty string in
    ``audit_path`` at each level where the current node was promoted
    unpaired — the verifier MUST skip the sibling combination at
    that level and only advance the index.

    Position at each level is the LSB of the index folded one bit
    per step. The audit_path therefore carries no L/R marker, only
    siblings (or '' for promote-skip).
    """
    if not 0 <= leaf_index < tree_size:
        return False
    if len(leaf_hash) != 32 or len(expected_root) != 32:
        return False

    h = leaf_hash
    idx = leaf_index
    for sibling_hex in audit_path:
        if sibling_hex == "":
            # Promoted unpaired at this level — h passes through.
            idx >>= 1
            continue
        if not isinstance(sibling_hex, str):
            return False
        try:
            sibling = bytes.fromhex(sibling_hex)
        except (TypeError, ValueError):
            return False
        if len(sibling) != 32:
            return False
        if idx & 1:
            # Current node sits on the right of its parent.
            h = _rfc6962_node_hash(sibling, h)
        else:
            h = _rfc6962_node_hash(h, sibling)
        idx >>= 1
    return h == expected_root


def _canonical_json(obj: dict) -> bytes:
    """Canonical JSON encoding for signing/verification.

    sorted keys, no whitespace, ensure_ascii=True. Bytes returned ready
    for ECDSA sign/verify input. Matches what the audit_archive plugin
    feeds into ``AgentManager.countersign`` server-side.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def _verify_es256_signature(
    payload: bytes,
    signature_b64u: str,
    pubkey_pem_bytes: bytes,
) -> bool:
    """Verify a JOSE ES256 signature (ECDSA P-256 + SHA-256) over
    ``payload`` against a PEM-encoded EC public key.

    ``signature_b64u`` is the JOSE flat encoding: base64url(r || s)
    where r and s are each 32 bytes big-endian (RFC 7515 §3.4 / RFC
    7518 §3.4 ``ES256``). We convert to the DER form ``cryptography``
    expects before calling ``verify``.

    Returns False on any malformed input or signature mismatch.
    Never raises — the offline verifier path must stay robust against
    adversarial bundle content.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )
    except ImportError:
        return False

    try:
        pad = "=" * (-len(signature_b64u) % 4)
        raw_sig = base64.urlsafe_b64decode(signature_b64u + pad)
        if len(raw_sig) != 64:
            return False
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        pubkey = serialization.load_pem_public_key(pubkey_pem_bytes)
        if not isinstance(pubkey, ec.EllipticCurvePublicKey):
            return False
        if not isinstance(pubkey.curve, ec.SECP256R1):
            return False
        pubkey.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001 — adversarial input must not crash CLI
        return False


def _sth_canonical_payload(sth: dict) -> bytes:
    """The exact field set the audit_archive plugin signs over.

    Order is documented in the patch: mastio_org_id, epoch_utc,
    tree_size, root_hash_hex, chain_seq_lo, chain_seq_hi, mastio_kid,
    issued_at. ``signature_b64u`` is NOT in the signed payload (it
    IS the signature). ``signed_at`` is also outside the canonical
    payload to match the server-side signer.
    """
    fields = {
        "mastio_org_id": sth["mastio_org_id"],
        "epoch_utc": sth["epoch_utc"],
        "tree_size": int(sth["tree_size"]),
        "root_hash_hex": sth["root_hash_hex"],
        "chain_seq_lo": int(sth["chain_seq_lo"]),
        "chain_seq_hi": int(sth["chain_seq_hi"]),
        "mastio_kid": sth["mastio_kid"],
        "issued_at": sth["signed_at"],
    }
    return _canonical_json(fields)


def _manifest_canonical_payload(manifest: dict) -> bytes:
    """Canonical payload the audit_archive plugin signs for each
    bundle manifest. Fields: epoch_utc, mastio_org_id, chain_seq_lo,
    chain_seq_hi, row_count, sink_url, bundle_sha256.
    """
    fields = {
        "epoch_utc": manifest["epoch_utc"],
        "mastio_org_id": manifest.get("mastio_org_id", ""),
        "chain_seq_lo": int(manifest["chain_seq_lo"]),
        "chain_seq_hi": int(manifest["chain_seq_hi"]),
        "row_count": int(manifest["row_count"]),
        "sink_url": manifest["sink_url"],
        "bundle_sha256": manifest["bundle_sha256"],
    }
    return _canonical_json(fields)


def verify_archive_proofs(
    sth_paths: list[str],
    proof_paths: list[str],
    manifest_paths: list[str],
    pubkey_pem_path: str | None,
    bundles: list[tuple[str, list[dict]]],
) -> tuple[int, int, int]:
    """Verify Enterprise audit_archive artefacts: STH signatures,
    bundle manifests, and per-row inclusion proofs against the
    Mastio's ES256 public key.

    Returns ``(sth_verified, manifest_verified, proof_verified)``.
    Exits 7 on any failure mode so an operator can wire archive
    verification into a distinct alarm vs chain (2) / anchor (3,5) /
    cross-ref (4) / Merkle proof (6).

    All three artefact families share the same pubkey: the auditor
    obtains it out of band (the Mastio's ``/v1/admin/mastio-pubkey``
    endpoint, or a customer-handover PEM). Trust path is "the
    auditor trusted this pubkey was the Mastio's at archive time",
    not "trust whatever kid is in the JSON".
    """
    if not (sth_paths or proof_paths or manifest_paths):
        return 0, 0, 0

    if pubkey_pem_path is None:
        print(
            "ARCHIVE VERIFY: --archive-manifest-pubkey is required when "
            "--archive-sth / --archive-proof / --archive-manifest is set"
        )
        sys.exit(7)

    try:
        with open(pubkey_pem_path, "rb") as f:
            pubkey_pem = f.read()
    except OSError as exc:
        print(f"ARCHIVE PUBKEY UNREADABLE path={pubkey_pem_path}: {exc}")
        sys.exit(7)

    # ── 1. STH JSONs ────────────────────────────────────────────────
    sth_verified = 0
    sth_by_epoch: dict[str, dict] = {}
    for path in sth_paths:
        sth = _load_json_file(path, "ARCHIVE STH")
        try:
            payload = _sth_canonical_payload(sth)
            sig = sth["signature_b64u"]
        except KeyError as exc:
            print(f"ARCHIVE STH MALFORMED path={path}: missing {exc}")
            sys.exit(7)
        if not _verify_es256_signature(payload, sig, pubkey_pem):
            print(
                f"ARCHIVE STH SIGNATURE INVALID path={path} "
                f"epoch={sth.get('epoch_utc', '?')}"
            )
            sys.exit(7)
        sth_by_epoch[str(sth["epoch_utc"])] = sth
        sth_verified += 1

    # ── 2. Manifests ────────────────────────────────────────────────
    manifest_verified = 0
    for path in manifest_paths:
        manifest = _load_json_file(path, "ARCHIVE MANIFEST")
        try:
            payload = _manifest_canonical_payload(manifest)
            sig = manifest["signature_b64u"]
        except KeyError as exc:
            print(f"ARCHIVE MANIFEST MALFORMED path={path}: missing {exc}")
            sys.exit(7)
        if not _verify_es256_signature(payload, sig, pubkey_pem):
            print(
                f"ARCHIVE MANIFEST SIGNATURE INVALID path={path} "
                f"epoch={manifest.get('epoch_utc', '?')}"
            )
            sys.exit(7)
        manifest_verified += 1

    # ── 3. Inclusion proofs ─────────────────────────────────────────
    # Each proof has its STH inlined (self-contained verify). We
    # re-verify the embedded STH signature even if the same epoch was
    # already verified standalone — the inlined STH could disagree
    # with the standalone one and that disagreement is the signal an
    # operator needs to see.
    proof_verified = 0
    by_chain_seq: dict[int, dict] = {}
    for _path, entries in bundles:
        for e in entries:
            seq = e.get("chain_seq")
            if seq is None:
                continue
            try:
                by_chain_seq[int(seq)] = e
            except (TypeError, ValueError):
                continue

    for path in proof_paths:
        proof = _load_json_file(path, "ARCHIVE PROOF")
        try:
            inlined_sth = proof["sth"]
            leaf_index = int(proof["leaf_index"])
            leaf_hash_hex = str(proof["leaf_hash_hex"])
            audit_path_hex = list(proof["audit_path"])
        except (KeyError, TypeError, ValueError) as exc:
            print(f"ARCHIVE PROOF MALFORMED path={path}: {exc}")
            sys.exit(7)

        sth_payload = _sth_canonical_payload(inlined_sth)
        if not _verify_es256_signature(
            sth_payload, inlined_sth["signature_b64u"], pubkey_pem,
        ):
            print(
                f"ARCHIVE PROOF STH-SIGNATURE INVALID path={path} "
                f"epoch={inlined_sth.get('epoch_utc', '?')}"
            )
            sys.exit(7)

        try:
            leaf_hash = bytes.fromhex(leaf_hash_hex)
            root = bytes.fromhex(inlined_sth["root_hash_hex"])
            tree_size = int(inlined_sth["tree_size"])
            chain_seq_lo = int(inlined_sth["chain_seq_lo"])
            # audit_path_hex stays as list[str] — entries may be ""
            # to signal a promoted-unpaired level (skip sibling combine).
        except (KeyError, TypeError, ValueError) as exc:
            print(f"ARCHIVE PROOF hex parse error: {exc}")
            sys.exit(7)

        if not _rfc6962_verify_audit_path(
            leaf_hash, audit_path_hex, leaf_index, tree_size, root,
        ):
            print(
                f"ARCHIVE PROOF INCLUSION FAIL path={path} "
                f"leaf_index={leaf_index} epoch={inlined_sth.get('epoch_utc', '?')}"
            )
            sys.exit(7)

        # Cross-check against the bundle: bundle row at
        # chain_seq = chain_seq_lo + leaf_index must have row_hash
        # whose RFC 6962 leaf hash equals the proof's leaf_hash.
        bundle_chain_seq = chain_seq_lo + leaf_index
        entry = by_chain_seq.get(bundle_chain_seq)
        if entry is not None:
            bundle_row_hash = entry.get("row_hash") or entry.get("entry_hash")
            if bundle_row_hash is not None:
                computed = _rfc6962_leaf_hash(str(bundle_row_hash))
                if computed != leaf_hash:
                    print(
                        f"ARCHIVE PROOF BUNDLE MISMATCH path={path} "
                        f"chain_seq={bundle_chain_seq}: bundle row_hash "
                        f"leaf-hash != proof leaf_hash_hex — bundle and "
                        f"proof disagree on the same row"
                    )
                    sys.exit(7)
        proof_verified += 1

    return sth_verified, manifest_verified, proof_verified


def _load_json_file(path: str, label: str) -> dict:
    try:
        with open(path) as f:
            obj = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{label} UNREADABLE path={path}: {exc}")
        sys.exit(7)
    if not isinstance(obj, dict):
        print(f"{label} not a JSON object: path={path}")
        sys.exit(7)
    return obj


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--bundle", action="append", required=True,
        help="Path to an audit export NDJSON file. Pass twice for cross-verify.",
    )
    ap.add_argument(
        "--tsa-trust-store",
        default=None,
        help=(
            "PEM bundle of trusted RFC 3161 TSA root certificates. "
            "Required for dispute-grade RFC 3161 anchor verification — "
            "the CMS signature on each TimeStampToken is checked against "
            "this trust store, the chain walked from the embedded signer "
            "leaf to one of these roots, and the signer cert's "
            "id-kp-timeStamping extKeyUsage is enforced. Without this "
            "flag the verifier refuses RFC 3161 anchors (exit 5) unless "
            "--tsa-allow-unverified-signature is set."
        ),
    )
    ap.add_argument(
        "--tsa-allow-unverified-signature",
        action="store_true",
        help=(
            "Downgrade RFC 3161 anchor verification to the pre-F-A-405 "
            "behaviour: messageImprint + EKU check only, no signature "
            "or chain check. The anchor is no longer dispute-grade — "
            "an attacker who knows the row_hash can fabricate a passing "
            "token. Use only when the trust store is genuinely "
            "unavailable to the verifying party. When the flag is in "
            "effect the verifier emits a WARNING line to stderr (not "
            "stdout) for each token whose signature was downgraded; "
            "operators piping stdout for machine-readable status must "
            "also capture stderr to see the downgrade signal."
        ),
    )
    ap.add_argument(
        "--tsa-max-age-days",
        type=int,
        default=3650,
        help=(
            "Reject TSA tokens whose genTime is older than this. Anchors "
            "are forensic and long-lived; the default 10 years catches "
            "obviously fabricated genTime values without flagging real "
            "historical exports. (default: 3650)"
        ),
    )
    ap.add_argument(
        "--tsa-skew-seconds",
        type=int,
        default=300,
        help=(
            "Tolerate TSA genTime values ahead of the verifier's wall "
            "clock by this many seconds before flagging them as future-"
            "dated. (default: 300)"
        ),
    )
    ap.add_argument(
        "--merkle-proof", action="append", default=[],
        metavar="PROOF_JSON",
        help=(
            "Path to a Merkle inclusion proof JSON file emitted by "
            "GET /v1/admin/audit/merkle/proof/{chain_seq} (ADR-037 "
            "Phase 2). For every file, the verifier asserts (a) the "
            "matching chain_seq entry exists in the loaded bundle(s), "
            "(b) its row_hash equals the proof's leaf_hex, and "
            "(c) the reconstructed Merkle root matches the proof's "
            "anchored root. Pass the flag multiple times to verify a "
            "batch of proofs in one run. Exit code 6 on any failure."
        ),
    )
    ap.add_argument(
        "--archive-sth", action="append", default=[],
        metavar="STH_JSON",
        help=(
            "Path to a Signed Tree Head JSON emitted by the Enterprise "
            "audit_archive plugin (GET /v1/admin/audit/sth/{epoch} or "
            "/sth/latest). The CLI verifies the ES256 signature over "
            "the canonical STH fields against --archive-manifest-pubkey. "
            "Pass multiple times to batch-verify a window of epochs."
        ),
    )
    ap.add_argument(
        "--archive-proof", action="append", default=[],
        metavar="PROOF_JSON",
        help=(
            "Path to an RFC 6962 inclusion proof JSON emitted by "
            "GET /v1/admin/audit/proof?chain_seq=N (Enterprise "
            "audit_archive plugin). Each proof carries its STH "
            "inlined; the CLI re-verifies the STH ES256 signature, "
            "walks the RFC 6962 audit_path bottom-up against the "
            "anchored root, and (when the bundle is loaded) confirms "
            "the proof's leaf_hash matches sha256(0x00 || row_hash) "
            "of the corresponding chain_seq entry. Exit code 7."
        ),
    )
    ap.add_argument(
        "--archive-manifest", action="append", default=[],
        metavar="MANIFEST_JSON",
        help=(
            "Path to a per-epoch bundle manifest JSON. The CLI verifies "
            "the ES256 signature over the manifest's canonical payload "
            "(epoch, range, row_count, sink_url, bundle_sha256) against "
            "--archive-manifest-pubkey, proving the operator's named "
            "bundle URL was authoritatively sealed by the Mastio at "
            "archive time."
        ),
    )
    ap.add_argument(
        "--archive-manifest-pubkey",
        default=None,
        metavar="PEM",
        help=(
            "Path to the Mastio's ES256 public key in PEM format. "
            "Required when any --archive-sth, --archive-proof, or "
            "--archive-manifest is set. The auditor obtains this "
            "pubkey out of band (the Mastio's /v1/admin/mastio-pubkey "
            "endpoint, or a customer handover); trust is anchored on "
            "having received this pubkey from a trusted channel, not "
            "on the kid metadata inside the JSONs."
        ),
    )
    args = ap.parse_args()

    bundles: list[tuple[str, list[dict]]] = []
    total_legacy = total_per_org = total_anchors = 0
    total_entries = 0
    total_orgs: set[str] = set()
    total_agents: set[str] = set()
    for path in args.bundle:
        entries, anchors = load_bundle(path)
        legacy_n, per_org_n, _agent_n = verify_chains(entries)
        anchor_n = verify_anchors(
            entries,
            anchors,
            trust_store_path=args.tsa_trust_store,
            allow_unverified_signature=args.tsa_allow_unverified_signature,
            max_age_days=args.tsa_max_age_days,
            skew_seconds=args.tsa_skew_seconds,
        )
        total_legacy += legacy_n
        total_per_org += per_org_n
        total_anchors += anchor_n
        total_entries += len(entries)
        for e in entries:
            if e.get("org_id"):
                total_orgs.add(e["org_id"])
            if e.get("agent_id"):
                total_agents.add(e["agent_id"])
        bundles.append((path, entries))

    cross_n = cross_reconcile(bundles)
    merkle_n = verify_merkle_proofs(args.merkle_proof, bundles)
    sth_n, manifest_n, archive_proof_n = verify_archive_proofs(
        args.archive_sth,
        args.archive_proof,
        args.archive_manifest,
        args.archive_manifest_pubkey,
        bundles,
    )

    # CISO-readable PASS summary. The line breaks below are deliberate
    # so the auditor's terminal output reads like a verdict, not a CSV.
    print("")
    print("✓ CHAIN VERIFIED")
    print("")
    print(
        f"  {total_entries} entries · "
        f"{len(total_agents)} agent{'s' if len(total_agents) != 1 else ''} · "
        f"{len(total_orgs)} org{'s' if len(total_orgs) != 1 else ''} · "
        f"{total_legacy} legacy · {total_per_org} per-org · "
        f"{total_anchors} TSA anchor{'s' if total_anchors != 1 else ''}"
    )
    if cross_n:
        print(f"  {cross_n} cross-org peer row{'s' if cross_n != 1 else ''} reconciled")
    if merkle_n:
        print(f"  {merkle_n} Merkle inclusion proof{'s' if merkle_n != 1 else ''} verified")
    if sth_n or manifest_n or archive_proof_n:
        parts: list[str] = []
        if sth_n:
            parts.append(f"{sth_n} STH{'s' if sth_n != 1 else ''}")
        if manifest_n:
            parts.append(
                f"{manifest_n} bundle manifest{'s' if manifest_n != 1 else ''}"
            )
        if archive_proof_n:
            parts.append(
                f"{archive_proof_n} archive inclusion proof"
                f"{'s' if archive_proof_n != 1 else ''}"
            )
        print(f"  {' · '.join(parts)} verified against the Mastio pubkey")
    print("")
    print("  Every entry_hash matches the SHA-256 of its canonical row.")
    print("  No previous_hash → next entry_hash break detected.")
    print("")
    print("  Bundle is intact end-to-end. No row was added, altered, or")
    print("  removed after the original audit chain was written.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
