"""RFC 3161 TSA client — anchor the audit chain to an external timestamp.

The Mastio sends a TimeStampReq over HTTP to a public TSA (default
``http://timestamp.digicert.com``, configurable via
``MCP_PROXY_AUDIT_ANCHOR_TSA_URL``); the TSA responds with a
TimeStampResp containing a CMS-wrapped TimeStampToken signed under
the TSA's own X.509 cert chain. The Mastio persists the token
verbatim under :class:`AuditChainAnchor.tsa_token` (prefixed with the
``T1|`` magic ``cullis-audit-verify.py`` already understands).

Why an external TSA at all: the in-tree audit chain is hash-chained
(SHA-256, forward integrity per F-A-402 / F-A-403), but the chain is
self-asserted. An operator who tampered with the database could
recompute every ``row_hash`` and pass ``verify_audit_chain`` — the
chain proves consistency, not provenance. The TSA's signature
provides provenance: "at GenTime ``t``, the chain head's ``row_hash``
was ``h``", witnessed by a third party the operator does not
control. A forgery requires compromising the TSA's signing key as
well as the Mastio's database, which raises the cost of an
end-to-end tamper attack from "DB write access" to "DB write +
public CA compromise".

This module is HTTP-only and uses ``httpx`` (already a runtime dep);
the TimeStampReq construction + TimeStampResp parsing live in
``rfc3161-client`` (added under ``mcp_proxy/requirements-proxy.txt``).
Both calls are synchronous; the lifespan watcher bridges to async via
``asyncio.to_thread`` so the event loop never blocks on the TSA RTT.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Final

import httpx

_log = logging.getLogger("mcp_proxy.audit.tsa_client")


# Free public RFC 3161 TSA. Stable, widely used (cosign, sigstore,
# many CA timestamping toolchains). Operators can override via env
# (``MCP_PROXY_AUDIT_ANCHOR_TSA_URL``) to use a CA they already
# trust on their PKI floor.
DEFAULT_TSA_URL: Final = "http://timestamp.digicert.com"


# ``T1|`` magic prefix so the offline verifier
# (``cullis-audit-verify.py``) can route the token to the
# ``rfc3161-client``/``asn1crypto`` decoder. The verifier already
# implements this branch (added with the standalone-verifier
# scaffolding); the magic prefix has never been written to a real DB
# row before — this client is the first producer.
RFC3161_TOKEN_PREFIX: Final = b"T1|"


# RFC 3161 application/timestamp-{query,reply} content types.
_REQ_CONTENT_TYPE: Final = "application/timestamp-query"
_REPLY_CONTENT_TYPE: Final = "application/timestamp-reply"


class TSAAnchorError(RuntimeError):
    """Raised when the TSA refuses, the HTTP call fails, or the
    returned token does not bind to the digest we sent."""


@dataclass(frozen=True)
class AnchorResult:
    """Output of :func:`anchor_row_hash`.

    ``token_bytes`` is the raw RFC 3161 TimeStampToken with the
    ``T1|`` magic prefix the offline verifier consumes. Persist
    verbatim to :class:`AuditChainAnchor.tsa_token`.
    """
    digest_hex: str  # sha256 hex of the input row_hash (the messageImprint)
    tsa_url: str
    token_bytes: bytes


def anchor_row_hash(
    row_hash: str,
    *,
    tsa_url: str = DEFAULT_TSA_URL,
    timeout_seconds: float = 10.0,
) -> AnchorResult:
    """Synchronously fetch a TimeStampToken binding to ``sha256(row_hash)``.

    Args:
        row_hash: the chain head's ``row_hash`` (a hex SHA-256 already).
            We re-hash it under SHA-256 again so the imprint sent to
            the TSA is a fixed-width 32-byte digest the TSA expects
            (RFC 3161 §2.4.1). The verifier reconstructs the same
            ``sha256(row_hash_hex_string)`` to match the imprint.
        tsa_url: HTTP(S) URL of the TSA. Default ``timestamp.digicert.com``.
        timeout_seconds: total HTTP request timeout. Short on purpose:
            anchoring is fire-and-forget from the lifespan watcher's
            perspective, and a wedged TSA must not stall the watcher
            past the next tick.

    Returns:
        :class:`AnchorResult` with the prefixed token bytes ready to
        persist.

    Raises:
        TSAAnchorError: HTTP failure, TSA refusal, malformed response,
            or imprint mismatch (defence-in-depth — we re-check the
            response's messageImprint against ours before trusting
            the token).
    """
    # Lazy import so the audit module loads on operator hosts that
    # never enable anchoring. The library is small but cffi-backed.
    try:
        from rfc3161_client import (  # type: ignore[import-not-found]
            HashAlgorithm,
            TimestampRequestBuilder,
        )
    except ImportError as exc:
        raise TSAAnchorError(
            "rfc3161-client is not installed — cannot anchor the audit "
            "chain. Add ``rfc3161-client`` to the Mastio image.",
        ) from exc

    # ``data`` here is the message that the rfc3161-client library
    # will hash internally with the algorithm we pass. The resulting
    # messageImprint inside the TimeStampReq is sha256 of the
    # row_hash hex string. The verifier reproduces the same imprint
    # by hashing the NDJSON ``row_hash`` field under sha256. Compute
    # it locally too so we can assert the response binds to it.
    message = row_hash.encode("ascii")
    digest = hashlib.sha256(message).digest()
    digest_hex = digest.hex()

    builder = TimestampRequestBuilder()
    builder = builder.data(message).hash_algorithm(HashAlgorithm.SHA256)
    # cert_request=True asks the TSA to embed its signing cert chain
    # in the response, which is how the offline verifier walks the
    # TSA's PKI without an out-of-band fetch.
    builder = builder.cert_request(cert_request=True)
    req = builder.build()
    req_der = req.as_bytes()

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.post(
                tsa_url,
                content=req_der,
                headers={"Content-Type": _REQ_CONTENT_TYPE},
            )
    except httpx.HTTPError as exc:
        raise TSAAnchorError(
            f"TSA HTTP request failed: {exc}",
        ) from exc

    if resp.status_code != 200:
        raise TSAAnchorError(
            f"TSA returned HTTP {resp.status_code}: "
            f"{resp.text[:200] if resp.text else '<empty>'}",
        )

    # Some TSAs misreport the content-type; tolerate variants but log.
    ct = resp.headers.get("content-type", "")
    if _REPLY_CONTENT_TYPE not in ct:
        _log.info(
            "tsa: unexpected content-type %r from %s (continuing — body "
            "parsing is the real check)", ct, tsa_url,
        )

    # Parse the response with ``asn1crypto`` rather than the strict
    # parser inside ``rfc3161-client``. Real-world TSAs (DigiCert
    # specifically) sometimes emit a ``SignedData.certificates`` SET
    # whose elements are not in canonical DER ordering — strictly
    # this violates DER, but it is widespread enough that every
    # production timestamp verifier (cosign, OpenSSL ``ts -verify``,
    # commercial PKI suites) accepts it. ``asn1crypto`` is lenient.
    try:
        from asn1crypto import tsp as _asn1_tsp  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TSAAnchorError(
            "asn1crypto is not installed — required to parse TSA "
            "responses. Add ``asn1crypto`` to the Mastio image.",
        ) from exc

    try:
        tsr = _asn1_tsp.TimeStampResp.load(resp.content)
    except Exception as exc:  # noqa: BLE001
        raise TSAAnchorError(
            f"TSA response is not a valid TimeStampResp: {exc}",
        ) from exc

    # RFC 3161 §2.4.2 — status MUST be ``granted`` (0) or
    # ``granted_with_mods`` (1) for the token to be usable.
    # asn1crypto exposes the enum as its string label.
    status_label = tsr["status"]["status"].native
    if status_label not in ("granted", "granted_with_mods"):
        status_str = tsr["status"]["status_string"].native or "<no string>"
        raise TSAAnchorError(
            f"TSA refused: PKIStatus={status_label!r} ({status_str})",
        )

    # The signed TimeStampToken is a ContentInfo with type ``signed_data``.
    # ``asn1crypto`` returns the raw ASN.1 bytes via ``.dump()``.
    token_raw = tsr["time_stamp_token"].dump()

    # Defence-in-depth: re-parse the token's TSTInfo and confirm the
    # messageImprint matches the digest we sent. The TST is wrapped
    # in a SignedData; the actual TSTInfo lives inside the
    # ``encap_content_info``.
    try:
        token_content = tsr["time_stamp_token"]["content"]
        # ContentInfo content is SignedData; .parsed handles the inner
        # EncapsulatedContentInfo + the TSTInfo decode.
        tst_info = token_content["encap_content_info"]["content"].parsed
        token_imprint = tst_info["message_imprint"]["hashed_message"].native
    except Exception as exc:  # noqa: BLE001
        raise TSAAnchorError(
            f"TSA TimeStampToken missing message_imprint: {exc}",
        ) from exc

    if token_imprint != digest:
        raise TSAAnchorError(
            f"TSA token messageImprint does not match digest sent "
            f"(sent={digest.hex()}, got={token_imprint.hex()})",
        )

    return AnchorResult(
        digest_hex=digest_hex,
        tsa_url=tsa_url,
        token_bytes=RFC3161_TOKEN_PREFIX + token_raw,
    )
