"""TSA client abstraction for audit chain anchoring (issue #75 Slice 2).

Two backends:

- `MockTsaClient` — default; produces a deterministic token that embeds
  the digest + current broker time. Useful for dev, CI, and demo. NOT
  dispute-grade: a dispute verifier who only trusts a real RFC 3161 TSA
  must reject these anchors.
- `Rfc3161TsaClient` — production; round-trips a TimeStampReq to a real
  RFC 3161 TSA (DigiCert, SwissSign, own TSA). Requires the optional
  `rfc3161-client` runtime dependency — import is lazy so the broker
  keeps booting on a minimal install.

`get_tsa_client(settings)` is the factory used by the worker; tests
inject a mock directly.
"""
from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import NamedTuple

_log = logging.getLogger("audit.tsa")

# Anchor tokens have a 2-byte magic prefix so a verifier can reject
# unknown formats fast instead of feeding garbage to an ASN.1 parser.
_MOCK_MAGIC = b"MK"
_RFC3161_MAGIC = b"T1"  # we wrap the raw DER TimeStampToken so the
                        # verifier always sees a framed payload


class TimestampedAnchor(NamedTuple):
    """Result of a timestamp operation.

    `token` is opaque bytes the backend understands for later verify.
    `tsa_url` is recorded for auditability (which authority signed).
    `created_at` is the broker-side wall clock; the authoritative time
    is inside the token itself, but recording local time helps detect
    clock skew on verify.
    """
    token: bytes
    tsa_url: str
    created_at: datetime


class TsaClient(ABC):
    """Protocol for TSA backends."""

    @abstractmethod
    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        """Return a TimestampedAnchor for the given sha256 hex digest."""

    @abstractmethod
    def verify(self, token: bytes, digest_hex: str) -> bool:
        """Return True if the token was issued for this digest. The
        verify is *cryptographic*, not network — the CLI uses it in
        offline mode on exported bundles."""


class MockTsaClient(TsaClient):
    """Deterministic backend for dev/CI/demo.

    Token layout (bytes):
      _MOCK_MAGIC (2) || "|" || digest_hex (64) || "|" || created_iso

    Verify simply re-encodes the digest and checks the prefix. There is
    NO cryptographic signing here — the mock is trust-equivalent to the
    broker database itself. Anyone serious about disputes must use the
    rfc3161 backend.
    """

    def __init__(self, url: str = "mock://broker-internal-tsa") -> None:
        self.url = url

    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        now = datetime.now(timezone.utc)
        payload = f"|{digest_hex}|{now.isoformat()}".encode("utf-8")
        token = _MOCK_MAGIC + payload
        return TimestampedAnchor(token=token, tsa_url=self.url, created_at=now)

    def verify(self, token: bytes, digest_hex: str) -> bool:
        if not token.startswith(_MOCK_MAGIC + b"|"):
            return False
        try:
            # strip magic + leading "|", split "digest|iso"
            remainder = token[len(_MOCK_MAGIC) + 1:].decode("utf-8")
        except UnicodeDecodeError:
            return False
        parts = remainder.split("|", 1)
        if len(parts) != 2:
            return False
        token_digest, _iso = parts
        return token_digest == digest_hex


class Rfc3161TsaClient(TsaClient):
    """RFC 3161 Time-Stamp Protocol client using `rfc3161-client`.

    The dep is imported lazily so a broker image without rfc3161-client
    can still boot (and default to the mock backend). An operator who
    sets AUDIT_TSA_BACKEND=rfc3161 without installing the lib will get
    a clear error at first timestamp() call — preferable to failing at
    startup because the worker is not in the boot-critical path.
    """

    def __init__(self, url: str) -> None:
        self.url = url

    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        # Lazy import — see class docstring.
        try:
            from rfc3161_client import (  # type: ignore[import-not-found]
                TimestampRequestBuilder,
                decode_timestamp_response,
            )
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "rfc3161-client + httpx required for AUDIT_TSA_BACKEND=rfc3161 — "
                "install with `pip install rfc3161-client httpx`"
            ) from exc

        digest = bytes.fromhex(digest_hex)
        req = (
            TimestampRequestBuilder()
            .data(digest)  # builder hashes if we pass raw; we already have digest
            .nonce(True)
            .build()
        )
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                self.url,
                content=req.as_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
            )
            resp.raise_for_status()
        tsa_resp = decode_timestamp_response(resp.content)
        token_bytes = tsa_resp.time_stamp_token
        now = datetime.now(timezone.utc)
        return TimestampedAnchor(
            token=_RFC3161_MAGIC + b"|" + token_bytes,
            tsa_url=self.url,
            created_at=now,
        )

    def verify(self, token: bytes, digest_hex: str) -> bool:
        if not token.startswith(_RFC3161_MAGIC + b"|"):
            return False
        try:
            import rfc3161_client  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:
            _log.warning(
                "rfc3161-client not installed — cannot verify RFC 3161 anchor; "
                "treating as not-verified"
            )
            return False
        raw = token[len(_RFC3161_MAGIC) + 1:]
        try:
            # Rebuild a partial response just to parse the token; the
            # library typically ships a dedicated TimestampToken decoder
            # too, but we keep the interface narrow here.
            # Cryptographic verify is left to the TSA's root — we check
            # only that the message_imprint matches our digest.
            from asn1crypto import tsp  # brought in transitively by rfc3161-client
            tst = tsp.TimeStampToken.load(raw)
            content = tst["content"]
            mi = content["encap_content_info"]["content"].parsed["message_imprint"]
            imprint_digest = mi["hashed_message"].native.hex()
            return imprint_digest == digest_hex
        except Exception as exc:  # noqa: BLE001
            _log.warning("rfc3161 verify failed: %s", exc)
            return False


def get_tsa_client(settings) -> TsaClient:
    """Factory: pick backend from settings.

    Unknown values fall back to MockTsaClient with a warning so a
    typo'd env var doesn't crash the worker.
    """
    backend = (getattr(settings, "audit_tsa_backend", "mock") or "mock").lower()
    url = getattr(settings, "audit_tsa_url", "") or "mock://broker-internal-tsa"
    if backend == "rfc3161":
        return Rfc3161TsaClient(url=url)
    if backend != "mock":
        _log.warning("unknown audit_tsa_backend=%r, falling back to mock", backend)
    return MockTsaClient(url=url)


def digest_hex_from_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
