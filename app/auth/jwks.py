"""
JWKS utilities — convert broker public keys (RSA or EC) to JWK format
(RFC 7517) and compute key IDs via JWK Thumbprint (RFC 7638).

Both kty=RSA (alg=RS256) and kty=EC / crv=P-256|P-384|P-521
(alg=ES256|ES384|ES512) are supported: the same broker key material used
to verify x509 agent certs is surfaced here.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate


_EC_CURVE_MAP = {
    "secp256r1": ("P-256", "ES256", 32),
    "secp384r1": ("P-384", "ES384", 48),
    "secp521r1": ("P-521", "ES512", 66),
}


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_bytes(n: int, length: int | None = None) -> bytes:
    """Convert a positive integer to big-endian bytes.

    If *length* is set the result is left-padded with zeros so that it has
    exactly *length* bytes — required by RFC 7518 §6.2.1 for EC x/y.
    """
    if length is None:
        length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder="big")


def _load_public_key(public_key_pem: str):
    pem_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    try:
        return serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError):
        cert = load_pem_x509_certificate(pem_bytes)
        return cert.public_key()


def _jwk_required_members(pub_key) -> dict:
    """Return only the JWK members that are part of the RFC 7638 thumbprint.

    For RSA those are {e, kty, n}; for EC {crv, kty, x, y}. Members MUST be
    alphabetical and contain no whitespace when hashed.
    """
    if isinstance(pub_key, RSAPublicKey):
        numbers = pub_key.public_numbers()
        return {
            "e": _b64url(_int_to_bytes(numbers.e)),
            "kty": "RSA",
            "n": _b64url(_int_to_bytes(numbers.n)),
        }
    if isinstance(pub_key, EllipticCurvePublicKey):
        curve_name = pub_key.curve.name
        if curve_name not in _EC_CURVE_MAP:
            raise ValueError(f"Unsupported EC curve for JWK: {curve_name}")
        crv, _alg, coord_len = _EC_CURVE_MAP[curve_name]
        numbers = pub_key.public_numbers()
        return {
            "crv": crv,
            "kty": "EC",
            "x": _b64url(_int_to_bytes(numbers.x, coord_len)),
            "y": _b64url(_int_to_bytes(numbers.y, coord_len)),
        }
    raise ValueError(f"Unsupported public key type: {type(pub_key).__name__}")


def _alg_for(pub_key) -> str:
    if isinstance(pub_key, RSAPublicKey):
        return "RS256"
    if isinstance(pub_key, EllipticCurvePublicKey):
        return _EC_CURVE_MAP[pub_key.curve.name][1]
    raise ValueError(f"Unsupported public key type: {type(pub_key).__name__}")


def pem_to_jwk(public_key_pem: str, kid: str | None = None) -> dict:
    """Convert a public key PEM (RSA or EC) to a JWK dict (RFC 7517).

    If *kid* is not supplied it is computed via ``compute_kid``.
    """
    pub_key = _load_public_key(public_key_pem)
    members = _jwk_required_members(pub_key)
    jwk = {
        **members,
        "use": "sig",
        "alg": _alg_for(pub_key),
        "kid": kid or compute_kid(public_key_pem),
    }
    return jwk


# Backward-compatible alias — some callers still import the old name.
def rsa_pem_to_jwk(public_key_pem: str, kid: str | None = None) -> dict:
    """Deprecated: use ``pem_to_jwk``. Kept for backward compatibility."""
    return pem_to_jwk(public_key_pem, kid=kid)


def compute_kid(public_key_pem: str) -> str:
    """Compute the JWK Thumbprint (RFC 7638) as a key ID.

    The thumbprint is the base64url-encoded SHA-256 hash of the canonical
    JSON representation of the JWK's required members (alphabetical order,
    no whitespace). Works for both RSA and EC public keys.
    """
    pub_key = _load_public_key(public_key_pem)
    required = _jwk_required_members(pub_key)
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return _b64url(digest)


def build_jwks(keys: list[dict]) -> dict:
    """Wrap JWK dicts into a JWKS response (RFC 7517 §5)."""
    return {"keys": keys}
