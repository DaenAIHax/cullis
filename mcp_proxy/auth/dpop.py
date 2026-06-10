"""
DPoP (Demonstrating Proof of Possession) — RFC 9449 implementation for MCP Proxy.

Standalone port from app/auth/dpop.py — no imports from app/.

Public API:
  verify_dpop_proof(proof_jwt, htm, htu, access_token=None, require_nonce=True) -> jkt
  compute_jkt(jwk_dict) -> str
  generate_dpop_nonce() -> str
  get_current_dpop_nonce() -> str
  set_dpop_nonce_header(response) -> None

Every validation failure raises HTTPException 401.
The DPoP JTI is consumed only after all checks pass — no partial state on failure.
"""
import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
from typing import Sequence
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi import HTTPException, Response, status
import jwt as jose_jwt

from mcp_proxy.config import get_settings
from mcp_proxy.utils.validation import (
    canonicalize_b64url as _canonicalize_b64url_impl,
    strict_b64url_decode as _strict_b64url_decode,
)

_log = logging.getLogger("mcp_proxy")


# ─────────────────────────────────────────────────────────────────────────────
# Server Nonce (RFC 9449 section 8)
# ─────────────────────────────────────────────────────────────────────────────

_NONCE_ROTATION_INTERVAL = 300  # 5 minutes

# Multi-worker correctness (RFC 9449 §8): the nonce MUST be reproducible by
# every uvicorn worker / replica, otherwise a nonce minted by worker A is
# rejected by worker B and the client loops on ``use_dpop_nonce`` 401s. The
# pre-fix implementation seeded ``os.urandom`` per process, so a 4-worker
# bundle rejected ~40% of /v1/llm/chat proofs on the first hop (each worker
# held an independent nonce). This is the same class as the dashboard signing
# key (audit F-B-10) and the JTI store (U-DD-1): per-process state that has to
# be shared. We derive the nonce as ``HMAC(secret, window)`` over a 5-minute
# window, keyed with a secret shared across workers — stateless, no Redis hop,
# and identical on every worker because the secret is identical. The nonce is
# still global-per-window (not per-client), matching the prior semantics; the
# per-client binding lives in the cert/jkt, not the nonce.

_nonce_secret_cache: bytes = b""


def _load_or_create_nonce_secret_file(path: str) -> str:
    """Load a persisted nonce secret from ``path``, creating it (0600) if missing.

    Mirrors ``dashboard.session._load_or_create_signing_key_file``: workers on
    a shared filesystem converge on the same secret, and the tmp+rename keeps
    two workers booting at once from racing on a half-written file.
    """
    import pathlib
    p = pathlib.Path(path)
    if p.exists():
        return p.read_text().strip()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret = os.urandom(32).hex()
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(secret)
    os.chmod(tmp, 0o600)
    try:
        os.rename(tmp, p)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        if p.exists():
            return p.read_text().strip()
        raise
    return secret


def _nonce_secret() -> bytes:
    """Return the shared HMAC secret used to derive DPoP nonces.

    Precedence:
      1. ``MCP_PROXY_DPOP_NONCE_SECRET`` env → wins (prod / multi-replica Helm).
      2. Persisted file at ``dpop_nonce_secret_path`` → shared across workers on
         a common filesystem (single-container bundle, the default).
      3. Per-process ``os.urandom`` — only when the file cannot be written
         (read-only sandbox). Logs a warning; multi-worker will see 401 churn.
    """
    global _nonce_secret_cache
    if _nonce_secret_cache:
        return _nonce_secret_cache
    settings = get_settings()
    configured = getattr(settings, "dpop_nonce_secret", "")
    if configured:
        _nonce_secret_cache = configured.encode()
        return _nonce_secret_cache
    path = getattr(settings, "dpop_nonce_secret_path", "")
    if path:
        try:
            secret = _load_or_create_nonce_secret_file(path)
            if secret:
                _nonce_secret_cache = secret.encode()
                return _nonce_secret_cache
        except OSError as exc:
            _log.warning(
                "Could not persist DPoP nonce secret to %s (%s) — falling back "
                "to a per-process secret. Multi-worker deploys will churn "
                "'use_dpop_nonce' 401s. Fix by setting MCP_PROXY_DPOP_NONCE_"
                "SECRET or making the path writable.",
                path, exc,
            )
    _nonce_secret_cache = os.urandom(32)
    return _nonce_secret_cache


def _nonce_for_window(window: int) -> str:
    """Deterministic nonce for a rotation window — same on every worker."""
    return _hmac.new(
        _nonce_secret(), str(window).encode(), hashlib.sha256
    ).hexdigest()[:32]


def _current_window() -> int:
    return int(time.time() // _NONCE_ROTATION_INTERVAL)


def generate_dpop_nonce() -> str:
    """Return the current server nonce.

    Kept for call-site compatibility (a boot-time warm-up call in ``main``).
    With the stateless HMAC scheme there is nothing to mutate, so this is an
    alias of :func:`get_current_dpop_nonce`.
    """
    return get_current_dpop_nonce()


def get_current_dpop_nonce() -> str:
    """Return the current server nonce for the active rotation window."""
    return _nonce_for_window(_current_window())


def _is_valid_nonce(nonce: str) -> bool:
    """Accept the current or previous window's nonce (tolerates rotation)."""
    if not nonce:
        return False
    window = _current_window()
    return (
        _hmac.compare_digest(nonce, _nonce_for_window(window))
        or _hmac.compare_digest(nonce, _nonce_for_window(window - 1))
    )


def set_dpop_nonce_header(response: Response) -> None:
    """Set the DPoP-Nonce header on the response."""
    response.headers["DPoP-Nonce"] = get_current_dpop_nonce()


# ─────────────────────────────────────────────────────────────────────────────
# Base64url helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str | bytes) -> bytes:
    """Strict base64url decode — delegates to ``mcp_proxy.utils.validation``.

    Audit S8: previously inlined; now imports from the single vendored copy
    so all Mastio paths stay in sync with ``app.utils.validation``.
    """
    return _strict_b64url_decode(s)


def _canonicalize_b64url(s: str) -> str:
    """Round-trip ``s`` through strict decode -> no-pad encode.

    Used for JKT canonicalization — collapses padding / tail-bit variants
    of the same key into a single canonical form before hashing.
    """
    return _canonicalize_b64url_impl(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ─────────────────────────────────────────────────────────────────────────────
# JWK Thumbprint (RFC 7638)
# ─────────────────────────────────────────────────────────────────────────────

def compute_jkt(jwk: dict) -> str:
    """Compute the RFC 7638 JWK Thumbprint (SHA-256, base64url, no padding).

    Required members by key type:
      EC  -> crv, kty, x, y  (alphabetical)
      RSA -> e, kty, n       (alphabetical)
    """
    kty = jwk.get("kty")
    if kty == "EC":
        raw = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
        try:
            raw["x"] = _canonicalize_b64url(raw["x"])
            raw["y"] = _canonicalize_b64url(raw["y"])
        except ValueError as exc:
            raise ValueError(f"malformed EC JWK coordinate: {exc}") from exc
        required = raw
    elif kty == "RSA":
        raw = {k: jwk[k] for k in ("e", "kty", "n")}
        try:
            raw["n"] = _canonicalize_b64url(raw["n"])
            raw["e"] = _canonicalize_b64url(raw["e"])
        except ValueError as exc:
            raise ValueError(f"malformed RSA JWK coordinate: {exc}") from exc
        required = raw
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")

    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return _b64url_encode(hashlib.sha256(canonical).digest())


# ─────────────────────────────────────────────────────────────────────────────
# JWK -> cryptography public key
# ─────────────────────────────────────────────────────────────────────────────

def _jwk_to_public_key(jwk: dict):
    """Convert a JWK dict to a cryptography public key object."""
    kty = jwk.get("kty")
    if kty == "EC":
        crv = jwk.get("crv")
        if crv != "P-256":
            raise ValueError(f"Unsupported EC curve: {crv!r}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        return pub_numbers.public_key()
    elif kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e=e, n=n).public_key()
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")


# ─────────────────────────────────────────────────────────────────────────────
# HTU normalization
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_htu(url: str) -> str:
    """Normalize an HTU for comparison (RFC 9449 section 4.3).

    - Strip query string and fragment
    - Lowercase scheme and host
    - Normalize ws:// -> http:// and wss:// -> https://
    """
    url = url.replace("wss://", "https://").replace("ws://", "http://")
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", "", ""))


# ─────────────────────────────────────────────────────────────────────────────
# JTI store (replay protection) — delegated to dpop_jti_store module
# ─────────────────────────────────────────────────────────────────────────────
#
# Previously this module defined its own InMemoryDpopJtiStore singleton. The
# dual-backend factory lives in ``mcp_proxy.auth.dpop_jti_store`` so that
# multi-worker deploys can share a Redis-backed store (audit F-B-12 / #182).


# ─────────────────────────────────────────────────────────────────────────────
# Main verifier
# ─────────────────────────────────────────────────────────────────────────────

async def verify_dpop_proof(
    proof_jwt: str,
    htm: str,
    htu: "str | Sequence[str]",
    access_token: str | None = None,
    require_nonce: bool = True,
) -> str:
    """Validate a DPoP proof JWT (RFC 9449 section 4.3 + section 8 server nonce).

    Returns the JWK thumbprint (jkt) on success.
    Raises HTTPException 401 on any failure.
    JTI is consumed only after all checks pass.

    ``htu`` accepts either a single string (backward-compat, pre-D-11 v2
    callers) or a sequence of candidate URLs — the proof is accepted if
    its ``htu`` claim normalizes to ANY of the candidates. This widens
    the binding when the same Mastio is legitimately reachable under
    multiple hostnames (pinned ``MCP_PROXY_PROXY_PUBLIC_URL`` vs the
    LAN IP / Host header the client actually used). Security-wise this
    is safe: htu is the anti-replay binding, not identity — the client
    must still possess the registered DPoP key to sign the proof, so
    accepting alternative URLs the same proxy answers on does not
    reduce the security posture; it just stops penalising deploy
    topologies (cold-reader on Linux, LAN IP access) where the pinned
    URL and the reached URL legitimately differ. Root cause confirmed
    via the dogfood VM 2026-05-26 — see fix/d11-v2-server-permissive-htu.

    12-point verification:
      1. JWT structurally valid
      2. typ == "dpop+jwt"
      3. alg in {ES256, PS256}
      4. jwk present and public (no 'd' field)
      5. jkt computable
      6. Signature valid
      7. jti present and not replayed
      8. iat within [-clock_skew, iat_window]
      9. htm matches (case-insensitive)
      10. htu matches at least one candidate (normalized)
      11. ath == base64url(SHA-256(access_token)) if provided
      12. nonce matches if require_nonce
    """
    settings = get_settings()

    # -- 1. Decode header without signature verification
    try:
        raw_header = proof_jwt.split(".")[0]
        header = json.loads(_b64url_decode(raw_header))
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: malformed JWT"
        )

    # -- 2. typ
    if header.get("typ") != "dpop+jwt":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: typ must be 'dpop+jwt'"
        )

    # -- 3. alg (asymmetric only)
    alg = header.get("alg", "")
    if alg not in ("ES256", "PS256"):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Invalid DPoP proof: unsupported algorithm {alg!r}",
        )

    # -- 4. jwk present and public
    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing jwk in header"
        )
    if "d" in jwk:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: jwk contains private key material",
        )

    # -- 5. jkt
    try:
        jkt = compute_jkt(jwk)
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: cannot compute JWK thumbprint",
        )

    # -- 6. Signature verification
    try:
        pub_key = _jwk_to_public_key(jwk)
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        claims = jose_jwt.decode(
            proof_jwt,
            pub_pem,
            algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False},
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: signature verification failed",
        )

    # -- 7. jti present
    jti = claims.get("jti")
    if not jti:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing jti"
        )

    # -- 8. iat freshness
    iat = claims.get("iat")
    if iat is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing iat"
        )
    age = time.time() - float(iat)
    if not (-settings.dpop_clock_skew <= age <= settings.dpop_iat_window):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: iat out of acceptable window",
        )

    # -- 9. htm
    if claims.get("htm", "").upper() != htm.upper():
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: htm mismatch"
        )

    # -- 10. htu
    # Accept either a single string (backward-compat) or a Sequence of
    # candidate URLs. The proof's htu claim must normalize to AT LEAST
    # ONE candidate — D-11 v2 root cause fix: a Mastio reachable under
    # both the pinned proxy_public_url and the actual request URL (LAN
    # IP, Host header) should accept proofs signed against either.
    htu_candidates: list[str] = (
        [htu] if isinstance(htu, str) else list(htu)
    )
    expected_norms = {_normalize_htu(h) for h in htu_candidates if h}
    got_norm = _normalize_htu(claims.get("htu", ""))
    if got_norm not in expected_norms:
        # Server-side: log structured diagnostics so operators can correlate
        # 401s with a wrong MCP_PROXY_PROXY_PUBLIC_URL (memory:
        # feedback_proxy_env_public_url_vm). Do NOT log the jkt to keep
        # client-key privacy invariant.
        _log.warning(
            "DPoP htu mismatch",
            extra={
                "expected_htus": sorted(expected_norms),
                "got_htu": got_norm,
                "hint": "htu_mismatch_check_proxy_public_url",
            },
        )
        # Header is a stable machine-readable diagnostic token. Safe in prod:
        # it does not leak the internal URL, but tells customer admins which
        # config knob to inspect (MCP_PROXY_PROXY_PUBLIC_URL / frontdesk.env).
        headers = {"X-Cullis-Hint": "htu_mismatch_check_proxy_public_url"}
        if settings.environment == "production":
            detail = "Invalid DPoP proof: htu mismatch"
        else:
            detail = (
                f"Invalid DPoP proof: htu mismatch "
                f"(expected={sorted(expected_norms)!r}, got={got_norm!r})"
            )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail, headers=headers
        )

    # -- 11. ath (access token hash)
    if access_token is not None:
        expected_ath = _b64url_encode(
            hashlib.sha256(access_token.encode()).digest()
        )
        if not _hmac.compare_digest(claims.get("ath", ""), expected_ath):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: ath mismatch"
            )

    # -- 12. Server nonce (RFC 9449 section 8)
    if require_nonce:
        proof_nonce = claims.get("nonce")
        if not proof_nonce:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "use_dpop_nonce",
                headers={"DPoP-Nonce": get_current_dpop_nonce()},
            )
        if not _is_valid_nonce(proof_nonce):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "use_dpop_nonce",
                headers={"DPoP-Nonce": get_current_dpop_nonce()},
            )

    # -- 13. Consume JTI atomically (only after all checks pass)
    from mcp_proxy.auth.dpop_jti_store import get_dpop_jti_store
    is_new = await get_dpop_jti_store().consume_jti(jti)
    if not is_new:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "DPoP proof replay detected"
        )

    _log.debug("DPoP proof verified: jkt=%s htm=%s", jkt, htm)
    return jkt
