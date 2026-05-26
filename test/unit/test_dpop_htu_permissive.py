"""Tests for D-11 v2 server-side permissive htu binding.

Root cause confirmed by the dogfood VM 2026-05-26: cold-reader on a
Linux host without ``host.docker.internal`` resolved the Mastio via the
LAN IP, but the server's ``_build_htu`` pinned the comparison to
``MCP_PROXY_PROXY_PUBLIC_URL=https://host.docker.internal:9443`` and
every ``/v1/llm/chat`` request 401'd with "htu mismatch" even though
the client was perfectly honest about which URL it dialled.

The fix:

  * ``verify_dpop_proof`` now accepts ``htu: str | Sequence[str]`` and
    matches the claim against set membership (was strict equality
    against a single normalized URL).
  * ``_build_htu(request)`` returns a tuple of acceptable URLs (the
    actual request URL, the pinned ``proxy_public_url``, and the URL
    implied by the ``Host:`` header when they differ).

Security: htu is the anti-replay binding, not identity — the client
still has to sign with the registered DPoP key, so widening the
accepted URL set does not reduce the security posture; it just stops
penalising deploys where the pinned URL and the reached URL
legitimately differ (LAN IP access, alternative DNS).

Five invariants pinned:

1. ``htu=<str>`` keeps working (pre-D-11 v2 callers — ``dependencies``,
   ``local_token``, ``local_agent_dep`` — still pass a single string).
2. ``htu=(a, b)`` with proof signed against ``a`` is accepted.
3. ``htu=(a, b)`` with proof signed against ``b`` is accepted.
4. ``htu=(a, b)`` with proof signed against ``c`` is rejected with a
   401 whose detail mentions "htu mismatch".
5. ``_build_htu(req)`` returns a tuple that includes BOTH the actual
   request URL AND the pinned ``proxy_public_url`` when they differ.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any
from unittest.mock import MagicMock

import jwt as jose_jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────
# Helpers — minimal local DPoP proof signing so the tests don't depend
# on the SDK's DpopKey shape (which lives in a different package and
# could drift). Mirrors ``cullis_sdk.dpop.DpopKey.sign_proof`` plus the
# RFC 7638 thumbprint helper.
# ─────────────────────────────────────────────────────────────────────


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_keypair() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """Generate an EC P-256 keypair and return (priv, public_jwk)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x = _b64url(nums.x.to_bytes(32, "big"))
    y = _b64url(nums.y.to_bytes(32, "big"))
    public_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return priv, public_jwk


def _sign_proof(
    priv: ec.EllipticCurvePrivateKey,
    public_jwk: dict,
    *,
    htm: str,
    htu: str,
    jti: str | None = None,
    iat: int | None = None,
) -> str:
    """Sign a DPoP proof JWT in the shape ``verify_dpop_proof`` expects."""
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    claims: dict[str, Any] = {
        "jti": jti or uuid.uuid4().hex,
        "htm": htm.upper(),
        "htu": htu,
        "iat": int(iat if iat is not None else time.time()),
    }
    return jose_jwt.encode(
        claims,
        priv_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": public_jwk},
    )


@pytest.fixture(autouse=True)
def _reset_dpop_singletons(monkeypatch):
    """Reset DPoP module-scoped state per test.

    ``verify_dpop_proof`` consumes JTIs into a module-level in-memory
    store; tests that reuse the same jti across calls would otherwise
    see a spurious "replay" 401. Forces a fresh store per test.
    """
    # Avoid the validate_config insecure-default refusal in dev — same
    # rationale as ``conftest.audit_test_env``.
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default"
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.auth import dpop_jti_store
    dpop_jti_store.reset_dpop_jti_store()

    yield

    get_settings.cache_clear()
    dpop_jti_store.reset_dpop_jti_store()


# ─────────────────────────────────────────────────────────────────────
# verify_dpop_proof tests
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_dpop_proof_accepts_string_htu_backward_compat():
    """Pin retrocompat: callers passing a single string still work.

    Pre-D-11 v2 callers (``dependencies.py``, ``local_token.py``,
    ``local_agent_dep.py``) still construct ``htu`` as a single string.
    The new signature accepts ``str | Sequence[str]`` and must not
    break those call sites.
    """
    from mcp_proxy.auth.dpop import verify_dpop_proof

    priv, pub_jwk = _make_keypair()
    url = "https://mastio.example/v1/llm/chat"
    proof = _sign_proof(priv, pub_jwk, htm="POST", htu=url)

    jkt = await verify_dpop_proof(
        proof,
        htm="POST",
        htu=url,  # string, not sequence
        access_token=None,
        require_nonce=False,
    )
    assert isinstance(jkt, str) and len(jkt) > 0


@pytest.mark.asyncio
async def test_verify_dpop_proof_accepts_first_of_sequence():
    """Proof signed against the FIRST candidate URL is accepted."""
    from mcp_proxy.auth.dpop import verify_dpop_proof

    priv, pub_jwk = _make_keypair()
    url_a = "https://host.docker.internal:9443/v1/llm/chat"
    url_b = "https://192.168.122.62:9443/v1/llm/chat"
    proof = _sign_proof(priv, pub_jwk, htm="POST", htu=url_a)

    jkt = await verify_dpop_proof(
        proof,
        htm="POST",
        htu=(url_a, url_b),
        access_token=None,
        require_nonce=False,
    )
    assert isinstance(jkt, str) and len(jkt) > 0


@pytest.mark.asyncio
async def test_verify_dpop_proof_accepts_second_of_sequence():
    """Proof signed against the SECOND candidate URL is accepted.

    This is the dogfood VM scenario: pinned ``proxy_public_url`` is
    ``host.docker.internal`` (candidate A) but the client actually
    reached the Mastio via the LAN IP (candidate B). Pre-fix the
    server rejected; post-fix it accepts.
    """
    from mcp_proxy.auth.dpop import verify_dpop_proof

    priv, pub_jwk = _make_keypair()
    url_a = "https://host.docker.internal:9443/v1/llm/chat"
    url_b = "https://192.168.122.62:9443/v1/llm/chat"
    proof = _sign_proof(priv, pub_jwk, htm="POST", htu=url_b)

    jkt = await verify_dpop_proof(
        proof,
        htm="POST",
        htu=(url_a, url_b),
        access_token=None,
        require_nonce=False,
    )
    assert isinstance(jkt, str) and len(jkt) > 0


@pytest.mark.asyncio
async def test_verify_dpop_proof_rejects_when_neither_matches():
    """Proof signed against a URL OUTSIDE the candidate set is rejected.

    The permissive binding only widens the accepted set to URLs the
    server explicitly considers legitimate for this request. A proof
    bound to an unrelated URL ("https://attacker.example/...") must
    still 401 — htu binding is not bypassed, just relaxed to a set.
    """
    from mcp_proxy.auth.dpop import verify_dpop_proof

    priv, pub_jwk = _make_keypair()
    url_a = "https://host.docker.internal:9443/v1/llm/chat"
    url_b = "https://192.168.122.62:9443/v1/llm/chat"
    url_c = "https://attacker.example:9443/v1/llm/chat"
    proof = _sign_proof(priv, pub_jwk, htm="POST", htu=url_c)

    with pytest.raises(HTTPException) as exc_info:
        await verify_dpop_proof(
            proof,
            htm="POST",
            htu=(url_a, url_b),
            access_token=None,
            require_nonce=False,
        )
    assert exc_info.value.status_code == 401
    assert "htu mismatch" in exc_info.value.detail


# ─────────────────────────────────────────────────────────────────────
# _build_htu tests
# ─────────────────────────────────────────────────────────────────────


def test_build_htu_returns_tuple_with_proxy_public_url_and_request_url(
    monkeypatch,
):
    """``_build_htu`` returns BOTH the request URL and the pinned URL.

    Scenario: ``MCP_PROXY_PROXY_PUBLIC_URL=https://host.docker.internal:9443``
    (the bundle community quickstart default), but the SDK reached the
    Mastio via ``https://192.168.122.62:9443/v1/llm/chat`` (LAN IP).
    The returned tuple must include both so ``verify_dpop_proof`` can
    accept a proof signed against either.
    """
    monkeypatch.setenv(
        "MCP_PROXY_PROXY_PUBLIC_URL",
        "https://host.docker.internal:9443",
    )
    monkeypatch.setenv(
        "MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default"
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        from mcp_proxy.auth.dpop_client_cert import _build_htu

        # Minimal Request mock — we only touch .url and .headers.
        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/v1/llm/chat"
        request.url.scheme = "https"
        request.url.__str__ = lambda self=None: (
            "https://192.168.122.62:9443/v1/llm/chat"
        )
        request.headers = {"host": "192.168.122.62:9443"}

        result = _build_htu(request)

        assert isinstance(result, tuple)
        # Both URLs must be present somewhere in the tuple.
        assert "https://192.168.122.62:9443/v1/llm/chat" in result
        assert (
            "https://host.docker.internal:9443/v1/llm/chat" in result
        ), (
            "pinned proxy_public_url + request.url.path must be in the "
            f"candidate tuple; got {result!r}"
        )
        # Deduplication: each entry appears once.
        assert len(result) == len(set(result))
    finally:
        get_settings.cache_clear()
