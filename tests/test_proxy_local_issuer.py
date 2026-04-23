"""ADR-012 Phase 1 / Phase 2.0 / Phase 2.2 — unit tests for ``LocalIssuer``
and the ``/.well-known/jwks-local.json`` endpoint.

The issuer is the primitive behind every intra-org session token. These
tests pin the wire format (ES256 claims, kid derivation, JWKS shape) so
future refactors can't silently break the contract the validator depends
on. Phase 2.0 shifts the issuer from holding its own leaf key+pubkey
pair to wrapping a ``MastioKey`` pulled from the keystore; the tests
reflect that change but keep the same wire-level assertions.

Phase 2.2: the JWKS endpoint reads from the keystore (not the single-
signer issuer) so it can enumerate every kid currently accepted for
verification — active + deprecated-but-within-grace. The endpoint tests
live below and exercise the rotation-grace behaviour directly.
"""
from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timezone

import jwt as jose_jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.local_issuer import (
    LOCAL_AUDIENCE,
    LOCAL_ISSUER_PREFIX,
    LOCAL_SCOPE,
    LocalIssuer,
)
from mcp_proxy.auth.local_keystore import MastioKey, compute_kid


def _fresh_key() -> tuple[ec.EllipticCurvePrivateKey, str, str]:
    """Return ``(priv_key_obj, priv_pem, pub_pem)`` for a fresh EC P-256 key."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, priv_pem, pub_pem


def _active_key(priv_pem: str, pub_pem: str) -> MastioKey:
    """Build an in-memory active ``MastioKey`` without touching the DB."""
    now = datetime.now(timezone.utc)
    return MastioKey(
        kid=compute_kid(pub_pem),
        pubkey_pem=pub_pem,
        privkey_pem=priv_pem,
        cert_pem=None,
        created_at=now,
        activated_at=now,
        deprecated_at=None,
        expires_at=None,
    )


def _decode_with_issuer(token: str, issuer: LocalIssuer) -> dict:
    return jose_jwt.decode(
        token,
        issuer.active_key.pubkey_pem,
        algorithms=["ES256"],
        audience=LOCAL_AUDIENCE,
        issuer=issuer.issuer,
    )


def test_issue_produces_decodable_es256_token_with_expected_claims():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    before = int(time.time())
    result = issuer.issue("orga::alice", ttl_seconds=60)
    after = int(time.time())

    header = jose_jwt.get_unverified_header(result.token)
    assert header["alg"] == "ES256"
    assert header["typ"] == "JWT"
    assert header["kid"] == issuer.kid
    assert header["kid"] == result.kid

    claims = _decode_with_issuer(result.token, issuer)
    assert claims["iss"] == f"{LOCAL_ISSUER_PREFIX}:orga"
    assert claims["aud"] == LOCAL_AUDIENCE
    assert claims["sub"] == "orga::alice"
    assert claims["scope"] == LOCAL_SCOPE
    assert before <= claims["iat"] <= after
    assert claims["exp"] == claims["iat"] + 60
    assert isinstance(claims["jti"], str) and len(claims["jti"]) >= 32
    assert result.issued_at == claims["iat"]
    assert result.expires_at == claims["exp"]


def test_kid_is_stable_for_same_pubkey_and_unique_across_keys():
    _, priv1, pub1 = _fresh_key()
    _, priv2, pub2 = _fresh_key()

    issuer1a = LocalIssuer(org_id="orga", active_key=_active_key(priv1, pub1))
    issuer1b = LocalIssuer(org_id="orga", active_key=_active_key(priv1, pub1))
    issuer2 = LocalIssuer(org_id="orga", active_key=_active_key(priv2, pub2))

    assert issuer1a.kid == issuer1b.kid
    assert issuer1a.kid != issuer2.kid

    expected = f"mastio-{hashlib.sha256(pub1.encode()).hexdigest()[:16]}"
    assert issuer1a.kid == expected


def test_extra_claims_cannot_overwrite_reserved_fields():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    extra = {
        "iss": "attacker",
        "sub": "attacker",
        "aud": "attacker",
        "scope": "root",
        "exp": 0,
        "iat": 0,
        "jti": "pinned",
        "capabilities": ["order.read"],
        "tenant_id": "t-42",
    }
    result = issuer.issue("orga::alice", ttl_seconds=60, extra_claims=extra)
    claims = _decode_with_issuer(result.token, issuer)

    assert claims["iss"] == issuer.issuer
    assert claims["sub"] == "orga::alice"
    assert claims["aud"] == LOCAL_AUDIENCE
    assert claims["scope"] == LOCAL_SCOPE
    assert claims["jti"] != "pinned"
    assert claims["capabilities"] == ["order.read"]
    assert claims["tenant_id"] == "t-42"


def test_issue_rejects_invalid_inputs():
    _, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    with pytest.raises(ValueError):
        issuer.issue("", ttl_seconds=60)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=0)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=-1)
    with pytest.raises(ValueError):
        issuer.issue("orga::alice", ttl_seconds=3601)


def test_constructor_rejects_bad_inputs():
    _, priv_pem, pub_pem = _fresh_key()
    with pytest.raises(ValueError):
        LocalIssuer(org_id="", active_key=_active_key(priv_pem, pub_pem))
    with pytest.raises(TypeError):
        LocalIssuer(org_id="orga", active_key="not-a-key")  # type: ignore[arg-type]

    # An inactive (never-activated or deprecated) key cannot anchor an issuer.
    now = datetime.now(timezone.utc)
    never_active = MastioKey(
        kid=compute_kid(pub_pem), pubkey_pem=pub_pem, privkey_pem=priv_pem,
        cert_pem=None, created_at=now,
        activated_at=None, deprecated_at=None, expires_at=None,
    )
    with pytest.raises(ValueError, match="not currently active"):
        LocalIssuer(org_id="orga", active_key=never_active)


def test_jwks_roundtrip_matches_leaf_pubkey():
    priv, priv_pem, pub_pem = _fresh_key()
    issuer = LocalIssuer(org_id="orga", active_key=_active_key(priv_pem, pub_pem))

    jwks = issuer.jwks()
    assert "keys" in jwks and len(jwks["keys"]) == 1
    jwk = jwks["keys"][0]
    assert jwk == {
        "kty": "EC",
        "crv": "P-256",
        "x": jwk["x"],
        "y": jwk["y"],
        "use": "sig",
        "alg": "ES256",
        "kid": issuer.kid,
    }

    def _unb64u(s: str) -> int:
        pad = "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")

    numbers = priv.public_key().public_numbers()
    assert _unb64u(jwk["x"]) == numbers.x
    assert _unb64u(jwk["y"]) == numbers.y


class _FakeKeyStore:
    """In-memory keystore stub for wire-level JWKS tests.

    The real ``LocalKeyStore`` hits the DB — these tests only need to
    pin the endpoint's contract (what it reads, what it serialises,
    when it 503s), so a list-backed stub keeps the fixture weight at
    zero.
    """

    def __init__(self, keys: list[MastioKey]) -> None:
        self._keys = keys

    async def all_valid_keys(self) -> list[MastioKey]:
        return [k for k in self._keys if k.is_valid_for_verification]


def _grace_key(priv_pem: str, pub_pem: str, *, deprecated_ago_seconds: int = 60,
               grace_seconds: int = 3600) -> MastioKey:
    """Build a deprecated-but-within-grace ``MastioKey`` in memory."""
    from datetime import timedelta  # local import to avoid top-level clutter

    now = datetime.now(timezone.utc)
    activated = now - timedelta(days=30)
    deprecated = now - timedelta(seconds=deprecated_ago_seconds)
    expires = now + timedelta(seconds=grace_seconds)
    return MastioKey(
        kid=compute_kid(pub_pem),
        pubkey_pem=pub_pem,
        privkey_pem=priv_pem,
        cert_pem=None,
        created_at=activated,
        activated_at=activated,
        deprecated_at=deprecated,
        expires_at=expires,
    )


def test_jwks_endpoint_503_when_keystore_missing():
    """Pre-lifespan state: ``local_keystore`` not set → 503 so callers
    can distinguish a bootstrapping proxy from an empty keystore."""
    from mcp_proxy.auth.jwks_local import router as jwks_router

    app = FastAPI()
    app.include_router(jwks_router)

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 503


def test_jwks_endpoint_503_when_keystore_empty():
    """Keystore attached but has no valid key — treat as ``identity not
    ensured yet`` rather than publishing an empty ``{"keys": []}`` that
    would silently break every validator polling the endpoint."""
    from mcp_proxy.auth.jwks_local import router as jwks_router

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[])

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 503


def test_jwks_endpoint_returns_single_active_key_pre_rotation():
    """Canonical pre-rotation state: one active key → one JWK with the
    expected kid + ES256 algorithm."""
    from mcp_proxy.auth.jwks_local import router as jwks_router

    _, priv_pem, pub_pem = _fresh_key()
    active = _active_key(priv_pem, pub_pem)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[active])

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["keys"]) == 1
        assert body["keys"][0]["kid"] == active.kid
        assert body["keys"][0]["alg"] == "ES256"
        assert body["keys"][0]["kty"] == "EC"
        assert body["keys"][0]["crv"] == "P-256"


def test_jwks_endpoint_exposes_active_plus_grace_key_during_rotation():
    """Phase 2.2 contract: during grace the endpoint publishes both
    kids so a consumer that cached the old kid can still verify its
    in-flight tokens after re-fetching the JWKS."""
    from mcp_proxy.auth.jwks_local import router as jwks_router

    _, old_priv, old_pub = _fresh_key()
    _, new_priv, new_pub = _fresh_key()
    grace = _grace_key(old_priv, old_pub)
    new_active = _active_key(new_priv, new_pub)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[grace, new_active])

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 200
        body = resp.json()
        kids = {k["kid"] for k in body["keys"]}
        assert kids == {grace.kid, new_active.kid}
        assert len(body["keys"]) == 2
        for entry in body["keys"]:
            assert entry["alg"] == "ES256"
            assert entry["kty"] == "EC"


def test_jwks_endpoint_drops_expired_deprecated_key():
    """``all_valid_keys`` filters on ``expires_at`` — the endpoint
    inherits that and MUST NOT surface a deprecated key whose grace
    window has elapsed (otherwise a stolen old key stays verifiable)."""
    from datetime import timedelta
    from mcp_proxy.auth.jwks_local import router as jwks_router

    _, old_priv, old_pub = _fresh_key()
    _, new_priv, new_pub = _fresh_key()
    now = datetime.now(timezone.utc)
    expired = MastioKey(
        kid=compute_kid(old_pub),
        pubkey_pem=old_pub,
        privkey_pem=old_priv,
        cert_pem=None,
        created_at=now - timedelta(days=400),
        activated_at=now - timedelta(days=400),
        deprecated_at=now - timedelta(days=30),
        expires_at=now - timedelta(days=1),  # grace elapsed
    )
    new_active = _active_key(new_priv, new_pub)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[expired, new_active])

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 200
        body = resp.json()
        kids = {k["kid"] for k in body["keys"]}
        assert kids == {new_active.kid}
        assert expired.kid not in kids


# ── Cache + ETag + rate-limit (#282) ─────────────────────────────────


def _reset_agent_rate_limiter() -> None:
    """Clear the module-level ``get_agent_rate_limiter`` state so the
    per-IP budget is full at the start of each test that exercises it.
    """
    from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
    limiter = get_agent_rate_limiter()
    try:
        limiter._windows.clear()
    except AttributeError:
        pass


def test_jwks_endpoint_sets_cacheable_headers():
    """The endpoint must emit ``Cache-Control: public, max-age=60,
    stale-while-revalidate=60`` and a strong ``ETag`` so a CDN /
    reverse-proxy in front can absorb the broadcast load during a
    rotation grace window (#282).
    """
    from mcp_proxy.auth.jwks_local import router as jwks_router
    _reset_agent_rate_limiter()

    _, priv_pem, pub_pem = _fresh_key()
    active = _active_key(priv_pem, pub_pem)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[active])

    with TestClient(app) as client:
        resp = client.get("/.well-known/jwks-local.json")
        assert resp.status_code == 200
        cc = resp.headers.get("cache-control", "")
        assert "public" in cc, cc
        assert "max-age=60" in cc, cc
        assert "stale-while-revalidate=60" in cc, cc
        etag = resp.headers.get("etag")
        assert etag is not None
        assert etag.startswith('"') and etag.endswith('"')


def test_jwks_endpoint_if_none_match_returns_304():
    """A repeat GET with ``If-None-Match: <etag>`` must return 304 and
    no body — the classic conditional-request fast path. Proves the
    caller can skip parsing the body after the first warm fetch.
    """
    from mcp_proxy.auth.jwks_local import router as jwks_router
    _reset_agent_rate_limiter()

    _, priv_pem, pub_pem = _fresh_key()
    active = _active_key(priv_pem, pub_pem)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[active])

    with TestClient(app) as client:
        first = client.get("/.well-known/jwks-local.json")
        assert first.status_code == 200
        etag = first.headers["etag"]

        second = client.get(
            "/.well-known/jwks-local.json",
            headers={"If-None-Match": etag},
        )
        assert second.status_code == 304
        # 304 responses per RFC 7232 MUST include the same cache
        # validators as the 200 would — especially ETag so a caller
        # that retries can still short-circuit.
        assert second.headers.get("etag") == etag
        # No body content on 304.
        assert not second.content


def test_jwks_endpoint_etag_changes_after_rotation():
    """After a rotation (different key set) the ETag must change so
    any downstream cache invalidates. Conversely, identical key sets
    yield identical ETags — a stable reads don't churn.
    """
    from mcp_proxy.auth.jwks_local import router as jwks_router
    _reset_agent_rate_limiter()

    _, priv_pem_a, pub_pem_a = _fresh_key()
    _, priv_pem_b, pub_pem_b = _fresh_key()
    active_a = _active_key(priv_pem_a, pub_pem_a)
    active_b = _active_key(priv_pem_b, pub_pem_b)

    # State 1: single key A.
    app1 = FastAPI()
    app1.include_router(jwks_router)
    app1.state.local_keystore = _FakeKeyStore(keys=[active_a])
    with TestClient(app1) as c1:
        r1 = c1.get("/.well-known/jwks-local.json")
        etag_1 = r1.headers["etag"]

    # State 2: post-rotation — key A + key B (grace window).
    grace_a = _grace_key(priv_pem_a, pub_pem_a)
    app2 = FastAPI()
    app2.include_router(jwks_router)
    app2.state.local_keystore = _FakeKeyStore(keys=[grace_a, active_b])
    with TestClient(app2) as c2:
        r2 = c2.get("/.well-known/jwks-local.json")
        etag_2 = r2.headers["etag"]

    assert etag_1 != etag_2, (
        "ETag must differ after rotation — otherwise stale caches stick"
    )

    # State 3: identical to state 1 — same single key A.
    app3 = FastAPI()
    app3.include_router(jwks_router)
    app3.state.local_keystore = _FakeKeyStore(keys=[active_a])
    with TestClient(app3) as c3:
        r3 = c3.get("/.well-known/jwks-local.json")
        etag_3 = r3.headers["etag"]
    assert etag_1 == etag_3, "stable reads must yield stable ETag"


def test_jwks_endpoint_rate_limits_per_ip():
    """Budget is 30/min/IP (``_JWKS_RATE_LIMIT_PER_MINUTE``). The 31st
    request from the same client gets 429 without touching the
    keystore or the body serialiser.
    """
    from mcp_proxy.auth.jwks_local import router as jwks_router
    _reset_agent_rate_limiter()

    _, priv_pem, pub_pem = _fresh_key()
    active = _active_key(priv_pem, pub_pem)

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=[active])

    with TestClient(app) as client:
        # TestClient sends a stable synthetic IP for all requests; 30
        # should pass, the 31st should 429.
        for i in range(30):
            r = client.get("/.well-known/jwks-local.json")
            assert r.status_code == 200, f"request {i+1}: {r.text}"

        r = client.get("/.well-known/jwks-local.json")
        assert r.status_code == 429, r.text


def test_jwks_endpoint_emits_keys_sorted_by_kid_not_activation_time():
    """Sorting by ``kid`` lexicographic (not by ``activated_at``)
    closes a rotation-timing oracle: a caller could previously infer
    "the freshest signer is the last entry" from the array order.
    With kid-sorted output, position is stable across rotations —
    ``keys[-1]`` is just the kid that sorts last, not the one minted
    most recently.
    """
    from mcp_proxy.auth.jwks_local import router as jwks_router
    _reset_agent_rate_limiter()

    # Generate two keys, identify which kid sorts first by
    # compute_kid output, then set activation times in the OPPOSITE
    # order. If the endpoint sorted by ``activated_at`` the first
    # entry would be the one activated earliest; kid-sorted output
    # instead puts the lexicographically-smaller kid first.
    from datetime import timedelta
    _, priv_a, pub_a = _fresh_key()
    _, priv_b, pub_b = _fresh_key()
    kid_a = compute_kid(pub_a)
    kid_b = compute_kid(pub_b)
    now = datetime.now(timezone.utc)

    # Give the lexicographically-LATER kid the EARLIER activation time
    # so "sort by activated_at ASC" would put it first — then assert
    # the endpoint does NOT surface that order.
    if kid_a < kid_b:
        earlier_ts = now - timedelta(days=2)
        later_ts = now - timedelta(days=1)
        ka = MastioKey(
            kid=kid_a, pubkey_pem=pub_a, privkey_pem=priv_a, cert_pem=None,
            created_at=later_ts, activated_at=later_ts,
            deprecated_at=None, expires_at=None,
        )
        kb = MastioKey(
            kid=kid_b, pubkey_pem=pub_b, privkey_pem=priv_b, cert_pem=None,
            created_at=earlier_ts, activated_at=earlier_ts,
            deprecated_at=now - timedelta(seconds=10),
            expires_at=now + timedelta(days=30),
        )
    else:
        earlier_ts = now - timedelta(days=2)
        later_ts = now - timedelta(days=1)
        ka = MastioKey(
            kid=kid_a, pubkey_pem=pub_a, privkey_pem=priv_a, cert_pem=None,
            created_at=earlier_ts, activated_at=earlier_ts,
            deprecated_at=now - timedelta(seconds=10),
            expires_at=now + timedelta(days=30),
        )
        kb = MastioKey(
            kid=kid_b, pubkey_pem=pub_b, privkey_pem=priv_b, cert_pem=None,
            created_at=later_ts, activated_at=later_ts,
            deprecated_at=None, expires_at=None,
        )

    # Pre-sort by activated_at ASC (what the legacy query would have
    # yielded) so the endpoint-under-test has to re-sort or it will
    # leak the activation order.
    keys_in_activation_order = sorted(
        [ka, kb], key=lambda k: k.activated_at,
    )

    app = FastAPI()
    app.include_router(jwks_router)
    app.state.local_keystore = _FakeKeyStore(keys=keys_in_activation_order)

    with TestClient(app) as client:
        r = client.get("/.well-known/jwks-local.json")
        assert r.status_code == 200, r.text
        emitted_kids = [k["kid"] for k in r.json()["keys"]]

    assert emitted_kids == sorted(emitted_kids), (
        "JWKS must emit keys in kid-sorted order (#282), "
        f"got {emitted_kids}"
    )
