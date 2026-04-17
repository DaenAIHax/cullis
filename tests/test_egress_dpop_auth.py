"""Unit tests for the DPoP-bound egress dep (F-B-11 Phase 1).

Exercises ``mcp_proxy.auth.dpop_api_key.get_agent_from_dpop_api_key``
in isolation by bypassing the legacy bcrypt + rate-limit path — those
are covered by the existing ``tests/test_proxy_*`` integration suites
and are not the contract under test here.

Scope per F-B-11 Phase 1 (issue #181):
  * ``CULLIS_EGRESS_DPOP_MODE=off`` (default) → dep delegates; no DPoP.
  * ``...=optional`` → missing ``DPoP`` header accepted; when present,
    the proof is fully verified (htm/htu/jti/iat/ath + nonce).
  * ``...=required`` → missing ``DPoP`` header rejected (401 + WWW-
    Authenticate); valid proof accepted.
  * Invalid / malformed / replayed proofs rejected in every non-off mode.
  * Unknown mode string falls back to ``off`` with a warning.

Phase 2 (separate PR) will add the per-agent ``dpop_jkt`` binding, its
migration, and the enrollment-side population. Those assertions live
with that PR.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest
from fastapi import HTTPException

from mcp_proxy.auth import dpop as _dpop_mod
from mcp_proxy.auth import dpop_api_key as _dpop_api_key_mod
from mcp_proxy.auth.dpop_api_key import (
    compute_api_key_ath,
    get_agent_from_dpop_api_key,
)
from mcp_proxy.models import InternalAgent
from tests.cert_factory import make_dpop_key_pair, make_dpop_proof

pytestmark = pytest.mark.asyncio


# ── Helpers ─────────────────────────────────────────────────────────

class _FakeURL:
    def __init__(self, url: str) -> None:
        self._s = url
        self.path = urlparse(url).path

    def __str__(self) -> str:
        return self._s


class _FakeRequest:
    """Stand-in for starlette Request with just the attributes read by
    ``get_agent_from_dpop_api_key``."""

    def __init__(self, *, method: str, url: str, headers: dict | None) -> None:
        self.method = method
        self.url = _FakeURL(url)
        self.headers = headers or {}


def _make_request(
    headers: dict | None = None,
    method: str = "POST",
    url: str = "http://test/v1/egress/message/send",
) -> _FakeRequest:
    return _FakeRequest(method=method, url=url, headers=headers)


_FAKE_AGENT = InternalAgent(
    agent_id="fb11-test-agent",
    display_name="fb11-test",
    capabilities=[],
    created_at="2026-04-17T00:00:00Z",
    is_active=True,
    cert_pem=None,
)


@pytest.fixture
def bypass_legacy(monkeypatch):
    """Stub ``get_agent_from_api_key`` so the dep's own logic is what
    gets exercised — not bcrypt, DB lookup, or rate limiting."""
    async def _ok(_request):
        return _FAKE_AGENT

    monkeypatch.setattr(_dpop_api_key_mod, "get_agent_from_api_key", _ok)


@pytest.fixture
def force_mode(monkeypatch):
    """Set ``MCP_PROXY_EGRESS_DPOP_MODE`` + clear the ``get_settings``
    lru_cache so the new value is honoured."""
    from mcp_proxy.config import get_settings

    def _set(mode: str) -> None:
        monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", mode)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


def _fresh_nonce() -> str:
    """Prime the proxy-side DPoP nonce store and return the current nonce
    so proofs carry a value the verifier accepts."""
    return _dpop_mod.get_current_dpop_nonce()


def _valid_proof(
    api_key: str,
    *,
    method: str = "POST",
    url: str = "http://test/v1/egress/message/send",
    jti: str | None = None,
    nonce: str | None = None,
):
    """Build (proof, priv, jwk) so tests can regenerate variants."""
    priv, jwk = make_dpop_key_pair()
    proof = make_dpop_proof(
        priv, jwk, method, url,
        access_token=api_key,
        jti=jti,
        nonce=nonce or _fresh_nonce(),
    )
    return proof, priv, jwk


# ── mode=off (default) ──────────────────────────────────────────────

async def test_mode_off_delegates_without_dpop(bypass_legacy, force_mode):
    force_mode("off")
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": "sk_local_x_" + "a" * 32})
    )
    assert agent is _FAKE_AGENT


async def test_mode_off_ignores_bogus_dpop_header(bypass_legacy, force_mode):
    """In off mode a garbage DPoP header is NOT validated — legacy
    bearer runs unchanged. No token flag could ever unintentionally
    enable enforcement via a stray header."""
    force_mode("off")
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={
            "X-API-Key": "sk_local_x_" + "a" * 32,
            "DPoP": "not.a.real.jwt",
        })
    )
    assert agent is _FAKE_AGENT


# ── mode=optional ───────────────────────────────────────────────────

async def test_mode_optional_accepts_legacy_without_dpop(bypass_legacy, force_mode):
    """Grace period: clients without the DPoP header still work."""
    force_mode("optional")
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": "sk_local_x_" + "a" * 32})
    )
    assert agent is _FAKE_AGENT


async def test_mode_optional_accepts_valid_proof(bypass_legacy, force_mode):
    force_mode("optional")
    api_key = "sk_local_test_" + "b" * 32
    proof, _, _ = _valid_proof(api_key)
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
    )
    assert agent is _FAKE_AGENT


async def test_mode_optional_rejects_malformed_proof(bypass_legacy, force_mode):
    force_mode("optional")
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": "sk_x", "DPoP": "garbage"})
        )
    assert exc.value.status_code == 401


# ── mode=required ───────────────────────────────────────────────────

async def test_mode_required_rejects_missing_dpop(bypass_legacy, force_mode):
    force_mode("required")
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": "sk_x"})
        )
    assert exc.value.status_code == 401
    assert "DPoP" in exc.value.headers.get("WWW-Authenticate", "")


async def test_mode_required_accepts_valid_proof(
    bound_agent_factory, force_mode,
):
    """Mode=required + bound agent + matching proof → accepted.

    Phase 2 tightened the required path: an agent with NULL
    ``dpop_jkt`` is refused under required mode. The dedicated
    coverage of that behavior lives in
    ``test_unbound_agent_rejected_in_required_mode`` below.
    """
    from mcp_proxy.auth.dpop import compute_jkt
    force_mode("required")
    api_key = "sk_local_test_" + "c" * 32

    priv, jwk = make_dpop_key_pair()
    registered_jkt = compute_jkt(jwk)
    bound_agent_factory(registered_jkt)

    proof = make_dpop_proof(
        priv, jwk, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, nonce=_fresh_nonce(),
    )
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
    )
    assert agent.dpop_jkt == registered_jkt


# ── Proof binding invariants ────────────────────────────────────────

async def test_proof_bound_to_different_api_key_rejected(bypass_legacy, force_mode):
    """``ath`` must match sha256(X-API-Key). A proof built against
    key-A replayed with key-B in the header is rejected."""
    force_mode("optional")
    api_key_a = "sk_local_a_" + "d" * 32
    api_key_b = "sk_local_b_" + "e" * 32
    proof, _, _ = _valid_proof(api_key_a)
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key_b, "DPoP": proof})
        )
    assert exc.value.status_code == 401


async def test_proof_with_wrong_htm_rejected(bypass_legacy, force_mode):
    force_mode("optional")
    api_key = "sk_local_htm_" + "f" * 32
    # Proof claims GET; request arrives as POST.
    priv, jwk = make_dpop_key_pair()
    proof = make_dpop_proof(
        priv, jwk, "GET", "http://test/v1/egress/message/send",
        access_token=api_key, nonce=_fresh_nonce(),
    )
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
        )
    assert exc.value.status_code == 401


async def test_proof_with_wrong_htu_rejected(bypass_legacy, force_mode):
    force_mode("optional")
    api_key = "sk_local_htu_" + "g" * 32
    # Proof signed against a different URL than the request target.
    priv, jwk = make_dpop_key_pair()
    proof = make_dpop_proof(
        priv, jwk, "POST", "http://test/v1/egress/some/other/path",
        access_token=api_key, nonce=_fresh_nonce(),
    )
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
        )
    assert exc.value.status_code == 401


async def test_replayed_jti_rejected(bypass_legacy, force_mode):
    force_mode("optional")
    api_key = "sk_local_replay_" + "h" * 32
    jti = "fixed-jti-for-replay-" + "i" * 16
    # First request: accepted.
    priv, jwk = make_dpop_key_pair()
    nonce = _fresh_nonce()
    proof_1 = make_dpop_proof(
        priv, jwk, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, jti=jti, nonce=nonce,
    )
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": api_key, "DPoP": proof_1})
    )
    assert agent is _FAKE_AGENT

    # Second request: same jti, different proof signature (new ephemeral
    # key). Still rejected because the jti has been consumed.
    priv2, jwk2 = make_dpop_key_pair()
    proof_2 = make_dpop_proof(
        priv2, jwk2, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, jti=jti, nonce=nonce,
    )
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof_2})
        )
    assert exc.value.status_code == 401


# ── Unknown mode defensive behaviour ────────────────────────────────

async def test_unknown_mode_falls_back_to_off(bypass_legacy, monkeypatch):
    """Typos in the env var must NOT silently enable enforcement
    (``required``) nor silently drop DPoP (``optional``) — fall back to
    off with a logged warning."""
    from mcp_proxy.config import get_settings

    monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "Require")  # case wrong + typo
    get_settings.cache_clear()

    warnings: list[str] = []

    def _record(msg, *args, **kwargs):
        warnings.append(str(msg) % args if args else str(msg))

    monkeypatch.setattr(_dpop_api_key_mod._log, "warning", _record)

    try:
        # No DPoP header: in off mode legacy passes. In required mode it
        # would 401. So success here confirms fallback to off.
        agent = await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": "sk_x"})
        )
        assert agent is _FAKE_AGENT
        assert any("Unknown" in msg and "off" in msg for msg in warnings), (
            f"expected fallback warning, got: {warnings}"
        )
    finally:
        get_settings.cache_clear()


# ── compute_api_key_ath helper ──────────────────────────────────────

def test_compute_api_key_ath_matches_rfc9449():
    """``ath`` = ``base64url(sha256(api_key))``, no padding. SDKs will
    reuse this helper to emit proofs the server accepts."""
    import hashlib
    import base64

    api_key = "sk_local_ath_test_" + "z" * 16
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(api_key.encode()).digest()
    ).rstrip(b"=").decode("ascii")
    assert compute_api_key_ath(api_key) == expected


# ── F-B-11 Phase 2: JWK thumbprint binding ──────────────────────────
#
# After Phase 2, a cryptographically-valid proof is necessary but not
# sufficient: the keypair that signed it must be the one the agent
# registered at enrollment. Stored via ``internal_agents.dpop_jkt``
# (migration 0014) and surfaced on the ``InternalAgent`` model.


def _agent_with_jkt(jkt: str) -> InternalAgent:
    return InternalAgent(
        agent_id="fb11-phase2-bound-agent",
        display_name="fb11-p2",
        capabilities=[],
        created_at="2026-04-17T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt=jkt,
    )


@pytest.fixture
def bound_agent_factory(monkeypatch):
    """Return a helper that installs an agent with the given jkt as the
    fake legacy-dep return value."""
    def _install(jkt: str) -> InternalAgent:
        agent = _agent_with_jkt(jkt)

        async def _ok(_request):
            return agent

        monkeypatch.setattr(_dpop_api_key_mod, "get_agent_from_api_key", _ok)
        return agent

    return _install


async def test_bound_agent_accepts_proof_from_registered_key(
    bound_agent_factory, force_mode,
):
    """Agent has ``dpop_jkt`` registered. A proof signed by the matching
    keypair is accepted."""
    from mcp_proxy.auth.dpop import compute_jkt
    force_mode("optional")
    api_key = "sk_local_bound_ok_" + "a" * 32

    priv, jwk = make_dpop_key_pair()
    registered_jkt = compute_jkt(jwk)
    bound_agent_factory(registered_jkt)

    proof = make_dpop_proof(
        priv, jwk, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, nonce=_fresh_nonce(),
    )
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
    )
    assert agent.dpop_jkt == registered_jkt


async def test_bound_agent_rejects_proof_from_different_key(
    bound_agent_factory, force_mode,
):
    """Proof is cryptographically valid but signed by a keypair the
    agent never registered → 401 with a body that names the mismatch.
    This is the core F-B-11 Phase 2 invariant: key-possession proof
    only counts when it is THIS agent's key."""
    from mcp_proxy.auth.dpop import compute_jkt
    force_mode("optional")
    api_key = "sk_local_bound_mismatch_" + "b" * 32

    # Agent registers key A.
    priv_a, jwk_a = make_dpop_key_pair()
    registered_jkt = compute_jkt(jwk_a)
    bound_agent_factory(registered_jkt)

    # Attacker signs with their own key B.
    priv_b, jwk_b = make_dpop_key_pair()
    assert compute_jkt(jwk_b) != registered_jkt, (
        "sanity: keypairs are distinct"
    )
    proof = make_dpop_proof(
        priv_b, jwk_b, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, nonce=_fresh_nonce(),
    )

    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
        )
    assert exc.value.status_code == 401
    assert "not registered" in exc.value.detail.lower()


async def test_bound_agent_mismatch_rejected_in_required_mode_too(
    bound_agent_factory, force_mode,
):
    """The jkt pin applies in both ``optional`` and ``required`` modes
    — once the agent has a stored jkt, any non-matching proof is a
    hard reject."""
    from mcp_proxy.auth.dpop import compute_jkt
    force_mode("required")
    api_key = "sk_local_bound_required_" + "c" * 32

    priv_a, jwk_a = make_dpop_key_pair()
    registered_jkt = compute_jkt(jwk_a)
    bound_agent_factory(registered_jkt)

    priv_b, jwk_b = make_dpop_key_pair()
    proof = make_dpop_proof(
        priv_b, jwk_b, "POST", "http://test/v1/egress/message/send",
        access_token=api_key, nonce=_fresh_nonce(),
    )
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
        )
    assert exc.value.status_code == 401


async def test_unbound_agent_accepted_in_optional_grace(
    bypass_legacy, force_mode,
):
    """Agent has NULL ``dpop_jkt`` (pre-Phase-3, not re-enrolled). In
    ``optional`` mode a valid proof is accepted — grace period."""
    force_mode("optional")
    api_key = "sk_local_unbound_opt_" + "d" * 32
    proof, _, _ = _valid_proof(api_key)
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
    )
    assert agent is _FAKE_AGENT  # no jkt set
    assert agent.dpop_jkt is None


async def test_unbound_agent_rejected_in_required_mode(
    bypass_legacy, force_mode,
):
    """Agent has NULL ``dpop_jkt`` but mode is ``required``. Refuse so
    operators who flipped the flag before every Connector was
    re-enrolled see the gap surface instead of silently accepting
    proofs that have no binding. The error body tells the operator
    what to do next."""
    force_mode("required")
    api_key = "sk_local_unbound_req_" + "e" * 32
    proof, _, _ = _valid_proof(api_key)
    with pytest.raises(HTTPException) as exc:
        await get_agent_from_dpop_api_key(
            _make_request(headers={"X-API-Key": api_key, "DPoP": proof})
        )
    assert exc.value.status_code == 401
    assert "no DPoP key registered" in exc.value.detail.lower() or \
           "re-enroll" in exc.value.detail.lower()


async def test_unbound_agent_still_works_in_off_mode(
    bypass_legacy, force_mode,
):
    """Mode=off short-circuits BEFORE any jkt logic runs. A pre-Phase-3
    agent + mode=off is exactly the pre-F-B-11 state: legacy bearer
    works, DPoP header is ignored."""
    force_mode("off")
    agent = await get_agent_from_dpop_api_key(
        _make_request(headers={"X-API-Key": "sk_local_unbound_off_" + "f" * 32})
    )
    assert agent is _FAKE_AGENT
    assert agent.dpop_jkt is None
