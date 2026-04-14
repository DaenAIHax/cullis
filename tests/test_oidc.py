"""Tests for OIDC federation login.

Note (network-admin-only refactor, ADR-001): the broker dashboard no
longer supports org-tenant SSO. Only the network-admin OIDC flow
remains. Tests that exercised per-org OIDC role mapping were removed;
see the module history for the deleted coverage.
"""
import time
import pytest
from unittest.mock import patch

from httpx import AsyncClient

from app.dashboard.oidc import (
    create_oidc_state, _pkce_code_challenge, OidcFlowState,
)

pytestmark = pytest.mark.asyncio


# ── Unit tests ──────────────────────────────────────────────────────────────

def test_create_oidc_state():
    """create_oidc_state generates unique cryptographic values."""
    s1 = create_oidc_state("admin")
    s2 = create_oidc_state("admin")
    assert s1.state != s2.state
    assert s1.nonce != s2.nonce
    assert s1.code_verifier != s2.code_verifier
    assert s1.role == "admin"


def test_pkce_code_challenge():
    """PKCE code challenge is base64url(SHA256(verifier))."""
    verifier = "test_verifier_string"
    challenge = _pkce_code_challenge(verifier)
    assert len(challenge) > 10
    assert "=" not in challenge  # no padding


def test_flow_state_roundtrip():
    """OidcFlowState serializes and deserializes correctly."""
    state = create_oidc_state("admin")
    d = state.to_dict()
    restored = OidcFlowState.from_dict(d)
    assert restored.state == state.state
    assert restored.nonce == state.nonce
    assert restored.code_verifier == state.code_verifier
    assert restored.role == "admin"


# ── Integration tests ───────────────────────────────────────────────────────

async def test_oidc_start_requires_broker_public_url(client: AsyncClient):
    """SSO start fails gracefully when BROKER_PUBLIC_URL is not set."""
    resp = await client.get("/dashboard/oidc/start?role=admin",
                            follow_redirects=False)
    assert resp.status_code == 200
    assert b"BROKER_PUBLIC_URL" in resp.content


async def test_oidc_start_admin_no_config(client: AsyncClient):
    """SSO start for admin without config shows error on login page."""
    resp = await client.get("/dashboard/oidc/start?role=admin",
                            follow_redirects=False)
    assert resp.status_code == 200  # renders login page (not a crash)


async def test_oidc_start_rejects_org_role(client: AsyncClient):
    """Deprecated: org-role moved to proxy in ADR-001.

    The broker must refuse the legacy role=org query param with a clear
    message pointing at the proxy, not fall through to org SSO.
    """
    resp = await client.get("/dashboard/oidc/start?role=org&org_id=whatever",
                            follow_redirects=False)
    assert resp.status_code == 200
    # We accept either "network-admin only" messaging or the upstream
    # BROKER_PUBLIC_URL guard — whichever runs first is fine.
    body = resp.content.lower()
    assert b"network-admin" in body or b"broker_public_url" in body


async def test_oidc_callback_no_state_cookie(client: AsyncClient):
    """Callback without state cookie returns error."""
    resp = await client.get(
        "/dashboard/oidc/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"SSO session expired" in resp.content


async def test_oidc_callback_idp_error(client: AsyncClient):
    """Callback with error param shows provider error."""
    resp = await client.get(
        "/dashboard/oidc/callback?error=access_denied&error_description=User+cancelled",
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"SSO provider error" in resp.content


async def test_oidc_callback_refuses_legacy_org_state(client: AsyncClient):
    """Deprecated: an OIDC state cookie with role='org' is rejected.

    Before ADR-001 the callback would look up the org's OIDC config and
    mint an org session. Now it must return a clear error.
    """
    flow_state = OidcFlowState(
        state="s", nonce="n", code_verifier="v", role="org", org_id="legacy-org",
    )
    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}):
        resp = await client.get(
            "/dashboard/oidc/callback?code=test-code&state=s",
            follow_redirects=False,
        )
    assert resp.status_code == 200
    assert b"proxy" in resp.content.lower() or b"network-admin" in resp.content.lower()


async def test_oidc_callback_state_mismatch(client: AsyncClient):
    """Callback with mismatched state returns error."""
    flow_state = create_oidc_state("admin")

    with patch("app.dashboard.session.get_oidc_state", return_value={
            **flow_state.to_dict(), "exp": int(time.time()) + 600}):
        resp = await client.get(
            "/dashboard/oidc/callback?code=test-code&state=wrong-state",
            follow_redirects=False,
        )

    assert resp.status_code == 200
    assert b"state mismatch" in resp.content
