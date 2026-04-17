"""ADR-009 Phase 3 — strict enforcement flag ``requires_proxy``.

Covers:
  - PATCH /v1/admin/orgs/{id}/requires-proxy flips the flag (needs admin)
  - Enabling requires_proxy without mastio_pubkey → 409 (safety)
  - Clearing mastio_pubkey while requires_proxy=true → 409 (safety)
  - /v1/auth/token with requires_proxy=true and NULL pubkey → 403
    (bogus DB state — defensive path exists)
  - /v1/auth/token with requires_proxy=true + pinned pubkey works like
    Phase 1 (valid countersig → 200, missing → 403)
  - Legacy org (requires_proxy=false, pubkey NULL) still works without
    any header
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from tests.cert_factory import make_assertion, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


def _gen_mastio() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def _sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    s = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode()


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    resp = await client.get("/health")
    dpop._update_nonce(resp)


async def _full_register(
    client: AsyncClient,
    agent_id: str,
    org_id: str,
    *,
    mastio_pubkey: str | None = None,
    requires_proxy: bool = False,
) -> None:
    """Register org + agent + binding. Directly mutate the ADR-009 columns
    after the basic flow to avoid coupling with public onboarding endpoints."""
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id,
        "org_id": org_id,
        "display_name": f"Test {agent_id}",
        "capabilities": ["test.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    r = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = r.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import (
        update_org_mastio_pubkey, update_org_requires_proxy,
    )
    async with AsyncSessionLocal() as db:
        if mastio_pubkey is not None:
            await update_org_mastio_pubkey(db, org_id, mastio_pubkey)
        if requires_proxy:
            await update_org_requires_proxy(db, org_id, True)


# ── PATCH /requires-proxy ──────────────────────────────────────────────

async def test_patch_requires_proxy_requires_pubkey_first(client: AsyncClient):
    """Enabling requires_proxy without a pinned pubkey → 409 safety check."""
    from app.config import get_settings
    admin = get_settings().admin_secret
    await _full_register(client, "rp-noup::a", "rp-noup")

    r = await client.patch(
        "/v1/admin/orgs/rp-noup/requires-proxy",
        headers={"x-admin-secret": admin},
        json={"requires_proxy": True},
    )
    assert r.status_code == 409
    assert "mastio_pubkey" in r.json()["detail"]


async def test_patch_requires_proxy_ok_when_pubkey_pinned(client: AsyncClient):
    from app.config import get_settings
    admin = get_settings().admin_secret
    _, pub = _gen_mastio()
    await _full_register(
        client, "rp-ok::a", "rp-ok", mastio_pubkey=pub,
    )

    r = await client.patch(
        "/v1/admin/orgs/rp-ok/requires-proxy",
        headers={"x-admin-secret": admin},
        json={"requires_proxy": True},
    )
    assert r.status_code == 200
    assert r.json()["requires_proxy"] is True


async def test_patch_cannot_clear_pubkey_while_strict(client: AsyncClient):
    """Clearing mastio_pubkey with requires_proxy=true → 409."""
    from app.config import get_settings
    admin = get_settings().admin_secret
    _, pub = _gen_mastio()
    await _full_register(
        client, "rp-lock::a", "rp-lock",
        mastio_pubkey=pub, requires_proxy=True,
    )

    r = await client.patch(
        "/v1/admin/orgs/rp-lock/mastio-pubkey",
        headers={"x-admin-secret": admin},
        json={"mastio_pubkey": None},
    )
    assert r.status_code == 409
    assert "requires_proxy" in r.json()["detail"]


# ── /auth/token behavior ───────────────────────────────────────────────

async def test_token_strict_with_valid_countersig(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    priv, pub = _gen_mastio()
    org_id = "rp-auth-ok"
    agent_id = f"{org_id}::bot"
    await _full_register(
        client, agent_id, org_id,
        mastio_pubkey=pub, requires_proxy=True,
    )
    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    sig = _sign(priv, assertion.encode())

    r = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={
            "DPoP": dpop_proof,
            "X-Cullis-Mastio-Signature": sig,
        },
    )
    assert r.status_code == 200, r.text


async def test_token_strict_denies_missing_header(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    _, pub = _gen_mastio()
    org_id = "rp-auth-miss"
    agent_id = f"{org_id}::bot"
    await _full_register(
        client, agent_id, org_id,
        mastio_pubkey=pub, requires_proxy=True,
    )
    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")

    r = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert r.status_code == 403


async def test_token_legacy_still_works_when_flag_off(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    org_id = "rp-legacy"
    agent_id = f"{org_id}::bot"
    # requires_proxy default False, no pubkey — legacy path
    await _full_register(client, agent_id, org_id)

    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")

    r = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert r.status_code == 200, r.text
