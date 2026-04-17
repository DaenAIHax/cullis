"""Audit F-B-2 regression — tenant-sealed orgs gate dashboard mutations.

Every dashboard mutation on an org must respect the ``organizations.sealed``
flag: sealed orgs require a short-lived per-org re-auth token on the admin
session cookie. The ``attach-ca`` onboarding flow seals the org at consume
time; network-admin-provisioned orgs start unsealed (backward compatible).

Scope of this module:
- Migration present on the stack (sealed column exists, default False).
- Attach-ca consume flips sealed → True.
- Plain admin session cannot mutate a sealed org (approve/reject/suspend/
  delete/unlock-ca/upload-ca/agent register/agent delete/agent cert rotate).
- Re-auth challenge mints a per-org scope that unlocks mutations for the
  configured TTL and is confined to that org (other sealed orgs stay
  locked).
- Unsealed orgs are unaffected (no behavior regression).
- Manual seal/unseal from the dashboard.
"""
import json
import time

import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_csrf(cookies: dict) -> str:
    cookie = cookies.get("cullis_session", "")
    if not cookie:
        return ""
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    import codecs
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        return json.loads(payload_str).get("csrf_token", "")
    except Exception:
        return ""


async def _admin_login(client: AsyncClient) -> tuple[dict, str]:
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    cookies = dict(resp.cookies)
    return cookies, _extract_csrf(cookies)


async def _seed_org(
    client: AsyncClient, cookies: dict, csrf: str, *, org_id: str,
    sealed: bool = False,
) -> None:
    """Create an org via the dashboard onboarding endpoint.

    The onboarding endpoint goes straight to sealed=False (it's the
    create-org path). To produce a sealed org we post-flip the flag via
    the /seal dashboard endpoint, which is what an admin would do
    manually (and exactly what attach-ca does automatically at consume).
    """
    from tests.cert_factory import get_org_ca_pem
    ca_pem = get_org_ca_pem(org_id)
    resp = await client.post(
        "/dashboard/orgs/onboard",
        data={
            "csrf_token": csrf,
            "org_id": org_id,
            "display_name": org_id.upper(),
            "secret": "s",
            "contact_email": "",
            "webhook_url": "",
            "ca_certificate": ca_pem,
            "action": "approve",
        },
        cookies=cookies,
    )
    assert resp.status_code == 200, resp.text

    if sealed:
        resp = await client.post(
            f"/dashboard/orgs/{org_id}/seal",
            data={"csrf_token": csrf}, cookies=cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303


async def _reauth(
    client: AsyncClient, cookies: dict, csrf: str, org_id: str,
) -> dict:
    """Clear the per-org re-auth challenge. Returns the refreshed cookie set."""
    resp = await client.post(
        f"/dashboard/orgs/{org_id}/unseal-reauth",
        data={
            "csrf_token": csrf,
            "password": get_settings().admin_secret,
            "next": "/dashboard/orgs",
        },
        cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    # The endpoint re-issues the session cookie with the scope baked in.
    new_cookies = dict(cookies)
    # httpx propagates Set-Cookie via resp.cookies; merge over the login set.
    for k, v in resp.cookies.items():
        new_cookies[k] = v
    return new_cookies


# ── Schema / default ──────────────────────────────────────────────────────────

async def test_sealed_column_defaults_false(db_session):
    """New orgs created through the plain register helper are unsealed."""
    from app.registry.org_store import register_org, get_org_by_id
    await register_org(
        db_session, org_id="seal-default", display_name="Seal Default",
        secret="s",
    )
    record = await get_org_by_id(db_session, "seal-default")
    assert record is not None
    assert record.sealed is False


async def test_set_org_sealed_helper(db_session):
    """The org_store helper flips the flag both ways."""
    from app.registry.org_store import register_org, get_org_by_id, set_org_sealed
    await register_org(db_session, org_id="seal-toggle",
                       display_name="T", secret="s")
    await set_org_sealed(db_session, "seal-toggle", True)
    rec = await get_org_by_id(db_session, "seal-toggle")
    assert rec.sealed is True
    await set_org_sealed(db_session, "seal-toggle", False)
    rec = await get_org_by_id(db_session, "seal-toggle")
    assert rec.sealed is False


# ── attach-ca onboarding ─────────────────────────────────────────────────────

async def test_attach_ca_seals_org(client: AsyncClient, db_session):
    """After attach-ca consume, the org's sealed flag is True."""
    from tests.cert_factory import get_org_ca_pem
    from app.registry.org_store import get_org_by_id
    org_id = "attach-seals"

    # Admin creates the stub org without CA.
    resp = await client.post(
        "/v1/registry/orgs", json={
            "org_id": org_id, "display_name": org_id.upper(), "secret": "ph",
        }, headers={"x-admin-secret": get_settings().admin_secret},
    )
    assert resp.status_code == 201, resp.text

    # Org starts unsealed.
    rec = await get_org_by_id(db_session, org_id)
    assert rec.sealed is False

    # Admin mints the attach-ca invite.
    resp = await client.post(
        f"/v1/admin/orgs/{org_id}/attach-invite",
        json={"label": "attach", "ttl_hours": 1},
        headers={"x-admin-secret": get_settings().admin_secret},
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["token"]

    # Proxy attaches CA — this seals the org.
    resp = await client.post("/v1/onboarding/attach", json={
        "ca_certificate": get_org_ca_pem(org_id),
        "invite_token": token,
        "secret": "proxy-secret",
    })
    assert resp.status_code == 200, resp.text

    # Force a fresh SQLAlchemy read — the onboarding flow committed on a
    # different session, so expire the local cache before re-fetching.
    db_session.expire_all()
    rec = await get_org_by_id(db_session, org_id)
    assert rec.sealed is True


# ── Enforcement on each mutation ─────────────────────────────────────────────

@pytest.mark.parametrize(
    "path",
    [
        "/dashboard/orgs/{org}/approve",
        "/dashboard/orgs/{org}/reject",
        "/dashboard/orgs/{org}/suspend",
        "/dashboard/orgs/{org}/delete",
        "/dashboard/orgs/{org}/unlock-ca",
        "/dashboard/orgs/{org}/unseal",
    ],
)
async def test_sealed_org_mutation_without_reauth_is_forbidden(
    client: AsyncClient, path: str,
):
    """Plain admin session posting an org mutation on a sealed org gets 403."""
    cookies, csrf = await _admin_login(client)
    org_id = f"sealed-{path.rsplit('/', 1)[-1]}"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    resp = await client.post(
        path.format(org=org_id),
        data={"csrf_token": csrf}, cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 403, resp.text
    assert "sealed" in resp.text.lower() or "re-auth" in resp.text.lower()


async def test_sealed_org_mutation_with_reauth_is_allowed(client: AsyncClient):
    """After a per-org re-auth, the admin can mutate the sealed org."""
    cookies, csrf = await _admin_login(client)
    org_id = "sealed-suspend-ok"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    cookies = await _reauth(client, cookies, csrf, org_id)
    csrf = _extract_csrf(cookies)  # cookie was re-issued → new CSRF-bearing payload

    resp = await client.post(
        f"/dashboard/orgs/{org_id}/suspend",
        data={"csrf_token": csrf}, cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text


async def test_reauth_scope_is_per_org(client: AsyncClient):
    """A re-auth for org A must NOT unlock mutations on sealed org B."""
    cookies, csrf = await _admin_login(client)
    await _seed_org(client, cookies, csrf, org_id="sealed-a", sealed=True)
    await _seed_org(client, cookies, csrf, org_id="sealed-b", sealed=True)

    cookies = await _reauth(client, cookies, csrf, "sealed-a")
    csrf = _extract_csrf(cookies)

    # A is unlocked — status change works.
    resp = await client.post(
        "/dashboard/orgs/sealed-a/suspend",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303

    # B is still locked — 403.
    resp = await client.post(
        "/dashboard/orgs/sealed-b/suspend",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_unsealed_org_mutation_unchanged(client: AsyncClient):
    """Existing, unsealed orgs behave exactly as before — no regression."""
    cookies, csrf = await _admin_login(client)
    org_id = "unsealed-ok"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=False)

    resp = await client.post(
        f"/dashboard/orgs/{org_id}/suspend",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303


async def test_reauth_bad_password_is_rejected(client: AsyncClient):
    """The re-auth form requires the actual admin password."""
    cookies, csrf = await _admin_login(client)
    org_id = "reauth-wrong"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    resp = await client.post(
        f"/dashboard/orgs/{org_id}/unseal-reauth",
        data={"csrf_token": csrf, "password": "wrong-" * 5,
              "next": "/dashboard/orgs"},
        cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 403

    # Sealed mutation still blocked.
    resp = await client.post(
        f"/dashboard/orgs/{org_id}/suspend",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_reauth_next_must_be_same_origin(client: AsyncClient):
    """An external ``next`` URL is ignored — we bounce back to /dashboard/orgs."""
    cookies, csrf = await _admin_login(client)
    org_id = "reauth-next-absolute"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    resp = await client.post(
        f"/dashboard/orgs/{org_id}/unseal-reauth",
        data={"csrf_token": csrf, "password": get_settings().admin_secret,
              "next": "https://evil.example.com/steal"},
        cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/orgs"


# ── Agent-level mutations on sealed orgs ─────────────────────────────────────

async def test_agent_delete_on_sealed_org_gated(client: AsyncClient):
    """Deleting an agent that belongs to a sealed org requires re-auth."""
    from app.registry.store import register_agent
    from app.registry.binding_store import create_binding
    from tests.conftest import TestSessionLocal

    cookies, csrf = await _admin_login(client)
    org_id = "sealed-agent-del"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    # Seed an agent directly via the registry helper so we don't hit the
    # sealed-gated /agents/register dashboard endpoint here.
    agent_id = f"{org_id}::a1"
    async with TestSessionLocal() as db:
        await register_agent(
            db, agent_id=agent_id, org_id=org_id,
            display_name="A1", capabilities=[], metadata={},
        )
        await create_binding(db, org_id, agent_id, scope=[])

    resp = await client.post(
        f"/dashboard/agents/{agent_id}/delete",
        data={"csrf_token": csrf}, cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_agent_register_on_sealed_org_gated(client: AsyncClient):
    """The /agents/register dashboard endpoint is gated on sealed orgs."""
    cookies, csrf = await _admin_login(client)
    org_id = "sealed-agent-reg"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    resp = await client.post(
        "/dashboard/agents/register",
        data={
            "csrf_token": csrf, "org_id": org_id,
            "agent_name": "a2", "display_name": "A2",
            "capabilities": "", "description": "",
        },
        cookies=cookies,
    )
    assert resp.status_code == 403
    assert "sealed" in resp.text.lower() or "re-auth" in resp.text.lower()


async def test_agent_register_after_reauth_succeeds(client: AsyncClient):
    """After a per-org re-auth, agent registration on a sealed org is allowed."""
    cookies, csrf = await _admin_login(client)
    org_id = "sealed-reg-ok"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    cookies = await _reauth(client, cookies, csrf, org_id)
    csrf = _extract_csrf(cookies)

    resp = await client.post(
        "/dashboard/agents/register",
        data={
            "csrf_token": csrf, "org_id": org_id,
            "agent_name": "a3", "display_name": "A3",
            "capabilities": "", "description": "",
        },
        cookies=cookies,
    )
    assert resp.status_code == 200
    assert "registered" in resp.text.lower()


# ── Manual seal/unseal ────────────────────────────────────────────────────────

async def test_manual_seal_is_allowed_without_reauth(client: AsyncClient, db_session):
    """The /seal action tightens protection — always safe without re-auth."""
    from app.registry.org_store import get_org_by_id

    cookies, csrf = await _admin_login(client)
    org_id = "manual-seal"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=False)

    resp = await client.post(
        f"/dashboard/orgs/{org_id}/seal",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303

    db_session.expire_all()
    rec = await get_org_by_id(db_session, org_id)
    assert rec.sealed is True


async def test_manual_unseal_requires_reauth(client: AsyncClient, db_session):
    """The /unseal action REMOVES protection — sealed-gated."""
    from app.registry.org_store import get_org_by_id

    cookies, csrf = await _admin_login(client)
    org_id = "manual-unseal"
    await _seed_org(client, cookies, csrf, org_id=org_id, sealed=True)

    # Without re-auth: 403.
    resp = await client.post(
        f"/dashboard/orgs/{org_id}/unseal",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 403

    # With re-auth: allowed.
    cookies = await _reauth(client, cookies, csrf, org_id)
    csrf = _extract_csrf(cookies)
    resp = await client.post(
        f"/dashboard/orgs/{org_id}/unseal",
        data={"csrf_token": csrf}, cookies=cookies, follow_redirects=False,
    )
    assert resp.status_code == 303

    db_session.expire_all()
    rec = await get_org_by_id(db_session, org_id)
    assert rec.sealed is False


# ── Session / TTL ─────────────────────────────────────────────────────────────

async def test_reauth_ttl_expiry_drops_from_session():
    """Expired re-auth entries are dropped at ``get_session`` read time."""
    from app.dashboard.session import (
        get_session, _sign, _COOKIE_NAME, REAUTH_TTL_SECONDS,
    )

    # Manually craft a session whose reauth_orgs entry is already stale.
    past = int(time.time()) - 10
    payload = json.dumps({
        "role": "admin", "org_id": None, "csrf_token": "x",
        "exp": int(time.time()) + 3600,
        "reauth_orgs": {"stale-org": past, "fresh-org": int(time.time()) + 60},
    })
    signed = _sign(payload)

    # Minimal request shim — we only need request.cookies.
    class _Req:
        def __init__(self, cookies: dict):
            self.cookies = cookies

    session = get_session(_Req({_COOKIE_NAME: signed}))
    assert session.logged_in is True
    assert session.has_reauth_scope("fresh-org") is True
    assert session.has_reauth_scope("stale-org") is False
    # Positive sanity: TTL constant is the expected 5 minutes.
    assert REAUTH_TTL_SECONDS == 5 * 60
