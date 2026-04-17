"""Audit F-B-6 — ``GET /v1/registry/orgs/me`` must not leak org existence.

Before this fix the endpoint returned 404 on a missing org and 403 on
wrong secret, differentiating the two cases by status code AND by
response latency (no bcrypt on miss vs one bcrypt on hit).

The fix reuses ``verify_org_credentials(org, secret, active_only=False)``
from ``app/registry/org_store.py`` so both paths:
  * respond with 403
  * run bcrypt once (dummy hash on miss, real hash on hit)

Non-active orgs (pending / rejected / suspended) are still allowed to
authenticate on this specific endpoint because the MCP Proxy polls it
during onboarding to learn when it becomes ``active`` — that is the
only authenticated surface with ``active_only=False``.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


async def _register_org(client: AsyncClient, org_id: str, secret: str) -> None:
    resp = await client.post(
        "/v1/registry/orgs",
        json={"org_id": org_id, "display_name": org_id, "secret": secret},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 201, resp.text


# ── Primary regression: unified 403 response ───────────────────────

async def test_orgs_me_missing_org_returns_403_not_404(client: AsyncClient):
    resp = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "nonexistent-org", "x-org-secret": "whatever"},
    )
    assert resp.status_code == 403
    # The body must NOT say "not found" or mention "Organization"
    # existence — the 403 path is the unified response shape.
    body = resp.json()
    assert "not found" not in body.get("detail", "").lower()


async def test_orgs_me_wrong_secret_returns_403(client: AsyncClient):
    await _register_org(client, "fb6-org-a", "good-secret-fb6a")
    resp = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "fb6-org-a", "x-org-secret": "wrong-secret"},
    )
    assert resp.status_code == 403


async def test_orgs_me_missing_vs_wrong_are_indistinguishable(client: AsyncClient):
    """The response status AND detail body must be byte-identical between
    'org not registered' and 'org registered but wrong secret' — that's
    the whole point of F-B-6."""
    await _register_org(client, "fb6-org-b", "good-secret-fb6b")

    missing = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "definitely-not-here", "x-org-secret": "x"},
    )
    wrong_secret = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "fb6-org-b", "x-org-secret": "wrong"},
    )

    assert missing.status_code == wrong_secret.status_code == 403
    assert missing.json() == wrong_secret.json()


# ── Happy paths stay functional ────────────────────────────────────

async def test_orgs_me_active_org_correct_secret_200(client: AsyncClient):
    await _register_org(client, "fb6-org-c", "good-secret-fb6c")
    resp = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "fb6-org-c", "x-org-secret": "good-secret-fb6c"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_id"] == "fb6-org-c"
    assert body["status"] == "active"


async def test_orgs_me_pending_org_can_poll_status(client: AsyncClient, db_session):
    """A pending org must still authenticate on /me so the MCP Proxy
    can poll for its approval. Regression guard on the active_only=False
    decision path."""
    from app.registry.org_store import OrganizationRecord, _DUMMY_HASH
    import bcrypt
    import json

    secret = "pending-secret-fb6"
    record = OrganizationRecord(
        org_id="fb6-org-pending",
        display_name="pending org",
        secret_hash=bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=4)).decode(),
        metadata_json=json.dumps({}),
        status="pending",
    )
    db_session.add(record)
    await db_session.commit()

    resp = await client.get(
        "/v1/registry/orgs/me",
        headers={"x-org-id": "fb6-org-pending", "x-org-secret": secret},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    # Sanity: unrelated dummy-hash import sanity-check (catches an accidental
    # removal of the constant-time helper — if _DUMMY_HASH disappears the
    # enumeration path reopens).
    assert isinstance(_DUMMY_HASH, str) and _DUMMY_HASH.startswith("$2")


# ── Timing oracle: bcrypt runs on both paths ───────────────────────

async def test_orgs_me_bcrypt_runs_on_missing_org(client: AsyncClient):
    """Closest deterministic proxy for the timing oracle: patch
    ``bcrypt.checkpw`` and assert it was invoked even when the org does
    not exist. Before the fix the 404 path short-circuited before any
    bcrypt call, which is what made the timing side channel measurable.
    """
    # Patch at the module where the helper imports bcrypt from.
    with patch("app.registry.org_store.bcrypt.checkpw", wraps=__import__("bcrypt").checkpw) as spy:
        resp = await client.get(
            "/v1/registry/orgs/me",
            headers={"x-org-id": "very-definitely-missing", "x-org-secret": "x"},
        )
    assert resp.status_code == 403
    # At least one bcrypt check happened for the missing-org branch.
    assert spy.call_count >= 1


async def test_orgs_me_bcrypt_runs_on_wrong_secret(client: AsyncClient):
    await _register_org(client, "fb6-org-d", "good-secret-fb6d")
    with patch("app.registry.org_store.bcrypt.checkpw", wraps=__import__("bcrypt").checkpw) as spy:
        resp = await client.get(
            "/v1/registry/orgs/me",
            headers={"x-org-id": "fb6-org-d", "x-org-secret": "wrong"},
        )
    assert resp.status_code == 403
    assert spy.call_count >= 1


# ── Unit test on verify_org_credentials helper ──────────────────────

def test_verify_org_credentials_active_only_false_accepts_pending():
    """Unit guard on the new ``active_only=False`` contract."""
    from app.registry.org_store import OrganizationRecord, verify_org_credentials
    import bcrypt
    import json

    secret = "unit-test-secret"
    org = OrganizationRecord(
        org_id="unit",
        display_name="unit",
        secret_hash=bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=4)).decode(),
        metadata_json=json.dumps({}),
        status="pending",
    )

    assert verify_org_credentials(org, secret, active_only=False) is True
    assert verify_org_credentials(org, "wrong", active_only=False) is False
    # Default active_only=True still rejects pending.
    assert verify_org_credentials(org, secret) is False


def test_verify_org_credentials_missing_runs_bcrypt_even_when_active_only_false():
    from app.registry.org_store import verify_org_credentials
    with patch(
        "app.registry.org_store.bcrypt.checkpw",
        wraps=__import__("bcrypt").checkpw,
    ) as spy:
        result = verify_org_credentials(None, "any-secret", active_only=False)
    assert result is False
    assert spy.call_count == 1
