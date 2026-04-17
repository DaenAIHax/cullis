"""Audit F-B-7 — ``POST /v1/registry/orgs/{org_id}/certificate`` must
not leak org existence.

Same pattern as F-B-6, same helper. Before the fix the endpoint
returned 404 on missing org and 401 on wrong secret, distinguishing the
two cases by status code and timing (no bcrypt on miss vs one bcrypt
on hit). After the fix both paths collapse to 403 with bcrypt on
every branch via ``verify_org_credentials(org, secret, active_only=True)``.

Unlike ``/orgs/me``, this endpoint keeps ``active_only=True``: there is
no legitimate use case for uploading a CA certificate to an org that
is not ``active``.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


VALID_CA_PEM = None  # lazily built once at import


def _make_ca_pem() -> str:
    """Build a minimal valid CA cert so the cert-shape checks downstream
    do not mask auth failures with a 400 Bad Request."""
    global VALID_CA_PEM
    if VALID_CA_PEM is not None:
        return VALID_CA_PEM

    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "fb7-test"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "fb7-test"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    VALID_CA_PEM = cert.public_bytes(serialization.Encoding.PEM).decode()
    return VALID_CA_PEM


async def _register_org(client: AsyncClient, org_id: str, secret: str) -> None:
    resp = await client.post(
        "/v1/registry/orgs",
        json={"org_id": org_id, "display_name": org_id, "secret": secret},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 201, resp.text


# ── Primary regression: 403 whether missing, wrong secret, or inactive ──

async def test_certificate_missing_org_returns_403(client: AsyncClient):
    resp = await client.post(
        "/v1/registry/orgs/fb7-missing/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-missing", "x-org-secret": "whatever"},
    )
    assert resp.status_code == 403
    body = resp.json()
    # Body must not leak org-existence info.
    assert "not found" not in body.get("detail", "").lower()


async def test_certificate_wrong_secret_returns_403(client: AsyncClient):
    await _register_org(client, "fb7-org-a", "real-secret-fb7a")
    resp = await client.post(
        "/v1/registry/orgs/fb7-org-a/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-org-a", "x-org-secret": "wrong"},
    )
    assert resp.status_code == 403


async def test_certificate_missing_vs_wrong_are_indistinguishable(client: AsyncClient):
    """Status code AND detail body must be identical — the whole
    F-B-7 invariant."""
    await _register_org(client, "fb7-org-b", "real-secret-fb7b")
    missing = await client.post(
        "/v1/registry/orgs/fb7-absent/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-absent", "x-org-secret": "x"},
    )
    wrong_secret = await client.post(
        "/v1/registry/orgs/fb7-org-b/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-org-b", "x-org-secret": "wrong"},
    )
    assert missing.status_code == wrong_secret.status_code == 403
    assert missing.json() == wrong_secret.json()


# ── org_id mismatch stays its own 403 (different semantic) ──

async def test_certificate_mismatch_org_id_still_blocks_with_403(client: AsyncClient):
    """``x-org-id`` header vs path param mismatch is a different
    semantic (caller authenticated as a different org) and the 403
    body is allowed to differ. What matters is that no enumeration
    oracle exists AFTER the mismatch check passes."""
    await _register_org(client, "fb7-org-c", "real-secret-fb7c")
    resp = await client.post(
        "/v1/registry/orgs/fb7-org-c/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "some-other-org", "x-org-secret": "real-secret-fb7c"},
    )
    assert resp.status_code == 403


# ── Happy path + active_only semantics ──

async def test_certificate_active_org_correct_secret_200(client: AsyncClient):
    await _register_org(client, "fb7-org-d", "real-secret-fb7d")
    resp = await client.post(
        "/v1/registry/orgs/fb7-org-d/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-org-d", "x-org-secret": "real-secret-fb7d"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_id"] == "fb7-org-d"
    assert body["ca_certificate_loaded"] is True


async def test_certificate_pending_org_rejected_with_403(
    client: AsyncClient, db_session,
):
    """Uploading a CA to a non-active org is refused. Distinct from
    ``/orgs/me`` which needs to accept pending for polling — here
    there is no legitimate pending use case (the org hasn't been
    approved yet, you shouldn't be rotating its CA)."""
    from app.registry.org_store import OrganizationRecord
    import bcrypt
    import json

    secret = "pending-secret-fb7"
    record = OrganizationRecord(
        org_id="fb7-org-pending",
        display_name="pending",
        secret_hash=bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=4)).decode(),
        metadata_json=json.dumps({}),
        status="pending",
    )
    db_session.add(record)
    await db_session.commit()

    resp = await client.post(
        "/v1/registry/orgs/fb7-org-pending/certificate",
        json={"ca_certificate": _make_ca_pem()},
        headers={"x-org-id": "fb7-org-pending", "x-org-secret": secret},
    )
    assert resp.status_code == 403
