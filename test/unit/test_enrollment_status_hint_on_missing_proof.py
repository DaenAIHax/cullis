"""B-2 dogfood fix tests — ``EnrollmentStatusResponse.detail`` hint.

When a cold-reader agent dev polls ``GET /v1/enrollment/{sid}/status``
after the admin has approved BUT did not pass the
``X-Enrollment-Proof`` header, the server used to return a bare
``{"status": "approved"}`` with every sensitive field nulled out and
no human-readable hint why. Result: every open-source dev who hadn't
read the router source bounced silently.

The fix populates an optional ``detail`` field in that exact
"approved-but-no-proof" combination, pointing the caller at the proof
header mechanism + the doc page. The M-onb-1 audit gate stays intact:
``cert_pem`` / ``agent_id`` / ``capabilities`` are still nulled out
without a valid proof.

These tests verify both halves on a live FastAPI app: the route
behaviour AND the schema field declaration.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment.router import router as enrollment_router
from mcp_proxy.enrollment.schemas import EnrollmentStatusResponse


# ── Schema declaration: detail field present + optional ───────────────


def test_status_response_carries_optional_detail_field() -> None:
    """The schema must expose ``detail: str | None``. Pinning this stops
    a future schema sweep from accidentally dropping it (the field is
    invisible on the happy path so the absence would not surface in
    other tests)."""
    fields = EnrollmentStatusResponse.model_fields
    assert "detail" in fields
    # Same shape as the other null-by-default fields on the response.
    assert fields["detail"].default is None


def test_status_response_does_not_carry_cert_chain_pem() -> None:
    """B-4 follow-up (2026-05-25): ``cert_pem`` already concatenates
    ``leaf || Mastio Intermediate`` server-side, so there is no
    separate ``cert_chain_pem`` field on the status response. Pinning
    the absence keeps a future schema sweep from re-introducing the
    duplicated-intermediate bug that broke ``from_identity_dir``
    sibling auto-discovery."""
    fields = EnrollmentStatusResponse.model_fields
    assert "cert_chain_pem" not in fields


# ── Route behaviour: detail fires only in the "approved-no-proof" combo ─


_ADMIN_SECRET = "test-admin-secret-enrollment-hint"


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite + full alembic chain.

    Same shape as ``test_admin_agents_atomic_enroll.proxy_db`` so the
    enrollment table is created via migrations (the column list on
    ``pending_enrollments`` is large enough that ``metadata.create_all``
    drifts from migrations 0003 + 0006 + later updates).
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", _ADMIN_SECRET)
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "enrollment_hint.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _make_app() -> FastAPI:
    """Bare app with only the enrollment router mounted. The status
    route doesn't depend on ``agent_manager`` after the B-4 cleanup,
    so no stub is required: ``cert_pem`` is read straight off the
    pending_enrollments row."""
    app = FastAPI()
    app.include_router(enrollment_router)
    return app


async def _seed_approved_enrollment(
    *,
    session_id: str,
    pubkey_pem: str,
    cert_pem: str,
    agent_id: str = "acme::dashboard-agent",
    capabilities: list[str] | None = None,
) -> None:
    """Insert a pending → approved row directly. Simulates the state
    after the admin clicks Approve in the dashboard, without exercising
    the full ``approve()`` machinery (which needs an AgentManager + CA
    + binding publisher)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    expires = (
        datetime.now(timezone.utc) + timedelta(minutes=30)
    ).isoformat(timespec="seconds")
    caps_json = json.dumps(capabilities or ["llm.chat"])
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO pending_enrollments (
                    session_id, pubkey_pem, pubkey_fingerprint,
                    requester_name, requester_email, reason, device_info,
                    status, created_at, expires_at,
                    decided_at, decided_by,
                    agent_id_assigned, capabilities_assigned, cert_pem
                ) VALUES (
                    :sid, :pk, 'deadbeef',
                    :name, :email, NULL, NULL,
                    'approved', :created, :expires,
                    :decided, 'admin',
                    :agent_id, :caps, :cert
                )"""
            ),
            {
                "sid": session_id,
                "pk": pubkey_pem,
                "name": "alice",
                "email": "alice@example.com",
                "created": now,
                "expires": expires,
                "decided": now,
                "agent_id": agent_id,
                "caps": caps_json,
                "cert": cert_pem,
            },
        )


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.asyncio
async def test_approved_without_proof_returns_detail_hint(proxy_db):
    """Approved row + missing ``X-Enrollment-Proof`` header → response
    carries the human-readable hint AND keeps the sensitive fields
    nulled out (PoP gate unchanged)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pubkey_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    session_id = "sid-approved-noproof"
    await _seed_approved_enrollment(
        session_id=session_id,
        pubkey_pem=pubkey_pem,
        cert_pem="-----BEGIN CERTIFICATE-----\nFAKE-LEAF\n-----END CERTIFICATE-----\n",
    )

    client = TestClient(_make_app())
    r = client.get(f"/v1/enrollment/{session_id}/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    # Sensitive fields stay nulled — PoP gate unchanged. B-4 follow-up:
    # ``cert_chain_pem`` field is removed entirely; verify it's absent
    # so the schema sweep doesn't drift back.
    assert body["cert_pem"] is None
    assert "cert_chain_pem" not in body
    assert body["agent_id"] is None
    assert body["capabilities"] is None
    # Hint is populated and includes the canonical message string + the
    # session_id so the caller knows exactly what to sign.
    assert body["detail"] is not None
    assert "X-Enrollment-Proof" in body["detail"]
    assert f"enrollment-status:v1|{session_id}" in body["detail"]
    assert "docs/operate/enrollment-protocol.md" in body["detail"]


@pytest.mark.asyncio
async def test_approved_with_valid_proof_releases_cert_and_no_detail(proxy_db):
    """Same row, this time WITH a valid proof header → cert_pem +
    agent_id + capabilities populated, detail stays None."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pubkey_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    session_id = "sid-approved-withproof"
    cert_pem = "-----BEGIN CERTIFICATE-----\nFAKE-LEAF\n-----END CERTIFICATE-----\n"
    await _seed_approved_enrollment(
        session_id=session_id,
        pubkey_pem=pubkey_pem,
        cert_pem=cert_pem,
    )

    # Sign the canonical message exactly as the SDK does.
    canonical = f"enrollment-status:v1|{session_id}".encode()
    proof = _b64url_nopad(priv.sign(canonical, ec.ECDSA(hashes.SHA256())))

    client = TestClient(_make_app())
    r = client.get(
        f"/v1/enrollment/{session_id}/status",
        headers={"X-Enrollment-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["cert_pem"] == cert_pem
    assert body["agent_id"] == "acme::dashboard-agent"
    assert body["capabilities"] == ["llm.chat"]
    # Detail must be absent on the happy path so existing SDK callers
    # don't surface confusing hint text.
    assert body["detail"] is None


@pytest.mark.asyncio
async def test_pending_status_has_no_detail(proxy_db):
    """A still-pending row → no detail, no hint. The hint is scoped
    strictly to the approved-but-no-proof combination to avoid noise."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    expires = (
        datetime.now(timezone.utc) + timedelta(minutes=30)
    ).isoformat(timespec="seconds")
    async with get_db() as conn:
        await conn.execute(
            text(
                """INSERT INTO pending_enrollments (
                    session_id, pubkey_pem, pubkey_fingerprint,
                    requester_name, requester_email, reason, device_info,
                    status, created_at, expires_at
                ) VALUES (
                    'sid-pending', 'fake', 'fp',
                    'alice', 'alice@example.com', NULL, NULL,
                    'pending', :created, :expires
                )"""
            ),
            {"created": now, "expires": expires},
        )

    client = TestClient(_make_app())
    r = client.get("/v1/enrollment/sid-pending/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["detail"] is None
    assert body["cert_pem"] is None


@pytest.mark.asyncio
async def test_approved_with_invalid_proof_returns_detail_hint(proxy_db):
    """Garbage proof header (wrong key, malformed sig) → treated as
    missing → detail hint fires, no cert leak."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pubkey_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    session_id = "sid-approved-badproof"
    await _seed_approved_enrollment(
        session_id=session_id,
        pubkey_pem=pubkey_pem,
        cert_pem="-----BEGIN CERTIFICATE-----\nFAKE-LEAF\n-----END CERTIFICATE-----\n",
    )

    # Random bytes that won't verify against the keypair on the row.
    bogus_proof = _b64url_nopad(b"\x00" * 70)

    client = TestClient(_make_app())
    r = client.get(
        f"/v1/enrollment/{session_id}/status",
        headers={"X-Enrollment-Proof": bogus_proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["cert_pem"] is None
    assert body["detail"] is not None
    assert "X-Enrollment-Proof" in body["detail"]
