"""ADR-011 Phase 3 Phase A — ``POST /auth/token`` deprecation headers + audit.

Successful token issuance must now carry:
- ``Deprecation: true`` (RFC 8594)
- ``Sunset`` HTTP-date ~90 days out
- ``Link`` rel=sunset pointing to the migration doc
- audit event ``auth.legacy_token`` per hit with the auth mode + sunset
  window the dashboard can filter on

Failures (unauth, wrong binding, etc.) MUST NOT carry these headers —
they're advisory for successful clients only; emitting them on 401 would
leak the deprecation state to unauthenticated probes and clutter the
audit stream with noise.
"""
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient

from app.auth.router import _DEPRECATION_GRACE_DAYS
from tests.cert_factory import make_assertion
from tests.test_auth import _register_agent, _prime_nonce

pytestmark = pytest.mark.asyncio


async def test_legacy_token_response_advertises_deprecation_headers(
    client: AsyncClient, dpop
):
    """Happy path 200 carries Deprecation+Sunset+Link."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "depr-org::agent-1", "depr-org")

    assertion = make_assertion("depr-org::agent-1", "depr-org")
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )

    assert resp.status_code == 200
    assert resp.headers.get("Deprecation") == "true"
    assert "Sunset" in resp.headers
    # Sunset must parse as an HTTP-date and land within the advertised
    # grace window (allow a 1-day slack for clock drift).
    from email.utils import parsedate_to_datetime
    sunset = parsedate_to_datetime(resp.headers["Sunset"])
    delta = sunset - datetime.now(timezone.utc)
    assert 0 <= delta.days <= _DEPRECATION_GRACE_DAYS
    # Link header present + rel=sunset pointing to the migration guide.
    link = resp.headers.get("Link", "")
    assert 'rel="sunset"' in link
    assert "/docs/migration/from-direct-login" in link


async def test_legacy_token_emits_audit_event_on_success(
    client: AsyncClient, dpop, db_session,
):
    """Every 200 on /auth/token writes an ``auth.legacy_token`` row that
    the dashboard can filter — the migration dashboard story needs this."""
    import json as _json

    from sqlalchemy import desc, select

    from app.db.audit import AuditLog

    await _prime_nonce(client, dpop)
    await _register_agent(client, "depr-audit::agent-1", "depr-audit")

    assertion = make_assertion("depr-audit::agent-1", "depr-audit")
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200

    # Fetch the freshest ``auth.legacy_token`` row for this agent.
    rows = (await db_session.execute(
        select(AuditLog)
        .where(AuditLog.event_type == "auth.legacy_token")
        .where(AuditLog.agent_id == "depr-audit::agent-1")
        .order_by(desc(AuditLog.id))
        .limit(1)
    )).scalars().all()
    assert rows, "auth.legacy_token audit row not written"
    row = rows[0]
    assert row.result == "ok"
    details = _json.loads(row.details) if row.details else {}
    assert details.get("auth_mode") in ("spiffe", "byoca")
    assert details.get("sunset_days") == _DEPRECATION_GRACE_DAYS
    assert details.get("migration_endpoint", "").startswith(
        "/v1/admin/agents/enroll/"
    )


async def test_denial_path_does_not_advertise_deprecation(
    client: AsyncClient, dpop,
):
    """401/403 responses do NOT carry Deprecation — the signal is for
    clients that would otherwise succeed, not for unauth probes."""
    # Unregistered agent → 401 path. No org, no binding → denial.
    await _prime_nonce(client, dpop)
    assertion = make_assertion("nobody::ghost", "nobody")
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code in (401, 403)
    assert "Deprecation" not in resp.headers
    assert "Sunset" not in resp.headers
