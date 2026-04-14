"""
Test dashboard — verifies all dashboard pages render and operations work.

Scope: network-admin only. Org-tenant login, org self-service pages, and
the org OIDC mapping UI were removed from the broker dashboard in the
ADR-001 refactor — tenants now operate on their per-org proxy.
Deprecated tests that exercised those flows were removed or rewritten.
"""
import json
import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


def _extract_csrf(cookies: dict) -> str:
    """Extract CSRF token from the signed session cookie.

    httpx stores the Set-Cookie value with Starlette's encoding
    (backslash-escaped special chars, surrounding quotes). We undo
    that encoding before parsing JSON.
    """
    cookie = cookies.get("cullis_session", "")
    if not cookie:
        return ""
    # Strip surrounding quotes added by Starlette cookie encoding
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    # Undo backslash/octal escapes (e.g. \\054 -> comma, \\" -> ")
    import codecs
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        data = json.loads(payload_str)
        return data.get("csrf_token", "")
    except (json.JSONDecodeError, TypeError):
        return ""


async def _admin_cookies(client: AsyncClient) -> dict:
    """Login as admin and return cookies dict."""
    resp = await client.post("/dashboard/login", data={
        "user_id": "admin", "password": get_settings().admin_secret,
    }, follow_redirects=False)
    assert resp.status_code == 303
    return dict(resp.cookies)


async def _admin_ctx(client: AsyncClient) -> tuple[dict, str]:
    """Login as admin, return (cookies, csrf_token)."""
    cookies = await _admin_cookies(client)
    return cookies, _extract_csrf(cookies)


# Deprecated: _org_cookies / _org_ctx helpers (org-tenant login moved to
# proxy in ADR-001). Any test that needs a non-admin session against the
# broker dashboard is now out of scope by design.


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

async def test_login_page_renders(client: AsyncClient):
    resp = await client.get("/dashboard/login")
    assert resp.status_code == 200
    # Network-admin-only copy emphasises the operator surface.
    assert "Network" in resp.text and "Admin" in resp.text
    assert "password" in resp.text


async def test_unauthenticated_redirects_to_login(client: AsyncClient):
    resp = await client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303


async def test_admin_login_success(client: AsyncClient):
    cookies = await _admin_cookies(client)
    assert "cullis_session" in cookies


async def test_admin_login_wrong_secret(client: AsyncClient):
    resp = await client.post("/dashboard/login", data={
        "user_id": "admin", "password": "wrong",
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text


async def test_logout(client: AsyncClient):
    cookies = await _admin_cookies(client)
    # Logout changed to POST with CSRF (#43)
    csrf = _extract_csrf(cookies)
    resp = await client.post("/dashboard/logout", cookies=cookies, follow_redirects=False,
                             data={"csrf_token": csrf})
    assert resp.status_code == 303


# ─────────────────────────────────────────────────────────────────────────────
# Admin — pages render
# ─────────────────────────────────────────────────────────────────────────────

async def test_overview_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=c)
    assert resp.status_code == 200
    assert "Overview" in resp.text


async def test_orgs_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/orgs", cookies=c)
    assert resp.status_code == 200
    assert "Organizations" in resp.text


async def test_agents_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/agents", cookies=c)
    assert resp.status_code == 200
    assert "Agents" in resp.text


async def test_sessions_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/sessions", cookies=c)
    assert resp.status_code == 200


async def test_sessions_filter(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/sessions?status=active", cookies=c)
    assert resp.status_code == 200


async def test_audit_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/audit", cookies=c)
    assert resp.status_code == 200
    assert "Audit Log" in resp.text


async def test_audit_filter(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/audit?q=auth", cookies=c)
    assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Admin — onboard org
# ─────────────────────────────────────────────────────────────────────────────

async def test_onboard_form_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/orgs/onboard", cookies=c)
    assert resp.status_code == 200
    assert "Onboard New Organization" in resp.text


async def test_onboard_org_and_approve(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-onboard-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-onboard-org", "display_name": "Dashboard Onboard Test",
        "secret": "test-secret", "contact_email": "test@example.com",
        "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered and approved" in resp.text


async def test_onboard_then_approve_button(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-pending-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-pending-org", "display_name": "Pending Org",
        "secret": "test-secret", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "pending",
    }, cookies=c)
    resp = await client.post("/dashboard/orgs/dash-pending-org/approve",
                             data={"csrf_token": csrf},
                             cookies=c, follow_redirects=False)
    assert resp.status_code == 303


async def test_onboard_duplicate_rejected(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-dup-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-dup-org", "display_name": "Dup", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-dup-org", "display_name": "Dup2", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "already exists" in resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Admin — onboard CA generator (shake-out P1-08)
# ─────────────────────────────────────────────────────────────────────────────

async def test_onboard_generate_ca_returns_valid_pair(client: AsyncClient):
    """Endpoint returns a parseable self-signed CA cert + matching private key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    c, csrf = await _admin_ctx(client)
    resp = await client.post(
        "/dashboard/orgs/onboard/generate-ca",
        data={"csrf_token": csrf, "display_name": "Acme Test CA"},
        cookies=c,
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert "cert_pem" in payload and "key_pem" in payload
    cert = x509.load_pem_x509_certificate(payload["cert_pem"].encode())
    key = serialization.load_pem_private_key(payload["key_pem"].encode(), password=None)
    # Self-signed
    assert cert.issuer == cert.subject
    # ECDSA-P256 per spec
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    # BasicConstraints: CA=true
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    # Display name is in the CN
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert "Acme Test CA" in cn


async def test_onboard_generate_ca_rejects_non_admin(client: AsyncClient):
    """Unauthenticated requests to the CA generator are rejected.

    Deprecated: previously this test also exercised org-role login and
    expected a 403; org login moved to the proxy in ADR-001, so there
    is no 'org session' on the broker anymore. The remaining guarantee
    is that an anonymous caller cannot mint a CA.
    """
    resp = await client.post(
        "/dashboard/orgs/onboard/generate-ca",
        data={"display_name": "Anon"},
    )
    # No session cookie → dashboard redirects, but the endpoint returns
    # JSON 401 for unauthenticated HTMX-style callers.
    assert resp.status_code in (401, 303, 307)


async def test_onboard_generate_ca_requires_csrf(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.post(
        "/dashboard/orgs/onboard/generate-ca",
        data={"display_name": "NoCsrf"},  # no csrf_token
        cookies=c,
    )
    assert resp.status_code == 403


async def test_onboard_generate_ca_unauthenticated(client: AsyncClient):
    resp = await client.post(
        "/dashboard/orgs/onboard/generate-ca",
        data={"display_name": "Anon"},
    )
    # Unauthenticated: dashboard redirect path is intercepted and turned into 401 JSON.
    assert resp.status_code in (401, 303, 307)


async def test_onboard_generated_ca_accepted_by_onboard_form(client: AsyncClient):
    """End-to-end: generate a CA, then use it to onboard an org in one flow."""
    c, csrf = await _admin_ctx(client)
    gen = await client.post(
        "/dashboard/orgs/onboard/generate-ca",
        data={"csrf_token": csrf, "display_name": "E2E Org"},
        cookies=c,
    )
    assert gen.status_code == 200
    cert_pem = gen.json()["cert_pem"]
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "e2e-generated-ca-org", "display_name": "E2E Org",
        "secret": "secret", "contact_email": "", "webhook_url": "",
        "ca_certificate": cert_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered and approved" in resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Admin — register agent
# ─────────────────────────────────────────────────────────────────────────────

async def test_register_agent_form_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/agents/register", cookies=c)
    assert resp.status_code == 200
    assert "Register New Agent" in resp.text


async def test_register_agent_via_dashboard(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    # Create org first
    ca_pem = get_org_ca_pem("dash-agent-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-agent-org", "display_name": "Agent Org", "secret": "secret",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    # Register agent
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "dash-agent-org", "agent_name": "test-agent",
        "display_name": "Test Agent", "capabilities": "order.read, order.write",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered" in resp.text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Org login — scoped view
# ─────────────────────────────────────────────────────────────────────────────

async def test_admin_sees_network_wide_agents(client: AsyncClient):
    """Admin sees agents across every org (no per-org scoping on the broker).

    Deprecated predecessor: test_org_login_and_scoped_view asserted an
    org session could only see its own agents. Org login moved to the
    proxy (ADR-001); the broker is network-admin only and unconditionally
    shows every agent.
    """
    from tests.cert_factory import get_org_ca_pem
    admin_c, admin_csrf = await _admin_ctx(client)

    for org_id in ("scope-org-a", "scope-org-b"):
        ca_pem = get_org_ca_pem(org_id)
        await client.post("/dashboard/orgs/onboard", data={
            "csrf_token": admin_csrf,
            "org_id": org_id, "display_name": org_id, "secret": f"{org_id}-secret",
            "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
        }, cookies=admin_c)
        await client.post("/dashboard/agents/register", data={
            "csrf_token": admin_csrf,
            "org_id": org_id, "agent_name": "agent",
            "display_name": f"Agent of {org_id}", "capabilities": "test.read",
        }, cookies=admin_c)

    resp = await client.get("/dashboard/agents", cookies=admin_c)
    assert resp.status_code == 200
    # Network-admin view: both orgs' agents are visible.
    assert "scope-org-a::agent" in resp.text
    assert "scope-org-b::agent" in resp.text


async def test_org_tenant_cannot_log_in(client: AsyncClient):
    """Deprecated: org-tenant login removed in ADR-001.

    A tenant attempting to log in with a non-admin user_id must be
    rejected with a message pointing at the proxy, never redirected into
    a session.
    """
    from tests.cert_factory import get_org_ca_pem
    admin_c, admin_csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("legacy-tenant")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": admin_csrf,
        "org_id": "legacy-tenant", "display_name": "Legacy Tenant",
        "secret": "tenant-secret", "contact_email": "",
        "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=admin_c)

    resp = await client.post("/dashboard/login", data={
        "user_id": "legacy-tenant", "password": "tenant-secret",
    }, follow_redirects=False)
    # Login page re-rendered with a deny message — no 303 session redirect.
    assert resp.status_code == 200
    assert "network-admin" in resp.text.lower() or "proxy" in resp.text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Security — CSRF protection
# ─────────────────────────────────────────────────────────────────────────────

async def test_csrf_missing_token_rejected(client: AsyncClient):
    """POST without CSRF token is rejected."""
    from tests.cert_factory import get_org_ca_pem
    c = await _admin_cookies(client)
    ca_pem = get_org_ca_pem("csrf-test-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "org_id": "csrf-test-org", "display_name": "CSRF Test",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


async def test_csrf_wrong_token_rejected(client: AsyncClient):
    """POST with wrong CSRF token is rejected."""
    from tests.cert_factory import get_org_ca_pem
    c = await _admin_cookies(client)
    ca_pem = get_org_ca_pem("csrf-wrong-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": "totally-wrong-token",
        "org_id": "csrf-wrong-org", "display_name": "CSRF Wrong",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


async def test_csrf_valid_token_accepted(client: AsyncClient):
    """POST with correct CSRF token is accepted."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("csrf-valid-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "csrf-valid-org", "display_name": "CSRF Valid",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered and approved" in resp.text


async def test_csrf_agent_register_rejected_without_token(client: AsyncClient):
    """Agent register POST without CSRF token is rejected."""
    c = await _admin_cookies(client)
    resp = await client.post("/dashboard/agents/register", data={
        "org_id": "some-org", "agent_name": "a",
        "display_name": "A", "capabilities": "",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Security — auth enforcement on approve/reject/badge
# ─────────────────────────────────────────────────────────────────────────────

async def test_approve_requires_auth(client: AsyncClient):
    """Unauthenticated approve redirects to login."""
    resp = await client.post("/dashboard/orgs/some-org/approve",
                             data={}, follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


async def test_reject_requires_auth(client: AsyncClient):
    """Unauthenticated reject redirects to login."""
    resp = await client.post("/dashboard/orgs/some-org/reject",
                             data={}, follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


async def test_approve_with_stale_non_admin_cookie_is_rejected(client: AsyncClient):
    """Deprecated predecessor: test_approve_requires_admin minted an org
    session to confirm it could not approve other orgs. Org sessions no
    longer exist on the broker (ADR-001). We now verify that a cookie
    forged with role!='admin' is treated as logged-out: the approve
    endpoint redirects to /dashboard/login rather than silently allowing
    the action.
    """
    # Forge a fake session cookie with role='org'. The dashboard hardened
    # get_session() to treat anything other than role='admin' as no
    # session; we expect the bounce-to-login path.
    from app.dashboard.session import _sign
    import json as _json
    import time as _time
    payload = _json.dumps({
        "role": "org", "org_id": "whoever", "csrf_token": "x",
        "exp": int(_time.time()) + 600,
    })
    fake_cookie = _sign(payload)
    resp = await client.post(
        "/dashboard/orgs/someone/approve", data={},
        cookies={"cullis_session": fake_cookie},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


async def test_badge_pending_orgs_requires_admin(client: AsyncClient):
    """Badge endpoint returns empty for unauthenticated users."""
    resp = await client.get("/dashboard/badge/pending-orgs")
    assert resp.status_code == 200
    assert resp.text == ""


async def test_badge_pending_sessions_requires_auth(client: AsyncClient):
    """Badge endpoint returns empty for unauthenticated users."""
    resp = await client.get("/dashboard/badge/pending-sessions")
    assert resp.status_code == 200
    assert resp.text == ""


# ─────────────────────────────────────────────────────────────────────────────
# Security — security headers
# ─────────────────────────────────────────────────────────────────────────────

async def test_security_headers_on_dashboard(client: AsyncClient):
    """Dashboard pages include security headers."""
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=c)
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in resp.headers.get("content-security-policy", "")


async def test_security_headers_on_api(client: AsyncClient):
    """API endpoints get base security headers but not CSP."""
    resp = await client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    # CSP is only on /dashboard routes
    assert "content-security-policy" not in resp.headers


# ─────────────────────────────────────────────────────────────────────────────
# Security — input validation
# ─────────────────────────────────────────────────────────────────────────────

async def test_invalid_org_id_rejected(client: AsyncClient):
    """Org IDs with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("x")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "bad org id!!", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "alphanumeric" in resp.text


async def test_invalid_webhook_url_rejected(client: AsyncClient):
    """Webhook URLs with invalid scheme are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("x")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "webhook-test-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "ftp://evil.com/pwn",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "https://" in resp.text or "http://" in resp.text


async def test_invalid_agent_id_rejected(client: AsyncClient):
    """Agent IDs with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("valid-id-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "valid-id-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "valid-id-org", "agent_name": "../../../etc/passwd",
        "display_name": "Evil Agent", "capabilities": "",
    }, cookies=c)
    assert resp.status_code == 200
    assert "alphanumeric" in resp.text


async def test_invalid_capability_rejected(client: AsyncClient):
    """Capabilities with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("cap-test-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "cap-test-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "cap-test-org", "agent_name": "agent",
        "display_name": "Agent", "capabilities": "<script>alert(1)</script>",
    }, cookies=c)
    assert resp.status_code == 200
    assert "Invalid capability" in resp.text
