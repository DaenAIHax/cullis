"""Cosmetic-batch dogfood fixes from session 3 + session current.

Five low-impact findings batched into one PR because each is a few
lines and shares the same risk profile (template / view-context
tweaks, plus one bundle shell helper):

* D-10 — ``deploy.sh --down --wipe-data`` skipped the busybox wipe
  when the host operator could not list the bind-dir contents (mode
  0700 owned by uid 10001 post init-permissions). Fix: drop the
  host-side ``compgen`` empty check, always mount + always run the
  idempotent ``find -delete``.
* A-2 — audit counters across sidebar badge, header chip, chain-verify
  banner, and DB row count looked like the same metric drifting. Fix:
  add explicit ``title`` tooltips on every counter so each says what
  it measures.
* A-4 — typo ``/proxy/update`` (singular) returned
  ``{"detail":"Not Found"}`` JSON instead of the dashboard page. Fix:
  301 redirect to ``/proxy/updates``.
* A-5 — overview landing page did not surface an update-available
  advisory when the cached ``update_check_latest_tag`` was newer than
  the running version. The HTMX banner in ``base.html`` already fires,
  but a server-rendered inline banner gives the operator the advisory
  even with HTMX failing. Fix: populate ``update_available`` +
  ``current_version`` + ``latest_version`` on the overview view ctx
  and add a conditional banner near the top of ``overview.html``.
* B-1 — enrollment start response ``poll_url`` stripped the operator
  ``:9443`` port because it was derived from ``request.base_url``
  (which inside the uvicorn container resolves to the internal
  ``http://mcp-proxy:8080/``). Fix: prefer
  ``settings.proxy_public_url`` over ``request.base_url``.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment.router import router as enrollment_router


# ────────────────────────────────────────────────────────────────────
# D-10 — ``_wipe_bind_dirs`` always mounts + runs busybox find -delete
# ────────────────────────────────────────────────────────────────────


_HELPERS_SH = (
    Path(__file__).resolve().parents[2]
    / "packaging"
    / "_common-deploy-helpers.sh"
)


def test_d10_wipe_bind_dirs_no_compgen_short_circuit() -> None:
    """The ``_wipe_bind_dirs`` body must NOT short-circuit on a host
    ``compgen`` listing.

    Pre-fix the function used ``compgen -G "$dir/*"`` (plus dotfile
    variants) to skip the docker mount + wipe on "empty" dirs. On a
    bundle deployed via ``./deploy.sh`` the data dir gets chowned to
    uid 10001 mode 0700 by the init-permissions service; an operator
    invoking ``./deploy.sh --down --wipe-data`` from their own uid
    sees an empty listing through ``compgen`` even when
    ``mcp_proxy.db`` is sitting inside, and the wipe never ran.

    The fix removes the compgen probe entirely (busybox
    ``find -mindepth 1 -delete`` is already idempotent on an empty
    mount, so the short-circuit was an unnecessary optimisation that
    hid a permissions footgun). Pinning the absence so a future
    cleanup does not re-introduce it.
    """
    body = _HELPERS_SH.read_text()
    # ``_wipe_bind_dirs`` is the function we care about; bound the
    # inspection to its body so the unrelated comment in
    # ``_wipe_orphan_sqlite`` does not poison the assertion.
    m = re.search(
        r"_wipe_bind_dirs\(\)\s*\{(.*?)\n\}\n",
        body,
        re.DOTALL,
    )
    assert m, "_wipe_bind_dirs() not found in _common-deploy-helpers.sh"
    fn = m.group(1)
    # Strip ``# ...`` shell comments so the rationale comment that
    # MENTIONS compgen (to explain why it was removed) does not trip
    # the assertion. We care about live code, not prose.
    fn_no_comments = "\n".join(
        re.sub(r"#.*$", "", line) for line in fn.splitlines()
    )
    assert "compgen" not in fn_no_comments, (
        "_wipe_bind_dirs must not call compgen on host dirs (D-10): "
        "permission-bound listing silently skips the wipe."
    )
    # Sanity: the function still uses busybox + find -delete to do the
    # actual work. If a future refactor swaps it out we want this test
    # to fail loudly so the replacement is considered consciously.
    assert "busybox" in fn
    assert "find" in fn and "-delete" in fn


def test_d10_wipe_bind_dirs_documents_d10() -> None:
    """The fix carries an inline ``D-10`` reference so the next reader
    sees why the old optimisation was removed and does not "restore"
    it during a cleanup sweep. The comment is the most reliable
    forward-looking guard for this category of regression.
    """
    body = _HELPERS_SH.read_text()
    m = re.search(
        r"_wipe_bind_dirs\(\)\s*\{(.*?)\n\}\n",
        body,
        re.DOTALL,
    )
    assert m
    fn = m.group(1)
    assert "D-10" in fn, "Inline D-10 marker missing in _wipe_bind_dirs body"


# ────────────────────────────────────────────────────────────────────
# A-2 — audit counter tooltips
# ────────────────────────────────────────────────────────────────────


_AUDIT_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "mcp_proxy" / "dashboard" / "templates" / "audit.html"
)
_BADGES_PY = (
    Path(__file__).resolve().parents[2]
    / "mcp_proxy" / "dashboard" / "badges_routes.py"
)


def test_a2_audit_template_counters_have_titles() -> None:
    """Each of the three header counters (Events/Tool calls, Admin,
    Traffic) carries an explicit ``title=...`` tooltip explaining what
    it measures. Pre-fix the three numbers looked like the same metric
    drifting; the tooltips pin which slice of ``audit_log`` each one
    counts.
    """
    body = _AUDIT_TEMPLATE.read_text()
    # The labels live in three sibling ``<div>`` blocks; assert each
    # neighbouring label sits next to a title attribute that mentions
    # the expected scope keyword.
    assert 'title="Admin-source events' in body
    assert 'title="Traffic-source events' in body
    # The first counter swaps between "Tool calls" (grouped view) and
    # "Events" (raw view); the tooltip must cover both via a Jinja
    # conditional. Match on the umbrella phrasing.
    assert 'Grouped tool-call cards on this page' in body
    assert 'Raw audit-log rows after the current filter' in body


def test_a2_audit_template_verify_banner_clarifies_entries() -> None:
    """The chain-verify success banner used to say "N entries"
    ambiguously — operators read it as the lifetime row count of
    ``audit_log`` and were confused when it differed from the header
    Events counter (filter-scoped) and the sidebar badge (1-hour
    rolling). C1 then split the count into the admin chain
    (``audit_log``) and the traffic chain (``local_audit``) so both
    streams are shown as separately verified. The tooltip still explains
    why these numbers differ from the header / sidebar counters.
    """
    body = _AUDIT_TEMPLATE.read_text()
    assert "' admin · '" in body
    assert "' traffic entries · '" in body
    assert "Hash-chained rows actually verified end-to-end" in body
    assert "rolling 1-hour count" in body


def test_a2_badge_audit_has_tooltip() -> None:
    """The sidebar ``/proxy/badge/audit`` HTMX fragment renders a small
    pill with the count; pre-fix it had no tooltip and looked
    indistinguishable from the header counter. The fix adds
    ``title="Audit events in the last hour"`` so a hover answers the
    "what does this number mean" question without crossing to
    ``/proxy/audit``.
    """
    body = _BADGES_PY.read_text()
    # Bound the inspection to the ``badge_audit`` handler so we do not
    # accidentally match an unrelated title attribute elsewhere.
    m = re.search(
        r"async def badge_audit\([^)]*\):(.*?)(?=\n@router\.|\nasync def |\Z)",
        body,
        re.DOTALL,
    )
    assert m, "badge_audit handler not found"
    fn = m.group(1)
    assert 'title="Audit events in the last hour"' in fn


# ────────────────────────────────────────────────────────────────────
# A-4 — ``/proxy/update`` (singular) 301 → ``/proxy/updates``
# ────────────────────────────────────────────────────────────────────


def test_a4_singular_update_path_redirects_to_plural() -> None:
    """GET ``/proxy/update`` returns ``301`` with
    ``Location: /proxy/updates``. The redirect lives on a sibling
    APIRouter (``alias_router``) so it can be mounted without
    inheriting the canonical ``/proxy/updates`` prefix.
    """
    from mcp_proxy.dashboard.updates_router import alias_router

    app = FastAPI()
    app.include_router(alias_router)
    client = TestClient(app, follow_redirects=False)
    r = client.get("/proxy/update")
    assert r.status_code == 301, r.text
    assert r.headers.get("location") == "/proxy/updates"


def test_a4_singular_update_path_preserves_query_string() -> None:
    """A hand-crafted link like ``/proxy/update?flash=ok`` should
    survive the redirect with the query string attached so the
    plural-form page can read its flash params normally. Pinning the
    query-preserve behaviour because dropping it would break operator
    bookmarks silently.
    """
    from mcp_proxy.dashboard.updates_router import alias_router

    app = FastAPI()
    app.include_router(alias_router)
    client = TestClient(app, follow_redirects=False)
    r = client.get("/proxy/update?flash=applied&x=1")
    assert r.status_code == 301
    assert r.headers.get("location") == "/proxy/updates?flash=applied&x=1"


# ────────────────────────────────────────────────────────────────────
# A-5 — overview server-rendered update banner
# ────────────────────────────────────────────────────────────────────


_OVERVIEW_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "mcp_proxy" / "dashboard" / "templates" / "overview.html"
)
_CORE_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "mcp_proxy" / "dashboard" / "core_routes.py"
)


def test_a5_overview_template_carries_conditional_banner() -> None:
    """``overview.html`` renders an inline update-available banner when
    ``update_available`` is truthy. The banner is the server-rendered
    fallback for the HTMX advisory in ``base.html``; both fire on the
    same cached values but the inline one is visible even when JS /
    HTMX is failing.
    """
    body = _OVERVIEW_TEMPLATE.read_text()
    assert "{% if update_available %}" in body
    assert "Mastio update available" in body
    assert "{{ current_version }}" in body
    assert "{{ latest_version }}" in body
    # The "view changelog" link must land on the canonical plural form;
    # the singular ``/proxy/update`` would 301 and add an extra round
    # trip for no reason.
    assert 'href="/proxy/updates"' in body


def test_a5_overview_view_passes_update_context_vars() -> None:
    """The ``overview_page`` handler in ``core_routes.py`` must pass
    ``update_available`` + ``current_version`` + ``latest_version``
    into the template context, derived from
    ``mcp_proxy.dashboard.update_check.get_update_status``. Without
    these three keys the template's conditional renders nothing even
    when the cache says an update is available.
    """
    body = _CORE_ROUTES_PY.read_text()
    # The handler must import get_update_status (lazily is fine — we
    # match the function name appearing somewhere in the file body).
    assert "get_update_status" in body
    assert "update_available=update_available" in body
    assert "current_version=current_version" in body
    assert "latest_version=latest_version" in body


# ────────────────────────────────────────────────────────────────────
# B-1 — enrollment poll_url honours settings.proxy_public_url
# ────────────────────────────────────────────────────────────────────


_TEST_PUBLIC_URL = "https://mastio.acme.example.com:9443"


@pytest_asyncio.fixture
async def enrollment_proxy_db(tmp_path, monkeypatch):
    """File-backed SQLite + the full alembic chain via ``init_db``.

    Same shape as
    ``test_enrollment_status_hint_on_missing_proof.proxy_db`` — the
    enrollment table needs the migration-driven schema (its column
    list drifts from ``metadata.create_all``).

    Also sets ``MCP_PROXY_PROXY_PUBLIC_URL`` to the operator-visible
    ``:9443`` URL so the B-1 fix path is exercised end-to-end.
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-b1")
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", _TEST_PUBLIC_URL)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "enroll_b1.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()  # type: ignore[attr-defined]


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(enrollment_router)
    return app


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _ec_keypair_with_pop() -> tuple[str, str]:
    """Generate an EC P-256 keypair and return ``(pubkey_pem,
    pop_signature)`` over the canonical ``enrollment-pop:v1|<fp>``
    string.

    Mirrors what the SDK does on
    ``CullisClient.enroll_via_dashboard_approval``: ECDSA-SHA256 over
    the fingerprint-bound canonical, base64url-encoded.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pubkey_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(der).hexdigest()
    canonical = f"enrollment-pop:v1|{fingerprint}".encode()
    sig = priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
    return pubkey_pem, _b64u(sig)


def _ec_dpop_jwk() -> dict:
    """Minimal valid EC P-256 JWK for the start payload."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()

    def _b64u_int(n: int) -> str:
        return _b64u(n.to_bytes(32, "big"))
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_int(nums.x),
        "y": _b64u_int(nums.y),
    }


@pytest.mark.asyncio
async def test_b1_enrollment_poll_url_carries_public_port(
    enrollment_proxy_db,
) -> None:
    """The enrollment start response ``poll_url`` must include
    ``:9443`` (the operator-set public port from
    ``MCP_PROXY_PROXY_PUBLIC_URL``).

    Pre-fix the URL was derived from ``request.base_url`` which inside
    the uvicorn container resolves to ``http://mcp-proxy:8080/`` —
    Connector polls would land on the wrong port (and the wrong
    hostname), so enrollment never completed end-to-end.
    """
    pubkey_pem, pop_sig = _ec_keypair_with_pop()
    payload = {
        "pubkey_pem": pubkey_pem,
        "pop_signature": pop_sig,
        "requester_name": "Alice",
        "requester_email": "alice@example.com",
        "reason": "B-1 regression pin",
        "dpop_jwk": _ec_dpop_jwk(),
    }

    client = TestClient(_make_app())
    r = client.post("/v1/enrollment/start", json=payload)
    assert r.status_code == 201, r.text
    body = r.json()
    poll_url = body.get("poll_url", "")
    enroll_url = body.get("enroll_url", "")

    # Both URLs use the public hostname + port, not the internal
    # uvicorn socket. The :9443 carry-through is the load-bearing
    # check (the host string is also part of the public URL so it
    # comes along for free, but the port is what the operator
    # noticed dropping in the dogfood session).
    assert poll_url.startswith(_TEST_PUBLIC_URL + "/"), (
        f"poll_url should start with {_TEST_PUBLIC_URL!r}, got {poll_url!r}"
    )
    assert ":9443/" in poll_url, (
        f"poll_url must carry the public :9443 port, got {poll_url!r}"
    )
    assert poll_url.endswith("/status")
    assert enroll_url.startswith(_TEST_PUBLIC_URL + "/")
    assert ":9443/enroll?session=" in enroll_url


@pytest.mark.asyncio
async def test_b1_enrollment_poll_url_falls_back_to_request_base_url(
    tmp_path, monkeypatch,
) -> None:
    """When ``MCP_PROXY_PROXY_PUBLIC_URL`` is unset (cold dev / test
    boot before the operator runs the setup wizard), the handler must
    fall back to ``request.base_url`` so the response is still
    well-formed instead of crashing. Pin the fallback path so a
    future refactor does not accidentally make the public URL a hard
    requirement of the start endpoint.
    """
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-b1b")
    monkeypatch.setenv("MCP_PROXY_AUDIT_CHAIN_DISABLED", "true")
    monkeypatch.delenv("MCP_PROXY_PROXY_PUBLIC_URL", raising=False)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    db_path = tmp_path / "enroll_b1_fallback.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    await init_db(url)
    try:
        pubkey_pem, pop_sig = _ec_keypair_with_pop()
        payload = {
            "pubkey_pem": pubkey_pem,
            "pop_signature": pop_sig,
            "requester_name": "Bob",
            "requester_email": "bob@example.com",
            "reason": "B-1 fallback pin",
            "dpop_jwk": _ec_dpop_jwk(),
        }
        client = TestClient(_make_app())
        r = client.post("/v1/enrollment/start", json=payload)
        assert r.status_code == 201, r.text
        body = r.json()
        poll_url = body.get("poll_url", "")
        # TestClient default base is ``http://testserver``; the
        # fallback path must produce a non-empty URL of that shape.
        assert poll_url.startswith("http://testserver/"), poll_url
        assert poll_url.endswith("/status")
    finally:
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]
