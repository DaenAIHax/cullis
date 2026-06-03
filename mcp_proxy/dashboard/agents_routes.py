"""Mastio dashboard — Agents sub-router.

Sprint F-B-201 PR-4 of 10. Extracts the agent registry surface
(``/proxy/agents`` + per-agent management endpoints) from
``mcp_proxy/dashboard/router.py``.

Mounted via ``router.include_router(agents_routes.router)``.

Routes (7):

  GET  /proxy/agents                            agent list + KPIs
  POST /proxy/agents/create                     enroll a new internal agent
  GET  /proxy/agents/{agent_id}                 developer-portal detail page
  GET  /proxy/agents/{agent_id}/env-download    download env.sample
  POST /proxy/agents/{agent_id}/reach           edit reach (intra/cross/both)
  POST /proxy/agents/{agent_id}/deactivate      flip is_active=False
  POST /proxy/agents/{agent_id}/delete          permanent delete + cascade

Mirrors Court PR-7 (#850) ``app/dashboard/agents_lifecycle_routes.py``
+ ``agents_credentials_routes.py`` pattern, here kept in a single
sub-router because the Mastio surface is simpler than Court's.
"""
from __future__ import annotations

import logging
from sqlalchemy.exc import IntegrityError
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_AGENTS_DELETE,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-agents"])


async def _refresh_org_status_from_broker() -> str:
    """Synchronously ask the broker for the current org status and update
    the cached value in proxy_config.

    The cached value can drift behind reality in two situations:
      1. The broker admin approves the org while the proxy was not polling
         (no dashboard tab open).
      2. The bootstrap script (setup_proxy_org.py) writes status='pending'
         and never updates it after the broker admin approves.

    Returns the latest known status string ('pending', 'active', 'rejected',
    or '' if unknown / not configured). On any error, returns the cached
    value unchanged so the page render still works offline.
    """
    import httpx
    from mcp_proxy.db import get_config, set_config

    cached = await get_config("org_status") or ""

    org_id = await get_config("org_id")
    broker_url = await get_config("broker_url")
    org_secret = await get_config("org_secret")
    if not org_id or not broker_url or not org_secret:
        return cached

    try:
        from mcp_proxy.config import get_settings as _s, broker_tls_verify
        async with httpx.AsyncClient(
            verify=broker_tls_verify(_s()), timeout=3.0,
        ) as http:
            resp = await http.get(
                f"{broker_url}/v1/registry/orgs/me",
                headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
            )
            if resp.is_success:
                fresh = (resp.json() or {}).get("status", "")
                if fresh and fresh != cached:
                    await set_config("org_status", fresh)
                return fresh or cached
    except Exception as exc:
        _log.debug("org_status refresh failed: %s", exc)

    return cached


@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config
    # Refresh the cached broker status BEFORE rendering, so the static
    # 'Approval Pending' banner in the template is never lying about a
    # state that the broker has already moved past.
    org_status = await _refresh_org_status_from_broker()
    agents = await list_agents()
    has_ca = bool(await get_config("org_ca_cert"))
    # Court / cross-org federation is uplink-gated: with no broker the proxy
    # is standalone (open-core default) and the federation UI stays hidden.
    federation_enabled = bool(await get_config("broker_url"))

    # Split by reach so the template can render two sections:
    # Federated (reach in {'cross','both'}) on top, Local (reach ==
    # 'intra') below. Peer-org agents live on /proxy/network now —
    # this page is exclusively "my agents". In standalone mode the
    # template ignores this split and lists ``agents`` in one table.
    federated_agents = [a for a in agents if a.get("reach", "both") != "intra"]
    local_agents = [a for a in agents if a.get("reach", "both") == "intra"]

    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        federated_agents=federated_agents,
        local_agents=local_agents,
        federation_enabled=federation_enabled,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=None,
    ))




@router.post("/agents/create")
async def agents_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import list_agents, log_audit, get_config
    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.config import get_settings

    # Court federation is uplink-gated; pass the flag through every render
    # path so an error re-render keeps the same (standalone vs federated) UI.
    federation_enabled = bool(await get_config("broker_url"))

    form = await request.form()
    agent_name = str(form.get("agent_name", "")).strip().lower().replace(" ", "_")
    display_name = str(form.get("display_name", "")).strip()
    capabilities_raw = str(form.get("capabilities", "")).strip()

    if not agent_name or not display_name:
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            federation_enabled=federation_enabled,
            error="Agent name and display name are required.",
            new_agent_id=None,
        ))

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]

    # Determine org_id from config or settings
    org_id = await get_config("org_id") or get_settings().org_id

    # ADR-014 PR-C — agent creation requires a loaded Org CA so the
    # Mastio can mint the agent's TLS client cert (the credential).
    try:
        mgr = AgentManager(org_id=org_id)
        ca_loaded = await mgr.load_org_ca_from_config()

        if not ca_loaded:
            agents = await list_agents()
            _org_status = await get_config("org_status") or ""
            return templates.TemplateResponse("agents.html", _ctx(
                request, session,
                active="agents",
                agents=agents,
                org_status=_org_status,
                has_ca=False,
                federation_enabled=federation_enabled,
                error=(
                    "Org CA is not loaded — complete broker setup before "
                    "creating agents (the cert is the agent credential)."
                ),
                new_agent_id=None,
            ))

        agent_info, _key_pem = await mgr.create_agent(agent_name, display_name, capabilities)
        agent_id = agent_info["agent_id"]
    except IntegrityError:
        # Most common path: admin submitted an agent_name that already
        # exists. The UNIQUE constraint on internal_agents.agent_id is
        # the brake. Surface a user-friendly hint instead of leaking
        # the raw SQL exception (which also contains the cert PEM in
        # parameters; see CLAUDE.md "Mai esporre stack trace").
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            federation_enabled=federation_enabled,
            error=(
                f"Agent name '{agent_name}' is already taken in this org. "
                f"Pick a different name, or delete the existing agent first."
            ),
            new_agent_id=None,
        ))
    except Exception:
        # Defensive catch-all: log the full stack for the operator
        # (via uvicorn stderr / docker logs) but show only a generic
        # error to the dashboard. Never interpolate ``exc`` into the
        # response body — SQLAlchemy IntegrityError ``str(exc)`` already
        # bit us once with the cert PEM in parameters.
        _log.exception("agent.create failed for agent_id=%s", agent_name)
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            federation_enabled=federation_enabled,
            error=(
                "Failed to create the agent. Check the Mastio container "
                "logs for the underlying cause."
            ),
            new_agent_id=None,
        ))

    await log_audit(
        agent_id=agent_id,
        action="agent.create",
        status="success",
        detail=f"display_name={display_name}, capabilities={capabilities}, mode=x509",
    )

    # ADR-010 Phase 6a-4 — the dashboard used to follow agent creation with
    # ``POST /v1/registry/agents`` + ``POST /v1/registry/bindings`` + auto-
    # approve via the legacy org_secret auth. That path is gone. Cross-org
    # exposure is now opt-in: the operator flips the federate toggle on
    # this agent row and manages bindings separately. Both happen through
    # the standard Mastio admin surface (see PATCH /v1/admin/agents/{id}/
    # federated and /v1/registry/bindings endpoints from the dashboard).

    agents = await list_agents()
    org_status = await get_config("org_status") or ""
    has_ca = bool(await get_config("org_ca_cert"))
    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        federation_enabled=federation_enabled,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=agent_id,
    ))


def _summarise_agent_cert(cert_pem: str | None) -> dict | None:
    """Parse the agent's stored cert PEM into a small dashboard summary.

    Returns ``None`` when ``cert_pem`` is missing or the cert cannot be
    parsed — callers treat that as "no cert" and render the empty
    state. When the cert parses, the returned dict carries enough for
    the operator to confirm at a glance which cert is bound to the
    agent: SHA-256 thumbprint hex, CN, SHA-256 fingerprint colon-form,
    not-after timestamp (UTC, ISO-8601 truncated to seconds).

    A-9 root cause: ``_agent_row_to_dict`` never populated
    ``cert_thumbprint`` (no column for it on ``internal_agents``), so
    the template's ``{% if agent.cert_thumbprint %}`` was always
    falsy and the page rendered "No cert" even for agents whose
    handshake worked. We derive the thumbprint on-the-fly from the
    ``cert_pem`` column instead.
    """
    if not cert_pem:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else ""
        # SHA-256 fingerprint in colon-separated upper-hex (the form
        # ``openssl x509 -fingerprint -sha256`` prints) so an operator
        # can grep it against a CA-side audit line.
        fp_bytes = cert.fingerprint(hashes.SHA256())
        fingerprint = ":".join(f"{b:02X}" for b in fp_bytes)
        # Plain SHA-256 hex for the existing template title= attribute
        # and the "short" 24-char preview the page already renders.
        thumbprint = fp_bytes.hex()
        not_after = cert.not_valid_after_utc.isoformat()[:19]
        return {
            "thumbprint": thumbprint,
            "fingerprint_sha256": fingerprint,
            "subject_cn": cn,
            "not_after": not_after,
        }
    except Exception:
        return None


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_detail_page(request: Request, agent_id: str):
    # D-14 cold-reader fix: this route used to be declared with
    # ``{agent_id:path}`` which (because of Starlette's greedy ``.*``
    # converter) matched every URL of the form
    # ``/agents/<id>/<anything>`` before the sub-route declarations
    # below got a chance. ``env-download`` and ``identity-bundle.zip``
    # silently 404'd via this route because ``get_agent`` resolved a
    # non-existent ``<id>/<sub-path>``. Agent IDs never contain ``/``
    # (``org_id::name`` shape is pinned by migration 0041), so the
    # default ``str`` converter (``[^/]+``) is both safer and more
    # accurate, and the sub-routes resolve correctly.
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # A-9: derive the cert summary from the stored PEM so the template
    # can switch on a real signal instead of the never-populated
    # ``cert_thumbprint`` field. Expose it under
    # ``agent['cert_thumbprint']`` for back-compat with the existing
    # template + a new ``agent['cert_summary']`` dict for the
    # parsed-cert detail panel.
    cert_summary = _summarise_agent_cert(agent.get("cert_pem"))
    if cert_summary is not None:
        agent["cert_thumbprint"] = cert_summary["thumbprint"]
        agent["cert_summary"] = cert_summary

    # Fetch recent audit entries for this agent
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    async with get_db() as db:
        result = await db.execute(
            text("SELECT * FROM audit_log WHERE agent_id = :agent_id ORDER BY timestamp DESC LIMIT 20"),
            {"agent_id": agent_id},
        )
        audit_entries = [dict(row) for row in result.mappings().all()]

    # Extra context for integration snippets
    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id
    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    return templates.TemplateResponse("agent_detail.html", _ctx(
        request, session,
        active="agents",
        agent=agent,
        audit_entries=audit_entries,
        proxy_url=proxy_url,
        broker_url=broker_url,
        org_id=org_id,
        agent_name=agent_name,
    ))


@router.get("/agents/{agent_id:path}/env-download")
async def agent_env_download(request: Request, agent_id: str):
    """Download .env file with agent configuration."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id

    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    env_content = f"""# Cullis Agent Configuration — {agent_id}
# Generated from MCP Proxy dashboard
# ADR-014: the agent authenticates by presenting its TLS client cert
# at the handshake. Mount cert.pem + key.pem from the identity bundle.
CULLIS_PROXY_URL={proxy_url}
CULLIS_AGENT_ID={agent_id}
CULLIS_ORG_ID={org_id}
CULLIS_BROKER_URL={broker_url}
"""

    return Response(
        content=env_content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{agent_name}.env"'
        },
    )


@router.get("/agents/{agent_id:path}/identity-bundle.zip")
async def agent_identity_bundle_download(request: Request, agent_id: str):
    """Download the agent's identity-dir layout as a zip (D-14).

    Cold-reader dogfood (2026-05-26) caught the gap: dashboard Create
    Agent mints a TLS client cert plus private key, persists them, and
    the post-create banner instructs the admin to "Open the agent's
    detail page to download cert + key" — but the only existing
    download endpoint returned a config-only ``.env`` with no
    credential material. Admins had no way to deliver the freshly
    minted identity to the agent host.

    The zip contains the four-file identity-dir layout
    ``CullisClient.from_identity_dir`` consumes:

    * ``agent.crt`` — TLS client cert PEM (leaf signed by Mastio
      Intermediate).
    * ``agent.key`` — TLS client cert private key PEM (PKCS#8).
    * ``ca-chain.pem`` — Mastio Intermediate concatenated with the Org
      Root, the same chain ``CullisClient`` auto-discovers as a
      sibling of ``cert_path``.
    * ``meta.json`` — agent_id, org_id, mastio_url, capabilities,
      created_at, spiffe_id. Informational only; the credential is the
      cert + key pair.

    NB: no ``dpop.jwk`` file. RFC 9449 + ADR-014 keep the DPoP key
    client-side: the agent generates its own EC P-256 keypair on first
    run (``cullis_sdk.dpop.DpopKey.load_or_generate``) and registers
    the public JWK via the admin DPoP endpoint or
    ``CullisClient.enroll_via_dashboard_approval``. The Mastio never
    holds the private DPoP material, so we cannot ship it in the
    bundle. D-11 already wires the SDK to auto-generate the file as a
    sibling of ``cert_path`` on first use, so the four-file layout is
    enough end-to-end.

    Admin role required, every successful download writes an
    ``agent.identity_bundle_downloaded`` audit row because the private
    key just left the server boundary.

    409 path: agents enrolled via BYOCA / SDK enrollment factory never
    handed their private key to the Mastio (the Mastio only signed the
    CSR). In that case there is no key to ship; the response points
    the admin at the SDK ``enroll_via_dashboard_approval`` factory
    which already exposes the credential to the agent process.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    # Mint-side bundle download exposes a private key — admin-only.
    if session.role != "admin" and "admin" not in (session.roles or ()):
        raise HTTPException(status_code=403, detail="admin role required")

    import io
    import json as _json
    import zipfile

    from mcp_proxy.db import get_agent, get_config, log_audit
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    cert_pem = agent.get("cert_pem")
    if not cert_pem:
        raise HTTPException(
            status_code=409,
            detail=(
                "Agent has no minted certificate yet. Wait for the "
                "create-agent flow to complete, or re-enroll via the "
                "dashboard."
            ),
        )

    # Private key lives in Vault (preferred) or proxy_config under
    # ``agent_key:{agent_id}`` (fallback). ``AgentManager.get_agent_credentials``
    # walks both. Agents enrolled via BYOCA / SDK never had their key
    # reach the Mastio, so the lookup raises and we return 409 with a
    # message pointing at the SDK enrol path.
    try:
        from mcp_proxy.egress.agent_manager import AgentManager
        org_id_cfg = await get_config("org_id") or get_settings().org_id
        mgr = AgentManager(org_id=org_id_cfg)
        _cert_from_mgr, key_pem = await mgr.get_agent_credentials(agent_id)
    except Exception as exc:  # noqa: BLE001 — surfaced as 409 below
        raise HTTPException(
            status_code=409,
            detail=(
                "Agent has no server-side private key. This typically "
                "means the agent was enrolled via an external CSR "
                "(BYOCA) or via the SDK enrol factory where the "
                "private key never reached the Mastio. Use "
                "cullis_sdk.CullisClient.enroll_via_dashboard_approval "
                "instead — that path keeps the key on the agent host "
                "by construction."
            ),
        ) from exc

    # CA chain: Mastio Intermediate || Org Root, PEM-concatenated. The
    # SDK auto-discovers this layout as the sibling ``ca-chain.pem``
    # of ``cert_path`` (D-9 / D-11).
    mastio_ca_pem = (await get_config("mastio_ca_cert") or "").strip()
    org_ca_pem = (await get_config("org_ca_cert") or "").strip()
    if mastio_ca_pem and org_ca_pem:
        ca_chain_pem = mastio_ca_pem + "\n" + org_ca_pem + "\n"
    else:
        ca_chain_pem = ((mastio_ca_pem or org_ca_pem) + "\n") if (
            mastio_ca_pem or org_ca_pem
        ) else ""

    settings = get_settings()
    org_id = agent.get("org_id") or await get_config("org_id") or settings.org_id
    meta = {
        "agent_id": agent_id,
        "org_id": org_id,
        "mastio_url": settings.proxy_public_url or f"https://localhost:{settings.port}",
        "capabilities": agent.get("capabilities") or [],
        "created_at": agent.get("created_at"),
        "spiffe_id": agent.get("spiffe_id"),
        # This Mastio-minted bundle is mTLS-only: it ships no dpop.jwk,
        # and from_identity_dir does not generate one (it adopts a
        # dpop.jwk sibling if present, otherwise runs without DPoP, see
        # test_from_identity_dir_dpop_autodiscovery). A DPoP-bound
        # identity comes from the SDK enroll flow, not this download, so
        # the notes below say that instead of promising an auto-gen that
        # never happens.
        "notes": (
            "Drop this directory at the agent host's identity dir "
            "(e.g. /etc/cullis/agent/), then point the SDK at it via "
            "CullisClient.from_identity_dir(path). This is an mTLS-only "
            "bundle: it carries the agent certificate and key but no "
            "DPoP key, and from_identity_dir does not create one, so an "
            "agent loaded from it authenticates by client certificate "
            "alone. It is rejected where the Mastio requires DPoP on "
            "egress (egress_dpop_mode=required). For a DPoP-bound "
            "identity, enroll with "
            "CullisClient.enroll_via_dashboard_approval instead: that "
            "flow generates the certificate and DPoP keys on the agent "
            "host and registers the DPoP public key with the Mastio."
        ),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("agent.crt", cert_pem)
        zf.writestr("agent.key", key_pem)
        if ca_chain_pem:
            zf.writestr("ca-chain.pem", ca_chain_pem)
        zf.writestr("meta.json", _json.dumps(meta, indent=2))

    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    # Audit BEFORE returning the bytes: the private key is on its way
    # out, every successful download needs a trail.
    try:
        await log_audit(
            agent_id=agent_id,
            action="agent.identity_bundle_downloaded",
            status="success",
            detail=f"downloaded_by_role={session.role}",
        )
    except Exception:  # noqa: BLE001 — best-effort audit, never block the download
        _log.warning(
            "agent.identity_bundle_downloaded audit row failed for %s",
            agent_id,
        )

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{agent_name}-identity.zip"'
            ),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


_VALID_REACH = {"intra", "cross", "both"}


_CAPABILITY_RE = __import__("re").compile(r"^[a-z_][a-z0-9_.]{0,63}$")
_MAX_CAP_ITEMS = 64


def _parse_capabilities_form(raw: str) -> tuple[list[str], str | None]:
    """Parse the comma-separated capability list from the dashboard form.

    Returns ``(parsed, err)``. ``err`` is non-None when validation
    fails — the caller renders the error back into the page rather
    than touching the DB. Mirrors the constraints applied by
    ``mcp_proxy.admin._capabilities.Capability`` so the dashboard
    surface and the admin API cannot drift.
    """
    items = [c.strip() for c in raw.split(",") if c.strip()]
    if len(items) > _MAX_CAP_ITEMS:
        return [], f"too many capabilities (max {_MAX_CAP_ITEMS})"
    for c in items:
        if not _CAPABILITY_RE.match(c):
            return (
                [],
                f"invalid capability {c!r}: must match "
                f"[a-z_][a-z0-9_.]{{0,63}} (lowercase, dotted)",
            )
    return items, None


@router.post("/agents/{agent_id:path}/capabilities")
async def agent_set_capabilities(request: Request, agent_id: str):
    """Replace the agent's capability set from the dashboard form.

    Symmetric to the admin API ``PATCH /v1/admin/agents/{id}/capabilities``
    — the dashboard talks to the DB directly (same pattern as
    ``/reach`` above) to keep the form-POST flow simple and CSRF-bound.

    Bumps ``federation_revision`` so the Phase 3 publisher will pick
    the change up on its next pass. Audit row carries the new list
    verbatim so an operator can replay history.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    capabilities_raw = str(form.get("capabilities", "")).strip()
    capabilities, err = _parse_capabilities_form(capabilities_raw)
    if err is not None:
        return RedirectResponse(
            url=f"/proxy/agents/{agent_id}?error={err}",
            status_code=303,
        )

    from mcp_proxy.db import get_agent, get_db, log_audit
    from sqlalchemy import text as _text
    import json as _json

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    async with get_db() as conn:
        await conn.execute(
            _text(
                """
                UPDATE internal_agents
                   SET capabilities = :caps,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"caps": _json.dumps(capabilities), "aid": agent_id},
        )

    await log_audit(
        agent_id=agent_id,
        action="agent.capabilities_set",
        status="success",
        detail=f"source=dashboard capabilities={capabilities}",
    )

    return RedirectResponse(
        url=f"/proxy/agents/{agent_id}", status_code=303,
    )


@router.post("/agents/{agent_id:path}/reach")
async def agent_set_reach(request: Request, agent_id: str):
    """Set ``internal_agents.reach`` from the dashboard.

    Migration 0017 introduced three states:

    * ``intra``  — same-org chat only, NOT published to the Court
    * ``cross``  — other-org chat only, published to the Court
    * ``both``   — intra + cross, published

    The legacy ``federated`` boolean is kept in sync so the publisher
    (ADR-010 Phase 3) still finds the right rows to PUT / revoke; it is
    now derived from ``reach`` instead of being the primary knob.
    ``federation_revision`` is bumped on every mutation so the publisher
    picks up the change on its next tick.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    new_reach = (form.get("reach") or "").strip().lower()
    if new_reach not in _VALID_REACH:
        raise HTTPException(
            status_code=400,
            detail=f"reach must be one of {sorted(_VALID_REACH)}",
        )

    from mcp_proxy.db import get_agent, get_db, log_audit
    from sqlalchemy import text as _text

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_federated = new_reach != "intra"
    async with get_db() as conn:
        await conn.execute(
            _text(
                """
                UPDATE internal_agents
                   SET reach = :reach,
                       federated = :fed,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"reach": new_reach, "fed": bool(new_federated), "aid": agent_id},
        )

    await log_audit(
        agent_id=agent_id,
        action="agent.reach_set",
        status="success",
        detail=f"source=dashboard reach={new_reach} federated={new_federated}",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/deactivate")
async def agent_deactivate(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import deactivate_agent, log_audit

    found = await deactivate_agent(agent_id)
    if not found:
        raise HTTPException(status_code=404, detail="Agent not found")

    await log_audit(
        agent_id=agent_id,
        action="agent.deactivate",
        status="success",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/delete")
async def agent_delete(request: Request, agent_id: str):
    """Permanently delete an agent and all associated data."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_AGENTS_DELETE,
        payload={"agent_id": agent_id},
        request=request,
    )
    if intercept is not None:
        return intercept

    from sqlalchemy import text

    from mcp_proxy.db import get_agent, get_db, log_audit

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Delete from local DB
    async with get_db() as db:
        await db.execute(
            text("DELETE FROM internal_agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        # Also remove stored key from proxy_config if present
        await db.execute(
            text("DELETE FROM proxy_config WHERE key = :key"),
            {"key": f"agent_key:{agent_id}"},
        )

    # ADR-010 Phase 6a-4 — the ``DELETE /v1/registry/agents/{id}`` hop is
    # gone. ``db_deactivate_agent`` bumps ``federation_revision`` for
    # federated rows, and the publisher carries the revocation to the
    # Court via ``/v1/federation/publish-agent`` on its next tick.

    await log_audit(
        agent_id=agent_id,
        action="agent.delete",
        status="success",
        detail="Agent permanently deleted",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)

