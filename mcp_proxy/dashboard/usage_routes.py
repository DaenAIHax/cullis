"""Mastio dashboard — LLM usage metering + per-agent budget sub-router.

Surfaces per-provider and per-agent token usage of the embedded AI
gateway, and lets an org admin set a per-agent cumulative token budget.
Unlike a commodity gateway's per-API-key counter, the usage numbers are
derived read-time from the append-only audit chain
(``aggregate_llm_usage`` in :mod:`mcp_proxy.db`): every ``egress_llm_chat``
row carries the token counts, so what the operator sees is exactly what an
auditor can re-verify from the signed chain — attribution is per agent
identity, not per shared key.

Budgets are *policy* rows (``agent_llm_budgets``, migration 0046); the
running total that enforces them is a Redis calendar counter
(:mod:`mcp_proxy.egress.budget`) seeded from the same chain. Enforcement
itself lives on the egress path (``llm_chat_router``); this surface is
read + configure only.

Mounted via ``router.include_router(usage_routes.router)``.

Routes:

  GET  /proxy/usage                  per-provider + per-agent token view
  POST /proxy/usage/budget/save      upsert a per-agent budget (CSRF)
  POST /proxy/usage/budget/delete    remove a per-agent budget (CSRF)
"""
from __future__ import annotations

import logging
import pathlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf
from mcp_proxy.db import (
    aggregate_llm_usage,
    delete_agent_budget,
    list_agent_budgets,
    list_agents,
    log_audit,
    upsert_agent_budget,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-usage"])

# Window selector → days of look-back. ``all`` scans the whole chain.
_WINDOWS: dict[str, int | None] = {"7d": 7, "30d": 30, "all": None}
_DEFAULT_WINDOW = "30d"


def _window_start(window: str) -> str | None:
    """ISO-8601 UTC cutoff for ``window``; ``None`` for all-time.

    Mirrors the ``datetime.now(timezone.utc).isoformat()`` shape that
    ``log_audit`` writes, so the ``timestamp >= window_start`` comparison
    is a valid lexicographic range over identically-formatted strings.
    """
    days = _WINDOWS.get(window)
    if days is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _form_int(value: object) -> int:
    """Parse a non-negative int from a form field; 0 on anything invalid."""
    try:
        return max(0, int(str(value or "0").strip() or "0"))
    except (TypeError, ValueError):
        return 0


def _updated_by(session) -> str:
    return (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )


@router.get("/usage", response_class=HTMLResponse)
async def usage_page(request: Request) -> HTMLResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    window = request.query_params.get("window", _DEFAULT_WINDOW)
    if window not in _WINDOWS:
        window = _DEFAULT_WINDOW

    usage = await aggregate_llm_usage(_window_start(window))
    budgets = await list_agent_budgets()
    agents = await list_agents()
    settings = get_settings()

    return templates.TemplateResponse(
        "usage.html",
        _ctx(
            request,
            session,
            active="usage",
            window=window,
            windows=list(_WINDOWS.keys()),
            by_provider=usage["by_provider"],
            by_agent=usage["by_agent"],
            totals=usage["totals"],
            scanned=usage["scanned"],
            capped=usage["capped"],
            budgets=budgets,
            agent_ids=sorted({a["agent_id"] for a in agents}),
            default_tokens_per_day=settings.llm_tokens_per_day,
            default_tokens_per_month=settings.llm_tokens_per_month,
            saved=request.query_params.get("saved"),
        ),
    )


@router.post("/usage/budget/save")
async def save_budget(request: Request) -> RedirectResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    form = await request.form()
    agent_id = str(form.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(400, "agent_id is required")
    tokens_per_day = _form_int(form.get("tokens_per_day"))
    tokens_per_month = _form_int(form.get("tokens_per_month"))
    enabled = bool(form.get("enabled"))
    updated_by = _updated_by(session)

    await upsert_agent_budget(
        agent_id,
        tokens_per_day=tokens_per_day,
        tokens_per_month=tokens_per_month,
        enabled=enabled,
        updated_by=updated_by,
    )
    await log_audit(
        agent_id=updated_by,
        action="budget.upsert",
        status="success",
        details={
            "target_agent_id": agent_id,
            "tokens_per_day": tokens_per_day,
            "tokens_per_month": tokens_per_month,
            "enabled": enabled,
            "via": "dashboard",
        },
    )
    _log.info(
        "dashboard budget upsert agent=%s day=%d month=%d enabled=%s by=%s",
        agent_id, tokens_per_day, tokens_per_month, enabled, updated_by,
    )
    return RedirectResponse(url="/proxy/usage?saved=budget", status_code=303)


@router.post("/usage/budget/delete")
async def delete_budget(request: Request) -> RedirectResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    form = await request.form()
    agent_id = str(form.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(400, "agent_id is required")
    updated_by = _updated_by(session)

    await delete_agent_budget(agent_id)
    await log_audit(
        agent_id=updated_by,
        action="budget.delete",
        status="success",
        details={"target_agent_id": agent_id, "via": "dashboard"},
    )
    _log.info("dashboard budget delete agent=%s by=%s", agent_id, updated_by)
    return RedirectResponse(url="/proxy/usage?saved=budget-removed", status_code=303)
