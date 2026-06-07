"""Mastio dashboard — LLM usage metering sub-router.

Surfaces per-provider and per-agent token usage of the embedded AI
gateway. Unlike a commodity gateway's per-API-key counter, the numbers
here are derived read-time from the append-only audit chain
(``aggregate_llm_usage`` in :mod:`mcp_proxy.db`): every ``egress_llm_chat``
row carries the token counts, so what the operator sees is exactly what an
auditor can re-verify from the signed chain — attribution is per agent
identity, not per shared key.

Mounted via ``router.include_router(usage_routes.router)`` from
``mcp_proxy/dashboard/router.py`` so the outer ``/proxy`` prefix is
inherited.

Routes (1):

  GET  /proxy/usage         per-provider + per-agent token usage view
"""
from __future__ import annotations

import logging
import pathlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login
from mcp_proxy.db import aggregate_llm_usage

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


@router.get("/usage", response_class=HTMLResponse)
async def usage_page(request: Request) -> HTMLResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    window = request.query_params.get("window", _DEFAULT_WINDOW)
    if window not in _WINDOWS:
        window = _DEFAULT_WINDOW

    usage = await aggregate_llm_usage(_window_start(window))

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
        ),
    )
