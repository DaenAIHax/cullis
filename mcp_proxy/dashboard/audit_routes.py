"""Mastio dashboard - Audit sub-router.

Sprint F-B-201 PR-7 of 10. Extracts the audit log viewer (admin +
traffic streams unified) from ``mcp_proxy/dashboard/router.py`` into
a dedicated module. One route + one private helper.

Mounted via ``router.include_router(audit_routes.router)``.

Routes (1):

  GET  /proxy/audit         unified audit log viewer (admin + traffic)

The handler keeps both streams merged into a single view exactly as
before: legacy ``audit_log`` rows (auth, enroll, agent CRUD, policy)
plus the hash-chained ``local_audit`` rows (oneshot, mcp tool execute,
session send).
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-audit"])


def _unnest_json_strings(node, _depth: int = 0):
    """Recursively re-parse JSON-encoded strings found inside a parsed payload.

    MCP ``TextContent`` carries ``{"type": "text", "text": "<json string>"}``,
    so the audit ``detail`` ends up rendering as ``"text": "{\\"ok\\": ...}"``
    — readable, but every nested quote shows up as ``\\"``. When we see a
    string that round-trips through ``json.loads`` into a dict/list, we
    substitute the parsed value so the inspector shows the underlying
    object indented inline rather than a single escaped one-liner.

    Depth cap guards against pathological self-referential payloads.
    """
    import json as _json
    if _depth >= 6:
        return node
    if isinstance(node, dict):
        return {k: _unnest_json_strings(v, _depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [_unnest_json_strings(v, _depth + 1) for v in node]
    if isinstance(node, str):
        stripped = node.strip()
        if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")) and len(stripped) >= 2:
            try:
                inner = _json.loads(stripped)
            except (ValueError, TypeError):
                return node
            if isinstance(inner, (dict, list)):
                return _unnest_json_strings(inner, _depth + 1)
    return node


def _pretty_and_recipient(raw: str | None) -> tuple[str | None, str | None]:
    """Pretty-print a JSON detail string and pluck the recipient hint.

    The proxy writes traffic events to ``local_audit.details`` as JSON
    strings (oneshot forwarded, mcp tool execute, session send...). We
    parse the payload once server-side so the template can show both a
    formatted blob in the inspector and a ``Target`` hint in the row
    without doing the parsing twice.
    """
    import json as _json
    if not raw:
        return None, None
    try:
        parsed = _json.loads(raw)
    except (ValueError, TypeError):
        return raw, None
    recipient = None
    if isinstance(parsed, dict):
        recipient = (
            parsed.get("recipient")
            or parsed.get("recipient_agent_id")
            or parsed.get("target_agent_id")
            or parsed.get("target")
        )
    unnested = _unnest_json_strings(parsed)
    pretty = _json.dumps(unnested, indent=2, sort_keys=True)
    return pretty, recipient


def _derive_org_from_agent_id(agent_id: str | None) -> str | None:
    """Pull the org prefix from a typed agent id like ``orga::agent-name``.

    ``audit_log`` rows don't carry ``org_id`` directly the way the hash-chained
    ``local_audit`` rows do, but the SPIFFE-shaped ``agent_id`` always carries
    it as the leading component before ``::``. Surface it so the inspector
    side panel can show ``Org`` consistently across both audit streams.
    """
    if not agent_id or "::" not in agent_id:
        return None
    head = agent_id.split("::", 1)[0]
    return head or None


def _extract_mcp_request_id(raw_details: str | None) -> str | None:
    """Pull ``mcp_request_id`` out of ``local_audit.details`` JSON.

    ``mcp_resource_forwarder.py`` writes the executor-side ``request_id``
    into ``audit_details["mcp_request_id"]`` so the dashboard can join
    the traffic-stream ``resource_call`` row with the admin-stream
    ``tool_execute`` + ``policy.*`` rows that fan out from the same
    tool call. Returns ``None`` gracefully on legacy rows that pre-date
    that change.
    """
    if not raw_details:
        return None
    import json as _json
    try:
        parsed = _json.loads(raw_details)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    rid = parsed.get("mcp_request_id")
    if rid is None:
        return None
    return str(rid)


# Events that participate in the "one tool call → many audit rows"
# fan-out. Anything not in this set stays as a singleton group on the
# dashboard (auth.login, enrollment.*, agent.cert.rotate, etc).
_TOOL_CALL_EVENTS = frozenset({
    "tool_execute",
    "resource_call",
    "policy.no_capability_required",
})

# Status precedence — when multiple events share a group_key, the worst
# outcome wins for the card-level badge. ``denied`` beats ``error``
# beats ``success`` so a single capability-deny on the policy row
# colours the whole card red even if the (never-executed) tool_execute
# ended up with a stale ``success``.
_STATUS_RANK = {
    "denied": 3,
    "error": 2,
    "allow": 1,
    "ok": 1,
    "success": 1,
}


def _worst_status(statuses: list[str]) -> str:
    """Return the most severe status across a group's rows."""
    ranked = [(s, _STATUS_RANK.get(s or "", 0)) for s in statuses]
    ranked.sort(key=lambda kv: kv[1], reverse=True)
    return ranked[0][0] if ranked else "—"


def _humanize_event(event: str | None) -> str:
    """Map backend event names to short CISO-readable phrases."""
    if not event:
        return "Event"
    return {
        "tool_execute":                 "Tool execution",
        "resource_call":                "Egress to MCP resource",
        "policy.no_capability_required": "Policy check passed",
        "auth.login":                   "Dashboard login",
        "auth.token":                   "Token issued",
        "enroll.approve":               "Agent enrollment approved",
        "enroll.deny":                  "Agent enrollment denied",
        "agent.cert.rotate":            "Agent cert rotated",
        "egress_llm_chat":              "LLM completion (AI gateway)",
    }.get(event, event.replace("_", " ").replace(".", " · "))


# ── Cullis Audit Envelope reader ──────────────────────────────────────
#
# The "Cullis Audit Envelope" is the proprietary pattern that turns a
# tool's raw RPC result into a business-readable audit row. Every tool
# in the Cullis ecosystem is encouraged to emit a sidecar field —
# ``_cullis_audit: {action, subject, outcome}`` — alongside its native
# payload. Mastio reads it and uses it as the card-level header on the
# audit dashboard.
#
# Why a sidecar instead of a per-tool summarizer in Mastio:
#   - One pattern, scales across domains (trading, KYC, DORA, KYB...).
#   - Tool developer writes three strings, gets a business-readable
#     audit row for free.
#   - Third-party tools that don't adopt the pattern still render with
#     a generic "Tool invoked: X" fallback (see ``_group_audit_events``).
#
# Spec lives in ADR-039 (cullis-audit-envelope).


def _extract_audit_envelope(detail_pretty: str | None) -> dict | None:
    """Pull ``_cullis_audit`` from a tool_execute / resource_call detail.

    The detail string is the already-pretty-printed JSON the dashboard
    renders (``_pretty_and_recipient`` runs the unnest pass on it), so
    nested ``content[i].text`` strings have already been turned back
    into objects. Walks the parsed tree looking for ``_cullis_audit``
    at any nesting depth — tools may emit it at the top of the result
    or inside a nested ``content`` entry, both are valid.

    Returns the envelope dict ``{action, subject, outcome}`` or
    ``None`` if no envelope is present (graceful degradation).
    """
    if not detail_pretty:
        return None
    import json as _json
    try:
        parsed = _json.loads(detail_pretty)
    except (ValueError, TypeError):
        return None

    def _walk(node, depth: int = 0):
        if depth > 8 or node is None:
            return None
        if isinstance(node, dict):
            env = node.get("_cullis_audit")
            if isinstance(env, dict) and {"action", "subject", "outcome"} <= env.keys():
                return env
            for v in node.values():
                found = _walk(v, depth + 1)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for v in node:
                found = _walk(v, depth + 1)
                if found is not None:
                    return found
        return None

    return _walk(parsed)


def _ts_seconds(iso: str | None) -> float:
    """Parse an ISO-8601 timestamp into a float of seconds.

    Used only for the ±N second tiebreaker in the grouper — accuracy
    to the millisecond is enough, and we tolerate any reasonable
    formatting variation the audit writers use.
    """
    if not iso:
        return 0.0
    from datetime import datetime
    try:
        # ``fromisoformat`` accepts the ``+00:00`` offset emitted by
        # ``log_audit`` / ``append_local_audit``.
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0.0


# MCP JSON-RPC ``id`` is always ``"1"`` per HTTP POST (each tool call
# is a single envelope), so ``request_id`` does NOT discriminate
# successive tool calls. The 3 fan-out rows of a single call land
# within ~50 ms of each other (PDP → executor → forwarder are
# in-process, sequential). 500 ms is a generous ceiling for the
# fan-out and an aggressive floor against successive LLM-driven
# tool calls (which typically wait for the previous result, so are
# seconds apart).
_GROUP_TIME_WINDOW_SEC = 0.5


def _group_audit_events(entries: list[dict]) -> list[dict]:
    """Collapse the 3-row fan-out of one tool call into a single card.

    Group key: ``(agent_id, tool_name, request_id)`` PLUS a ±5s
    timestamp tiebreaker.

    Why the tiebreaker exists: the SDK uses the MCP JSON-RPC sequence
    (1, 2, 3, ...) for ``request_id``, so two tool calls a few seconds
    apart on the same agent can collide on ``(agent, tool, "1")``.
    Without the tiebreaker the dashboard collapses every successive
    ``get_market_data`` call into one fat card. With it, calls that
    drift more than 5 seconds apart land in separate cards even if
    the request_id happens to be re-used.

    Events outside :data:`_TOOL_CALL_EVENTS` stay as singletons. So do
    tool-call events that happen to have ``request_id`` missing on a
    legacy row — better one row by itself than a wrong collapse.
    """
    # Walk entries in chronological order so the tiebreaker can compare
    # against the latest timestamp in the candidate bucket. The
    # ``entries`` argument arrives sorted DESC, so reverse for the
    # grouping pass and re-sort the card list at the end.
    asc = sorted(entries, key=lambda x: _ts_seconds(x.get("timestamp")))
    groups_by_key: dict[str, dict] = {}
    singletons: list[dict] = []

    for e in asc:
        event = e.get("event")
        agent_id = e.get("agent_id")
        tool_name = e.get("tool_name") or e.get("target")
        request_id = e.get("request_id")

        if (
            event in _TOOL_CALL_EVENTS
            and agent_id
            and tool_name
            and request_id
        ):
            base_key = f"{agent_id}::{tool_name}::{request_id}"
            ts = _ts_seconds(e.get("timestamp"))
            # Find an existing bucket within the time window, else
            # open a new one with a generation suffix.
            chosen_key = None
            gen = 0
            while True:
                candidate = f"{base_key}::{gen}"
                bucket = groups_by_key.get(candidate)
                if bucket is None:
                    chosen_key = candidate
                    break
                last_ts = bucket["_last_ts"]
                if abs(ts - last_ts) <= _GROUP_TIME_WINDOW_SEC:
                    chosen_key = candidate
                    break
                gen += 1

            bucket = groups_by_key.setdefault(chosen_key, {
                "key": chosen_key,
                "kind": "tool_call",
                "title": f"Tool invoked: {tool_name}",
                "subtitle": None,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "org_id": e.get("org_id"),
                "request_id": request_id,
                "events": [],
                "_last_ts": ts,
            })
            bucket["events"].append(e)
            bucket["_last_ts"] = max(bucket["_last_ts"], ts)
        else:
            singletons.append({
                "key": f"singleton::{e.get('timestamp')}::{event}::{agent_id}",
                "kind": "singleton",
                "title": _humanize_event(event),
                "subtitle": e.get("target"),
                "agent_id": agent_id,
                "tool_name": e.get("tool_name"),
                "org_id": e.get("org_id"),
                "request_id": e.get("request_id"),
                "events": [e],
            })

    cards: list[dict] = list(groups_by_key.values()) + singletons

    for card in cards:
        evs = sorted(card["events"], key=lambda x: x.get("timestamp") or "")
        card["events"] = evs
        card["timestamp"] = evs[0].get("timestamp") if evs else None
        card["timestamp_end"] = evs[-1].get("timestamp") if evs else None
        card["status"] = _worst_status([ev.get("status") for ev in evs])
        # Duration comes from the ``tool_execute`` row when present;
        # ``resource_call`` doesn't carry one and ``policy.*`` is point-in-time.
        tool_exec = next((ev for ev in evs if ev.get("event") == "tool_execute"), None)
        card["duration_ms"] = (tool_exec or evs[0]).get("duration_ms") if evs else None
        card["chain_seqs"] = [ev.get("chain_seq") for ev in evs if ev.get("chain_seq") is not None]
        # ── Cullis Audit Envelope override ────────────────────────────
        # If the tool emitted ``_cullis_audit`` (see ADR-039), use it
        # as the card title/subtitle so the dashboard tells a business
        # story instead of an RPC name. Search the resource_call detail
        # first (closest to the tool's native response) and fall back
        # to tool_execute detail (carries the same payload through
        # PR #886's result_summary).
        envelope = None
        for ev in evs:
            if ev.get("event") in ("resource_call", "tool_execute"):
                envelope = _extract_audit_envelope(ev.get("detail_pretty"))
                if envelope:
                    break
        card["envelope"] = envelope
        if envelope:
            card["title"] = f"{envelope['action']}: {envelope['subject']}"
            card["subtitle"] = envelope["outcome"]
        elif card["kind"] == "tool_call":
            for ev in evs:
                if ev.get("event") == "resource_call" and ev.get("endpoint_url"):
                    card["subtitle"] = ev["endpoint_url"]
                    break
            if not card["subtitle"]:
                card["subtitle"] = "via Mastio gateway"
        card["events_count"] = len(evs)

    # Most recent card first by *end* timestamp (the last event written
    # for a group is the one that closes it).
    cards.sort(key=lambda c: c.get("timestamp_end") or c.get("timestamp") or "", reverse=True)
    return cards


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db, list_agents

    agent_filter = request.query_params.get("agent", "")
    action_filter = request.query_params.get("action", "")
    status_filter = request.query_params.get("status", "")
    source_filter = request.query_params.get("source", "")  # '', 'admin', 'traffic'
    # ``view=grouped`` (default) collapses the 3-row fan-out of one
    # tool call into a single card readable by a CISO. ``view=raw``
    # keeps the legacy per-row table for maintainer-side debugging.
    view_mode = request.query_params.get("view", "grouped")
    if view_mode not in ("grouped", "raw"):
        view_mode = "grouped"
    page = int(request.query_params.get("page", "1"))
    per_page = 50

    from sqlalchemy import text

    # ``audit_log`` uses ``status='success'``; ``local_audit`` uses
    # ``result='ok'`` for the same concept. Map the UI filter once and
    # use the per-table equivalent when building WHERE clauses.
    local_audit_result_for = {"success": "ok", "ok": "ok", "error": "error", "denied": "denied"}

    async with get_db() as db:
        admin_rows: list[dict] = []
        traffic_rows: list[dict] = []

        # Admin stream - legacy ``audit_log`` (auth, enroll, agent CRUD, policy...)
        if source_filter in ("", "admin"):
            a_conds: list[str] = []
            a_params: dict[str, object] = {}
            if agent_filter:
                a_conds.append("agent_id = :agent_id")
                a_params["agent_id"] = agent_filter
            if action_filter:
                a_conds.append("action = :action")
                a_params["action"] = action_filter
            if status_filter:
                a_conds.append("status = :status")
                a_params["status"] = status_filter
            a_where = (" WHERE " + " AND ".join(a_conds)) if a_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM audit_log{a_where} ORDER BY timestamp DESC LIMIT 500"),
                a_params,
            )
            admin_rows = [dict(r) for r in result.mappings().all()]

        # Traffic stream - hash-chained ``local_audit`` (oneshot, mcp, sessions)
        if source_filter in ("", "traffic"):
            t_conds: list[str] = []
            t_params: dict[str, object] = {}
            if agent_filter:
                t_conds.append("agent_id = :agent_id")
                t_params["agent_id"] = agent_filter
            if action_filter:
                t_conds.append("event_type = :event_type")
                t_params["event_type"] = action_filter
            if status_filter:
                t_conds.append("result = :result")
                t_params["result"] = local_audit_result_for.get(status_filter, status_filter)
            t_where = (" WHERE " + " AND ".join(t_conds)) if t_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM local_audit{t_where} ORDER BY timestamp DESC LIMIT 500"),
                t_params,
            )
            traffic_rows = [dict(r) for r in result.mappings().all()]

        # Distinct actions + event_types for the filter dropdown.
        r1 = await db.execute(text("SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL"))
        r2 = await db.execute(text("SELECT DISTINCT event_type FROM local_audit WHERE event_type IS NOT NULL"))
        actions = sorted(set(r[0] for r in r1.fetchall()) | set(r[0] for r in r2.fetchall()))

    # Normalize both streams into a single shape so the template has
    # exactly one cell layout to render. Fields that only exist in one
    # table are left as ``None`` for the other source; the inspector
    # hides rows where the value is missing.
    unified: list[dict] = []
    for r in admin_rows:
        detail_pretty, _ = _pretty_and_recipient(r.get("detail"))
        agent_id = r.get("agent_id")
        unified.append({
            "source": "admin",
            "timestamp": r.get("timestamp"),
            "agent_id": agent_id,
            "event": r.get("action"),
            "status": r.get("status"),
            "target": r.get("tool_name"),
            "tool_name": r.get("tool_name"),
            "duration_ms": r.get("duration_ms"),
            "request_id": r.get("request_id"),
            "endpoint_url": None,
            "session_id": None,
            # ``audit_log`` rows participate in the same hash chain as
            # ``local_audit`` (ADR-014). Surface ``chain_seq`` + ``row_hash``
            # in the side panel so admin events show their chain position
            # alongside traffic events. Org is derived from the typed
            # agent_id prefix (no native column on ``audit_log``).
            "org_id": _derive_org_from_agent_id(agent_id),
            "chain_seq": r.get("chain_seq"),
            "entry_hash": r.get("row_hash"),
            "peer_org_id": None,
            "detail_pretty": detail_pretty,
        })
    for r in traffic_rows:
        raw_details = r.get("details")
        detail_pretty, recipient = _pretty_and_recipient(raw_details)
        raw_result = r.get("result")
        status_display = "success" if raw_result == "ok" else raw_result
        # Pull ``tool`` and ``endpoint_url`` out of the details JSON
        # so the grouper can match on ``tool_name`` and surface the
        # MCP origin (mcp-portfolio:9900) in the card subtitle.
        import json as _json_local
        tool_name_traffic = None
        endpoint_url = None
        if raw_details:
            try:
                _det = _json_local.loads(raw_details)
                if isinstance(_det, dict):
                    tool_name_traffic = _det.get("tool")
                    endpoint_url = _det.get("endpoint_url")
            except (ValueError, TypeError):
                pass
        unified.append({
            "source": "traffic",
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "event": r.get("event_type"),
            "status": status_display,
            "target": recipient or tool_name_traffic,
            "tool_name": tool_name_traffic,
            "endpoint_url": endpoint_url,
            "duration_ms": None,
            "request_id": _extract_mcp_request_id(raw_details),
            "session_id": r.get("session_id"),
            "org_id": r.get("org_id"),
            "chain_seq": r.get("chain_seq"),
            "entry_hash": r.get("entry_hash"),
            "peer_org_id": r.get("peer_org_id"),
            "detail_pretty": detail_pretty,
        })

    # ISO-8601 strings sort correctly as plain strings, no parsing needed.
    unified.sort(key=lambda x: x["timestamp"] or "", reverse=True)

    admin_total = sum(1 for e in unified if e["source"] == "admin")
    traffic_total = len(unified) - admin_total

    # ``view=grouped`` (default) → CISO-mode card view, one card per
    # tool call. ``view=raw`` → maintainer-mode flat row table.
    if view_mode == "grouped":
        cards = _group_audit_events(unified)
        total = len(cards)
        total_pages = max(1, (total + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        page_cards = cards[offset:offset + per_page]
        entries = []  # raw-view list stays empty in grouped mode
    else:
        total = len(unified)
        total_pages = max(1, (total + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        entries = unified[offset:offset + per_page]
        page_cards = []

    agents = await list_agents()
    agent_ids = sorted(set(a["agent_id"] for a in agents))

    return templates.TemplateResponse("audit.html", _ctx(
        request, session,
        active="audit",
        view_mode=view_mode,
        cards=page_cards,
        entries=entries,
        agent_ids=agent_ids,
        actions=actions,
        agent_filter=agent_filter,
        action_filter=action_filter,
        status_filter=status_filter,
        source_filter=source_filter,
        page=page,
        total_pages=total_pages,
        admin_total=admin_total,
        traffic_total=traffic_total,
        total=total,
    ))


# ── Chain integrity verification (POST /proxy/audit/verify) ────────
#
# Mirrors the logic in ``scripts/cullis-audit-verify.py`` but runs
# in-process against the live ``local_audit`` table so an operator can
# click "Verify chain integrity" in the dashboard and get a verdict
# without having to export NDJSON + run a CLI offline. Both paths
# remain valid — the CLI is the auditor's "without trusting Cullis"
# story, this is the operator's "is my chain healthy today" story.


def _canonical_for_row(entry: dict, previous_hash: str | None) -> str:
    """Reconstruct the canonical string used to compute ``entry_hash``.

    Kept byte-compatible with ``scripts/cullis-audit-verify.py::canonical``
    (and with the writer in ``mcp_proxy/local/audit_chain.py``) so a
    pass here matches a pass under the offline verifier and vice versa.
    """
    fmt = (entry.get("hash_format") or "v1").lower()
    chain_seq = entry.get("chain_seq")
    if fmt == "v2":
        canonical_str = "|".join([
            "v2",
            entry["timestamp"] or "",
            entry["event_type"],
            entry.get("agent_id") or "",
            entry.get("session_id") or "",
            entry.get("org_id") or "",
            entry["result"],
            entry.get("details") or "",
            previous_hash or "genesis",
            f"seq={chain_seq}",
            f"peer={entry.get('peer_org_id') or ''}",
        ])
    else:
        base = "|".join([
            str(entry["id"]),
            entry["timestamp"] or "",
            entry["event_type"],
            entry.get("agent_id") or "",
            entry.get("session_id") or "",
            entry.get("org_id") or "",
            entry["result"],
            entry.get("details") or "",
            previous_hash or "genesis",
        ])
        if chain_seq is None:
            canonical_str = base
        else:
            canonical_str = (
                f"{base}|seq={chain_seq}|peer={entry.get('peer_org_id') or ''}"
            )
    pt = entry.get("principal_type")
    if pt and pt != "agent":
        canonical_str = f"{canonical_str}|pt={pt}"
    return canonical_str


@router.post("/audit/verify")
async def verify_chain(request: Request) -> JSONResponse:
    """Run the same chain check as ``cullis-audit-verify.py``, in-process.

    Returns 200 with a JSON verdict regardless of pass/fail — the
    front-end inspects ``ok`` and renders a green or red banner. Real
    failures use HTTP 200 + ``ok: false`` rather than HTTP 4xx/5xx so
    the operator can read the failure detail without their browser
    showing an error page.
    """
    import hashlib
    from collections import defaultdict

    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return JSONResponse({"ok": False, "error": "auth_required"}, status_code=401)
    if not await verify_csrf(request, session):
        return JSONResponse({"ok": False, "error": "csrf_invalid"}, status_code=403)

    from mcp_proxy.db import get_db
    from sqlalchemy import text

    async with get_db() as db:
        result = await db.execute(text(
            "SELECT id, timestamp, agent_id, event_type, details, "
            "previous_hash, entry_hash, session_id, org_id, result, "
            "chain_seq, peer_org_id, peer_row_hash, hash_format "
            "FROM local_audit ORDER BY id ASC"
        ))
        entries = [dict(r) for r in result.mappings().all()]

    # Per-org chain check (mirrors verify_chains in the CLI). Legacy
    # global-chain rows (chain_seq IS NULL) are still validated first
    # so their tail becomes the seed for the per-org chain.
    agents_seen: set[str] = set()
    orgs_seen: set[str] = set()
    for e in entries:
        if e.get("agent_id"):
            agents_seen.add(e["agent_id"])
        if e.get("org_id"):
            orgs_seen.add(e["org_id"])

    # Legacy global chain
    legacy_prev: str | None = None
    legacy_n = 0
    for e in entries:
        if e.get("chain_seq") is not None or e.get("entry_hash") is None:
            continue
        expected = _canonical_for_row(e, legacy_prev)
        computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if computed != e["entry_hash"]:
            return JSONResponse({
                "ok": False,
                "failure": {
                    "kind": "mismatch",
                    "scope": "legacy",
                    "id": e["id"],
                    "agent_id": e.get("agent_id"),
                    "event_type": e.get("event_type"),
                    "timestamp": e.get("timestamp"),
                    "expected_hash": computed,
                    "observed_hash": e["entry_hash"],
                },
            })
        if e.get("previous_hash") != legacy_prev:
            return JSONResponse({
                "ok": False,
                "failure": {
                    "kind": "break",
                    "scope": "legacy",
                    "id": e["id"],
                    "timestamp": e.get("timestamp"),
                    "declared_prev": e.get("previous_hash"),
                    "expected_prev": legacy_prev,
                },
            })
        legacy_prev = e["entry_hash"]
        legacy_n += 1

    last_legacy: dict[str, str] = {}
    for e in entries:
        if e.get("chain_seq") is None and e.get("entry_hash") is not None:
            last_legacy[e.get("org_id") or ""] = e["entry_hash"]

    per_org: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("chain_seq") is not None:
            per_org[e.get("org_id") or ""].append(e)

    per_org_n = 0
    for org, rows in per_org.items():
        rows.sort(key=lambda r: r["chain_seq"])
        expected_prev = last_legacy.get(org)
        for e in rows:
            expected = _canonical_for_row(e, expected_prev)
            computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
            if computed != e["entry_hash"]:
                return JSONResponse({
                    "ok": False,
                    "failure": {
                        "kind": "mismatch",
                        "scope": "per_org",
                        "org_id": org,
                        "chain_seq": e["chain_seq"],
                        "id": e["id"],
                        "agent_id": e.get("agent_id"),
                        "event_type": e.get("event_type"),
                        "timestamp": e.get("timestamp"),
                        "expected_hash": computed,
                        "observed_hash": e["entry_hash"],
                    },
                })
            if e.get("previous_hash") != expected_prev:
                return JSONResponse({
                    "ok": False,
                    "failure": {
                        "kind": "break",
                        "scope": "per_org",
                        "org_id": org,
                        "chain_seq": e["chain_seq"],
                        "id": e["id"],
                        "timestamp": e.get("timestamp"),
                        "declared_prev": e.get("previous_hash"),
                        "expected_prev": expected_prev,
                    },
                })
            expected_prev = e["entry_hash"]
            per_org_n += 1

    return JSONResponse({
        "ok": True,
        "entries": len(entries),
        "agents": len(agents_seen),
        "orgs": len(orgs_seen),
        "legacy_chain_rows": legacy_n,
        "per_org_chain_rows": per_org_n,
    })
