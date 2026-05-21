"""MCP-style tool handlers for the Pitchbook Builder.

Chinese Wall is enforced HERE, at the boundary between the LLM and the
internal research store. `read_internal_research` passes the memo's desk
into the capability gate context; the gate refuses if the principal's
`desk` scope does not match.

This is the same pattern Mastio uses for per-tenant data access:
the capability gate, not the LLM, is the source of truth.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

from shared.audit_hooks import AuditChain
from shared.capability_gate import CapabilityDenied, CapabilityGate, Principal
from shared.test_fixtures import COMPS_DB, INTERNAL_RESEARCH, NEWS_FEED

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "query_comps_db",
            "description": "Look up public comparable companies by industry and rough size range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "industry": {"type": "string"},
                    "size_range": {"type": "string", "description": "e.g. 'mid', 'large'"},
                },
                "required": ["industry"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_internal_research",
            "description": "Read an internal research memo by ID. Gated by Chinese Wall: cross-desk reads are denied.",
            "parameters": {
                "type": "object",
                "properties": {
                    "memo_id": {"type": "string"},
                },
                "required": ["memo_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "news_feed_query",
            "description": "Pull public news headlines for a target company.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_name": {"type": "string"},
                    "timeframe": {"type": "string", "description": "e.g. '30d'"},
                },
                "required": ["target_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_excel",
            "description": "Emit an Excel artefact for a comps table. Returns an opaque artefact ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "comps_table": {
                        "type": "array",
                        "items": {"type": "object"},
                    },
                },
                "required": ["comps_table"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_pptx",
            "description": "Emit a PowerPoint deck artefact. Returns an opaque artefact ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "brief": {"type": "string"},
                    "comps_artifact_id": {"type": "string"},
                    "sections": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["brief", "sections"],
            },
        },
    },
]


def query_comps_db(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="pitchbook.read_comps", context={"tool": "query_comps_db"})
    audit.append("tool_call", {"tool": "query_comps_db", "args": args})
    industry = args.get("industry", "").lower()
    rows = COMPS_DB.get(industry, [])
    result = {"industry": industry, "rows": rows, "count": len(rows)}
    audit.append("tool_result", {"tool": "query_comps_db", "args": args, "result": result})
    return result


def read_internal_research(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    memo_id = args.get("memo_id", "")
    memo = INTERNAL_RESEARCH.get(memo_id)
    audit.append(
        "tool_call",
        {
            "tool": "read_internal_research",
            "args": args,
            "principal_desk": principal.scopes.get("desk"),
            "memo_desk": memo["desk"] if memo else None,
        },
    )
    if memo is None:
        result: dict[str, Any] = {"ok": False, "error": "memo_not_found"}
        audit.append(
            "tool_result",
            {"tool": "read_internal_research", "args": args, "result": result},
        )
        return result

    # Chinese Wall: gate context includes the memo's desk so the YAML
    # `required_scopes.desk.from_context: memo_desk` resolves against the
    # principal's `desk` scope.
    gate.require(
        principal,
        capability="pitchbook.read_research",
        context={"memo_desk": memo["desk"], "memo_id": memo_id},
    )

    result = {
        "ok": True,
        "memo_id": memo_id,
        "title": memo["title"],
        "desk": memo["desk"],
        "mnpi": memo["mnpi"],
        "body": memo["body"],
    }
    audit.append(
        "tool_result",
        {"tool": "read_internal_research", "args": args, "result": result},
    )
    return result


def news_feed_query(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(principal, capability="pitchbook.read_news", context={"tool": "news_feed_query"})
    audit.append("tool_call", {"tool": "news_feed_query", "args": args})
    target = args.get("target_name", "")
    rows = NEWS_FEED.get(target, [])
    result = {"target_name": target, "headlines": rows, "count": len(rows)}
    audit.append("tool_result", {"tool": "news_feed_query", "args": args, "result": result})
    return result


def generate_excel(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(
        principal,
        capability="pitchbook.generate_artifact",
        context={"tool": "generate_excel"},
    )
    audit.append("tool_call", {"tool": "generate_excel", "args": args})
    artifact_id = f"xlsx_{uuid.uuid4().hex[:10]}"
    result = {
        "artifact_id": artifact_id,
        "type": "xlsx",
        "row_count": len(args.get("comps_table", [])),
    }
    audit.append("tool_result", {"tool": "generate_excel", "args": args, "result": result})
    return result


def generate_pptx(
    args: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    gate.require(
        principal,
        capability="pitchbook.generate_artifact",
        context={"tool": "generate_pptx"},
    )
    audit.append("tool_call", {"tool": "generate_pptx", "args": args})
    artifact_id = f"pptx_{uuid.uuid4().hex[:10]}"
    result = {
        "artifact_id": artifact_id,
        "type": "pptx",
        "section_count": len(args.get("sections", [])),
    }
    audit.append("tool_result", {"tool": "generate_pptx", "args": args, "result": result})
    return result


HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "query_comps_db": query_comps_db,
    "read_internal_research": read_internal_research,
    "news_feed_query": news_feed_query,
    "generate_excel": generate_excel,
    "generate_pptx": generate_pptx,
}


def dispatch(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    principal: Principal,
    gate: CapabilityGate,
    audit: AuditChain,
) -> dict[str, Any]:
    handler = HANDLERS.get(tool_name)
    if handler is None:
        result = {"ok": False, "error": "unknown_tool", "tool": tool_name}
        audit.append("tool_error", {"tool": tool_name, "args": arguments, "error": result})
        return result
    try:
        return handler(arguments, principal=principal, gate=gate, audit=audit)
    except CapabilityDenied as exc:
        # Surface the denial as a structured tool result so the LLM can
        # observe it inside the conversation and adjust (e.g. NOT cite the
        # blocked memo in the final deck brief).
        return {
            "ok": False,
            "error": "capability_denied",
            "capability": exc.capability,
            "reason": exc.reason,
        }
