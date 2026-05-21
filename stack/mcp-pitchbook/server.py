"""MCP server: Pitchbook tools for the reference demo (modern dogfood stack).

JSON-RPC 2.0 over POST /. Five tools backed by synthetic in-memory mock
data (comps DB, internal research memos, news feed, artefact emitters).

The server returns memo data with its `desk` and `mnpi` fields populated;
the Information Barrier ("Chinese Wall") enforcement happens at the
agent loop layer on the Mastio side: the agent inspects the response,
compares memo.desk to its inherited principal.desk scope, and refuses
to cite blocked content. The server does NOT enforce per-call gating
because Mastio's per-resource binding is the current authz unit
(per-tool binding is future ADR work).

Tools:
  * query_comps_db(industry, size_range)
  * read_internal_research(memo_id)
  * news_feed_query(target_name, timeframe)
  * generate_excel(comps_table)
  * generate_pptx(brief, comps_artifact_id, sections)
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-pitchbook", version="0.1.0")

_DB_PATH = Path(os.environ.get("MCP_PITCHBOOK_DB", "/data/pitchbook_artifacts.jsonl"))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_PROTOCOL_VERSION = "2024-11-05"

_COMPS_DB: dict[str, list[dict[str, Any]]] = {
    "saas": [
        {"name": "DemoCorpA", "ev_revenue": 8.4, "ev_ebitda": 32.0, "growth": 0.41},
        {"name": "DemoCorpB", "ev_revenue": 6.1, "ev_ebitda": 28.5, "growth": 0.34},
        {"name": "DemoCorpC", "ev_revenue": 4.7, "ev_ebitda": 22.0, "growth": 0.28},
    ],
    "industrials": [
        {"name": "IndustrialDemoA", "ev_revenue": 1.8, "ev_ebitda": 12.0, "growth": 0.08},
        {"name": "IndustrialDemoB", "ev_revenue": 2.1, "ev_ebitda": 14.5, "growth": 0.11},
    ],
}

_INTERNAL_RESEARCH: dict[str, dict[str, Any]] = {
    "memo_tech_001": {
        "memo_id": "memo_tech_001",
        "desk": "tech",
        "title": "DemoCorpA Q3 outlook",
        "mnpi": True,
        "body": "[SYNTHETIC] tech-desk MNPI body content",
    },
    "memo_industrials_001": {
        "memo_id": "memo_industrials_001",
        "desk": "industrials",
        "title": "IndustrialDemoA capex cycle",
        "mnpi": False,
        "body": "[SYNTHETIC] industrials-desk public-side content",
    },
    "memo_industrials_002": {
        "memo_id": "memo_industrials_002",
        "desk": "industrials",
        "title": "IndustrialDemoB carve-out rumor",
        "mnpi": True,
        "body": "[SYNTHETIC] industrials-desk MNPI body content",
    },
}

_NEWS_FEED: dict[str, list[dict[str, Any]]] = {
    "DemoCorpA": [
        {"timestamp": "2026-05-10T09:14:00Z", "headline": "DemoCorpA expands EU footprint"},
        {"timestamp": "2026-05-18T11:00:00Z", "headline": "DemoCorpA hires new CFO"},
    ],
    "IndustrialDemoA": [
        {"timestamp": "2026-05-12T08:30:00Z", "headline": "IndustrialDemoA capex up 12% YoY"}
    ],
    "IndustrialDemoB": [
        {"timestamp": "2026-05-15T10:45:00Z", "headline": "IndustrialDemoB explores divestments"}
    ],
}


_TOOLS = [
    {
        "name": "query_comps_db",
        "description": "Look up public comparable companies by industry and rough size range.",
        "inputSchema": {
            "type": "object",
            "required": ["industry"],
            "properties": {
                "industry": {"type": "string"},
                "size_range": {"type": "string", "description": "e.g. 'mid', 'large'"},
            },
        },
    },
    {
        "name": "read_internal_research",
        "description": "Read an internal research memo by ID. Returns the memo with `desk` and `mnpi` fields; the agent enforces Chinese Wall on the response.",
        "inputSchema": {
            "type": "object",
            "required": ["memo_id"],
            "properties": {"memo_id": {"type": "string"}},
        },
    },
    {
        "name": "news_feed_query",
        "description": "Pull public news headlines for a target company.",
        "inputSchema": {
            "type": "object",
            "required": ["target_name"],
            "properties": {
                "target_name": {"type": "string"},
                "timeframe": {"type": "string", "description": "e.g. '30d'"},
            },
        },
    },
    {
        "name": "generate_excel",
        "description": "Emit an Excel artefact for a comps table. Returns an opaque artefact ID.",
        "inputSchema": {
            "type": "object",
            "required": ["comps_table"],
            "properties": {
                "comps_table": {"type": "array", "items": {"type": "object"}},
            },
        },
    },
    {
        "name": "generate_pptx",
        "description": "Emit a PowerPoint deck artefact. Returns an opaque artefact ID.",
        "inputSchema": {
            "type": "object",
            "required": ["brief", "sections"],
            "properties": {
                "brief": {"type": "string"},
                "comps_artifact_id": {"type": "string"},
                "sections": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
]


def _persist_artifact(kind: str, artifact_id: str, payload: dict[str, Any]) -> None:
    with _DB_PATH.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {"kind": kind, "artifact_id": artifact_id, "at": time.time(), "payload": payload},
                sort_keys=True,
            )
        )
        fh.write("\n")


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "db": str(_DB_PATH), "tools": len(_TOOLS)}


def _query_comps_db(args: dict[str, Any]) -> dict[str, Any]:
    industry = (args.get("industry") or "").lower()
    rows = _COMPS_DB.get(industry, [])
    return {"industry": industry, "rows": rows, "count": len(rows)}


def _read_internal_research(args: dict[str, Any]) -> dict[str, Any]:
    memo_id = args.get("memo_id", "")
    memo = _INTERNAL_RESEARCH.get(memo_id)
    if memo is None:
        return {"ok": False, "error": "memo_not_found", "memo_id": memo_id}
    return {
        "ok": True,
        "memo_id": memo_id,
        "title": memo["title"],
        "desk": memo["desk"],
        "mnpi": memo["mnpi"],
        "body": memo["body"],
    }


def _news_feed_query(args: dict[str, Any]) -> dict[str, Any]:
    target = args.get("target_name", "")
    rows = _NEWS_FEED.get(target, [])
    return {"target_name": target, "headlines": rows, "count": len(rows)}


def _generate_excel(args: dict[str, Any]) -> dict[str, Any]:
    aid = f"xlsx_{uuid.uuid4().hex[:10]}"
    rows = args.get("comps_table") or []
    _persist_artifact("xlsx", aid, {"row_count": len(rows)})
    return {"artifact_id": aid, "type": "xlsx", "row_count": len(rows)}


def _generate_pptx(args: dict[str, Any]) -> dict[str, Any]:
    aid = f"pptx_{uuid.uuid4().hex[:10]}"
    sections = args.get("sections") or []
    _persist_artifact("pptx", aid, {"section_count": len(sections)})
    return {"artifact_id": aid, "type": "pptx", "section_count": len(sections)}


_DISPATCH = {
    "query_comps_db": _query_comps_db,
    "read_internal_research": _read_internal_research,
    "news_feed_query": _news_feed_query,
    "generate_excel": _generate_excel,
    "generate_pptx": _generate_pptx,
}


@app.post("/")
async def rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_rpc_error(None, -32700, "parse error"), status_code=400)

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params") or {}

    print(
        f"mcp-pitchbook: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)[:200]}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-pitchbook", "version": "0.1.0"},
        }))

    if method == "notifications/initialized":
        return JSONResponse(None, status_code=204)

    if method == "tools/list":
        return JSONResponse(_rpc_result(req_id, {"tools": _TOOLS}))

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        handler = _DISPATCH.get(name)
        if handler is None:
            return JSONResponse(_rpc_error(req_id, -32601, f"tool not found: {name}"))
        try:
            result = handler(args)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _rpc_result(
                    req_id,
                    {"content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(exc)})}]},
                )
            )
        return JSONResponse(_rpc_result(req_id, {
            "content": [{"type": "text", "text": json.dumps(result)}]
        }))

    return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))
