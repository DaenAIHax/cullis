"""MCP server: KYC tools for the reference demo (modern dogfood stack).

JSON-RPC 2.0 over POST /. Four tools backed by synthetic in-memory mock
data, intentionally signaled to prevent confusion with real records.
Mirrors stack/mcp-messages/server.py shape; runs inside the docker
network and is reverse-proxied by Mastio after BYOCA enrolment +
local_agent_resource_bindings approval.

Tools:
  * verify_identity(document_id)            -- mock Onfido/Veriff lookup
  * screen_sanctions(family_name, dob)       -- mock OFAC+EU consolidated
  * query_beneficial_owners(entity_name)     -- mock OpenCorporates query
  * escalate_to_compliance(case_id, reason)  -- emits a structured event

The server itself is intentionally trustful: Mastio's PDP +
local_agent_resource_bindings is the gate. Per-tool capability gating
within a single MCP server is not yet supported (future ADR work);
for the demo, the KYC agent's outcome-level checks (score threshold,
kyc.auto_approve presence on the principal) run inside the agent loop
on the Mastio side, mirroring the standalone scaffold.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-kyc", version="0.1.0")

_DB_PATH = Path(os.environ.get("MCP_KYC_DB", "/data/kyc_events.jsonl"))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_PROTOCOL_VERSION = "2024-11-05"

# Synthetic mock data. ALL fictional. No real persons, no real KYC.
_KYC_DOCUMENTS: dict[str, dict[str, Any]] = {
    "doc_low_risk_retail": {
        "doc_id": "doc_low_risk_retail",
        "type": "passport",
        "country": "IT",
        "given_name": "Mario",
        "family_name": "Rossi",
        "dob": "1985-04-12",
        "expiry": "2034-03-01",
        "image_quality": 0.94,
    },
    "doc_sanctions_hit": {
        "doc_id": "doc_sanctions_hit",
        "type": "passport",
        "country": "RU",
        "given_name": "Synthetic-Sanctions-Test",
        "family_name": "Petrov",
        "dob": "1970-01-01",
        "expiry": "2030-01-01",
        "image_quality": 0.91,
    },
    "doc_high_risk_pep": {
        "doc_id": "doc_high_risk_pep",
        "type": "national_id",
        "country": "IT",
        "given_name": "Synthetic-PEP-Test",
        "family_name": "Bianchi",
        "dob": "1962-07-21",
        "expiry": "2031-12-31",
        "image_quality": 0.88,
    },
}

_SANCTIONS_LIST: list[dict[str, Any]] = [
    {
        "list_name": "OFAC-SDN-DEMO",
        "family_name": "Petrov",
        "given_name": "Synthetic-Sanctions-Test",
        "dob": "1970-01-01",
        "reason": "synthetic_demo_entry",
    },
]

_PEP_LIST: list[dict[str, Any]] = [
    {
        "family_name": "Bianchi",
        "given_name": "Synthetic-PEP-Test",
        "dob": "1962-07-21",
        "role": "synthetic_demo_minister",
    },
]


_TOOLS = [
    {
        "name": "verify_identity",
        "description": "Verify an identity document against the (mocked) Onfido/Veriff provider.",
        "inputSchema": {
            "type": "object",
            "required": ["document_id"],
            "properties": {
                "document_id": {"type": "string"},
            },
        },
    },
    {
        "name": "screen_sanctions",
        "description": "Screen a (family_name, given_name, dob) tuple against the (mocked) OFAC + EU consolidated lists.",
        "inputSchema": {
            "type": "object",
            "required": ["family_name", "dob"],
            "properties": {
                "family_name": {"type": "string"},
                "given_name": {"type": "string"},
                "dob": {"type": "string", "description": "ISO date YYYY-MM-DD"},
            },
        },
    },
    {
        "name": "query_beneficial_owners",
        "description": "Look up beneficial owners for a corporate entity (mock OpenCorporates).",
        "inputSchema": {
            "type": "object",
            "required": ["entity_name"],
            "properties": {
                "entity_name": {"type": "string"},
            },
        },
    },
    {
        "name": "escalate_to_compliance",
        "description": "Hand the case to a human compliance officer queue. Always required when score >= 30 or any sanctions/PEP hit.",
        "inputSchema": {
            "type": "object",
            "required": ["case_id", "reason"],
            "properties": {
                "case_id": {"type": "string"},
                "reason": {"type": "string"},
                "score": {"type": "integer"},
            },
        },
    },
]


def _document_hash(document_id: str) -> str:
    return hashlib.sha256(document_id.encode("utf-8")).hexdigest()


def _persist_event(event_type: str, payload: dict[str, Any]) -> None:
    event = {"type": event_type, "at": time.time(), **payload}
    with _DB_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True))
        fh.write("\n")


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "db": str(_DB_PATH), "tools": len(_TOOLS)}


def _verify_identity(args: dict[str, Any]) -> dict[str, Any]:
    doc_id = args.get("document_id", "")
    doc = _KYC_DOCUMENTS.get(doc_id)
    if doc is None:
        return {"ok": False, "reason": "document_not_found"}
    return {
        "ok": True,
        "doc_id": doc_id,
        "document_hash": _document_hash(doc_id),
        "verified": doc["image_quality"] > 0.85,
        "image_quality": doc["image_quality"],
        "given_name": doc["given_name"],
        "family_name": doc["family_name"],
        "dob": doc["dob"],
        "country": doc["country"],
    }


def _screen_sanctions(args: dict[str, Any]) -> dict[str, Any]:
    family = args.get("family_name", "")
    dob = args.get("dob", "")
    hit = next(
        (e for e in _SANCTIONS_LIST if e["family_name"] == family and e["dob"] == dob),
        None,
    )
    pep_hit = next(
        (e for e in _PEP_LIST if e["family_name"] == family and e["dob"] == dob),
        None,
    )
    return {
        "hit": hit is not None,
        "list_name": hit["list_name"] if hit else None,
        "reason": hit["reason"] if hit else None,
        "pep_hit": pep_hit is not None,
        "pep_role": pep_hit["role"] if pep_hit else None,
    }


def _query_beneficial_owners(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity_name": args.get("entity_name", ""),
        "ultimate_beneficial_owners": [
            {"name": "Synthetic-UBO-Test", "ownership_percent": 100.0, "country": "IT"}
        ],
    }


def _escalate_to_compliance(args: dict[str, Any]) -> dict[str, Any]:
    result = {
        "case_id": args.get("case_id", ""),
        "status": "ESCALATED",
        "queue": "human_compliance_review",
        "reason": args.get("reason", "unspecified"),
        "score": args.get("score"),
    }
    _persist_event("escalation", result)
    return result


_DISPATCH = {
    "verify_identity": _verify_identity,
    "screen_sanctions": _screen_sanctions,
    "query_beneficial_owners": _query_beneficial_owners,
    "escalate_to_compliance": _escalate_to_compliance,
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
        f"mcp-kyc: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)[:200]}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-kyc", "version": "0.1.0"},
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
        except Exception as exc:  # noqa: BLE001 -- demo wants to surface any failure to LLM
            return JSONResponse(
                _rpc_result(
                    req_id,
                    {
                        "content": [
                            {"type": "text", "text": json.dumps({"ok": False, "error": str(exc)})}
                        ]
                    },
                )
            )
        return JSONResponse(_rpc_result(req_id, {
            "content": [{"type": "text", "text": json.dumps(result)}]
        }))

    return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))
