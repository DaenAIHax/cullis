"""MCP server: DORA Vendor/TPA tools for the reference demo (modern dogfood stack).

JSON-RPC 2.0 over POST /. Four tools backed by synthetic in-memory mock
data (vendor registry, vendor assessments, federation roster).

The cross-org A2A handler (`submit_to_auditor_org`) here returns a
synthetic `transmission_id` and writes a local JSONL evidence trail.
A real Cullis stack integration would replace this with a sealed A2A
envelope via `cullis_sdk.send_to_agent` routed through the Court
federation to the auditor org's Mastio audit chain.

Tools:
  * list_third_party_vendors(criticality_filter)
  * query_vendor_assessment(vendor_id)
  * draft_dora_register_entry(vendor_id, criticality, ...)
  * submit_to_auditor_org(entry_hash, vendor_id, auditor_org_id)

The federation enrolment check (auditor org must be in
FEDERATED_AUDITOR_ORGS with `enrolled=true`) lives here so the agent
can observe a structured denial when the target is off-federation.
The capability + role checks (`dora.cross_org_submit` +
`compliance_officer`) run on the Mastio side via PDP + the agent
loop's pre-flight role check; this server trusts what reaches it.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-dora", version="0.1.0")

_DB_PATH = Path(os.environ.get("MCP_DORA_DB", "/data/dora_evidence.jsonl"))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_PROTOCOL_VERSION = "2024-11-05"

_VENDOR_REGISTRY: list[dict[str, Any]] = [
    {
        "vendor_id": "vendor_cloud_demo",
        "name": "DemoCloud SaaS",
        "category": "cloud_infrastructure",
        "criticality": "CRITICAL",
        "country": "IE",
    },
    {
        "vendor_id": "vendor_kyc_demo",
        "name": "DemoKYC Provider",
        "category": "kyc_screening",
        "criticality": "IMPORTANT",
        "country": "DE",
    },
    {
        "vendor_id": "vendor_email_demo",
        "name": "DemoMail Provider",
        "category": "communication",
        "criticality": "NON_IMPORTANT",
        "country": "IT",
    },
]

_VENDOR_ASSESSMENTS: dict[str, dict[str, Any]] = {
    "vendor_cloud_demo": {
        "vendor_id": "vendor_cloud_demo",
        "last_assessment": "2026-04-01",
        "soc2_type2": True,
        "iso27001": True,
        "data_residency_eu": True,
        "subcontractors_disclosed": ["DemoCloud-EU-North", "DemoCloud-EU-South"],
        "exit_strategy_documented": True,
        "rto_minutes": 60,
    },
    "vendor_kyc_demo": {
        "vendor_id": "vendor_kyc_demo",
        "last_assessment": "2026-03-15",
        "soc2_type2": True,
        "iso27001": False,
        "data_residency_eu": True,
        "subcontractors_disclosed": [],
        "exit_strategy_documented": True,
        "rto_minutes": 240,
    },
    "vendor_email_demo": {
        "vendor_id": "vendor_email_demo",
        "last_assessment": "2026-02-01",
        "soc2_type2": False,
        "iso27001": False,
        "data_residency_eu": False,
        "subcontractors_disclosed": [],
        "exit_strategy_documented": False,
        "rto_minutes": 1440,
    },
}

_FEDERATED_AUDITOR_ORGS: dict[str, dict[str, Any]] = {
    "auditor_org_demo": {
        "org_id": "auditor_org_demo",
        "name": "DemoAudit EU",
        "country": "LU",
        "court_anchor": "https://court-demo.cullis.invalid/anchor",
        "enrolled": True,
    },
    "auditor_org_not_enrolled": {
        "org_id": "auditor_org_not_enrolled",
        "name": "DemoAudit Off-Federation",
        "country": "CH",
        "court_anchor": None,
        "enrolled": False,
    },
}


_TOOLS = [
    {
        "name": "list_third_party_vendors",
        "description": "List ICT third-party vendors from the Mastio vendor registry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "criticality_filter": {
                    "type": "string",
                    "description": "Optional filter (CRITICAL|IMPORTANT|NON_IMPORTANT).",
                }
            },
        },
    },
    {
        "name": "query_vendor_assessment",
        "description": "Pull the latest risk assessment for a vendor.",
        "inputSchema": {
            "type": "object",
            "required": ["vendor_id"],
            "properties": {"vendor_id": {"type": "string"}},
        },
    },
    {
        "name": "draft_dora_register_entry",
        "description": "Produce a DORA Art. 28 register entry from a vendor assessment.",
        "inputSchema": {
            "type": "object",
            "required": ["vendor_id", "criticality"],
            "properties": {
                "vendor_id": {"type": "string"},
                "criticality": {"type": "string"},
                "rto_minutes": {"type": "integer"},
                "exit_strategy_documented": {"type": "boolean"},
                "drafted_by_principal": {"type": "string"},
                "drafted_by_org": {"type": "string"},
            },
        },
    },
    {
        "name": "submit_to_auditor_org",
        "description": "Cross-organisation submit of a drafted entry via Cullis Court federation.",
        "inputSchema": {
            "type": "object",
            "required": ["entry_hash", "vendor_id", "auditor_org_id"],
            "properties": {
                "entry_hash": {"type": "string"},
                "vendor_id": {"type": "string"},
                "auditor_org_id": {"type": "string"},
                "caller_org": {"type": "string"},
            },
        },
    },
]


def _entry_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _persist_event(kind: str, payload: dict[str, Any]) -> None:
    with _DB_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": kind, "at": time.time(), **payload}, sort_keys=True))
        fh.write("\n")


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "db": str(_DB_PATH), "tools": len(_TOOLS)}


def _list_third_party_vendors(args: dict[str, Any]) -> dict[str, Any]:
    crit_filter = args.get("criticality_filter")
    rows = [
        v for v in _VENDOR_REGISTRY if crit_filter is None or v["criticality"] == crit_filter
    ]
    return {"count": len(rows), "vendors": rows}


def _query_vendor_assessment(args: dict[str, Any]) -> dict[str, Any]:
    vendor_id = args.get("vendor_id", "")
    assessment = _VENDOR_ASSESSMENTS.get(vendor_id)
    if assessment is None:
        return {"ok": False, "error": "assessment_not_found", "vendor_id": vendor_id}
    return {"ok": True, "vendor_id": vendor_id, "assessment": assessment}


def _draft_dora_register_entry(args: dict[str, Any]) -> dict[str, Any]:
    vendor_id = args.get("vendor_id", "")
    entry = {
        "schema": "DORA_Art28_Register_v1",
        "vendor_id": vendor_id,
        "criticality": args.get("criticality", ""),
        "rto_minutes": args.get("rto_minutes"),
        "exit_strategy_documented": args.get("exit_strategy_documented"),
        "drafted_by_principal": args.get("drafted_by_principal"),
        "drafted_by_org": args.get("drafted_by_org"),
    }
    h = _entry_hash(entry)
    _persist_event("draft", {"vendor_id": vendor_id, "entry_hash": h, "entry": entry})
    return {"ok": True, "vendor_id": vendor_id, "entry_hash": h, "entry": entry}


def _submit_to_auditor_org(args: dict[str, Any]) -> dict[str, Any]:
    auditor_org_id = args.get("auditor_org_id", "")
    auditor = _FEDERATED_AUDITOR_ORGS.get(auditor_org_id)
    if auditor is None:
        return {"ok": False, "error": "auditor_org_unknown", "auditor_org_id": auditor_org_id}
    if not auditor.get("enrolled"):
        return {
            "ok": False,
            "error": "auditor_org_not_federated",
            "auditor_org_id": auditor_org_id,
        }
    transmission_id = f"a2a_{uuid.uuid4().hex[:12]}"
    payload = {
        "transmission_id": transmission_id,
        "entry_hash": args.get("entry_hash"),
        "vendor_id": args.get("vendor_id"),
        "caller_org": args.get("caller_org"),
        "auditor_org_id": auditor_org_id,
        "court_anchor": auditor["court_anchor"],
    }
    _persist_event("submit_outbound", payload)
    _persist_event(
        "submit_inbound_ack",
        {**payload, "status": "accepted"},
    )
    return {
        "ok": True,
        "transmission_id": transmission_id,
        "vendor_id": args.get("vendor_id"),
        "auditor_org_id": auditor_org_id,
        "dual_write_confirmed": True,
    }


_DISPATCH = {
    "list_third_party_vendors": _list_third_party_vendors,
    "query_vendor_assessment": _query_vendor_assessment,
    "draft_dora_register_entry": _draft_dora_register_entry,
    "submit_to_auditor_org": _submit_to_auditor_org,
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
        f"mcp-dora: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)[:200]}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-dora", "version": "0.1.0"},
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
