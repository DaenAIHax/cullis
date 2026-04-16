"""Fake MCP server for ADR-007 Phase 1 smoke A8.

Speaks a minimal JSON-RPC 2.0 subset over POST /:

  - initialize                     → handshake
  - notifications/initialized      → 204 ack
  - tools/list                     → one fixed 'echo' tool
  - tools/call name=echo           → echoes params.arguments as JSON text

GET /healthz returns 200 for the compose healthcheck.

Every RPC is printed with flush=True so the smoke assertion can grep
``docker compose logs mcp-echo`` for the current NONCE.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-echo", version="0.1.0")

_PROTOCOL_VERSION = "2024-11-05"
_ECHO_TOOL = {
    "name": "echo",
    "description": "Echo back the caller's arguments for ADR-007 smoke testing.",
    "inputSchema": {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "additionalProperties": True,
    },
}


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


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
        f"mcp-echo: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-echo", "version": "0.1.0"},
        }))

    if method == "notifications/initialized":
        return JSONResponse(None, status_code=204)

    if method == "tools/list":
        return JSONResponse(_rpc_result(req_id, {"tools": [_ECHO_TOOL]}))

    if method == "tools/call":
        name = params.get("name")
        if name != "echo":
            return JSONResponse(_rpc_error(req_id, -32601, f"tool not found: {name}"))
        args = params.get("arguments") or {}
        return JSONResponse(_rpc_result(req_id, {
            "content": [{"type": "text", "text": json.dumps(args, sort_keys=True)}],
            "isError": False,
        }))

    return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))
