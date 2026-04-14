"""A2A protocol HTTP router — ADR-002 Phase 2a + 2b.

Phase 2a — read-only discovery:
  GET /v1/a2a/directory
  GET /v1/a2a/agents/{org_id}/{agent_id}/.well-known/agent.json
  Both unauthenticated — discovery runs before credentials exist.

Phase 2b — authenticated JSON-RPC surface:
  POST /v1/a2a/rpc  (methods: message/send, tasks/get, tasks/cancel)

The RPC endpoint authenticates via the standard Cullis token chain and
reuses the broker's existing send/session logic — A2A Phase 2b is a
translation layer, not a parallel implementation. Per ADR-002 §2.2 the
A2A `contextId` and `taskId` are both the Cullis session_id. Phase 2b
does NOT create sessions on first call: the caller must already be a
participant of an existing Cullis session (session negotiation stays
Cullis-native until Phase 3 ships the baseline-A2A bootstrap path).

Phase 2c will add streaming + push notifications.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.a2a.adapter import (
    a2a_message_to_cullis_envelope,
    session_to_task,
)
from app.a2a.agent_card import build_agent_card
from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.broker.db_models import SessionMessageRecord, SessionRecord
from app.broker.models import MessageEnvelope, SessionCloseReason, SessionStatus
from app.broker.session import SessionStore, get_session_store
from app.broker.persistence import save_session
from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.registry.store import get_agent_by_id, list_agents

logger = logging.getLogger("agent_trust.a2a")

router = APIRouter(prefix="/a2a", tags=["a2a"])


def _public_base_url(request: Request) -> str:
    """Pick the broker's public URL: settings override > request scheme+host."""
    settings = get_settings()
    if settings.broker_public_url:
        return settings.broker_public_url.rstrip("/")
    return f"{request.url.scheme}://{request.url.netloc}"


def _agent_card_path(org_id: str, agent_name: str) -> str:
    return f"/v1/a2a/agents/{org_id}/{agent_name}/.well-known/agent.json"


def _split_agent_id(agent_id: str) -> tuple[str, str]:
    """Split internal `org::name` into (org, name); return (org, agent_id) if no separator."""
    if "::" in agent_id:
        org, name = agent_id.split("::", 1)
        return org, name
    return "", agent_id


@router.get("/directory")
async def directory(
    request: Request,
    capability: Optional[list[str]] = Query(None, description="Filter by capability (repeatable, AND semantics)"),
    org_id: Optional[str] = Query(None, description="Filter by org_id"),
    db: AsyncSession = Depends(get_db),
):
    """List Cullis agents discoverable via A2A.

    Matches Cullis' own agent listing semantics: active agents only, with
    AgentCard URLs the caller can fetch. Phase 2a does not enforce
    cross-org binding visibility (it would require auth — out of scope
    for discovery). Phase 3 adds the cross-org-federation sub-feature
    that filters cross-org listings against approved bindings.
    """
    base = _public_base_url(request)
    agents = await list_agents(db, org_id=org_id)
    out = []
    for agent in agents:
        if not agent.is_active:
            continue
        if capability:
            agent_caps = set(agent.capabilities)
            if not all(c in agent_caps for c in capability):
                continue
        org, name = _split_agent_id(agent.agent_id)
        out.append(
            {
                "agent_id": agent.agent_id,
                "org_id": agent.org_id,
                "display_name": agent.display_name,
                "capabilities": agent.capabilities,
                "agent_card_url": f"{base}{_agent_card_path(agent.org_id, name)}",
            }
        )
    return {"agents": out, "count": len(out)}


@router.get("/agents/{org_id}/{agent_name}/.well-known/agent.json")
async def agent_card(
    org_id: str,
    agent_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return the AgentCard for `{org_id}::{agent_name}`.

    404 when the agent does not exist or is deactivated. Cache headers
    let A2A clients avoid re-fetching on every call.
    """
    settings = get_settings()
    internal_id = f"{org_id}::{agent_name}"
    agent = await get_agent_by_id(db, internal_id)
    if agent is None or not agent.is_active:
        raise HTTPException(status_code=404, detail="agent_not_found")

    card = build_agent_card(
        agent,
        base_url=_public_base_url(request),
        trust_domain=settings.trust_domain,
    )
    # AgentCard pydantic models serialize via model_dump_json — wrap in
    # a JSONResponse with explicit cache headers so peers don't hammer us.
    return JSONResponse(
        content=json.loads(card.model_dump_json()),
        headers={
            "Cache-Control": "public, max-age=300",
            "Content-Type": "application/json",
        },
    )


# ── Phase 2b — JSON-RPC surface ─────────────────────────────────────

# JSON-RPC 2.0 error codes used by the A2A surface. The base -32xxx
# range follows the JSON-RPC spec; the -32001..-32004 range is the
# A2A-specific subset documented in the v0.3 spec.
_JSONRPC_PARSE_ERROR = -32700
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS = -32602
_JSONRPC_INTERNAL_ERROR = -32603
_A2A_TASK_NOT_FOUND = -32001
_A2A_TASK_NOT_CANCELABLE = -32002


def _rpc_error(req_id: Any, code: int, message: str, *, status_code: int = 200):
    return JSONResponse(
        status_code=status_code,
        content={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        },
    )


def _rpc_result(req_id: Any, result: dict):
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": req_id, "result": result},
    )


async def _load_session_or_error(
    db: AsyncSession, session_id: str
) -> SessionRecord | None:
    stmt = select(SessionRecord).where(SessionRecord.session_id == session_id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    return row


async def _load_session_messages(
    db: AsyncSession, session_id: str
) -> list[SessionMessageRecord]:
    stmt = (
        select(SessionMessageRecord)
        .where(SessionMessageRecord.session_id == session_id)
        .order_by(SessionMessageRecord.seq)
    )
    return list((await db.execute(stmt)).scalars().all())


def _is_participant(session_row: SessionRecord, agent_id: str) -> bool:
    return agent_id in (session_row.initiator_agent_id, session_row.target_agent_id)


@router.post("/rpc")
async def jsonrpc_dispatch(
    request: Request,
    payload: dict = Body(...),
    current_agent: TokenPayload = Depends(get_current_agent),
    store: SessionStore = Depends(get_session_store),
    db: AsyncSession = Depends(get_db),
):
    """A2A v0.3 JSON-RPC entrypoint (ADR-002 Phase 2b).

    Supported methods:
      - message/send — post a Cullis envelope carried as an A2A Message
        to an existing session; returns the updated Task
      - tasks/get — fetch a Task (== Cullis session projection) with
        optional historyLength truncation
      - tasks/cancel — transition the underlying session to
        closed/canceled; idempotent on already-canceled tasks

    Session creation is NOT exposed here in 2b — A2A peers must join an
    existing Cullis session negotiated via the native /v1/broker surface.
    """
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return _rpc_error(
            payload.get("id") if isinstance(payload, dict) else None,
            _JSONRPC_INVALID_REQUEST,
            "Invalid JSON-RPC 2.0 request",
        )

    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, "params must be an object")

    if method == "message/send":
        return await _rpc_message_send(
            req_id, params, current_agent=current_agent, store=store, db=db
        )
    if method == "tasks/get":
        return await _rpc_tasks_get(
            req_id, params, current_agent=current_agent, db=db
        )
    if method == "tasks/cancel":
        return await _rpc_tasks_cancel(
            req_id, params, current_agent=current_agent, store=store, db=db
        )

    return _rpc_error(req_id, _JSONRPC_METHOD_NOT_FOUND, f"method not found: {method}")


async def _rpc_message_send(
    req_id: Any,
    params: dict,
    *,
    current_agent: TokenPayload,
    store: SessionStore,
    db: AsyncSession,
):
    from a2a.types import Message

    raw_message = params.get("message")
    if not isinstance(raw_message, dict):
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, "params.message required")
    try:
        msg = Message.model_validate(raw_message)
    except Exception as exc:  # pydantic validation
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, f"invalid Message: {exc}")

    context_id = msg.context_id or msg.task_id
    if not context_id:
        return _rpc_error(
            req_id,
            _JSONRPC_INVALID_PARAMS,
            "message.contextId (or taskId) is required — Phase 2b does not create sessions",
        )

    session_row = await _load_session_or_error(db, context_id)
    if session_row is None:
        return _rpc_error(req_id, _A2A_TASK_NOT_FOUND, "contextId/taskId not found")
    if not _is_participant(session_row, current_agent.agent_id):
        return _rpc_error(
            req_id, _JSONRPC_INVALID_REQUEST, "caller is not a session participant"
        )

    try:
        envelope_dict = a2a_message_to_cullis_envelope(msg)
    except ValueError as exc:
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, str(exc))

    # Build a Cullis MessageEnvelope the broker understands. Required
    # transport fields (nonce, timestamp, signature) must be present in
    # `message.metadata.cullis` — Phase 2b treats this as the contract
    # for Cullis-aware A2A peers. Phase 3 ships the baseline path for
    # pure-A2A peers via the cullis-trust/v1 extension negotiation.
    missing = [
        k for k in ("nonce", "timestamp", "signature", "sender_agent_id")
        if k not in envelope_dict
    ]
    if missing:
        return _rpc_error(
            req_id,
            _JSONRPC_INVALID_PARAMS,
            f"message.metadata.cullis missing fields: {missing}",
        )
    try:
        envelope = MessageEnvelope(
            session_id=context_id,
            sender_agent_id=envelope_dict["sender_agent_id"],
            payload=envelope_dict["payload"],
            nonce=envelope_dict["nonce"],
            timestamp=int(envelope_dict["timestamp"]),
            signature=envelope_dict["signature"],
            client_seq=envelope_dict.get("client_seq"),
        )
    except Exception as exc:
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, f"envelope invalid: {exc}")

    # Delegate to the broker's existing send_message handler — it owns
    # signature verification, nonce dedup, policy + injection checks,
    # persistence, and delivery (WS push or M3 queue). Calling it as a
    # plain async function preserves all guarantees without duplicating
    # ~270 lines of validation.
    from app.broker.router import send_message as broker_send_message

    try:
        await broker_send_message(
            session_id=context_id,
            envelope=envelope,
            ttl_seconds=300,
            idempotency_key=None,
            current_agent=current_agent,
            store=store,
            db=db,
        )
    except HTTPException as exc:
        code = _JSONRPC_INVALID_REQUEST if exc.status_code < 500 else _JSONRPC_INTERNAL_ERROR
        return _rpc_error(req_id, code, str(exc.detail))

    # Reload + project the updated session as a Task
    session_row = await _load_session_or_error(db, context_id)
    messages = await _load_session_messages(db, context_id)
    task = session_to_task(session_row, messages)

    await log_event(
        db, "a2a.message_send", "ok",
        agent_id=current_agent.agent_id, session_id=context_id,
        org_id=current_agent.org,
        details={"method": "message/send"},
    )

    return _rpc_result(req_id, json.loads(task.model_dump_json()))


async def _rpc_tasks_get(
    req_id: Any, params: dict, *, current_agent: TokenPayload, db: AsyncSession
):
    task_id = params.get("id")
    history_length = params.get("historyLength")
    if not isinstance(task_id, str) or not task_id:
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, "params.id required")
    if history_length is not None and not isinstance(history_length, int):
        return _rpc_error(
            req_id, _JSONRPC_INVALID_PARAMS, "historyLength must be an integer"
        )

    session_row = await _load_session_or_error(db, task_id)
    if session_row is None:
        return _rpc_error(req_id, _A2A_TASK_NOT_FOUND, "task not found")
    if not _is_participant(session_row, current_agent.agent_id):
        return _rpc_error(
            req_id, _A2A_TASK_NOT_FOUND, "task not found"
        )  # mask participation to avoid session enumeration

    messages = await _load_session_messages(db, task_id)
    task = session_to_task(session_row, messages, history_length=history_length)
    return _rpc_result(req_id, json.loads(task.model_dump_json()))


async def _rpc_tasks_cancel(
    req_id: Any,
    params: dict,
    *,
    current_agent: TokenPayload,
    store: SessionStore,
    db: AsyncSession,
):
    task_id = params.get("id")
    if not isinstance(task_id, str) or not task_id:
        return _rpc_error(req_id, _JSONRPC_INVALID_PARAMS, "params.id required")

    session_row = await _load_session_or_error(db, task_id)
    if session_row is None:
        return _rpc_error(req_id, _A2A_TASK_NOT_FOUND, "task not found")
    if not _is_participant(session_row, current_agent.agent_id):
        return _rpc_error(req_id, _A2A_TASK_NOT_FOUND, "task not found")

    # Idempotent: already-canceled returns the current state. Already
    # closed with a different reason → TaskNotCancelable so peers know
    # the session ended elsewhere.
    if session_row.status == SessionStatus.closed.value:
        if session_row.close_reason == SessionCloseReason.canceled.value:
            messages = await _load_session_messages(db, task_id)
            task = session_to_task(session_row, messages)
            return _rpc_result(req_id, json.loads(task.model_dump_json()))
        return _rpc_error(
            req_id,
            _A2A_TASK_NOT_CANCELABLE,
            f"task already closed (reason={session_row.close_reason})",
        )

    async with store._lock:
        in_mem = store.get(task_id)
        if in_mem is not None:
            store.close(task_id, SessionCloseReason.canceled)
            await save_session(db, in_mem)
        else:
            # Session not in the in-memory store (e.g. rehydration gap);
            # flip the DB row directly so the Task projection is correct.
            session_row.status = SessionStatus.closed.value
            session_row.close_reason = SessionCloseReason.canceled.value
            await db.commit()

    await log_event(
        db, "a2a.task_cancel", "ok",
        agent_id=current_agent.agent_id, session_id=task_id,
        org_id=current_agent.org,
        details={"method": "tasks/cancel"},
    )

    session_row = await _load_session_or_error(db, task_id)
    messages = await _load_session_messages(db, task_id)
    task = session_to_task(session_row, messages)
    return _rpc_result(req_id, json.loads(task.model_dump_json()))
