"""Sessionless one-shot messaging — ADR-008 Phase 1 PR #1.

Adds two endpoints to the egress router:

  POST /v1/egress/message/send    — send a one-shot message
  GET  /v1/egress/message/inbox   — poll pending one-shot messages

Unlike ``/v1/egress/sessions/*/send``, these endpoints do not require
an open session. A one-shot message carries a ``correlation_id`` (UUID
generated server-side when omitted) so the recipient can link a reply
back to the request. Cross-org recipients return 501 in this PR;
Phase 2 wires them to the broker.

Auth mirrors the rest of ``/v1/egress/*`` — ``X-API-Key`` via
``get_agent_from_api_key``. Storage reuses the existing
``local_messages`` queue with ``session_id=NULL`` and ``is_oneshot=1``
(see migration 0008). Audit is written through ``append_local_audit``
with ``event_type`` in
{``oneshot_sent``, ``oneshot_denied``, ``oneshot_delivered``}.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_proxy.auth.api_key import get_agent_from_api_key
from mcp_proxy.config import get_settings
from mcp_proxy.egress.routing import decide_route
from mcp_proxy.local import message_queue as local_queue
from mcp_proxy.local.audit import append_local_audit
from mcp_proxy.models import InternalAgent
from mcp_proxy.policy.local_eval import evaluate_local_message

logger = logging.getLogger("mcp_proxy.egress.oneshot")

router = APIRouter(prefix="/v1/egress", tags=["egress-oneshot"])


# ── Request / response schemas ──────────────────────────────────────

class SendOneShotRequest(BaseModel):
    """Body of ``POST /v1/egress/message/send``."""

    recipient_id: str = Field(
        ...,
        description="SPIFFE URI (spiffe://...) or internal org::agent form.",
    )
    payload: dict = Field(..., description="Application-defined body.")
    correlation_id: str | None = Field(
        None,
        description="Omit to have the server generate one. "
                    "Pass the request's correlation_id on replies and set "
                    "reply_to to that same value.",
    )
    reply_to: str | None = Field(
        None,
        description="correlation_id of the message this one is a reply to.",
    )
    mode: Literal["envelope", "mtls-only"] = Field(
        "mtls-only",
        description="Transport signalling mirrors the session /send path.",
    )
    signature: str | None = Field(
        None,
        description="For mode=mtls-only: RSA-PSS signature over the canonical "
                    "plaintext (session_id replaced by 'oneshot:<correlation_id>' "
                    "for domain separation from session messages).",
    )
    nonce: str | None = Field(
        None,
        description="Opaque random string; server de-duplicates via UNIQUE(nonce).",
    )
    timestamp: int | None = Field(
        None,
        description="Unix timestamp seconds. Server enforces freshness.",
    )
    ttl_seconds: int = Field(
        300,
        ge=10,
        le=3600,
        description="Recipient offline TTL. 5 min default, max 1h.",
    )


class SendOneShotResponse(BaseModel):
    correlation_id: str
    msg_id: str
    status: Literal["enqueued", "duplicate"]


class InboxMessage(BaseModel):
    msg_id: str
    correlation_id: str
    reply_to: str | None
    sender_agent_id: str
    payload_ciphertext: str
    idempotency_key: str | None
    enqueued_at: str
    expires_at: str | None


class InboxResponse(BaseModel):
    messages: list[InboxMessage]
    count: int


# ── Helpers ────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _serialize_envelope(body: SendOneShotRequest) -> str:
    """Pack the envelope exactly the same shape the session ``/send`` path
    uses, so the recipient's verification path stays agnostic.
    """
    import json
    envelope = {
        "mode": body.mode,
        "payload": body.payload,
        "signature": body.signature,
        "nonce": body.nonce,
        "timestamp": body.timestamp,
        "correlation_id": body.correlation_id,
        "reply_to": body.reply_to,
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True)


# ── POST /v1/egress/message/send ────────────────────────────────────

@router.post("/message/send", response_model=SendOneShotResponse)
async def send_oneshot(
    body: SendOneShotRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
) -> SendOneShotResponse:
    """Enqueue a sessionless message for delivery to ``recipient_id``.

    Intra-org recipients land in ``local_messages`` with ``is_oneshot=1``
    and get pushed via the local WS manager if the recipient is online,
    queued otherwise.

    Cross-org recipients return 501 until Phase 2 wires the broker-side
    forwarder.
    """
    settings = get_settings()
    local_org = settings.org_id or ""
    trust_domain = settings.trust_domain

    try:
        path = decide_route(body.recipient_id, local_org, trust_domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # correlation_id: generate if absent.
    corr_id = body.correlation_id or str(uuid.uuid4())
    # Backfill into body so the envelope carries it.
    body = body.model_copy(update={"correlation_id": corr_id})

    audit_details = {
        "correlation_id": corr_id,
        "reply_to": body.reply_to,
        "recipient": body.recipient_id,
        "mode": body.mode,
    }

    if path == "cross":
        await append_local_audit(
            event_type="oneshot_denied",
            result="error",
            agent_id=agent.agent_id,
            org_id=local_org,
            details={**audit_details, "reason": "cross_org_not_implemented"},
        )
        raise HTTPException(
            status_code=501,
            detail="Cross-org one-shot messaging not implemented (Phase 2).",
        )

    # Policy: evaluate the payload the same way session /send does.
    decision = await evaluate_local_message(
        org_id=local_org,
        payload=body.payload,
    )
    if not decision.allowed:
        await append_local_audit(
            event_type="oneshot_denied",
            result="denied",
            agent_id=agent.agent_id,
            org_id=local_org,
            details={**audit_details, "reason": decision.reason or "policy_deny"},
        )
        raise HTTPException(
            status_code=403,
            detail=f"Policy: {decision.reason or 'message blocked'}",
        )

    # Recipient must match the internal_agents.agent_id format the
    # receiver presents at /inbox. Session /send stores the bare agent
    # name (recipient=session.target_agent_id); align here.
    recipient_bare: str
    if body.recipient_id.startswith("spiffe://"):
        from mcp_proxy.spiffe import parse_spiffe
        _, _, recipient_bare = parse_spiffe(body.recipient_id)
    elif "::" in body.recipient_id:
        recipient_bare = body.recipient_id.split("::", 1)[1]
    else:
        recipient_bare = body.recipient_id

    envelope = _serialize_envelope(body)

    msg_id, inserted = await local_queue.enqueue_oneshot(
        sender_agent_id=agent.agent_id,
        recipient_agent_id=recipient_bare,
        correlation_id=corr_id,
        reply_to_correlation_id=body.reply_to,
        payload_ciphertext=envelope,
        ttl_seconds=body.ttl_seconds,
    )

    # Push via the local WS manager if the recipient is connected. The
    # session-based /send does this via app.state.local_ws_manager; same
    # hook works for one-shot. Offline recipients drain on next connect.
    ws_manager = getattr(request.app.state, "local_ws_manager", None)
    if ws_manager is not None and inserted:
        try:
            await ws_manager.send_to_agent(
                recipient_bare,
                {
                    "type": "oneshot_message",
                    "msg_id": msg_id,
                    "correlation_id": corr_id,
                    "reply_to": body.reply_to,
                    "sender_agent_id": agent.agent_id,
                    "payload": body.payload,
                    "mode": body.mode,
                    "signature": body.signature,
                    "nonce": body.nonce,
                    "timestamp": body.timestamp,
                },
            )
        except Exception:
            logger.exception("Failed to push one-shot message via WS")

    await append_local_audit(
        event_type="oneshot_sent",
        result="ok",
        agent_id=agent.agent_id,
        org_id=local_org,
        details={**audit_details, "msg_id": msg_id, "duplicate": not inserted},
    )

    return SendOneShotResponse(
        correlation_id=corr_id,
        msg_id=msg_id,
        status="duplicate" if not inserted else "enqueued",
    )


# ── GET /v1/egress/message/inbox ────────────────────────────────────

@router.get("/message/inbox", response_model=InboxResponse)
async def receive_oneshot_inbox(
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_api_key),
) -> InboxResponse:
    """Poll pending one-shot messages addressed to this agent.

    Filters the shared ``local_messages`` queue to the caller's inbox,
    then narrows to ``is_oneshot = 1``. Session messages stay on
    ``/v1/egress/messages/{session_id}`` — keeping the two surfaces
    disjoint simplifies callers' mental model.
    """
    all_pending = await local_queue.fetch_pending_for_recipient(
        agent.agent_id,
    )
    one_shots = [m for m in all_pending if m.is_oneshot]

    return InboxResponse(
        messages=[
            InboxMessage(
                msg_id=m.msg_id,
                correlation_id=m.correlation_id or "",
                reply_to=m.reply_to_correlation_id,
                sender_agent_id=m.sender_agent_id,
                payload_ciphertext=m.payload_ciphertext,
                idempotency_key=m.idempotency_key,
                enqueued_at=_iso(m.enqueued_at),
                expires_at=_iso(m.expires_at) if m.expires_at else None,
            )
            for m in one_shots
        ],
        count=len(one_shots),
    )
