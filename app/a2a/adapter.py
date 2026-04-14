"""Bidirectional Cullis ⇄ A2A translation — ADR-002 Phase 2b.

Pure mapping functions, no I/O. The router layer calls these to:

  - wrap a Cullis envelope as an A2A `Message` (outbound)
  - unwrap an A2A `Message` back to a Cullis envelope (inbound)
  - project a Cullis session + its messages as an A2A `Task`
  - normalize TaskState strings (hyphen↔underscore, unknown→failed)

Per ADR-002 §2.2 the adapter holds the mapping contextId==taskId==session_id.
Per §2.3 / spike Q1 the ciphertext rides as a single `DataPart`, with the
mediaType marker in `metadata`, and Cullis-specific transport fields
(nonce, signature, timestamp, client_seq, sender_agent_id) ride in
`Message.metadata.cullis`.
"""
from __future__ import annotations

import json
from typing import Any

from a2a.types import DataPart, Message, Part, Role, Task, TaskState, TaskStatus

CULLIS_E2E_MEDIATYPE = "application/vnd.cullis.e2e+json"

_CIPHER_FIELDS = ("ciphertext", "iv", "encrypted_key", "ephemeral_pubkey")
_TRANSPORT_FIELDS = ("nonce", "timestamp", "signature", "client_seq", "sender_agent_id")

_SESSION_STATE_MAP = {
    "pending": TaskState.submitted,
    "active": TaskState.working,
    "denied": TaskState.rejected,
}

_CLOSE_REASON_MAP = {
    "normal": TaskState.completed,
    "rejected": TaskState.rejected,
    "canceled": TaskState.canceled,  # surface A2A CancelTask explicitly
    "idle_timeout": TaskState.failed,
    "ttl_expired": TaskState.failed,
    "peer_lost": TaskState.failed,
    "policy_revoked": TaskState.failed,
    "pending_timeout": TaskState.failed,
}


def normalize_task_state(raw: str | None) -> TaskState:
    """Accept hyphen/underscore variants; map unknown or missing → failed.

    Spike Q5: SDK wire form uses hyphens (`input-required`), protobuf
    canonical form uses underscores (`input_required`). The adapter
    accepts both at the boundary. The SDK's `unknown` value is treated
    as `failed` so peers see a definite terminal state.
    """
    if not raw:
        return TaskState.failed
    normalized = raw.replace("_", "-").lower()
    try:
        state = TaskState(normalized)
    except ValueError:
        return TaskState.failed
    if state == TaskState.unknown:
        return TaskState.failed
    return state


def session_state_to_task_state(
    status: str, close_reason: str | None = None
) -> TaskState:
    """Map Cullis SessionStatus (+close_reason if closed) to A2A TaskState."""
    if status in _SESSION_STATE_MAP:
        return _SESSION_STATE_MAP[status]
    if status == "closed":
        if close_reason is None:
            return TaskState.completed
        return _CLOSE_REASON_MAP.get(close_reason, TaskState.failed)
    return TaskState.failed


def cullis_envelope_to_a2a_message(
    envelope: dict[str, Any],
    *,
    context_id: str,
    task_id: str,
    message_id: str,
    role: Role = Role.agent,
) -> Message:
    """Wrap a Cullis envelope as an A2A Message.

    `envelope` is expected in the broker's on-the-wire shape: a `payload`
    dict holding the cipher blob (or cipher fields at top level, for
    tests) plus the transport fields (nonce, timestamp, …). Anything we
    can't classify is discarded — the envelope is reconstructable from
    the fields we keep.
    """
    cipher: dict[str, Any]
    if "payload" in envelope and isinstance(envelope["payload"], dict):
        cipher = dict(envelope["payload"])
    else:
        cipher = {k: envelope[k] for k in _CIPHER_FIELDS if k in envelope}

    part = DataPart(data=cipher, metadata={"mediaType": CULLIS_E2E_MEDIATYPE})

    cullis_meta = {k: envelope[k] for k in _TRANSPORT_FIELDS if k in envelope}

    return Message(
        role=role,
        parts=[Part(root=part)],
        message_id=message_id,
        context_id=context_id,
        task_id=task_id,
        metadata={"cullis": cullis_meta} if cullis_meta else None,
    )


def a2a_message_to_cullis_envelope(msg: Message) -> dict[str, Any]:
    """Extract a Cullis envelope from an A2A Message.

    Inverse of `cullis_envelope_to_a2a_message`. Finds the first
    DataPart whose metadata declares the Cullis mediaType; lifts the
    cipher into `payload` and copies transport fields back out of
    `message.metadata.cullis`.

    Raises ValueError when the message carries no Cullis DataPart.
    """
    cipher: dict[str, Any] | None = None
    for part in msg.parts:
        inner = part.root
        if isinstance(inner, DataPart):
            meta = inner.metadata or {}
            if meta.get("mediaType") == CULLIS_E2E_MEDIATYPE:
                cipher = dict(inner.data or {})
                break
    if cipher is None:
        raise ValueError("a2a_message_missing_cullis_datapart")

    envelope: dict[str, Any] = {"payload": cipher}
    cullis_meta = {}
    if msg.metadata and isinstance(msg.metadata, dict):
        cullis_meta = msg.metadata.get("cullis") or {}
    for k in _TRANSPORT_FIELDS:
        if k in cullis_meta:
            envelope[k] = cullis_meta[k]
    return envelope


def session_to_task(
    session_record: Any,
    messages: list[Any],
    *,
    history_length: int | None = None,
) -> Task:
    """Build an A2A Task view of a Cullis session.

    ADR-002 §2.2: taskId == contextId == session_id. One Task per
    session; multi-turn conversations append to `Task.history`. The
    `history_length` hint mirrors A2A GetTask semantics: 0 → no history,
    N → last N messages, None → full history.
    """
    state = session_state_to_task_state(
        session_record.status, session_record.close_reason
    )
    ts = (
        session_record.closed_at
        or session_record.last_activity_at
        or session_record.created_at
    )

    ordered = sorted(messages, key=lambda m: m.seq)
    if history_length is not None:
        ordered = [] if history_length <= 0 else ordered[-history_length:]

    history: list[Message] = []
    for m in ordered:
        payload = m.payload if isinstance(m.payload, dict) else _loads(m.payload)
        envelope: dict[str, Any] = {"payload": payload}
        envelope["nonce"] = m.nonce
        if m.timestamp is not None:
            envelope["timestamp"] = int(m.timestamp.timestamp())
        if m.signature is not None:
            envelope["signature"] = m.signature
        if m.client_seq is not None:
            envelope["client_seq"] = m.client_seq
        envelope["sender_agent_id"] = m.sender_agent_id
        role = (
            Role.user
            if m.sender_agent_id == session_record.initiator_agent_id
            else Role.agent
        )
        history.append(
            cullis_envelope_to_a2a_message(
                envelope,
                context_id=session_record.session_id,
                task_id=session_record.session_id,
                message_id=f"{session_record.session_id}:{m.seq}",
                role=role,
            )
        )

    return Task(
        id=session_record.session_id,
        context_id=session_record.session_id,
        status=TaskStatus(
            state=state,
            timestamp=ts.isoformat() if ts else None,
        ),
        history=history,
    )


def _loads(s: Any) -> dict[str, Any]:
    try:
        out = json.loads(s)
        return out if isinstance(out, dict) else {"raw": out}
    except (TypeError, ValueError):
        return {"raw": s}
