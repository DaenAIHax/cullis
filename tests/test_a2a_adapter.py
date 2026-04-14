"""ADR-002 Phase 2b — A2A adapter unit tests.

Pure mapping, no HTTP / no DB. Verifies:
  - envelope → Message → envelope round-trip
  - mediaType lands in metadata (spike Q1)
  - transport fields survive via Message.metadata.cullis
  - session_to_task projects Cullis session into A2A Task
  - historyLength 0/N/None truncation
  - TaskState normalization: hyphen/underscore/unknown → canonical
  - SessionStatus + close_reason → TaskState mapping
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from a2a.types import DataPart, Message, Role, TaskState

from app.a2a.adapter import (
    CULLIS_E2E_MEDIATYPE,
    a2a_message_to_cullis_envelope,
    cullis_envelope_to_a2a_message,
    normalize_task_state,
    session_state_to_task_state,
    session_to_task,
)


# ── envelope ↔ Message ──────────────────────────────────────────────

def _envelope():
    return {
        "payload": {
            "ciphertext": "Y2lwaGVy",
            "iv": "aXY=",
            "encrypted_key": "a2V5",
            "ephemeral_pubkey": "cGs=",
        },
        "nonce": "n-1",
        "timestamp": 1_700_000_000,
        "signature": "sig-xyz",
        "client_seq": 3,
        "sender_agent_id": "acme::alice",
    }


def test_envelope_to_message_places_mediatype_in_part_metadata():
    msg = cullis_envelope_to_a2a_message(
        _envelope(), context_id="c", task_id="c", message_id="m1"
    )
    inner = msg.parts[0].root
    assert isinstance(inner, DataPart)
    assert inner.data["ciphertext"] == "Y2lwaGVy"
    assert (inner.metadata or {}).get("mediaType") == CULLIS_E2E_MEDIATYPE


def test_envelope_to_message_carries_transport_fields_in_message_metadata():
    msg = cullis_envelope_to_a2a_message(
        _envelope(), context_id="c", task_id="c", message_id="m1"
    )
    cullis = (msg.metadata or {}).get("cullis") or {}
    assert cullis["nonce"] == "n-1"
    assert cullis["timestamp"] == 1_700_000_000
    assert cullis["signature"] == "sig-xyz"
    assert cullis["client_seq"] == 3
    assert cullis["sender_agent_id"] == "acme::alice"


def test_envelope_message_envelope_round_trip_via_json():
    msg = cullis_envelope_to_a2a_message(
        _envelope(), context_id="c", task_id="c", message_id="m1"
    )
    rt_msg = Message.model_validate_json(msg.model_dump_json())
    rt_env = a2a_message_to_cullis_envelope(rt_msg)
    assert rt_env["payload"]["ciphertext"] == "Y2lwaGVy"
    assert rt_env["nonce"] == "n-1"
    assert rt_env["timestamp"] == 1_700_000_000
    assert rt_env["signature"] == "sig-xyz"
    assert rt_env["client_seq"] == 3


def test_a2a_message_without_cullis_datapart_raises():
    from a2a.types import Part, TextPart

    msg = Message(
        role=Role.user,
        parts=[Part(root=TextPart(text="hello"))],
        message_id="m",
        context_id="c",
        task_id="c",
    )
    with pytest.raises(ValueError, match="cullis_datapart"):
        a2a_message_to_cullis_envelope(msg)


def test_envelope_to_message_accepts_role_user():
    msg = cullis_envelope_to_a2a_message(
        _envelope(), context_id="c", task_id="c", message_id="m", role=Role.user
    )
    assert msg.role == Role.user


# ── TaskState normalization (spike Q5) ──────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("submitted", TaskState.submitted),
        ("working", TaskState.working),
        ("input-required", TaskState.input_required),
        ("input_required", TaskState.input_required),
        ("auth-required", TaskState.auth_required),
        ("auth_required", TaskState.auth_required),
        ("completed", TaskState.completed),
        ("canceled", TaskState.canceled),
        ("failed", TaskState.failed),
        ("rejected", TaskState.rejected),
        ("unknown", TaskState.failed),  # unknown → failed
        ("something-else", TaskState.failed),
        ("", TaskState.failed),
        (None, TaskState.failed),
    ],
)
def test_normalize_task_state(raw, expected):
    assert normalize_task_state(raw) == expected


# ── SessionStatus → TaskState ───────────────────────────────────────

@pytest.mark.parametrize(
    "status,reason,expected",
    [
        ("pending", None, TaskState.submitted),
        ("active", None, TaskState.working),
        ("denied", None, TaskState.rejected),
        ("closed", "normal", TaskState.completed),
        ("closed", "rejected", TaskState.rejected),
        ("closed", "canceled", TaskState.canceled),
        ("closed", "idle_timeout", TaskState.failed),
        ("closed", "ttl_expired", TaskState.failed),
        ("closed", "policy_revoked", TaskState.failed),
        ("closed", "peer_lost", TaskState.failed),
        ("closed", "pending_timeout", TaskState.failed),
        ("closed", None, TaskState.completed),
        ("closed", "unexpected", TaskState.failed),
        ("weird", None, TaskState.failed),
    ],
)
def test_session_state_to_task_state(status, reason, expected):
    assert session_state_to_task_state(status, reason) == expected


# ── session_to_task ─────────────────────────────────────────────────

def _session(status="active", close_reason=None, closed_at=None):
    return SimpleNamespace(
        session_id="sess-123",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="beta::bob",
        target_org_id="beta",
        status=status,
        close_reason=close_reason,
        created_at=datetime(2026, 4, 14, 10, 0, tzinfo=timezone.utc),
        last_activity_at=datetime(2026, 4, 14, 10, 5, tzinfo=timezone.utc),
        closed_at=closed_at,
    )


def _message(seq, sender, nonce="n", client_seq=None):
    return SimpleNamespace(
        seq=seq,
        sender_agent_id=sender,
        payload={"ciphertext": f"ct-{seq}", "iv": "iv", "encrypted_key": "k"},
        nonce=nonce,
        timestamp=datetime(2026, 4, 14, 10, 0, seq, tzinfo=timezone.utc),
        signature=f"sig-{seq}",
        client_seq=client_seq,
    )


def test_session_to_task_basic_active():
    sess = _session()
    msgs = [_message(1, "acme::alice"), _message(2, "beta::bob")]
    task = session_to_task(sess, msgs)

    assert task.id == "sess-123"
    assert task.context_id == "sess-123"
    assert task.status.state == TaskState.working
    assert len(task.history) == 2
    assert task.history[0].role == Role.user  # initiator
    assert task.history[1].role == Role.agent  # target
    assert task.history[0].message_id == "sess-123:1"
    # cipher survived
    assert task.history[0].parts[0].root.data["ciphertext"] == "ct-1"


def test_session_to_task_closed_maps_to_completed():
    sess = _session(
        status="closed",
        close_reason="normal",
        closed_at=datetime(2026, 4, 14, 11, 0, tzinfo=timezone.utc),
    )
    task = session_to_task(sess, [])
    assert task.status.state == TaskState.completed


def test_session_to_task_canceled():
    sess = _session(
        status="closed",
        close_reason="canceled",
        closed_at=datetime(2026, 4, 14, 11, 0, tzinfo=timezone.utc),
    )
    task = session_to_task(sess, [])
    assert task.status.state == TaskState.canceled


def test_session_to_task_history_length_zero_returns_empty():
    sess = _session()
    msgs = [_message(i, "acme::alice") for i in range(1, 4)]
    task = session_to_task(sess, msgs, history_length=0)
    assert task.history == []


def test_session_to_task_history_length_truncates_to_last_n():
    sess = _session()
    msgs = [_message(i, "acme::alice", nonce=f"n-{i}") for i in range(1, 6)]
    task = session_to_task(sess, msgs, history_length=2)
    assert [m.message_id for m in task.history] == ["sess-123:4", "sess-123:5"]


def test_session_to_task_history_preserves_order_regardless_of_input_order():
    sess = _session()
    msgs = [_message(3, "a", nonce="n3"), _message(1, "a", nonce="n1"), _message(2, "a", nonce="n2")]
    task = session_to_task(sess, msgs)
    assert [m.message_id for m in task.history] == [
        "sess-123:1",
        "sess-123:2",
        "sess-123:3",
    ]


def test_session_to_task_serializable_via_json():
    from a2a.types import Task

    sess = _session()
    msgs = [_message(1, "acme::alice")]
    task = session_to_task(sess, msgs)
    rt = Task.model_validate_json(task.model_dump_json())
    assert rt.id == "sess-123"
    assert rt.status.state == TaskState.working
    assert len(rt.history) == 1
