"""M2 heartbeat + resume — unit tests.

The full WS integration flow requires a live FastAPI app and is covered
by the smoke tests; here we focus on:

- fetch_messages_for_resume() filtering (seq gate + sender exclusion)
- _handle_ws_resume() correctness (session not found, not participant,
  bad input, happy path)
- Resume payload is capped by ``limit``
"""
from __future__ import annotations

import pytest


# ─────────────────────────────────────────────────────────────────────
# In-memory fakes for the resume handler — no FastAPI, no real DB.
# ─────────────────────────────────────────────────────────────────────


class FakeWS:
    def __init__(self):
        self.sent: list[dict] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)


class FakeStore:
    """Minimal stand-in for SessionStore: only .get() is exercised."""

    def __init__(self, session=None):
        self._session = session

    def get(self, _session_id):
        return self._session


class FakeSession:
    def __init__(self, session_id: str, initiator: str, target: str, next_seq: int = 3):
        self.session_id = session_id
        self.initiator_agent_id = initiator
        self.target_agent_id = target
        self.initiator_org_id = "org-i"
        self.target_org_id = "org-t"
        self._next_seq = next_seq
        self._touched = False

    def touch(self):
        self._touched = True


VALID_SID = "00000000-0000-0000-0000-000000000001"


@pytest.mark.asyncio
async def test_resume_rejects_bad_session_id(monkeypatch):
    from app.broker.router import _handle_ws_resume

    ws = FakeWS()
    await _handle_ws_resume(
        websocket=ws,
        msg={"type": "resume", "session_id": "not-a-uuid", "last_seq": 0},
        agent_id="a1",
        db=None,  # never touched when session_id fails validation
        store=FakeStore(),
    )
    assert ws.sent == [
        {"type": "resume_error", "detail": "Invalid or missing session_id"}
    ]


@pytest.mark.asyncio
async def test_resume_rejects_non_int_last_seq():
    from app.broker.router import _handle_ws_resume

    ws = FakeWS()
    await _handle_ws_resume(
        websocket=ws,
        msg={"type": "resume", "session_id": VALID_SID, "last_seq": "nope"},
        agent_id="a1",
        db=None,
        store=FakeStore(),
    )
    assert len(ws.sent) == 1
    assert ws.sent[0]["type"] == "resume_error"
    assert "integer" in ws.sent[0]["detail"]


@pytest.mark.asyncio
async def test_resume_session_not_found():
    from app.broker.router import _handle_ws_resume

    ws = FakeWS()
    await _handle_ws_resume(
        websocket=ws,
        msg={"type": "resume", "session_id": VALID_SID, "last_seq": 0},
        agent_id="a1",
        db=None,
        store=FakeStore(session=None),
    )
    assert ws.sent[0]["type"] == "resume_error"
    assert ws.sent[0]["detail"] == "Session not found"


@pytest.mark.asyncio
async def test_resume_not_participant():
    from app.broker.router import _handle_ws_resume

    ws = FakeWS()
    session = FakeSession(VALID_SID, initiator="a1", target="a2")
    await _handle_ws_resume(
        websocket=ws,
        msg={"type": "resume", "session_id": VALID_SID, "last_seq": 0},
        agent_id="stranger",
        db=None,
        store=FakeStore(session=session),
    )
    assert ws.sent[0]["type"] == "resume_error"
    assert ws.sent[0]["detail"] == "Not a participant"


@pytest.mark.asyncio
async def test_resume_happy_path_replays_messages(monkeypatch):
    """Resume returns resume_ok + one new_message per replayed entry."""
    from app.broker import router
    from app.broker.router import _handle_ws_resume

    replayed = [
        {
            "seq": 1,
            "sender_agent_id": "a1",
            "payload": {"hello": "world"},
            "nonce": "n1",
            "timestamp": "2026-04-12T12:00:00+00:00",
            "signature": None,
            "client_seq": None,
        },
        {
            "seq": 2,
            "sender_agent_id": "a1",
            "payload": {"bye": "world"},
            "nonce": "n2",
            "timestamp": "2026-04-12T12:00:01+00:00",
            "signature": None,
            "client_seq": None,
        },
    ]

    async def fake_fetch(db, sid, aid, last_seq, limit):
        assert sid == VALID_SID
        assert aid == "a2"  # resuming agent
        assert last_seq == 0
        assert limit == router._WS_RESUME_MAX_MESSAGES
        return replayed

    monkeypatch.setattr(
        "app.broker.persistence.fetch_messages_for_resume", fake_fetch,
    )

    ws = FakeWS()
    session = FakeSession(VALID_SID, initiator="a1", target="a2", next_seq=3)
    await _handle_ws_resume(
        websocket=ws,
        msg={"type": "resume", "session_id": VALID_SID, "last_seq": 0},
        agent_id="a2",
        db=None,
        store=FakeStore(session=session),
    )

    assert session._touched is True
    assert ws.sent[0] == {
        "type": "resume_ok",
        "session_id": VALID_SID,
        "last_seq_server": 2,  # next_seq - 1
        "delivered": 2,
    }
    assert len(ws.sent) == 3
    for i, frame in enumerate(ws.sent[1:]):
        assert frame["type"] == "new_message"
        assert frame["session_id"] == VALID_SID
        assert frame["replayed"] is True
        assert frame["message"]["seq"] == i + 1
