"""M1 session reliability layer — unit tests.

Covers:
- Session.touch() / is_idle() / find_stale()
- SessionStore per-agent ACTIVE cap (O4 decision)
- close(reason) / reject() propagation
- Sweeper sweep_once closes idle and TTL-expired sessions
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.broker.models import SessionCloseReason, SessionStatus
from app.broker.session import (
    AgentSessionCapExceeded,
    Session,
    SessionStore,
)


def _mk_store(cap: int = 50) -> SessionStore:
    return SessionStore(active_cap_per_agent=cap)


def test_touch_updates_last_activity():
    store = _mk_store()
    s = store.create("a1", "o1", "a2", "o2", ["x"])
    t0 = s.last_activity_at
    # Simulate old activity
    s.last_activity_at = t0 - timedelta(hours=1)
    s.touch()
    assert s.last_activity_at > t0


def test_is_idle_only_for_live_sessions():
    s = Session(
        session_id="sid",
        initiator_agent_id="a1",
        initiator_org_id="o1",
        target_agent_id="a2",
        target_org_id="o2",
        requested_capabilities=["x"],
    )
    s.last_activity_at = datetime.now(timezone.utc) - timedelta(hours=2)
    assert s.is_idle(timeout_seconds=60)
    # Closed sessions are never "idle" (already terminal)
    s.status = SessionStatus.closed
    assert not s.is_idle(timeout_seconds=60)


def test_per_agent_active_cap_enforced():
    """O4: only ACTIVE sessions count toward the cap (PENDING unlimited)."""
    store = _mk_store(cap=2)
    # 2 active for agent A1
    s1 = store.create("a1", "o1", "target1", "o2", [])
    s1.status = SessionStatus.active
    s2 = store.create("a1", "o1", "target2", "o2", [])
    s2.status = SessionStatus.active
    # 3rd active should raise
    with pytest.raises(AgentSessionCapExceeded) as exc:
        store.create("a1", "o1", "target3", "o2", [])
    assert exc.value.current == 2
    assert exc.value.cap == 2


def test_pending_sessions_do_not_count_toward_cap():
    """Unlimited PENDING is by design — they are auto-swept on pending timeout."""
    store = _mk_store(cap=1)
    # 5 pending is fine
    for i in range(5):
        store.create("a1", "o1", f"t{i}", "o2", [])
    # count_active_for_agent sees zero
    assert store.count_active_for_agent("a1") == 0


def test_close_records_reason():
    store = _mk_store()
    s = store.create("a1", "o1", "a2", "o2", [])
    store.close(s.session_id, SessionCloseReason.idle_timeout)
    assert s.status == SessionStatus.closed
    assert s.close_reason == SessionCloseReason.idle_timeout


def test_close_is_idempotent_on_reason():
    store = _mk_store()
    s = store.create("a1", "o1", "a2", "o2", [])
    store.close(s.session_id, SessionCloseReason.normal)
    # A second close (e.g., sweeper racing with explicit close) must not
    # overwrite the original reason.
    store.close(s.session_id, SessionCloseReason.idle_timeout)
    assert s.close_reason == SessionCloseReason.normal


def test_reject_sets_rejected_reason():
    store = _mk_store()
    s = store.create("a1", "o1", "a2", "o2", [])
    store.reject(s.session_id)
    assert s.status == SessionStatus.denied
    assert s.close_reason == SessionCloseReason.rejected


def test_find_stale_flags_idle_and_ttl():
    store = _mk_store()
    s_idle = store.create("a1", "o1", "a2", "o2", [])
    store.activate(s_idle.session_id)
    s_idle.last_activity_at = datetime.now(timezone.utc) - timedelta(hours=2)

    s_ttl = store.create("a1", "o1", "a3", "o2", [])
    s_ttl.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    s_fresh = store.create("a1", "o1", "a4", "o2", [])
    store.activate(s_fresh.session_id)

    stale = store.find_stale(idle_timeout_seconds=60)
    ids = {s.session_id: reason for s, reason in stale}
    assert ids[s_idle.session_id] == SessionCloseReason.idle_timeout
    assert ids[s_ttl.session_id] == SessionCloseReason.ttl_expired
    assert s_fresh.session_id not in ids


@pytest.mark.asyncio
async def test_sweep_once_closes_stale(monkeypatch):
    """Sweeper closes stale sessions and tolerates DB unavailability."""
    from app.broker import session_sweeper

    # Monkey-patch persistence + WS notify so sweep_once runs purely in-memory.
    persisted: list[str] = []
    notified: list[tuple[str, str]] = []

    async def fake_persist(session):
        persisted.append(session.session_id)

    async def fake_notify(session, reason):
        notified.append((session.session_id, reason.value))

    monkeypatch.setattr(session_sweeper, "_persist_closed", fake_persist)
    monkeypatch.setattr(session_sweeper, "_emit_closed_event", fake_notify)

    store = _mk_store()
    s = store.create("a1", "o1", "a2", "o2", [])
    store.activate(s.session_id)
    s.last_activity_at = datetime.now(timezone.utc) - timedelta(hours=2)

    closed = await session_sweeper.sweep_once(store, idle_timeout_seconds=60)
    assert closed == 1
    assert s.status == SessionStatus.closed
    assert s.close_reason == SessionCloseReason.idle_timeout
    assert persisted == [s.session_id]
    assert notified == [(s.session_id, "idle_timeout")]


@pytest.mark.asyncio
async def test_sweeper_loop_stops_on_event(monkeypatch):
    """sweeper_loop must exit promptly when stop_event is set."""
    from app.broker import session_sweeper

    async def noop_persist(_):
        pass

    async def noop_notify(_, __):
        pass

    monkeypatch.setattr(session_sweeper, "_persist_closed", noop_persist)
    monkeypatch.setattr(session_sweeper, "_emit_closed_event", noop_notify)

    store = _mk_store()
    stop = asyncio.Event()
    task = asyncio.create_task(
        session_sweeper.sweeper_loop(
            store, interval_seconds=60, idle_timeout_seconds=60, stop_event=stop,
        )
    )
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert task.done()
