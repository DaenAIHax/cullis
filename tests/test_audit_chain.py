"""Tests for the audit log cryptographic hash chain."""
import pytest
import pytest_asyncio
from sqlalchemy import update

from app.db.audit import AuditLog, log_event, verify_chain, compute_entry_hash
from tests.conftest import TestSessionLocal

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def audit_db():
    """Provide a clean DB session with empty audit table."""
    from sqlalchemy import delete
    # Clean BEFORE to avoid pollution from other test modules
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.commit()
    async with TestSessionLocal() as session:
        yield session
    # Clean AFTER as well
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.commit()


async def test_log_event_creates_hash(audit_db):
    """First audit entry should have entry_hash and previous_hash=None."""
    entry = await log_event(audit_db, "test.event", "ok", details={"key": "val"})
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64  # SHA-256 hex
    assert entry.previous_hash is None


async def test_chain_linkage(audit_db):
    """Each entry's previous_hash must equal the prior entry's entry_hash."""
    e1 = await log_event(audit_db, "event.1", "ok")
    e2 = await log_event(audit_db, "event.2", "ok")
    e3 = await log_event(audit_db, "event.3", "denied")

    assert e1.previous_hash is None
    assert e2.previous_hash == e1.entry_hash
    assert e3.previous_hash == e2.entry_hash


async def test_hash_determinism(audit_db):
    """Recomputing the hash from entry fields must match entry_hash."""
    from datetime import timezone
    entry = await log_event(audit_db, "test.determinism", "ok",
                           agent_id="org::agent", session_id="sess-1",
                           org_id="org", details={"foo": "bar"})
    ts = entry.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    recomputed = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
    )
    assert entry.entry_hash == recomputed


async def test_verify_chain_valid(audit_db):
    """verify_chain on a valid chain returns (True, N, 0)."""
    for i in range(5):
        await log_event(audit_db, f"event.{i}", "ok")

    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is True
    assert total == 5
    assert broken_id == 0


async def test_verify_chain_detects_tamper(audit_db):
    """Modifying an entry's details must break the chain."""
    await log_event(audit_db, "event.1", "ok", details={"original": True})
    e2 = await log_event(audit_db, "event.2", "ok")
    await log_event(audit_db, "event.3", "ok")

    # Tamper with entry 2's details
    await audit_db.execute(
        update(AuditLog).where(AuditLog.id == e2.id).values(details='{"tampered": true}')
    )
    await audit_db.commit()

    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is False
    assert broken_id == e2.id


async def test_verify_chain_empty(audit_db):
    """verify_chain on empty table returns (True, 0, 0)."""
    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is True
    assert total == 0
    assert broken_id == 0
