"""
Session persistence — write-through to SQLite and restore on startup.

Every state operation (create, activate, close) updates the record
in the DB in addition to the in-memory store. On broker startup, non-expired
sessions are reloaded into memory from the DB.
"""
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import SessionRecord, SessionMessageRecord
from app.broker.models import SessionStatus
from app.broker.session import Session, StoredMessage, SessionStore

# Dialect-specific inserts for atomic nonce uniqueness check
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

logger = logging.getLogger("agent_trust")


async def save_session(db: AsyncSession, session: Session) -> None:
    """Upsert the session record (create or update status/closed_at)."""
    closed_at = None
    if session.status in (SessionStatus.closed, SessionStatus.denied):
        closed_at = datetime.now(timezone.utc)

    close_reason_value = (
        session.close_reason.value if session.close_reason is not None else None
    )

    existing = await db.get(SessionRecord, session.session_id)
    if existing:
        existing.status = session.status.value
        existing.closed_at = closed_at
        existing.last_activity_at = session.last_activity_at
        existing.close_reason = close_reason_value
    else:
        db.add(SessionRecord(
            session_id=session.session_id,
            initiator_agent_id=session.initiator_agent_id,
            initiator_org_id=session.initiator_org_id,
            target_agent_id=session.target_agent_id,
            target_org_id=session.target_org_id,
            status=session.status.value,
            requested_capabilities=json.dumps(session.requested_capabilities),
            created_at=session.created_at,
            expires_at=session.expires_at,
            closed_at=closed_at,
            last_activity_at=session.last_activity_at,
            close_reason=close_reason_value,
        ))
    await db.commit()


async def save_message(
    db: AsyncSession,
    session_id: str,
    msg: StoredMessage,
) -> bool:
    """Insert a message atomically, using the nonce UNIQUE constraint.

    Returns True if the message was inserted, False if the nonce was
    already present (replay attack).  Uses INSERT ... ON CONFLICT DO NOTHING
    so the check-and-insert is a single atomic operation — same pattern as
    ``jti_blacklist.check_and_consume_jti``.
    """
    values = dict(
        session_id=session_id,
        seq=msg.seq,
        sender_agent_id=msg.sender_agent_id,
        payload=json.dumps(msg.payload),
        nonce=msg.nonce,
        timestamp=msg.timestamp,
        signature=msg.signature,
        client_seq=msg.client_seq,
    )

    dialect_name = db.bind.dialect.name if db.bind else "unknown"

    if dialect_name == "postgresql":
        stmt = pg_insert(SessionMessageRecord).values(**values)
        stmt = stmt.on_conflict_do_nothing(index_elements=["nonce"])
    else:
        stmt = sqlite_insert(SessionMessageRecord).values(**values)
        stmt = stmt.on_conflict_do_nothing(index_elements=["nonce"])

    result = await db.execute(stmt)
    await db.commit()

    return result.rowcount > 0


async def fetch_messages_for_resume(
    db: AsyncSession,
    session_id: str,
    recipient_agent_id: str,
    after_seq: int,
    limit: int = 500,
) -> list[dict]:
    """Fetch messages for a session-resume request (M2.2).

    Returns messages with ``seq > after_seq`` whose ``sender_agent_id``
    is NOT the resuming agent (we replay incoming traffic only — the
    resumer's own outbound messages are not re-delivered). Ordered by
    seq ascending. Capped by ``limit`` to bound a single resume payload.
    """
    result = await db.execute(
        select(SessionMessageRecord)
        .where(
            SessionMessageRecord.session_id == session_id,
            SessionMessageRecord.seq > after_seq,
            SessionMessageRecord.sender_agent_id != recipient_agent_id,
        )
        .order_by(SessionMessageRecord.seq)
        .limit(limit)
    )
    out: list[dict] = []
    for rec in result.scalars().all():
        out.append({
            "seq": rec.seq,
            "sender_agent_id": rec.sender_agent_id,
            "payload": json.loads(rec.payload),
            "nonce": rec.nonce,
            "timestamp": rec.timestamp.replace(tzinfo=timezone.utc).isoformat(),
            "signature": rec.signature,
            "client_seq": rec.client_seq,
        })
    return out


async def restore_sessions(db: AsyncSession, store: SessionStore) -> int:
    """
    Load from DB all non-expired, non-closed sessions,
    reconstituting the in-memory store (sessions + messages + nonces).

    Each session is re-validated before restoration:
    - initiator binding must still be approved
    - session policy must still allow the initiator→target org pair

    Sessions failing validation are closed in DB and skipped.
    Returns the number of sessions successfully restored.
    """
    # Deferred imports to avoid circular dependencies at module load time.
    from app.policy.engine import PolicyEngine
    from app.registry.binding_store import get_approved_binding

    now = datetime.now(timezone.utc)
    policy_engine = PolicyEngine()

    result = await db.execute(
        select(SessionRecord).where(
            SessionRecord.status.in_(["pending", "active"]),
        )
    )
    records = result.scalars().all()

    restored = 0
    for rec in records:
        # Skip expired sessions
        if rec.expires_at and rec.expires_at.replace(tzinfo=timezone.utc) < now:
            continue

        # Re-validate initiator binding — must still be approved after restart.
        binding = await get_approved_binding(db, rec.initiator_org_id, rec.initiator_agent_id)
        if not binding:
            logger.warning(
                "Session %s invalidated on restore: binding revoked or missing for agent %s",
                rec.session_id, rec.initiator_agent_id,
            )
            rec.status = "closed"
            rec.closed_at = now
            await db.commit()
            continue

        # Re-validate session policy — may have been deactivated since session was opened.
        capabilities = json.loads(rec.requested_capabilities)
        decision = await policy_engine.evaluate_session(
            db,
            initiator_org_id=rec.initiator_org_id,
            target_org_id=rec.target_org_id,
            capabilities=capabilities,
            session_id=rec.session_id,
        )
        if not decision.allowed:
            logger.warning(
                "Session %s invalidated on restore: policy denied — %s",
                rec.session_id, decision.reason,
            )
            rec.status = "closed"
            rec.closed_at = now
            await db.commit()
            continue

        last_activity = (
            rec.last_activity_at.replace(tzinfo=timezone.utc)
            if rec.last_activity_at is not None
            else rec.created_at.replace(tzinfo=timezone.utc)
        )

        session = Session(
            session_id=rec.session_id,
            initiator_agent_id=rec.initiator_agent_id,
            initiator_org_id=rec.initiator_org_id,
            target_agent_id=rec.target_agent_id,
            target_org_id=rec.target_org_id,
            requested_capabilities=json.loads(rec.requested_capabilities),
            status=SessionStatus(rec.status),
            created_at=rec.created_at.replace(tzinfo=timezone.utc),
            expires_at=rec.expires_at.replace(tzinfo=timezone.utc) if rec.expires_at else None,
            last_activity_at=last_activity,
        )

        # Reload messages and rebuild nonce set
        msg_result = await db.execute(
            select(SessionMessageRecord)
            .where(SessionMessageRecord.session_id == rec.session_id)
            .order_by(SessionMessageRecord.seq)
        )
        for msg_rec in msg_result.scalars().all():
            stored = StoredMessage(
                seq=msg_rec.seq,
                sender_agent_id=msg_rec.sender_agent_id,
                payload=json.loads(msg_rec.payload),
                nonce=msg_rec.nonce,
                timestamp=msg_rec.timestamp.replace(tzinfo=timezone.utc),
                signature=msg_rec.signature,
                client_seq=msg_rec.client_seq,
            )
            session._messages.append(stored)
            session.used_nonces.add(msg_rec.nonce)
            session._next_seq = max(session._next_seq, msg_rec.seq + 1)

        store._sessions[session.session_id] = session
        restored += 1

    return restored
