"""
Invite tokens — gated onboarding for the Cullis trust network.

An admin generates a one-time invite token (the "biglietto da visita").
External orgs must present this token when calling POST /onboarding/join.
Without a valid, unexpired, unused token the endpoint returns 403.
"""
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from sqlalchemy import Column, String, DateTime, Boolean, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class InviteToken(Base):
    __tablename__ = "invite_tokens"

    id = Column(String(64), primary_key=True)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    label = Column(String(256), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    used_by_org_id = Column(String(128), nullable=True)
    revoked = Column(Boolean, default=False, nullable=False)


def _hash_token(token: str) -> str:
    """SHA-256 hash of the plaintext token (we never store plaintext)."""
    return hashlib.sha256(token.encode()).hexdigest()


async def create_invite(
    db: AsyncSession,
    *,
    label: str = "",
    ttl_hours: int = 72,
) -> tuple[InviteToken, str]:
    """
    Generate a new invite token.

    Returns (record, plaintext_token).  The plaintext is shown once to the
    admin and never stored — only the SHA-256 hash is persisted.
    """
    plaintext = secrets.token_urlsafe(32)
    record = InviteToken(
        id=secrets.token_hex(16),
        token_hash=_hash_token(plaintext),
        label=label,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record, plaintext


async def validate_and_consume(
    db: AsyncSession,
    plaintext_token: str,
    org_id: str,
) -> InviteToken | None:
    """
    Validate an invite token and mark it as consumed.

    Returns the record if valid, None otherwise.
    Token is consumed atomically — a second call with the same token fails.
    """
    from sqlalchemy import update as sa_update

    h = _hash_token(plaintext_token)
    now = datetime.now(timezone.utc)

    # Atomic consume: UPDATE WHERE used=false AND revoked=false RETURNING *
    # This prevents TOCTOU race: only one concurrent request succeeds.
    stmt = (
        sa_update(InviteToken)
        .where(
            InviteToken.token_hash == h,
            InviteToken.used == False,  # noqa: E712
            InviteToken.revoked == False,  # noqa: E712
        )
        .values(used=True, used_at=now, used_by_org_id=org_id)
        .returning(InviteToken)
    )
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        return None

    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        # Token was expired — rollback consumption
        record.used = False
        record.used_at = None
        record.used_by_org_id = None
        await db.commit()
        return None

    await db.commit()
    await db.refresh(record)
    return record


async def revoke_invite(db: AsyncSession, invite_id: str) -> InviteToken | None:
    """Revoke an unused invite token."""
    result = await db.execute(
        select(InviteToken).where(InviteToken.id == invite_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        return None
    record.revoked = True
    await db.commit()
    await db.refresh(record)
    return record


async def list_invites(db: AsyncSession) -> list[InviteToken]:
    """List all invite tokens (newest first)."""
    result = await db.execute(
        select(InviteToken).order_by(InviteToken.created_at.desc())
    )
    return list(result.scalars().all())
