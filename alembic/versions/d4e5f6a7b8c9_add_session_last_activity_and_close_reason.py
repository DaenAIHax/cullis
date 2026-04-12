"""add last_activity_at and close_reason to sessions

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-04-12 16:30:00.000000

M1 Session Reliability Layer:
- last_activity_at tracks the last send/poll on a session (idle timeout detection)
- close_reason records why the session was terminated (normal/idle_timeout/ttl_expired/peer_lost/policy_revoked)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'sessions',
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'sessions',
        sa.Column('close_reason', sa.String(length=32), nullable=True),
    )
    # Backfill last_activity_at with created_at for existing rows
    op.execute(
        "UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL"
    )


def downgrade() -> None:
    op.drop_column('sessions', 'close_reason')
    op.drop_column('sessions', 'last_activity_at')
