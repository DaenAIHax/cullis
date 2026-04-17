"""drop org.requires_proxy — ADR-009 Phase 4 cleanup

Revision ID: i9d0e1f2a3b4
Revises: h8c9d0e1f2a3
Create Date: 2026-04-17 12:30:00.000000

Phase 4 removes the ``requires_proxy`` flag entirely. After Phase 3 it
became redundant: the only way an org can emit a token is by pinning a
mastio_pubkey first, so the strict/soft distinction collapsed. Keeping
the column would be dead config — drop it and let the presence of
``mastio_pubkey`` be the sole contract.

``mastio_pubkey IS NULL`` now means "onboarding incomplete — no token
will be issued for this org" rather than "legacy opt-out".
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'i9d0e1f2a3b4'
down_revision: Union[str, Sequence[str], None] = 'h8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('organizations') as batch_op:
        batch_op.drop_column('requires_proxy')


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column(
        'organizations',
        sa.Column(
            'requires_proxy',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
