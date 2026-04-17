"""add org.requires_proxy for ADR-009 Phase 3 strict enforcement

Revision ID: h8c9d0e1f2a3
Revises: g7b8c9d0e1f2
Create Date: 2026-04-17 11:50:00.000000

Adds a non-nullable ``requires_proxy`` BOOLEAN column (default FALSE) to
``organizations``. When set, /v1/auth/token for that org rejects any
request that doesn't carry a valid X-Cullis-Mastio-Signature — even if
mastio_pubkey is somehow null. Closes the last legacy path: an org can
now explicitly declare "no agent may bypass the mastio".

Default FALSE preserves backward compatibility — every existing org
keeps the soft enforcement introduced in Phase 1 (enforce only if
mastio_pubkey is pinned). Phase 4 will migrate appropriate orgs to
TRUE and remove the legacy soft path entirely.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'h8c9d0e1f2a3'
down_revision: Union[str, Sequence[str], None] = 'g7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'organizations',
        sa.Column(
            'requires_proxy',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('organizations', 'requires_proxy')
