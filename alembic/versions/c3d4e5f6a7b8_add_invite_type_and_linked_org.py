"""add invite_type and linked_org_id to invite_tokens

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-04-12 10:00:00.000000

Adds two columns to invite_tokens to support attach-ca invites, which are
bound to a specific org_id and only usable via POST /onboarding/attach (not /join).

- invite_type: 'org-join' (default, legacy behaviour) | 'attach-ca'
- linked_org_id: NULL for org-join; set to target org_id for attach-ca
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'invite_tokens',
        sa.Column('invite_type', sa.String(length=32), nullable=False,
                  server_default='org-join'),
    )
    op.add_column(
        'invite_tokens',
        sa.Column('linked_org_id', sa.String(length=128), nullable=True),
    )
    op.create_index(
        'ix_invite_tokens_linked_org_id',
        'invite_tokens',
        ['linked_org_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_invite_tokens_linked_org_id', table_name='invite_tokens')
    op.drop_column('invite_tokens', 'linked_org_id')
    op.drop_column('invite_tokens', 'invite_type')
