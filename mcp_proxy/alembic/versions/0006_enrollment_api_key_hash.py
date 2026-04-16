"""Add api_key_hash column to pending_enrollments — #122 follow-up.

Revision ID: 0006_enrollment_api_key_hash
Revises: 0005_schema_parity_with_broker
Create Date: 2026-04-16

The connector now generates its own X-API-Key locally at enroll-start
time, hashes it (bcrypt) and sends the hash with the enrollment
request. The server stores the hash here; on approve() it copies it
into internal_agents.api_key_hash so the device-code-approved agent
has a usable API key from day one — without the server ever seeing
the raw key.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_enrollment_api_key_hash"
down_revision: Union[str, Sequence[str], None] = "0005_schema_parity_with_broker"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("pending_enrollments") as batch_op:
        batch_op.add_column(
            sa.Column("api_key_hash", sa.Text(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("pending_enrollments") as batch_op:
        batch_op.drop_column("api_key_hash")
