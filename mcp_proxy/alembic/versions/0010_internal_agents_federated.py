"""ADR-010 Phase 2 — internal_agents.federated flag.

Revision ID: 0010_internal_agents_federated
Revises: 0009_audit_chain_unique_seq
Create Date: 2026-04-17 17:00:00.000000

Adds three columns to ``internal_agents`` so the Mastio can mark agents
as federated (published to the Court) and track the push state:

  federated            BOOL NOT NULL DEFAULT 0
  federated_at         TIMESTAMP NULL
  federation_revision  INTEGER NOT NULL DEFAULT 0

Default ``federated=0`` matches ADR-010 D1 "opt-in, admin flips the
flag to expose". ``federation_revision`` is bumped on every mutation
(cert rotate, caps change, etc.) so the publisher loop (Phase 3) can
tell whether the row needs a re-push.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_internal_agents_federated"
down_revision: Union[str, Sequence[str], None] = "0009_audit_chain_unique_seq"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "federated", sa.Boolean(),
                nullable=False, server_default=sa.false(),
            ),
        )
        batch_op.add_column(
            sa.Column("federated_at", sa.DateTime(timezone=True), nullable=True),
        )
        batch_op.add_column(
            sa.Column(
                "federation_revision", sa.Integer(),
                nullable=False, server_default="0",
            ),
        )


def downgrade() -> None:
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.drop_column("federation_revision")
        batch_op.drop_column("federated_at")
        batch_op.drop_column("federated")
