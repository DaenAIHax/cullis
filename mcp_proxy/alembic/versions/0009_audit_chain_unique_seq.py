"""local_audit — UNIQUE(org_id, chain_seq) for multi-worker safety.

Revision ID: 0009_audit_chain_unique_seq
Revises: 0008_oneshot_messages
Create Date: 2026-04-17

Twin of broker migration ``k1f2a3b4c5d6_audit_chain_unique_seq.py``.

The proxy's ``local_audit`` table is written by
``mcp_proxy/local/audit.py`` which serialises per-org appends with a
module-level ``_org_locks`` dict — process-local, same failure mode as
the broker: two workers racing on the same org_id can both insert a
row with the same ``chain_seq``, silently forking the per-org chain.

Adding UNIQUE(org_id, chain_seq) turns that race into an
``IntegrityError``; ``append_local_audit`` catches and retries with
the new head. NULL-tolerant on both SQLite and Postgres, so rows
without a per-org chain (legacy/system events with chain_seq IS NULL)
are unaffected.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0009_audit_chain_unique_seq"
down_revision: Union[str, Sequence[str], None] = "0008_oneshot_messages"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("local_audit") as batch_op:
        batch_op.create_unique_constraint(
            "uq_local_audit_org_chain_seq",
            ["org_id", "chain_seq"],
        )


def downgrade() -> None:
    with op.batch_alter_table("local_audit") as batch_op:
        batch_op.drop_constraint(
            "uq_local_audit_org_chain_seq",
            type_="unique",
        )
