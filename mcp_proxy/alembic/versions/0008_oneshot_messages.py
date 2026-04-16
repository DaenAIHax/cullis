"""Sessionless one-shot messaging columns — ADR-008 Phase 1 PR #1.

Revision ID: 0008_oneshot_messages
Revises: 0007_mcp_resources
Create Date: 2026-04-16

Additive extension of ``local_messages`` for the ADR-008 sessionless
one-shot pattern (req/resp correlated via ``correlation_id``, without
opening a full session).

Changes:
  * ``local_messages.session_id`` becomes nullable. One-shot rows carry
    ``session_id = NULL``; session rows are unchanged.
  * New columns: ``is_oneshot`` (0/1 flag), ``correlation_id``,
    ``reply_to_correlation_id``.
  * New indexes: ``idx_local_messages_correlation`` for reply lookups
    and ``idx_local_messages_recipient_oneshot`` to keep the offline
    drain query cheap across both session + oneshot rows.

The existing ``uq_local_messages_session_seq`` UNIQUE over
``(session_id, seq)`` stays intact — multicolumn UNIQUE treats NULLs
as distinct on both SQLite and Postgres, so session rows keep their
(non-null session_id, seq) uniqueness while one-shot rows with NULL
NULL never collide with each other.

No DB-level UNIQUE on ``correlation_id``: idempotency is enforced
application-side via the existing ``idempotency_key`` path scoped by
(recipient, key), matching the single-process-proxy contract
documented in ``mcp_proxy/local/message_queue.py``.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_oneshot_messages"
down_revision: Union[str, Sequence[str], None] = "0007_mcp_resources"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("local_messages") as batch_op:
        batch_op.alter_column(
            "session_id",
            existing_type=sa.Text(),
            nullable=True,
        )
        batch_op.add_column(
            sa.Column("is_oneshot", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("correlation_id", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("reply_to_correlation_id", sa.Text(), nullable=True)
        )

    op.create_index(
        "idx_local_messages_correlation",
        "local_messages",
        ["correlation_id"],
    )
    op.create_index(
        "idx_local_messages_recipient_oneshot",
        "local_messages",
        ["recipient_agent_id", "is_oneshot", "delivery_status"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_local_messages_recipient_oneshot",
        table_name="local_messages",
    )
    op.drop_index(
        "idx_local_messages_correlation",
        table_name="local_messages",
    )
    with op.batch_alter_table("local_messages") as batch_op:
        batch_op.drop_column("reply_to_correlation_id")
        batch_op.drop_column("correlation_id")
        batch_op.drop_column("is_oneshot")
        batch_op.alter_column(
            "session_id",
            existing_type=sa.Text(),
            nullable=False,
        )
