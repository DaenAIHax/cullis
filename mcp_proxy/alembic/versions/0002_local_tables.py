"""Local-* tables — ADR-001 Phase 1 scope.

Revision ID: 0002_local_tables
Revises: 0001_initial_snapshot
Create Date: 2026-04-13

Creates the five local_* tables that will host intra-org routing artifacts
when Phase 4 wires the proxy as a mini-broker. Phase 1 only deploys the
schema — no application code reads from or writes to these tables yet.

- local_agents: scope=local agents (broker doesn't see them).
- local_sessions: intra-org session records.
- local_messages: M3-twin queue for intra-org delivery.
- local_policies: local-only policy rules.
- local_audit: append-only, hash-chained intra-org audit trail.

Hash chain enforcement on local_audit is Phase 4 (trigger or app-level).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_local_tables"
down_revision: Union[str, Sequence[str], None] = "0001_initial_snapshot"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "local_agents",
        sa.Column("agent_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("capabilities", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("cert_pem", sa.Text(), nullable=True),
        sa.Column("api_key_hash", sa.Text(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=False, server_default="local"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
    )

    op.create_table(
        "local_sessions",
        sa.Column("session_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("initiator_agent_id", sa.Text(), nullable=False),
        sa.Column("responder_agent_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("last_activity_at", sa.Text(), nullable=True),
        sa.Column("close_reason", sa.Text(), nullable=True),
    )
    op.create_index("idx_local_sessions_initiator", "local_sessions", ["initiator_agent_id"])
    op.create_index("idx_local_sessions_responder", "local_sessions", ["responder_agent_id"])
    op.create_index("idx_local_sessions_status", "local_sessions", ["status"])

    op.create_table(
        "local_messages",
        sa.Column("msg_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("sender_agent_id", sa.Text(), nullable=False),
        sa.Column("recipient_agent_id", sa.Text(), nullable=False),
        sa.Column("payload_ciphertext", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("enqueued_at", sa.Text(), nullable=False),
        sa.Column("delivered_at", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.Text(), nullable=True),
    )
    op.create_index("idx_local_messages_session", "local_messages", ["session_id"])
    op.create_index(
        "idx_local_messages_recipient_status",
        "local_messages",
        ["recipient_agent_id", "status"],
    )
    op.create_index("idx_local_messages_idempotency", "local_messages", ["idempotency_key"])

    op.create_table(
        "local_policies",
        sa.Column("policy_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False, server_default="intra"),
        sa.Column("rules_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )

    op.create_table(
        "local_audit",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text(), nullable=False),
        sa.Column("actor_agent_id", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("row_hash", sa.Text(), nullable=True),
    )
    op.create_index("idx_local_audit_timestamp", "local_audit", ["timestamp"])
    op.create_index("idx_local_audit_actor", "local_audit", ["actor_agent_id"])


def downgrade() -> None:
    op.drop_index("idx_local_audit_actor", table_name="local_audit")
    op.drop_index("idx_local_audit_timestamp", table_name="local_audit")
    op.drop_table("local_audit")
    op.drop_table("local_policies")
    op.drop_index("idx_local_messages_idempotency", table_name="local_messages")
    op.drop_index("idx_local_messages_recipient_status", table_name="local_messages")
    op.drop_index("idx_local_messages_session", table_name="local_messages")
    op.drop_table("local_messages")
    op.drop_index("idx_local_sessions_status", table_name="local_sessions")
    op.drop_index("idx_local_sessions_responder", table_name="local_sessions")
    op.drop_index("idx_local_sessions_initiator", table_name="local_sessions")
    op.drop_table("local_sessions")
    op.drop_table("local_agents")
