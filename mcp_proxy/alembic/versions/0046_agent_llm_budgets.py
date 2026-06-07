"""Add ``agent_llm_budgets`` — per-agent cumulative LLM token budgets.

Revision ID: 0046_agent_llm_budgets
Revises: 0045_principal_capabilities
Create Date: 2026-06-07 12:00:00.000000

The usage dashboard (PR #1073) surfaces per-provider / per-agent token
consumption derived from the audit chain. This migration adds the
storage for the enforcement half: an optional per-agent cumulative token
ceiling over the calendar UTC day / month.

One row per agent that has a budget. ``tokens_per_day`` /
``tokens_per_month`` of ``0`` mean "no ceiling for that period" (same
convention as the global ``MCP_PROXY_LLM_TOKENS_PER_DAY`` /
``_PER_MONTH`` settings, which apply when no enabled row exists). The
runtime counter lives in Redis (``mcp_proxy.egress.budget``) and is
seeded from the audit chain on a cold key, so this table only holds the
*policy* (the ceiling), never the running total.

Idempotent: skips creation when the table already exists, so a
``metadata.create_all`` bootstrap (tests, ``PROXY_SKIP_MIGRATIONS=1``)
and the alembic path converge on the same schema.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0046_agent_llm_budgets"
down_revision: Union[str, Sequence[str], None] = "0045_principal_capabilities"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "agent_llm_budgets"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        return
    op.create_table(
        _TABLE,
        sa.Column("agent_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("tokens_per_day", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_per_month", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        op.drop_table(_TABLE)
