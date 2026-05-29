"""Add ``capabilities`` to typed principals (users + workloads).

Revision ID: 0045_principal_capabilities
Revises: 0044_audit_merkle_anchors
Create Date: 2026-05-28 21:00:00.000000

v0.6.4 made the capability check fail-loud on ``llm.chat`` and
``mcp.tools.list`` (issues #22, #23). On the agent path the
capability set already lives in ``internal_agents.capabilities``;
typed principals (``user::*``, ``workload::*``) had no equivalent
storage, so ``mcp_proxy.auth.local_agent_dep`` was hardcoding
``scope=[]`` for them and the new gate started 403-ing every
Frontdesk user + workload that asked ``/v1/mcp tools/list``.

This migration adds the missing column on both tables:

  * ``local_user_principals.capabilities``     (Text, JSON array, default '[]')
  * ``local_workload_principals.capabilities`` (Text, JSON array, default '[]')

Same encoding as ``internal_agents.capabilities`` (JSON string of an
array) so the lookup code in ``local_agent_dep`` can share the parse.
Default ``'[]'`` keeps the column NOT NULL while preserving the
zero-trust default-deny semantics: every existing user + workload
starts cap-less and must be granted capabilities explicitly via the
admin API.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0045_principal_capabilities"
down_revision: Union[str, Sequence[str], None] = "0044_audit_merkle_anchors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_USERS = "local_user_principals"
_WORKLOADS = "local_workload_principals"
_COLUMN = "capabilities"


def _has_column(inspector: sa.Inspector, table: str, column: str) -> bool:
    if table not in set(inspector.get_table_names()):
        return False
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table in (_USERS, _WORKLOADS):
        if _has_column(inspector, table, _COLUMN):
            continue
        op.add_column(
            table,
            sa.Column(
                _COLUMN,
                sa.Text(),
                nullable=False,
                server_default="[]",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in (_USERS, _WORKLOADS):
        if _has_column(inspector, table, _COLUMN):
            op.drop_column(table, _COLUMN)
