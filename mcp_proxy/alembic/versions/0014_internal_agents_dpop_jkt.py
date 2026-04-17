"""F-B-11 Phase 2 — ``internal_agents.dpop_jkt`` pins the agent's DPoP JWK.

Revision ID: 0014_internal_agents_dpop_jkt
Revises: 0013_internal_agents_device_info
Create Date: 2026-04-17 23:30:00.000000

Adds a nullable ``dpop_jkt`` column on ``internal_agents`` so each
enrolled agent can bind its ``X-API-Key`` to a locally-held EC/RSA
keypair (RFC 7638 JWK thumbprint). Without the binding, a leaked
``.env`` is enough to impersonate an agent on the Mastio egress
surface (audit F-B-11, issue #181).

Nullable on purpose — Phase 3 wires the SDK to send the JWK at
enrollment time and Phase 6 flips ``CULLIS_EGRESS_DPOP_MODE`` to
``required``. Until then, legacy bearer auth keeps working for any
row with NULL ``dpop_jkt``. See
``mcp_proxy/auth/dpop_api_key.get_agent_from_dpop_api_key`` for the
runtime enforcement rules.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0014_internal_agents_dpop_jkt"
down_revision: Union[str, Sequence[str], None] = "0013_internal_agents_device_info"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent add — ``init_db`` may call ``metadata.create_all``
    # before stamping on legacy-unstamped SQLite deploys, in which case
    # the table already carries ``dpop_jkt`` from the current model.
    # See the ``feedback_alembic_partial_legacy`` convention +
    # migration 0013 for the precedent.
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "dpop_jkt" in existing:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.add_column(
            sa.Column("dpop_jkt", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "dpop_jkt" not in existing:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.drop_column("dpop_jkt")
