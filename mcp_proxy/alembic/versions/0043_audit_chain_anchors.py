"""TSA anchors — append-only mirror of audit_log hash chain heads.

Revision ID: 0043_audit_chain_anchors
Revises: 0042_audit_log_v2
Create Date: 2026-05-24 09:00:00.000000

Introduces the ``audit_chain_anchors`` table that stores RFC 3161
TimeStampTokens binding to the chain head at periodic intervals.
``cullis-audit-verify.py`` already understands the
``T1|<token bytes>`` format the lifespan watcher writes here; this
migration is the storage side.

Same append-only trigger pattern as audit_log (F-A-402): rows are
written once, never updated, never deleted. An operator who tampers
with audit_log to forge a history would also need to forge the TSA
signature in the corresponding anchor row to evade
``verify_anchors`` in the standalone verifier — the trigger guards
the storage layer, the TSA's cert chain guards the signature.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0043_audit_chain_anchors"
down_revision: Union[str, Sequence[str], None] = "0042_audit_log_v2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "audit_chain_anchors"


_PG_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION audit_chain_anchors_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_chain_anchors is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_PG_TRIGGER = """
CREATE TRIGGER audit_chain_anchors_no_update_or_delete
BEFORE UPDATE OR DELETE ON audit_chain_anchors
FOR EACH ROW EXECUTE FUNCTION audit_chain_anchors_no_mutate();
"""

_SQLITE_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS audit_chain_anchors_no_update
BEFORE UPDATE ON audit_chain_anchors
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_chain_anchors is append-only: UPDATE not permitted');
END;
"""

_SQLITE_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS audit_chain_anchors_no_delete
BEFORE DELETE ON audit_chain_anchors
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_chain_anchors is append-only: DELETE not permitted');
END;
"""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        return  # Idempotent — re-running the chain finds it.

    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("anchored_at", sa.Text(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("chain_seq", sa.Integer(), nullable=False),
        sa.Column("row_hash", sa.Text(), nullable=False),
        sa.Column("tsa_url", sa.Text(), nullable=False),
        sa.Column("tsa_token", sa.LargeBinary(), nullable=False),
    )
    op.create_index(
        "idx_audit_chain_anchors_chain_seq", _TABLE, ["chain_seq"],
    )
    op.create_index(
        "idx_audit_chain_anchors_anchored_at", _TABLE, ["anchored_at"],
    )

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(_PG_TRIGGER_FN)
        op.execute(
            "DROP TRIGGER IF EXISTS audit_chain_anchors_no_update_or_delete "
            "ON audit_chain_anchors"
        )
        op.execute(_PG_TRIGGER)
    elif dialect == "sqlite":
        op.execute(_SQLITE_TRIGGER_UPDATE)
        op.execute(_SQLITE_TRIGGER_DELETE)


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS audit_chain_anchors_no_update_or_delete "
            "ON audit_chain_anchors"
        )
        op.execute("DROP FUNCTION IF EXISTS audit_chain_anchors_no_mutate")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_chain_anchors_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_chain_anchors_no_delete")
    op.drop_index("idx_audit_chain_anchors_anchored_at", _TABLE)
    op.drop_index("idx_audit_chain_anchors_chain_seq", _TABLE)
    op.drop_table(_TABLE)
