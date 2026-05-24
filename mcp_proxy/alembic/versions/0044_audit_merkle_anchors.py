"""Merkle batch anchors — append-only Merkle roots over audit_log
chain_seq batches (ADR-037 Phase 1).

Revision ID: 0044_audit_merkle_anchors
Revises: 0043_audit_chain_anchors
Create Date: 2026-05-24 14:00:00.000000

Introduces ``audit_merkle_anchors``, the storage side for Phase 1 of
the Merkle audit anchoring design. Each row binds a contiguous batch
of audit_log chain_seq values to a single Merkle root, with the
optional TSA TimeStampToken over the root for tamper-evidence
against the operator.

The pure tree math lives in ``mcp_proxy.audit.merkle`` (Phase 0,
PR #918). This migration is the persistence layer; the lifespan
watcher (this PR) reads audit_log, computes the root, and writes
one row here per batch.

Same append-only trigger pattern as audit_log (F-A-402) and
audit_chain_anchors (PR #911): rows are written once, never
updated, never deleted. An operator who tampers with audit_log to
forge history would also need to forge the Merkle root match in
the corresponding anchor row to evade the offline verifier (Phase 2
follow-up).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0044_audit_merkle_anchors"
down_revision: Union[str, Sequence[str], None] = "0043_audit_chain_anchors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "audit_merkle_anchors"


_PG_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION audit_merkle_anchors_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_merkle_anchors is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_PG_TRIGGER = """
CREATE TRIGGER audit_merkle_anchors_no_update_or_delete
BEFORE UPDATE OR DELETE ON audit_merkle_anchors
FOR EACH ROW EXECUTE FUNCTION audit_merkle_anchors_no_mutate();
"""

_SQLITE_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS audit_merkle_anchors_no_update
BEFORE UPDATE ON audit_merkle_anchors
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_merkle_anchors is append-only: UPDATE not permitted');
END;
"""

_SQLITE_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS audit_merkle_anchors_no_delete
BEFORE DELETE ON audit_merkle_anchors
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_merkle_anchors is append-only: DELETE not permitted');
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
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        # Range of audit_log.chain_seq covered by this anchor, inclusive
        # on both ends. The watcher walks forward by starting the next
        # batch at chain_seq_end + 1.
        sa.Column("chain_seq_start", sa.Integer(), nullable=False),
        sa.Column("chain_seq_end", sa.Integer(), nullable=False),
        sa.Column("leaf_count", sa.Integer(), nullable=False),
        # 64 lowercase hex chars = SHA-256 binary tree root over the
        # row_hash bytes of every audit_log row in [start, end].
        sa.Column("merkle_root", sa.Text(), nullable=False),
        # Optional RFC 3161 TSA TimeStampToken over the merkle_root.
        # NULL when the worker ran with TSA anchoring disabled or when
        # the TSA call failed at batch time (the local batch is still
        # written; the TSA retry is "next batch", not "stop the loop").
        sa.Column("tsa_url", sa.Text(), nullable=True),
        sa.Column("tsa_token", sa.LargeBinary(), nullable=True),
    )
    # Lookup the most recent anchor for an org (the watcher's hot path).
    op.create_index(
        "idx_audit_merkle_anchors_org_chain_seq_end",
        _TABLE, ["org_id", "chain_seq_end"],
    )
    # Lookup the anchor covering a specific chain_seq (the offline
    # verifier's hot path: "which Merkle anchor includes chain_seq N?").
    op.create_index(
        "idx_audit_merkle_anchors_chain_seq_start",
        _TABLE, ["chain_seq_start"],
    )

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(_PG_TRIGGER_FN)
        op.execute(
            "DROP TRIGGER IF EXISTS audit_merkle_anchors_no_update_or_delete "
            "ON audit_merkle_anchors"
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
            "DROP TRIGGER IF EXISTS audit_merkle_anchors_no_update_or_delete "
            "ON audit_merkle_anchors"
        )
        op.execute("DROP FUNCTION IF EXISTS audit_merkle_anchors_no_mutate")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_merkle_anchors_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_merkle_anchors_no_delete")
    op.drop_index("idx_audit_merkle_anchors_chain_seq_start", _TABLE)
    op.drop_index("idx_audit_merkle_anchors_org_chain_seq_end", _TABLE)
    op.drop_table(_TABLE)
