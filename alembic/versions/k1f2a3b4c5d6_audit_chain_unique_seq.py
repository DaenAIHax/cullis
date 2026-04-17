"""audit chain — UNIQUE(org_id, chain_seq) for multi-worker safety

Revision ID: k1f2a3b4c5d6
Revises: j0e1f2a3b4c5
Create Date: 2026-04-17 16:00:00.000000

Audit finding F-D-8 (`imp/audit_2026_04_17/phase1_D_race.md`).

Background
----------
``app/db/audit.py`` serialises per-org audit appends with a
module-level ``_org_locks: dict[str, asyncio.Lock]``. That lock is
process-local. In a multi-worker deployment (CULLIS_WORKERS > 1 or
gunicorn ``workers=N``) two workers can both read
``_last_per_org(X) = (hash_k, seq=5)`` concurrently and both insert
``chain_seq=6`` — two competing continuations of the per-org chain,
detectable only on ``verify_chain`` which picks one arbitrarily and
flags the other as tampered.

Fix
---
Add a UNIQUE constraint on ``(org_id, chain_seq)`` so the database
rejects the loser of any race. ``log_event`` then catches the
``IntegrityError``, re-reads the org head, and retries with the new
seq. The process-local lock stays as the happy-path fast lane.

The same fix applies to the proxy ``local_audit`` table; that one
lives in ``mcp_proxy/alembic/versions/0009_audit_chain_unique_seq.py``.

Backfill
--------
No backfill required: the constraint applies to future writes only
and matches the invariant already maintained (best-effort) by the
per-org lock. Existing rows with ``chain_seq IS NULL`` (legacy,
pre-per-org migration) are ignored by the unique index because NULL
is distinct on both Postgres and SQLite multi-column UNIQUE.
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'k1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'j0e1f2a3b4c5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add UNIQUE(org_id, chain_seq) to audit_log for multi-worker safety.

    Uses ``batch_alter_table`` so the migration applies cleanly on
    SQLite (which has no native ALTER TABLE ADD CONSTRAINT — alembic
    rewrites the table via copy-and-move). Postgres runs the same code
    path as a plain ``ALTER TABLE ... ADD CONSTRAINT``.
    """
    # NULL-tolerant on both Postgres and SQLite — legacy rows with
    # chain_seq IS NULL remain insertable without conflict.
    with op.batch_alter_table('audit_log') as batch_op:
        batch_op.create_unique_constraint(
            'uq_audit_log_org_chain_seq',
            ['org_id', 'chain_seq'],
        )


def downgrade() -> None:
    """Drop the UNIQUE constraint."""
    with op.batch_alter_table('audit_log') as batch_op:
        batch_op.drop_constraint(
            'uq_audit_log_org_chain_seq',
            type_='unique',
        )
