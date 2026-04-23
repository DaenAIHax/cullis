"""``migration_state_backups`` — snapshot blob for federation update rollback.

Revision ID: 0020_migration_state_backups
Revises: 0019_pending_updates
Create Date: 2026-04-23 22:00:00.000000

Federation update framework (imp/federation_hardening_plan.md Parte 1)
PR 3 of 5 — backup storage for the first concrete migration.

One row per ``migration_id``; ``snapshot_json`` is an opaque per-migration
blob whose schema is owned by the migration itself, not by the DB layer.
``INSERT OR REPLACE`` on apply means a second apply overwrites the prior
backup (the previous state is no longer recoverable by design — the
admin drove a fresh apply, acknowledging the reset).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0020_migration_state_backups"
down_revision: Union[str, Sequence[str], None] = "0019_pending_updates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "migration_state_backups" in existing_tables:
        return

    op.create_table(
        "migration_state_backups",
        sa.Column("migration_id", sa.Text(), primary_key=True),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("snapshot_json", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "migration_state_backups" not in existing:
        return
    op.drop_table("migration_state_backups")
