"""Anomaly detection tables — ADR-013 Phase 4.

Revision ID: 0021_anomaly_detector_tables
Revises: 0020_migration_state_backups
Create Date: 2026-04-24 12:00:00.000000

Three additive tables backing the single-agent anomaly detector
(imp/adr_013_phase4_design.md):

- ``agent_traffic_samples``: 10-min bucketed request counts per agent,
  4-week rolling window. Traffic recorder middleware flushes to this
  table every 30 s.
- ``agent_hourly_baselines``: daily roll-up of traffic samples into 168
  hour-of-week buckets (dow * 24 + hour). Source of truth for the
  ratio detector.
- ``agent_quarantine_events``: append-only audit trail of every
  quarantine decision, including shadow-mode "would have" events.
  Dashboard + expiry cron read from here.

Timestamps are ISO-8601 ``Text`` (project convention — see
``mastio_keys``, ``internal_agents``, ``pending_enrollments``).
SQLite/Postgres render identically with ``Text``; a mixed
``TIMESTAMPTZ``/``Text`` schema would break the ``EXPECTED_TABLES``
parity tests. ``hour_of_week`` uses ``SmallInteger`` + a CHECK; both
dialects render that CHECK literally.

Schema-only. No data migration — this is a new feature with no prior
state to carry forward.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0021_anomaly_detector_tables"
down_revision: Union[str, Sequence[str], None] = "0020_migration_state_backups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "agent_traffic_samples" not in existing_tables:
        op.create_table(
            "agent_traffic_samples",
            sa.Column("agent_id", sa.Text(), nullable=False),
            sa.Column("bucket_ts", sa.Text(), nullable=False),
            sa.Column("req_count", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint(
                "agent_id", "bucket_ts", name="pk_agent_traffic_samples"
            ),
        )
        op.create_index(
            "idx_traffic_samples_bucket",
            "agent_traffic_samples",
            ["bucket_ts"],
        )

    if "agent_hourly_baselines" not in existing_tables:
        op.create_table(
            "agent_hourly_baselines",
            sa.Column("agent_id", sa.Text(), nullable=False),
            sa.Column("hour_of_week", sa.SmallInteger(), nullable=False),
            sa.Column("req_per_min_avg", sa.Float(), nullable=False),
            sa.Column("req_per_min_p95", sa.Float(), nullable=False),
            sa.Column("sample_count", sa.Integer(), nullable=False),
            sa.Column("updated_at", sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint(
                "agent_id", "hour_of_week", name="pk_agent_hourly_baselines"
            ),
            sa.CheckConstraint(
                "hour_of_week BETWEEN 0 AND 167",
                name="ck_agent_hourly_baselines_hour_range",
            ),
        )

    if "agent_quarantine_events" not in existing_tables:
        op.create_table(
            "agent_quarantine_events",
            sa.Column(
                "id", sa.Integer(), primary_key=True, autoincrement=True
            ),
            sa.Column("agent_id", sa.Text(), nullable=False),
            sa.Column("quarantined_at", sa.Text(), nullable=False),
            sa.Column("mode", sa.Text(), nullable=False),
            sa.Column("trigger_ratio", sa.Float(), nullable=True),
            sa.Column("trigger_abs_rate", sa.Float(), nullable=True),
            sa.Column("expires_at", sa.Text(), nullable=True),
            sa.Column("resolved_at", sa.Text(), nullable=True),
            sa.Column("resolved_by", sa.Text(), nullable=True),
            sa.Column(
                "notification_sent",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.CheckConstraint(
                "mode IN ('shadow', 'enforce')",
                name="ck_agent_quarantine_events_mode",
            ),
        )
        op.create_index(
            "idx_quarantine_agent",
            "agent_quarantine_events",
            ["agent_id", "quarantined_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())

    if "agent_quarantine_events" in existing:
        op.drop_index(
            "idx_quarantine_agent", table_name="agent_quarantine_events"
        )
        op.drop_table("agent_quarantine_events")

    if "agent_hourly_baselines" in existing:
        op.drop_table("agent_hourly_baselines")

    if "agent_traffic_samples" in existing:
        op.drop_index(
            "idx_traffic_samples_bucket", table_name="agent_traffic_samples"
        )
        op.drop_table("agent_traffic_samples")
