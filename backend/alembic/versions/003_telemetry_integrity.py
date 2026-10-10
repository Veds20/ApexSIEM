"""add telemetry provenance, normalized evidence, and collector state

Revision ID: 003
Revises: 002
Create Date: 2026-10-01 22:35:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "normalized_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(), nullable=False),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("source_name", sa.String(), nullable=False),
        sa.Column("collector", sa.String(), nullable=False),
        sa.Column("source_event_id", sa.String(), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(), nullable=False),
        sa.Column("ingestion_timestamp", sa.DateTime(), nullable=False),
        sa.Column("raw_evidence", sa.Text(), nullable=False),
        sa.Column("normalized_data", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
    )
    op.create_index(op.f("ix_normalized_events_id"), "normalized_events", ["id"], unique=False)
    op.create_index(op.f("ix_normalized_events_event_key"), "normalized_events", ["event_key"], unique=True)
    op.create_index(op.f("ix_normalized_events_source_type"), "normalized_events", ["source_type"], unique=False)
    op.create_index(op.f("ix_normalized_events_event_timestamp"), "normalized_events", ["event_timestamp"], unique=False)
    op.create_index(op.f("ix_normalized_events_ingestion_timestamp"), "normalized_events", ["ingestion_timestamp"], unique=False)

    op.create_table(
        "collector_health",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collector_name", sa.String(), nullable=False),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="DISCONNECTED"),
        sa.Column("last_event_received", sa.DateTime(), nullable=True),
        sa.Column("events_per_second", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("collector_name"),
    )
    op.create_index(op.f("ix_collector_health_id"), "collector_health", ["id"], unique=False)
    op.create_index(op.f("ix_collector_health_collector_name"), "collector_health", ["collector_name"], unique=True)

    op.create_table(
        "collector_cursors",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collector_name", sa.String(), nullable=False),
        sa.Column("source_name", sa.String(), nullable=False),
        sa.Column("cursor_value", sa.String(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("collector_name", "source_name", name="uq_collector_cursor"),
    )
    op.create_index(op.f("ix_collector_cursors_id"), "collector_cursors", ["id"], unique=False)
    op.create_index(op.f("ix_collector_cursors_collector_name"), "collector_cursors", ["collector_name"], unique=False)

    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("source_type", sa.String(), nullable=True))
        batch.add_column(sa.Column("source_name", sa.String(), nullable=True))
        batch.add_column(sa.Column("collector", sa.String(), nullable=True))
        batch.add_column(sa.Column("source_event_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("event_timestamp", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("ingestion_timestamp", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("event_key", sa.String(), nullable=True))
        batch.add_column(sa.Column("normalized_event_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_alerts_normalized_event", "normalized_events", ["normalized_event_id"], ["id"])
        batch.create_index("ix_alerts_source_type", ["source_type"])
        batch.create_index("ix_alerts_event_timestamp", ["event_timestamp"])
        batch.create_index("ix_alerts_ingestion_timestamp", ["ingestion_timestamp"])
        batch.create_index("ix_alerts_event_key", ["event_key"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.drop_index("ix_alerts_event_key")
        batch.drop_index("ix_alerts_ingestion_timestamp")
        batch.drop_index("ix_alerts_event_timestamp")
        batch.drop_index("ix_alerts_source_type")
        batch.drop_constraint("fk_alerts_normalized_event", type_="foreignkey")
        for name in ("normalized_event_id", "event_key", "ingestion_timestamp", "event_timestamp", "source_event_id", "collector", "source_name", "source_type"):
            batch.drop_column(name)
    op.drop_table("collector_cursors")
    op.drop_table("collector_health")
    op.drop_table("normalized_events")
