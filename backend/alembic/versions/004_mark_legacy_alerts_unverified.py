"""mark pre-provenance alerts as legacy/unverified without deleting them

Revision ID: 004
Revises: 003
Create Date: 2026-10-01 22:50:00.000000
"""
from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    # The prior watcher did not persist source record IDs or raw evidence.
    # Preserve those rows for audit/history, but make their lack of proof
    # explicit and keep them out of the active real-telemetry queue.
    op.execute("""
        UPDATE alerts
        SET source_type = 'legacy_unverified',
            source_name = 'Unverified legacy alert',
            collector = 'LegacyIngestion',
            source_event_id = 'legacy:' || id,
            event_timestamp = timestamp,
            ingestion_timestamp = timestamp,
            event_key = 'legacy:' || id
        WHERE source_type IS NULL
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE alerts
        SET source_type = NULL,
            source_name = NULL,
            collector = NULL,
            source_event_id = NULL,
            event_timestamp = NULL,
            ingestion_timestamp = NULL,
            event_key = NULL
        WHERE source_type = 'legacy_unverified'
    """)
