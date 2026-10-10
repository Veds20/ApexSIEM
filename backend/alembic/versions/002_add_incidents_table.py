"""add_incidents_table

Revision ID: 002
Revises: 001
Create Date: 2026-10-01 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', name='incidentseverity'), nullable=False, server_default='MEDIUM'),
        sa.Column('status', sa.Enum('OPEN', 'IN_PROGRESS', 'UNDER_INVESTIGATION', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE', name='incidentstatus'), nullable=False, server_default='OPEN'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('assigned_to', sa.String(length=100), nullable=True),
        sa.Column('assigned_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(length=100), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('threat_intelligence', sa.Text(), nullable=True),
        sa.Column('timeline', sa.Text(), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('false_positive_reason', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
    op.create_index(op.f('ix_incidents_incident_id'), 'incidents', ['incident_id'], unique=True)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)

    op.create_table(
        'incident_alerts',
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('incident_id', 'alert_id')
    )


def downgrade() -> None:
    op.drop_table('incident_alerts')
    op.drop_index(op.f('ix_incidents_created_at'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_severity'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_incident_id'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_id'), table_name='incidents')
    op.drop_table('incidents')
