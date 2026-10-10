"""initial_schema

Revision ID: 001
Revises: 
Create Date: 2026-08-19 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source_ip', sa.String(), nullable=False),
        sa.Column('destination_ip', sa.String(), nullable=True),
        sa.Column('attack_type', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('trust_score', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('log_source', sa.String(), nullable=True),
        sa.Column('event_type', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('raw_log', sa.Text(), nullable=True),
        sa.Column('priority', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('assigned_to', sa.String(), nullable=True),
        sa.Column('analysis_report', sa.Text(), nullable=True),
        sa.Column('investigation_status', sa.String(), nullable=True),
        sa.Column('investigation_reason', sa.Text(), nullable=True),
        sa.Column('investigated_at', sa.DateTime(), nullable=True),
        sa.Column('anomaly_score', sa.Float(), nullable=True),
        sa.Column('is_anomaly', sa.Boolean(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)
    op.create_index(op.f('ix_alerts_source_ip'), 'alerts', ['source_ip'], unique=False)
    op.create_index(op.f('ix_alerts_timestamp'), 'alerts', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_alerts_timestamp'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_id'), table_name='alerts')
    op.drop_table('alerts')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_table('users')
