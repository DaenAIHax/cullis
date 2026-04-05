"""add rfq and transaction token tables

Revision ID: a1b2c3d4e5f6
Revises: 7043c1ddb652
Create Date: 2026-04-05 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '7043c1ddb652'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # RFQ requests — matches app/broker/db_models.py RfqRecord
    op.create_table(
        'rfq_requests',
        sa.Column('rfq_id', sa.String(length=128), nullable=False),
        sa.Column('initiator_agent_id', sa.String(length=256), nullable=False),
        sa.Column('initiator_org_id', sa.String(length=128), nullable=False),
        sa.Column('capability_filter', sa.Text(), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('matched_agents_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('rfq_id'),
    )
    op.create_index('ix_rfq_requests_initiator_agent_id', 'rfq_requests', ['initiator_agent_id'])
    op.create_index('ix_rfq_requests_initiator_org_id', 'rfq_requests', ['initiator_org_id'])
    op.create_index('ix_rfq_requests_status', 'rfq_requests', ['status'])

    # RFQ responses — matches app/broker/db_models.py RfqResponseRecord
    op.create_table(
        'rfq_responses',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rfq_id', sa.String(length=128), nullable=False),
        sa.Column('responder_agent_id', sa.String(length=256), nullable=False),
        sa.Column('responder_org_id', sa.String(length=128), nullable=False),
        sa.Column('response_payload', sa.Text(), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('rfq_id', 'responder_agent_id', name='uq_rfq_responder'),
    )
    op.create_index('ix_rfq_responses_rfq_id', 'rfq_responses', ['rfq_id'])

    # Transaction tokens — matches app/auth/transaction_db.py TransactionTokenRecord
    op.create_table(
        'transaction_tokens',
        sa.Column('jti', sa.String(length=128), nullable=False),
        sa.Column('txn_type', sa.String(length=64), nullable=False),
        sa.Column('agent_id', sa.String(length=256), nullable=False),
        sa.Column('org_id', sa.String(length=128), nullable=False),
        sa.Column('resource_id', sa.String(length=256), nullable=True),
        sa.Column('payload_hash', sa.String(length=64), nullable=False),
        sa.Column('approved_by', sa.String(length=256), nullable=False),
        sa.Column('parent_jti', sa.String(length=128), nullable=True),
        sa.Column('rfq_id', sa.String(length=128), nullable=True),
        sa.Column('target_agent_id', sa.String(length=256), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('jti'),
    )
    op.create_index('ix_transaction_tokens_agent_id', 'transaction_tokens', ['agent_id'])
    op.create_index('ix_transaction_tokens_rfq_id', 'transaction_tokens', ['rfq_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_transaction_tokens_rfq_id', table_name='transaction_tokens')
    op.drop_index('ix_transaction_tokens_agent_id', table_name='transaction_tokens')
    op.drop_table('transaction_tokens')

    op.drop_index('ix_rfq_responses_rfq_id', table_name='rfq_responses')
    op.drop_table('rfq_responses')

    op.drop_index('ix_rfq_requests_status', table_name='rfq_requests')
    op.drop_index('ix_rfq_requests_initiator_org_id', table_name='rfq_requests')
    op.drop_index('ix_rfq_requests_initiator_agent_id', table_name='rfq_requests')
    op.drop_table('rfq_requests')
