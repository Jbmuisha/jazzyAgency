"""add service and status to appointement

Revision ID: add_service_status_to_appointement
Revises: 
Create Date: 2025-08-11 10:58:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_service_status_to_appointement'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add service column
    op.add_column('appointement', 
        sa.Column('service', sa.String(length=50), nullable=False, server_default='general')
    )
    # Add status column with default 'pending'
    op.add_column('appointement',
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending')
    )

def downgrade():
    # Remove the columns if we need to rollback
    op.drop_column('appointement', 'service')
    op.drop_column('appointement', 'status')
