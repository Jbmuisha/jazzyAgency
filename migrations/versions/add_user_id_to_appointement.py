"""Add user_id to appointement

Revision ID: add_user_id_to_appointement
Revises: add_service_status_to_appointement
Create Date: 2025-08-11 14:36:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_user_id_to_appointement'
down_revision = 'add_service_status_to_appointement'
branch_labels = None
depends_on = None

def upgrade():
    # Add user_id column with a default value of 1 (or any valid user ID)
    op.add_column('appointement', 
                 sa.Column('user_id', sa.Integer(), 
                          sa.ForeignKey('users.id'), 
                          nullable=False, 
                          server_default='1'))
    # If you need to update existing records, you can do it here
    # op.execute('UPDATE appointement SET user_id = 1')
    # Then remove the server_default if needed
    # op.alter_column('appointement', 'user_id', server_default=None)

def downgrade():
    op.drop_constraint('appointement_user_id_fkey', 'appointement', type_='foreignkey')
    op.drop_column('appointement', 'user_id')
