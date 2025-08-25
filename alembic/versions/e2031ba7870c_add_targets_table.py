"""add_targets_table

Revision ID: e2031ba7870c
Revises: df88a648bb7a
Create Date: 2025-08-24 19:35:47.447845

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2031ba7870c'
down_revision: Union[str, Sequence[str], None] = 'df88a648bb7a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
