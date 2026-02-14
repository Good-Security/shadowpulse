"""Make scans/findings session_id nullable for target-first runs.

Revision ID: 20260210_0003
Revises: 20260210_0002
Create Date: 2026-02-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260210_0003"
down_revision = "20260210_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("scans", "session_id", existing_type=sa.String(), nullable=True)
    op.alter_column("findings", "session_id", existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    # Downgrading would require that no rows have NULL session_id.
    op.alter_column("findings", "session_id", existing_type=sa.String(), nullable=False)
    op.alter_column("scans", "session_id", existing_type=sa.String(), nullable=False)

