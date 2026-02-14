"""Add rich fields to messages for chat replay.

Revision ID: 20260213_0006
Revises: 20260213_0005
Create Date: 2026-02-13
"""

from alembic import op
import sqlalchemy as sa


revision = "20260213_0006"
down_revision = "20260213_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("tool_args", sa.JSON(), nullable=True))
    op.add_column("messages", sa.Column("tool_output", sa.Text(), nullable=True))
    op.add_column(
        "messages",
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=True),
    )
    op.add_column(
        "messages",
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("messages", "finding_id")
    op.drop_column("messages", "scan_id")
    op.drop_column("messages", "tool_output")
    op.drop_column("messages", "tool_args")
