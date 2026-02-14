"""Phase 8: Hardening — run_events audit trail table.

Revision ID: 20260213_0005
Revises: 20260210_0004
Create Date: 2026-02-13
"""

from alembic import op
import sqlalchemy as sa


revision = "20260213_0005"
down_revision = "20260210_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_run_events_target_id_created_at", "run_events", ["target_id", "created_at"])
    op.create_index("ix_run_events_run_id_created_at", "run_events", ["run_id", "created_at"])
    op.create_index("ix_run_events_event_type", "run_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_run_events_event_type", table_name="run_events")
    op.drop_index("ix_run_events_run_id_created_at", table_name="run_events")
    op.drop_index("ix_run_events_target_id_created_at", table_name="run_events")
    op.drop_table("run_events")
