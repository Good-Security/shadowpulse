"""Phase 5/6: schedules/jobs; add verified_run_id to assets/services.

Revision ID: 20260210_0004
Revises: 20260210_0003
Create Date: 2026-02-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260210_0004"
down_revision = "20260210_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add verification provenance to assets/services.
    op.add_column("assets", sa.Column("verified_run_id", sa.String(), nullable=True))
    op.create_foreign_key(
        "fk_assets_verified_run_id_runs",
        "assets",
        "runs",
        ["verified_run_id"],
        ["id"],
    )
    op.create_index("ix_assets_target_id_verified_run_id", "assets", ["target_id", "verified_run_id"])

    op.add_column("services", sa.Column("verified_run_id", sa.String(), nullable=True))
    op.create_foreign_key(
        "fk_services_verified_run_id_runs",
        "services",
        "runs",
        ["verified_run_id"],
        ["id"],
    )
    op.create_index("ix_services_target_id_verified_run_id", "services", ["target_id", "verified_run_id"])

    # Phase 6: schedules and jobs tables.
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default=sa.text("86400")),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("pipeline_config", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_schedules_target_id_enabled", "schedules", ["target_id", "enabled"])
    op.create_index("ix_schedules_next_run_at", "schedules", ["next_run_at"])

    op.create_table(
        "jobs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("available_at", sa.DateTime(), nullable=True),
        sa.Column("locked_at", sa.DateTime(), nullable=True),
        sa.Column("locked_by", sa.String(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_jobs_status_available_at", "jobs", ["status", "available_at"])
    op.create_index("ix_jobs_target_id_status", "jobs", ["target_id", "status"])
    op.create_index("ix_jobs_run_id", "jobs", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_run_id", table_name="jobs")
    op.drop_index("ix_jobs_target_id_status", table_name="jobs")
    op.drop_index("ix_jobs_status_available_at", table_name="jobs")
    op.drop_table("jobs")

    op.drop_index("ix_schedules_next_run_at", table_name="schedules")
    op.drop_index("ix_schedules_target_id_enabled", table_name="schedules")
    op.drop_table("schedules")

    op.drop_index("ix_services_target_id_verified_run_id", table_name="services")
    op.drop_constraint("fk_services_verified_run_id_runs", "services", type_="foreignkey")
    op.drop_column("services", "verified_run_id")

    op.drop_index("ix_assets_target_id_verified_run_id", table_name="assets")
    op.drop_constraint("fk_assets_verified_run_id_runs", "assets", type_="foreignkey")
    op.drop_column("assets", "verified_run_id")

