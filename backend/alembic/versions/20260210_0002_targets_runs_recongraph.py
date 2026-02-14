"""Targets, runs, recongraph-lite tables; link sessions/scans/findings.

Revision ID: 20260210_0002
Revises: 20260210_0001
Create Date: 2026-02-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260210_0002"
down_revision = "20260210_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("root_domain", sa.String(), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("root_domain", name="uq_targets_root_domain"),
    )
    op.create_index("ix_targets_created_at", "targets", ["created_at"])

    op.create_table(
        "runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("trigger", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_runs_target_id_created_at", "runs", ["target_id", "created_at"])

    # Phase 0: sessions -> target_id
    op.add_column("sessions", sa.Column("target_id", sa.String(), nullable=True))
    op.create_foreign_key(
        "fk_sessions_target_id_targets",
        "sessions",
        "targets",
        ["target_id"],
        ["id"],
    )
    op.create_index("ix_sessions_target_id_created_at", "sessions", ["target_id", "created_at"])

    # Scans: add target_id, run_id
    op.add_column("scans", sa.Column("target_id", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("run_id", sa.String(), nullable=True))
    op.create_foreign_key(
        "fk_scans_target_id_targets",
        "scans",
        "targets",
        ["target_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_scans_run_id_runs",
        "scans",
        "runs",
        ["run_id"],
        ["id"],
    )
    op.create_index("ix_scans_target_id_created_at", "scans", ["target_id", "created_at"])
    op.create_index("ix_scans_run_id_created_at", "scans", ["run_id", "created_at"])

    # ReconGraph-lite: assets/services/edges
    op.create_table(
        "assets",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized", sa.Text(), nullable=False),
        sa.Column("first_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("last_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("target_id", "type", "normalized", name="uq_assets_target_type_normalized"),
    )
    op.create_index("ix_assets_target_id_type_normalized", "assets", ["target_id", "type", "normalized"])
    op.create_index("ix_assets_target_id_last_seen_at", "assets", ["target_id", "last_seen_at"])

    op.create_table(
        "services",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("proto", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("first_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("last_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("target_id", "asset_id", "port", "proto", name="uq_services_target_asset_port_proto"),
    )
    op.create_index("ix_services_target_asset_port_proto", "services", ["target_id", "asset_id", "port", "proto"])
    op.create_index("ix_services_target_id_last_seen_at", "services", ["target_id", "last_seen_at"])

    op.create_table(
        "edges",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_id", sa.String(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("from_asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("to_asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("rel_type", sa.String(), nullable=False),
        sa.Column("first_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("last_seen_run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_edges_target_rel", "edges", ["target_id", "rel_type"])
    op.create_index("ix_edges_target_from_to", "edges", ["target_id", "from_asset_id", "to_asset_id"])

    # Findings: add columns needed by current code + link to target/run/assets/services.
    op.add_column("findings", sa.Column("impact", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("remediation_example", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("target_id", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("run_id", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("asset_id", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("service_id", sa.String(), nullable=True))

    op.create_foreign_key(
        "fk_findings_target_id_targets",
        "findings",
        "targets",
        ["target_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_findings_run_id_runs",
        "findings",
        "runs",
        ["run_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_findings_asset_id_assets",
        "findings",
        "assets",
        ["asset_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_findings_service_id_services",
        "findings",
        "services",
        ["service_id"],
        ["id"],
    )

    op.create_index("ix_findings_target_id_created_at", "findings", ["target_id", "created_at"])
    op.create_index("ix_findings_run_id_created_at", "findings", ["run_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_findings_run_id_created_at", table_name="findings")
    op.drop_index("ix_findings_target_id_created_at", table_name="findings")

    op.drop_constraint("fk_findings_service_id_services", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_asset_id_assets", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_run_id_runs", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_target_id_targets", "findings", type_="foreignkey")

    op.drop_column("findings", "service_id")
    op.drop_column("findings", "asset_id")
    op.drop_column("findings", "run_id")
    op.drop_column("findings", "target_id")
    op.drop_column("findings", "remediation_example")
    op.drop_column("findings", "impact")

    op.drop_index("ix_edges_target_from_to", table_name="edges")
    op.drop_index("ix_edges_target_rel", table_name="edges")
    op.drop_table("edges")

    op.drop_index("ix_services_target_id_last_seen_at", table_name="services")
    op.drop_index("ix_services_target_asset_port_proto", table_name="services")
    op.drop_table("services")

    op.drop_index("ix_assets_target_id_last_seen_at", table_name="assets")
    op.drop_index("ix_assets_target_id_type_normalized", table_name="assets")
    op.drop_table("assets")

    op.drop_index("ix_scans_run_id_created_at", table_name="scans")
    op.drop_index("ix_scans_target_id_created_at", table_name="scans")
    op.drop_constraint("fk_scans_run_id_runs", "scans", type_="foreignkey")
    op.drop_constraint("fk_scans_target_id_targets", "scans", type_="foreignkey")
    op.drop_column("scans", "run_id")
    op.drop_column("scans", "target_id")

    op.drop_index("ix_sessions_target_id_created_at", table_name="sessions")
    op.drop_constraint("fk_sessions_target_id_targets", "sessions", type_="foreignkey")
    op.drop_column("sessions", "target_id")

    op.drop_index("ix_runs_target_id_created_at", table_name="runs")
    op.drop_table("runs")

    op.drop_index("ix_targets_created_at", table_name="targets")
    op.drop_table("targets")
