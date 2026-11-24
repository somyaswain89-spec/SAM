"""add authorized passive external asset discovery

Revision ID: a4d8c2e79105
Revises: 9f4c8b2a6d11
Create Date: 2026-11-24
"""

import sqlalchemy as sa
from alembic import op

revision = "a4d8c2e79105"
down_revision = "9f4c8b2a6d11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_discovery_targets",
        sa.Column("id", sa.String(length=80), primary_key=True),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("authorization_note", sa.Text(), nullable=False),
        sa.Column("authorized_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.Column("last_run_at", sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(["authorized_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("domain", name="uq_external_discovery_targets_domain"),
    )
    op.create_index(
        "ix_external_discovery_targets_active_domain",
        "external_discovery_targets",
        ["active", "domain"],
    )

    op.create_table(
        "external_discovery_runs",
        sa.Column("id", sa.String(length=80), primary_key=True),
        sa.Column("target_id", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=False),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.Column("pages_read", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_read", sa.Integer(), server_default="0", nullable=False),
        sa.Column("candidates_created", sa.Integer(), server_default="0", nullable=False),
        sa.Column("candidates_updated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued','running','completed','failed')",
            name="ck_external_discovery_runs_status",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["external_discovery_targets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_external_discovery_runs_target_id", "external_discovery_runs", ["target_id"]
    )
    op.create_index("ix_external_discovery_runs_status", "external_discovery_runs", ["status"])
    op.create_index(
        "ix_external_discovery_runs_target_started",
        "external_discovery_runs",
        ["target_id", "started_at"],
    )
    op.create_index(
        "uq_external_discovery_runs_active_target",
        "external_discovery_runs",
        ["target_id"],
        unique=True,
        sqlite_where=sa.text("status IN ('queued', 'running')"),
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "discovered_external_assets",
        sa.Column("id", sa.String(length=80), primary_key=True),
        sa.Column("target_id", sa.String(length=80), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=24), server_default="pending_review", nullable=False),
        sa.Column("first_seen_at", sa.String(length=40), nullable=False),
        sa.Column("last_seen_at", sa.String(length=40), nullable=False),
        sa.Column("evidence", sa.Text(), server_default="{}", nullable=False),
        sa.Column("last_run_id", sa.String(length=80), nullable=True),
        sa.Column("asset_id", sa.String(length=120), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.String(length=40), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending_review','accepted','dismissed')",
            name="ck_discovered_external_assets_status",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["external_discovery_targets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["last_run_id"], ["external_discovery_runs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("target_id", "hostname", name="uq_discovered_external_target_hostname"),
    )
    op.create_index(
        "ix_discovered_external_assets_target_id", "discovered_external_assets", ["target_id"]
    )
    op.create_index(
        "ix_discovered_external_status_last_seen",
        "discovered_external_assets",
        ["status", "last_seen_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_discovered_external_status_last_seen", table_name="discovered_external_assets"
    )
    op.drop_index(
        "ix_discovered_external_assets_target_id", table_name="discovered_external_assets"
    )
    op.drop_table("discovered_external_assets")
    op.drop_index("uq_external_discovery_runs_active_target", table_name="external_discovery_runs")
    op.drop_index("ix_external_discovery_runs_target_started", table_name="external_discovery_runs")
    op.drop_index("ix_external_discovery_runs_status", table_name="external_discovery_runs")
    op.drop_index("ix_external_discovery_runs_target_id", table_name="external_discovery_runs")
    op.drop_table("external_discovery_runs")
    op.drop_index(
        "ix_external_discovery_targets_active_domain", table_name="external_discovery_targets"
    )
    op.drop_table("external_discovery_targets")
