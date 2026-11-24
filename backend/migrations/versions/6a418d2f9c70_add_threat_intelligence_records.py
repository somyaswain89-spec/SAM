"""persist CISA KEV and FIRST EPSS snapshots

Revision ID: 6a418d2f9c70
Revises: 2f4e9a3b11c7
Create Date: 2026-11-24 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "6a418d2f9c70"
down_revision = "2f4e9a3b11c7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_records",
        sa.Column("cve", sa.String(length=40), nullable=False),
        sa.Column("kev_listed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("kev_catalog_version", sa.String(length=80), nullable=True),
        sa.Column("kev_date_added", sa.String(length=10), nullable=True),
        sa.Column("kev_due_date", sa.String(length=10), nullable=True),
        sa.Column("kev_vendor", sa.String(length=255), nullable=True),
        sa.Column("kev_product", sa.String(length=255), nullable=True),
        sa.Column("kev_vulnerability_name", sa.String(length=500), nullable=True),
        sa.Column("kev_short_description", sa.Text(), nullable=True),
        sa.Column("kev_required_action", sa.Text(), nullable=True),
        sa.Column("kev_ransomware_use", sa.String(length=32), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("epss_date", sa.String(length=10), nullable=True),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_threat_intel_epss_score",
        ),
        sa.CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)",
            name="ck_threat_intel_epss_percentile",
        ),
        sa.PrimaryKeyConstraint("cve"),
    )
    op.create_index(
        "ix_threat_intel_kev_epss", "threat_intel_records", ["kev_listed", "epss_score"]
    )


def downgrade() -> None:
    op.drop_index("ix_threat_intel_kev_epss", table_name="threat_intel_records")
    op.drop_table("threat_intel_records")
