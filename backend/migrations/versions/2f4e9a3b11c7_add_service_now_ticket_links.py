"""add idempotent ServiceNow ticket references

Revision ID: 2f4e9a3b11c7
Revises: 288c01b5bbb6
Create Date: 2026-11-24 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "2f4e9a3b11c7"
down_revision = "288c01b5bbb6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ticket_links",
        sa.Column("id", sa.String(length=80), nullable=False),
        sa.Column("finding_id", sa.String(length=150), nullable=True),
        sa.Column("asset_id", sa.String(length=120), nullable=True),
        sa.Column("finding_ref", sa.String(length=150), nullable=False),
        sa.Column("asset_ref", sa.String(length=120), nullable=False),
        sa.Column("source", sa.String(length=40), server_default="servicenow", nullable=False),
        sa.Column("correlation_id", sa.String(length=40), nullable=False),
        sa.Column("idempotency_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("external_sys_id", sa.String(length=120), nullable=True),
        sa.Column("external_number", sa.String(length=80), nullable=True),
        sa.Column("status", sa.String(length=24), server_default="processing", nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("requested_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "status IN ('processing','created','failed','unknown')", name="ck_ticket_links_status"
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_id", name="uq_ticket_links_correlation"),
        sa.UniqueConstraint("idempotency_hash", name="uq_ticket_links_idempotency"),
    )
    op.create_index(
        "ix_ticket_links_finding_created", "ticket_links", ["finding_ref", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_ticket_links_finding_created", table_name="ticket_links")
    op.drop_table("ticket_links")
