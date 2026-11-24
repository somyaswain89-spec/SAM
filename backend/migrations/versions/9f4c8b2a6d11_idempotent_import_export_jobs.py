"""add idempotency references to import and export jobs

Revision ID: 9f4c8b2a6d11
Revises: 8d643821abd0
Create Date: 2026-11-24 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "9f4c8b2a6d11"
down_revision = "8d643821abd0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("import_jobs", sa.Column("idempotency_hash", sa.String(length=64)))
    op.add_column("import_jobs", sa.Column("request_hash", sa.String(length=64)))
    op.create_index("uq_import_jobs_idempotency", "import_jobs", ["idempotency_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_import_jobs_idempotency", table_name="import_jobs")
    op.drop_column("import_jobs", "request_hash")
    op.drop_column("import_jobs", "idempotency_hash")
