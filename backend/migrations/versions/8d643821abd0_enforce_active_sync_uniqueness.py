"""enforce one active synchronization per integration source

Revision ID: 8d643821abd0
Revises: 7b204291fe13
Create Date: 2026-11-24 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "8d643821abd0"
down_revision = "7b204291fe13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Preserve the newest in-flight run if an older version raced across API instances.
    # Workers skip terminal run IDs after this migration, so queued stale messages are safe.
    op.execute(
        sa.text(
            """
            WITH ranked AS (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY source ORDER BY started_at DESC, id DESC
                ) AS active_rank
                FROM sync_runs
                WHERE status IN ('queued', 'running')
            )
            UPDATE sync_runs
            SET status = 'failed',
                finished_at = started_at,
                error = 'Superseded by the active-run uniqueness migration'
            WHERE id IN (SELECT id FROM ranked WHERE active_rank > 1)
            """
        )
    )
    op.create_index(
        "uq_sync_runs_active_source",
        "sync_runs",
        ["source"],
        unique=True,
        sqlite_where=sa.text("status IN ('queued', 'running')"),
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_sync_runs_active_source", table_name="sync_runs")
