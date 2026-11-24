"""normalize multi-CVE finding references

Revision ID: 7b204291fe13
Revises: 6a418d2f9c70
Create Date: 2026-11-24 00:00:00.000000
"""

import json
import re

import sqlalchemy as sa
from alembic import context, op

revision = "7b204291fe13"
down_revision = "6a418d2f9c70"
branch_labels = None
depends_on = None

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _cves(primary: str | None, evidence: str | None) -> set[str]:
    candidates = [primary]
    try:
        decoded = json.loads(evidence or "{}")
    except (json.JSONDecodeError, TypeError):
        decoded = {}
    if isinstance(decoded, dict) and isinstance(decoded.get("cves"), list):
        candidates.extend(decoded["cves"])
    return {
        value.strip().upper()
        for value in candidates
        if isinstance(value, str) and _CVE_PATTERN.fullmatch(value.strip())
    }


def _backfill_offline(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            """
            INSERT INTO finding_cves (finding_id, cve)
            SELECT id, upper(trim(cve))
            FROM findings
            WHERE cve IS NOT NULL AND upper(trim(cve)) ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
            ON CONFLICT DO NOTHING
            """
        )
        op.execute(
            """
            INSERT INTO finding_cves (finding_id, cve)
            SELECT f.id, upper(trim(item.value))
            FROM findings AS f
            CROSS JOIN LATERAL jsonb_array_elements_text(
              CASE
                WHEN pg_input_is_valid(f.evidence, 'jsonb') THEN
                  CASE
                    WHEN jsonb_typeof(f.evidence::jsonb -> 'cves') = 'array'
                    THEN f.evidence::jsonb -> 'cves'
                    ELSE '[]'::jsonb
                  END
                ELSE '[]'::jsonb
              END
            ) AS item(value)
            WHERE upper(trim(item.value)) ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
            ON CONFLICT DO NOTHING
            """
        )
        return
    if dialect == "sqlite":
        op.execute(
            """
            INSERT OR IGNORE INTO finding_cves (finding_id, cve)
            SELECT id, upper(trim(cve))
            FROM findings
            WHERE cve IS NOT NULL
              AND upper(trim(cve)) GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'
              AND substr(upper(trim(cve)), 10) NOT GLOB '*[^0-9]*'
            """
        )
        op.execute(
            """
            INSERT OR IGNORE INTO finding_cves (finding_id, cve)
            SELECT f.id, upper(trim(item.value))
            FROM findings AS f,
              json_each(
                CASE
                  WHEN json_valid(f.evidence) THEN
                    CASE
                      WHEN json_type(f.evidence, '$.cves') = 'array'
                      THEN json_extract(f.evidence, '$.cves')
                      ELSE '[]'
                    END
                  ELSE '[]'
                END
              ) AS item
            WHERE upper(trim(item.value)) GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'
              AND substr(upper(trim(item.value)), 10) NOT GLOB '*[^0-9]*'
            """
        )
        return
    raise RuntimeError(f"Offline CVE backfill is unsupported for {dialect}")


def upgrade() -> None:
    op.create_table(
        "finding_cves",
        sa.Column("finding_id", sa.String(length=150), nullable=False),
        sa.Column("cve", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id", "cve"),
    )
    op.create_index("ix_finding_cves_cve", "finding_cves", ["cve"])

    if context.is_offline_mode():
        _backfill_offline(context.get_context().dialect.name)
        return

    connection = op.get_bind()
    findings = sa.table(
        "findings",
        sa.column("id", sa.String),
        sa.column("cve", sa.String),
        sa.column("evidence", sa.Text),
    )
    links = sa.table(
        "finding_cves",
        sa.column("finding_id", sa.String),
        sa.column("cve", sa.String),
    )
    batch: list[dict[str, str]] = []
    result = connection.execution_options(stream_results=True).execute(
        sa.select(findings.c.id, findings.c.cve, findings.c.evidence)
    )
    for finding_id, primary, evidence in result:
        batch.extend({"finding_id": finding_id, "cve": cve} for cve in _cves(primary, evidence))
        if len(batch) >= 1000:
            op.bulk_insert(links, batch)
            batch.clear()
    if batch:
        op.bulk_insert(links, batch)


def downgrade() -> None:
    op.drop_index("ix_finding_cves_cve", table_name="finding_cves")
    op.drop_table("finding_cves")
