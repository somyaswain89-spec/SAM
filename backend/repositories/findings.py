from __future__ import annotations

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


class FindingRepository:
    def __init__(self, session: Session):
        self.session = session

    def list(
        self,
        *,
        severity=None,
        state=None,
        asset_id=None,
        sort="risk",
        direction="desc",
        limit=100,
        offset=0,
    ):
        conditions = []
        if severity:
            conditions.append(Finding.severity == severity)
        if state:
            conditions.append(Finding.state == state)
        if asset_id:
            conditions.append(Finding.asset_id == asset_id)
        total = (
            self.session.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
        )
        direction_fn = {"asc": lambda column: column.asc(), "desc": lambda column: column.desc()}[
            direction
        ]
        if sort == "risk":
            sort_expr = case(SEVERITY_ORDER, value=Finding.severity, else_=99)
        else:
            sort_expr = getattr(Finding, sort)
        statement = (
            select(
                Finding,
                Asset.name.label("asset_name"),
                Asset.kind.label("asset_kind"),
                Asset.criticality.label("asset_criticality"),
                Asset.classification,
            )
            .join(Asset, Asset.id == Finding.asset_id)
            .where(*conditions)
            .order_by(direction_fn(sort_expr), Finding.updated_at.desc(), Finding.id)
            .limit(limit)
            .offset(offset)
        )
        return self.session.execute(statement).all(), total

    def get(self, finding_id: str) -> Finding | None:
        return self.session.get(Finding, finding_id)

    def find_source_record(
        self, source: str, source_finding_id: str, asset_id: str
    ) -> Finding | None:
        statement = select(Finding).where(
            Finding.source == source,
            Finding.source_finding_id == source_finding_id,
            Finding.asset_id == asset_id,
        )
        return self.session.scalar(statement)
