"""Scoped SAM records used as context by the assistant service."""

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding


class AnalystRepository:
    def __init__(self, session: Session):
        self.session = session

    def assets(self, entity: str | None = None) -> list[Asset]:
        query = select(Asset).where(Asset.status != "Retired")
        if entity:
            query = query.where(Asset.kind == entity)
        return list(self.session.scalars(query.order_by(Asset.name, Asset.id).limit(25)).all())

    def asset_summary(self, entity: str | None = None) -> dict[str, int]:
        query = select(
            func.count(Asset.id),
            func.sum(case((Asset.kind == "Website", 1), else_=0)),
            func.sum(case((Asset.kind == "Server", 1), else_=0)),
            func.sum(case((Asset.status == "Quarantined", 1), else_=0)),
            func.sum(case((Asset.compliance.is_(None), 1), else_=0)),
            func.sum(case((Asset.compliance.is_not(None) & (Asset.compliance < 80), 1), else_=0)),
            func.sum(case(((Asset.kind == "Website") & (Asset.waf == "Protected"), 1), else_=0)),
            func.sum(case(((Asset.kind == "Website") & (Asset.waf == "Unknown"), 1), else_=0)),
            func.sum(case((Asset.classification == "External facing", 1), else_=0)),
            func.sum(case((Asset.classification == "Internal facing", 1), else_=0)),
        ).where(Asset.status != "Retired")
        if entity:
            query = query.where(Asset.kind == entity)
        row = self.session.execute(query).one()
        keys = (
            "totalAssets",
            "websites",
            "servers",
            "quarantined",
            "complianceUnknown",
            "complianceBelow80",
            "websitesWafProtected",
            "websitesWafUnknown",
            "externalFacing",
            "internalFacing",
        )
        return {key: int(value or 0) for key, value in zip(keys, row, strict=True)}

    def findings(self, entity: str | None = None, limit: int = 100) -> list[tuple[Finding, Asset]]:
        query = (
            select(Finding, Asset)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.state.in_(("Open", "In Progress")))
        )
        if entity:
            query = query.where(Asset.kind == entity)
        query = query.order_by(
            case(
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4},
                value=Finding.severity,
                else_=5,
            ),
            Finding.updated_at.desc(),
            Finding.id,
        ).limit(limit)
        return [(row[0], row[1]) for row in self.session.execute(query).all()]

    def open_finding_count(self, entity: str | None = None) -> int:
        query = (
            select(func.count(Finding.id))
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.state.in_(("Open", "In Progress")))
        )
        if entity:
            query = query.where(Asset.kind == entity)
        return self.session.scalar(query) or 0
