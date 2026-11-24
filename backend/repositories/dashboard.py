"""Database queries for the executive dashboard and risk prioritization views."""

from __future__ import annotations

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding


class DashboardRepository:
    def __init__(self, session: Session):
        self.session = session

    def summary(self, entity: str | None = None) -> dict:
        asset_filter = [Asset.kind == entity] if entity else []
        asset_count, average = self.session.execute(
            select(func.count(Asset.id), func.avg(Asset.compliance)).where(*asset_filter)
        ).one()
        severity_query = (
            select(Finding.severity, func.count(Finding.id))
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.state.in_(("Open", "In Progress")), *asset_filter)
            .group_by(Finding.severity)
        )
        severity_rows = self.session.execute(severity_query).all()
        by_severity: dict[str, int] = {row[0]: row[1] for row in severity_rows}
        website_total, protected_total = self.session.execute(
            select(
                func.count(Asset.id),
                func.coalesce(func.sum(case((Asset.waf == "Protected", 1), else_=0)), 0),
            ).where(Asset.kind == "Website")
        ).one()
        noncompliant = (
            self.session.scalar(
                select(func.count(Asset.id)).where(
                    Asset.compliance.is_not(None), Asset.compliance < 80, *asset_filter
                )
            )
            or 0
        )
        websites = (
            0
            if entity == "Server"
            else self.session.scalar(select(func.count(Asset.id)).where(Asset.kind == "Website"))
            or 0
        )
        servers = (
            0
            if entity == "Website"
            else self.session.scalar(select(func.count(Asset.id)).where(Asset.kind == "Server"))
            or 0
        )
        return {
            "assets": asset_count,
            "websites": websites,
            "servers": servers,
            "openFindings": sum(by_severity.values()),
            "bySeverity": by_severity,
            "compliancePercent": round(average or 0, 1),
            "nonCompliantAssets": noncompliant,
            "websitesWafProtected": protected_total,
            "websitesTotal": website_total,
        }

    def priority_rows(self, entity: str | None = None) -> list[tuple[Finding, Asset]]:
        query = (
            select(Finding, Asset)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.state.in_(("Open", "In Progress")))
        )
        if entity:
            query = query.where(Asset.kind == entity)
        return [(row[0], row[1]) for row in self.session.execute(query).all()]
