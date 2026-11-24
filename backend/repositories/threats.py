"""Queries for recorded threat signals and vulnerability candidates."""

from sqlalchemy import case, exists, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding, FindingCVE, ZeroDaySignal


class ThreatRepository:
    def __init__(self, session: Session):
        self.session = session

    def signals(self) -> list[ZeroDaySignal]:
        return list(
            self.session.scalars(
                select(ZeroDaySignal).order_by(ZeroDaySignal.created_at.desc(), ZeroDaySignal.id)
            ).all()
        )

    def open_findings(self, *, no_cve_only: bool = False) -> list[tuple[Finding, Asset]]:
        query = (
            select(Finding, Asset)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.state.in_(("Open", "In Progress")))
            .order_by(
                case(
                    {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4},
                    value=Finding.severity,
                    else_=5,
                ),
                Finding.id,
            )
        )
        if no_cve_only:
            query = query.where(
                Finding.cve.is_(None),
                ~exists(select(FindingCVE.finding_id).where(FindingCVE.finding_id == Finding.id)),
            )
        return [(row[0], row[1]) for row in self.session.execute(query).all()]
