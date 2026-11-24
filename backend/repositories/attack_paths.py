"""Queries for recorded asset relationships and open-finding counts."""

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding


class AttackPathRepository:
    def __init__(self, session: Session):
        self.session = session

    def active_assets(self) -> list[Asset]:
        query = select(Asset).where(Asset.status != "Retired").order_by(Asset.id)
        return list(self.session.scalars(query).all())

    def open_risk_counts(self) -> dict[str, int]:
        query = (
            select(
                Finding.asset_id,
                func.sum(case((Finding.severity == "Critical", 1), else_=0)),
            )
            .where(Finding.state.in_(("Open", "In Progress")))
            .group_by(Finding.asset_id)
        )
        return {
            asset_id: int(critical or 0) for asset_id, critical in self.session.execute(query).all()
        }
