"""Persisted asset exposure and WAF posture queries."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding


class ExposureRepository:
    def __init__(self, session: Session):
        self.session = session

    def classification_counts(self, entity: str | None = None) -> list[dict]:
        query = (
            select(Asset.classification, Asset.kind, func.count(Asset.id))
            .where(Asset.status != "Retired")
            .group_by(Asset.classification, Asset.kind)
        )
        if entity:
            query = query.where(Asset.kind == entity)
        return [
            {"classification": classification, "kind": kind, "n": count}
            for classification, kind, count in self.session.execute(query).all()
        ]

    def waf_counts(self) -> list[dict]:
        query = (
            select(Asset.waf, func.count(Asset.id))
            .where(Asset.kind == "Website", Asset.status != "Retired")
            .group_by(Asset.waf)
        )
        return [{"waf": waf, "n": count} for waf, count in self.session.execute(query).all()]

    def external_assets(self) -> list[tuple[Asset, int]]:
        open_states = ("Open", "In Progress")
        query = (
            select(Asset, func.count(Finding.id))
            .outerjoin(
                Finding,
                (Finding.asset_id == Asset.id) & (Finding.state.in_(open_states)),
            )
            .where(Asset.classification == "External facing", Asset.status != "Retired")
            .group_by(Asset.id)
            .order_by(Asset.criticality.asc(), func.count(Finding.id).desc(), Asset.id)
        )
        return [(asset, int(count)) for asset, count in self.session.execute(query).all()]
