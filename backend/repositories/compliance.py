"""Persisted asset compliance score queries."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset


class ComplianceRepository:
    def __init__(self, session: Session):
        self.session = session

    def scores(self, entity: str | None = None) -> list[int]:
        query = select(Asset.compliance).where(Asset.compliance.is_not(None))
        if entity:
            query = query.where(Asset.kind == entity)
        return [score for score in self.session.scalars(query).all() if score is not None]

    def unknown_count(self, entity: str | None = None) -> int:
        query = select(func.count(Asset.id)).where(Asset.compliance.is_(None))
        if entity:
            query = query.where(Asset.kind == entity)
        return self.session.scalar(query) or 0

    def assets(self, entity: str | None = None) -> list[Asset]:
        query = select(Asset)
        if entity:
            query = query.where(Asset.kind == entity)
        return list(self.session.scalars(query.order_by(Asset.compliance.asc(), Asset.id)).all())
