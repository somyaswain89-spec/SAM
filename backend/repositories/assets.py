from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from backend.db.models import Asset


class AssetRepository:
    def __init__(self, session: Session):
        self.session = session

    def list(
        self,
        *,
        entity=None,
        classification=None,
        status=None,
        query=None,
        sort="name",
        direction="asc",
        limit=100,
        offset=0,
    ):
        conditions = []
        if entity:
            conditions.append(Asset.kind == entity)
        if classification:
            conditions.append(Asset.classification == classification)
        if status:
            conditions.append(Asset.status == status)
        if query:
            match = f"%{query}%"
            conditions.append(
                or_(Asset.name.ilike(match), Asset.id.ilike(match), Asset.owner.ilike(match))
            )
        total = self.session.scalar(select(func.count()).select_from(Asset).where(*conditions)) or 0
        column = getattr(Asset, sort)
        order = column.asc() if direction == "asc" else column.desc()
        rows = self.session.scalars(
            select(Asset).where(*conditions).order_by(order, Asset.id).limit(limit).offset(offset)
        ).all()
        return rows, total

    def get(self, asset_id: str) -> Asset | None:
        return self.session.scalar(
            select(Asset).options(selectinload(Asset.findings)).where(Asset.id == asset_id)
        )

    def add(self, asset: Asset) -> Asset:
        self.session.add(asset)
        self.session.flush()
        return asset

    def update(self, asset: Asset, values: dict) -> Asset:
        for key, value in values.items():
            setattr(asset, key, value)
        self.session.flush()
        return asset
