"""SQLAlchemy queries for approvals, operational workflows, and containment requests."""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, ContainmentAction, ExceptionRequest, Finding, WorkflowRequest


class GovernanceRepository:
    def __init__(self, session: Session):
        self.session = session

    def asset(self, asset_id: str) -> Asset | None:
        return self.session.get(Asset, asset_id)

    def finding(self, finding_id: str) -> Finding | None:
        return self.session.get(Finding, finding_id)

    def finding_for_asset(self, finding_id: str, asset_id: str) -> Finding | None:
        return self.session.scalar(
            select(Finding).where(Finding.id == finding_id, Finding.asset_id == asset_id)
        )

    def add_exception(self, item: ExceptionRequest) -> None:
        self.session.add(item)
        self.session.flush()

    def pending_exception(self, item_id: str) -> ExceptionRequest | None:
        return self.session.scalar(
            select(ExceptionRequest)
            .where(ExceptionRequest.id == item_id, ExceptionRequest.status == "Pending")
            .with_for_update()
        )

    def list_exceptions(
        self,
        state: str | None,
        limit: int,
        offset: int,
        requested_by: int | None = None,
    ):
        query = select(ExceptionRequest, Asset.name.label("asset_name")).join(
            Asset, Asset.id == ExceptionRequest.asset_id
        )
        count_query = select(func.count()).select_from(ExceptionRequest)
        if requested_by is not None:
            owner_filter = ExceptionRequest.requested_by == requested_by
            query = query.where(owner_filter)
            count_query = count_query.where(owner_filter)
        if state:
            query = query.where(ExceptionRequest.status == state)
            count_query = count_query.where(ExceptionRequest.status == state)
        rows = self.session.execute(
            query.order_by(ExceptionRequest.created_at.desc(), ExceptionRequest.id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self.session.scalar(count_query) or 0
        return rows, total

    def add_workflow(self, item: WorkflowRequest) -> None:
        self.session.add(item)
        self.session.flush()

    def list_workflows(self, limit: int, offset: int, requested_by: int | None = None):
        query = select(WorkflowRequest).order_by(
            WorkflowRequest.created_at.desc(), WorkflowRequest.id
        )
        count_query = select(func.count()).select_from(WorkflowRequest)
        if requested_by is not None:
            owner_filter = WorkflowRequest.requested_by == requested_by
            query = query.where(owner_filter)
            count_query = count_query.where(owner_filter)
        rows = self.session.scalars(query.limit(limit).offset(offset)).all()
        total = self.session.scalar(count_query) or 0
        return rows, total

    def dependent_assets(self, asset_id: str) -> list[str]:
        assets = self.session.scalars(select(Asset).where(Asset.status != "Retired")).all()
        dependent_names: list[str] = []
        for asset in assets:
            if asset.id == asset_id:
                continue
            try:
                dependencies = json.loads(asset.attributes or "{}").get("depends_on", [])
            except (TypeError, ValueError):
                continue
            if isinstance(dependencies, list) and asset_id in dependencies:
                dependent_names.append(asset.name)
        return sorted(dependent_names)

    def add_containment(self, item: ContainmentAction) -> None:
        self.session.add(item)
        self.session.flush()

    def pending_containment(self, item_id: str) -> ContainmentAction | None:
        return self.session.scalar(
            select(ContainmentAction)
            .where(
                ContainmentAction.id == item_id,
                ContainmentAction.status == "Approval required",
            )
            .with_for_update()
        )

    def list_containment(self, limit: int, offset: int, requested_by: int | None = None):
        query = select(ContainmentAction).order_by(
            ContainmentAction.created_at.desc(), ContainmentAction.id
        )
        count_query = select(func.count()).select_from(ContainmentAction)
        if requested_by is not None:
            owner_filter = ContainmentAction.requested_by == requested_by
            query = query.where(owner_filter)
            count_query = count_query.where(owner_filter)
        rows = self.session.scalars(query.limit(limit).offset(offset)).all()
        total = self.session.scalar(count_query) or 0
        return rows, total
