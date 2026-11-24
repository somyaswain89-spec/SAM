"""SQLAlchemy queries for authorized external-domain discovery records."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import DiscoveredExternalAsset, ExternalDiscoveryRun, ExternalDiscoveryTarget


class ExternalDiscoveryRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_target(self, target_id: str) -> ExternalDiscoveryTarget | None:
        return self.session.get(ExternalDiscoveryTarget, target_id)

    def target_for_domain(self, domain: str) -> ExternalDiscoveryTarget | None:
        return self.session.scalar(
            select(ExternalDiscoveryTarget).where(ExternalDiscoveryTarget.domain == domain)
        )

    def list_targets(self, limit: int, offset: int):
        total = self.session.scalar(select(func.count()).select_from(ExternalDiscoveryTarget)) or 0
        rows = self.session.scalars(
            select(ExternalDiscoveryTarget)
            .order_by(ExternalDiscoveryTarget.domain)
            .limit(limit)
            .offset(offset)
        ).all()
        return rows, total

    def active_run(self, target_id: str) -> ExternalDiscoveryRun | None:
        return self.session.scalar(
            select(ExternalDiscoveryRun)
            .where(
                ExternalDiscoveryRun.target_id == target_id,
                ExternalDiscoveryRun.status.in_(("queued", "running")),
            )
            .limit(1)
        )

    def get_run(self, run_id: str) -> ExternalDiscoveryRun | None:
        return self.session.get(ExternalDiscoveryRun, run_id)

    def list_runs(self, target_id: str | None, limit: int, offset: int):
        query = select(ExternalDiscoveryRun)
        count_query = select(func.count()).select_from(ExternalDiscoveryRun)
        if target_id:
            query = query.where(ExternalDiscoveryRun.target_id == target_id)
            count_query = count_query.where(ExternalDiscoveryRun.target_id == target_id)
        total = self.session.scalar(count_query) or 0
        rows = self.session.scalars(
            query.order_by(ExternalDiscoveryRun.started_at.desc(), ExternalDiscoveryRun.id)
            .limit(limit)
            .offset(offset)
        ).all()
        domains = {
            target.id: target.domain
            for target in self.session.scalars(select(ExternalDiscoveryTarget)).all()
        }
        return rows, total, domains

    def get_candidate(self, candidate_id: str) -> DiscoveredExternalAsset | None:
        return self.session.get(DiscoveredExternalAsset, candidate_id)

    def candidate_for_hostname(self, target_id: str, hostname: str):
        return self.session.scalar(
            select(DiscoveredExternalAsset).where(
                DiscoveredExternalAsset.target_id == target_id,
                DiscoveredExternalAsset.hostname == hostname,
            )
        )

    def list_candidates(self, target_id: str | None, status: str | None, limit: int, offset: int):
        query = select(DiscoveredExternalAsset)
        count_query = select(func.count()).select_from(DiscoveredExternalAsset)
        conditions = []
        if target_id:
            conditions.append(DiscoveredExternalAsset.target_id == target_id)
        if status:
            conditions.append(DiscoveredExternalAsset.status == status)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        total = self.session.scalar(count_query) or 0
        rows = self.session.scalars(
            query.order_by(
                DiscoveredExternalAsset.status,
                DiscoveredExternalAsset.last_seen_at.desc(),
                DiscoveredExternalAsset.hostname,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        targets = {
            target.id: target.domain
            for target in self.session.scalars(select(ExternalDiscoveryTarget)).all()
        }
        return rows, total, targets
