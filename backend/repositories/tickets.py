"""ServiceNow ticket operation persistence."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import Finding, TicketLink


class TicketRepository:
    def __init__(self, session: Session):
        self.session = session

    def finding(self, finding_id: str) -> Finding | None:
        return self.session.scalar(
            select(Finding).where(Finding.id == finding_id).with_for_update()
        )

    def by_idempotency_hash(self, idempotency_hash: str) -> TicketLink | None:
        return self.session.scalar(
            select(TicketLink)
            .where(TicketLink.idempotency_hash == idempotency_hash)
            .with_for_update()
        )

    def by_finding(self, finding_id: str, *, limit: int = 100) -> list[TicketLink]:
        query = (
            select(TicketLink)
            .where(TicketLink.finding_ref == finding_id)
            .order_by(TicketLink.created_at.desc(), TicketLink.id)
            .limit(limit)
        )
        return list(self.session.scalars(query).all())
