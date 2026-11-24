"""Persistence for ordered, tamper-evident audit events."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import AuditChainHead, AuditEvent, User


class AuditRepository:
    def __init__(self, session: Session):
        self.session = session

    def lock_chain_head(self) -> AuditChainHead:
        head = self.session.scalar(
            select(AuditChainHead).where(AuditChainHead.chain_name == "global").with_for_update()
        )
        if head is None:
            raise RuntimeError(
                "Audit chain head is missing; apply migrations before writing events"
            )
        return head

    def append(self, event: AuditEvent, head: AuditChainHead) -> None:
        self.session.add(event)
        self.session.flush()
        head.entry_hash = event.entry_hash

    def recent(self, *, limit: int) -> list[tuple[AuditEvent, str | None]]:
        query = (
            select(AuditEvent, User.email)
            .outerjoin(User, User.id == AuditEvent.user_id)
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        )
        return [(row[0], row[1]) for row in self.session.execute(query).all()]

    def all_ordered(self) -> list[AuditEvent]:
        return list(self.session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all())

    def chain_head(self) -> str:
        head = self.session.get(AuditChainHead, "global")
        return head.entry_hash if head else ""
