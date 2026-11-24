from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.core.database import SessionLocal
from backend.db.models import AuditEvent, IdempotencyRecord
from backend.workers.tasks import prune_idempotency_records


def test_idempotency_retention_prunes_expired_and_abandoned_records():
    current = datetime.now(UTC)
    expired_key = "a" * 64
    abandoned_key = "b" * 64
    fresh_claim_key = "c" * 64
    recent_completed_key = "d" * 64
    with SessionLocal() as session:
        audit_event = AuditEvent(
            action="test.audit.retention",
            object_type="test",
            object_id="retained",
            detail="{}",
            created_at=current.isoformat(),
            previous_hash="",
            entry_hash="test-entry-hash",
        )
        session.add_all(
            [
                IdempotencyRecord(
                    key=expired_key,
                    operation="test.completed",
                    response_status=200,
                    response_body="{}",
                    created_at=(current - timedelta(days=8)).isoformat(),
                ),
                IdempotencyRecord(
                    key=abandoned_key,
                    operation="test.abandoned",
                    response_status=0,
                    response_body="{}",
                    created_at=(current - timedelta(minutes=31)).isoformat(),
                ),
                IdempotencyRecord(
                    key=fresh_claim_key,
                    operation="test.processing",
                    response_status=0,
                    response_body="{}",
                    created_at=current.isoformat(),
                ),
                IdempotencyRecord(
                    key=recent_completed_key,
                    operation="test.recent",
                    response_status=200,
                    response_body="{}",
                    created_at=current.isoformat(),
                ),
            ]
        )
        session.add(audit_event)
        session.commit()
        audit_event_id = audit_event.id

    result = prune_idempotency_records.run()

    assert result == {"deleted": 2}
    with SessionLocal() as session:
        remaining = set(session.scalars(select(IdempotencyRecord.key)).all())
        assert session.get(AuditEvent, audit_event_id) is not None
    assert remaining == {fresh_claim_key, recent_completed_key}
