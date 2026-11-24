from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import delete, or_
from sqlalchemy.engine import CursorResult

from backend.core.config import IDEMPOTENCY_RETENTION_DAYS
from backend.core.database import SessionLocal
from backend.db.models import IdempotencyRecord
from backend.workers.celery_app import celery_app


@celery_app.task(name="sam.healthcheck")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@celery_app.task(name="sam.prune_idempotency_records")
def prune_idempotency_records() -> dict[str, int]:
    """Bound idempotency storage while preserving the configured replay period."""
    current = datetime.now(UTC)
    completed_cutoff = (current - timedelta(days=IDEMPOTENCY_RETENTION_DAYS)).isoformat()
    abandoned_cutoff = (current - timedelta(minutes=30)).isoformat()
    with SessionLocal() as session:
        result = cast(
            CursorResult,
            session.execute(
                delete(IdempotencyRecord).where(
                    or_(
                        (IdempotencyRecord.response_status > 0)
                        & (IdempotencyRecord.created_at < completed_cutoff),
                        (IdempotencyRecord.response_status == 0)
                        & (IdempotencyRecord.created_at < abandoned_cutoff),
                    )
                )
            ),
        )
        session.commit()
        return {"deleted": result.rowcount or 0}
