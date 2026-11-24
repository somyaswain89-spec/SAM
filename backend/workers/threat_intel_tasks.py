"""Daily schedule for persisted CISA KEV and FIRST EPSS feed refreshes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from celery.utils.log import get_task_logger
from sqlalchemy import select

from backend.core.database import SessionLocal
from backend.db.models import SyncRun
from backend.services.audit import record_event
from backend.workers.celery_app import celery_app
from backend.workers.integration_tasks import run_integration_sync

logger = get_task_logger(__name__)


def enqueue_daily_threat_intel_sync() -> dict:
    session = SessionLocal()
    try:
        active_run = session.scalar(
            select(SyncRun.id)
            .where(SyncRun.source == "threat_intel", SyncRun.status.in_(("queued", "running")))
            .limit(1)
        )
        if active_run:
            return {"status": "skipped", "reason": "sync already active", "run_id": active_run}

        run = SyncRun(
            id=str(uuid.uuid4()),
            source="threat_intel",
            status="queued",
            started_at=datetime.now(UTC).isoformat(),
            records_read=0,
            records_written=0,
        )
        session.add(run)
        record_event(
            session,
            None,
            "integration.sync.requested",
            "sync_run",
            run.id,
            {"source": "threat_intel", "trigger": "daily_schedule"},
        )
        session.commit()
        try:
            task = run_integration_sync.delay("threat_intel", run.id)
        except Exception:
            session.rollback()
            failed_run = session.get(SyncRun, run.id)
            if failed_run:
                failed_run.status = "failed"
                failed_run.finished_at = datetime.now(UTC).isoformat()
                failed_run.error = "Background queue unavailable; scheduled sync was not started"
                record_event(
                    session,
                    None,
                    "integration.sync.failed",
                    "sync_run",
                    failed_run.id,
                    {"source": "threat_intel", "error": failed_run.error},
                )
                session.commit()
            logger.error("daily_threat_intel_queue_failed", extra={"run_id": run.id})
            return {"status": "failed", "run_id": run.id}
        return {"status": "queued", "run_id": run.id, "task_id": task.id}
    finally:
        session.close()


@celery_app.task(name="sam.schedule_daily_threat_intel_sync")
def schedule_daily_threat_intel_sync() -> dict:
    return enqueue_daily_threat_intel_sync()
