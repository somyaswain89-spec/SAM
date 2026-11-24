"""Celery task for remote source synchronization."""

from __future__ import annotations

from celery.utils.log import get_task_logger

from backend.core.database import SessionLocal
from backend.db.models import SyncRun
from backend.integrations.base import IntegrationError
from backend.services.audit import record_event
from backend.services.integrations import run_sync
from backend.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="sam.sync_integration", max_retries=5)
def run_integration_sync(self, source: str, run_id: str) -> dict:
    session = SessionLocal()
    try:
        result = run_sync(session, source, run_id)
        logger.info(
            "integration_sync_task_finished",
            extra={
                "source": source,
                "run_id": run_id,
                "records_read": result["records_read"],
                "records_written": result["records_written"],
                "status": result["status"],
            },
        )
        return result
    except IntegrationError as exc:
        logger.warning(
            "integration_sync_failed",
            extra={"source": source, "run_id": run_id, "status_code": exc.status_code},
        )
        transient = exc.status_code is None or exc.status_code in {429, 500, 502, 503, 504}
        if transient and self.request.retries < self.max_retries:
            run = session.get(SyncRun, run_id)
            if run is not None and run.status == "failed":
                run.status = "queued"
                run.finished_at = None
                run.error = None
                record_event(
                    session,
                    None,
                    "integration.sync.retrying",
                    "sync_run",
                    run.id,
                    {"source": source, "attempt": self.request.retries + 1},
                )
                session.commit()
            raise self.retry(exc=exc, countdown=min(300, 2 ** (self.request.retries + 1))) from exc
        raise
    except Exception:
        logger.exception(
            "integration_sync_unexpected_failure", extra={"source": source, "run_id": run_id}
        )
        raise
    finally:
        session.close()
