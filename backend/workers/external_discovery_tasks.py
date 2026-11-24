"""Celery task and retry policy for passive domain discovery."""

from __future__ import annotations

from datetime import UTC, datetime

from celery.utils.log import get_task_logger

from backend.core.database import SessionLocal
from backend.db.models import ExternalDiscoveryRun
from backend.integrations.base import IntegrationError
from backend.services.audit import record_event
from backend.services.external_discovery import run_discovery
from backend.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="sam.run_external_discovery", max_retries=4)
def run_external_discovery(self, run_id: str) -> dict:
    session = SessionLocal()
    try:
        result = run_discovery(session, run_id)
        logger.info(
            "external_discovery_finished",
            extra={"run_id": run_id, "status": result.get("status")},
        )
        return result
    except IntegrationError as exc:
        run = session.get(ExternalDiscoveryRun, run_id)
        transient = exc.status_code is None or exc.status_code in {429, 500, 502, 503, 504}
        if transient and self.request.retries < self.max_retries:
            if run is not None:
                run.status = "queued"
                run.finished_at = None
                run.error = None
                run.pages_read = 0
                run.records_read = 0
                run.candidates_created = 0
                run.candidates_updated = 0
                record_event(
                    session,
                    {"id": run.requested_by} if run.requested_by else None,
                    "exposure.discovery.run.retrying",
                    "external_discovery_run",
                    run.id,
                    {"attempt": self.request.retries + 1, "status_code": exc.status_code},
                )
                session.commit()
            raise self.retry(exc=exc, countdown=min(300, 2 ** (self.request.retries + 1))) from exc
        logger.warning(
            "external_discovery_failed",
            extra={"run_id": run_id, "status_code": exc.status_code},
        )
        raise
    except Exception:
        logger.exception("external_discovery_unexpected_failure", extra={"run_id": run_id})
        run = session.get(ExternalDiscoveryRun, run_id)
        if run is not None and run.status in {"queued", "running"}:
            run.status = "failed"
            run.finished_at = datetime.now(UTC).isoformat()
            run.error = "Unexpected discovery worker error; consult protected server logs"
            record_event(
                session,
                {"id": run.requested_by} if run.requested_by else None,
                "exposure.discovery.run.failed",
                "external_discovery_run",
                run.id,
                {"error": run.error},
            )
            session.commit()
        raise
    finally:
        session.close()
