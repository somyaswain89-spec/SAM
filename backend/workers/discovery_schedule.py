"""Daily scheduler for explicitly authorized passive-discovery targets."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from backend.core.database import SessionLocal
from backend.db.models import ExternalDiscoveryRun, ExternalDiscoveryTarget
from backend.integrations.certspotter import CertSpotterAdapter
from backend.services.audit import record_event
from backend.services.external_discovery import DiscoveryConflict, create_run
from backend.workers.celery_app import celery_app
from backend.workers.external_discovery_tasks import run_external_discovery

logger = logging.getLogger("sam.discovery.schedule")


def enqueue_daily_discoveries() -> dict:
    if not CertSpotterAdapter().configured:
        return {"status": "skipped", "reason": "Cert Spotter credentials are not configured"}

    session = SessionLocal()
    queued = 0
    skipped = 0
    try:
        target_ids = session.scalars(
            select(ExternalDiscoveryTarget.id)
            .where(ExternalDiscoveryTarget.active.is_(True))
            .order_by(ExternalDiscoveryTarget.domain)
        ).all()
        for target_id in target_ids:
            try:
                run_data = create_run(session, target_id, None, trigger="daily_schedule")
                session.commit()
            except (DiscoveryConflict, IntegrityError, SQLAlchemyError):
                session.rollback()
                skipped += 1
                logger.info("daily_external_discovery_skipped", extra={"target_id": target_id})
                continue
            try:
                run_external_discovery.delay(run_data["id"])
                queued += 1
            except Exception:
                session.rollback()
                run = session.get(ExternalDiscoveryRun, run_data["id"])
                if run is not None:
                    run.status = "failed"
                    run.finished_at = datetime.now(UTC).isoformat()
                    run.error = "Background queue unavailable; scheduled discovery was not started"
                    record_event(
                        session,
                        None,
                        "exposure.discovery.run.failed",
                        "external_discovery_run",
                        run.id,
                        {"error": run.error, "trigger": "daily_schedule"},
                    )
                    session.commit()
                skipped += 1
                logger.exception(
                    "daily_external_discovery_queue_failed", extra={"run_id": run_data["id"]}
                )
        return {"status": "completed", "queued": queued, "skipped": skipped}
    finally:
        session.close()


@celery_app.task(name="sam.schedule_daily_external_discovery")
def schedule_daily_external_discovery() -> dict:
    return enqueue_daily_discoveries()
