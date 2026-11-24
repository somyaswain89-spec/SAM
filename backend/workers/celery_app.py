from celery import Celery
from celery.schedules import crontab

from backend.core.config import CELERY_TASK_ALWAYS_EAGER, REDIS_URL

celery_app = Celery(
    "sam",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "backend.workers.tasks",
        "backend.workers.import_tasks",
        "backend.workers.integration_tasks",
        "backend.workers.external_discovery_tasks",
        "backend.workers.discovery_schedule",
        "backend.workers.threat_intel_tasks",
    ],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_always_eager=CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=True,
    task_default_queue="sam",
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    task_default_retry_delay=15,
    task_max_retries=5,
    enable_utc=True,
    timezone="UTC",
    beat_schedule={
        "daily-threat-intelligence-refresh": {
            "task": "sam.schedule_daily_threat_intel_sync",
            "schedule": crontab(hour=2, minute=15),
        },
        "daily-idempotency-retention": {
            "task": "sam.prune_idempotency_records",
            "schedule": crontab(hour=3, minute=10),
        },
        "daily-authorized-external-discovery": {
            "task": "sam.schedule_daily_external_discovery",
            "schedule": crontab(hour=3, minute=45),
        },
    },
)
