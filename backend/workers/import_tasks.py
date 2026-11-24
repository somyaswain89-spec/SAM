from __future__ import annotations

import csv
import json
from pathlib import Path

from celery.utils.log import get_task_logger
from pydantic import ValidationError
from sqlalchemy import select

from backend.core.config import UPLOAD_DIR
from backend.core.database import SessionLocal
from backend.core.util import now
from backend.db.models import Asset, ImportJob
from backend.services.audit import record_event
from backend.services.file_processing import load_rows, parse_asset_row
from backend.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(
    bind=True,
    name="sam.process_asset_import",
    autoretry_for=(OSError,),
    retry_backoff=True,
    max_retries=5,
)
def process_asset_import(self, job_id: str) -> dict:
    session = SessionLocal()
    source_path = None
    try:
        job = session.get(ImportJob, job_id)
        if job is None or job.job_type != "import" or not job.input_path:
            return {"status": "missing"}
        job.status = "running"
        job.task_id = self.request.id
        job.updated_at = now()
        session.commit()
        source_path = Path(job.input_path).resolve()
        root = Path(job.input_path).parents[2].resolve()
        if root not in source_path.parents:
            raise ValueError("Import path is outside managed upload storage")
        mapping = json.loads(job.column_mapping)
        seen: set[str] = set()
        errors: list[dict] = []
        processed = 0
        rejected = 0
        for line_number, row in load_rows(source_path):
            try:
                values = parse_asset_row(row, mapping)
                if values.id in seen:
                    raise ValueError("Duplicate asset ID in the uploaded file")
                seen.add(values.id)
                existing = session.get(Asset, values.id)
                if existing is not None:
                    if existing.source != f"file:{job.id}":
                        raise ValueError("Asset ID already exists in SAM")
                    # A retried worker may encounter rows committed by an earlier batch.
                    # Treat those as completed for this immutable import job.
                    processed += 1
                else:
                    asset = Asset(
                        id=values.id,
                        name=values.name,
                        kind=values.kind,
                        classification=values.classification,
                        owner=values.owner,
                        environment=values.environment,
                        criticality=values.criticality,
                        compliance=values.compliance,
                        status="Active",
                        waf=values.waf,
                        source=f"file:{job.id}",
                        attributes=json.dumps(values.attributes),
                        created_at=now(),
                        updated_at=now(),
                    )
                    session.add(asset)
                    session.flush()
                    record_event(
                        session,
                        {"id": job.created_by} if job.created_by else None,
                        "asset.import",
                        "asset",
                        values.id,
                        {"job_id": job.id, "row": line_number},
                    )
                    processed += 1
            except (ValueError, TypeError, ValidationError) as exc:
                rejected += 1
                if len(errors) < 1000:
                    if isinstance(exc, ValidationError):
                        description = (
                            "Invalid asset fields; check required fields, types, and ranges"
                        )
                    elif str(exc) in {
                        "Duplicate asset ID in the uploaded file",
                        "Asset ID already exists in SAM",
                    }:
                        description = str(exc)
                    else:
                        description = "Invalid or unsupported field value"
                    errors.append({"row": line_number, "error": description})
            if (processed + rejected) % 100 == 0:
                job.processed_rows = processed + rejected
                job.rejected_rows = rejected
                job.updated_at = now()
                session.commit()
        job.status = "completed_with_errors" if rejected else "completed"
        job.total_rows = processed + rejected
        job.processed_rows = processed + rejected
        job.rejected_rows = rejected
        job.error_summary = json.dumps(errors, ensure_ascii=False)
        if errors:
            report_path = source_path.with_name(f"{source_path.stem}.errors.csv")
            with report_path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["row", "error"])
                writer.writeheader()
                writer.writerows(errors)
            job.result_path = str(report_path)
        job.updated_at = now()
        job.input_path = None
        session.commit()
        source_path.unlink(missing_ok=True)
        logger.info(
            "asset_import_complete",
            extra={"job_id": job.id, "processed": processed, "rejected": rejected},
        )
        return {"status": job.status, "processed": processed, "rejected": rejected}
    except Exception as exc:
        session.rollback()
        job = session.get(ImportJob, job_id)
        retry_pending = isinstance(exc, OSError) and self.request.retries < self.max_retries
        if job:
            job.status = "queued" if retry_pending else "failed"
            if not retry_pending:
                job.error_summary = json.dumps(
                    [{"error": "Import failed due to an unexpected processing error"}]
                )
            job.updated_at = now()
            if not retry_pending:
                job.input_path = None
            session.commit()
        if source_path and not retry_pending:
            source_path.unlink(missing_ok=True)
        logger.exception("asset_import_failed", extra={"job_id": job_id})
        raise
    finally:
        session.close()


@celery_app.task(
    bind=True,
    name="sam.process_asset_export",
    autoretry_for=(OSError,),
    retry_backoff=True,
    max_retries=5,
)
def process_asset_export(self, job_id: str) -> dict:
    session = SessionLocal()
    try:
        job = session.get(ImportJob, job_id)
        if job is None or job.job_type != "export":
            return {"status": "missing"}
        job.status = "running"
        job.task_id = self.request.id
        job.updated_at = now()
        session.commit()
        assets = session.scalars(select(Asset).order_by(Asset.id)).all()
        path = Path(job.result_path or "").resolve()
        export_root = (UPLOAD_DIR / "exports").resolve()
        if export_root not in path.parents:
            raise ValueError("Export path is outside managed export storage")
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=[
                    "id",
                    "name",
                    "kind",
                    "classification",
                    "owner",
                    "environment",
                    "criticality",
                    "compliance",
                    "status",
                    "waf",
                ],
            )
            writer.writeheader()
            for asset in assets:
                row = {key: getattr(asset, key) for key in writer.fieldnames}
                for key, value in row.items():
                    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                        row[key] = "'" + value
                writer.writerow(row)
        job.status = "completed"
        job.total_rows = len(assets)
        job.processed_rows = len(assets)
        job.updated_at = now()
        session.commit()
        return {"status": job.status, "rows": len(assets)}
    except Exception:
        session.rollback()
        job = session.get(ImportJob, job_id)
        if job:
            job.status = "failed"
            job.error_summary = json.dumps(
                [{"error": "Export failed due to an unexpected processing error"}]
            )
            job.updated_at = now()
            session.commit()
        logger.exception("asset_export_failed", extra={"job_id": job_id})
        raise
    finally:
        session.close()
