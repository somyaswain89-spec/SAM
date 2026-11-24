from __future__ import annotations

import hashlib
import json
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.core.util import now
from backend.db.models import ImportJob
from backend.schemas.imports import ImportJobAccepted, ImportJobPage, ImportJobRead
from backend.services.file_processing import inspect_headers, sanitize_filename, validate_mapping
from backend.services.idempotency import (
    IdempotencyConflict,
    request_digest,
    scoped_idempotency_hash,
)

logger = logging.getLogger("sam.imports")
router = APIRouter(prefix="/imports", tags=["file imports"])
MAX_CHUNK = 64 * 1024


def _remove_staging(path: Path) -> None:
    path.unlink(missing_ok=True)
    try:
        path.parent.rmdir()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("staging_directory_cleanup_failed", extra={"error_type": type(exc).__name__})


async def _store_upload(upload: UploadFile, destination: Path) -> tuple[int, str]:
    size = 0
    first = b""
    digest = hashlib.sha256()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        with temporary.open("wb") as target:
            while chunk := await upload.read(MAX_CHUNK):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Upload exceeds configured size limit")
                if destination.suffix.lower() == ".csv" and b"\x00" in chunk:
                    raise HTTPException(415, "File content is not valid text CSV")
                if len(first) < 8:
                    first += chunk[: 8 - len(first)]
                digest.update(chunk)
                target.write(chunk)
        if destination.suffix.lower() == ".xlsx" and not first.startswith(b"PK\x03\x04"):
            raise HTTPException(415, "File content does not match an XLSX workbook")
        if destination.suffix.lower() == ".csv" and b"\x00" in first:
            raise HTTPException(415, "File content is not valid text CSV")
        temporary.replace(destination)
        return size, digest.hexdigest()
    except Exception:
        temporary.unlink(missing_ok=True)
        destination.unlink(missing_ok=True)
        raise


def _job_json(job: ImportJob) -> dict:
    errors = []
    if job.error_summary:
        try:
            errors = json.loads(job.error_summary)
        except ValueError:
            errors = [{"error": "Job error details could not be decoded"}]
    return {
        "id": job.id,
        "jobType": job.job_type,
        "source": job.source,
        "status": job.status,
        "filename": job.filename,
        "totalRows": job.total_rows,
        "processedRows": job.processed_rows,
        "rejectedRows": job.rejected_rows,
        "errors": errors,
        "createdAt": job.created_at,
        "updatedAt": job.updated_at,
        "downloadAvailable": bool(job.result_path and Path(job.result_path).is_file()),
    }


def _idempotent_job(session: Session, key_hash: str, request_hash: str) -> ImportJob | None:
    job = session.scalar(select(ImportJob).where(ImportJob.idempotency_hash == key_hash))
    if job is not None and job.request_hash != request_hash:
        raise IdempotencyConflict("Idempotency key was already used with different input")
    return job


def _job_response(job: ImportJob) -> dict:
    return {"job": _job_json(job), "statusUrl": f"/api/v1/imports/jobs/{job.id}"}


def _can_access(job: ImportJob, user: dict) -> bool:
    return job.created_by == user["id"] or user["role"] in {"admin", "security_admin", "auditor"}


@router.post("/assets", status_code=202, response_model=ImportJobAccepted)
async def upload_assets(
    file: UploadFile = File(...),
    column_mapping: str = Form(...),
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    try:
        mapping = validate_mapping(column_mapping)
        filename = sanitize_filename(file.filename or "")
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(422, str(exc)) from None
    extension = Path(filename).suffix.lower()
    accepted_mime = {
        ".csv": {
            "text/csv",
            "application/csv",
            "application/vnd.ms-excel",
            "text/plain",
            "application/octet-stream",
        },
        ".xlsx": {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/octet-stream",
        },
    }
    if extension not in accepted_mime or (
        file.content_type and file.content_type not in accepted_mime[extension]
    ):
        raise HTTPException(415, "Upload a CSV or XLSX file with a matching content type")
    staging_path = UPLOAD_DIR / "staging" / uuid.uuid4().hex / filename
    try:
        _, file_hash = await _store_upload(file, staging_path)
    except HTTPException:
        _remove_staging(staging_path)
        raise
    try:
        headers = inspect_headers(staging_path)
        missing = sorted(set(mapping.values()) - set(headers))
        if missing:
            raise HTTPException(
                422, "Mapped columns are missing from the uploaded file: " + ", ".join(missing)
            )
    except HTTPException:
        _remove_staging(staging_path)
        raise
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        _remove_staging(staging_path)
        raise HTTPException(422, "The uploaded file could not be safely parsed") from None
    key_hash = scoped_idempotency_hash(user["id"], "imports.assets", idempotency_key)
    request_hash = request_digest(
        {"filename": filename, "mapping": mapping, "file_sha256": file_hash}
    )
    try:
        existing = _idempotent_job(session, key_hash, request_hash)
    except IdempotencyConflict as exc:
        _remove_staging(staging_path)
        raise HTTPException(409, str(exc)) from None
    if existing is not None:
        _remove_staging(staging_path)
        return _job_response(existing)

    job_id = "IMP-" + uuid.uuid4().hex
    destination = UPLOAD_DIR / "imports" / job_id / filename
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging_path.replace(destination)
    _remove_staging(staging_path)
    stamp = now()
    job = ImportJob(
        id=job_id,
        source="file_upload",
        job_type="import",
        status="queued",
        filename=filename,
        input_path=str(destination),
        column_mapping=json.dumps(mapping),
        created_by=user["id"],
        idempotency_hash=key_hash,
        request_hash=request_hash,
        created_at=stamp,
        updated_at=stamp,
    )
    session.add(job)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        destination.unlink(missing_ok=True)
        try:
            existing = _idempotent_job(session, key_hash, request_hash)
        except IdempotencyConflict as exc:
            raise HTTPException(409, str(exc)) from None
        if existing is not None:
            return _job_response(existing)
        raise HTTPException(409, "Import job conflicts with an existing record") from None
    except Exception:
        session.rollback()
        destination.unlink(missing_ok=True)
        raise
    try:
        from backend.workers.import_tasks import process_asset_import

        result = process_asset_import.delay(job_id)
        job.task_id = result.id
        session.commit()
    except Exception:
        job.status = "failed"
        job.input_path = None
        job.error_summary = json.dumps(
            [{"error": "Background queue is unavailable; the import was not processed"}]
        )
        job.updated_at = now()
        session.commit()
        destination.unlink(missing_ok=True)
        logger.exception("import_queue_unavailable", extra={"job_id": job_id})
        raise HTTPException(
            503, "Import queue is unavailable; no asset data was imported"
        ) from None
    return _job_response(job)


@router.get("/jobs", response_model=ImportJobPage)
def list_jobs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    query = select(ImportJob).order_by(ImportJob.created_at.desc())
    count_query = select(func.count()).select_from(ImportJob)
    if user["role"] not in {"admin", "security_admin", "auditor"}:
        owner_filter = ImportJob.created_by == user["id"]
        query = query.where(owner_filter)
        count_query = count_query.where(owner_filter)
    rows = session.scalars(query.limit(limit).offset(offset)).all()
    total = session.scalar(count_query) or 0
    return {
        "items": [_job_json(job) for job in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/jobs/{job_id}", response_model=ImportJobRead)
def get_job(job_id: str, user=Depends(current_user), session: Session = Depends(get_db)):
    job = session.get(ImportJob, job_id)
    if job is None or not _can_access(job, user):
        raise HTTPException(404, "Job not found")
    return _job_json(job)


@router.get(
    "/jobs/{job_id}/download",
    response_class=FileResponse,
    responses={
        200: {
            "description": "Generated CSV or job error report",
            "content": {
                "text/csv": {"schema": {"type": "string", "format": "binary"}},
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}},
            },
        }
    },
)
def download_job_file(job_id: str, user=Depends(current_user), session: Session = Depends(get_db)):
    job = session.get(ImportJob, job_id)
    if job is None or not _can_access(job, user):
        raise HTTPException(404, "Job not found")
    path_value = job.result_path
    if not path_value or job.status not in {"completed", "completed_with_errors"}:
        raise HTTPException(409, "Job output is not available")
    path = Path(path_value).resolve()
    root = UPLOAD_DIR.resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(404, "Job output not found")
    media_type = "text/csv" if path.suffix.lower() == ".csv" else "application/octet-stream"
    download_name = (
        f"{Path(job.filename).stem}.errors.csv" if job.job_type == "import" else job.filename
    )
    return FileResponse(path, media_type=media_type, filename=download_name)


exports_router = APIRouter(prefix="/exports", tags=["file exports"])


@exports_router.post("/assets", status_code=202, response_model=ImportJobAccepted)
def create_asset_export(
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst", "auditor")),
    session: Session = Depends(get_db),
):
    from backend.core.config import UPLOAD_DIR
    from backend.workers.import_tasks import process_asset_export

    key_hash = scoped_idempotency_hash(user["id"], "exports.assets", idempotency_key)
    request_hash = request_digest({"export": "assets", "format": "csv", "version": 1})
    try:
        existing = _idempotent_job(session, key_hash, request_hash)
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    if existing is not None:
        return _job_response(existing)

    job_id = "EXP-" + uuid.uuid4().hex
    folder = UPLOAD_DIR / "exports"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = folder / f"{job_id}.csv"
    stamp = now()
    job = ImportJob(
        id=job_id,
        source="asset_inventory",
        job_type="export",
        status="queued",
        filename="sam-assets.csv",
        result_path=str(output),
        created_by=user["id"],
        idempotency_hash=key_hash,
        request_hash=request_hash,
        created_at=stamp,
        updated_at=stamp,
    )
    session.add(job)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        try:
            existing = _idempotent_job(session, key_hash, request_hash)
        except IdempotencyConflict as exc:
            raise HTTPException(409, str(exc)) from None
        if existing is not None:
            return _job_response(existing)
        raise HTTPException(409, "Export job conflicts with an existing record") from None
    try:
        result = process_asset_export.delay(job_id)
        job.task_id = result.id
        session.commit()
    except Exception:
        job.status = "failed"
        job.error_summary = json.dumps(
            [{"error": "Background queue is unavailable; the export was not created"}]
        )
        job.updated_at = now()
        session.commit()
        raise HTTPException(503, "Export queue is unavailable; no export was created") from None
    return _job_response(job)
