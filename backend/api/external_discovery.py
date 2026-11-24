"""Authorized passive discovery, durable run tracking, and analyst-reviewed asset intake."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.db.models import ExternalDiscoveryRun
from backend.integrations.certspotter import CertSpotterAdapter
from backend.schemas.exposure import (
    DiscoveredExternalAssetPage,
    DiscoveredExternalAssetRead,
    ExternalAssetReview,
    ExternalDiscoveryRunCreated,
    ExternalDiscoveryRunPage,
    ExternalDiscoveryStatusRead,
    ExternalDiscoveryTargetActiveUpdate,
    ExternalDiscoveryTargetCreate,
    ExternalDiscoveryTargetPage,
    ExternalDiscoveryTargetRead,
)
from backend.services.audit import record_event
from backend.services.external_discovery import (
    DiscoveryConflict,
    DiscoveryNotFound,
    create_run,
    create_target,
    list_candidates,
    list_runs,
    list_targets,
    review_candidate,
    set_target_active,
)
from backend.services.idempotency import IdempotencyConflict, execute_idempotently
from backend.workers.external_discovery_tasks import run_external_discovery

router = APIRouter(prefix="/exposure/discovery", tags=["authorized external discovery"])
IDEMPOTENCY_HEADER = Header(
    ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
)


def _run_read(run: ExternalDiscoveryRun, domain: str) -> dict:
    return {
        "id": run.id,
        "target_id": run.target_id,
        "domain": domain,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "pages_read": run.pages_read,
        "records_read": run.records_read,
        "candidates_created": run.candidates_created,
        "candidates_updated": run.candidates_updated,
        "error": run.error,
    }


@router.get("/targets", response_model=ExternalDiscoveryTargetPage)
def get_targets(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    items, total = list_targets(session, limit, offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/status", response_model=ExternalDiscoveryStatusRead)
def discovery_status(user=Depends(current_user)):
    return {
        "provider": "SSLMate Cert Spotter",
        "configured": CertSpotterAdapter().configured,
        "method": "passive_certificate_transparency",
        "behavior": "Reads public certificate-transparency issuance records only; SAM does not contact discovered hosts.",
    }


@router.post("/targets", status_code=201, response_model=ExternalDiscoveryTargetRead)
def add_target(
    body: ExternalDiscoveryTargetCreate,
    idempotency_key: str = IDEMPOTENCY_HEADER,
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="exposure.discovery.target.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=201,
            execute=lambda: create_target(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except DiscoveryConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except IntegrityError:
        raise HTTPException(409, "A discovery target already exists for this domain") from None


@router.patch("/targets/{target_id}", response_model=ExternalDiscoveryTargetRead)
def update_target(
    target_id: str,
    body: ExternalDiscoveryTargetActiveUpdate,
    idempotency_key: str = IDEMPOTENCY_HEADER,
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="exposure.discovery.target.update",
            idempotency_key=idempotency_key,
            request_payload={"target_id": target_id, **body.model_dump(mode="json")},
            response_status=200,
            execute=lambda: set_target_active(
                session,
                target_id,
                body.active,
                user,
                body.authorization_note,
                body.authorization_confirmed,
            ),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except DiscoveryNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except DiscoveryConflict as exc:
        raise HTTPException(409, str(exc)) from None


@router.post(
    "/targets/{target_id}/runs", status_code=202, response_model=ExternalDiscoveryRunCreated
)
def start_discovery(
    target_id: str,
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    adapter = CertSpotterAdapter()
    if not adapter.configured:
        raise HTTPException(503, "Cert Spotter API credentials are not configured")
    try:
        run_data = create_run(session, target_id, user)
        session.commit()
    except DiscoveryNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except DiscoveryConflict as exc:
        session.rollback()
        raise HTTPException(409, str(exc)) from None
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "Discovery is already running for this domain") from None

    try:
        task = run_external_discovery.delay(run_data["id"])
        run = session.get(ExternalDiscoveryRun, run_data["id"])
        if run is None:
            raise RuntimeError("Discovery run disappeared after it was queued")
        if not task.id:
            raise RuntimeError("Background queue did not return a task identifier")
        return {**_run_read(run, run_data["domain"]), "task_id": task.id}
    except Exception:
        session.rollback()
        run = session.get(ExternalDiscoveryRun, run_data["id"])
        if run is not None:
            run.status = "failed"
            run.finished_at = datetime.now(UTC).isoformat()
            run.error = "Background queue unavailable; discovery was not started"
            record_event(
                session,
                user,
                "exposure.discovery.run.failed",
                "external_discovery_run",
                run.id,
                {"error": run.error},
            )
            session.commit()
        raise HTTPException(
            503, "Background queue unavailable; discovery was not started"
        ) from None


@router.get("/runs", response_model=ExternalDiscoveryRunPage)
def get_runs(
    target_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    items, total = list_runs(session, target_id, limit, offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/candidates", response_model=DiscoveredExternalAssetPage)
def get_candidates(
    target_id: str | None = None,
    status: str | None = Query(None, pattern=r"^(pending_review|accepted|dismissed)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    items, total = list_candidates(session, target_id, status, limit, offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/candidates/{candidate_id}/review", response_model=DiscoveredExternalAssetRead)
def decide_candidate(
    candidate_id: str,
    body: ExternalAssetReview,
    idempotency_key: str = IDEMPOTENCY_HEADER,
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="exposure.discovery.candidate.review",
            idempotency_key=idempotency_key,
            request_payload={"candidate_id": candidate_id, **body.model_dump(mode="json")},
            response_status=200,
            execute=lambda: review_candidate(session, candidate_id, body.decision, body.note, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except DiscoveryNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except DiscoveryConflict as exc:
        raise HTTPException(409, str(exc)) from None
