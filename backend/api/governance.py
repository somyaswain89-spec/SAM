"""Governance, operational workflow, and approval-controlled containment routes."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.schemas.common import (
    ContainmentRequest,
    ExceptionCreate,
    ReviewDecision,
    WorkflowCreate,
)
from backend.schemas.governance import (
    ContainmentDecisionRead,
    ContainmentImpactRead,
    ContainmentPage,
    ContainmentRequestRead,
    ExceptionPage,
    ExceptionRead,
    WorkflowPage,
    WorkflowRead,
)
from backend.services.governance import (
    GovernanceConflict,
    GovernanceInvalid,
    GovernanceNotFound,
    create_exception,
    create_workflow,
    preview_containment_impact,
    request_containment,
    review_containment,
)
from backend.services.governance import (
    list_containment as list_containment_service,
)
from backend.services.governance import (
    list_exceptions as list_exceptions_service,
)
from backend.services.governance import (
    list_workflows as list_workflows_service,
)
from backend.services.governance import (
    review_exception as review_exception_service,
)
from backend.services.idempotency import IdempotencyConflict, execute_idempotently

router = APIRouter(prefix="", tags=["governance and response"])


@router.get("/containment/impact/{asset_id}", response_model=ContainmentImpactRead)
def containment_impact_preview(
    asset_id: str,
    action: Literal["Quarantine", "Release"] = Query("Quarantine"),
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return preview_containment_impact(session, asset_id, action)
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None


@router.post("/exceptions", status_code=201, response_model=ExceptionRead)
def request_exception(
    body: ExceptionCreate,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="governance.exception.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=201,
            execute=lambda: create_exception(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except GovernanceInvalid as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/exceptions", response_model=ExceptionPage)
def list_exceptions(
    state: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    requested_by = None if user["role"] in {"admin", "security_admin", "auditor"} else user["id"]
    items, total = list_exceptions_service(session, state, limit, offset, requested_by)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/exceptions/{eid}/review", response_model=ExceptionRead)
def review_exception(
    eid: str,
    body: ReviewDecision,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="governance.exception.review",
            idempotency_key=idempotency_key,
            request_payload={"exception_id": eid, **body.model_dump(mode="json")},
            response_status=200,
            execute=lambda: review_exception_service(session, eid, body.decision, body.note, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except GovernanceConflict as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/workflows", status_code=201, response_model=WorkflowRead)
def create_workflow_route(
    body: WorkflowCreate,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="governance.workflow.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=201,
            execute=lambda: create_workflow(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except GovernanceInvalid as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/workflows", response_model=WorkflowPage)
def list_workflows(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    requested_by = None if user["role"] in {"admin", "security_admin", "auditor"} else user["id"]
    items, total = list_workflows_service(session, limit, offset, requested_by)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/containment/requests", status_code=202, response_model=ContainmentRequestRead)
def containment(
    body: ContainmentRequest,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="governance.containment.request",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=202,
            execute=lambda: request_containment(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except GovernanceConflict as exc:
        raise HTTPException(409, str(exc)) from None


@router.get("/containment/requests", response_model=ContainmentPage)
def list_containment(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    requested_by = None if user["role"] in {"admin", "security_admin", "auditor"} else user["id"]
    items, total = list_containment_service(session, limit, offset, requested_by)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "executionEnabled": False,
    }


@router.post("/containment/requests/{action_id}/decision", response_model=ContainmentDecisionRead)
def decide_containment(
    action_id: str,
    body: ReviewDecision,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="governance.containment.review",
            idempotency_key=idempotency_key,
            request_payload={"containment_id": action_id, **body.model_dump(mode="json")},
            response_status=200,
            execute=lambda: review_containment(session, action_id, body.decision, body.note, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GovernanceNotFound as exc:
        raise HTTPException(404, str(exc)) from None
    except GovernanceConflict as exc:
        raise HTTPException(409, str(exc)) from None
