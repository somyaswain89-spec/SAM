from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.schemas.common import FindingCreate, FindingRead, FindingState, PageResponse
from backend.services.findings import FindingNotFound, update_finding_state
from backend.services.findings import list_findings as list_findings_service
from backend.services.findings import upsert_finding as upsert_finding_service
from backend.services.idempotency import IdempotencyConflict, execute_idempotently

router = APIRouter(prefix="/findings", tags=["vulnerability management"])


@router.get("", response_model=PageResponse[FindingRead])
def list_findings(
    severity: str | None = None,
    state: str | None = None,
    asset_id: str | None = None,
    sort: str = "risk",
    direction: str = "desc",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    if sort not in {"risk", "first_seen", "due_at", "updated_at"} or direction not in {
        "asc",
        "desc",
    }:
        raise HTTPException(422, "Unsupported sort")
    items, total = list_findings_service(
        session,
        severity=severity,
        state=state,
        asset_id=asset_id,
        sort=sort,
        direction=direction,
        limit=limit,
        offset=offset,
    )
    return {
        "items": items,
        "total": total,
        "sort": sort,
        "direction": direction,
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201, response_model=FindingRead)
def create_finding(
    body: FindingCreate,
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
            operation="findings.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=201,
            execute=lambda: upsert_finding_service(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except IntegrityError:
        raise HTTPException(422, "Asset or finding reference does not exist") from None


@router.patch("/{finding_id}/state", response_model=FindingRead)
def set_state(
    finding_id: str,
    body: FindingState | None = None,
    state: str | None = None,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    target = body.state if body else state
    if target not in {"Open", "In Progress", "Resolved", "Accepted Risk"}:
        raise HTTPException(422, "A valid finding state is required")
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="findings.state",
            idempotency_key=idempotency_key,
            request_payload={"finding_id": finding_id, "state": target},
            response_status=200,
            execute=lambda: update_finding_state(session, finding_id, target, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except FindingNotFound:
        raise HTTPException(404, "Finding not found") from None
