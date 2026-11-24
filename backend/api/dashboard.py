from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.analytics import DashboardRead, RiskPriorityResponse
from backend.services.dashboard import dashboard_summary, prioritize_findings

router = APIRouter(prefix="", tags=["dashboard and risk"])


def _validate_entity(entity: str | None) -> None:
    if entity is not None and entity not in {"Website", "Server"}:
        raise HTTPException(422, "entity must be Website or Server")


@router.get("/dashboard", response_model=DashboardRead)
def dashboard(
    entity: str | None = None,
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    _validate_entity(entity)
    return dashboard_summary(session, entity)


@router.get("/risk/priorities", response_model=RiskPriorityResponse)
def priorities(
    entity: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    _validate_entity(entity)
    return prioritize_findings(session, entity=entity, limit=limit)
