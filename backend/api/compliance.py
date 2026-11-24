from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.analytics import ComplianceAssetsRead, ComplianceSummaryRead
from backend.services.compliance import compliance_assets as compliance_assets_service
from backend.services.compliance import compliance_summary

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _validate_entity(entity: str | None) -> None:
    if entity is not None and entity not in {"Website", "Server"}:
        raise HTTPException(422, "entity must be Website or Server")


@router.get("/summary", response_model=ComplianceSummaryRead)
def summary(
    entity: str | None = None,
    target: int = Query(90, ge=1, le=100),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    _validate_entity(entity)
    return compliance_summary(session, entity=entity, target=target)


@router.get("/assets", response_model=ComplianceAssetsRead)
def compliance_assets(
    entity: str | None = None,
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    _validate_entity(entity)
    return compliance_assets_service(session, entity=entity)
