from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.analytics import ExposureSummaryRead, ExternalAssetsRead
from backend.services.exposure import exposure_summary
from backend.services.exposure import external_assets as external_assets_service

router = APIRouter(prefix="/exposure", tags=["attack surface and WAF"])


@router.get("/summary", response_model=ExposureSummaryRead)
def exposure(
    entity: str | None = None,
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    if entity is not None and entity not in {"Website", "Server"}:
        raise HTTPException(422, "entity must be Website or Server")
    return exposure_summary(session, entity=entity)


@router.get("/external-assets", response_model=ExternalAssetsRead)
def external_assets(user=Depends(current_user), session: Session = Depends(get_db)):
    return external_assets_service(session)
