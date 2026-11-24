from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.schemas.common import AssetType
from backend.schemas.threat_intel import ThreatIntelPage
from backend.schemas.threats import ZeroDaySignalsRead
from backend.services.threat_intel import list_threat_intelligence
from backend.services.threats import zero_day_signals

router = APIRouter(prefix="/threats", tags=["threat intelligence"])


@router.get("/zero-day-signals", response_model=ZeroDaySignalsRead)
def list_signals(user=Depends(current_user), session: Session = Depends(get_db)):
    return zero_day_signals(session)


@router.get("/intelligence", response_model=ThreatIntelPage)
def list_intelligence(
    entity: AssetType | None = None,
    cve: str | None = Query(None, min_length=1, max_length=40, pattern=r"^[A-Za-z0-9-]+$"),
    kev_only: bool = False,
    min_epss: float | None = Query(None, ge=0, le=1),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    return list_threat_intelligence(
        session,
        entity=entity,
        cve=cve,
        kev_only=kev_only,
        min_epss=min_epss,
        limit=limit,
        offset=offset,
    )
