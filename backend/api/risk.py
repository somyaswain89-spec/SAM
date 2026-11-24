from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.core.util import now
from backend.schemas.analytics import SLAForecastRead
from backend.services.dashboard import prioritize_findings

router = APIRouter(prefix="/risk", tags=["risk and SLA"])


@router.get("/sla-forecast", response_model=SLAForecastRead)
def sla_forecast(user=Depends(current_user), session: Session = Depends(get_db)):
    items = prioritize_findings(session, limit=500)["items"]
    breached = []
    at_risk = []
    for f in items:
        due = f.get("due_at")
        if not due:
            continue
        try:
            days = (
                datetime.fromisoformat(due.replace("Z", "+00:00")) - datetime.now(UTC)
            ).total_seconds() / 86400
        except ValueError:
            continue
        row = {
            "findingId": f["id"],
            "title": f["title"],
            "assetId": f["asset_id"],
            "dueAt": due,
            "daysRemaining": round(days, 1),
        }
        if days < 0:
            breached.append(row)
        elif days <= 7:
            at_risk.append(row)
    return {
        "breached": breached,
        "atRiskNext7Days": at_risk,
        "evaluatedAt": now(),
        "forecastMethod": "Due-date deterministic rule; no predictive model or assumed SLA is applied.",
    }
