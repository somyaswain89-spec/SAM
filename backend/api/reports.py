from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user
from backend.core.util import now
from backend.schemas.analytics import ExecutiveReportRead
from backend.services.compliance import compliance_summary
from backend.services.dashboard import dashboard_summary
from backend.services.findings import list_findings as list_findings_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/executive", response_model=ExecutiveReportRead)
def executive(user=Depends(current_user), session: Session = Depends(get_db)):
    top_findings, _ = list_findings_service(
        session, sort="risk", direction="desc", limit=10, offset=0
    )
    return {
        "reportType": "Executive security posture",
        "generatedAt": now(),
        "dashboard": dashboard_summary(session),
        "compliance": compliance_summary(session, target=90),
        "topFindings": top_findings,
    }
