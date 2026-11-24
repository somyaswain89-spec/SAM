from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import require_roles
from backend.schemas.audit import AuditEventPage, AuditVerification
from backend.services.audit import audit_events, verify_audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditEventPage)
def events(
    limit: int = Query(100, ge=1, le=1000),
    user=Depends(require_roles("admin", "security_admin", "auditor")),
    session: Session = Depends(get_db),
):
    return audit_events(session, limit=limit)


@router.get("/verify", response_model=AuditVerification)
def verify_chain(
    user=Depends(require_roles("admin", "security_admin", "auditor")),
    session: Session = Depends(get_db),
):
    return verify_audit_chain(session)
