"""Authenticated integration status, connection validation, and background sync APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import SERVICENOW_TABLES
from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.db.models import SyncRun
from backend.integrations.analyst_model import AnalystModelAdapter
from backend.integrations.base import IntegrationError
from backend.integrations.qualys import QualysAdapter
from backend.integrations.servicenow import ServiceNowAdapter
from backend.integrations.servicenow_tickets import ServiceNowTicketAdapter
from backend.integrations.threat_intel import ThreatIntelAdapter
from backend.schemas.integrations import (
    ConnectionTestRead,
    IntegrationStatusRead,
    SyncRunCreated,
    SyncRunPage,
)
from backend.schemas.tickets import ServiceNowTicketRequest, TicketLinkPage, TicketLinkRead
from backend.services.audit import record_event
from backend.services.tickets import (
    TicketConflict,
    TicketNotFound,
    TicketOutcomeUnknown,
    TicketProviderFailure,
    create_servicenow_ticket,
    list_tickets,
)
from backend.workers.integration_tasks import run_integration_sync

router = APIRouter(prefix="/integrations", tags=["integrations"])
ADAPTERS = {
    "qualys": ("Qualys VMDR", QualysAdapter),
    "servicenow": ("ServiceNow CMDB", ServiceNowAdapter),
    "threat_intel": ("CISA KEV and FIRST EPSS", ThreatIntelAdapter),
}


def _run_payload(run: SyncRun) -> dict:
    return {
        "id": run.id,
        "source": run.source,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "records_read": run.records_read,
        "records_written": run.records_written,
        "error": run.error,
    }


@router.get("/status", response_model=IntegrationStatusRead)
def status(user=Depends(current_user), session: Session = Depends(get_db)):
    recent = session.scalars(select(SyncRun).order_by(SyncRun.started_at.desc()).limit(20)).all()
    qualys = QualysAdapter()
    servicenow = ServiceNowAdapter()
    threat_intel = ThreatIntelAdapter()
    ticket_adapter = ServiceNowTicketAdapter()
    analyst_adapter = AnalystModelAdapter()
    return {
        "connectors": [
            {
                "id": "qualys",
                "name": "Qualys VMDR",
                "status": "configured" if qualys.configured else "unconfigured",
                "configured": qualys.configured,
                "capabilities": ["connection_test", "asset_sync", "finding_sync"],
            },
            {
                "id": "servicenow",
                "name": "ServiceNow CMDB",
                "status": "configured" if servicenow.configured else "unconfigured",
                "configured": servicenow.configured,
                "tables": list(SERVICENOW_TABLES),
                "capabilities": ["connection_test", "asset_sync"]
                + (["ticket_write"] if ticket_adapter.configured else []),
            },
            {
                "id": "threat_intel",
                "name": "CISA KEV and FIRST EPSS",
                "status": "configured" if threat_intel.configured else "unconfigured",
                "configured": threat_intel.configured,
                "capabilities": ["connection_test", "asset_sync", "finding_enrichment"],
            },
        ],
        "recentRuns": [_run_payload(run) for run in recent],
        "note": "Scanner, CMDB, and public threat-feed syncs are read-only. ServiceNow incident creation is separate, explicit, and requires ticket write access to be enabled. Credentials are deployment-managed and never returned by this API.",
        "ticketWriteConfigured": ticket_adapter.configured,
        "aiAnalystConfigured": analyst_adapter.configured,
    }


@router.post("/servicenow/tickets", response_model=TicketLinkRead)
def create_ticket(
    body: ServiceNowTicketRequest,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    try:
        return create_servicenow_ticket(
            session,
            finding_id=body.finding_id,
            business_impact=body.business_impact,
            idempotency_key=idempotency_key,
            actor=user,
        )
    except TicketNotFound:
        raise HTTPException(404, "Finding or linked asset was not found") from None
    except TicketConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except TicketOutcomeUnknown:
        raise HTTPException(
            409, "Provider outcome is uncertain; reconcile by SAM correlation ID before retrying"
        ) from None
    except TicketProviderFailure as exc:
        if exc.ambiguous:
            raise HTTPException(
                502, "Provider outcome is uncertain; use the same idempotency key to reconcile"
            ) from None
        if not exc.configured:
            raise HTTPException(503, "ServiceNow incident write access is not configured") from None
        raise HTTPException(502, "ServiceNow could not create or validate the incident") from None


@router.get("/servicenow/tickets", response_model=TicketLinkPage)
def service_now_tickets(
    finding_id: str = Query(min_length=1, max_length=150),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    return list_tickets(session, finding_id=finding_id, limit=limit)


@router.post("/{source}/test", response_model=ConnectionTestRead)
def test_connection(
    source: str,
    user=Depends(require_roles("admin", "security_admin")),
):
    adapter_entry = ADAPTERS.get(source)
    if not adapter_entry:
        raise HTTPException(404, "Unknown connector")
    try:
        return adapter_entry[1]().check_connection()
    except IntegrationError as exc:
        code = 503 if "not configured" in str(exc).lower() else 502
        raise HTTPException(code, str(exc)) from None


@router.post("/{source}/sync", status_code=202, response_model=SyncRunCreated)
def request_sync(
    source: str,
    user=Depends(require_roles("admin", "security_admin")),
    session: Session = Depends(get_db),
):
    adapter_entry = ADAPTERS.get(source)
    if not adapter_entry:
        raise HTTPException(404, "Unknown connector")
    adapter = adapter_entry[1]()
    if not adapter.configured:
        raise HTTPException(503, f"{adapter_entry[0]} is not configured")
    active_run = session.scalar(
        select(SyncRun.id)
        .where(SyncRun.source == source, SyncRun.status.in_(("queued", "running")))
        .limit(1)
    )
    if active_run:
        raise HTTPException(409, "A synchronization for this connector is already active")
    run = SyncRun(
        id=str(uuid.uuid4()),
        source=source,
        status="queued",
        started_at=datetime.now(UTC).isoformat(),
        records_read=0,
        records_written=0,
    )
    session.add(run)
    record_event(
        session, user, "integration.sync.requested", "sync_run", run.id, {"source": source}
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        concurrent_run = session.scalar(
            select(SyncRun.id)
            .where(SyncRun.source == source, SyncRun.status.in_(("queued", "running")))
            .limit(1)
        )
        if concurrent_run:
            raise HTTPException(
                409, "A synchronization for this connector is already active"
            ) from None
        raise HTTPException(500, "Synchronization request could not be recorded") from None
    try:
        task = run_integration_sync.delay(source, run.id)
        return {**_run_payload(run), "task_id": task.id}
    except Exception:
        session.rollback()
        failed_run = session.get(SyncRun, run.id)
        if failed_run:
            failed_run.status = "failed"
            failed_run.finished_at = datetime.now(UTC).isoformat()
            failed_run.error = "Background queue unavailable; sync was not started"
            record_event(
                session,
                user,
                "integration.sync.failed",
                "sync_run",
                failed_run.id,
                {"source": source, "error": failed_run.error},
            )
            session.commit()
        raise HTTPException(503, "Background queue unavailable; sync was not started") from None


@router.get("/runs", response_model=SyncRunPage)
def list_runs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    total = session.scalar(select(func.count()).select_from(SyncRun)) or 0
    rows = session.scalars(
        select(SyncRun).order_by(SyncRun.started_at.desc()).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_run_payload(run) for run in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
