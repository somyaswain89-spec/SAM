"""Idempotent, audited ticket creation and provider outcome reconciliation."""

from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.util import now
from backend.db.models import Asset, Finding, TicketLink
from backend.integrations.base import IntegrationError
from backend.integrations.servicenow_tickets import ServiceNowIncident, ServiceNowTicketAdapter
from backend.repositories.tickets import TicketRepository
from backend.services.audit import record_event


class TicketNotFound(Exception):
    pass


class TicketConflict(Exception):
    pass


class TicketOutcomeUnknown(Exception):
    pass


class TicketProviderFailure(Exception):
    def __init__(self, *, status_code: int | None, ambiguous: bool, configured: bool = True):
        self.status_code = status_code
        self.ambiguous = ambiguous
        self.configured = configured


def serialize_ticket(ticket: TicketLink) -> dict:
    return {
        "id": ticket.id,
        "finding_id": ticket.finding_ref,
        "asset_id": ticket.asset_ref,
        "source": ticket.source,
        "status": ticket.status,
        "external_sys_id": ticket.external_sys_id,
        "external_number": ticket.external_number,
        "correlation_id": ticket.correlation_id,
        "error_code": ticket.error_code,
        "created_at": ticket.created_at,
        "updated_at": ticket.updated_at,
    }


def _impact_urgency(severity: str) -> tuple[int, int]:
    values = {
        "Critical": (1, 1),
        "High": (2, 1),
        "Medium": (2, 2),
        "Low": (3, 3),
        "Informational": (3, 3),
    }
    return values.get(severity, (3, 3))


def _description(finding: Finding, asset: Asset, business_impact: str) -> str:
    fields = [
        "Created by SAM vulnerability management.",
        f"SAM finding: {finding.id}",
        f"Asset: {asset.name} ({asset.id})",
        f"Severity: {finding.severity}",
        f"CVE: {finding.cve or 'Not recorded'}",
        f"Due date: {finding.due_at or 'Not recorded'}",
        f"Finding: {finding.title}",
        "Business impact supplied by the requester:",
        business_impact.strip(),
    ]
    return "\n".join(part.replace("\x00", " ") for part in fields)


def _apply_provider_reference(
    session: Session, ticket: TicketLink, incident: ServiceNowIncident, actor: dict
) -> None:
    ticket.status = "created"
    ticket.external_sys_id = incident.sys_id
    ticket.external_number = incident.number
    ticket.error_code = None
    ticket.updated_at = now()
    record_event(
        session,
        actor,
        "ticket.provider_created",
        "ticket_link",
        ticket.id,
        {"source": ticket.source, "external_number": incident.number},
    )
    session.commit()


def _reconcile_unknown(
    session: Session, ticket: TicketLink, actor: dict, adapter: ServiceNowTicketAdapter
) -> dict:
    try:
        incident = adapter.find_by_correlation(ticket.correlation_id)
    except IntegrationError:
        raise TicketOutcomeUnknown(ticket.id) from None
    if incident is None:
        raise TicketOutcomeUnknown(ticket.id)
    _apply_provider_reference(session, ticket, incident, actor)
    return serialize_ticket(ticket)


def create_servicenow_ticket(
    session: Session,
    *,
    finding_id: str,
    business_impact: str,
    idempotency_key: str,
    actor: dict,
    adapter: ServiceNowTicketAdapter | None = None,
) -> dict:
    adapter = adapter or ServiceNowTicketAdapter()
    if not adapter.configured:
        raise TicketProviderFailure(status_code=None, ambiguous=False, configured=False)
    repository = TicketRepository(session)
    key_hash = hashlib.sha256(f"{actor['id']}:{idempotency_key}".encode()).hexdigest()
    request_hash = hashlib.sha256(
        json.dumps(
            {"finding_id": finding_id, "business_impact": business_impact.strip()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    correlation_id = "SAM-" + key_hash[:32]
    existing = repository.by_idempotency_hash(key_hash)
    if existing:
        if existing.request_hash != request_hash:
            raise TicketConflict("Idempotency key was already used with a different request")
        if existing.status == "created":
            return serialize_ticket(existing)
        if existing.status == "unknown":
            return _reconcile_unknown(session, existing, actor, adapter)
        if existing.status == "processing":
            raise TicketConflict("Ticket creation is still processing")
        raise TicketConflict("This idempotency key was already used for a failed ticket request")

    finding = repository.finding(finding_id)
    if finding is None:
        raise TicketNotFound(finding_id)
    if finding.state == "Resolved":
        raise TicketConflict("A ticket cannot be created for a resolved finding")
    asset = session.get(Asset, finding.asset_id)
    if asset is None:
        raise TicketNotFound(finding_id)

    stamp = now()
    ticket = TicketLink(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        asset_id=asset.id,
        finding_ref=finding.id,
        asset_ref=asset.id,
        source="servicenow",
        correlation_id=correlation_id,
        idempotency_hash=key_hash,
        request_hash=request_hash,
        status="processing",
        requested_by=actor["id"],
        created_at=stamp,
        updated_at=stamp,
    )
    session.add(ticket)
    record_event(
        session,
        actor,
        "ticket.create_requested",
        "ticket_link",
        ticket.id,
        {"finding_id": finding.id, "asset_id": asset.id, "source": "servicenow"},
    )
    try:
        # Commit the idempotency marker before a remote side effect can occur.
        session.commit()
    except IntegrityError:
        session.rollback()
        duplicate = repository.by_idempotency_hash(key_hash)
        if duplicate and duplicate.status == "created":
            return serialize_ticket(duplicate)
        raise TicketConflict(
            "A ticket request with this idempotency key is already active"
        ) from None

    impact, urgency = _impact_urgency(finding.severity)
    short_description = f"SAM {finding.severity} vulnerability: {finding.title}"
    description = _description(finding, asset, business_impact)
    try:
        incident = adapter.find_by_correlation(correlation_id)
    except IntegrationError as exc:
        ticket.status = "failed"
        ticket.error_code = (
            f"provider_http_{exc.status_code}"
            if exc.status_code is not None
            else "provider_unavailable"
        )
        ticket.updated_at = now()
        record_event(
            session,
            actor,
            "ticket.provider_lookup_failed",
            "ticket_link",
            ticket.id,
            {"status_code": exc.status_code},
        )
        session.commit()
        raise TicketProviderFailure(status_code=exc.status_code, ambiguous=False) from None
    try:
        incident = incident or adapter.post_incident(
            correlation_id=correlation_id,
            short_description=short_description,
            description=description,
            impact=impact,
            urgency=urgency,
        )
    except IntegrationError as exc:
        ambiguous = exc.status_code is None or exc.status_code >= 500
        ticket.status = "unknown" if ambiguous else "failed"
        ticket.error_code = (
            "provider_outcome_unknown" if ambiguous else f"provider_http_{exc.status_code}"
        )
        ticket.updated_at = now()
        record_event(
            session,
            actor,
            "ticket.provider_create_failed",
            "ticket_link",
            ticket.id,
            {"status_code": exc.status_code, "outcome_ambiguous": ambiguous},
        )
        session.commit()
        raise TicketProviderFailure(status_code=exc.status_code, ambiguous=ambiguous) from None

    _apply_provider_reference(session, ticket, incident, actor)
    return serialize_ticket(ticket)


def list_tickets(session: Session, *, finding_id: str, limit: int = 100) -> dict:
    items = [
        serialize_ticket(item)
        for item in TicketRepository(session).by_finding(finding_id, limit=limit)
    ]
    return {"items": items, "total": len(items), "limit": limit}
