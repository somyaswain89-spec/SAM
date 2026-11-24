"""Transactional services for exception, workflow, and containment operations."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from backend.db.models import ContainmentAction, ExceptionRequest, WorkflowRequest
from backend.repositories.governance import GovernanceRepository
from backend.schemas.common import ContainmentRequest, ExceptionCreate, WorkflowCreate
from backend.services.audit import record_event


class GovernanceNotFound(Exception):
    pass


class GovernanceConflict(Exception):
    pass


class GovernanceInvalid(Exception):
    pass


def _stamp() -> str:
    return datetime.now(UTC).isoformat()


def _serialize(model: Any, *, json_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    values = {column.name: getattr(model, column.name) for column in model.__table__.columns}
    for field in json_fields:
        try:
            values[field] = json.loads(values[field] or "{}")
        except (TypeError, ValueError):
            values[field] = {}
    return values


def create_exception(
    session: Session, body: ExceptionCreate, actor: dict[str, Any]
) -> dict[str, Any]:
    try:
        expiry = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise GovernanceInvalid("expires_at must be ISO-8601") from None
    if expiry.tzinfo is None or expiry <= datetime.now(UTC):
        raise GovernanceInvalid("Expiry must be a future timezone-aware timestamp")

    repository = GovernanceRepository(session)
    if repository.asset(body.asset_id) is None:
        raise GovernanceNotFound("Asset not found")
    if body.finding_id and repository.finding_for_asset(body.finding_id, body.asset_id) is None:
        raise GovernanceInvalid("Finding does not belong to asset")

    stamp = _stamp()
    item = ExceptionRequest(
        id="EX-" + uuid.uuid4().hex[:10].upper(),
        asset_id=body.asset_id,
        finding_id=body.finding_id,
        requested_by=actor["id"],
        reason=body.reason,
        expires_at=expiry.astimezone(UTC).isoformat(),
        status="Pending",
        created_at=stamp,
        updated_at=stamp,
    )
    repository.add_exception(item)
    record_event(session, actor, "exception.request", "exception", item.id, body.model_dump())
    return _serialize(item)


def list_exceptions(
    session: Session,
    state: str | None,
    limit: int,
    offset: int,
    requested_by: int | None = None,
) -> tuple[list[dict[str, Any]], int]:
    rows, total = GovernanceRepository(session).list_exceptions(state, limit, offset, requested_by)
    items = []
    for request, asset_name in rows:
        item = _serialize(request)
        item["asset_name"] = asset_name
        items.append(item)
    return items, total


def review_exception(
    session: Session, item_id: str, decision: str, note: str, actor: dict[str, Any]
) -> dict[str, Any]:
    item = GovernanceRepository(session).pending_exception(item_id)
    if item is None:
        raise GovernanceNotFound("Pending exception not found")
    if item.requested_by == actor["id"]:
        raise GovernanceConflict("Requester cannot review their own exception")
    if datetime.fromisoformat(item.expires_at) <= datetime.now(UTC):
        raise GovernanceConflict("Expired exceptions cannot be approved")

    item.status = "Approved" if decision == "Approve" else "Rejected"
    item.reviewed_by = actor["id"]
    item.review_note = note
    item.updated_at = _stamp()
    record_event(
        session, actor, "exception." + item.status.lower(), "exception", item.id, {"note": note}
    )
    session.flush()
    return _serialize(item)


def create_workflow(
    session: Session, body: WorkflowCreate, actor: dict[str, Any]
) -> dict[str, Any]:
    repository = GovernanceRepository(session)
    if body.asset_id and repository.asset(body.asset_id) is None:
        raise GovernanceNotFound("Asset not found")
    if body.finding_id:
        finding = repository.finding(body.finding_id)
        if finding is None:
            raise GovernanceNotFound("Finding not found")
        if body.asset_id and finding.asset_id != body.asset_id:
            raise GovernanceInvalid("Finding does not belong to asset")

    stamp = _stamp()
    item = WorkflowRequest(
        id="WF-" + uuid.uuid4().hex[:10].upper(),
        kind=body.kind,
        asset_id=body.asset_id,
        finding_id=body.finding_id,
        status="Pending",
        payload=json.dumps(body.payload, sort_keys=True),
        requested_by=actor["id"],
        created_at=stamp,
        updated_at=stamp,
    )
    repository.add_workflow(item)
    record_event(session, actor, "workflow.create", "workflow", item.id, body.model_dump())
    return _serialize(item, json_fields=("payload",))


def list_workflows(
    session: Session, limit: int, offset: int, requested_by: int | None = None
) -> tuple[list[dict[str, Any]], int]:
    rows, total = GovernanceRepository(session).list_workflows(limit, offset, requested_by)
    return [_serialize(item, json_fields=("payload",)) for item in rows], total


def request_containment(
    session: Session, body: ContainmentRequest, actor: dict[str, Any]
) -> dict[str, Any]:
    if not body.acknowledge_impact:
        raise GovernanceConflict(
            "Business impact must be acknowledged before requesting containment"
        )
    repository = GovernanceRepository(session)
    asset = repository.asset(body.asset_id)
    if asset is None:
        raise GovernanceNotFound("Asset not found")

    dependents = repository.dependent_assets(asset.id)
    preview = _containment_impact(asset, dependents, body.action)
    impact = preview["impact"]
    stamp = _stamp()
    item = ContainmentAction(
        id="CT-" + uuid.uuid4().hex[:10].upper(),
        asset_id=asset.id,
        action=body.action,
        status="Approval required",
        impact=impact,
        requested_by=actor["id"],
        created_at=stamp,
        updated_at=stamp,
    )
    repository.add_containment(item)
    record_event(
        session,
        actor,
        "containment.request",
        "containment",
        item.id,
        {"asset_id": asset.id, "action": body.action, "impact": impact},
    )
    return {
        "id": item.id,
        "assetId": asset.id,
        "action": item.action,
        "status": item.status,
        "impact": item.impact,
        "executionEnabled": False,
    }


def preview_containment_impact(session: Session, asset_id: str, action: str) -> dict[str, Any]:
    repository = GovernanceRepository(session)
    asset = repository.asset(asset_id)
    if asset is None:
        raise GovernanceNotFound("Asset not found")
    return _containment_impact(asset, repository.dependent_assets(asset.id), action)


def _containment_impact(asset: Any, dependents: list[str], action: str) -> dict[str, Any]:
    compliance = (
        f"{asset.compliance}% recorded compliance"
        if asset.compliance is not None
        else "compliance is unknown"
    )
    dependent_text = (
        f"{len(dependents)} dependent asset(s): {', '.join(dependents[:10])}"
        if dependents
        else "no dependent assets recorded"
    )
    impact = (
        f"{asset.criticality} criticality {asset.kind} '{asset.name}' owned by "
        f"{asset.owner or 'Unknown owner'} in {asset.environment}; current state "
        f"{asset.status}; {compliance}; {dependent_text}. Review service dependencies, "
        "customer impact, and the recovery plan before action."
    )
    expected_effect = (
        "Quarantine may interrupt access to this asset and services recorded as dependent on it."
        if action == "Quarantine"
        else "Release may restore access to this asset; verify the original risk is controlled first."
    )
    return {
        "assetId": asset.id,
        "action": action,
        "expectedEffect": expected_effect,
        "impact": impact,
        "dependentAssets": dependents,
        "impactBasis": "SAM asset and dependency records",
    }


def list_containment(
    session: Session, limit: int, offset: int, requested_by: int | None = None
) -> tuple[list[dict[str, Any]], int]:
    rows, total = GovernanceRepository(session).list_containment(limit, offset, requested_by)
    return [_serialize(item) for item in rows], total


def review_containment(
    session: Session, item_id: str, decision: str, note: str, actor: dict[str, Any]
) -> dict[str, Any]:
    item = GovernanceRepository(session).pending_containment(item_id)
    if item is None:
        raise GovernanceNotFound("Pending containment request not found")
    if item.requested_by == actor["id"]:
        raise GovernanceConflict("Requester cannot review their own containment request")

    item.status = "Approved; awaiting integration" if decision == "Approve" else "Rejected"
    item.approved_by = actor["id"]
    item.updated_at = _stamp()
    execution_status = "pending_connector" if decision == "Approve" else "not_applicable"
    record_event(
        session,
        actor,
        "containment." + decision.lower(),
        "containment",
        item.id,
        {"note": note, "executionStatus": execution_status},
    )
    session.flush()
    return {
        "id": item.id,
        "status": item.status,
        "executionStatus": execution_status,
        "externalActionExecuted": False,
        "note": (
            "The approval is stored in SAM. Asset state is unchanged until the environment "
            "configures and validates a containment connector."
        ),
    }
