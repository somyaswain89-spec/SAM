from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import Finding, FindingCVE
from backend.repositories.findings import FindingRepository
from backend.services.audit import record_event
from backend.services.finding_cves import cves_by_finding_id, replace_finding_cves


class FindingNotFound(Exception):
    pass


def serialize_finding(
    finding: Finding, related: dict | None = None, cves: list[str] | None = None
) -> dict:
    data = {column.name: getattr(finding, column.name) for column in Finding.__table__.columns}
    try:
        data["evidence"] = json.loads(data["evidence"] or "{}")
    except (TypeError, ValueError):
        data["evidence"] = {}
    if cves is None:
        cves = sorted(
            {link.cve for link in finding.cve_links} | ({finding.cve} if finding.cve else set())
        )
    data["cves"] = cves
    if related:
        data.update(related)
    return data


def list_findings(session: Session, **query) -> tuple[list[dict], int]:
    rows, total = FindingRepository(session).list(**query)
    cves = cves_by_finding_id(session, (row[0].id for row in rows))
    return [
        serialize_finding(
            row[0],
            {
                "asset_name": row.asset_name,
                "asset_kind": row.asset_kind,
                "asset_criticality": row.asset_criticality,
                "classification": row.classification,
            },
            cves.get(row[0].id, []),
        )
        for row in rows
    ], total


def upsert_finding(session: Session, body, actor: dict) -> dict:
    repository = FindingRepository(session)
    finding = (
        repository.find_source_record(body.source, body.source_finding_id, body.asset_id)
        if body.source_finding_id
        else repository.get(body.id)
    )
    evidence = {**body.evidence, "cvss": body.cvss, "epss": body.epss, "kev": body.kev}
    linked_cves = [body.cve, *body.cves]
    evidence_cves = evidence.get("cves")
    if isinstance(evidence_cves, list):
        linked_cves.extend(evidence_cves)
    values = {
        "asset_id": body.asset_id,
        "source": body.source,
        "source_finding_id": body.source_finding_id,
        "title": body.title,
        "cve": body.cve or (body.cves[0] if body.cves else None),
        "severity": body.severity,
        "state": body.state,
        "first_seen": body.first_seen,
        "last_seen": body.last_seen,
        "due_at": body.due_at,
        "evidence": json.dumps(evidence),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if finding is None:
        finding = Finding(id=body.id, created_at=values["updated_at"], **values)
        session.add(finding)
    else:
        for key, value in values.items():
            setattr(finding, key, value)
    stored_cves = replace_finding_cves(session, finding, linked_cves)
    session.flush()
    record_event(
        session,
        actor,
        "finding.upsert",
        "finding",
        finding.id,
        {"asset_id": body.asset_id, "state": body.state, "source": body.source},
    )
    return serialize_finding(finding, cves=stored_cves)


def update_finding_state(session: Session, finding_id: str, state: str, actor: dict) -> dict:
    finding = FindingRepository(session).get(finding_id)
    if finding is None:
        raise FindingNotFound(finding_id)
    finding.state = state
    finding.updated_at = datetime.now(UTC).isoformat()
    record_event(session, actor, "finding.state", "finding", finding_id, {"state": state})
    linked = list(
        session.scalars(
            select(FindingCVE.cve)
            .where(FindingCVE.finding_id == finding.id)
            .order_by(FindingCVE.cve)
        ).all()
    )
    if finding.cve and finding.cve not in linked:
        linked.append(finding.cve)
    return serialize_finding(finding, cves=linked)
