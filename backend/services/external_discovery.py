"""Business rules for authorized passive external-asset discovery."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from backend.db.models import (
    Asset,
    DiscoveredExternalAsset,
    ExternalDiscoveryRun,
    ExternalDiscoveryTarget,
)
from backend.integrations.base import IntegrationError
from backend.integrations.certspotter import CertificateIssuance, CertSpotterAdapter
from backend.repositories.external_discovery import ExternalDiscoveryRepository
from backend.schemas.exposure import normalize_domain
from backend.services.audit import record_event


class DiscoveryNotFound(Exception):
    pass


class DiscoveryConflict(Exception):
    pass


class IssuancePageSource(Protocol):
    def iter_issuance_pages(self, domain: str) -> Iterable[Sequence[CertificateIssuance]]: ...


def _stamp() -> str:
    return datetime.now(UTC).isoformat()


def _serialize(model: Any) -> dict[str, Any]:
    return {column.name: getattr(model, column.name) for column in model.__table__.columns}


def _domain_scope(hostname: str, domain: str) -> str | None:
    candidate = hostname.strip().rstrip(".").lower()
    wildcard = candidate.startswith("*.")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    try:
        candidate = candidate.encode("idna").decode("ascii")
        normalize_domain(candidate)
    except ValueError:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return None
    if candidate == domain or candidate.endswith("." + domain):
        return "*." + candidate if wildcard else candidate
    return None


def create_target(session: Session, body, actor: dict[str, Any]) -> dict[str, Any]:
    domain = normalize_domain(body.domain)
    repository = ExternalDiscoveryRepository(session)
    if repository.target_for_domain(domain) is not None:
        raise DiscoveryConflict("A discovery target already exists for this domain")
    timestamp = _stamp()
    target = ExternalDiscoveryTarget(
        id="EDT-" + uuid.uuid4().hex[:20].upper(),
        domain=domain,
        active=True,
        authorization_note=body.authorization_note,
        authorized_by=int(actor["id"]),
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(target)
    session.flush()
    record_event(
        session,
        actor,
        "exposure.discovery.target.create",
        "external_discovery_target",
        target.id,
        {"domain": domain, "authorization_note": body.authorization_note},
    )
    return _serialize(target)


def set_target_active(
    session: Session,
    target_id: str,
    active: bool,
    actor: dict[str, Any],
    authorization_note: str | None = None,
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    target = ExternalDiscoveryRepository(session).get_target(target_id)
    if target is None:
        raise DiscoveryNotFound("Discovery target not found")
    active_run = ExternalDiscoveryRepository(session).active_run(target.id)
    if not active and active_run:
        raise DiscoveryConflict("A target cannot be disabled while discovery is running")
    if target.active == active:
        return _serialize(target)
    if active:
        if not authorization_confirmed or not authorization_note or len(authorization_note) < 20:
            raise DiscoveryConflict(
                "Reactivation requires renewed domain authorization attestation"
            )
        target.authorization_note = authorization_note
        target.authorized_by = int(actor["id"])
    target.active = active
    target.updated_at = _stamp()
    record_event(
        session,
        actor,
        "exposure.discovery.target.enabled" if active else "exposure.discovery.target.disabled",
        "external_discovery_target",
        target.id,
        {"domain": target.domain, "authorization_note": authorization_note},
    )
    session.flush()
    return _serialize(target)


def create_run(
    session: Session, target_id: str, actor: dict[str, Any] | None, trigger: str = "manual"
) -> dict[str, Any]:
    repository = ExternalDiscoveryRepository(session)
    target = repository.get_target(target_id)
    if target is None or not target.active:
        raise DiscoveryNotFound("Active discovery target not found")
    if repository.active_run(target_id):
        raise DiscoveryConflict("Discovery is already running for this domain")
    run = ExternalDiscoveryRun(
        id="EDR-" + uuid.uuid4().hex[:20].upper(),
        target_id=target.id,
        status="queued",
        started_at=_stamp(),
        pages_read=0,
        records_read=0,
        candidates_created=0,
        candidates_updated=0,
        requested_by=int(actor["id"]) if actor else None,
    )
    session.add(run)
    record_event(
        session,
        actor,
        "exposure.discovery.run.requested",
        "external_discovery_run",
        run.id,
        {"target_id": target.id, "domain": target.domain, "trigger": trigger},
    )
    session.flush()
    return {**_serialize(run), "domain": target.domain}


def _candidate_evidence(issuance: CertificateIssuance) -> str:
    return json.dumps(
        {
            "provider": "SSLMate Cert Spotter",
            "issuance_id": issuance.issuance_id,
            "certificate_sha256": issuance.cert_sha256,
            "not_before": issuance.not_before,
            "not_after": issuance.not_after,
            "revoked": issuance.revoked,
            "issuer": issuance.issuer,
            "discovery_method": "passive_certificate_transparency",
        },
        sort_keys=True,
    )


def _upsert_candidate(
    session: Session,
    *,
    target: ExternalDiscoveryTarget,
    run: ExternalDiscoveryRun,
    hostname: str,
    issuance: CertificateIssuance,
    timestamp: str,
) -> bool:
    repository = ExternalDiscoveryRepository(session)
    candidate = repository.candidate_for_hostname(target.id, hostname)
    if candidate is None:
        candidate = DiscoveredExternalAsset(
            id="EDA-" + uuid.uuid4().hex[:20].upper(),
            target_id=target.id,
            hostname=hostname,
            status="pending_review",
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            evidence=_candidate_evidence(issuance),
            last_run_id=run.id,
        )
        session.add(candidate)
        session.flush()
        return True
    candidate.last_seen_at = timestamp
    candidate.last_run_id = run.id
    candidate.evidence = _candidate_evidence(issuance)
    return False


def run_discovery(
    session: Session,
    run_id: str,
    adapter: IssuancePageSource | None = None,
) -> dict[str, Any]:
    repository = ExternalDiscoveryRepository(session)
    run = repository.get_run(run_id)
    if run is None:
        return {"status": "missing", "run_id": run_id}
    if run.status == "completed":
        return {"status": "completed", "run_id": run.id}
    target = repository.get_target(run.target_id)
    if target is None:
        run.status = "failed"
        run.finished_at = _stamp()
        run.error = "Discovery target no longer exists"
        session.commit()
        return {"status": run.status, "run_id": run.id}
    if not target.active:
        run.status = "failed"
        run.finished_at = _stamp()
        run.error = "Discovery target is inactive"
        session.commit()
        return {"status": run.status, "run_id": run.id}
    run.status = "running"
    run.error = None
    session.commit()
    timestamp = _stamp()
    adapter = adapter or CertSpotterAdapter()
    try:
        for page in adapter.iter_issuance_pages(target.domain):
            run.pages_read += 1
            run.records_read += len(page)
            for issuance in page:
                for raw_name in issuance.dns_names:
                    hostname = _domain_scope(raw_name, target.domain)
                    if hostname is None:
                        continue
                    if _upsert_candidate(
                        session,
                        target=target,
                        run=run,
                        hostname=hostname,
                        issuance=issuance,
                        timestamp=timestamp,
                    ):
                        run.candidates_created += 1
                    else:
                        run.candidates_updated += 1
            if run.pages_read % 5 == 0:
                session.commit()
        run.status = "completed"
        run.finished_at = _stamp()
        run.error = None
        target.last_run_at = run.finished_at
        target.updated_at = run.finished_at
        record_event(
            session,
            {"id": run.requested_by} if run.requested_by else None,
            "exposure.discovery.run.completed",
            "external_discovery_run",
            run.id,
            {
                "target_id": target.id,
                "pages_read": run.pages_read,
                "records_read": run.records_read,
                "candidates_created": run.candidates_created,
                "candidates_updated": run.candidates_updated,
            },
        )
        session.commit()
        return {"status": run.status, "run_id": run.id}
    except IntegrationError as exc:
        session.rollback()
        run = repository.get_run(run_id)
        if run is not None:
            run.status = "failed"
            run.finished_at = _stamp()
            run.error = str(exc)[:500]
            record_event(
                session,
                {"id": run.requested_by} if run.requested_by else None,
                "exposure.discovery.run.failed",
                "external_discovery_run",
                run.id,
                {"target_id": run.target_id, "error": run.error},
            )
            session.commit()
        raise


def list_targets(session: Session, limit: int, offset: int) -> tuple[list[dict], int]:
    rows, total = ExternalDiscoveryRepository(session).list_targets(limit, offset)
    return [_serialize(row) for row in rows], total


def _run_data(run: ExternalDiscoveryRun, domain: str) -> dict:
    return {**_serialize(run), "domain": domain}


def list_runs(
    session: Session, target_id: str | None, limit: int, offset: int
) -> tuple[list[dict], int]:
    rows, total, domains = ExternalDiscoveryRepository(session).list_runs(target_id, limit, offset)
    return [_run_data(run, domains.get(run.target_id, "")) for run in rows], total


def list_candidates(
    session: Session,
    target_id: str | None,
    status: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict], int]:
    rows, total, domains = ExternalDiscoveryRepository(session).list_candidates(
        target_id, status, limit, offset
    )
    items = []
    for candidate in rows:
        data = _serialize(candidate)
        try:
            data["evidence"] = json.loads(candidate.evidence or "{}")
        except (json.JSONDecodeError, TypeError):
            data["evidence"] = {}
        data["domain"] = domains.get(candidate.target_id, "")
        items.append(data)
    return items, total


def review_candidate(
    session: Session,
    candidate_id: str,
    decision: str,
    note: str,
    actor: dict[str, Any],
) -> dict[str, Any]:
    repository = ExternalDiscoveryRepository(session)
    candidate = repository.get_candidate(candidate_id)
    if candidate is None:
        raise DiscoveryNotFound("Discovered hostname not found")
    if candidate.status != "pending_review":
        raise DiscoveryConflict("Only pending discoveries can be reviewed")
    target = repository.get_target(candidate.target_id)
    if target is None or _domain_scope(candidate.hostname, target.domain) != candidate.hostname:
        raise DiscoveryConflict("Discovery candidate is outside the authorized domain")

    asset_id = None
    if decision == "accept":
        asset_id = "ct:" + hashlib.sha256(candidate.hostname.encode("ascii")).hexdigest()[:32]
        asset = session.get(Asset, asset_id)
        if asset is None:
            timestamp = _stamp()
            asset = Asset(
                id=asset_id,
                name=candidate.hostname,
                kind="Website",
                classification="External facing",
                owner="",
                environment="Unknown",
                criticality="Medium",
                compliance=None,
                status="Active",
                waf=None,
                source="certspotter",
                source_id=candidate.hostname,
                attributes=json.dumps(
                    {
                        "discovery_target": target.domain,
                        "discovery_method": "passive_certificate_transparency",
                        "evidence": json.loads(candidate.evidence or "{}"),
                    },
                    sort_keys=True,
                ),
                created_at=timestamp,
                updated_at=timestamp,
            )
            session.add(asset)
            session.flush()
            record_event(
                session,
                actor,
                "asset.create.from_external_discovery",
                "asset",
                asset.id,
                {"hostname": candidate.hostname, "target_id": target.id},
            )
        candidate.asset_id = asset_id

    candidate.status = "accepted" if decision == "accept" else "dismissed"
    candidate.reviewed_by = int(actor["id"])
    candidate.reviewed_at = _stamp()
    candidate.review_note = note
    record_event(
        session,
        actor,
        f"exposure.discovery.candidate.{candidate.status}",
        "external_discovery_candidate",
        candidate.id,
        {
            "hostname": candidate.hostname,
            "domain": target.domain,
            "asset_id": asset_id,
            "note": note,
        },
    )
    session.flush()
    data = _serialize(candidate)
    data["domain"] = target.domain
    data["evidence"] = json.loads(candidate.evidence or "{}")
    return data
