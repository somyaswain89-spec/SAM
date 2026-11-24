"""Connector reconciliation: map provider records into SAM-owned inventory and findings."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding, SyncRun, ThreatIntelRecord
from backend.integrations.base import IntegrationError
from backend.integrations.qualys import QualysAdapter, QualysDetection, QualysHost
from backend.integrations.servicenow import ServiceNowAdapter, ServiceNowCI
from backend.integrations.threat_intel import ThreatIntelAdapter
from backend.services.audit import record_event
from backend.services.finding_cves import all_finding_cves, normalize_cves, replace_finding_cves

SEVERITY_MAP = {
    "1": "Informational",
    "2": "Low",
    "3": "Medium",
    "4": "High",
    "5": "Critical",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
CRITICALITY_MAP = {
    "1": "Critical",
    "critical": "Critical",
    "very high": "Critical",
    "2": "High",
    "high": "High",
    "3": "Medium",
    "medium": "Medium",
    "4": "Low",
    "low": "Low",
}


def _normalize_exposure(value: str | None) -> str:
    normalized = (value or "").strip().lower().replace("_", " ")
    if normalized in {"external", "external facing", "internet facing", "true", "yes", "1"}:
        return "External facing"
    if normalized in {"internal", "internal facing", "false", "no", "0"}:
        return "Internal facing"
    return "Unknown"


def _criticality(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    for label in ("critical", "high", "medium", "low"):
        if (
            normalized == label
            or normalized.startswith(f"{label} ")
            or normalized.startswith(f"{label} -")
        ):
            return label.title()
    return CRITICALITY_MAP.get(normalized, "Medium")


def _upsert_asset(session: Session, values: dict) -> tuple[Asset, bool]:
    asset = session.scalar(
        select(Asset).where(
            Asset.source == values["source"], Asset.source_id == values["source_id"]
        )
    )
    created = asset is None
    if asset is None:
        asset = Asset(
            id=values["id"],
            name=values["name"],
            kind=values["kind"],
            source=values["source"],
            source_id=values["source_id"],
            created_at=values["updated_at"],
        )
        session.add(asset)
    for key, value in values.items():
        setattr(asset, key, value)
    return asset, created


def _qualys_asset_values(host: QualysHost, timestamp: str) -> dict:
    details = {
        "provider": "Qualys VMDR",
        "ip_address": host.ip,
        "dns": host.dns,
        "operating_system": host.os,
        "tracking_method": host.tracking_method,
        "last_activity": host.last_activity,
    }
    return {
        "id": f"qualys:{host.provider_id}",
        "name": host.name[:255],
        "kind": "Server",
        "classification": "Unknown",
        "owner": "",
        "environment": "Unknown",
        "criticality": "Medium",
        "compliance": None,
        "status": "Active",
        "waf": None,
        "source": "qualys",
        "source_id": host.provider_id,
        "attributes": json.dumps(details, sort_keys=True),
        "updated_at": timestamp,
    }


def _qualys_finding_values(host: Asset, detection: QualysDetection, timestamp: str) -> dict:
    source_ref = f"{detection.host_id}:{detection.qid}"
    state = "Resolved" if detection.status.strip().upper() == "FIXED" else "Open"
    cves = normalize_cves(detection.cves)
    return {
        "id": f"qualys:{source_ref}"[:150],
        "asset_id": host.id,
        "source": "qualys",
        "source_finding_id": source_ref,
        "title": detection.title[:500],
        "cve": cves[0] if cves else None,
        "cves": cves,
        "severity": SEVERITY_MAP.get(detection.severity.strip().lower(), "Medium"),
        "state": state,
        "first_seen": detection.first_seen,
        "last_seen": detection.last_seen,
        "due_at": None,
        "evidence": json.dumps(
            {"qid": detection.qid, "status": detection.status, "cves": cves},
            sort_keys=True,
        ),
        "updated_at": timestamp,
    }


def _save_progress(session: Session, run_id: str, records_read: int, records_written: int) -> None:
    run = session.get(SyncRun, run_id)
    if run:
        run.records_read = records_read
        run.records_written = records_written
        session.commit()


def _sync_qualys(session: Session, run_id: str) -> tuple[int, int]:
    adapter = QualysAdapter()
    timestamp = datetime.now(UTC).isoformat()
    records_read = 0
    records_written = 0
    batch_size = 500
    for host in adapter.iter_assets():
        _upsert_asset(session, _qualys_asset_values(host, timestamp))
        records_read += 1
        records_written += 1
        if records_read % batch_size == 0:
            _save_progress(session, run_id, records_read, records_written)
    session.flush()
    session.commit()
    for detection in adapter.iter_detections():
        records_read += 1
        mapped_asset = session.get(Asset, f"qualys:{detection.host_id}")
        if mapped_asset is None:
            if records_read % batch_size == 0:
                _save_progress(session, run_id, records_read, records_written)
            continue
        values = _qualys_finding_values(mapped_asset, detection, timestamp)
        linked_cves = values.pop("cves")
        existing = session.scalar(
            select(Finding).where(
                Finding.source == "qualys",
                Finding.source_finding_id == values["source_finding_id"],
                Finding.asset_id == mapped_asset.id,
            )
        )
        if existing is None:
            finding = Finding(created_at=timestamp, **values)
            session.add(finding)
        else:
            finding = existing
            for key, value in values.items():
                setattr(existing, key, value)
        replace_finding_cves(session, finding, linked_cves)
        records_written += 1
        if records_read % batch_size == 0:
            _save_progress(session, run_id, records_read, records_written)
    session.flush()
    _save_progress(session, run_id, records_read, records_written)
    return records_read, records_written


def _servicenow_asset_values(ci: ServiceNowCI, timestamp: str) -> dict:
    table_class = f"{ci.table} {ci.class_name or ''}".lower()
    kind = (
        "Website"
        if any(term in table_class for term in ("website", "web_application", "web app"))
        else "Server"
    )
    attributes = {
        "provider": "ServiceNow CMDB",
        "table": ci.table,
        "hostname": ci.hostname,
        "ip_address": ci.ip_address,
        "operating_system": ci.os,
        "manufacturer": ci.manufacturer,
        "model": ci.model,
        "class_name": ci.class_name,
        "source_updated_at": ci.updated_at,
    }
    attributes = {key: value for key, value in attributes.items() if value is not None}
    install = (ci.install_status or "").strip().lower()
    return {
        "id": f"servicenow:{ci.table}:{ci.provider_id}"[:120],
        "name": ci.name[:255],
        "kind": kind,
        "classification": _normalize_exposure(ci.exposure),
        "owner": "",
        "environment": (ci.environment or "Unknown")[:80],
        "criticality": _criticality(ci.criticality),
        "compliance": None,
        "status": "Retired" if install in {"7", "retired"} else "Active",
        "waf": None,
        "source": "servicenow",
        "source_id": f"{ci.table}:{ci.provider_id}",
        "attributes": json.dumps(attributes, sort_keys=True),
        "updated_at": timestamp,
    }


def _sync_servicenow(session: Session, run_id: str) -> tuple[int, int]:
    adapter = ServiceNowAdapter()
    timestamp = datetime.now(UTC).isoformat()
    records_read = 0
    written = 0
    for ci in adapter.iter_records():
        _upsert_asset(session, _servicenow_asset_values(ci, timestamp))
        written += 1
        records_read += 1
        if records_read % 500 == 0:
            _save_progress(session, run_id, records_read, written)
    session.flush()
    _save_progress(session, run_id, records_read, written)
    return records_read, written


def _sync_threat_intel(session: Session, run_id: str) -> tuple[int, int]:
    cves = all_finding_cves(session)
    snapshot = ThreatIntelAdapter().fetch(cves)
    updated_at = datetime.now(UTC).isoformat()
    values_by_cve: dict[str, dict] = {}
    for item in snapshot.kev:
        values_by_cve[item.cve] = {
            "kev_listed": True,
            "kev_catalog_version": snapshot.catalog_version,
            "kev_date_added": item.date_added,
            "kev_due_date": item.due_date,
            "kev_vendor": item.vendor,
            "kev_product": item.product,
            "kev_vulnerability_name": item.vulnerability_name,
            "kev_short_description": item.short_description,
            "kev_required_action": item.required_action,
            "kev_ransomware_use": item.ransomware_use,
            "updated_at": updated_at,
        }
    for epss_item in snapshot.epss:
        epss_values = {
            "epss_score": epss_item.score,
            "epss_percentile": epss_item.percentile,
            "epss_date": epss_item.score_date,
            "updated_at": updated_at,
        }
        values_by_cve.setdefault(epss_item.cve, {}).update(epss_values)
    for cve in cves:
        normalized_cve = cve.upper()
        if normalized_cve.startswith("CVE-"):
            values_by_cve.setdefault(normalized_cve, {"updated_at": updated_at})

    # The new catalog and score set were fully fetched and validated before replacing this snapshot.
    session.execute(
        update(ThreatIntelRecord).values(
            kev_listed=False,
            kev_catalog_version=None,
            kev_date_added=None,
            kev_due_date=None,
            kev_vendor=None,
            kev_product=None,
            kev_vulnerability_name=None,
            kev_short_description=None,
            kev_required_action=None,
            kev_ransomware_use=None,
            epss_score=None,
            epss_percentile=None,
            epss_date=None,
            updated_at=updated_at,
        )
    )
    keys = list(values_by_cve)
    existing: dict[str, ThreatIntelRecord] = {}
    for start in range(0, len(keys), 800):
        rows = session.scalars(
            select(ThreatIntelRecord).where(ThreatIntelRecord.cve.in_(keys[start : start + 800]))
        ).all()
        existing.update({row.cve: row for row in rows})
    for cve, values in values_by_cve.items():
        record = existing.get(cve)
        if record is None:
            record = ThreatIntelRecord(cve=cve, kev_listed=False, updated_at=updated_at)
            session.add(record)
        for key, value in values.items():
            setattr(record, key, value)

    records_read = len(snapshot.kev) + len(snapshot.epss)
    records_written = len(values_by_cve)
    _save_progress(session, run_id, records_read, records_written)
    return records_read, records_written


def run_sync(session: Session, source: str, run_id: str) -> dict:
    """Execute an explicitly requested sync and persist its final outcome."""
    run = session.get(SyncRun, run_id)
    if run is None or run.source != source:
        raise IntegrationError("Sync run does not exist")
    if run.status != "queued":
        return {
            "status": run.status,
            "records_read": run.records_read,
            "records_written": run.records_written,
        }
    claimed = cast(
        CursorResult,
        session.execute(
            update(SyncRun)
            .where(SyncRun.id == run_id, SyncRun.source == source, SyncRun.status == "queued")
            .values(status="running")
        ),
    )
    if claimed.rowcount != 1:
        session.rollback()
        current = session.get(SyncRun, run_id)
        if current is None:
            raise IntegrationError("Sync run does not exist")
        return {
            "status": current.status,
            "records_read": current.records_read,
            "records_written": current.records_written,
        }
    session.commit()
    try:
        if source == "qualys":
            read, written = _sync_qualys(session, run_id)
        elif source == "servicenow":
            read, written = _sync_servicenow(session, run_id)
        elif source == "threat_intel":
            read, written = _sync_threat_intel(session, run_id)
        else:
            raise IntegrationError("Unknown connector")
        completed_run = session.get(SyncRun, run_id)
        if completed_run is None:
            raise RuntimeError("Sync run disappeared before completion")
        completed_run.status = "completed"
        completed_run.records_read = read
        completed_run.records_written = written
        completed_run.finished_at = datetime.now(UTC).isoformat()
        completed_run.error = None
        record_event(
            session,
            None,
            "integration.sync.completed",
            "sync_run",
            run_id,
            {"source": source, "records_read": read, "records_written": written},
        )
        session.commit()
        return {"status": "completed", "records_read": read, "records_written": written}
    except Exception as exc:
        session.rollback()
        run = session.get(SyncRun, run_id)
        if run is not None:
            run.status = "failed"
            run.finished_at = datetime.now(UTC).isoformat()
            run.error = (
                str(exc)[:500]
                if isinstance(exc, IntegrationError)
                else "Sync failed; see protected worker logs"
            )
            record_event(
                session,
                None,
                "integration.sync.failed",
                "sync_run",
                run_id,
                {"source": source, "error": run.error},
            )
            session.commit()
        raise
