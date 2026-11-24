"""Business rules for dashboard aggregates and risk-ranked findings."""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.core.util import now
from backend.db.models import Finding
from backend.repositories.dashboard import DashboardRepository
from backend.repositories.threat_intel import ThreatIntelRepository
from backend.services.finding_cves import cves_by_finding_id

logger = logging.getLogger("sam.dashboard")
SEVERITY_WEIGHTS = {"Critical": 40, "High": 25, "Medium": 12, "Low": 5, "Informational": 1}


def dashboard_summary(session: Session, entity: str | None = None) -> dict:
    return {**DashboardRepository(session).summary(entity), "generatedAt": now()}


def _age_points(value: str | None) -> int:
    if not value:
        return 0
    try:
        seen = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=UTC)
        return max(0, min(15, (datetime.now(UTC) - seen).days // 7))
    except (ValueError, TypeError):
        return 0


def _evidence(value: str, finding_id: str) -> dict:
    try:
        decoded = json.loads(value or "{}")
        return decoded if isinstance(decoded, dict) else {}
    except (json.JSONDecodeError, TypeError):
        logger.warning("finding_evidence_invalid_json", extra={"finding_id": finding_id})
        return {}


def prioritize_findings(session: Session, *, entity: str | None = None, limit: int = 100) -> dict:
    scored = []
    priority_rows = DashboardRepository(session).priority_rows(entity)
    linked_cves = cves_by_finding_id(session, (finding.id for finding, _asset in priority_rows))
    intel_by_cve = ThreatIntelRepository(session).records_for_cves(
        {cve for finding, _asset in priority_rows for cve in linked_cves.get(finding.id, [])}
    )
    for finding, asset in priority_rows:
        evidence = _evidence(finding.evidence, finding.id)
        cves = linked_cves.get(finding.id, [])
        intel_candidates = [intel_by_cve[cve] for cve in cves if cve in intel_by_cve]
        intel = max(
            intel_candidates,
            key=lambda item: (bool(item.kev_listed), item.epss_score or 0),
            default=None,
        )
        evidence_cves = evidence.get("cves")
        if not cves and isinstance(evidence_cves, list):
            cves = [cve for cve in evidence_cves if isinstance(cve, str)]
        epss_value = intel.epss_score if intel else evidence.get("epss")
        epss: float | None = None
        try:
            parsed_epss = float(epss_value or 0)
            epss_points = (
                int(min(1.0, max(0.0, parsed_epss)) * 10) if math.isfinite(parsed_epss) else 0
            )
            epss = parsed_epss if epss_value is not None and math.isfinite(parsed_epss) else None
        except (ValueError, TypeError, OverflowError):
            epss = None
            epss_points = 0
        evidence_kev = evidence.get("kev")
        kev = (
            bool(intel.kev_listed)
            if intel
            else (evidence_kev if isinstance(evidence_kev, bool) else None)
        )
        kev_points = 10 if kev is True else 0
        score = (
            SEVERITY_WEIGHTS.get(finding.severity, 0)
            + (20 if asset.classification == "External facing" else 0)
            + (15 if asset.criticality == "Critical" else 0)
            + kev_points
            + epss_points
            + _age_points(finding.first_seen or finding.created_at)
        )
        row = {column.name: getattr(finding, column.name) for column in Finding.__table__.columns}
        row["evidence"] = evidence
        row.update(
            {
                "cves": cves,
                "asset_name": asset.name,
                "asset_kind": asset.kind,
                "criticality": asset.criticality,
                "classification": asset.classification,
                "compliance": asset.compliance,
                "riskScore": min(score, 100),
                "kev": kev,
                "epss": epss,
                "threatIntelSource": (
                    "CISA KEV / FIRST EPSS"
                    if intel
                    else ("finding evidence" if "kev" in evidence or "epss" in evidence else None)
                ),
                "riskFactors": {
                    "severity": finding.severity,
                    "externalFacing": asset.classification == "External facing",
                    "criticalAsset": asset.criticality == "Critical",
                    "kev": kev,
                    "epss": epss,
                    "threatIntelSource": (
                        "CISA KEV / FIRST EPSS"
                        if intel
                        else (
                            "finding evidence" if "kev" in evidence or "epss" in evidence else None
                        )
                    ),
                },
            }
        )
        scored.append(row)
    items = sorted(
        scored, key=lambda item: (-item["riskScore"], item["due_at"] or "9999", item["id"])
    )[:limit]
    return {
        "items": items,
        "sortRule": "riskScore desc, due date asc, finding ID asc",
        "scoreModel": "Transparent heuristic; not a calibrated probability",
    }
