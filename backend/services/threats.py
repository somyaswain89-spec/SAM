"""Threat signal presentation and linked impacted-asset lists."""

import json

from sqlalchemy.orm import Session

from backend.repositories.threats import ThreatRepository


def _candidate(finding, asset) -> dict:
    return {
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "asset_id": asset.id,
        "name": asset.name,
        "kind": asset.kind,
        "owner": asset.owner,
        "criticality": asset.criticality,
    }


def zero_day_signals(session: Session) -> dict:
    repository = ThreatRepository(session)
    signals = []
    candidate_by_id = {
        finding.id: _candidate(finding, asset) for finding, asset in repository.open_findings()
    }
    for signal in repository.signals():
        try:
            evidence = json.loads(signal.evidence or "{}")
        except (ValueError, TypeError):
            evidence = {}
        if not isinstance(evidence, dict):
            evidence = {}
        signal_data: dict[str, object] = {
            "id": signal.id,
            "title": signal.title,
            "severity": signal.severity,
            "confidence": signal.confidence,
            "status": signal.status,
            "source": signal.source,
            "evidence": evidence,
            "created_at": signal.created_at,
        }
        finding_ids = evidence.get("finding_ids", [])
        if not isinstance(finding_ids, list):
            finding_ids = []
        signal_data["impactedAssets"] = [
            candidate_by_id[finding_id]
            for finding_id in finding_ids
            if isinstance(finding_id, str) and finding_id in candidate_by_id
        ]
        signals.append(signal_data)
    candidates = [
        _candidate(finding, asset) for finding, asset in repository.open_findings(no_cve_only=True)
    ]
    return {
        "signals": signals,
        "candidateFindings": candidates,
        "warning": "A suspected signal is not confirmation of a zero-day; validate evidence and affected versions.",
    }
