"""Answer analyst questions using scoped SAM records and optional generative AI."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from backend.core.util import now
from backend.integrations.analyst_model import AnalystModelAdapter
from backend.integrations.base import IntegrationError
from backend.repositories.analyst import AnalystRepository

logger = logging.getLogger("sam.analyst")


def _context(repository: AnalystRepository, entity: str | None, finding_count: int) -> dict:
    """Build a bounded, data-minimized context; never send raw evidence or credentials."""
    assets = repository.assets(entity)
    findings = repository.findings(entity, limit=40)
    asset_records = [
        {
            "id": asset.id,
            "name": asset.name[:255],
            "type": asset.kind,
            "classification": asset.classification,
            "criticality": asset.criticality,
            "environment": asset.environment,
            "status": asset.status,
            "compliancePercent": asset.compliance,
            "wafRecordedStatus": asset.waf if asset.kind == "Website" else None,
        }
        for asset in assets
    ]
    finding_records = [
        {
            "id": finding.id,
            "assetId": asset.id,
            "assetName": asset.name[:255],
            "assetType": asset.kind,
            "assetCriticality": asset.criticality,
            "assetClassification": asset.classification,
            "title": finding.title[:500],
            "cve": finding.cve,
            "severity": finding.severity,
            "state": finding.state,
            "dueAt": finding.due_at,
        }
        for finding, asset in findings
    ]
    return {
        "scope": entity or "All",
        "summary": repository.asset_summary(entity),
        "openFindingCount": finding_count,
        "assetSampleLimit": 25,
        "assetSample": asset_records,
        "findingSampleLimit": 40,
        "highestPriorityOpenFindings": finding_records,
        "samplingNotice": (
            "Asset and finding lists are bounded samples. Summary counts are complete. "
            "Do not imply an item is absent from SAM merely because it is not in a sample."
        ),
    }


def _rule_based_answer(
    repository: AnalystRepository,
    question: str,
    entity: str | None,
    finding_count: int,
) -> str:
    normalized = question.lower()
    summary = repository.asset_summary(entity)
    if any(keyword in normalized for keyword in ("rescan", "scan again")):
        return "To request a rescan, create a Rescan workflow with the asset, finding, reason, and approved time window. A real scan requires a configured scanner connector and explicit approval."
    if any(keyword in normalized for keyword in ("quarantine", "isolate", "contain")):
        return "Use the containment request workflow after reviewing the named asset, owner, criticality, compliance and dependencies. In this QA build, requests are recorded for approval only; no system is isolated."
    if "waf" in normalized:
        website_count = summary["websites"] if entity != "Server" else 0
        answer = f"{summary['websitesWafProtected']} of {website_count} in-scope websites are marked Protected. This is recorded posture, not independent verification."
        if entity == "Server":
            return (
                "WAF classification applies to websites; the current scope contains only servers."
            )
        return answer
    if "compliance" in normalized:
        return f"{summary['complianceBelow80']} in-scope assets have recorded compliance below 80%. {summary['complianceUnknown']} assets have no recorded compliance value; those values are unknown, not failures."
    if any(keyword in normalized for keyword in ("zero day", "zeroday", "undisclosed")):
        return "Open Threats → zero-day signals. The QA backend lists candidate findings without CVEs; these are investigation candidates, not confirmed zero-days."
    if any(keyword in normalized for keyword in ("triage", "priorit")):
        return f"There are {finding_count} open findings in scope. The findings endpoint sorts by severity priority, then last update. Use /api/risk/priorities for the transparent risk score and factors."
    if any(keyword in normalized for keyword in ("remediat", "patch", "fix")):
        return f"SAM has {finding_count} open findings in scope. Review the finding evidence and vendor advisory before applying a patch; SAM does not invent a package-specific remediation when source evidence is missing."
    return f"Current scope contains {summary['totalAssets']} assets ({summary['websites']} websites and {summary['servers']} servers) and {finding_count} open findings. The connected analyst can answer questions about the persisted SAM inventory and workflows when enabled; without it this QA response is limited to known guidance and summary facts."


def answer_question(
    session: Session,
    *,
    question: str,
    entity: str | None = None,
    history: list[dict[str, str]] | None = None,
) -> dict:
    repository = AnalystRepository(session)
    finding_count = repository.open_finding_count(entity)
    model = AnalystModelAdapter()
    warning = None
    if model.configured:
        try:
            answer = model.answer(
                question=question,
                context=_context(repository, entity, finding_count),
                history=history or [],
            )
            return {
                "answer": answer,
                "mode": "ai-grounded",
                "sources": ["SAM database", "AI analyst provider"],
                "generatedAt": now(),
                "scope": entity or "All",
                "warning": None,
            }
        except IntegrationError as exc:
            logger.warning("analyst_provider_unavailable", extra={"error_type": type(exc).__name__})
            warning = "AI provider unavailable; this answer uses limited rule-based guidance and SAM summary counts."

    return {
        "answer": _rule_based_answer(repository, question, entity, finding_count),
        "mode": "rule-based-qa" if warning is None else "rule-based-fallback",
        "sources": ["SAM database"],
        "generatedAt": now(),
        "scope": entity or "All",
        "warning": warning,
    }
