"""Compliance posture calculations based only on explicitly recorded scores."""

from sqlalchemy.orm import Session

from backend.core.util import now
from backend.repositories.compliance import ComplianceRepository


def compliance_summary(session: Session, *, entity: str | None = None, target: int = 90) -> dict:
    repository = ComplianceRepository(session)
    scores = repository.scores(entity)
    average = round(sum(scores) / len(scores), 1) if scores else None
    return {
        "assetsEvaluated": len(scores),
        "averagePercent": average,
        "targetPercent": target,
        "belowTarget": sum(score < target for score in scores),
        "unknownAssets": repository.unknown_count(entity),
        "method": "Mean of explicitly recorded asset compliance scores; no policy evaluation is inferred.",
        "calculatedAt": now(),
    }


def compliance_assets(session: Session, *, entity: str | None = None) -> dict:
    items = [
        {
            "id": asset.id,
            "name": asset.name,
            "kind": asset.kind,
            "owner": asset.owner,
            "compliance": asset.compliance,
        }
        for asset in ComplianceRepository(session).assets(entity)
    ]
    return {
        "items": items,
        "sortRule": "lowest known compliance first; NULL scores remain unknown",
    }
