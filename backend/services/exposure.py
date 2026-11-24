"""Exposure summaries based on recorded inventory and evidence."""

from sqlalchemy.orm import Session

from backend.repositories.exposure import ExposureRepository
from backend.services.assets import serialize_asset


def exposure_summary(session: Session, *, entity: str | None = None) -> dict:
    repository = ExposureRepository(session)
    return {
        "classificationCounts": repository.classification_counts(entity),
        "wafCounts": repository.waf_counts(),
        "verificationNote": "WAF state must come from an approved provider or operator evidence; DNS alone is insufficient.",
    }


def external_assets(session: Session) -> dict:
    items = []
    for asset, open_findings in ExposureRepository(session).external_assets():
        data = serialize_asset(asset)
        data["open_findings"] = open_findings
        items.append(data)
    return {"items": items, "source": "SAM asset inventory; not external discovery"}
