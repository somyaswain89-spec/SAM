"""Construct paths only from explicit, recorded asset dependency relationships."""

import json

from sqlalchemy.orm import Session

from backend.repositories.attack_paths import AttackPathRepository


def _path_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    source = item.get("from")
    target = item.get("to")
    source_id = source.get("id", "") if isinstance(source, dict) else ""
    target_id = target.get("id", "") if isinstance(target, dict) else ""
    score = item.get("riskScore", 0)
    score_value = score if isinstance(score, int) else 0
    return (-score_value, str(source_id), str(target_id))


def list_attack_paths(session: Session) -> dict:
    repository = AttackPathRepository(session)
    assets = repository.active_assets()
    critical_counts = repository.open_risk_counts()
    by_id = {asset.id: asset for asset in assets}
    paths: list[dict[str, object]] = []
    for asset in assets:
        try:
            attributes = json.loads(asset.attributes or "{}")
        except (ValueError, TypeError):
            attributes = {}
        targets = attributes.get("depends_on", []) if isinstance(attributes, dict) else []
        if not isinstance(targets, list):
            continue
        for target_id in targets:
            if not isinstance(target_id, str):
                continue
            target = by_id.get(target_id)
            if target is None:
                continue
            paths.append(
                {
                    "from": {"id": asset.id, "name": asset.name},
                    "to": {"id": target.id, "name": target.name},
                    "relationship": "depends_on",
                    "source": "asset attributes",
                    "verified": True,
                    "riskScore": (critical_counts.get(asset.id, 0) * 25)
                    + (20 if asset.classification == "External facing" else 0)
                    + (20 if target.criticality == "Critical" else 0),
                }
            )
    ordered = sorted(paths, key=_path_sort_key)
    return {
        "items": ordered,
        "total": len(ordered),
        "note": "Only explicitly recorded depends_on relationships are returned; missing relationships are not inferred.",
    }
