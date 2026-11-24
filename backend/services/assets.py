from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db.models import Asset
from backend.repositories.assets import AssetRepository
from backend.services.audit import record_event


class AssetConflict(Exception):
    pass


class AssetNotFound(Exception):
    pass


def serialize_asset(asset: Asset, include_findings: bool = False) -> dict:
    data = {column.name: getattr(asset, column.name) for column in Asset.__table__.columns}
    data["attributes"] = json.loads(data["attributes"] or "{}")
    if include_findings:
        data["findings"] = []
        for finding in sorted(
            asset.findings,
            key=lambda f: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(
                    f.severity, 5
                ),
                f.updated_at or "",
            ),
        ):
            finding_data = {
                column.name: getattr(finding, column.name) for column in finding.__table__.columns
            }
            try:
                finding_data["evidence"] = json.loads(finding_data["evidence"] or "{}")
            except (TypeError, ValueError):
                finding_data["evidence"] = {}
            data["findings"].append(finding_data)
    return data


def list_assets(session: Session, **query) -> tuple[list[dict], int]:
    rows, total = AssetRepository(session).list(**query)
    return [serialize_asset(asset) for asset in rows], total


def get_asset(session: Session, asset_id: str) -> dict:
    asset = AssetRepository(session).get(asset_id)
    if asset is None:
        raise AssetNotFound(asset_id)
    return serialize_asset(asset, include_findings=True)


def create_asset(session: Session, body, actor: dict) -> dict:
    asset = Asset(
        id=body.id,
        name=body.name,
        kind=body.kind,
        classification=body.classification,
        owner=body.owner,
        environment=body.environment,
        criticality=body.criticality,
        compliance=body.compliance,
        status="Active",
        waf=body.waf,
        attributes=json.dumps(body.attributes),
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )
    try:
        AssetRepository(session).add(asset)
    except IntegrityError as exc:
        session.rollback()
        raise AssetConflict(body.id) from exc
    record_event(session, actor, "asset.create", "asset", body.id, body.model_dump())
    return serialize_asset(asset)


def update_asset(session: Session, asset_id: str, values: dict, actor: dict) -> dict:
    asset = AssetRepository(session).get(asset_id)
    if asset is None:
        raise AssetNotFound(asset_id)
    if "attributes" in values:
        values["attributes"] = json.dumps(values["attributes"])
    values["updated_at"] = datetime.now(UTC).isoformat()
    AssetRepository(session).update(asset, values)
    record_event(session, actor, "asset.update", "asset", asset_id, values)
    return serialize_asset(asset)
