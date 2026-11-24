from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import current_user, require_roles
from backend.schemas.common import AssetCreate, AssetRead, AssetUpdate, PageResponse
from backend.services.assets import (
    AssetConflict,
    AssetNotFound,
)
from backend.services.assets import (
    create_asset as create_asset_service,
)
from backend.services.assets import get_asset as get_asset_service
from backend.services.assets import list_assets as list_assets_service
from backend.services.assets import update_asset as update_asset_service
from backend.services.idempotency import IdempotencyConflict, execute_idempotently

router = APIRouter(prefix="/assets", tags=["asset inventory"])


@router.get("", response_model=PageResponse[AssetRead])
def list_assets(
    entity: str | None = None,
    classification: str | None = None,
    status: str | None = None,
    q: str | None = Query(None, max_length=200),
    sort: str = "name",
    direction: str = "asc",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    if entity and entity not in ("Website", "Server"):
        raise HTTPException(422, "entity must be Website or Server")
    if classification and classification not in ("Internal facing", "External facing", "Unknown"):
        raise HTTPException(422, "Unsupported asset classification")
    if sort not in {"name", "criticality", "compliance", "updated_at", "kind"} or direction not in {
        "asc",
        "desc",
    }:
        raise HTTPException(422, "Unsupported sort")
    items, total = list_assets_service(
        session,
        entity=entity,
        classification=classification,
        status=status,
        query=q,
        sort=sort,
        direction=direction,
        limit=limit,
        offset=offset,
    )
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "direction": direction,
    }


@router.post("", status_code=201, response_model=AssetRead)
def create_asset(
    body: AssetCreate,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="assets.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            response_status=201,
            execute=lambda: create_asset_service(session, body, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except AssetConflict:
        raise HTTPException(409, "Asset ID already exists") from None
    except IntegrityError:
        raise HTTPException(409, "Asset conflicts with an existing record") from None


@router.get("/{asset_id}", response_model=AssetRead)
def asset_detail(asset_id: str, user=Depends(current_user), session: Session = Depends(get_db)):
    try:
        return get_asset_service(session, asset_id)
    except AssetNotFound:
        raise HTTPException(404, "Asset not found") from None


@router.patch("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: str,
    body: AssetUpdate,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    ),
    user=Depends(require_roles("admin", "security_admin", "analyst")),
    session: Session = Depends(get_db),
):
    data = body.model_dump(exclude_unset=True)
    if any(
        key in data and data[key] is None
        for key in (
            "name",
            "classification",
            "owner",
            "environment",
            "criticality",
            "status",
            "attributes",
        )
    ):
        raise HTTPException(422, "This field cannot be null")
    if not data:
        raise HTTPException(400, "No update fields supplied")
    try:
        return execute_idempotently(
            session,
            actor=user,
            operation="assets.update",
            idempotency_key=idempotency_key,
            request_payload={"asset_id": asset_id, "fields": data},
            response_status=200,
            execute=lambda: update_asset_service(session, asset_id, data, user),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except AssetNotFound:
        raise HTTPException(404, "Asset not found") from None
