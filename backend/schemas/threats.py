"""Typed response contracts for zero-day investigation signals."""

from typing import Any

from pydantic import BaseModel


class ImpactedAssetRead(BaseModel):
    finding_id: str
    title: str
    severity: str
    asset_id: str
    name: str
    kind: str
    owner: str | None = None
    criticality: str


class ZeroDaySignalRead(BaseModel):
    id: str
    title: str
    severity: str
    confidence: str
    status: str
    source: str
    evidence: dict[str, Any]
    created_at: str
    impactedAssets: list[ImpactedAssetRead]


class ZeroDaySignalsRead(BaseModel):
    signals: list[ZeroDaySignalRead]
    candidateFindings: list[ImpactedAssetRead]
    warning: str
