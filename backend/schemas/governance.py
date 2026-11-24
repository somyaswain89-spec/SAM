"""Typed response contracts for governance and containment APIs."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class ExceptionRead(BaseModel):
    id: str
    asset_id: str
    finding_id: str | None = None
    requested_by: int
    reason: str
    expires_at: str
    status: str
    reviewed_by: int | None = None
    review_note: str | None = None
    created_at: str
    updated_at: str
    asset_name: str | None = None


class ExceptionPage(BaseModel):
    items: list[ExceptionRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)


class WorkflowRead(BaseModel):
    id: str
    kind: str
    asset_id: str | None = None
    finding_id: str | None = None
    status: str
    payload: dict[str, Any]
    requested_by: int
    created_at: str
    updated_at: str


class WorkflowPage(BaseModel):
    items: list[WorkflowRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)


class ContainmentRead(BaseModel):
    id: str
    asset_id: str
    action: Literal["Quarantine", "Release"]
    status: str
    impact: str
    requested_by: int
    approved_by: int | None = None
    created_at: str
    updated_at: str


class ContainmentRequestRead(BaseModel):
    id: str
    assetId: str
    action: Literal["Quarantine", "Release"]
    status: str
    impact: str
    executionEnabled: bool


class ContainmentImpactRead(BaseModel):
    assetId: str
    action: Literal["Quarantine", "Release"]
    expectedEffect: str
    impact: str
    dependentAssets: list[str]
    impactBasis: Literal["SAM asset and dependency records"]


class ContainmentPage(BaseModel):
    items: list[ContainmentRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)
    executionEnabled: bool


class ContainmentDecisionRead(BaseModel):
    id: str
    status: str
    executionStatus: str
    externalActionExecuted: bool
    note: str


class PageEnvelope(BaseModel):
    """Used only as a typing helper for response contract documentation."""

    items: list[Any]
    total: int
    limit: int
    offset: int
