"""Request and response contracts for ServiceNow ticket workflows."""

from pydantic import BaseModel, Field


class ServiceNowTicketRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=150)
    business_impact: str = Field(min_length=10, max_length=2000)


class TicketLinkRead(BaseModel):
    id: str
    finding_id: str
    asset_id: str
    source: str
    status: str
    external_sys_id: str | None = None
    external_number: str | None = None
    correlation_id: str
    error_code: str | None = None
    created_at: str
    updated_at: str


class TicketLinkPage(BaseModel):
    items: list[TicketLinkRead]
    total: int
    limit: int
