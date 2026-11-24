"""Audit log and chain-verification API response contracts."""

from typing import Any

from pydantic import BaseModel


class AuditEventRead(BaseModel):
    id: int
    user_id: int | None
    actor: str | None
    action: str
    object_type: str
    object_id: str | None
    detail: dict[str, Any]
    created_at: str
    previous_hash: str
    entry_hash: str


class AuditEventPage(BaseModel):
    items: list[AuditEventRead]


class AuditVerification(BaseModel):
    valid: bool
    checked: int
    headMatches: bool | None = None
    eventId: int | None = None
