"""Contracts for authorized external-domain discovery and candidate review."""

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Enter a valid internationalized domain name") from None
    if len(domain) > 253 or "." not in domain or domain in {"localhost", "local"}:
        raise ValueError("Enter a registered root domain, such as example.com")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a DNS domain, not an IP address")
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise ValueError("Enter a valid DNS domain name")
    return domain


class ExternalDiscoveryTargetCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    authorization_note: str = Field(min_length=20, max_length=1000)
    authorization_confirmed: Literal[True]

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("authorization_note")
    @classmethod
    def nonblank_note(cls, value: str) -> str:
        if len(value.strip()) < 20:
            raise ValueError("Explain the authorization basis in at least 20 characters")
        return value.strip()


class ExternalDiscoveryTargetRead(BaseModel):
    id: str
    domain: str
    active: bool
    authorization_note: str
    authorized_by: int | None = None
    created_at: str
    updated_at: str
    last_run_at: str | None = None


class ExternalDiscoveryTargetPage(BaseModel):
    items: list[ExternalDiscoveryTargetRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class ExternalDiscoveryStatusRead(BaseModel):
    provider: str
    configured: bool
    method: str
    behavior: str


class ExternalDiscoveryTargetActiveUpdate(BaseModel):
    active: bool
    authorization_note: str | None = Field(None, min_length=20, max_length=1000)
    authorization_confirmed: bool = False

    @field_validator("authorization_note")
    @classmethod
    def nonblank_note(cls, value: str | None) -> str | None:
        if value is not None and len(value.strip()) < 20:
            raise ValueError("Explain the authorization basis in at least 20 characters")
        return value.strip() if value else value


class ExternalDiscoveryRunRead(BaseModel):
    id: str
    target_id: str
    domain: str
    status: Literal["queued", "running", "completed", "failed"]
    started_at: str
    finished_at: str | None = None
    pages_read: int = Field(ge=0)
    records_read: int = Field(ge=0)
    candidates_created: int = Field(ge=0)
    candidates_updated: int = Field(ge=0)
    error: str | None = None


class ExternalDiscoveryRunCreated(ExternalDiscoveryRunRead):
    task_id: str


class ExternalDiscoveryRunPage(BaseModel):
    items: list[ExternalDiscoveryRunRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class DiscoveredExternalAssetRead(BaseModel):
    id: str
    target_id: str
    domain: str
    hostname: str
    status: Literal["pending_review", "accepted", "dismissed"]
    first_seen_at: str
    last_seen_at: str
    evidence: dict
    last_run_id: str | None = None
    asset_id: str | None = None
    reviewed_by: int | None = None
    reviewed_at: str | None = None
    review_note: str | None = None


class DiscoveredExternalAssetPage(BaseModel):
    items: list[DiscoveredExternalAssetRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class ExternalAssetReview(BaseModel):
    decision: Literal["accept", "dismiss"]
    note: str = Field(min_length=3, max_length=1000)

    @field_validator("note")
    @classmethod
    def nonblank_note(cls, value: str) -> str:
        if len(value.strip()) < 3:
            raise ValueError("A review note is required")
        return value.strip()
