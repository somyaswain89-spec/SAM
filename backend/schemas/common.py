import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

AssetType = Literal["Website", "Server"]
Exposure = Literal["Internal facing", "External facing", "Unknown"]
Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]


class PageResponse[T](BaseModel):
    items: list[T]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)
    sort: str | None = None
    direction: Literal["asc", "desc"] | None = None


class FindingRead(BaseModel):
    id: str
    asset_id: str
    source: str
    source_finding_id: str | None = None
    title: str
    cve: str | None = None
    cves: list[str] = Field(default_factory=list)
    severity: Severity
    state: Literal["Open", "In Progress", "Resolved", "Accepted Risk"]
    first_seen: str | None = None
    last_seen: str | None = None
    due_at: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    asset_name: str | None = None
    asset_kind: AssetType | None = None
    asset_criticality: str | None = None
    classification: Exposure | None = None


class AssetRead(BaseModel):
    id: str
    name: str
    kind: AssetType
    classification: Exposure
    owner: str
    environment: str
    criticality: Literal["Critical", "High", "Medium", "Low"]
    compliance: int | None = Field(None, ge=0, le=100)
    status: Literal["Active", "Quarantined", "Retired"]
    waf: str | None = None
    source: str
    source_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    findings: list[FindingRead] = Field(default_factory=list)


class Login(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=256)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class CreateUser(BaseModel):
    email: str = Field(min_length=5, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "security_admin", "analyst", "auditor", "viewer"] = "analyst"


class AssetCreate(BaseModel):
    id: str = Field(min_length=2, max_length=120)
    name: str = Field(min_length=1, max_length=255)
    kind: AssetType
    classification: Exposure = "Unknown"
    owner: str = ""
    environment: str = "Unknown"
    criticality: Literal["Critical", "High", "Medium", "Low"] = "Medium"
    compliance: int | None = Field(None, ge=0, le=100)
    waf: str | None = None
    attributes: dict = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    name: str | None = None
    classification: Exposure | None = None
    owner: str | None = None
    environment: str | None = None
    criticality: Literal["Critical", "High", "Medium", "Low"] | None = None
    compliance: int | None = Field(None, ge=0, le=100)
    # Quarantine is a provider-confirmed containment state, not a generic asset edit.
    status: Literal["Active", "Retired"] | None = None
    waf: str | None = None
    attributes: dict | None = None


class FindingCreate(BaseModel):
    id: str = Field(min_length=1, max_length=150)
    asset_id: str
    source: str = "manual"
    source_finding_id: str | None = None
    title: str
    cve: str | None = None
    cves: list[str] = Field(default_factory=list, max_length=100)
    severity: Severity
    state: Literal["Open", "In Progress", "Resolved", "Accepted Risk"] = "Open"
    first_seen: str | None = None
    last_seen: str | None = None
    due_at: str | None = None
    cvss: float | None = Field(None, ge=0, le=10)
    epss: float | None = Field(None, ge=0, le=1)
    kev: bool = False
    evidence: dict = Field(default_factory=dict)

    @field_validator("cve")
    @classmethod
    def canonicalize_cve(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            raise ValueError("CVE must use the CVE-YYYY-NNNN format")
        return normalized

    @field_validator("cves")
    @classmethod
    def canonicalize_cves(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            cve = value.strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ValueError("Each CVE must use the CVE-YYYY-NNNN format")
            if cve not in normalized:
                normalized.append(cve)
        return normalized


class ExceptionCreate(BaseModel):
    asset_id: str
    finding_id: str | None = None
    reason: str = Field(min_length=10, max_length=3000)
    expires_at: str


class FindingState(BaseModel):
    state: Literal["Open", "In Progress", "Resolved", "Accepted Risk"]


class ReviewDecision(BaseModel):
    decision: Literal["Approve", "Reject"]
    note: str = Field(min_length=3, max_length=1000)


class WorkflowCreate(BaseModel):
    kind: Literal["Rescan", "FalsePositive", "Remediation", "SLAReview"]
    asset_id: str | None = None
    finding_id: str | None = None
    payload: dict = Field(default_factory=dict)


class ContainmentRequest(BaseModel):
    asset_id: str
    action: Literal["Quarantine", "Release"]
    acknowledge_impact: bool = False
