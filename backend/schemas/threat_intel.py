"""Threat intelligence response contracts."""

from pydantic import BaseModel, Field

from backend.schemas.common import AssetType


class ThreatIntelSummary(BaseModel):
    openFindingsWithCve: int = Field(ge=0)
    kevImpactedFindings: int = Field(ge=0)
    epssAtLeast50PercentFindings: int = Field(ge=0)
    feedStatus: str
    lastSyncAt: str | None = None
    lastSyncError: str | None = None
    recordsRead: int = Field(ge=0)
    recordsWritten: int = Field(ge=0)


class ThreatIntelItem(BaseModel):
    findingId: str
    cve: str
    title: str
    severity: str
    state: str
    dueAt: str | None = None
    assetId: str
    assetName: str
    assetType: AssetType
    classification: str
    criticality: str
    kevListed: bool | None = None
    kevDateAdded: str | None = None
    kevDueDate: str | None = None
    kevVendor: str | None = None
    kevProduct: str | None = None
    kevVulnerabilityName: str | None = None
    kevRequiredAction: str | None = None
    kevRansomwareUse: str | None = None
    kevCatalogVersion: str | None = None
    epssScore: float | None = Field(None, ge=0, le=1)
    epssPercentile: float | None = Field(None, ge=0, le=1)
    epssDate: str | None = None
    threatIntelUpdatedAt: str | None = None


class ThreatIntelPage(BaseModel):
    summary: ThreatIntelSummary
    items: list[ThreatIntelItem]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)
    source: str = "CISA KEV and FIRST EPSS"
    interpretation: str = (
        "CISA KEV records confirmed past exploitation; EPSS estimates population-level "
        "exploitation likelihood over the next 30 days. Neither alone is a complete asset risk score."
    )
