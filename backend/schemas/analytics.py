"""Typed response contracts for risk, compliance, exposure, and reports."""

from typing import Any

from pydantic import BaseModel, Field

from backend.schemas.common import AssetRead, AssetType, Exposure, FindingRead, Severity


class DashboardRead(BaseModel):
    assets: int = Field(ge=0)
    websites: int = Field(ge=0)
    servers: int = Field(ge=0)
    openFindings: int = Field(ge=0)
    bySeverity: dict[str, int]
    compliancePercent: float = Field(ge=0, le=100)
    nonCompliantAssets: int = Field(ge=0)
    websitesWafProtected: int = Field(ge=0)
    websitesTotal: int = Field(ge=0)
    generatedAt: str


class RiskFactorsRead(BaseModel):
    severity: Severity
    externalFacing: bool
    criticalAsset: bool
    kev: bool | None = None
    epss: float | None = None
    threatIntelSource: str | None = None


class RiskPriorityRead(FindingRead):
    asset_name: str
    asset_kind: AssetType
    criticality: str
    classification: Exposure
    compliance: int | None = None
    riskScore: int = Field(ge=0, le=100)
    kev: bool | None = None
    epss: float | None = None
    threatIntelSource: str | None = None
    riskFactors: RiskFactorsRead


class RiskPriorityResponse(BaseModel):
    items: list[RiskPriorityRead]
    sortRule: str
    scoreModel: str


class ComplianceSummaryRead(BaseModel):
    assetsEvaluated: int = Field(ge=0)
    averagePercent: float | None = Field(None, ge=0, le=100)
    targetPercent: int = Field(ge=1, le=100)
    belowTarget: int = Field(ge=0)
    unknownAssets: int = Field(ge=0)
    method: str
    calculatedAt: str


class ComplianceAssetRead(BaseModel):
    id: str
    name: str
    kind: str
    owner: str | None = None
    compliance: int | None = Field(None, ge=0, le=100)


class ComplianceAssetsRead(BaseModel):
    items: list[ComplianceAssetRead]
    sortRule: str


class ExposureClassificationCount(BaseModel):
    classification: str
    kind: str
    n: int = Field(ge=0)


class ExposureWafCount(BaseModel):
    waf: str | None = None
    n: int = Field(ge=0)


class ExposureSummaryRead(BaseModel):
    classificationCounts: list[ExposureClassificationCount]
    wafCounts: list[ExposureWafCount]
    verificationNote: str


class ExternalAssetRead(AssetRead):
    open_findings: int = Field(ge=0)


class ExternalAssetsRead(BaseModel):
    items: list[ExternalAssetRead]
    source: str


class AttackPathEndpoint(BaseModel):
    id: str
    name: str


class AttackPathRead(BaseModel):
    from_: AttackPathEndpoint = Field(alias="from")
    to: AttackPathEndpoint
    relationship: str
    source: str
    verified: bool
    riskScore: int = Field(ge=0)


class AttackPathsRead(BaseModel):
    items: list[AttackPathRead]
    total: int = Field(ge=0)
    note: str


class SLAForecastItem(BaseModel):
    findingId: str
    title: str
    assetId: str
    dueAt: str
    daysRemaining: float


class SLAForecastRead(BaseModel):
    breached: list[SLAForecastItem]
    atRiskNext7Days: list[SLAForecastItem]
    evaluatedAt: str
    forecastMethod: str


class ExecutiveReportRead(BaseModel):
    reportType: str
    generatedAt: str
    dashboard: DashboardRead
    compliance: ComplianceSummaryRead
    topFindings: list[FindingRead]


class ErrorDetail(BaseModel):
    code: str | None = None
    message: str | None = None
    request_id: str | None = None
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
