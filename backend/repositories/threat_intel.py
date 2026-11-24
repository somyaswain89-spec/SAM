"""Persisted threat-feed and impacted-finding queries."""

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from backend.db.models import Asset, Finding, FindingCVE, SyncRun, ThreatIntelRecord

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class ThreatIntelRepository:
    def __init__(self, session: Session):
        self.session = session

    def list_impacted_findings(
        self,
        *,
        entity: str | None = None,
        cve: str | None = None,
        kev_only: bool = False,
        min_epss: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        conditions: list[ColumnElement[bool]] = [
            Finding.state.in_(("Open", "In Progress")),
        ]
        if entity:
            conditions.append(Asset.kind == entity)
        if cve:
            conditions.append(FindingCVE.cve.ilike(f"%{cve}%"))
        if kev_only:
            conditions.append(ThreatIntelRecord.kev_listed.is_(True))
        if min_epss is not None:
            conditions.append(ThreatIntelRecord.epss_score >= min_epss)

        total = (
            self.session.scalar(
                select(func.count(FindingCVE.cve))
                .select_from(Finding)
                .join(Asset, Asset.id == Finding.asset_id)
                .join(FindingCVE, FindingCVE.finding_id == Finding.id)
                .outerjoin(ThreatIntelRecord, ThreatIntelRecord.cve == FindingCVE.cve)
                .where(*conditions)
            )
            or 0
        )
        statement = (
            select(Finding, Asset, FindingCVE.cve, ThreatIntelRecord)
            .join(Asset, Asset.id == Finding.asset_id)
            .join(FindingCVE, FindingCVE.finding_id == Finding.id)
            .outerjoin(ThreatIntelRecord, ThreatIntelRecord.cve == FindingCVE.cve)
            .where(*conditions)
            .order_by(
                case((ThreatIntelRecord.kev_listed.is_(True), 0), else_=1),
                ThreatIntelRecord.epss_score.desc().nulls_last(),
                case(SEVERITY_ORDER, value=Finding.severity, else_=5),
                Finding.due_at.asc().nulls_last(),
                Finding.id,
            )
            .limit(limit)
            .offset(offset)
        )
        rows = []
        for finding, asset, cve_value, intel in self.session.execute(statement).all():
            rows.append(
                {
                    "findingId": finding.id,
                    "cve": cve_value,
                    "title": finding.title,
                    "severity": finding.severity,
                    "state": finding.state,
                    "dueAt": finding.due_at,
                    "assetId": asset.id,
                    "assetName": asset.name,
                    "assetType": asset.kind,
                    "classification": asset.classification,
                    "criticality": asset.criticality,
                    "kevListed": bool(intel.kev_listed) if intel else None,
                    "kevDateAdded": intel.kev_date_added if intel else None,
                    "kevDueDate": intel.kev_due_date if intel else None,
                    "kevVendor": intel.kev_vendor if intel else None,
                    "kevProduct": intel.kev_product if intel else None,
                    "kevVulnerabilityName": intel.kev_vulnerability_name if intel else None,
                    "kevRequiredAction": intel.kev_required_action if intel else None,
                    "kevRansomwareUse": intel.kev_ransomware_use if intel else None,
                    "kevCatalogVersion": intel.kev_catalog_version if intel else None,
                    "epssScore": intel.epss_score if intel else None,
                    "epssPercentile": intel.epss_percentile if intel else None,
                    "epssDate": intel.epss_date if intel else None,
                    "threatIntelUpdatedAt": intel.updated_at if intel else None,
                }
            )
        return rows, int(total)

    def records_for_cves(self, cves: set[str]) -> dict[str, ThreatIntelRecord]:
        normalized = {cve.upper() for cve in cves if cve}
        if not normalized:
            return {}
        records = self.session.scalars(
            select(ThreatIntelRecord).where(func.upper(ThreatIntelRecord.cve).in_(normalized))
        ).all()
        return {record.cve.upper(): record for record in records}

    def summary(self, entity: str | None = None) -> dict:
        conditions: list[ColumnElement[bool]] = [
            Finding.state.in_(("Open", "In Progress")),
        ]
        if entity:
            conditions.append(Asset.kind == entity)
        total, kev_count, high_epss = self.session.execute(
            select(
                func.count(func.distinct(Finding.id)),
                func.coalesce(
                    func.count(
                        func.distinct(
                            case((ThreatIntelRecord.kev_listed.is_(True), Finding.id), else_=None)
                        )
                    ),
                    0,
                ),
                func.coalesce(
                    func.count(
                        func.distinct(
                            case((ThreatIntelRecord.epss_score >= 0.5, Finding.id), else_=None)
                        )
                    ),
                    0,
                ),
            )
            .select_from(Finding)
            .join(Asset, Asset.id == Finding.asset_id)
            .join(FindingCVE, FindingCVE.finding_id == Finding.id)
            .outerjoin(ThreatIntelRecord, ThreatIntelRecord.cve == FindingCVE.cve)
            .where(*conditions)
        ).one()
        latest_run = self.session.scalar(
            select(SyncRun)
            .where(SyncRun.source == "threat_intel")
            .order_by(SyncRun.started_at.desc(), SyncRun.id)
            .limit(1)
        )
        return {
            "openFindingsWithCve": int(total or 0),
            "kevImpactedFindings": int(kev_count or 0),
            "epssAtLeast50PercentFindings": int(high_epss or 0),
            "feedStatus": latest_run.status if latest_run else "never_synced",
            "lastSyncAt": latest_run.finished_at if latest_run else None,
            "lastSyncError": latest_run.error
            if latest_run and latest_run.status == "failed"
            else None,
            "recordsRead": latest_run.records_read if latest_run else 0,
            "recordsWritten": latest_run.records_written if latest_run else 0,
        }
