"""Deterministic fictional records for isolated demo and QA environments."""

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.core.database import SessionLocal
from backend.core.util import now
from backend.db.models import Asset, Finding, FindingCVE, ZeroDaySignal


def load_qa_data() -> None:
    created = now()
    assets = [
        Asset(
            id="WEB-1042",
            name="customer-portal.acme.test",
            kind="Website",
            classification="External facing",
            owner="Digital Experience",
            environment="Production",
            criticality="Critical",
            compliance=72,
            status="Active",
            waf="Protected",
            attributes=json.dumps({"depends_on": ["SRV-2201"]}),
            created_at=created,
            updated_at=created,
        ),
        Asset(
            id="WEB-1048",
            name="staff.acme.test",
            kind="Website",
            classification="Internal facing",
            owner="Corporate IT",
            environment="Production",
            criticality="High",
            compliance=91,
            status="Active",
            waf="Unknown",
            attributes="{}",
            created_at=created,
            updated_at=created,
        ),
        Asset(
            id="WEB-1071",
            name="api.acme.test",
            kind="Website",
            classification="External facing",
            owner="Platform Engineering",
            environment="Production",
            criticality="Critical",
            compliance=64,
            status="Active",
            waf="Unverified",
            attributes="{}",
            created_at=created,
            updated_at=created,
        ),
        Asset(
            id="SRV-2201",
            name="prod-app-01",
            kind="Server",
            classification="External facing",
            owner="Platform Engineering",
            environment="Production",
            criticality="Critical",
            compliance=68,
            status="Active",
            attributes=json.dumps({"depends_on": ["SRV-2208"]}),
            created_at=created,
            updated_at=created,
        ),
        Asset(
            id="SRV-2208",
            name="corp-ad-02",
            kind="Server",
            classification="Internal facing",
            owner="Corporate IT",
            environment="Production",
            criticality="Critical",
            compliance=88,
            status="Active",
            attributes="{}",
            created_at=created,
            updated_at=created,
        ),
        Asset(
            id="SRV-2233",
            name="analytics-stage-03",
            kind="Server",
            classification="Internal facing",
            owner="Data Platform",
            environment="Staging",
            criticality="Medium",
            compliance=43,
            status="Active",
            attributes="{}",
            created_at=created,
            updated_at=created,
        ),
    ]
    raw_findings = [
        (
            "FND-8012",
            "WEB-1042",
            "Remote code execution in runtime",
            "CVE-2026-1842",
            "Critical",
            0.91,
            True,
            -2,
        ),
        (
            "FND-8016",
            "WEB-1071",
            "Authentication bypass",
            "CVE-2026-2031",
            "Critical",
            0.78,
            True,
            3,
        ),
        (
            "FND-7894",
            "SRV-2201",
            "Kernel privilege escalation",
            "CVE-2026-0441",
            "High",
            0.66,
            False,
            14,
        ),
        (
            "FND-7880",
            "SRV-2233",
            "Missing security update",
            "CVE-2026-1322",
            "High",
            0.18,
            False,
            9,
        ),
    ]
    findings = [
        Finding(
            id=finding_id,
            asset_id=asset_id,
            title=title,
            cve=cve,
            cve_links=[FindingCVE(cve=cve)],
            severity=severity,
            first_seen=created,
            last_seen=created,
            due_at=(datetime.now(UTC) + timedelta(days=due_days)).isoformat(),
            evidence=json.dumps({"epss": epss, "kev": kev}),
            created_at=created,
            updated_at=created,
        )
        for finding_id, asset_id, title, cve, severity, epss, kev, due_days in raw_findings
    ]
    signal = ZeroDaySignal(
        id="ZD-QA-001",
        title="Undisclosed runtime behavior candidate",
        severity="Critical",
        confidence="Medium",
        status="Needs validation",
        source="QA synthetic signal",
        evidence=json.dumps({"finding_ids": ["FND-8012", "FND-8016"]}),
        created_at=created,
    )
    with SessionLocal() as session:
        if session.scalar(select(Asset.id).limit(1)):
            return
        session.add_all([*assets, *findings, signal])
        session.commit()
