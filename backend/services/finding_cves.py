"""Normalize and persist the CVEs associated with findings."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.db.models import Finding, FindingCVE

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize_cves(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        cve = value.strip().upper()
        if cve and _CVE_PATTERN.fullmatch(cve) and cve not in seen:
            normalized.append(cve)
            seen.add(cve)
    return normalized


def replace_finding_cves(session: Session, finding: Finding, values: Iterable[object]) -> list[str]:
    cves = normalize_cves(values)
    session.execute(delete(FindingCVE).where(FindingCVE.finding_id == finding.id))
    session.add_all(FindingCVE(finding_id=finding.id, cve=cve) for cve in cves)
    # Keep the legacy primary CVE column populated for existing integrations and API clients.
    finding.cve = cves[0] if cves else None
    return cves


def cves_by_finding_id(session: Session, finding_ids: Iterable[str]) -> dict[str, list[str]]:
    ids = list(dict.fromkeys(finding_ids))
    result: dict[str, list[str]] = defaultdict(list)
    if not ids:
        return result
    for start in range(0, len(ids), 800):
        chunk = ids[start : start + 800]
        rows = session.execute(
            select(FindingCVE.finding_id, FindingCVE.cve)
            .where(FindingCVE.finding_id.in_(chunk))
            .order_by(FindingCVE.finding_id, FindingCVE.cve)
        ).all()
        for finding_id, cve in rows:
            result[finding_id].append(cve)
        # Keep compatibility with rows written by older versions of the application.
        for finding_id, cve in session.execute(
            select(Finding.id, Finding.cve).where(Finding.id.in_(chunk), Finding.cve.is_not(None))
        ).all():
            normalized = normalize_cves([cve])
            if normalized and normalized[0] not in result[finding_id]:
                result[finding_id].append(normalized[0])
    return result


def all_finding_cves(session: Session) -> list[str]:
    """Return normalized CVEs from links and the legacy column without duplicates."""
    values = set(session.scalars(select(FindingCVE.cve)).all())
    values.update(
        normalize_cves(session.scalars(select(Finding.cve).where(Finding.cve.is_not(None))).all())
    )
    return sorted(values)
