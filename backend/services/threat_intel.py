"""Present feed-enriched findings and their impacted assets."""

from sqlalchemy.orm import Session

from backend.repositories.threat_intel import ThreatIntelRepository


def list_threat_intelligence(
    session: Session,
    *,
    entity: str | None = None,
    cve: str | None = None,
    kev_only: bool = False,
    min_epss: float | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    repository = ThreatIntelRepository(session)
    items, total = repository.list_impacted_findings(
        entity=entity,
        cve=cve,
        kev_only=kev_only,
        min_epss=min_epss,
        limit=limit,
        offset=offset,
    )
    return {
        "summary": repository.summary(entity),
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
