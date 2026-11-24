"""Audit event construction, serialization, and chain verification."""

from __future__ import annotations

import hashlib
import json

from sqlalchemy.orm import Session

from backend.core.util import now
from backend.db.models import AuditChainHead, AuditEvent
from backend.repositories.audit import AuditRepository


def _digest(previous: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()


def record_event(
    session: Session, actor: dict | None, action: str, object_type: str, object_id=None, detail=None
) -> AuditEvent:
    """Append an ordered hash-linked record in the caller's transaction."""
    actor_id = actor["id"] if actor else None
    created = now()
    safe_detail = detail or {}
    repository = AuditRepository(session)
    head: AuditChainHead = repository.lock_chain_head()
    previous = head.entry_hash or ""
    payload = {
        "user_id": actor_id,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "detail": safe_detail,
        "created_at": created,
    }
    event = AuditEvent(
        user_id=actor_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        detail=json.dumps(safe_detail, sort_keys=True, separators=(",", ":")),
        created_at=created,
        previous_hash=previous,
        entry_hash=_digest(previous, payload),
    )
    repository.append(event, head)
    return event


def audit_events(session: Session, *, limit: int) -> dict:
    items = []
    for event, email in AuditRepository(session).recent(limit=limit):
        items.append(
            {
                "id": event.id,
                "user_id": event.user_id,
                "actor": email,
                "action": event.action,
                "object_type": event.object_type,
                "object_id": event.object_id,
                "detail": json.loads(event.detail or "{}"),
                "created_at": event.created_at,
                "previous_hash": event.previous_hash,
                "entry_hash": event.entry_hash,
            }
        )
    return {"items": items}


def verify_audit_chain(session: Session) -> dict:
    previous = ""
    rows = AuditRepository(session).all_ordered()
    for index, event in enumerate(rows, start=1):
        try:
            detail = json.loads(event.detail or "{}")
        except (TypeError, ValueError):
            return {"valid": False, "checked": index - 1, "eventId": event.id}
        payload = {
            "user_id": event.user_id,
            "action": event.action,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "detail": detail,
            "created_at": event.created_at,
        }
        expected = _digest(previous, payload)
        if event.previous_hash != previous or event.entry_hash != expected:
            return {"valid": False, "checked": index - 1, "eventId": event.id}
        previous = expected
    stored = AuditRepository(session).chain_head()
    return {"valid": stored == previous, "checked": len(rows), "headMatches": stored == previous}
