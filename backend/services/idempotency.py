"""Durable idempotency for local write operations with retry-safe responses."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.core.util import now
from backend.db.models import IdempotencyRecord

logger = logging.getLogger("sam.idempotency")


class IdempotencyConflict(Exception):
    """The key was reused for different input or its original request is still running."""


def request_digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def scoped_idempotency_hash(actor_id: int, operation: str, key: str) -> str:
    return hashlib.sha256(f"{actor_id}:{operation}:{key}".encode()).hexdigest()


def _decode_replay(record: IdempotencyRecord, request_hash: str) -> Any:
    try:
        stored = json.loads(record.response_body)
    except (TypeError, json.JSONDecodeError):
        raise IdempotencyConflict("The previous operation cannot be safely replayed") from None
    if not isinstance(stored, dict):
        raise IdempotencyConflict("The previous operation cannot be safely replayed")
    if stored.get("request_hash") != request_hash:
        raise IdempotencyConflict("Idempotency key was already used with different input")
    if record.response_status <= 0 or stored.get("state") != "completed":
        raise IdempotencyConflict("An operation with this key is still in progress")
    return stored.get("response")


def execute_idempotently(
    session: Session,
    *,
    actor: dict[str, Any],
    operation: str,
    idempotency_key: str,
    request_payload: Any,
    response_status: int,
    execute: Callable[[], Any],
) -> Any:
    """Claim a scoped key, atomically store a successful result, and replay retries.

    This helper is for database-local operations. Do not wrap external side effects here;
    providers require a persisted correlation/uncertain-outcome protocol of their own.
    """
    actor_id = int(actor["id"])
    hashed_key = scoped_idempotency_hash(actor_id, operation, idempotency_key)
    request_hash = request_digest(request_payload)
    existing = session.get(IdempotencyRecord, hashed_key)
    if existing is not None:
        return _decode_replay(existing, request_hash)

    claim = IdempotencyRecord(
        key=hashed_key,
        actor_id=actor_id,
        operation=operation,
        response_status=0,
        response_body=json.dumps(
            {"request_hash": request_hash, "state": "processing"}, sort_keys=True
        ),
        created_at=now(),
    )
    session.add(claim)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        concurrent = session.get(IdempotencyRecord, hashed_key)
        if concurrent is not None:
            return _decode_replay(concurrent, request_hash)
        raise IdempotencyConflict("A concurrent operation already claimed this key") from None

    try:
        response = execute()
        encoded_response = json.dumps(response, sort_keys=True, separators=(",", ":"))
        stored_claim = session.get(IdempotencyRecord, hashed_key)
        if stored_claim is None:
            raise IdempotencyConflict("Idempotency claim disappeared during the operation")
        stored_claim.response_status = response_status
        stored_claim.response_body = json.dumps(
            {
                "request_hash": request_hash,
                "state": "completed",
                "response": json.loads(encoded_response),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        session.commit()
        return response
    except Exception:
        session.rollback()
        marker = session.get(IdempotencyRecord, hashed_key)
        if marker is not None:
            session.delete(marker)
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()
                logger.exception("idempotency_claim_cleanup_failed", extra={"operation": operation})
        raise
