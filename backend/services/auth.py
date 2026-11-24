"""Authentication workflows and account/session policy."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import ACCESS_TOKEN_TTL_MINUTES
from backend.core.security import (
    hash_password,
    issue_token,
    needs_password_rehash,
    new_refresh_token,
    refresh_expiry,
    token_digest,
    verify_password,
)
from backend.core.util import now
from backend.db.models import PasswordResetToken, User
from backend.repositories.auth import AuthRepository
from backend.services.audit import record_event


class UserNotFound(Exception):
    """The requested account does not exist."""


class UserStatusConflict(Exception):
    """The account status change would violate account safety policy."""


def _user_data(user: User) -> dict:
    return {"id": user.id, "email": user.email, "role": user.role, "active": user.active}


def authenticate(session: Session, *, email: str, password: str) -> dict | None:
    """Authenticate and persist lockout state; invalid credentials return None."""
    repository = AuthRepository(session)
    user = repository.user_by_email(email.lower())
    if user is None:
        return None
    current_time = datetime.now(UTC)
    if user.locked_until:
        try:
            if datetime.fromisoformat(user.locked_until) > current_time:
                return None
        except ValueError:
            pass
    if not user.active or not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        user.locked_until = (
            (current_time + timedelta(minutes=15)).isoformat()
            if user.failed_login_count >= 5
            else None
        )
        # Failed-attempt state must survive the 401 response rollback.
        session.commit()
        return None
    if needs_password_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    session.flush()
    return _user_data(user)


def start_session(session: Session, user: dict) -> tuple[str, str]:
    repository = AuthRepository(session)
    access_token = issue_token(user)
    refresh_token = new_refresh_token()
    family_id = secrets.token_hex(16)
    created = datetime.now(UTC).isoformat()
    repository.access_session(
        token_digest(access_token),
        user["id"],
        family_id,
        (datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).isoformat(),
        created,
    )
    repository.refresh_session(
        token_digest(refresh_token), user["id"], family_id, refresh_expiry(), created
    )
    record_event(session, user, "login", "session")
    return access_token, refresh_token


def logout(session: Session, *, access_token: str, user: dict) -> None:
    repository = AuthRepository(session)
    digest = token_digest(access_token)
    access_session = repository.access_session_by_hash(digest)
    if access_session:
        access_session.revoked_at = now()
        if access_session.family_id:
            repository.revoke_refresh_family(access_session.family_id, now())
    record_event(session, user, "logout", "session")


def request_reset(session: Session, *, email: str) -> tuple[User | None, str | None]:
    repository = AuthRepository(session)
    user = repository.active_user_by_email(email.lower())
    if not user:
        return None, None
    raw = secrets.token_urlsafe(40)
    expires = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
    repository.reset_token(token_digest(raw), user.id, expires, now())
    session.flush()
    return user, raw


def discard_reset(session: Session, raw_token: str) -> None:
    token = session.get(PasswordResetToken, token_digest(raw_token))
    if token is not None:
        session.delete(token)


def confirm_reset(session: Session, *, raw_token: str, new_password: str) -> bool:
    repository = AuthRepository(session)
    digest = token_digest(raw_token)
    reset = repository.reset_by_hash(digest)
    if reset is None or reset.used_at is not None:
        return False
    try:
        expiry = datetime.fromisoformat(reset.expires_at)
    except ValueError:
        return False
    if expiry <= datetime.now(UTC):
        return False
    user = repository.user_by_id(reset.user_id)
    if user is None or not user.active:
        return False
    user.password_hash = hash_password(new_password)
    user.failed_login_count = 0
    user.locked_until = None
    reset.used_at = now()
    repository.revoke_user_sessions(user.id, now())
    record_event(session, _user_data(user), "password.reset", "user", str(user.id))
    return True


def rotate_refresh(session: Session, *, raw_token: str) -> tuple[dict, str, str] | None:
    """Rotate a refresh token; revoke-and-commit replay, expiry, and disabled accounts."""
    repository = AuthRepository(session)
    digest = token_digest(raw_token)
    row = repository.refresh_by_hash(digest)
    if row is None:
        return None
    if row.revoked_at or row.replaced_by_hash:
        repository.revoke_refresh_family(row.family_id, now())
        session.commit()
        return None
    try:
        expired = datetime.fromisoformat(row.expires_at) <= datetime.now(UTC)
    except ValueError:
        expired = True
    if expired:
        row.revoked_at = now()
        session.commit()
        return None
    user_model = repository.user_by_id(row.user_id)
    if user_model is None or not user_model.active:
        repository.revoke_refresh_family(row.family_id, now())
        session.commit()
        return None
    user = _user_data(user_model)
    next_refresh = new_refresh_token()
    next_hash = token_digest(next_refresh)
    row.revoked_at = now()
    row.replaced_by_hash = next_hash
    created = now()
    repository.refresh_session(next_hash, user["id"], row.family_id, refresh_expiry(), created)
    access_token = issue_token(user)
    repository.access_session(
        token_digest(access_token),
        user["id"],
        row.family_id,
        (datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).isoformat(),
        created,
    )
    record_event(session, user, "refresh.rotate", "session")
    return user, access_token, next_refresh


def create_user(session: Session, *, email: str, password: str, role: str, actor: dict) -> User:
    repository = AuthRepository(session)
    user = repository.create_user(
        email=email.lower(),
        password_hash=hash_password(password),
        role=role,
        created_at=now(),
    )
    record_event(session, actor, "user.create", "user", email.lower(), {"role": role})
    return user


def list_users(session: Session, *, limit: int, offset: int) -> dict:
    users, total = AuthRepository(session).users_page(limit, offset)
    return {
        "items": [_user_data(user) for user in users],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def set_user_active(session: Session, *, user_id: int, active: bool, actor: dict) -> dict:
    repository = AuthRepository(session)
    user = repository.user_by_id_for_update(user_id)
    if user is None:
        raise UserNotFound
    if user.id == actor["id"] and not active:
        raise UserStatusConflict("Administrators cannot deactivate their own account")
    if user.active == active:
        return _user_data(user)
    if (
        not active
        and user.role == "admin"
        and repository.active_administrator_count_for_update() <= 1
    ):
        raise UserStatusConflict("At least one active administrator must remain")

    user.active = active
    if not active:
        repository.revoke_user_sessions(user.id, now())
    else:
        user.failed_login_count = 0
        user.locked_until = None
    record_event(session, actor, "user.active", "user", str(user.id), {"active": active})
    session.flush()
    return _user_data(user)


def set_user_role(session: Session, *, user_id: int, role: str, actor: dict) -> dict:
    repository = AuthRepository(session)
    user = repository.user_by_id_for_update(user_id)
    if user is None:
        raise UserNotFound
    if user.id == actor["id"]:
        raise UserStatusConflict("Administrators cannot change their own role")
    if user.role == role:
        return _user_data(user)
    if user.active and user.role == "admin" and role != "admin":
        if repository.active_administrator_count_for_update() <= 1:
            raise UserStatusConflict("At least one active administrator must remain")

    old_role = user.role
    user.role = role
    repository.revoke_user_sessions(user.id, now())
    record_event(
        session,
        actor,
        "user.role",
        "user",
        str(user.id),
        {"old_role": old_role, "new_role": role},
    )
    session.flush()
    return _user_data(user)


def is_unique_user_error(error: IntegrityError) -> bool:
    """Identify a unique email collision without exposing vendor database text."""
    message = str(error.orig).lower()
    return "unique" in message or "duplicate" in message
