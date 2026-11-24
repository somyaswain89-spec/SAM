"""Central password, access-token and route-authorization services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session as DatabaseSession

from backend.core.config import ACCESS_TOKEN_TTL_MINUTES, MODE, REFRESH_TOKEN_TTL_DAYS, TOKEN_SECRET
from backend.core.database import get_db
from backend.repositories.auth import AuthRepository

bearer = HTTPBearer(auto_error=False)
password_hasher = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16
)
JWT_ISSUER = "sam-security-platform"
JWT_AUDIENCE = "sam-api"
_EPHEMERAL_DEV_SECRET = secrets.token_urlsafe(48)


def _jwt_secret() -> str:
    if TOKEN_SECRET:
        return TOKEN_SECRET
    if MODE in {"qa", "demo", "development", "test"}:
        # Local-only sessions intentionally expire when the process restarts.
        return _EPHEMERAL_DEV_SECRET
    raise HTTPException(status_code=503, detail="Authentication is not configured")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    """Verify Argon2id hashes and upgrade legacy PBKDF2 hashes at login."""
    if encoded.startswith("$argon2id$"):
        try:
            return password_hasher.verify(encoded, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    # Existing SAM accounts used PBKDF2-SHA256; retain verification for migration.
    try:
        raw = base64.urlsafe_b64decode(encoded.encode())
        if len(raw) < 48:
            return False
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 310_000)
        return hmac.compare_digest(raw[16:], key)
    except (ValueError, TypeError):
        return False


def needs_password_rehash(encoded: str) -> bool:
    return not encoded.startswith("$argon2id$") or password_hasher.check_needs_rehash(encoded)


def issue_token(user: dict) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(user["id"]),
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
        "jti": secrets.token_urlsafe(24),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(claims, _jwt_secret(), algorithm="HS256")


def current_user(
    auth: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: DatabaseSession = Depends(get_db),
):
    if not auth:
        raise HTTPException(
            status_code=401, detail="Bearer token required", headers={"WWW-Authenticate": "Bearer"}
        )
    try:
        claims = jwt.decode(
            auth.credentials,
            _jwt_secret(),
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )
        user_id = int(claims["sub"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    user = AuthRepository(session).user_for_access_token(
        user_id, hashlib.sha256(auth.credentials.encode()).hexdigest()
    )
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Session expired or account disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"id": user.id, "email": user.email, "role": user.role, "active": user.active}


def require_roles(*roles: str):
    def check(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return check


def new_refresh_token() -> str:
    return secrets.token_urlsafe(64)


def refresh_expiry() -> str:
    return (datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_TTL_DAYS)).isoformat()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
