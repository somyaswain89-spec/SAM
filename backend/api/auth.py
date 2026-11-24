"""HTTP endpoints for secure authentication and account workflows."""

import hmac
import secrets
import smtplib

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import (
    ACCESS_TOKEN_TTL_MINUTES,
    COOKIE_SECURE,
    PUBLIC_BASE_URL,
    REFRESH_TOKEN_TTL_DAYS,
    SMTP_FROM,
    SMTP_HOST,
)
from backend.core.database import get_db
from backend.core.limiter import limiter
from backend.core.security import bearer, current_user, require_roles
from backend.integrations.email import EmailDeliveryNotConfigured, send_password_reset
from backend.schemas.auth import (
    AccountCreated,
    AuthStatus,
    SessionResponse,
    UserActiveUpdate,
    UserPage,
    UserRead,
    UserRoleUpdate,
)
from backend.schemas.common import CreateUser, Login, PasswordResetConfirm, PasswordResetRequest
from backend.services.auth import (
    UserNotFound,
    UserStatusConflict,
    authenticate,
    confirm_reset,
    discard_reset,
    is_unique_user_error,
    list_users,
    request_reset,
    rotate_refresh,
    start_session,
)
from backend.services.auth import (
    create_user as create_user_service,
)
from backend.services.auth import (
    logout as logout_service,
)
from backend.services.auth import (
    set_user_active as set_user_active_service,
)
from backend.services.auth import (
    set_user_role as set_user_role_service,
)
from backend.services.idempotency import IdempotencyConflict, execute_idempotently

router = APIRouter(prefix="/auth", tags=["authentication"])


def _session_response(user: dict, access_token: str, refresh_token: str) -> dict:
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_TTL_MINUTES * 60,
        "user": {"id": user["id"], "email": user["email"], "role": user["role"]},
    }


@router.post("/password-reset/request", status_code=202, response_model=AuthStatus)
@limiter.limit("5/minute")
def request_password_reset(
    request: Request,
    body: PasswordResetRequest,
    session: Session = Depends(get_db),
):
    if not SMTP_HOST or not SMTP_FROM:
        raise HTTPException(503, "Password reset email delivery is not configured")
    user, raw_token = request_reset(session, email=body.email)
    if not user or not raw_token:
        return {"status": "If the account exists, a reset message has been queued."}
    # Persist before dispatch so the recipient cannot receive an uncommitted token.
    session.commit()
    try:
        send_password_reset(user.email, f"{PUBLIC_BASE_URL}/reset-password?token={raw_token}")
    except EmailDeliveryNotConfigured:
        discard_reset(session, raw_token)
        session.commit()
        raise HTTPException(503, "Password reset email delivery is not configured") from None
    except (OSError, smtplib.SMTPException):
        discard_reset(session, raw_token)
        session.commit()
        raise HTTPException(
            503, "Password reset email delivery is temporarily unavailable"
        ) from None
    return {"status": "If the account exists, a reset message has been queued."}


@router.post("/password-reset/confirm", response_model=AuthStatus)
@limiter.limit("10/minute")
def confirm_password_reset(
    request: Request,
    body: PasswordResetConfirm,
    session: Session = Depends(get_db),
):
    if not confirm_reset(session, raw_token=body.token, new_password=body.new_password):
        raise HTTPException(400, "Reset token is invalid or expired")
    return {"status": "Password changed; sign in again."}


@router.post("/login", response_model=SessionResponse)
@limiter.limit("20/minute")
def login(request: Request, body: Login, response: Response, session: Session = Depends(get_db)):
    user = authenticate(session, email=body.email, password=body.password)
    if user is None:
        raise HTTPException(401, "Invalid email or password")
    access_token, refresh_token = start_session(session, user)
    set_refresh_cookies(response, refresh_token)
    return _session_response(user, access_token, refresh_token)


@router.get("/me", response_model=UserRead)
def me(user=Depends(current_user)):
    return user


@router.post("/logout", response_model=AuthStatus)
def logout(
    response: Response,
    auth: HTTPAuthorizationCredentials | None = Depends(bearer),
    user=Depends(current_user),
    session: Session = Depends(get_db),
):
    if auth is None:
        raise HTTPException(401, "Bearer token required")
    logout_service(session, access_token=auth.credentials, user=user)
    clear_refresh_cookies(response)
    return {"status": "signed_out"}


def set_refresh_cookies(response: Response, refresh: str):
    response.set_cookie(
        "sam_refresh",
        refresh,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/api/v1/auth",
        max_age=REFRESH_TOKEN_TTL_DAYS * 86400,
    )
    response.set_cookie(
        "sam_csrf",
        # This is a double-submit CSRF token and is intentionally readable by the browser.
        secrets.token_urlsafe(32),
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
        max_age=REFRESH_TOKEN_TTL_DAYS * 86400,
    )


def clear_refresh_cookies(response: Response):
    response.delete_cookie(
        "sam_refresh", path="/api/v1/auth", secure=COOKIE_SECURE, httponly=True, samesite="strict"
    )
    response.delete_cookie("sam_csrf", path="/", secure=COOKIE_SECURE, samesite="strict")


@router.post("/refresh", response_model=SessionResponse)
@limiter.limit("30/minute")
def refresh_access(request: Request, response: Response, session: Session = Depends(get_db)):
    refresh = request.cookies.get("sam_refresh")
    csrf_cookie = request.cookies.get("sam_csrf", "")
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if (
        not refresh
        or not csrf_cookie
        or not csrf_header
        or not hmac.compare_digest(csrf_cookie, csrf_header)
    ):
        clear_refresh_cookies(response)
        raise HTTPException(401, "Refresh session is unavailable")
    rotated = rotate_refresh(session, raw_token=refresh)
    if rotated is None:
        clear_refresh_cookies(response)
        raise HTTPException(401, "Refresh session is unavailable")
    user, access_token, next_refresh = rotated
    set_refresh_cookies(response, next_refresh)
    return _session_response(user, access_token, next_refresh)


@router.post("/users", status_code=201, response_model=AccountCreated)
def create_user(
    body: CreateUser,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    user=Depends(require_roles("admin")),
    session: Session = Depends(get_db),
):
    try:

        def create_account() -> dict:
            created = create_user_service(
                session,
                email=body.email,
                password=body.password,
                role=body.role,
                actor=user,
            )
            return {"email": created.email, "role": created.role}

        return execute_idempotently(
            session,
            actor=user,
            operation="auth.users.create",
            idempotency_key=idempotency_key,
            request_payload=body.model_dump(),
            response_status=201,
            execute=create_account,
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except IntegrityError as error:
        session.rollback()
        if is_unique_user_error(error):
            raise HTTPException(409, "Email already exists") from None
        raise


@router.get("/users", response_model=UserPage)
def get_users(
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(require_roles("admin")),
    session: Session = Depends(get_db),
):
    return list_users(session, limit=limit, offset=offset)


@router.patch("/users/{user_id}/active", response_model=UserRead)
def set_user_active(
    user_id: int,
    body: UserActiveUpdate,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    actor=Depends(require_roles("admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=actor,
            operation="auth.users.active",
            idempotency_key=idempotency_key,
            request_payload={"user_id": user_id, "active": body.active},
            response_status=200,
            execute=lambda: set_user_active_service(
                session, user_id=user_id, active=body.active, actor=actor
            ),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except UserNotFound:
        raise HTTPException(404, "User not found") from None
    except UserStatusConflict as exc:
        raise HTTPException(409, str(exc)) from None


@router.patch("/users/{user_id}/role", response_model=UserRead)
def set_user_role(
    user_id: int,
    body: UserRoleUpdate,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    actor=Depends(require_roles("admin")),
    session: Session = Depends(get_db),
):
    try:
        return execute_idempotently(
            session,
            actor=actor,
            operation="auth.users.role",
            idempotency_key=idempotency_key,
            request_payload={"user_id": user_id, "role": body.role},
            response_status=200,
            execute=lambda: set_user_role_service(
                session, user_id=user_id, role=body.role, actor=actor
            ),
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except UserNotFound:
        raise HTTPException(404, "User not found") from None
    except UserStatusConflict as exc:
        raise HTTPException(409, str(exc)) from None
