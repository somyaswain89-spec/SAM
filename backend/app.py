"""SAM FastAPI application composition and HTTP cross-cutting controls."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import cast
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ExceptionHandler

from backend.api import (
    analyst,
    assets,
    attack_paths,
    audit,
    auth,
    compliance,
    dashboard,
    exposure,
    external_discovery,
    findings,
    governance,
    imports,
    integrations,
    reports,
    risk,
    threats,
)
from backend.core.config import (
    APP_ENV,
    BOOTSTRAP_EMAIL,
    BOOTSTRAP_PASSWORD,
    COOKIE_SECURE,
    CORS_ORIGINS,
    DATABASE_URL,
    LOAD_SAMPLE_DATA,
    MODE,
    ROOT,
    TOKEN_SECRET,
)
from backend.core.database import SessionLocal, engine, initialize_schema
from backend.core.limiter import limiter
from backend.core.logging import configure_logging
from backend.core.security import hash_password
from backend.core.util import now
from backend.db.models import User
from backend.schemas.health import LivenessRead, ReadinessRead

logger = logging.getLogger("sam.api")
configure_logging()
routers = [
    auth.router,
    assets.router,
    findings.router,
    dashboard.router,
    compliance.router,
    governance.router,
    exposure.router,
    external_discovery.router,
    threats.router,
    attack_paths.router,
    integrations.router,
    audit.router,
    risk.router,
    reports.router,
    analyst.router,
    imports.router,
    imports.exports_router,
]


def _validate_production_origins(origins: list[str]) -> None:
    if not origins:
        raise RuntimeError("Production requires an explicit HTTPS CORS origin allowlist")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        ):
            raise RuntimeError("Production CORS origins must be explicit HTTPS origins")


def seed_qa_data() -> None:
    """Load deterministic fictional data only when explicitly enabled for QA."""
    if MODE not in {"demo", "qa", "development", "test"} or not LOAD_SAMPLE_DATA:
        return
    from backend.qa.seed import load_qa_data

    load_qa_data()


def _ensure_bootstrap_user() -> None:
    if not BOOTSTRAP_EMAIL or not BOOTSTRAP_PASSWORD:
        if APP_ENV == "production":
            raise RuntimeError("Configure bootstrap credentials before first production startup")
        return
    with SessionLocal() as session:
        if session.scalar(select(User.id).limit(1)):
            return
        session.add(
            User(
                email=BOOTSTRAP_EMAIL.lower(),
                password_hash=hash_password(BOOTSTRAP_PASSWORD),
                role="admin",
                created_at=now(),
            )
        )
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            # Multiple API instances may race on first deployment. A committed user is fine.
            if session.scalar(select(User.id).limit(1)) is None:
                raise


@asynccontextmanager
async def lifespan(_: FastAPI):
    if APP_ENV == "production":
        if not DATABASE_URL.startswith("postgresql+"):
            raise RuntimeError("Production must use PostgreSQL")
        if len(TOKEN_SECRET) < 32:
            raise RuntimeError("Production requires a signing secret of at least 32 characters")
        if not COOKIE_SECURE:
            raise RuntimeError("Production refresh cookies must be Secure")
        if LOAD_SAMPLE_DATA:
            raise RuntimeError("Sample data must be disabled in production")
        _validate_production_origins(CORS_ORIGINS)
    initialize_schema()
    _ensure_bootstrap_user()
    seed_qa_data()
    yield


def create_app() -> FastAPI:
    docs_enabled = APP_ENV != "production"
    application = FastAPI(
        title="SAM Security Exposure Platform API",
        version="2.1.0",
        docs_url="/api/v1/docs" if docs_enabled else None,
        openapi_url="/api/v1/openapi.json" if docs_enabled else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.state.limiter = limiter
    application.add_exception_handler(
        RateLimitExceeded, cast(ExceptionHandler, _rate_limit_exceeded_handler)
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "Idempotency-Key",
            "X-CSRF-Token",
        ],
        expose_headers=["X-Request-ID"],
    )

    for router in routers:
        application.include_router(router, prefix="/api/v1")
        # Temporary compatibility aliases keep existing deployments and QA clients working.
        application.include_router(router, prefix="/api", include_in_schema=False)

    @application.middleware("http")
    async def security_and_request_logging(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        if APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        logger.info(
            "api_request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        return response

    @application.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        message = exc.detail if isinstance(exc.detail, str) else "Request could not be completed"
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": f"http_{exc.status_code}",
                    "message": message,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
            headers=exc.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Do not include submitted values in an error response or logs.
        errors = [
            {
                "loc": error.get("loc", []),
                "type": error.get("type", "invalid"),
                "msg": error.get("msg", "Invalid value"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed",
                    "details": errors,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "unhandled_api_error", extra={"request_id": request_id, "path": request.url.path}
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "The request could not be completed",
                    "request_id": request_id,
                }
            },
        )

    @application.get("/health/live", tags=["operations"], response_model=LivenessRead)
    def liveness():
        return {"status": "alive"}

    @application.get("/health/ready", tags=["operations"], response_model=ReadinessRead)
    def readiness():
        with engine.connect() as db:
            db.exec_driver_sql("SELECT 1")
        return {"status": "ready", "database": "connected", "mode": MODE}

    @application.get("/api/v1/health", tags=["operations"], response_model=ReadinessRead)
    def health():
        with engine.connect() as db:
            db.exec_driver_sql("SELECT 1")
        return {"status": "ok", "mode": MODE, "database": "connected"}

    frontend_dist = ROOT / "frontend" / "dist"
    if frontend_dist.exists():
        application.mount(
            "/assets", StaticFiles(directory=frontend_dist / "assets"), name="frontend-assets"
        )

        @application.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            if path.startswith("api/") or path.startswith("health/"):
                return JSONResponse(
                    status_code=404,
                    content={"error": {"code": "not_found", "message": "Resource not found"}},
                )
            return FileResponse(frontend_dist / "index.html", media_type="text/html")
    else:

        @application.get("/", include_in_schema=False)
        def frontend_legacy():
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "frontend_not_built",
                        "message": "Start the Vite client with `npm run dev` or build frontend/dist.",
                    }
                },
            )

    return application


app = create_app()
