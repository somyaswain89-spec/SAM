"""SQLAlchemy engine, request-scoped sessions, and migration readiness checks."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import DATABASE_URL, ROOT


def _build_engine() -> Engine:
    options: dict = {"pool_pre_ping": True, "pool_recycle": 1800}
    if DATABASE_URL.startswith("sqlite:"):
        options["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if DATABASE_URL in {"sqlite://", "sqlite:///:memory:"}:
            from sqlalchemy.pool import StaticPool

            options["poolclass"] = StaticPool
    return create_engine(DATABASE_URL, **options)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency with explicit commit/rollback and deterministic close."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def initialize_schema() -> None:
    """Require the latest Alembic schema; never create or upgrade tables at startup."""
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    with engine.connect() as conn:
        if engine.dialect.name == "sqlite":
            exists = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'")
            ).first()
        else:
            exists = conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar()
        current_revision = (
            MigrationContext.configure(conn).get_current_revision() if exists else None
        )
    if not exists:
        raise RuntimeError(
            "Database schema is missing. Apply Alembic migrations before starting SAM."
        )
    config = Config(str(ROOT / "alembic.ini"))
    head_revision = ScriptDirectory.from_config(config).get_current_head()
    if current_revision != head_revision:
        raise RuntimeError(
            "Database migrations are not current. Apply Alembic upgrades before startup."
        )
