"""Environment-backed settings. Production requires explicit secrets and PostgreSQL."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_ENV = os.getenv("APP_ENV", "development").lower()
MODE = os.getenv("SAM_MODE", "qa" if APP_ENV in {"development", "test"} else APP_ENV).lower()
raw_database_url = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'sam.db'}")
if raw_database_url.startswith("postgres://"):
    raw_database_url = "postgresql+psycopg://" + raw_database_url.removeprefix("postgres://")
elif raw_database_url.startswith("postgresql://"):
    raw_database_url = "postgresql+psycopg://" + raw_database_url.removeprefix("postgresql://")
DATABASE_URL = raw_database_url
TOKEN_SECRET = os.getenv("SAM_TOKEN_SECRET", os.getenv("APP_SECRET_KEY", ""))
TOKEN_TTL_HOURS = max(1, int(os.getenv("SAM_TOKEN_TTL_HOURS", "1")))
ACCESS_TOKEN_TTL_MINUTES = max(1, int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "10")))
REFRESH_TOKEN_TTL_DAYS = max(1, int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "14")))
BOOTSTRAP_EMAIL = os.getenv("SAM_ADMIN_EMAIL", os.getenv("BOOTSTRAP_ADMIN_EMAIL", "")).lower()
BOOTSTRAP_PASSWORD = os.getenv("SAM_ADMIN_PASSWORD", os.getenv("BOOTSTRAP_ADMIN_PASSWORD", ""))
LOAD_SAMPLE_DATA = os.getenv("LOAD_SAMPLE_DATA", "false").lower() in {"1", "true", "yes"}
CORS_ORIGINS = [
    x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()
]
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(ROOT / "uploads"))).resolve()
MAX_UPLOAD_BYTES = max(1024, int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024))))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", str(APP_ENV == "production")).lower() in {
    "1",
    "true",
    "yes",
}
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:5173").rstrip("/")

# Connector credentials are supplied only by the deployment secret manager or .env.
# They are never stored in SAM tables or returned from an API endpoint.
QUALYS_BASE_URL = os.getenv("QUALYS_BASE_URL", "").rstrip("/")
QUALYS_USERNAME = os.getenv("QUALYS_USERNAME", "")
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD", "")
QUALYS_API_VERSION = os.getenv("QUALYS_API_VERSION", "6.0")
SERVICENOW_BASE_URL = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/")
SERVICENOW_USERNAME = os.getenv("SERVICENOW_USERNAME", "")
SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD", "")
SERVICENOW_TABLES = tuple(
    value.strip()
    for value in os.getenv("SERVICENOW_TABLES", "cmdb_ci_server,cmdb_ci_web_application").split(",")
    if value.strip()
)
SERVICENOW_EXPOSURE_FIELD = os.getenv("SERVICENOW_EXPOSURE_FIELD", "")
SERVICENOW_ENVIRONMENT_FIELD = os.getenv("SERVICENOW_ENVIRONMENT_FIELD", "environment")
SERVICENOW_CRITICALITY_FIELD = os.getenv("SERVICENOW_CRITICALITY_FIELD", "business_criticality")
SERVICENOW_TICKET_WRITE_ENABLED = os.getenv("SERVICENOW_TICKET_WRITE_ENABLED", "false").lower() in {
    "1",
    "true",
    "yes",
}
SERVICENOW_INCIDENT_TABLE = os.getenv("SERVICENOW_INCIDENT_TABLE", "incident")
SERVICENOW_TICKET_BASE_URL = (
    os.getenv("SERVICENOW_TICKET_BASE_URL") or SERVICENOW_BASE_URL
).rstrip("/")
SERVICENOW_TICKET_USERNAME = os.getenv("SERVICENOW_TICKET_USERNAME", "")
SERVICENOW_TICKET_PASSWORD = os.getenv("SERVICENOW_TICKET_PASSWORD", "")
AI_ANALYST_ENABLED = os.getenv("AI_ANALYST_ENABLED", "false").lower() in {"1", "true", "yes"}
AI_ANALYST_DATA_APPROVED = os.getenv("AI_ANALYST_DATA_APPROVED", "false").lower() in {
    "1",
    "true",
    "yes",
}
AI_ANALYST_API_KEY = os.getenv("AI_ANALYST_API_KEY", "")
AI_ANALYST_MODEL = os.getenv("AI_ANALYST_MODEL", "")
AI_ANALYST_BASE_URL = os.getenv("AI_ANALYST_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_ANALYST_MAX_OUTPUT_TOKENS = min(
    2000, max(100, int(os.getenv("AI_ANALYST_MAX_OUTPUT_TOKENS", "600")))
)
CISA_KEV_FEED_URL = os.getenv(
    "CISA_KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
CERTSPOTTER_BASE_URL = os.getenv("CERTSPOTTER_BASE_URL", "https://api.certspotter.com").rstrip("/")
CERTSPOTTER_API_TOKEN = os.getenv("CERTSPOTTER_API_TOKEN", "")
EXTERNAL_DISCOVERY_MAX_PAGES = min(
    500, max(1, int(os.getenv("EXTERNAL_DISCOVERY_MAX_PAGES", "100")))
)
INTEGRATION_TIMEOUT_SECONDS = min(60, max(2, int(os.getenv("INTEGRATION_TIMEOUT_SECONDS", "15"))))
INTEGRATION_MAX_PAGES = min(1000, max(1, int(os.getenv("INTEGRATION_MAX_PAGES", "100"))))
IDEMPOTENCY_RETENTION_DAYS = min(30, max(1, int(os.getenv("IDEMPOTENCY_RETENTION_DAYS", "7"))))
CELERY_TASK_ALWAYS_EAGER = os.getenv("CELERY_TASK_ALWAYS_EAGER", "false").lower() in {
    "1",
    "true",
    "yes",
}
if CELERY_TASK_ALWAYS_EAGER and APP_ENV not in {"development", "test"}:
    raise RuntimeError(
        "CELERY_TASK_ALWAYS_EAGER is restricted to development and test environments"
    )
