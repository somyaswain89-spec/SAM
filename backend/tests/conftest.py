import os
import tempfile
from itertools import count

# Set configuration before importing the FastAPI application.
_db = tempfile.NamedTemporaryFile(prefix="sam-qa-", suffix=".db", delete=False)
_db.close()
_upload_dir = tempfile.mkdtemp(prefix="sam-uploads-")
_test_client_addresses = count(1)
os.environ["SAM_MODE"] = "qa"
os.environ["DATABASE_URL"] = "sqlite:///" + _db.name
os.environ["SAM_ADMIN_EMAIL"] = "admin@sam.local"
os.environ["SAM_ADMIN_PASSWORD"] = "demo-access"  # noqa: S105 - isolated QA fixture credential
os.environ["SAM_TOKEN_SECRET"] = "isolated-qa-test-secret-with-more-than-32-chars"  # noqa: S105 - isolated QA fixture secret
os.environ["LOAD_SAMPLE_DATA"] = "true"
os.environ["UPLOAD_DIR"] = _upload_dir
os.environ["QUALYS_BASE_URL"] = ""
os.environ["QUALYS_USERNAME"] = ""
os.environ["QUALYS_PASSWORD"] = ""
os.environ["SERVICENOW_BASE_URL"] = ""
os.environ["SERVICENOW_USERNAME"] = ""
os.environ["SERVICENOW_PASSWORD"] = ""
os.environ["CERTSPOTTER_API_TOKEN"] = ""
os.environ["QUALYS_API_VERSION"] = "6.0"
os.environ["SERVICENOW_TABLES"] = "cmdb_ci_server,cmdb_ci_web_application"
os.environ["SERVICENOW_EXPOSURE_FIELD"] = ""
os.environ["AI_ANALYST_ENABLED"] = "false"
os.environ["AI_ANALYST_DATA_APPROVED"] = "false"
os.environ["AI_ANALYST_API_KEY"] = ""
os.environ["AI_ANALYST_MODEL"] = ""
os.environ["CISA_KEV_FEED_URL"] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
os.environ["EPSS_API_URL"] = "https://api.first.org/data/v1/epss"
from pathlib import Path  # noqa: E402 - environment must be set before app imports

import pytest  # noqa: E402 - environment must be set before app imports
from alembic import command  # noqa: E402 - environment must be set before app imports
from alembic.config import Config  # noqa: E402 - environment must be set before app imports
from fastapi.testclient import TestClient  # noqa: E402 - environment must be set before app imports

_repo_root = Path(__file__).resolve().parents[2]
command.upgrade(Config(str(_repo_root / "alembic.ini")), "head")
from backend.app import app  # noqa: E402 - environment must be set before app imports
from backend.core.database import engine  # noqa: E402 - environment must be set before app imports


@pytest.fixture(autouse=True)
def reset_database():
    engine.dispose()
    for suffix in ("", "-shm", "-wal"):
        Path(_db.name + suffix).unlink(missing_ok=True)
    command.upgrade(Config(str(_repo_root / "alembic.ini")), "head")


@pytest.fixture
def client():
    address = f"198.51.100.{next(_test_client_addresses)}"
    with TestClient(app, client=(address, 50000)) as c:
        yield c


@pytest.fixture
def admin_token(client):
    r = client.post("/api/auth/login", json={"email": "admin@sam.local", "password": "demo-access"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture
def auth(admin_token):
    return {"Authorization": "Bearer " + admin_token}
