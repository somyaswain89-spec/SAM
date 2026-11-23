"""Environment-backed settings. Secrets never belong in frontend code."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODE = os.getenv("SAM_MODE", "qa").lower()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'sam.db'}")
TOKEN_SECRET = os.getenv("SAM_TOKEN_SECRET", "")
TOKEN_TTL_HOURS = int(os.getenv("SAM_TOKEN_TTL_HOURS", "8"))
BOOTSTRAP_EMAIL = os.getenv("SAM_ADMIN_EMAIL", "admin@sam.local" if MODE in {"demo", "qa"} else "").lower()
BOOTSTRAP_PASSWORD = os.getenv("SAM_ADMIN_PASSWORD", "demo-access" if MODE in {"demo", "qa"} else "")
CORS_ORIGINS = [x.strip() for x in os.getenv("SAM_CORS_ORIGINS", "http://127.0.0.1:8765,http://localhost:8765").split(",") if x.strip()]
