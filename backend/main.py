"""Uvicorn entry point. Feature endpoints live in backend/api/*.py."""

from backend.app import app  # noqa: F401 - imported by the Uvicorn module path
