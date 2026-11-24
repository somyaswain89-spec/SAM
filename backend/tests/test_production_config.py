import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend.app import _validate_production_origins


@pytest.mark.parametrize(
    "origin", ["http://localhost:8080", "https://localhost", "https://sam.example.com/path"]
)
def test_production_cors_rejects_local_http_and_path_origins(origin):
    with pytest.raises(RuntimeError, match="HTTPS origins"):
        _validate_production_origins([origin])


def test_production_cors_requires_explicit_https_origin():
    _validate_production_origins(["https://sam.example.com"])
    with pytest.raises(RuntimeError, match="explicit HTTPS"):
        _validate_production_origins([])


def test_inline_celery_execution_is_rejected_outside_local_dev_and_test():
    environment = os.environ.copy()
    environment.update({"APP_ENV": "qa", "CELERY_TASK_ALWAYS_EAGER": "true"})
    # The executable and import statement are fixed; no user-controlled command is evaluated.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import backend.core.config"],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "restricted to development and test" in result.stderr
