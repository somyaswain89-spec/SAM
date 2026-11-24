import json
import logging
import sys

from backend.core.logging import JsonFormatter


def test_structured_logs_omit_exception_text_that_may_contain_secrets():
    try:
        raise RuntimeError("password=never-log-this-token")
    except RuntimeError:
        record = logging.LogRecord(
            "sam.test", logging.ERROR, __file__, 10, "operation_failed", (), sys.exc_info()
        )

    formatted = JsonFormatter().format(record)
    entry = json.loads(formatted)
    assert entry["exception_type"] == "RuntimeError"
    assert "never-log-this-token" not in formatted
    assert "exception" not in entry
