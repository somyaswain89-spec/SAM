import json
import logging
import os
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "job_id",
            "source",
            "attempt",
            "error_type",
        ):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            # Exception text/tracebacks can contain SQL parameters, tokens, or provider URLs.
            entry["exception_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "Error"
        return json.dumps(entry, ensure_ascii=False, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
