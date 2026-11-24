"""Shared, bounded outbound HTTP behavior for configured source adapters."""

from __future__ import annotations

import base64
import email.utils
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

logger = logging.getLogger("sam.integrations")
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class IntegrationError(Exception):
    """Safe-to-report connector error with no provider response body or credentials."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class BasicAuth:
    username: str
    password: str

    def header(self) -> str:
        encoded = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        return f"Basic {encoded}"


def validate_base_url(value: str, provider: str) -> str:
    """Require an explicit HTTPS origin; adapter URLs are never accepted from API input."""
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
            and parsed.port in {None, 443}
        )
    except ValueError:
        valid = False
    if not valid:
        raise IntegrationError(f"{provider} endpoint must be a valid HTTPS origin")
    return value.rstrip("/")


def request_bytes(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int,
    method: str = "GET",
    data: bytes | None = None,
    opener_factory: Callable = build_opener,
) -> bytes:
    """Call a configured provider with TLS, bounded output, and safe retry rules."""
    from urllib.request import HTTPRedirectHandler

    class RejectRedirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, response_headers, newurl):
            return None

    parsed_url = urlsplit(url)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username:
        raise IntegrationError("Provider requests require a configured HTTPS host")
    if method not in {"GET", "POST"} or (method == "GET" and data is not None):
        raise IntegrationError("Unsupported provider request method")
    opener = opener_factory(RejectRedirects())
    max_attempts = 3 if method == "GET" else 1
    for attempt in range(max_attempts):
        request = Request(url, data=data, headers=headers, method=method)  # noqa: S310 - HTTPS only, redirects rejected
        try:
            with opener.open(request, timeout=timeout) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                    raise IntegrationError("Provider response exceeded the configured size limit")
                body = bytes(response.read(MAX_RESPONSE_BYTES + 1))
                if len(body) > MAX_RESPONSE_BYTES:
                    raise IntegrationError("Provider response exceeded the configured size limit")
                return body
        except HTTPError as exc:
            status = int(exc.code)
            if status not in RETRYABLE_STATUS or attempt == max_attempts - 1:
                logger.warning("connector_http_error", extra={"status_code": status})
                raise IntegrationError(
                    "Provider rejected the request" if status < 500 else "Provider request failed",
                    status_code=status,
                ) from None
            retry_after = exc.headers.get("Retry-After", "")
            try:
                delay = min(5.0, max(0.0, float(retry_after)))
            except ValueError:
                try:
                    retry_at = email.utils.parsedate_to_datetime(retry_after).timestamp()
                    delay = min(5.0, max(0.0, retry_at - time.time()))
                except (TypeError, ValueError, OverflowError):
                    delay = min(2.0, 0.25 * (2**attempt))
            logger.info("connector_retry", extra={"attempt": attempt + 1, "status_code": status})
            time.sleep(delay)
        except (URLError, TimeoutError, OSError) as exc:
            if attempt == max_attempts - 1:
                logger.warning(
                    "connector_transport_error", extra={"error_type": type(exc).__name__}
                )
                raise IntegrationError("Could not reach the configured provider") from None
            time.sleep(min(2.0, 0.25 * (2**attempt)))
    raise IntegrationError("Provider request failed")
