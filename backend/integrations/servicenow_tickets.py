"""Approval initiated ServiceNow incident creation adapter."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlencode

from backend.core.config import (
    INTEGRATION_TIMEOUT_SECONDS,
    SERVICENOW_INCIDENT_TABLE,
    SERVICENOW_TICKET_BASE_URL,
    SERVICENOW_TICKET_PASSWORD,
    SERVICENOW_TICKET_USERNAME,
    SERVICENOW_TICKET_WRITE_ENABLED,
)
from backend.integrations.base import BasicAuth, IntegrationError, request_bytes, validate_base_url

TABLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,99}$")


@dataclass(frozen=True)
class ServiceNowIncident:
    sys_id: str
    number: str
    correlation_id: str


class ServiceNowTicketAdapter:
    def __init__(
        self,
        base_url: str = SERVICENOW_TICKET_BASE_URL,
        username: str = SERVICENOW_TICKET_USERNAME,
        password: str = SERVICENOW_TICKET_PASSWORD,
        incident_table: str = SERVICENOW_INCIDENT_TABLE,
        write_enabled: bool = SERVICENOW_TICKET_WRITE_ENABLED,
    ):
        self.configured = bool(base_url and username and password and write_enabled)
        self.base_url = base_url
        self.username = username
        self.password = password
        self.incident_table = incident_table
        if not TABLE_PATTERN.fullmatch(incident_table):
            raise IntegrationError("ServiceNow incident table name is invalid")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": BasicAuth(self.username, self.password).header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _url(self, query: dict[str, str] | None = None) -> str:
        base = validate_base_url(self.base_url, "ServiceNow")
        url = f"{base}/api/now/table/{self.incident_table}"
        return f"{url}?{urlencode(query)}" if query else url

    @staticmethod
    def _parse(payload: bytes) -> dict:
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise IntegrationError("ServiceNow returned an invalid incident response") from None
        if not isinstance(decoded, dict) or not isinstance(decoded.get("result"), dict):
            raise IntegrationError("ServiceNow response did not contain an incident record")
        return cast(dict[str, object], decoded["result"])

    @staticmethod
    def _incident(record: dict, expected_correlation: str) -> ServiceNowIncident:
        sys_id = record.get("sys_id")
        number = record.get("number")
        correlation_id = record.get("correlation_id") or expected_correlation
        if not isinstance(sys_id, str) or not sys_id or not isinstance(number, str) or not number:
            raise IntegrationError("ServiceNow incident response is missing its reference")
        if correlation_id != expected_correlation:
            raise IntegrationError("ServiceNow returned a different incident correlation ID")
        return ServiceNowIncident(sys_id=sys_id, number=number, correlation_id=correlation_id)

    def _require_config(self) -> None:
        if not self.configured:
            raise IntegrationError("ServiceNow incident write access is not configured")

    def find_by_correlation(self, correlation_id: str) -> ServiceNowIncident | None:
        self._require_config()
        query = {
            "sysparm_query": f"correlation_id={correlation_id}",
            "sysparm_fields": "sys_id,number,correlation_id",
            "sysparm_limit": "2",
            "sysparm_display_value": "false",
        }
        payload = request_bytes(
            self._url(query), headers=self._headers(), timeout=INTEGRATION_TIMEOUT_SECONDS
        )
        try:
            decoded = json.loads(payload)
            records = decoded.get("result") if isinstance(decoded, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise IntegrationError(
                "ServiceNow returned an invalid incident lookup response"
            ) from None
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            raise IntegrationError("ServiceNow incident lookup did not return a record list")
        if len(records) > 1:
            raise IntegrationError("ServiceNow returned duplicate incident correlation IDs")
        return self._incident(records[0], correlation_id) if records else None

    def create_incident(
        self,
        *,
        correlation_id: str,
        short_description: str,
        description: str,
        impact: int,
        urgency: int,
    ) -> ServiceNowIncident:
        """Find an existing correlated incident before issuing one non-retried POST."""
        self._require_config()
        existing = self.find_by_correlation(correlation_id)
        if existing:
            return existing
        return self.post_incident(
            correlation_id=correlation_id,
            short_description=short_description,
            description=description,
            impact=impact,
            urgency=urgency,
        )

    def post_incident(
        self,
        *,
        correlation_id: str,
        short_description: str,
        description: str,
        impact: int,
        urgency: int,
    ) -> ServiceNowIncident:
        """Issue one non-retried create request after the caller has checked correlation."""
        self._require_config()
        body = json.dumps(
            {
                "correlation_id": correlation_id,
                "short_description": short_description[:160],
                "description": description,
                "impact": impact,
                "urgency": urgency,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        payload = request_bytes(
            self._url(),
            headers=self._headers(),
            timeout=INTEGRATION_TIMEOUT_SECONDS,
            method="POST",
            data=body,
        )
        return self._incident(self._parse(payload), correlation_id)
