"""Read-only ServiceNow CMDB Table API adapter."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlencode

from backend.core.config import (
    INTEGRATION_MAX_PAGES,
    INTEGRATION_TIMEOUT_SECONDS,
    SERVICENOW_BASE_URL,
    SERVICENOW_CRITICALITY_FIELD,
    SERVICENOW_ENVIRONMENT_FIELD,
    SERVICENOW_EXPOSURE_FIELD,
    SERVICENOW_PASSWORD,
    SERVICENOW_TABLES,
    SERVICENOW_USERNAME,
)
from backend.integrations.base import BasicAuth, IntegrationError, request_bytes, validate_base_url

TABLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,99}$")


@dataclass(frozen=True)
class ServiceNowCI:
    table: str
    provider_id: str
    name: str
    hostname: str | None
    ip_address: str | None
    os: str | None
    manufacturer: str | None
    model: str | None
    install_status: str | None
    class_name: str | None
    criticality: str | None
    exposure: str | None
    environment: str | None
    updated_at: str | None


class ServiceNowAdapter:
    def __init__(
        self,
        base_url=SERVICENOW_BASE_URL,
        username=SERVICENOW_USERNAME,
        password=SERVICENOW_PASSWORD,
        tables=SERVICENOW_TABLES,
        exposure_field=SERVICENOW_EXPOSURE_FIELD,
        environment_field=SERVICENOW_ENVIRONMENT_FIELD,
        criticality_field=SERVICENOW_CRITICALITY_FIELD,
    ):
        self.configured = bool(base_url and username and password and tables)
        self.base_url = base_url
        self.username = username
        self.password = password
        self.tables = tuple(tables)
        self.exposure_field = exposure_field
        self.environment_field = environment_field
        self.criticality_field = criticality_field
        if any(not TABLE_PATTERN.fullmatch(table) for table in self.tables):
            raise IntegrationError(
                "ServiceNow table names must use letters, digits, and underscores"
            )
        field_names = {
            "sys_id",
            "name",
            "host_name",
            "ip_address",
            "os",
            "manufacturer",
            "model",
            "install_status",
            "sys_class_name",
            "sys_updated_on",
            self.criticality_field,
            self.environment_field,
        }
        if self.exposure_field:
            field_names.add(self.exposure_field)
        if any(not TABLE_PATTERN.fullmatch(field) for field in field_names):
            raise IntegrationError(
                "ServiceNow field mappings must use letters, digits, and underscores"
            )
        self.fields = ",".join(sorted(field_names))

    def _fetch_page(self, table: str, offset: int, limit: int) -> list[dict]:
        base = validate_base_url(self.base_url, "ServiceNow")
        query = urlencode(
            {
                "sysparm_limit": str(limit),
                "sysparm_offset": str(offset),
                "sysparm_fields": self.fields,
                "sysparm_exclude_reference_link": "true",
                "sysparm_display_value": "true",
                "sysparm_query": "ORDERBYsys_id",
            }
        )
        url = f"{base}/api/now/table/{table}?{query}"
        payload = request_bytes(
            url,
            headers={
                "Authorization": BasicAuth(self.username, self.password).header(),
                "Accept": "application/json",
            },
            timeout=INTEGRATION_TIMEOUT_SECONDS,
        )
        try:
            data = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise IntegrationError("ServiceNow returned an invalid JSON response") from None
        rows = data.get("result") if isinstance(data, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise IntegrationError("ServiceNow response did not contain a result list")
        return rows

    @staticmethod
    def _value(row: dict, key: str) -> str | None:
        value = row.get(key)
        if isinstance(value, dict):
            value = value.get("display_value") or value.get("value")
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def check_connection(self) -> dict:
        self._require_config()
        self._fetch_page(self.tables[0], 0, 1)
        return {"ok": True, "provider": "ServiceNow CMDB"}

    def _require_config(self):
        if not self.configured:
            raise IntegrationError("ServiceNow is not configured")

    def iter_records(self):
        self._require_config()
        for table in self.tables:
            offset = 0
            for _page_number in range(INTEGRATION_MAX_PAGES):
                rows = self._fetch_page(table, offset, 1000)
                for row in rows:
                    provider_id = self._value(row, "sys_id")
                    if not provider_id:
                        continue
                    yield ServiceNowCI(
                        table=table,
                        provider_id=provider_id,
                        name=self._value(row, "name")
                        or self._value(row, "host_name")
                        or f"CMDB CI {provider_id}",
                        hostname=self._value(row, "host_name"),
                        ip_address=self._value(row, "ip_address"),
                        os=self._value(row, "os"),
                        manufacturer=self._value(row, "manufacturer"),
                        model=self._value(row, "model"),
                        install_status=self._value(row, "install_status"),
                        class_name=self._value(row, "sys_class_name"),
                        criticality=self._value(row, self.criticality_field),
                        exposure=self._value(row, self.exposure_field)
                        if self.exposure_field
                        else None,
                        environment=self._value(row, self.environment_field),
                        updated_at=self._value(row, "sys_updated_on"),
                    )
                if len(rows) < 1000:
                    break
                offset += len(rows)
            else:
                raise IntegrationError("ServiceNow pagination exceeded the configured page limit")

    def fetch(self) -> list[ServiceNowCI]:
        return list(self.iter_records())
