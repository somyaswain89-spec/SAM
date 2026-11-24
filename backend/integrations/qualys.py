"""Read-only Qualys VMDR Host List and Host Detection API adapter."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlencode, urlsplit

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from backend.core.config import (
    INTEGRATION_MAX_PAGES,
    INTEGRATION_TIMEOUT_SECONDS,
    QUALYS_API_VERSION,
    QUALYS_BASE_URL,
    QUALYS_PASSWORD,
    QUALYS_USERNAME,
)
from backend.integrations.base import BasicAuth, IntegrationError, request_bytes, validate_base_url

logger = logging.getLogger("sam.integrations.qualys")
API_VERSIONS = {"2.0", "3.0", "4.0", "5.0", "6.0"}


@dataclass(frozen=True)
class QualysHost:
    provider_id: str
    name: str
    ip: str | None
    dns: str | None
    os: str | None
    tracking_method: str | None
    last_activity: str | None


@dataclass(frozen=True)
class QualysDetection:
    host_id: str
    qid: str
    title: str
    severity: str
    status: str
    first_seen: str | None
    last_seen: str | None
    cves: tuple[str, ...]


class QualysAdapter:
    def __init__(
        self, base_url=QUALYS_BASE_URL, username=QUALYS_USERNAME, password=QUALYS_PASSWORD
    ):
        self.configured = bool(base_url and username and password)
        self.base_url = base_url
        self.username = username
        self.password = password
        if QUALYS_API_VERSION not in API_VERSIONS:
            raise IntegrationError("QUALYS_API_VERSION must be a supported Qualys API version")
        self.version = QUALYS_API_VERSION

    def _url(self, endpoint: str, params: dict[str, str]) -> str:
        base = validate_base_url(self.base_url, "Qualys")
        return f"{base}/api/{self.version}/fo/asset/host/{endpoint}?{urlencode(params)}"

    def _get_page(
        self, endpoint: str, params: dict[str, str], next_url: str | None = None
    ) -> bytes:
        url = next_url or self._url(endpoint, params)
        if next_url:
            base = validate_base_url(self.base_url, "Qualys")
            parsed = urlsplit(next_url)
            expected_path = f"/api/{self.version}/fo/asset/host/{endpoint}"
            if (
                parsed.scheme != "https"
                or parsed.netloc != urlsplit(base).netloc
                or parsed.path != expected_path
            ):
                raise IntegrationError(
                    "Qualys pagination link did not match the configured endpoint"
                )
        return request_bytes(
            url,
            headers={
                "Authorization": BasicAuth(self.username, self.password).header(),
                "X-Requested-With": "SAM Security Platform",
                "Accept": "application/xml",
            },
            timeout=INTEGRATION_TIMEOUT_SECONDS,
        )

    @staticmethod
    def _parse(payload: bytes) -> ET.Element:
        # Qualys includes a DTD declaration; remove it so XML parsing never fetches external data.
        safe = re.sub(rb"<!DOCTYPE[^>]*(?:\[[\s\S]*?\]\s*)?>", b"", payload, flags=re.I)
        if re.search(rb"<!ENTITY", safe, flags=re.I):
            raise IntegrationError("Qualys returned an unsupported XML entity declaration")
        try:
            return cast(ET.Element, SafeET.fromstring(safe))
        except (ET.ParseError, DefusedXmlException):
            raise IntegrationError("Qualys returned an invalid XML response") from None

    @staticmethod
    def _text(node: ET.Element, name: str) -> str | None:
        child = node.find(name)
        value = (child.text or "").strip() if child is not None else ""
        return value or None

    def _pages(self, endpoint: str, params: dict[str, str]):
        next_url = None
        for _page_number in range(INTEGRATION_MAX_PAGES):
            root = self._parse(self._get_page(endpoint, params, next_url))
            yield root
            continuation = root.findtext(".//WARNING/URL") or root.findtext(".//WARNING/url")
            next_url = continuation.strip() if continuation else None
            if not next_url:
                return
        raise IntegrationError("Qualys pagination exceeded the configured page limit")

    def check_connection(self) -> dict:
        self._require_config()
        root = self._parse(
            self._get_page("", {"action": "list", "details": "Basic", "truncation_limit": "1"})
        )
        if root.find(".//RESPONSE") is None and root.find(".//response") is None:
            raise IntegrationError("Qualys response did not contain an API result")
        return {"ok": True, "provider": "Qualys VMDR"}

    def _require_config(self):
        if not self.configured:
            raise IntegrationError("Qualys is not configured")

    def iter_assets(self):
        self._require_config()
        for root in self._pages("", {"action": "list", "details": "All", "show_asset_id": "1"}):
            for host in root.findall(".//HOST_LIST/HOST") + root.findall(".//host_list/host"):
                provider_id = self._text(host, "ID") or self._text(host, "id")
                if not provider_id:
                    continue
                yield QualysHost(
                    provider_id=provider_id,
                    name=self._text(host, "DNS")
                    or self._text(host, "DNS_DATA/HOSTNAME")
                    or self._text(host, "IP")
                    or f"Qualys host {provider_id}",
                    ip=self._text(host, "IP"),
                    dns=self._text(host, "DNS"),
                    os=self._text(host, "OS"),
                    tracking_method=self._text(host, "TRACKING_METHOD"),
                    last_activity=self._text(host, "LAST_ACTIVITY"),
                )

    def fetch_assets(self) -> list[QualysHost]:
        return list(self.iter_assets())

    def iter_detections(self):
        self._require_config()
        endpoint = "vm/detection/"
        for root in self._pages(
            endpoint, {"action": "list", "truncation_limit": "1000", "show_asset_id": "1"}
        ):
            hosts = root.findall(".//HOST_LIST/HOST") + root.findall(".//host_list/host")
            for host in hosts:
                host_id = self._text(host, "ID") or self._text(host, "id")
                if not host_id:
                    continue
                detections = host.findall(".//DETECTION_LIST/DETECTION") + host.findall(
                    ".//detection_list/detection"
                )
                for detection in detections:
                    qid = self._text(detection, "QID") or self._text(detection, "qid")
                    if not qid:
                        continue
                    cves = tuple(
                        (item.text or "").strip()
                        for item in detection.findall(".//CVE_LIST/CVE")
                        + detection.findall(".//cve_list/cve")
                        if (item.text or "").strip()
                    )
                    yield QualysDetection(
                        host_id=host_id,
                        qid=qid,
                        title=self._text(detection, "TITLE")
                        or self._text(detection, "title")
                        or f"Qualys QID {qid}",
                        severity=self._text(detection, "SEVERITY")
                        or self._text(detection, "severity")
                        or "3",
                        status=self._text(detection, "STATUS")
                        or self._text(detection, "status")
                        or "ACTIVE",
                        first_seen=self._text(detection, "FIRST_FOUND_DATETIME")
                        or self._text(detection, "FIRST_FOUND_DATETIME_GMT"),
                        last_seen=self._text(detection, "LAST_FOUND_DATETIME")
                        or self._text(detection, "LAST_FOUND_DATETIME_GMT"),
                        cves=cves,
                    )

    def fetch_detections(self) -> list[QualysDetection]:
        return list(self.iter_detections())

    def fetch(self) -> tuple[list[QualysHost], list[QualysDetection]]:
        return self.fetch_assets(), self.fetch_detections()
