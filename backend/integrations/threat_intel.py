"""CISA KEV and FIRST EPSS read-only feed adapters."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import date
from urllib.parse import urlencode, urlsplit

from backend.core.config import (
    CISA_KEV_FEED_URL,
    EPSS_API_URL,
    INTEGRATION_MAX_PAGES,
    INTEGRATION_TIMEOUT_SECONDS,
)
from backend.integrations.base import IntegrationError, request_bytes

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.IGNORECASE)
MAX_CVE_QUERY_CHARS = 1800
MAX_CVES_PER_REQUEST = 90  # FIRST's default response page limit is 100.


@dataclass(frozen=True)
class KevRecord:
    cve: str
    vendor: str
    product: str
    vulnerability_name: str
    short_description: str
    date_added: str
    due_date: str
    required_action: str
    ransomware_use: str


@dataclass(frozen=True)
class EpssRecord:
    cve: str
    score: float
    percentile: float
    score_date: str


@dataclass(frozen=True)
class ThreatIntelSnapshot:
    catalog_version: str
    catalog_released: str
    kev: tuple[KevRecord, ...]
    epss: tuple[EpssRecord, ...]


def _require_https_endpoint(url: str, provider: str) -> str:
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and parsed.port in {None, 443}
        )
    except ValueError:
        valid = False
    if not valid:
        raise IntegrationError(f"{provider} endpoint must be a valid HTTPS URL")
    return url


def _json_request(url: str, provider: str, *, allow_query: bool = False) -> dict:
    if allow_query:
        parsed = urlsplit(url)
        _require_https_endpoint(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", provider)
    else:
        _require_https_endpoint(url, provider)
    body = request_bytes(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SAM-Security-Platform/1.0",
        },
        timeout=INTEGRATION_TIMEOUT_SECONDS,
    )
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError(f"{provider} returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise IntegrationError(f"{provider} returned an invalid response")
    return payload


def _text(record: dict, field: str, *, max_length: int = 4000) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise IntegrationError("CISA KEV catalog is missing a required field")
    return value.strip()[:max_length]


def _date(value: str, provider: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise IntegrationError(f"{provider} returned an invalid date") from None


class ThreatIntelAdapter:
    """Fetch public exploitation and exploit-likelihood data without credentials."""

    def __init__(self, kev_url: str = CISA_KEV_FEED_URL, epss_url: str = EPSS_API_URL):
        self.kev_url = kev_url
        self.epss_url = epss_url
        # URLs are deployment settings, never supplied by an API request.
        try:
            _require_https_endpoint(kev_url, "CISA KEV")
            _require_https_endpoint(epss_url, "FIRST EPSS")
            self.configured = True
        except IntegrationError:
            self.configured = False

    def _fetch_kev(self) -> tuple[str, str, tuple[KevRecord, ...]]:
        payload = _json_request(self.kev_url, "CISA KEV")
        version = _text(payload, "catalogVersion", max_length=80)
        released = _text(payload, "dateReleased", max_length=80)
        vulnerabilities = payload.get("vulnerabilities")
        count = payload.get("count")
        if (
            not isinstance(vulnerabilities, list)
            or not isinstance(count, int)
            or count != len(vulnerabilities)
            or count < 0
        ):
            raise IntegrationError("CISA KEV catalog failed its completeness check")

        records: list[KevRecord] = []
        seen: set[str] = set()
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise IntegrationError("CISA KEV catalog contains an invalid record")
            cve = _text(item, "cveID", max_length=40).upper()
            if not CVE_PATTERN.fullmatch(cve) or cve in seen:
                raise IntegrationError("CISA KEV catalog contains an invalid or duplicate CVE")
            seen.add(cve)
            date_added = _date(_text(item, "dateAdded", max_length=10), "CISA KEV")
            due_date = _date(_text(item, "dueDate", max_length=10), "CISA KEV")
            records.append(
                KevRecord(
                    cve=cve,
                    vendor=_text(item, "vendorProject", max_length=255),
                    product=_text(item, "product", max_length=255),
                    vulnerability_name=_text(item, "vulnerabilityName", max_length=500),
                    short_description=_text(item, "shortDescription"),
                    date_added=date_added,
                    due_date=due_date,
                    required_action=_text(item, "requiredAction"),
                    ransomware_use=_text(item, "knownRansomwareCampaignUse", max_length=32),
                )
            )
        return version, released, tuple(records)

    def _cve_batches(self, cves: list[str]):
        batch: list[str] = []
        batch_chars = 0
        for raw_cve in sorted({item.upper() for item in cves}):
            if not CVE_PATTERN.fullmatch(raw_cve):
                continue
            next_size = len(raw_cve) + (1 if batch else 0)
            if batch and (
                batch_chars + next_size > MAX_CVE_QUERY_CHARS or len(batch) >= MAX_CVES_PER_REQUEST
            ):
                yield batch
                batch = []
                batch_chars = 0
                next_size = len(raw_cve)
            batch.append(raw_cve)
            batch_chars += next_size
        if batch:
            yield batch

    @staticmethod
    def _parse_epss_value(value: object, field: str) -> float:
        if not isinstance(value, (str, int, float)):
            raise IntegrationError(f"FIRST EPSS returned an invalid {field}")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            raise IntegrationError(f"FIRST EPSS returned an invalid {field}") from None
        if not math.isfinite(number) or not 0 <= number <= 1:
            raise IntegrationError(f"FIRST EPSS returned an out-of-range {field}")
        return number

    def _fetch_epss(self, cves: list[str]) -> tuple[EpssRecord, ...]:
        records: list[EpssRecord] = []
        batches = 0
        base_url = _require_https_endpoint(self.epss_url, "FIRST EPSS")
        for batch in self._cve_batches(cves):
            batches += 1
            if batches > INTEGRATION_MAX_PAGES:
                raise IntegrationError("FIRST EPSS lookup exceeded the configured request limit")
            query = urlencode({"cve": ",".join(batch)})
            payload = _json_request(f"{base_url}?{query}", "FIRST EPSS", allow_query=True)
            if payload.get("status") != "OK" or not isinstance(payload.get("data"), list):
                raise IntegrationError("FIRST EPSS response did not contain score data")
            requested = set(batch)
            for item in payload["data"]:
                if not isinstance(item, dict):
                    raise IntegrationError("FIRST EPSS returned an invalid record")
                cve = _text(item, "cve", max_length=40).upper()
                if cve not in requested or not CVE_PATTERN.fullmatch(cve):
                    raise IntegrationError("FIRST EPSS returned an unexpected CVE")
                score_date = _date(_text(item, "date", max_length=10), "FIRST EPSS")
                records.append(
                    EpssRecord(
                        cve=cve,
                        score=self._parse_epss_value(item.get("epss"), "score"),
                        percentile=self._parse_epss_value(item.get("percentile"), "percentile"),
                        score_date=score_date,
                    )
                )
        return tuple(records)

    def fetch(self, cves: list[str]) -> ThreatIntelSnapshot:
        if not self.configured:
            raise IntegrationError("Threat intelligence feed URLs are not configured")
        version, released, kev = self._fetch_kev()
        epss = self._fetch_epss(cves)
        return ThreatIntelSnapshot(version, released, kev, epss)

    def check_connection(self) -> dict:
        if not self.configured:
            raise IntegrationError("Threat intelligence feed URLs are not configured")
        self._fetch_kev()
        self._fetch_epss(["CVE-2021-44228"])
        return {"ok": True, "provider": "CISA KEV and FIRST EPSS"}
