"""Bounded passive Certificate Transparency search through SSLMate Cert Spotter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode

from backend.core.config import (
    CERTSPOTTER_API_TOKEN,
    CERTSPOTTER_BASE_URL,
    EXTERNAL_DISCOVERY_MAX_PAGES,
    INTEGRATION_TIMEOUT_SECONDS,
)
from backend.integrations.base import IntegrationError, request_bytes, validate_base_url


@dataclass(frozen=True)
class CertificateIssuance:
    issuance_id: str
    dns_names: tuple[str, ...]
    not_before: str | None
    not_after: str | None
    revoked: bool | None
    cert_sha256: str | None
    issuer: str | None


class CertSpotterAdapter:
    """Read only: searches CT names for a target domain; it does not probe discovered hosts."""

    def __init__(self, base_url=CERTSPOTTER_BASE_URL, api_token=CERTSPOTTER_API_TOKEN):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token.strip()
        try:
            approved_origin = validate_base_url(self.base_url, "Cert Spotter")
        except IntegrationError:
            approved_origin = ""
        self.configured = bool(self.api_token and approved_origin == "https://api.certspotter.com")

    def _page(self, domain: str, after: str | None) -> list[dict]:
        base = validate_base_url(self.base_url, "Cert Spotter")
        if not self.configured or base != "https://api.certspotter.com":
            raise IntegrationError("Cert Spotter endpoint must use the approved API origin")
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "match_wildcards": "true",
            "expand": "dns_names",
        }
        if after:
            params["after"] = after
        payload = request_bytes(
            f"{base}/v1/issuances?{urlencode(params)}",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json",
                "User-Agent": "SAM-Exposure-Management/1.0",
            },
            timeout=INTEGRATION_TIMEOUT_SECONDS,
        )
        try:
            result = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise IntegrationError("Cert Spotter returned an invalid JSON response") from None
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise IntegrationError("Cert Spotter returned an unexpected response schema")
        return result

    def iter_issuance_pages(self, domain: str):
        if not self.configured:
            raise IntegrationError("Cert Spotter is not configured")
        after: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(EXTERNAL_DISCOVERY_MAX_PAGES):
            rows = self._page(domain, after)
            if not rows:
                return
            issuances = []
            for row in rows:
                issuance_id = row.get("id")
                names = row.get("dns_names")
                if not isinstance(issuance_id, (str, int)) or not isinstance(names, list):
                    raise IntegrationError("Cert Spotter returned an incomplete issuance record")
                valid_names = tuple(
                    sorted(
                        {
                            name.strip().lower().rstrip(".")
                            for name in names
                            if isinstance(name, str) and name.strip()
                        }
                    )
                )
                issuer = row.get("issuer")
                issuer_name = issuer.get("friendly_name") if isinstance(issuer, dict) else None
                issuances.append(
                    CertificateIssuance(
                        issuance_id=str(issuance_id)[:120],
                        dns_names=valid_names,
                        not_before=row.get("not_before")
                        if isinstance(row.get("not_before"), str)
                        else None,
                        not_after=row.get("not_after")
                        if isinstance(row.get("not_after"), str)
                        else None,
                        revoked=row.get("revoked")
                        if isinstance(row.get("revoked"), bool)
                        else None,
                        cert_sha256=row.get("cert_sha256")
                        if isinstance(row.get("cert_sha256"), str)
                        else None,
                        issuer=issuer_name[:255] if isinstance(issuer_name, str) else None,
                    )
                )
            yield tuple(issuances)
            cursor = str(rows[-1].get("id", ""))
            if not cursor or cursor in seen_cursors:
                raise IntegrationError("Cert Spotter pagination cursor was missing or repeated")
            seen_cursors.add(cursor)
            after = cursor
        raise IntegrationError("Certificate discovery exceeded the configured page limit")
