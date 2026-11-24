import json

import pytest
from sqlalchemy import select

from backend.core.database import SessionLocal
from backend.db.models import Asset, DiscoveredExternalAsset, ExternalDiscoveryRun
from backend.integrations.base import IntegrationError
from backend.integrations.certspotter import CertificateIssuance, CertSpotterAdapter
from backend.schemas.exposure import ExternalDiscoveryTargetCreate, normalize_domain
from backend.services.external_discovery import (
    create_run,
    create_target,
    review_candidate,
    run_discovery,
)


def test_domain_normalization_and_invalid_input():
    assert normalize_domain("  Exämple.com. ") == "xn--exmple-cua.com"
    for invalid in ("localhost", "192.0.2.4", "example..com", "-bad.example", "example_.com"):
        with pytest.raises(ValueError):
            normalize_domain(invalid)


def test_certspotter_paginates_and_expands_sans(monkeypatch):
    requests = []

    def fake_request(url, *, headers, **_kwargs):
        requests.append((url, headers))
        if len(requests) == 1:
            return json.dumps(
                [
                    {
                        "id": "issuance-1",
                        "dns_names": ["api.example.com", "*.example.com", "outside.test"],
                        "not_after": "2027-01-01T00:00:00Z",
                        "revoked": False,
                        "cert_sha256": "a" * 64,
                    }
                ]
            ).encode()
        return b"[]"

    monkeypatch.setattr("backend.integrations.certspotter.request_bytes", fake_request)
    fixture_credential = "secret-test-token"
    pages = list(
        CertSpotterAdapter(api_token=fixture_credential).iter_issuance_pages("example.com")
    )
    assert len(pages) == 1
    assert pages[0][0].issuance_id == "issuance-1"
    assert pages[0][0].dns_names == ("*.example.com", "api.example.com", "outside.test")
    assert "after=issuance-1" in requests[1][0]
    assert requests[0][1]["Authorization"] == "Bearer secret-test-token"
    assert "expand=dns_names" in requests[0][0]


def test_certspotter_rejects_bad_schema_and_page_limit(monkeypatch):
    fixture_credential = "fixture-only-value"
    monkeypatch.setattr("backend.integrations.certspotter.request_bytes", lambda *_a, **_k: b"{}")
    with pytest.raises(IntegrationError, match="unexpected response schema"):
        list(CertSpotterAdapter(api_token=fixture_credential).iter_issuance_pages("example.com"))

    monkeypatch.setattr("backend.integrations.certspotter.EXTERNAL_DISCOVERY_MAX_PAGES", 1)
    row = json.dumps([{"id": "one", "dns_names": ["www.example.com"]}]).encode()
    monkeypatch.setattr("backend.integrations.certspotter.request_bytes", lambda *_a, **_k: row)
    with pytest.raises(IntegrationError, match="page limit"):
        list(CertSpotterAdapter(api_token=fixture_credential).iter_issuance_pages("example.com"))


def test_target_registration_requires_attestation_and_replays(client, auth):
    body = {
        "domain": "Example.com.",
        "authorization_note": "Approved under customer security change CHG-1042.",
        "authorization_confirmed": True,
    }
    headers = {**auth, "Idempotency-Key": "domain-register-key-0001"}
    created = client.post("/api/v1/exposure/discovery/targets", headers=headers, json=body)
    replay = client.post("/api/v1/exposure/discovery/targets", headers=headers, json=body)
    assert created.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["id"] == created.json()["id"]
    assert created.json()["domain"] == "example.com"

    unconfirmed = client.post(
        "/api/v1/exposure/discovery/targets",
        headers={**auth, "Idempotency-Key": "domain-register-key-0002"},
        json={**body, "authorization_confirmed": False},
    )
    assert unconfirmed.status_code == 422


def test_discovery_requires_provider_credentials(client, auth):
    status = client.get("/api/v1/exposure/discovery/status", headers=auth)
    assert status.status_code == 200
    assert status.json()["configured"] is False
    target = client.post(
        "/api/v1/exposure/discovery/targets",
        headers={**auth, "Idempotency-Key": "domain-register-key-0003"},
        json={
            "domain": "client.example",
            "authorization_note": "Approved under security review SR-2133 and scope record.",
            "authorization_confirmed": True,
        },
    )
    response = client.post(
        f"/api/v1/exposure/discovery/targets/{target.json()['id']}/runs", headers=auth
    )
    assert response.status_code == 503
    assert "credentials are not configured" in response.json()["error"]["message"]


def test_discovery_mutations_are_role_checked_and_reactivation_requires_new_attestation(
    client, auth
):
    viewer = client.post(
        "/api/v1/auth/users",
        headers={**auth, "Idempotency-Key": "discovery-viewer-create-0001"},
        json={
            "email": "discovery-viewer@sam.local",
            "password": "viewer-initial-password",
            "role": "viewer",
        },
    )
    assert viewer.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "discovery-viewer@sam.local", "password": "viewer-initial-password"},
    )
    viewer_auth = {"Authorization": "Bearer " + login.json()["access_token"]}
    assert client.get("/api/v1/exposure/discovery/targets", headers=viewer_auth).status_code == 200
    denied = client.post(
        "/api/v1/exposure/discovery/targets",
        headers={**viewer_auth, "Idempotency-Key": "discovery-viewer-target-0001"},
        json={
            "domain": "unauthorized.example.com",
            "authorization_note": "Viewer should not be allowed to register this domain.",
            "authorization_confirmed": True,
        },
    )
    assert denied.status_code == 403

    target = client.post(
        "/api/v1/exposure/discovery/targets",
        headers={**auth, "Idempotency-Key": "discovery-admin-target-0001"},
        json={
            "domain": "authorized.example.com",
            "authorization_note": "Approved under security review SR-2201 and signed scope.",
            "authorization_confirmed": True,
        },
    )
    target_id = target.json()["id"]
    disabled = client.patch(
        f"/api/v1/exposure/discovery/targets/{target_id}",
        headers={**auth, "Idempotency-Key": "discovery-admin-pause-0001"},
        json={"active": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["active"] is False
    no_attestation = client.patch(
        f"/api/v1/exposure/discovery/targets/{target_id}",
        headers={**auth, "Idempotency-Key": "discovery-admin-resume-0001"},
        json={"active": True},
    )
    assert no_attestation.status_code == 409
    renewed = client.patch(
        f"/api/v1/exposure/discovery/targets/{target_id}",
        headers={**auth, "Idempotency-Key": "discovery-admin-resume-0002"},
        json={
            "active": True,
            "authorization_note": "Reauthorized under change record CHG-6722 and current owner approval.",
            "authorization_confirmed": True,
        },
    )
    assert renewed.status_code == 200
    assert renewed.json()["active"] is True


def test_passive_discovery_persists_candidates_and_promotion(client, auth):
    actor = {"id": 1, "role": "admin", "email": "admin@sam.local"}
    target_body = ExternalDiscoveryTargetCreate(
        domain="example.net",
        authorization_note="Approved under security review SR-4488 and signed scope document.",
        authorization_confirmed=True,
    )

    class FixtureAdapter:
        def iter_issuance_pages(self, domain):
            assert domain == "example.net"
            yield (
                CertificateIssuance(
                    issuance_id="ct-1",
                    dns_names=("api.example.net", "*.example.net", "out.of.scope.invalid"),
                    not_before="2026-10-01T00:00:00Z",
                    not_after="2027-10-01T00:00:00Z",
                    revoked=False,
                    cert_sha256="f" * 64,
                    issuer="Fixture CA",
                ),
            )

    with SessionLocal() as session:
        target = create_target(session, target_body, actor)
        run = create_run(session, target["id"], actor)
        session.commit()
        result = run_discovery(session, run["id"], FixtureAdapter())
        assert result["status"] == "completed"
        discovered = client.get(
            "/api/v1/exposure/discovery/candidates?target_id=" + target["id"], headers=auth
        )
        assert discovered.status_code == 200
        items = discovered.json()["items"]
        assert {item["hostname"] for item in items} == {"api.example.net", "*.example.net"}
        assert all(item["status"] == "pending_review" for item in items)
        assert all(
            item["evidence"]["discovery_method"] == "passive_certificate_transparency"
            for item in items
        )

        promoted = review_candidate(
            session, items[0]["id"], "accept", "Owner verified host.", actor
        )
        assert promoted["status"] == "accepted"
        assert promoted["asset_id"]
        asset = session.get(Asset, promoted["asset_id"])
        assert asset is not None
        assert asset.kind == "Website"
        assert asset.classification == "External facing"
        assert asset.source == "certspotter"
        stored_run = session.scalar(
            select(ExternalDiscoveryRun).where(ExternalDiscoveryRun.id == run["id"])
        )
        assert stored_run is not None
        assert stored_run.status == "completed"

        second_run = create_run(session, target["id"], actor)
        session.commit()
        run_discovery(session, second_run["id"], FixtureAdapter())
        candidate = session.scalar(
            select(DiscoveredExternalAsset).where(DiscoveredExternalAsset.id == items[0]["id"])
        )
        assert candidate is not None
        assert candidate.status == "accepted"
        assert (
            session.scalar(select(Asset.id).where(Asset.id == promoted["asset_id"]))
            == promoted["asset_id"]
        )
