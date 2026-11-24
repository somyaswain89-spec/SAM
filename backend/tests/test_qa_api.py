import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from backend.app import app
from backend.core.database import SessionLocal
from backend.core.security import current_user, hash_password, token_digest
from backend.core.util import now
from backend.db.models import (
    Asset,
    AuditEvent,
    ContainmentAction,
    ExceptionRequest,
    ImportJob,
    PasswordResetToken,
    ThreatIntelRecord,
    User,
    WorkflowRequest,
)


def test_auth_and_asset_paging(client, auth):
    assert client.get("/api/assets").status_code == 401


def test_asset_and_finding_mutations_replay_without_duplicate_audit(client, auth):
    asset_headers = {**auth, "Idempotency-Key": "qa-asset-create-replay-000001"}
    asset_body = {
        "id": "WEB-" + "A" * 116,
        "name": "replay.example.test",
        "kind": "Website",
    }
    asset_first = client.post("/api/v1/assets", json=asset_body, headers=asset_headers)
    asset_replay = client.post("/api/v1/assets", json=asset_body, headers=asset_headers)
    assert asset_first.status_code == asset_replay.status_code == 201
    assert asset_replay.json() == asset_first.json()
    assert (
        client.post(
            "/api/v1/assets",
            json={**asset_body, "name": "changed.example.test"},
            headers=asset_headers,
        ).status_code
        == 409
    )

    finding_headers = {**auth, "Idempotency-Key": "qa-finding-create-replay-0001"}
    finding_body = {
        "id": "FND-" + "F" * 146,
        "asset_id": asset_body["id"],
        "title": "Replay-safe finding",
        "severity": "High",
    }
    finding_first = client.post("/api/v1/findings", json=finding_body, headers=finding_headers)
    finding_replay = client.post("/api/v1/findings", json=finding_body, headers=finding_headers)
    assert finding_first.status_code == finding_replay.status_code == 201
    assert finding_replay.json() == finding_first.json()

    asset_update_headers = {**auth, "Idempotency-Key": "qa-asset-update-replay-0001"}
    update_body = {"owner": "QA Operations"}
    update_first = client.patch(
        f"/api/v1/assets/{asset_body['id']}", json=update_body, headers=asset_update_headers
    )
    update_replay = client.patch(
        f"/api/v1/assets/{asset_body['id']}", json=update_body, headers=asset_update_headers
    )
    assert update_first.status_code == update_replay.status_code == 200
    assert update_replay.json() == update_first.json()
    assert (
        client.patch(
            f"/api/v1/assets/{asset_body['id']}",
            json={"owner": "Different owner"},
            headers=asset_update_headers,
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/assets/{asset_body['id']}",
            json={"status": "Quarantined"},
            headers={**auth, "Idempotency-Key": "qa-bypass-containment-0001"},
        ).status_code
        == 422
    )

    state_headers = {**auth, "Idempotency-Key": "qa-finding-state-replay-0001"}
    state_first = client.patch(
        f"/api/v1/findings/{finding_body['id']}/state",
        json={"state": "In Progress"},
        headers=state_headers,
    )
    state_replay = client.patch(
        f"/api/v1/findings/{finding_body['id']}/state",
        json={"state": "In Progress"},
        headers=state_headers,
    )
    assert state_first.status_code == state_replay.status_code == 200
    assert state_replay.json() == state_first.json()
    assert (
        client.patch(
            f"/api/v1/findings/{finding_body['id']}/state",
            json={"state": "Resolved"},
            headers=state_headers,
        ).status_code
        == 409
    )

    with SessionLocal() as session:
        asset_events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "asset.create", AuditEvent.object_id == asset_body["id"]
            )
        ).all()
        finding_events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "finding.upsert", AuditEvent.object_id == finding_body["id"]
            )
        ).all()
        update_events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "asset.update", AuditEvent.object_id == asset_body["id"]
            )
        ).all()
        state_events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "finding.state", AuditEvent.object_id == finding_body["id"]
            )
        ).all()
        assert (
            len(asset_events) == len(finding_events) == len(update_events) == len(state_events) == 1
        )


def test_import_job_count_and_rows_are_scoped_to_the_requesting_user(client, auth):
    created = client.post(
        "/api/v1/auth/users",
        json={
            "email": "import-owner@sam.local",
            "password": "import-owner-password",
            "role": "analyst",
        },
        headers={**auth, "Idempotency-Key": "qa-create-import-owner-0001"},
    )
    assert created.status_code == 201
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "import-owner@sam.local", "password": "import-owner-password"},
    ).json()["access_token"]
    owner_auth = {"Authorization": "Bearer " + token}

    with SessionLocal() as session:
        admin = session.scalar(select(User).where(User.email == "admin@sam.local"))
        owner = session.scalar(select(User).where(User.email == "import-owner@sam.local"))
        assert admin is not None and owner is not None
        stamp = now()
        session.add_all(
            [
                ImportJob(
                    id="IMP-ADMIN-PRIVATE",
                    source="test",
                    status="completed",
                    filename="admin.csv",
                    created_by=admin.id,
                    created_at=stamp,
                    updated_at=stamp,
                ),
                ImportJob(
                    id="IMP-OWNER-PRIVATE",
                    source="test",
                    status="completed",
                    filename="owner.csv",
                    created_by=owner.id,
                    created_at=stamp,
                    updated_at=stamp,
                ),
            ]
        )
        session.commit()

    owner_page = client.get("/api/v1/imports/jobs", headers=owner_auth).json()
    assert owner_page["total"] == 1
    assert [job["id"] for job in owner_page["items"]] == ["IMP-OWNER-PRIVATE"]
    assert (
        client.get("/api/v1/imports/jobs/IMP-ADMIN-PRIVATE", headers=owner_auth).status_code == 404
    )

    admin_page = client.get("/api/v1/imports/jobs", headers=auth).json()
    assert admin_page["total"] == 2
    assert {job["id"] for job in admin_page["items"]} == {
        "IMP-ADMIN-PRIVATE",
        "IMP-OWNER-PRIVATE",
    }


def test_governance_lists_scope_private_requests_to_the_owner(client, auth):
    created = client.post(
        "/api/v1/auth/users",
        json={
            "email": "governance-owner@sam.local",
            "password": "governance-owner-password",
            "role": "analyst",
        },
        headers={**auth, "Idempotency-Key": "qa-create-governance-owner-001"},
    )
    assert created.status_code == 201
    token = client.post(
        "/api/v1/auth/login",
        json={
            "email": "governance-owner@sam.local",
            "password": "governance-owner-password",
        },
    ).json()["access_token"]
    owner_auth = {"Authorization": "Bearer " + token}

    with SessionLocal() as session:
        admin = session.scalar(select(User).where(User.email == "admin@sam.local"))
        owner = session.scalar(select(User).where(User.email == "governance-owner@sam.local"))
        assert admin is not None and owner is not None
        stamp = now()
        for item_id, requester_id in (
            ("EX-ADMIN-PRIVATE", admin.id),
            ("EX-OWNER-PRIVATE", owner.id),
        ):
            session.add(
                ExceptionRequest(
                    id=item_id,
                    asset_id="WEB-1042",
                    requested_by=requester_id,
                    reason=f"Private exception request {item_id}",
                    expires_at="2030-01-01T00:00:00+00:00",
                    status="Pending",
                    created_at=stamp,
                    updated_at=stamp,
                )
            )
        for item_id, requester_id in (
            ("WF-ADMIN-PRIVATE", admin.id),
            ("WF-OWNER-PRIVATE", owner.id),
        ):
            session.add(
                WorkflowRequest(
                    id=item_id,
                    kind="Rescan",
                    asset_id="WEB-1042",
                    status="Pending",
                    payload=json.dumps({"reason": f"Private workflow {item_id}"}),
                    requested_by=requester_id,
                    created_at=stamp,
                    updated_at=stamp,
                )
            )
        for item_id, requester_id in (
            ("CT-ADMIN-PRIVATE", admin.id),
            ("CT-OWNER-PRIVATE", owner.id),
        ):
            session.add(
                ContainmentAction(
                    id=item_id,
                    asset_id="WEB-1042",
                    action="Quarantine",
                    status="Approval required",
                    impact=f"Private impact {item_id}",
                    requested_by=requester_id,
                    created_at=stamp,
                    updated_at=stamp,
                )
            )
        session.commit()

    endpoints = (
        ("/api/v1/exceptions", "EX-ADMIN-PRIVATE", "EX-OWNER-PRIVATE"),
        ("/api/v1/workflows", "WF-ADMIN-PRIVATE", "WF-OWNER-PRIVATE"),
        ("/api/v1/containment/requests", "CT-ADMIN-PRIVATE", "CT-OWNER-PRIVATE"),
    )
    for endpoint, admin_item_id, owner_item_id in endpoints:
        owner_page = client.get(endpoint, headers=owner_auth).json()
        assert owner_page["total"] == 1
        assert [item["id"] for item in owner_page["items"]] == [owner_item_id]
        admin_page = client.get(endpoint, headers=auth).json()
        assert admin_page["total"] == 2
        assert {item["id"] for item in admin_page["items"]} == {admin_item_id, owner_item_id}
    assert client.get("/api/assets", headers=auth).status_code == 200
    assert client.get("/api/assets?entity=Website&limit=2", headers=auth).json()["total"] == 3
    page = client.get("/api/assets?entity=Server&limit=2&offset=1", headers=auth).json()
    assert len(page["items"]) == 2 and page["offset"] == 1
    assert client.get("/api/assets").status_code == 401


def test_openapi_includes_versioned_response_contracts(client):
    spec = client.get("/api/v1/openapi.json")
    assert spec.status_code == 200
    paths = spec.json()["paths"]
    assert "200" in paths["/api/v1/auth/login"]["post"]["responses"]
    assert "200" in paths["/api/v1/audit/verify"]["get"]["responses"]
    assert "200" in paths["/api/v1/analyst/ask"]["post"]["responses"]


def test_feature_apis_publish_typed_response_contracts(client):
    spec = client.get("/api/v1/openapi.json").json()
    documented = [
        ("/api/v1/dashboard", "get", "200"),
        ("/api/v1/risk/priorities", "get", "200"),
        ("/api/v1/risk/sla-forecast", "get", "200"),
        ("/api/v1/compliance/summary", "get", "200"),
        ("/api/v1/compliance/assets", "get", "200"),
        ("/api/v1/exposure/summary", "get", "200"),
        ("/api/v1/exposure/external-assets", "get", "200"),
        ("/api/v1/attack-paths", "get", "200"),
        ("/api/v1/threats/zero-day-signals", "get", "200"),
        ("/api/v1/reports/executive", "get", "200"),
        ("/api/v1/imports/jobs", "get", "200"),
        ("/api/v1/exceptions", "get", "200"),
        ("/api/v1/workflows", "get", "200"),
        ("/api/v1/containment/requests", "get", "200"),
    ]
    for path, method, status in documented:
        response = spec["paths"][path][method]["responses"][status]
        assert response["content"]["application/json"]["schema"], (path, method)
    download = spec["paths"]["/api/v1/imports/jobs/{job_id}/download"]["get"]["responses"]["200"]
    assert download["content"]["text/csv"]["schema"] == {
        "type": "string",
        "format": "binary",
    }

    previous_override = app.dependency_overrides.get(current_user)

    def qa_admin():
        return {"id": 1, "email": "admin@sam.local", "role": "admin"}

    app.dependency_overrides[current_user] = qa_admin
    try:
        for path in (
            "/api/dashboard",
            "/api/compliance/summary",
            "/api/compliance/assets",
            "/api/exposure/summary",
            "/api/exposure/external-assets",
            "/api/attack-paths",
            "/api/threats/zero-day-signals",
            "/api/reports/executive",
            "/api/imports/jobs",
            "/api/exceptions",
            "/api/workflows",
            "/api/containment/requests",
        ):
            assert client.get(path).status_code == 200, path
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous_override


def test_finding_sort_and_dashboard(client, auth):
    findings = client.get("/api/findings", headers=auth).json()["items"]
    assert [x["severity"] for x in findings[:2]] == ["Critical", "Critical"]
    dash = client.get("/api/dashboard", headers=auth).json()
    assert dash["assets"] == 6 and dash["openFindings"] == 4


def test_priority_sla_and_attack_paths(client, auth):
    priority = client.get("/api/risk/priorities", headers=auth).json()
    assert priority["items"][0]["riskScore"] >= priority["items"][-1]["riskScore"]
    assert client.get("/api/risk/sla-forecast", headers=auth).json()["breached"]
    assert len(client.get("/api/attack-paths", headers=auth).json()["items"]) == 2
    assert isinstance(priority["items"][0]["riskFactors"]["kev"], bool)


def test_threat_intelligence_enriches_findings_and_shows_impacted_assets(client, auth):
    with SessionLocal() as session:
        session.add(
            ThreatIntelRecord(
                cve="CVE-2026-1842",
                kev_listed=True,
                kev_catalog_version="2026.11.24",
                kev_date_added="2026-11-20",
                kev_due_date="2026-12-10",
                kev_vendor="Example Vendor",
                kev_product="Example Product",
                kev_required_action="Apply the current vendor patch.",
                kev_ransomware_use="Known",
                epss_score=0.92,
                epss_percentile=0.99,
                epss_date="2026-11-24",
                updated_at=now(),
            )
        )
        session.commit()

    page = client.get("/api/v1/threats/intelligence?kev_only=true", headers=auth)
    assert page.status_code == 200
    body = page.json()
    assert body["summary"]["kevImpactedFindings"] == 1
    assert body["total"] == 1
    impacted = body["items"][0]
    assert impacted["findingId"] == "FND-8012"
    assert impacted["assetId"] == "WEB-1042"
    assert impacted["kevListed"] is True
    assert impacted["epssScore"] == 0.92
    search = client.get("/api/v1/threats/intelligence?cve=cve-2026-1842&limit=1", headers=auth)
    assert search.status_code == 200
    assert search.json()["total"] == 1
    assert search.json()["items"][0]["cve"] == "CVE-2026-1842"

    priorities = client.get("/api/v1/risk/priorities", headers=auth).json()["items"]
    risk = next(item for item in priorities if item["id"] == "FND-8012")
    assert risk["riskFactors"]["kev"] is True
    assert risk["riskFactors"]["epss"] == 0.92
    assert risk["riskFactors"]["threatIntelSource"] == "CISA KEV / FIRST EPSS"


def test_multi_cve_findings_are_persisted_and_correlated(client, auth):
    with SessionLocal() as session:
        session.add(
            ThreatIntelRecord(
                cve="CVE-2026-91002",
                kev_listed=True,
                updated_at=now(),
            )
        )
        session.commit()

    created = client.post(
        "/api/v1/findings",
        headers={**auth, "Idempotency-Key": "qa-multicve-create-0000001"},
        json={
            "id": "FND-MULTI-CVE",
            "asset_id": "WEB-1042",
            "title": "One scanner detection references multiple CVEs",
            "severity": "High",
            "cve": "CVE-2026-91001",
            "cves": ["cve-2026-91002", "CVE-2026-91001"],
            "evidence": {"scanner": "Qualys"},
        },
    )
    assert created.status_code == 201
    assert created.json()["cve"] == "CVE-2026-91001"
    assert created.json()["cves"] == ["CVE-2026-91001", "CVE-2026-91002"]

    impacted = client.get(
        "/api/v1/threats/intelligence?cve=CVE-2026-91002&kev_only=true", headers=auth
    )
    assert impacted.status_code == 200
    assert impacted.json()["total"] == 1
    assert impacted.json()["items"][0]["findingId"] == "FND-MULTI-CVE"
    assert impacted.json()["items"][0]["assetId"] == "WEB-1042"

    sync = client.get("/api/v1/findings?asset_id=WEB-1042", headers=auth)
    persisted = next(item for item in sync.json()["items"] if item["id"] == "FND-MULTI-CVE")
    assert persisted["cves"] == ["CVE-2026-91001", "CVE-2026-91002"]


def test_governance_containment_is_simulated(client, auth):
    preview = client.get("/api/v1/containment/impact/SRV-2201?action=Quarantine", headers=auth)
    assert preview.status_code == 200
    preview_body = preview.json()
    assert preview_body["assetId"] == "SRV-2201"
    assert preview_body["action"] == "Quarantine"
    assert "may interrupt access" in preview_body["expectedEffect"]
    assert "customer-portal.acme.test" in preview_body["dependentAssets"]
    assert preview_body["impactBasis"] == "SAM asset and dependency records"

    release_preview = client.get("/api/v1/containment/impact/SRV-2201?action=Release", headers=auth)
    assert "restore access" in release_preview.json()["expectedEffect"]
    assert client.get("/api/v1/containment/impact/MISSING", headers=auth).status_code == 404

    body = {"asset_id": "WEB-1042", "action": "Quarantine", "acknowledge_impact": True}
    headers = {**auth, "Idempotency-Key": "qa-containment-key-00000001"}
    r = client.post("/api/containment/requests", json=body, headers=headers)
    assert r.status_code == 202 and r.json()["executionEnabled"] is False
    assert r.json()["status"] == "Approval required"
    integrations = client.get("/api/integrations/status", headers=auth).json()
    statuses = {item["id"]: item["status"] for item in integrations["connectors"]}
    assert statuses["qualys"] == "unconfigured"
    assert statuses["servicenow"] == "unconfigured"
    assert statuses["threat_intel"] == "configured"
    assert client.post("/api/integrations/qualys/sync", headers=auth).status_code == 503


def test_compliance_unknowns_and_analyst(client, auth):
    compliance = client.get("/api/compliance/summary", headers=auth).json()
    assert compliance["assetsEvaluated"] == 6
    answer = client.post(
        "/api/analyst/ask", json={"question": "How do I request a rescan?"}, headers=auth
    ).json()["answer"]
    assert "Rescan workflow" in answer


def test_analyst_uses_configured_model_for_arbitrary_questions(client, auth, monkeypatch):
    observed = {}

    class ConfiguredAnalyst:
        configured = True

        def answer(self, *, question, context, history):
            observed["question"] = question
            observed["context"] = context
            observed["history"] = history
            return "There are 6 assets in scope. [Asset WEB-1042]"

    monkeypatch.setattr("backend.services.analyst.AnalystModelAdapter", ConfiguredAnalyst)
    response = client.post(
        "/api/v1/analyst/ask",
        json={
            "question": "Explain that impact for the leadership team.",
            "history": [
                {"role": "user", "content": "What are the most critical findings?"},
                {"role": "assistant", "content": "Finding FND-8012 is critical."},
            ],
        },
        headers=auth,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["answer"].startswith("There are 6 assets")
    assert body["mode"] == "ai-grounded"
    assert body["sources"] == ["SAM database", "AI analyst provider"]
    assert observed["question"].startswith("Explain that impact")
    assert observed["history"][0]["content"] == "What are the most critical findings?"
    assert observed["context"]["summary"]["totalAssets"] == 6
    assert observed["context"]["assetSampleLimit"] == 25
    assert "evidence" not in str(observed["context"]).lower()


def test_analyst_clearly_labels_rule_fallback_when_provider_fails(client, auth, monkeypatch):
    from backend.integrations.base import IntegrationError

    class UnavailableAnalyst:
        configured = True

        def answer(self, **_kwargs):
            raise IntegrationError("Provider request failed")

    monkeypatch.setattr("backend.services.analyst.AnalystModelAdapter", UnavailableAnalyst)
    response = client.post(
        "/api/v1/analyst/ask",
        json={"question": "How many assets are in the inventory?"},
        headers=auth,
    )

    assert response.status_code == 200
    assert response.json()["mode"] == "rule-based-fallback"
    assert "provider unavailable" in response.json()["warning"].lower()


def test_versioned_api_and_tamper_evident_asset_audit(client, auth):
    response = client.patch(
        "/api/v1/assets/WEB-1042",
        json={"compliance": 72},
        headers={**auth, "Idempotency-Key": "qa-asset-audit-patch-0001"},
    )
    assert response.status_code == 200
    events = client.get("/api/v1/audit", headers=auth).json()["items"]
    event = next(item for item in events if item["action"] == "asset.update")
    assert len(event["entry_hash"]) == 64
    assert event["previous_hash"] is not None
    assert client.get("/api/v1/audit/verify", headers=auth).json()["valid"] is True


def test_admin_user_creation_and_server_side_rbac(client, auth):
    create_headers = {**auth, "Idempotency-Key": "qa-create-viewer-account-00001"}
    created = client.post(
        "/api/v1/auth/users",
        json={"email": "viewer@sam.local", "password": "qa-viewer-password", "role": "viewer"},
        headers=create_headers,
    )
    assert created.status_code == 201
    replay = client.post(
        "/api/v1/auth/users",
        json={"email": "viewer@sam.local", "password": "qa-viewer-password", "role": "viewer"},
        headers=create_headers,
    )
    assert replay.status_code == 201 and replay.json() == created.json()
    changed = client.post(
        "/api/v1/auth/users",
        json={"email": "different@sam.local", "password": "qa-viewer-password", "role": "viewer"},
        headers=create_headers,
    )
    assert changed.status_code == 409
    token = client.post(
        "/api/v1/auth/login", json={"email": "viewer@sam.local", "password": "qa-viewer-password"}
    ).json()["access_token"]
    viewer = {"Authorization": "Bearer " + token}
    forbidden = client.post(
        "/api/v1/auth/users",
        json={"email": "other@sam.local", "password": "qa-other-password", "role": "admin"},
        headers={**viewer, "Idempotency-Key": "qa-forbidden-user-create-00001"},
    )
    assert forbidden.status_code == 403
    assert (
        client.post(
            "/api/v1/assets",
            json={"id": "WEB-9000", "name": "unauthorized.test", "kind": "Website"},
            headers=viewer,
        ).status_code
        == 403
    )
    assert client.get("/api/v1/containment/impact/SRV-2201", headers=viewer).status_code == 403
    assert client.get("/api/v1/containment/impact/SRV-2201").status_code == 401
    assert client.get("/api/v1/auth/users", headers=viewer).status_code == 403
    viewer_id = next(
        item["id"]
        for item in client.get("/api/v1/auth/users?limit=200", headers=auth).json()["items"]
        if item["email"] == "viewer@sam.local"
    )
    assert (
        client.patch(
            f"/api/v1/auth/users/{viewer_id}/role",
            json={"role": "analyst"},
            headers={**viewer, "Idempotency-Key": "qa-viewer-role-update-denied-1"},
        ).status_code
        == 403
    )


def test_admin_user_access_management_lists_replays_and_revokes_sessions(client, auth):
    created = client.post(
        "/api/v1/auth/users",
        json={
            "email": "managed@sam.local",
            "password": "managed-account-password",
            "role": "viewer",
        },
        headers={**auth, "Idempotency-Key": "qa-create-managed-account-00001"},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "managed@sam.local", "password": "managed-account-password"},
    )
    assert login.status_code == 200
    managed_token = login.json()["access_token"]
    managed_auth = {"Authorization": "Bearer " + managed_token}

    page = client.get("/api/v1/auth/users?limit=1&offset=0", headers=auth)
    assert page.status_code == 200
    assert page.json()["total"] >= 2
    assert len(page.json()["items"]) == 1
    all_users = client.get("/api/v1/auth/users?limit=200&offset=0", headers=auth).json()
    managed = next(item for item in all_users["items"] if item["email"] == "managed@sam.local")

    headers = {**auth, "Idempotency-Key": "qa-user-deactivate-00000001"}
    disabled = client.patch(
        f"/api/v1/auth/users/{managed['id']}/active", json={"active": False}, headers=headers
    )
    replay = client.patch(
        f"/api/v1/auth/users/{managed['id']}/active", json={"active": False}, headers=headers
    )
    assert disabled.status_code == replay.status_code == 200
    assert disabled.json() == replay.json()
    assert disabled.json()["active"] is False
    assert client.get("/api/v1/auth/me", headers=managed_auth).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "managed@sam.local", "password": "managed-account-password"},
        ).status_code
        == 401
    )
    assert any(
        event["action"] == "user.active"
        for event in client.get("/api/v1/audit", headers=auth).json()["items"]
    )

    changed = client.patch(
        f"/api/v1/auth/users/{managed['id']}/active",
        json={"active": True},
        headers=headers,
    )
    assert changed.status_code == 409
    reactivated = client.patch(
        f"/api/v1/auth/users/{managed['id']}/active",
        json={"active": True},
        headers={**auth, "Idempotency-Key": "qa-user-reactivate-0000001"},
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["active"] is True
    reactivated_login = client.post(
        "/api/v1/auth/login",
        json={"email": "managed@sam.local", "password": "managed-account-password"},
    )
    assert reactivated_login.status_code == 200
    role_token = reactivated_login.json()["access_token"]
    role_headers = {"Authorization": "Bearer " + role_token}
    role_change_headers = {**auth, "Idempotency-Key": "qa-user-role-change-000001"}
    role_change = client.patch(
        f"/api/v1/auth/users/{managed['id']}/role",
        json={"role": "analyst"},
        headers=role_change_headers,
    )
    role_replay = client.patch(
        f"/api/v1/auth/users/{managed['id']}/role",
        json={"role": "analyst"},
        headers=role_change_headers,
    )
    assert role_change.status_code == role_replay.status_code == 200
    assert role_change.json() == role_replay.json()
    assert role_change.json()["role"] == "analyst"
    assert client.get("/api/v1/auth/me", headers=role_headers).status_code == 401
    assert (
        client.patch(
            f"/api/v1/auth/users/{managed['id']}/role",
            json={"role": "viewer"},
            headers=role_change_headers,
        ).status_code
        == 409
    )
    updated_login = client.post(
        "/api/v1/auth/login",
        json={"email": "managed@sam.local", "password": "managed-account-password"},
    )
    assert updated_login.status_code == 200
    assert updated_login.json()["user"]["role"] == "analyst"

    current_user_id = client.get("/api/v1/auth/me", headers=auth).json()["id"]
    self_deactivation = client.patch(
        f"/api/v1/auth/users/{current_user_id}/active",
        json={"active": False},
        headers={**auth, "Idempotency-Key": "qa-self-deactivate-0000001"},
    )
    assert self_deactivation.status_code == 409
    self_role_change = client.patch(
        f"/api/v1/auth/users/{current_user_id}/role",
        json={"role": "viewer"},
        headers={**auth, "Idempotency-Key": "qa-self-role-change-000001"},
    )
    assert self_role_change.status_code == 409


def test_refresh_rotation_csrf_and_logout(client):
    login = client.post(
        "/api/v1/auth/login", json={"email": "admin@sam.local", "password": "demo-access"}
    )
    assert login.status_code == 200
    assert "httponly" in login.headers.get("set-cookie", "").lower()
    csrf = login.cookies.get("sam_csrf")
    first_refresh = login.cookies.get("sam_refresh")
    denied = client.post("/api/v1/auth/refresh")
    assert denied.status_code == 401
    rotated = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200
    assert rotated.cookies.get("sam_refresh") != first_refresh
    access = rotated.json()["access_token"]
    out = client.post("/api/v1/auth/logout", headers={"Authorization": "Bearer " + access})
    assert out.status_code == 200
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + access}).status_code
        == 401
    )


def test_refresh_token_reuse_revokes_the_session_family(client):
    login = client.post(
        "/api/v1/auth/login", json={"email": "admin@sam.local", "password": "demo-access"}
    )
    first_refresh = login.cookies["sam_refresh"]
    csrf = login.cookies["sam_csrf"]
    rotated = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200
    rotated_refresh = rotated.cookies["sam_refresh"]

    client.cookies.set("sam_refresh", first_refresh)
    client.cookies.set("sam_csrf", csrf)
    replay = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert replay.status_code == 401
    client.cookies.set("sam_refresh", rotated_refresh)
    client.cookies.set("sam_csrf", csrf)
    family_reuse = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert family_reuse.status_code == 401


def test_failed_login_attempts_persist_and_lock_the_account(client):
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sam.local", "password": "incorrect-password"},
        )
        assert response.status_code == 401
    locked = client.post(
        "/api/v1/auth/login", json={"email": "admin@sam.local", "password": "demo-access"}
    )
    assert locked.status_code == 401
    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.email == "admin@sam.local"))
        assert user is not None and user.failed_login_count == 5 and user.locked_until is not None


def test_containment_requires_independent_approval_and_never_claims_execution(client, auth):
    request = client.post(
        "/api/v1/containment/requests",
        json={"asset_id": "WEB-1042", "action": "Quarantine", "acknowledge_impact": True},
        headers={**auth, "Idempotency-Key": "qa-containment-approval-000001"},
    )
    assert request.status_code == 202
    action_id = request.json()["id"]
    self_review_headers = {**auth, "Idempotency-Key": "qa-containment-self-review-0001"}
    self_review = client.post(
        f"/api/v1/containment/requests/{action_id}/decision",
        json={"decision": "Approve", "note": "Not an independent reviewer"},
        headers=self_review_headers,
    )
    assert self_review.status_code == 409
    client.post(
        "/api/v1/auth/users",
        json={
            "email": "reviewer@sam.local",
            "password": "reviewer-password-2026",
            "role": "security_admin",
        },
        headers={**auth, "Idempotency-Key": "qa-create-reviewer-account-0001"},
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "reviewer@sam.local", "password": "reviewer-password-2026"},
    ).json()["access_token"]
    approval_body = {"decision": "Approve", "note": "Approved pending configured connector"}
    reviewer_headers = {
        "Authorization": "Bearer " + token,
        "Idempotency-Key": "qa-containment-reviewer-approval-0001",
    }
    approval = client.post(
        f"/api/v1/containment/requests/{action_id}/decision",
        json=approval_body,
        headers=reviewer_headers,
    )
    replay = client.post(
        f"/api/v1/containment/requests/{action_id}/decision",
        json=approval_body,
        headers=reviewer_headers,
    )
    assert approval.status_code == 200
    assert replay.status_code == 200 and replay.json() == approval.json()
    assert approval.json()["externalActionExecuted"] is False
    assert approval.json()["executionStatus"] == "pending_connector"
    assert (
        client.post(
            f"/api/v1/containment/requests/{action_id}/decision",
            json={**approval_body, "note": "Different approval context"},
            headers=reviewer_headers,
        ).status_code
        == 409
    )
    assert client.get("/api/v1/assets/WEB-1042", headers=auth).json()["status"] == "Active"


def test_exception_review_is_idempotent_and_separate_from_the_requester(client, auth):
    created = client.post(
        "/api/v1/auth/users",
        json={
            "email": "exception-requester@sam.local",
            "password": "exception-requester-password",
            "role": "analyst",
        },
        headers={**auth, "Idempotency-Key": "qa-create-exception-requester-1"},
    )
    assert created.status_code == 201
    token = client.post(
        "/api/v1/auth/login",
        json={
            "email": "exception-requester@sam.local",
            "password": "exception-requester-password",
        },
    ).json()["access_token"]
    requester_headers = {
        "Authorization": "Bearer " + token,
        "Idempotency-Key": "qa-exception-request-0000001",
    }
    request = client.post(
        "/api/v1/exceptions",
        json={
            "asset_id": "WEB-1042",
            "reason": "Temporary patch validation exception for QA.",
            "expires_at": (datetime.now(UTC) + timedelta(days=14)).isoformat(),
        },
        headers=requester_headers,
    )
    assert request.status_code == 201
    exception_id = request.json()["id"]

    review_body = {"decision": "Approve", "note": "Approved with a bounded expiry"}
    reviewer_headers = {**auth, "Idempotency-Key": "qa-exception-review-0000001"}
    first = client.post(
        f"/api/v1/exceptions/{exception_id}/review", json=review_body, headers=reviewer_headers
    )
    replay = client.post(
        f"/api/v1/exceptions/{exception_id}/review", json=review_body, headers=reviewer_headers
    )
    assert first.status_code == replay.status_code == 200
    assert replay.json() == first.json()
    assert first.json()["status"] == "Approved"
    assert (
        client.post(
            f"/api/v1/exceptions/{exception_id}/review",
            json={**review_body, "decision": "Reject"},
            headers=reviewer_headers,
        ).status_code
        == 409
    )


def test_containment_idempotency_replays_without_duplicate_action(client, auth):
    body = {"asset_id": "WEB-1042", "action": "Quarantine", "acknowledge_impact": True}
    headers = {**auth, "Idempotency-Key": "qa-containment-retry-00000001"}

    first = client.post("/api/v1/containment/requests", json=body, headers=headers)
    replay = client.post("/api/v1/containment/requests", json=body, headers=headers)

    assert first.status_code == replay.status_code == 202
    assert first.json()["id"] == replay.json()["id"]
    assert client.get("/api/v1/containment/requests", headers=auth).json()["total"] == 1

    conflicting = client.post(
        "/api/v1/containment/requests",
        json={**body, "action": "Release"},
        headers=headers,
    )
    assert conflicting.status_code == 409


def test_workflow_idempotency_replays_and_releases_key_after_validation_failure(client, auth):
    headers = {**auth, "Idempotency-Key": "qa-workflow-retry-00000001"}
    invalid = client.post(
        "/api/v1/workflows",
        json={"kind": "Rescan", "asset_id": "UNKNOWN-ASSET", "payload": {"reason": "QA"}},
        headers=headers,
    )
    assert invalid.status_code == 404

    body = {
        "kind": "Rescan",
        "asset_id": "WEB-1042",
        "payload": {"reason": "Validate scanner refresh"},
    }
    first = client.post("/api/v1/workflows", json=body, headers=headers)
    replay = client.post("/api/v1/workflows", json=body, headers=headers)
    assert first.status_code == replay.status_code == 201
    assert first.json()["id"] == replay.json()["id"]

    changed = client.post(
        "/api/v1/workflows",
        json={**body, "payload": {"reason": "Different request"}},
        headers=headers,
    )
    assert changed.status_code == 409


def test_password_reset_requires_delivery_config_and_revokes_sessions(client):
    old = client.post(
        "/api/v1/auth/login", json={"email": "admin@sam.local", "password": "demo-access"}
    ).json()["access_token"]
    assert (
        client.post(
            "/api/v1/auth/password-reset/request", json={"email": "admin@sam.local"}
        ).status_code
        == 503
    )
    reset = "qa-one-time-reset-token-value-2026"
    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.email == "admin@sam.local"))
        assert user is not None
        session.add(
            PasswordResetToken(
                token_hash=token_digest(reset),
                user_id=user.id,
                expires_at=(datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
                created_at=now(),
            )
        )
        session.commit()
    changed = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": reset, "new_password": "new-admin-password-2026"},
    )
    assert changed.status_code == 200
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + old}).status_code == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sam.local", "password": "new-admin-password-2026"},
        ).status_code
        == 200
    )
    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.email == "admin@sam.local"))
        assert user is not None
        user.password_hash = hash_password("demo-access")
        user.failed_login_count = 0
        user.locked_until = None
        session.commit()


def test_asset_csv_import_is_queued_and_processed_with_row_errors(client, auth, monkeypatch):
    from backend.workers.import_tasks import process_asset_import

    queued_jobs = []

    def fake_delay(job_id):
        queued_jobs.append(job_id)
        return SimpleNamespace(id="unit-task-1")

    monkeypatch.setattr(process_asset_import, "delay", fake_delay)
    mapping = {
        "id": "Asset ID",
        "name": "Name",
        "kind": "Type",
        "classification": "Classification",
        "owner": "Owner",
        "compliance": "Compliance",
    }
    content = (
        b"Asset ID,Name,Type,Classification,Owner,Compliance\n"
        b"WEB-9901,imported.example,Website,External facing,QA,88\n"
        b"WEB-9901,duplicate.example,Website,External facing,QA,70\n"
        b"WEB-9902,invalid.example,Server,Internal facing,QA,not-a-number\n"
    )
    response = client.post(
        "/api/v1/imports/assets",
        headers={**auth, "Idempotency-Key": "qa-import-key-0000000001"},
        data={"column_mapping": json.dumps(mapping)},
        files={"file": ("inventory.csv", content, "text/csv")},
    )
    assert response.status_code == 202
    job_id = response.json()["job"]["id"]
    replay = client.post(
        "/api/v1/imports/assets",
        headers={**auth, "Idempotency-Key": "qa-import-key-0000000001"},
        data={"column_mapping": json.dumps(mapping)},
        files={"file": ("inventory.csv", content, "text/csv")},
    )
    assert replay.status_code == 202 and replay.json()["job"]["id"] == job_id
    assert queued_jobs == [job_id]
    with SessionLocal() as session:
        stored_job = session.get(ImportJob, job_id)
        assert stored_job is not None
        assert stored_job.idempotency_hash != "qa-import-key-0000000001"
        assert len(stored_job.idempotency_hash or "") == 64
        assert len(stored_job.request_hash or "") == 64
    conflicting = client.post(
        "/api/v1/imports/assets",
        headers={**auth, "Idempotency-Key": "qa-import-key-0000000001"},
        data={"column_mapping": json.dumps(mapping)},
        files={"file": ("inventory.csv", content.replace(b"not-a-number", b"91"), "text/csv")},
    )
    assert conflicting.status_code == 409
    processed = process_asset_import.run(job_id)
    assert (
        processed["status"] == "completed_with_errors"
        and processed["processed"] == 1
        and processed["rejected"] == 2
    )
    job = client.get(f"/api/v1/imports/jobs/{job_id}", headers=auth).json()
    assert job["processedRows"] == 3 and job["downloadAvailable"] is True
    assert client.get("/api/v1/assets/WEB-9901", headers=auth).status_code == 200
    assert client.get(f"/api/v1/imports/jobs/{job_id}/download", headers=auth).status_code == 200


def test_import_worker_retry_resumes_committed_batch_without_duplicates(client, auth, monkeypatch):
    from backend.core.config import UPLOAD_DIR
    from backend.workers.import_tasks import process_asset_import

    monkeypatch.setattr(
        process_asset_import,
        "delay",
        lambda _job_id: SimpleNamespace(id="retryable-import-task"),
    )
    mapping = {"id": "Asset ID", "name": "Name", "kind": "Type"}
    rows = [
        {"Asset ID": f"WEB-RTRY-{index:04}", "Name": f"retry-{index}.example", "Type": "Website"}
        for index in range(101)
    ]
    csv_rows = "\n".join(f"{row['Asset ID']},{row['Name']},{row['Type']}" for row in rows)
    content = f"Asset ID,Name,Type\n{csv_rows}\n".encode()
    created = client.post(
        "/api/v1/imports/assets",
        headers={**auth, "Idempotency-Key": "qa-import-retry-00000001"},
        data={"column_mapping": json.dumps(mapping)},
        files={"file": ("retry.csv", content, "text/csv")},
    )
    assert created.status_code == 202
    job_id = created.json()["job"]["id"]

    calls = 0

    def fail_after_first_batch(_path):
        nonlocal calls
        calls += 1
        for line_number, row in enumerate(rows, start=2):
            if calls == 1 and line_number == 102:
                raise OSError("temporary file read failure")
            yield line_number, row

    monkeypatch.setattr("backend.workers.import_tasks.load_rows", fail_after_first_batch)
    with pytest.raises(OSError, match="temporary file read failure"):
        process_asset_import.run(job_id)

    with SessionLocal() as session:
        job = session.get(ImportJob, job_id)
        assert job is not None and job.status == "queued"
        assert job.input_path and Path(job.input_path).is_relative_to(UPLOAD_DIR)
        assert (
            session.scalar(select(Asset.id).where(Asset.source == f"file:{job_id}").limit(1))
            is not None
        )
        committed_count = len(
            session.scalars(select(Asset.id).where(Asset.source == f"file:{job_id}")).all()
        )
        assert committed_count == 100

    retried = process_asset_import.run(job_id)
    assert retried == {"status": "completed", "processed": 101, "rejected": 0}
    with SessionLocal() as session:
        job = session.get(ImportJob, job_id)
        imported_count = len(
            session.scalars(select(Asset.id).where(Asset.source == f"file:{job_id}")).all()
        )
        audit_events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "asset.import")
        ).all()
        assert job is not None and job.status == "completed" and job.input_path is None
        assert job.total_rows == job.processed_rows == imported_count == 101
        assert len(audit_events) == 101


def test_asset_export_runs_as_job_and_escapes_csv_formulas(client, auth, monkeypatch):
    from backend.workers.import_tasks import process_asset_export

    queued_jobs = []

    def fake_delay(job_id):
        queued_jobs.append(job_id)
        return SimpleNamespace(id="unit-export-1")

    monkeypatch.setattr(process_asset_export, "delay", fake_delay)
    created = client.post(
        "/api/v1/assets",
        json={"id": "WEB-9910", "name": "=1+1", "kind": "Website"},
        headers={**auth, "Idempotency-Key": "qa-asset-export-formula-0001"},
    )
    assert created.status_code == 201
    export_headers = {**auth, "Idempotency-Key": "qa-export-key-0000000001"}
    response = client.post("/api/v1/exports/assets", headers=export_headers)
    assert response.status_code == 202
    job_id = response.json()["job"]["id"]
    replay = client.post("/api/v1/exports/assets", headers=export_headers)
    assert replay.status_code == 202 and replay.json()["job"]["id"] == job_id
    assert queued_jobs == [job_id]
    assert process_asset_export.run(job_id)["status"] == "completed"
    download = client.get(f"/api/v1/imports/jobs/{job_id}/download", headers=auth)
    assert download.status_code == 200
    assert b"'=1+1" in download.content
