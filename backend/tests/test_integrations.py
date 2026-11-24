import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from backend.api import integrations as integration_api
from backend.core.database import SessionLocal
from backend.db.models import Asset, Finding, SyncRun, ThreatIntelRecord
from backend.integrations.analyst_model import AnalystModelAdapter
from backend.integrations.base import IntegrationError
from backend.integrations.qualys import QualysAdapter
from backend.integrations.servicenow import ServiceNowAdapter
from backend.integrations.servicenow_tickets import ServiceNowIncident, ServiceNowTicketAdapter
from backend.integrations.threat_intel import EpssRecord, KevRecord, ThreatIntelSnapshot
from backend.services import integrations as integration_service
from backend.services import tickets as ticket_service
from backend.workers import threat_intel_tasks

QUALYS_HOSTS = b"""<?xml version="1.0"?><!DOCTYPE HOST_LIST_OUTPUT SYSTEM "https://bad.example/external.dtd"><HOST_LIST_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1234</ID><IP>192.0.2.10</IP><DNS>qa.example.test</DNS><OS>Linux</OS><TRACKING_METHOD>Cloud Agent</TRACKING_METHOD></HOST></HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>"""
QUALYS_DETECTIONS = b"""<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1234</ID><DETECTION_LIST><DETECTION><QID>98765</QID><TITLE>Sample vulnerability</TITLE><SEVERITY>5</SEVERITY><STATUS>ACTIVE</STATUS><FIRST_FOUND_DATETIME>2026-01-01T00:00:00Z</FIRST_FOUND_DATETIME><LAST_FOUND_DATETIME>2026-01-02T00:00:00Z</LAST_FOUND_DATETIME><CVE_LIST><CVE>CVE-2026-1234</CVE></CVE_LIST></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""


def test_qualys_adapter_parses_host_and_detection_without_resolving_dtd(monkeypatch):
    requested = []

    def fake_request(url, **kwargs):
        requested.append((url, kwargs["headers"]))
        return QUALYS_DETECTIONS if "vm/detection" in url else QUALYS_HOSTS

    monkeypatch.setattr("backend.integrations.qualys.request_bytes", fake_request)
    adapter = QualysAdapter("https://qualys.example", "scanner", "secret")
    hosts, detections = adapter.fetch()

    assert hosts[0].provider_id == "1234"
    assert hosts[0].name == "qa.example.test"
    assert detections[0].qid == "98765"
    assert detections[0].cves == ("CVE-2026-1234",)
    assert all(item[1]["X-Requested-With"] == "SAM Security Platform" for item in requested)
    assert all(item[1]["Authorization"].startswith("Basic ") for item in requested)


def test_qualys_rejects_non_https_endpoint():
    adapter = QualysAdapter("http://127.0.0.1", "scanner", "secret")
    try:
        adapter.check_connection()
    except Exception as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("HTTP provider endpoint should be rejected")


def test_cisa_and_epss_adapter_validates_and_normalizes_public_feed_records(monkeypatch):
    requests = []
    kev_payload = {
        "catalogVersion": "2026.11.24",
        "dateReleased": "2026-11-24T12:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1234",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Remote code execution",
                "dateAdded": "2026-11-22",
                "shortDescription": "A test vulnerability",
                "requiredAction": "Apply the vendor patch.",
                "dueDate": "2026-12-01",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }
    epss_payload = {
        "status": "OK",
        "status-code": 200,
        "total": 1,
        "data": [
            {"cve": "CVE-2026-1234", "epss": "0.72", "percentile": "0.96", "date": "2026-11-24"}
        ],
    }

    def fake_request(url, **kwargs):
        requests.append((url, kwargs))
        payload = kev_payload if url.endswith("/kev.json") else epss_payload
        return json.dumps(payload).encode()

    monkeypatch.setattr("backend.integrations.threat_intel.request_bytes", fake_request)
    adapter = integration_service.ThreatIntelAdapter(
        "https://feeds.example/kev.json", "https://feeds.example/epss"
    )
    snapshot = adapter.fetch(["cve-2026-1234"])

    assert snapshot.catalog_version == "2026.11.24"
    assert snapshot.kev[0].cve == "CVE-2026-1234"
    assert snapshot.epss[0].score == 0.72
    assert len(requests) == 2
    assert all(item[1].get("method", "GET") == "GET" for item in requests)
    assert "CVE-2026-1234" in requests[1][0]


def test_threat_intel_adapter_rejects_incomplete_kev_catalog(monkeypatch):
    monkeypatch.setattr(
        "backend.integrations.threat_intel.request_bytes",
        lambda *_args,
        **_kwargs: b'{"catalogVersion":"v1","dateReleased":"today","count":2,"vulnerabilities":[]}',
    )
    adapter = integration_service.ThreatIntelAdapter(
        "https://feeds.example/kev.json", "https://feeds.example/epss"
    )
    try:
        adapter.fetch([])
    except IntegrationError as exc:
        assert "completeness" in str(exc)
    else:
        raise AssertionError("Incomplete feed must not replace the stored snapshot")


def test_threat_intel_sync_persists_snapshot_and_replaces_stale_values(monkeypatch):
    kev = KevRecord(
        cve="CVE-2026-1842",
        vendor="Example Vendor",
        product="Example Product",
        vulnerability_name="Known exploit",
        short_description="Observed exploitation",
        date_added="2026-11-20",
        due_date="2026-12-10",
        required_action="Apply the patch.",
        ransomware_use="Known",
    )

    class FakeThreatIntelAdapter:
        configured = True

        def fetch(self, cves):
            assert "CVE-2026-1842" in cves
            return ThreatIntelSnapshot(
                "2026.11.24",
                "2026-11-24T12:00:00Z",
                (kev,),
                (EpssRecord("CVE-2026-1842", 0.88, 0.99, "2026-11-24"),),
            )

    monkeypatch.setattr(integration_service, "ThreatIntelAdapter", FakeThreatIntelAdapter)
    with SessionLocal() as session:
        current_time = datetime.now(UTC).isoformat()
        asset = Asset(
            id="THREAT-TEST-ASSET",
            name="threat-test.internal",
            kind="Server",
            created_at=current_time,
            updated_at=current_time,
        )
        session.add(asset)
        session.add_all(
            [
                Finding(
                    id="FND-THREAT-CURRENT",
                    asset_id=asset.id,
                    title="Known exploit candidate",
                    cve="CVE-2026-1842",
                    severity="Critical",
                    created_at=current_time,
                    updated_at=current_time,
                    evidence="{}",
                ),
                Finding(
                    id="FND-THREAT-STALE",
                    asset_id=asset.id,
                    title="Previously listed exploit",
                    cve="CVE-2026-2031",
                    severity="High",
                    created_at=current_time,
                    updated_at=current_time,
                    evidence="{}",
                ),
            ]
        )
        stale = ThreatIntelRecord(
            cve="CVE-2026-2031",
            kev_listed=True,
            kev_catalog_version="old",
            epss_score=0.99,
            epss_percentile=0.99,
            epss_date="2026-01-01",
            updated_at="2026-01-01T00:00:00Z",
        )
        run = SyncRun(
            id="threat-intel-sync-test",
            source="threat_intel",
            status="queued",
            started_at=datetime.now(UTC).isoformat(),
            records_read=0,
            records_written=0,
        )
        session.add_all([stale, run])
        session.commit()
        result = integration_service.run_sync(session, "threat_intel", run.id)
        updated = session.get(ThreatIntelRecord, "CVE-2026-1842")
        cleared = session.get(ThreatIntelRecord, "CVE-2026-2031")
        assert result["status"] == "completed"
        assert updated is not None and updated.kev_listed and updated.epss_score == 0.88
        assert cleared is not None and not cleared.kev_listed and cleared.epss_score is None


def test_daily_threat_intel_scheduler_queues_at_most_one_active_sync(monkeypatch):
    queued = []

    def queue(source, run_id):
        queued.append((source, run_id))
        return SimpleNamespace(id="daily-task")

    monkeypatch.setattr(
        threat_intel_tasks.run_integration_sync,
        "delay",
        queue,
    )

    first = threat_intel_tasks.enqueue_daily_threat_intel_sync()
    second = threat_intel_tasks.enqueue_daily_threat_intel_sync()

    assert first["status"] == "queued"
    assert second["status"] == "skipped"
    assert len(queued) == 1 and queued[0] == ("threat_intel", first["run_id"])


def test_servicenow_adapter_uses_offset_pagination_and_maps_rows(monkeypatch):
    seen = []

    def fake_request(url, **_kwargs):
        seen.append(url)
        if "sysparm_offset=0" in url:
            return b'{"result":[{"sys_id":"abc123","name":"web-qa","host_name":"web-qa","sys_class_name":"cmdb_ci_web_application","ip_address":"203.0.113.10","install_status":"Installed","internet_facing":"true","environment":"QA","business_criticality":"Critical"}]}'
        return b'{"result":[]}'

    monkeypatch.setattr("backend.integrations.servicenow.request_bytes", fake_request)
    adapter = ServiceNowAdapter(
        "https://acme.service-now.com",
        "sam_reader",
        "secret",
        ("cmdb_ci_web_application",),
        exposure_field="internet_facing",
    )
    records = adapter.fetch()

    assert records[0].provider_id == "abc123"
    assert records[0].exposure == "true"
    assert records[0].environment == "QA"
    assert "sysparm_limit=1000" in seen[0]
    assert "sysparm_offset=0" in seen[0]


def test_servicenow_ticket_adapter_uses_correlation_lookup_and_single_post(monkeypatch):
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs))
        if kwargs.get("method", "GET") == "GET":
            return b'{"result":[]}'
        payload = json.loads(kwargs["data"])
        assert payload["correlation_id"] == "SAM-0123456789abcdef0123456789abcdef"
        assert payload["impact"] == 1 and payload["urgency"] == 1
        return b'{"result":{"sys_id":"sn-id-1","number":"INC0010001","correlation_id":"SAM-0123456789abcdef0123456789abcdef"}}'

    monkeypatch.setattr("backend.integrations.servicenow_tickets.request_bytes", fake_request)
    adapter = ServiceNowTicketAdapter(
        "https://acme.service-now.com", "sam_writer", "secret", write_enabled=True
    )
    incident = adapter.create_incident(
        correlation_id="SAM-0123456789abcdef0123456789abcdef",
        short_description="Critical issue",
        description="Asset and impact",
        impact=1,
        urgency=1,
    )

    assert incident.number == "INC0010001"
    assert len(calls) == 2
    assert calls[0][1].get("method", "GET") == "GET"
    assert calls[1][1]["method"] == "POST"


def test_ticket_api_persists_idempotent_creation_and_reconciles_uncertain_outcome(
    client, auth, monkeypatch
):
    external = ServiceNowIncident(
        sys_id="sn-ticket-77",
        number="INC0010077",
        correlation_id="placeholder",
    )

    class FakeTicketAdapter:
        configured = True
        created = 0
        reconciled = False
        correlation = ""

        def find_by_correlation(self, correlation_id):
            self.correlation = correlation_id
            if self.reconciled:
                return ServiceNowIncident(external.sys_id, external.number, correlation_id)
            return None

        def post_incident(self, **_kwargs):
            self.created += 1
            raise IntegrationError("Provider failed after request", status_code=503)

    fake = FakeTicketAdapter()
    monkeypatch.setattr(ticket_service, "ServiceNowTicketAdapter", lambda: fake)
    headers = {**auth, "Idempotency-Key": "qa-ticket-key-00000001"}
    payload = {
        "finding_id": "FND-8012",
        "business_impact": "Customer checkout service may be unavailable.",
    }
    uncertain = client.post(
        "/api/v1/integrations/servicenow/tickets", json=payload, headers=headers
    )
    assert uncertain.status_code == 502
    assert fake.created == 1

    fake.reconciled = True
    reconciled = client.post(
        "/api/v1/integrations/servicenow/tickets", json=payload, headers=headers
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["status"] == "created"
    assert reconciled.json()["external_number"] == "INC0010077"
    assert fake.created == 1

    repeated = client.post("/api/v1/integrations/servicenow/tickets", json=payload, headers=headers)
    assert repeated.status_code == 200
    assert repeated.json()["id"] == reconciled.json()["id"]
    mismatch = client.post(
        "/api/v1/integrations/servicenow/tickets",
        json={
            "finding_id": "FND-8012",
            "business_impact": "Different business impact on the same request.",
        },
        headers=headers,
    )
    assert mismatch.status_code == 409
    assert (
        client.get(
            "/api/v1/integrations/servicenow/tickets?finding_id=FND-8012", headers=auth
        ).json()["total"]
        == 1
    )


def test_ticket_creation_stays_disabled_without_explicit_write_configuration(client, auth):
    status = client.get("/api/v1/integrations/status", headers=auth).json()
    assert status["ticketWriteConfigured"] is False
    assert status["aiAnalystConfigured"] is False
    response = client.post(
        "/api/v1/integrations/servicenow/tickets",
        json={"finding_id": "FND-8012", "business_impact": "Customer checkout may be affected."},
        headers={**auth, "Idempotency-Key": "qa-ticket-key-00000002"},
    )
    assert response.status_code == 503


def test_ai_analyst_adapter_posts_bounded_request_without_server_side_storage(monkeypatch):
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs))
        return b'{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"Review finding FND-1."}]}]}'

    monkeypatch.setattr("backend.integrations.analyst_model.request_bytes", fake_request)
    adapter = AnalystModelAdapter(
        api_key="server-only-test-key",
        model="qa-model",
        base_url="https://api.openai.com/v1",
        enabled=True,
        data_approved=True,
    )
    answer = adapter.answer(
        question="What should we review?",
        context={"scope": "Server", "highestPriorityOpenFindings": [{"id": "FND-1"}]},
        history=[{"role": "user", "content": "Which asset has the issue?"}],
    )

    assert answer == "Review finding FND-1."
    assert len(calls) == 1
    url, request = calls[0]
    payload = json.loads(request["data"])
    user_input = json.loads(payload["input"])
    assert url == "https://api.openai.com/v1/responses"
    assert request["method"] == "POST"
    assert request["headers"]["Authorization"] == "Bearer server-only-test-key"
    assert payload["store"] is False
    assert user_input["question"] == "What should we review?"
    assert user_input["prior_conversation"][0]["content"] == "Which asset has the issue?"
    assert user_input["sam_context"]["scope"] == "Server"


def test_ai_analyst_adapter_requires_both_enablement_and_data_approval():
    assert not AnalystModelAdapter(
        api_key="test-key", model="qa-model", enabled=True, data_approved=False
    ).configured
    assert not AnalystModelAdapter(
        api_key="test-key", model="qa-model", enabled=False, data_approved=True
    ).configured


def test_ai_analyst_adapter_rejects_incomplete_provider_response(monkeypatch):
    monkeypatch.setattr(
        "backend.integrations.analyst_model.request_bytes",
        lambda *_args, **_kwargs: b'{"status":"incomplete","output":[]}',
    )
    adapter = AnalystModelAdapter(
        api_key="test-key",
        model="qa-model",
        base_url="https://api.openai.com/v1",
        enabled=True,
        data_approved=True,
    )
    try:
        adapter.answer(question="Question", context={})
    except IntegrationError as exc:
        assert "did not complete" in str(exc)
    else:
        raise AssertionError("Incomplete provider responses must not be treated as answers")


def test_qualys_sync_upserts_assets_and_findings_once(monkeypatch):
    class FakeQualys:
        def iter_assets(self):
            yield integration_service.QualysHost(
                provider_id="9876",
                name="sync-test.internal",
                ip="192.0.2.44",
                dns="sync-test.internal",
                os="Linux",
                tracking_method="Cloud Agent",
                last_activity=None,
            )

        def iter_detections(self):
            yield integration_service.QualysDetection(
                host_id="9876",
                qid="654",
                title="Test finding",
                severity="5",
                status="ACTIVE",
                first_seen=None,
                last_seen=None,
                cves=("CVE-2026-1000",),
            )

    monkeypatch.setattr(integration_service, "QualysAdapter", FakeQualys)
    for index in range(2):
        session = SessionLocal()
        run = SyncRun(
            id=f"qualys-test-{index}",
            source="qualys",
            status="queued",
            started_at=datetime.now(UTC).isoformat(),
            records_read=0,
            records_written=0,
        )
        session.add(run)
        session.commit()
        result = integration_service.run_sync(session, "qualys", run.id)
        assert result["status"] == "completed"
        assert result["records_read"] == 2
        assert result["records_written"] == 2
        session.close()

    session = SessionLocal()
    asset = session.get(Asset, "qualys:9876")
    assert asset is not None
    assert len(asset.findings) == 1
    assert asset.findings[0].severity == "Critical"
    session.close()


def test_admin_can_validate_and_queue_configured_connector(client, auth, monkeypatch):
    class ConfiguredAdapter:
        configured = True

        def check_connection(self):
            return {"ok": True, "provider": "Qualys VMDR"}

    monkeypatch.setitem(integration_api.ADAPTERS, "qualys", ("Qualys VMDR", ConfiguredAdapter))
    monkeypatch.setattr(
        integration_api.run_integration_sync,
        "delay",
        lambda source, run_id: SimpleNamespace(id="qa-task-123"),
    )
    tested = client.post("/api/v1/integrations/qualys/test", headers=auth)
    queued = client.post("/api/v1/integrations/qualys/sync", headers=auth)

    assert tested.status_code == 200 and tested.json()["ok"] is True
    assert queued.status_code == 202
    assert queued.json()["task_id"] == "qa-task-123"
    assert client.post("/api/v1/integrations/qualys/sync", headers=auth).status_code == 409
    assert (
        client.get("/api/v1/integrations/runs", headers=auth).json()["items"][0]["status"]
        == "queued"
    )


def test_database_rejects_concurrent_active_sync_runs_for_same_source():
    stamp = datetime.now(UTC).isoformat()
    with SessionLocal() as session:
        session.add(
            SyncRun(
                id="active-sync-one",
                source="qualys",
                status="queued",
                started_at=stamp,
                records_read=0,
                records_written=0,
            )
        )
        session.commit()
        session.add(
            SyncRun(
                id="active-sync-two",
                source="qualys",
                status="running",
                started_at=stamp,
                records_read=0,
                records_written=0,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_queue_failure_is_persisted_without_reporting_success(client, auth, monkeypatch):
    class ConfiguredAdapter:
        configured = True

    def reject_queue(*_args):
        raise RuntimeError("Redis unavailable")

    monkeypatch.setitem(integration_api.ADAPTERS, "qualys", ("Qualys VMDR", ConfiguredAdapter))
    monkeypatch.setattr(integration_api.run_integration_sync, "delay", reject_queue)
    response = client.post("/api/v1/integrations/qualys/sync", headers=auth)

    assert response.status_code == 503
    latest = client.get("/api/v1/integrations/runs", headers=auth).json()["items"][0]
    assert latest["status"] == "failed"
    assert latest["error"] == "Background queue unavailable; sync was not started"
