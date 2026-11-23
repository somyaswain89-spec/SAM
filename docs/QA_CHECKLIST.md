# SAM QA checklist

## Start and authenticate

1. Start the API with `uvicorn backend.main:app --host 127.0.0.1 --port 8765`.
2. Confirm `GET /api/health` returns `status=ok` and `database=connected`.
3. Open `/api/docs`; log in at `POST /api/auth/login` with the configured QA account.
4. Use the returned bearer token for all other routes. Confirm missing/invalid tokens return 401 and logout invalidates the session.

## Inventory and findings

- List assets with no filter, `entity=Website`, `entity=Server`, classification, text search, pagination, and each allowed sort.
- Create an asset, retrieve it, update its classification/owner/compliance, and confirm an audit event exists.
- List findings; verify Critical sorts before High, then Medium; add a finding and exercise Open → In Progress → Resolved.
- Submit a finding for a non-existent asset and confirm validation fails without partial writes.

## Risk, compliance, and exposure

- Compare dashboard totals with the filtered asset and finding lists.
- Verify priority output includes `riskScore` and factors; vary severity/classification/criticality/KEV/EPSS/age and inspect ordering.
- Verify null compliance remains unknown and is excluded from average; check only explicit due dates appear in SLA forecast.
- Verify WAF values report as recorded and never claim independent verification.
- Add an explicit `attributes.depends_on` relationship and check it appears in attack-path results; remove it and confirm the edge disappears.
- Inspect zero-day candidate warning and impacted candidate findings.

## Governance and reports

- Create an exception; confirm it is pending. Attempt self-approval and confirm it is rejected. Approve/reject using a different security admin.
- Create a rescan/false-positive/remediation workflow and verify it appears in workflow history.
- Request containment without impact acknowledgement (expect 409); request with acknowledgement; verify approval by a different admin only changes SAM QA status and reports no external action.
- Open the executive report and the AI analyst; verify answers use current database records and unknown facts are not fabricated.
- Verify audit access is limited to admin/security_admin/auditor roles.

## Integration boundary

- Confirm `GET /api/integrations/status` reports both connectors pending.
- Confirm sync requests return 501 and no `sync_runs` or remote changes are falsely recorded.
