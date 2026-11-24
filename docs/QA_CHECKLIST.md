# QA acceptance checklist

Use an isolated QA environment, customer-approved test data, test identities, and non-production connector credentials. Never use the production environment for containment or destructive tests.

## Start and authenticate

- `docker compose config` validates the environment file and service configuration.
- `docker compose up --build -d` completes the migration service before API/worker start.
- Nginx `/healthz`, API `/health/live`, and API `/health/ready` pass; the worker health check reports a Celery worker.
- Login succeeds only with the provisioned account; verify missing/invalid token is 401 and role-forbidden API requests are 403.
- Create two analyst accounts with distinct import and governance requests; verify each sees only their own rows and page totals, while admin/security-admin/auditor oversight lists show all. Directly request another user's job and expect 404.
- Verify refresh-cookie rotation, CSRF rejection, logout revocation, password reset delivery configuration, account lockout, and security headers.
- Verify errors return correlation IDs but no stack traces, submitted passwords, reset tokens, DB paths, or environment secrets.

## Asset and finding data

- List assets with Website/Server filters, Internal facing/External facing classifications, search, status, supported sort, and pagination.
- Create, detail, update, and export an asset. Confirm persistence after API restart and an audit event for the update.
- Create/import duplicate IDs and invalid row data; verify only valid rows persist and a row-level error report is downloadable.
- Verify finding filters, deterministic severity ordering, state transitions, impacted assets, risk factors, and SLA due-date handling.
- Try invalid entity, sort, compliance range, cross-asset finding link, and direct unauthorized requests.

## Risk, compliance, and exposure

- Compare dashboard counts with server-filtered asset and finding lists.
- Inspect risk-score factors and ensure the score is described as a heuristic, not a probability.
- Verify null compliance remains unknown; due-date forecasts include explicit SLA dates only.
- Verify WAF/exposure labels are shown as source-recorded evidence, not independent discovery.
- Add/remove an explicit `depends_on` relation and verify the attack-path relationship changes.
- Review zero-day signals, confidence/evidence, and the impacted-asset list; a missing CVE is not a confirmed zero-day.

## Governance, containment, and analyst

- Submit an exception, reject self-review, and record an independent approval or rejection with notes and expiry.
- Create workflow requests and inspect their durable state/audit history.
- Preview quarantine/release impact before submitting. Verify the API lists recorded dependent assets, the action-specific expected effect, and the data basis; confirm changing the asset/action resets acknowledgement and that the preview does not claim unrecorded business impact.
- Request quarantine/release only in QA. Verify business-impact acknowledgement and independent approval are required, and that SAM says `pending_connector` until an external provider confirms an action.
- Ask the analyst rescan, WAF, compliance, prioritization, containment, and arbitrary questions; verify responses use server records or clearly state limits.
- Ask a follow-up question that refers to the previous answer; verify only the bounded recent conversation is used and that provider-disabled mode stays clearly labeled.
- Confirm executive report values match API records and audit-chain verification detects tampered data in an isolated test.

## File and worker flow

- Reject oversize, unsupported, MIME-mismatched, malformed, and traversal-style filenames.
- Confirm upload creates a queued job; worker reads from shared storage; job progress/errors are recorded; restart API/worker and confirm files remain available.
- Inject a transient worker I/O failure after a committed import batch; confirm the job keeps its staged file while retrying, the retry resumes without duplicate assets or audit events, and the final row counts match the source file.
- Confirm export runs in worker, formula-prefixed data is escaped, and only authorized job owners/admin roles can access output.
- Stop Redis/worker and verify enqueue returns an error without false success or partial imported asset records.

## Integrations and operational controls

- With no credentials, connector status is `unconfigured`, connection tests and sync return configuration errors, and no source data is created.
- Run the threat-intelligence connection check and manual sync against the public feed endpoints. Verify CISA count validation, bounded FIRST EPSS batching, CVE-to-finding and impacted-asset joins, exact score/date persistence, priority source labels, and no overwriting the last good snapshot on an incomplete feed response.
- For a scanner detection containing more than one CVE, confirm each CVE persists in `finding_cves`, appears in finding details, is searched independently, and resolves to the same impacted finding and asset. Apply migrations to a pre-existing QA database and confirm old primary/evidence CVEs are backfilled.
- Verify exactly one Beat scheduler is deployed, daily execution is UTC 02:15, an active manual run suppresses a duplicate schedule, and failures are visible in sync history without claiming refreshed data.
- Configure the Cert Spotter credential on API and worker; confirm the status endpoint reports only configuration, not provider health. Register a customer-authorized domain with an audit note, verify duplicate active runs are blocked, inspect bounded pagination/errors, and ensure only in-scope CT names become candidates. Confirm candidate acceptance requires an authorized admin review, writes an external-facing website asset with source evidence, and that discovery never sends traffic to discovered hosts. Verify the daily Beat task skips cleanly without credentials and runs against approved targets when configured.
- Retry exception, workflow, and containment submissions with the same idempotency key and payload; verify one persisted operation and an identical replay. Reuse the key with a different body and expect `409`. Verify the DB partial unique index allows only one queued/running sync per connector across API replicas.
- Retry asset create/update and finding create/state mutations with the same key; verify one response and one audit event. Run the idempotency-retention worker and verify expired completed records and abandoned claims are removed while fresh claims and audit history remain.
- Retry the same asset import file/mapping and export request with the same key. Confirm the existing job is returned, the worker is enqueued once, a changed import payload returns `409`, and the raw idempotency key is never stored.
- Adapter parser/mapping and stable-ID repeat-upsert tests pass locally. With approved sandbox credentials, validate connection and field mappings first; sync a limited sample and verify pagination, deduplication, tenant-specific reconciliation, retry/rate-limit behavior, audit, and secret redaction. The current adapter does not retire records absent from a later pull; agree the stale-record policy separately.
- Validate containment only with a provider sandbox, explicit two-person approval, impact review, action idempotency, and a tested recovery path.
- From the repository root, run `npm --prefix frontend ci`, `npx --prefix frontend playwright install chromium`, and `npm --prefix frontend run test:e2e` against the isolated SQLite QA stack; run API and browser journeys against PostgreSQL in a Docker-capable QA environment as a separate deployment gate. Also run frontend unit/build/type/lint, backend tests/lint/type checks, dependency scanning, and security regression tests in CI.
- Take a backup, restore it to a clean QA environment, verify data/audit/job state and volumes, and document elapsed RPO/RTO evidence.
