# Deployment and recovery operations

## Environments and configuration

Use separate PostgreSQL databases, Redis instances, object/file storage, credentials, and allowed origins for development, QA, staging, and production. Never reuse production records or secrets in lower environments. Keep `.env` out of Git and inject production secrets from the customer secret manager.

The Compose file runs PostgreSQL 17 and Redis 7.4 on an internal-only data network. Only Nginx publishes a port. The API and worker also receive outbound access on the dedicated egress network for configured integrations; PostgreSQL and Redis remain unreachable from that network. The API and Celery worker share the private `uploads_data` volume so queued jobs can read uploaded files and expose completed exports after container replacement. The database, Redis queue, and uploaded files use named volumes; configure volume encryption and restricted backup access in the hosting platform.

Required Compose values:

- `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `APP_SECRET_KEY`: independent high-entropy secrets. Use URL-safe alphanumeric values for database and Redis passwords because Compose builds connection URLs from them.
- `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`: initial administrator credentials. Keep the password unique and rotate it after first login.
- `CORS_ORIGINS`: exact browser origins, comma separated. Do not use wildcards with credentialed cookies.
- `APP_ENV`: `development` for local HTTP, or `production` behind a trusted HTTPS terminator. Production startup rejects SQLite, short signing secrets, insecure refresh cookies, sample data, or the default CORS origin.
- `COOKIE_SECURE`: `false` only for isolated local development; `true` under HTTPS.
- Optional `QUALYS_*` and ServiceNow CMDB values: credentials are read from the API/worker environment and never persisted in SAM. Set each provider base URL to its approved HTTPS origin. Qualys uses its v6.0 Host List and Detection APIs by default. ServiceNow defaults to `cmdb_ci_server` and `cmdb_ci_web_application`; configured table and field mappings must match the customer's CMDB schema and ACLs. Exposure mapping is omitted unless `SERVICENOW_EXPOSURE_FIELD` is set to a real field in the customer's instance. Use read-only accounts for scanner and CMDB sync.
- Optional ServiceNow ticket writer values: set `SERVICENOW_TICKET_WRITE_ENABLED=true`, `SERVICENOW_TICKET_BASE_URL`, `SERVICENOW_TICKET_USERNAME`, and `SERVICENOW_TICKET_PASSWORD` only after approving the ServiceNow incident API and a dedicated least-privilege writer account. The incident table defaults to `incident`. SAM records a local idempotency key and external correlation ID before sending a non-retried create request. It looks up the correlation ID before creation and reconciles uncertain outcomes on a repeated request. A timeout or provider 5xx stays marked unknown until reconciliation; it is never reported as success without a confirmed ServiceNow incident reference.
- Optional AI analyst values: configure `AI_ANALYST_API_KEY`, `AI_ANALYST_MODEL`, and (if using an approved compatible endpoint) `AI_ANALYST_BASE_URL`, then set both `AI_ANALYST_ENABLED=true` and `AI_ANALYST_DATA_APPROVED=true`. The analyst sends the current question, up to four previous chat turns, a bounded sample of asset metadata, complete aggregate counts, and up to 40 prioritized findings. It excludes raw finding evidence and provider credentials. Review data residency, retention, and model-provider terms with the customer before enabling; the default request disables provider-side response storage but is not a substitute for that review. The API key is supplied only to the API container and never returned to the browser or worker.
- Public threat feeds: `CISA_KEV_FEED_URL` and `EPSS_API_URL` default to the CISA KEV JSON catalog and FIRST EPSS lookup endpoint. They require no API credentials. The worker validates HTTPS, response structure, CVE IDs, dates, score ranges, and catalog counts before updating the local snapshot. `INTEGRATION_MAX_PAGES` bounds the number of batched EPSS requests. Restrict egress to approved hosts at the deployment firewall when available.
- Passive external discovery: set `CERTSPOTTER_API_TOKEN` for both API and worker containers. The approved endpoint origin is fixed to `https://api.certspotter.com`; `EXTERNAL_DISCOVERY_MAX_PAGES` bounds work per target. Register only explicitly authorized domains in SAM. Discovery reads public CT issuance records and never contacts the discovered hostnames. Candidates require administrator review before inventory promotion. The scheduled discovery task runs daily at 03:45 UTC and skips safely when credentials are absent.
- `INTEGRATION_TIMEOUT_SECONDS` and `INTEGRATION_MAX_PAGES`: upper-bounded outbound request timeout and maximum pagination. Provider responses are size-limited, redirects are rejected, and transient provider errors receive bounded retries.
- `IDEMPOTENCY_RETENTION_DAYS`: completed API mutation responses remain replayable for 1–30 days (default 7). A daily worker task removes expired response rows and abandoned in-progress claims older than 30 minutes; audit history is retained separately.

For local Compose, use `.env.example` as a template and keep `APP_ENV=development` plus `COOKIE_SECURE=false`. For production, set `APP_ENV=production`, use `COOKIE_SECURE=true`, set the real HTTPS frontend origin, and terminate TLS at a trusted ingress/load balancer. Do not expose PostgreSQL or Redis publicly. The API listens only on Compose networks and trusts proxy headers only from those private paths; do not publish it directly. If an external ingress fronts Nginx, configure Nginx real-IP handling with the ingress's exact trusted CIDRs so forwarded client addresses cannot be spoofed.

## Deploy and migrate

```sh
docker compose config
docker compose build
docker compose up -d
docker compose ps
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/health/ready
```

The `migrate` one-shot service runs `alembic upgrade head` and must succeed before API, worker, or Beat startup. Review migrations before deployment. Never downgrade production automatically and never recreate production tables at application startup. The API is stateless apart from PostgreSQL, Redis, and the shared upload volume; deploy at least two API replicas behind the ingress when the hosting platform and capacity plan support it. Celery workers can scale separately based on import queue depth. Run one Celery Beat instance; it schedules the public threat-feed refresh daily at 02:15 UTC, idempotency retention cleanup daily at 03:10 UTC, and authorized passive external discovery daily at 03:45 UTC. Discovery skips without provider credentials and avoids duplicate active runs per domain.

After deployment, verify the current Alembic revision, `/health/ready`, API login, a read-only API request, worker health, and a small QA-approved import/export in a non-production environment. The present Compose file is a single-host reference deployment; production multi-host deployments need an orchestrator, managed PostgreSQL/Redis, shared encrypted object storage, TLS, and external monitoring.

## Backup

Run the custom-format PostgreSQL backup script on a schedule from a host with Docker access:

```sh
SAM_BACKUP_DIR=/secure/backup/location ./scripts/backup_postgres.sh
```

The script applies restrictive local permissions and writes a SHA-256 sidecar. Move backups to the customer's encrypted, access-controlled backup store with retention and off-site replication. Protect backups as sensitive production data. Back up `uploads_data` separately or move files to managed object storage; a database backup alone does not preserve import inputs or exports. Define RPO/RTO and retention with the customer.

## Restore

Restoration replaces database contents. Practice in an isolated recovery environment before relying on it:

```sh
./scripts/restore_postgres.sh /secure/backup/location/sam-postgres-YYYYMMDDTHHMMSSZ.dump
```

The script verifies the sidecar when present, asks for the literal `RESTORE`, stops API and worker writes, and restores the custom-format dump. Restore the matching upload volume snapshot too, then check migration state, readiness, login, inventory counts, audit-chain verification, queued job state, and a representative export before reopening traffic. Keep a fresh pre-restore backup.

## Rollback

For an application-only release, roll back to the previous immutable image while preserving the database revision. For a migration that is backward compatible, deploy the prior app image and then create a forward fix. For a non-backward-compatible migration, stop writes, take a verified backup, and follow the approved restore procedure. Do not assume `alembic downgrade` can recover deleted or transformed customer data.

## Observability and security operations

- Collect JSON application logs and ingress logs into the customer SIEM; apply access controls and retention. Do not log secrets, tokens, uploaded file contents, or raw reset links.
- Monitor `/health/live`, `/health/ready`, the Celery worker health check, PostgreSQL, Redis, queue depth, job failures, disk/volume capacity, import row rejection rates, authentication lockouts, and 5xx/latency.
- Configure alert ownership and on-call response with the customer. No external error-tracking endpoint is configured by default.
- Rotate secrets and admin credentials, revoke sessions after compromise, apply reviewed Alembic changes, rebuild pinned images, and run dependency scanning before release.
- Before enabling real containment, require a least-privilege connector, explicit asset/provider mapping, independent approval, rollback/recovery workflow, idempotency, audit, timeout/retry rules, and tested customer-specific business-impact policy.

## Scanner and CMDB synchronization

The Integrations page exposes provider connection checks, asynchronous sync requests, and persisted sync history. A connection test performs an actual bounded read request. A sync is submitted to Celery and returns a run ID; status and record counts are read from the `sync_runs` table. Provider secrets are not returned or stored in application tables. Finding triage can create a ServiceNow incident only when the dedicated writer is enabled; the requester must provide business-impact context and the API requires an idempotency key. Ticket references and uncertain outcomes are persisted in `ticket_links`.

Threat intelligence sync downloads the complete CISA KEV catalog, then queries FIRST EPSS only for CVEs present in SAM findings, in bounded batches. Validated values are persisted in `threat_intel_records`; the current public snapshot is replaced only after both sources have been fetched and validated. The threat page lists each matching finding and impacted asset, distinguishes un-enriched values from negative matches, and supports CVE search, pagination, KEV, EPSS, and asset-type filtering. Prioritization uses the feed value when a current snapshot exists and identifies its source. EPSS estimates population-level likelihood over the next 30 days; combine it with confirmed KEV status, asset exposure, severity, and business criticality rather than treating it as a complete risk score. The scheduled run is visible in normal integration history and can be triggered manually by an administrator.

Qualys ingestion reads host inventory and vulnerability detections. Stable IDs use the provider host ID and QID; repeated runs update the same SAM records. Qualys inventory records are classified as servers with exposure unknown unless a separate approved source provides exposure data. ServiceNow ingestion reads configured CMDB tables using offset pagination and normalizes CI name, class, exposure, environment, criticality, and status. Unknown exposure remains `Unknown`; SAM does not infer internet exposure from an IP address. The CMDB adapter is read-only; incident writeback is a separate opt-in capability and account.

External discovery is a separate passive capability. An administrator records an ownership/authorization attestation for a registered domain. Cert Spotter is queried for certificate-transparency names and issuance metadata; out-of-scope names are discarded. This does not prove that a hostname resolves, is owned by the customer, is reachable, has a WAF, or is vulnerable. Administrators must validate the service owner and scope before accepting a candidate. Accepted records enter inventory as external-facing websites with discovery evidence; no DNS, HTTP, port, or vulnerability probe is sent to the hostname. Configure `CERTSPOTTER_API_TOKEN` from the deployment secret manager and verify provider access in the customer tenant before enabling operational use.

Before a customer sync, validate instance URL, API permissions, table and field names, CI class strategy, unique identifier behavior, and collision rules in the provider sandbox. Default mappings are a starting contract; tenant-specific display values and custom fields may require a mapping change. Reconcile a limited sample and compare source counts before loading full production inventory. The current sync is a full read and upsert, not a source-delete reconciliation: provider records missing from later responses are not automatically retired or deleted. Stale-record policy must be agreed before production scheduling. Qualys and ServiceNow CMDB syncs are operator-triggered in this build; only the public threat-feed refresh has an automatic daily schedule.

## Current unverified deployment items

This workspace has no local Docker daemon, PostgreSQL server, or Redis server. The Compose stack, PostgreSQL-specific locking behavior, backup/restore, and worker health command have not been executed here. Run those checks in QA before acceptance. Qualys and ServiceNow adapter code is implemented and locally parser/reconciliation tested; real endpoint access, customer ACLs/field mappings, and actual sync remain dependent on customer credentials and QA tenant details. Identity provider, email, and containment credentials/endpoints remain customer-provided dependencies.
