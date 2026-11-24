# Render staging deployment

The root `render.yaml` describes a staging stack in the Ohio region: a public Nginx frontend, a private FastAPI service, a Celery worker, a Celery Beat scheduler, Render PostgreSQL, and private Render Key Value for Redis. PostgreSQL and Redis accept only private-network connections. The API migrations run as a pre-deploy command. Render receives application logs from container stdout/stderr; the frontend health probe uses `/healthz`, and the private API receives Render's TCP health probe.

## Deployment gate: shared upload storage

Do not deploy this Blueprint for feature acceptance until file processing is moved from `UPLOAD_DIR` to shared object storage. SAM currently writes import uploads and export files to a local filesystem path used by both API and worker. Render persistent disks attach to one service and cannot be mounted by both API and worker. An API-only disk would make imports/exports fail in the worker; independent disks would lose access across services. Implement and test an S3-compatible storage adapter (upload staging, worker reads, export writes/downloads, retention and deletion) before enabling import/export on Render. Configure a private bucket and least-privilege credentials through Render secrets; do not commit them.

Qualys, ServiceNow, Cert Spotter, SMTP, and optional AI credentials are intentionally not included. Add them only after customer approval and staging endpoint validation. The account bootstrap email/password are `sync: false` prompts during initial Blueprint creation and must be unique staging credentials.

## Render setup

1. Sign in to the Render Dashboard with the GitHub account that has access to `somyaswain89-spec/SAM`.
2. Create a Blueprint from the repository, select branch `codex/sam-full-stack-transformation`, and use the repository-root `render.yaml`.
3. Review the resource plan and billing before provisioning. The Blueprint deliberately uses paid compute, persistent PostgreSQL, and persistent Key Value so migrations and queue state are not based on free-tier ephemeral resources.
4. Enter unique staging bootstrap credentials. Do not reuse any production password.
5. Keep the deployment gated until the shared object-storage adapter is implemented. After it is, deploy staging only, verify migrations, `/healthz`, login, API-to-database and API/worker-to-Redis private connections, import/export job persistence, logs, and restore procedures.
6. Run scanner/CMDB and other provider checks only with approved sandbox credentials. Record the test evidence and any tenant-specific mappings.
7. Obtain explicit customer approval before creating or promoting any production Blueprint. Use separate production database, queue, secrets, bucket, and service names.

Blueprint file syntax can be parsed locally, but Render's authenticated Blueprint validation and provisioning have not been performed from this workspace.
