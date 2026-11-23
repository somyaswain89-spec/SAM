# SAM
SAM RFP

---

# SAM Security Exposure Platform — QA build

SAM now has a modular, persistent API for QA. Feature routers live under `backend/api/`; shared database, settings, authentication, and audit helpers live under `backend/core/`; validated request contracts live under `backend/schemas/`. Qualys and ServiceNow connectivity are isolated as pending adapters in `backend/api/integrations.py`.

## Run for QA

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8765
```

Default mode is `qa`, with fictional seed data and OpenAPI at `/api/docs`. Default QA login is `admin@sam.local` / `demo-access`. Override with `SAM_ADMIN_EMAIL` and `SAM_ADMIN_PASSWORD` before first startup. Set `DATABASE_URL=postgresql://user:password@host:5432/sam` to use PostgreSQL, or use the default local SQLite database. Set `SAM_TOKEN_SECRET` and `SAM_CORS_ORIGINS` for an environment-specific QA deployment. Do not use demo credentials outside an isolated QA environment.

## Run the QA checks

```sh
pip install -r backend/requirements-qa.txt
python -m pytest backend/tests -q
```

The tests use an isolated temporary SQLite database and fictional data. They exercise authentication, inventory pagination, finding order, dashboard counts, priority/SLA output, attack paths, governance safeguards, analyst responses, and the explicit integration-pending behavior.

## Feature map

- `backend/api/auth.py` — login, logout, session identity, QA user provisioning.
- `backend/api/assets.py` — paged inventory, filters, CRUD, asset detail with findings.
- `backend/api/findings.py` — findings, state changes, deterministic severity sorting.
- `backend/api/dashboard.py` — dashboard aggregation and risk-priority scoring.
- `backend/api/risk.py` — due-date SLA forecast; no SLA is inferred when no due date exists.
- `backend/api/compliance.py` — recorded-score summary and per-asset compliance view; unknown is not treated as failure.
- `backend/api/exposure.py` — external/internal classifications and recorded WAF posture.
- `backend/api/attack_paths.py` — explicit `attributes.depends_on` graph edges only.
- `backend/api/threats.py` — zero-day candidate findings and synthetic QA signals.
- `backend/api/governance.py` — exceptions, two-person review, response workflows, containment impact/approval simulation.
- `backend/api/reports.py` — executive JSON report.
- `backend/api/analyst.py` — authenticated, rule-based QA analyst grounded in SAM records.
- `backend/api/audit.py` — role-restricted audit-event query.
- `backend/api/integrations.py` — connector health and explicit not-yet-implemented sync boundary.

## Data rules

- List APIs return `items`, `total`, `limit`, and `offset`; maximum page size is 500.
- Assets default to `name ASC, id ASC`. Allowed asset sorts: `name`, `criticality`, `compliance`, `updated_at`, `kind`.
- Findings default to severity-weighted risk order (Critical, High, Medium, Low, Informational), then latest update, then ID. `/api/risk/priorities` returns the computed score and factors and sorts by score descending, due date ascending, then finding ID.
- The risk score is a transparent heuristic from severity, exposure classification, criticality, KEV flag, EPSS, and age. It is not a calibrated probability.
- Compliance percentages are stored observations. SAM does not claim a compliance control passed unless control evidence is integrated.
- SLA forecast only uses explicit `due_at` values.
- Attack paths include only relationships explicitly stored in an asset's `attributes.depends_on` array.
- Containment approval changes only SAM's QA asset state. It never calls endpoint, cloud, firewall, network, or WAF systems.

## Main routes

`POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`; `GET|POST /api/assets`, `GET|PATCH /api/assets/{id}`; `GET|POST /api/findings`, `PATCH /api/findings/{id}/state`; `GET /api/dashboard`; `GET /api/risk/priorities`, `GET /api/risk/sla-forecast`; `GET /api/compliance/summary`, `/api/compliance/assets`; `GET /api/exposure/summary`, `/api/exposure/external-assets`; `GET /api/attack-paths`; `GET /api/threats/zero-day-signals`; `POST|GET /api/exceptions`, `POST /api/exceptions/{id}/review`; `POST|GET /api/workflows`; `POST|GET /api/containment/requests`, `POST /api/containment/requests/{id}/decision`; `GET /api/reports/executive`; `POST /api/analyst/ask`; `GET /api/audit`; `GET /api/integrations/status`.

## Integration boundary

The integration endpoints intentionally report `501` until source-specific Qualys and ServiceNow adapters are implemented and validated. No live records are fetched or written. Integration remains the planned pending work; the QA customer can test SAM-owned data flows, API behavior, scoring, reports, audit, and simulated approvals without sending actions to infrastructure.

This build is for isolated QA, not production. Before go-live, add versioned schema migrations, SSO and organization-scoped authorization, managed secrets, backup/restore verification, monitoring, a durable import queue, and client-approved source adapters. PostgreSQL is supported for QA; do not assume this alone constitutes production hardening.
