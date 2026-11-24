# Run SAM locally in a client environment

This runbook starts the complete Docker Compose stack: React/Nginx, FastAPI, PostgreSQL, Redis, Celery worker, Celery Beat, and the Alembic migration step. It is for isolated client QA on a single workstation. For shared QA or production, use a secured hosted environment and customer-approved secrets.

## 1. Get the repository

Use the repository's **main** branch: <https://github.com/somyaswain89-spec/SAM>.

Recommended: install Git and clone the repository:

```sh
git clone https://github.com/somyaswain89-spec/SAM.git
cd SAM
```

Alternatively, on GitHub open the repository, choose **Code → Download ZIP**, extract the ZIP, then open Terminal/PowerShell in the extracted `SAM-main` directory. The repository root is the folder containing `docker-compose.yml`, `render.yaml`, and `.env.example`. Do not download or open `frontend/index.html` by itself; it is not the full application.

## 2. Install and start Docker

Install Docker Desktop for macOS or Windows, start it, and wait until it reports that the Docker engine is running. On a Linux workstation, install Docker Engine and the Docker Compose plugin. Check:

```sh
docker --version
docker compose version
```

The stack needs permission to pull the pinned base images and install the locked Python/JavaScript dependencies on its first build.

## 3. Create local settings

Copy the example file in the repository root:

```sh
cp .env.example .env
```

In Windows PowerShell, use `Copy-Item .env.example .env` instead. Edit `.env` and set unique local values for `APP_SECRET_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `BOOTSTRAP_ADMIN_EMAIL`, and `BOOTSTRAP_ADMIN_PASSWORD`. Use URL-safe random strings for the database and Redis passwords because Compose places them in connection URLs. For example, generate each value with:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set these local values:

```dotenv
APP_ENV=development
COOKIE_SECURE=false
CORS_ORIGINS=http://localhost:8080
PUBLIC_BASE_URL=http://localhost:8080
```

Keep `.env` on the workstation. Never upload it to GitHub, include it in a client ticket, or reuse its credentials in staging/production. The `.gitignore` excludes it.

## 4. Validate and start the stack

From the repository root:

```sh
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Compose starts PostgreSQL and Redis, waits for their health checks, runs Alembic migrations, then starts the API, worker, scheduler, and frontend. The first build can take several minutes.

Check readiness and open the application:

```sh
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/health/ready
```

Open <http://localhost:8080/login> and sign in with the bootstrap email/password that you put in `.env`. No sample customer data is loaded by default. Configure approved scanner/CMDB connections or import authorized QA data to populate the workspace.

## 5. Inspect logs and stop safely

```sh
docker compose logs --tail=100 api worker beat frontend migrate
docker compose down
```

`docker compose down` stops the containers and preserves named database, queue, and upload volumes. **Do not add `-v`** unless you intend to delete this local database and uploaded files. See [backup and restore](OPERATIONS.md) before moving or retaining a client dataset.

## 6. Customer connection requirements

Use only non-production credentials and approved QA endpoints for Qualys, ServiceNow, email, threat-intelligence approval, and external discovery. Keep integrations unconfigured until the client supplies and approves those values. Quarantine/shutdown remains pending an independently approved infrastructure adapter; the SAM governance record alone does not isolate a host. For production, customer platform and security teams must separately approve TLS, secret storage, monitoring, backups, retention, and recovery objectives.

## Alternative: lightweight local feature QA

`./scripts/run-local-qa.sh` runs a SQLite development database and inline Celery tasks for a single-user review. It is not a PostgreSQL/Redis deployment test. Prefer the Docker Compose steps above when validating the client's full stack.
