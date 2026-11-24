#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
ALEMBIC="$ROOT/.venv/bin/alembic"
UVICORN="$ROOT/.venv/bin/uvicorn"
VITE="$ROOT/frontend/node_modules/.bin/vite"
LOCAL_DIR="$ROOT/.sam-local"
DATABASE_URL="sqlite:///$LOCAL_DIR/sam-qa.db"
API_PID=""
VITE_PID=""

if [[ ! -x "$PYTHON" || ! -x "$ALEMBIC" || ! -x "$UVICORN" ]]; then
  echo "Python dependencies are missing. Run: uv sync --locked --extra dev" >&2
  exit 1
fi
if [[ ! -x "$VITE" ]]; then
  echo "Frontend dependencies are missing. Run: npm --prefix frontend ci" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for local readiness checks." >&2
  exit 1
fi

mkdir -p "$LOCAL_DIR/uploads"
export APP_ENV=development
export SAM_MODE=qa
export DATABASE_URL
export SAM_ADMIN_EMAIL="${SAM_ADMIN_EMAIL:-admin@sam.local}"
export SAM_ADMIN_PASSWORD="${SAM_ADMIN_PASSWORD:-demo-access}"
export SAM_TOKEN_SECRET="${SAM_TOKEN_SECRET:-sam-local-qa-only-secret-change-before-sharing}"
export COOKIE_SECURE=false
export CORS_ORIGINS="http://127.0.0.1:5173"
export LOAD_SAMPLE_DATA=true
export CELERY_TASK_ALWAYS_EAGER=true
export UPLOAD_DIR="$LOCAL_DIR/uploads"

"$ALEMBIC" -c "$ROOT/alembic.ini" upgrade head
cd "$ROOT"
"$UVICORN" backend.app:app --host 127.0.0.1 --port 8000 \
  >"$LOCAL_DIR/api.log" 2>&1 &
API_PID=$!
(
  cd "$ROOT/frontend"
  "$VITE" --host 127.0.0.1 --strictPort
) \
  >"$LOCAL_DIR/frontend.log" 2>&1 &
VITE_PID=$!

cleanup() {
  for pid in "$VITE_PID" "$API_PID"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  [[ -n "$VITE_PID" ]] && wait "$VITE_PID" 2>/dev/null || true
  [[ -n "$API_PID" ]] && wait "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=false
for _ in $(seq 1 40); do
  if ! kill -0 "$API_PID" 2>/dev/null || ! kill -0 "$VITE_PID" 2>/dev/null; then
    break
  fi
  if curl --silent --fail http://127.0.0.1:8000/health/ready >/dev/null \
    && curl --silent --fail http://127.0.0.1:5173/ >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done

if [[ "$ready" != true ]]; then
  echo "Local QA did not become ready. Recent service logs:" >&2
  tail -n 40 "$LOCAL_DIR/api.log" "$LOCAL_DIR/frontend.log" >&2 || true
  exit 1
fi

echo "SAM local QA is ready at http://127.0.0.1:5173"
echo "API readiness: http://127.0.0.1:8000/health/ready"
echo "Demo login: $SAM_ADMIN_EMAIL / $SAM_ADMIN_PASSWORD"
echo "Press Ctrl+C to stop both services. This profile uses a local SQLite DB and inline QA tasks."
tail -n 0 -F "$LOCAL_DIR/api.log" "$LOCAL_DIR/frontend.log" &
TAIL_PID=$!
wait "$TAIL_PID"
