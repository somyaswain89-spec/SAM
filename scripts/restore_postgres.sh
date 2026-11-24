#!/usr/bin/env bash
set -euo pipefail

backup_file="${1:-}"
if [[ -z "$backup_file" || ! -s "$backup_file" ]]; then
  echo "Usage: $0 path/to/sam-postgres-YYYYMMDDTHHMMSSZ.dump" >&2
  exit 2
fi
if [[ -f "$backup_file.sha256" ]]; then
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$backup_file.sha256"
  else
    sha256sum -c "$backup_file.sha256"
  fi
fi

echo "This replaces the SAM database contents with $backup_file."
read -r -p "Type RESTORE to continue: " confirmation
if [[ "$confirmation" != "RESTORE" ]]; then
  echo "Restore cancelled."
  exit 1
fi

docker compose stop api worker
docker compose exec -T postgres pg_restore \
  --username=sam --dbname=sam --clean --if-exists --no-owner --exit-on-error \
  < "$backup_file"
docker compose up -d api worker
echo "Database restore completed. Verify /health/ready and application data before reopening traffic."
