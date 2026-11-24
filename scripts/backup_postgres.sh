#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the configured PostgreSQL backup." >&2
  exit 1
fi

backup_dir="${SAM_BACKUP_DIR:-./backups}"
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="$backup_dir/sam-postgres-$stamp.dump"
umask 077

docker compose exec -T postgres pg_dump --username=sam --format=custom --no-owner sam > "$backup_file"
if [[ ! -s "$backup_file" ]]; then
  rm -f "$backup_file"
  echo "PostgreSQL returned an empty backup; no backup was retained." >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$backup_file" > "$backup_file.sha256"
else
  sha256sum "$backup_file" > "$backup_file.sha256"
fi
echo "Created $backup_file"
