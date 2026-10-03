#!/bin/sh
set -eu

task_repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_repo_dir"

for task_command in go docker; do
    if ! command -v "$task_command" >/dev/null 2>&1; then
        printf 'Required command is missing: %s\n' "$task_command" >&2
        exit 1
    fi
done

if ! docker info >/dev/null 2>&1; then
    printf 'Start Docker, then run this script again.\n' >&2
    exit 1
fi

if [ ! -f .env ]; then
    cp .env.example .env
    printf 'Created .env with synthetic local demonstration settings.\n'
fi
set -a
. ./.env
set +a

docker compose up -d --wait db
go run ./cmd/migrate
printf 'Starting the EK1 API; use Ctrl+C to stop the server.\n'
exec go run ./cmd/server
