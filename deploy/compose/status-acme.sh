#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ -f "$environment" ] && [ ! -L "$environment" ] || {
  echo "missing or unsafe production environment file: $environment" >&2
  exit 1
}
docker compose --env-file "$environment" -f "$compose" ps --all
