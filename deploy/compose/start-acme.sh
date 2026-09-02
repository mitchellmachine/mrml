#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

"$directory/validate-acme.sh"
docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never
