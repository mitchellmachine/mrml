#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

"$directory/validate-git.sh"
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  up -d --no-build --pull never
