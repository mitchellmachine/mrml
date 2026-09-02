#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ -f "$environment" ] && [ ! -L "$environment" ] || {
  echo "missing or unsafe production environment file: $environment" >&2
  exit 1
}
[ "$(stat -c %a "$environment")" = 600 ] || {
  echo "production environment file must have mode 0600" >&2
  exit 1
}
"$directory/test-compose-acme.sh" "$compose"
docker compose --env-file "$environment" -f "$compose" config --quiet
echo "MRML ACME deployment validation PASS"
