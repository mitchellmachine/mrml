#!/bin/sh
set -eu

[ "${1-}" = confirm-exact-records ] && [ "$#" -eq 1 ] || {
  echo "usage: $0 confirm-exact-records" >&2
  exit 64
}

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
"$directory/validate-acme.sh"

docker compose --env-file "$environment" -f "$compose" stop acmed
restart=true
trap 'if [ "$restart" = true ]; then docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed; fi' EXIT HUP INT TERM
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  -e MRML_ACMED_OFFLINE_ADMIN=1 acmed /usr/bin/mrml-acmed \
  dns-cleanup confirm-exact-records
docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed
restart=false
trap - EXIT HUP INT TERM
echo "persisted DNS-01 cleanup completed; unrelated TXT values were not selected"
