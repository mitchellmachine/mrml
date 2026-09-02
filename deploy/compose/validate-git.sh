#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ -f "$environment" ] && [ ! -L "$environment" ] || {
  echo "missing or unsafe production environment file: $environment" >&2
  exit 1
}
[ "$(stat -c %a "$environment")" = 600 ] || {
  echo "production environment file must have mode 0600" >&2
  exit 1
}
"$directory/test-compose-git.sh" "$git_compose"
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" config --quiet
echo "MRML Git deployment validation PASS"
