#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  run --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
  initialize-token-store /mnt/mrml/gitd/state/tokens.v2 /run/secrets/gitd-token-pepper 21001
echo "empty authenticated token store initialized; no access token was created"
