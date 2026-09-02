#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}

[ "$#" -eq 1 ] || {
  echo "usage: $0 OWNER/REPOSITORY" >&2
  exit 64
}
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
[ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q gitd)" ] || {
  echo "repository initialization requires stopped Gitd" >&2
  exit 1
}

docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  run --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
  initialize-repository /etc/mrml/gitd.conf "$1"
