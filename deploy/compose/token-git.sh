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
[ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q gitd)" ] || {
  echo "token administration requires stopped Gitd" >&2
  exit 1
}

action=${1-}
shift || true
base="/mnt/mrml/gitd/state/tokens.v1"
pepper="/run/secrets/gitd-token-pepper"
case "$action" in
  issue)
    [ "$#" -eq 6 ] || {
      echo "usage: $0 issue REPOSITORY read|write|admin VALID_FROM EXPIRES_AT REVOCATION_GENERATION LABEL" >&2
      exit 64
    }
    docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
      run --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
      issue-token "$base" "$pepper" 21001 "$1" "$2" "$3" "$4" "$5" "$6"
    ;;
  revoke)
    [ "$#" -eq 0 ] || { echo "usage: printf TOKEN | $0 revoke" >&2; exit 64; }
    docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
      run -T --rm --no-deps --entrypoint /usr/bin/mrml-gitd gitd \
      revoke-token "$base" "$pepper" 21001
    ;;
  *) echo "usage: $0 issue|revoke ..." >&2; exit 64 ;;
esac
