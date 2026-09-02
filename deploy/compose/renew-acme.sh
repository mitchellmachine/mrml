#!/bin/sh
set -eu

action=${1-}
approval=${2-}
case "$action" in
  preview) [ -z "$approval" ] || { echo "usage: $0 preview|commit APPROVAL_SHA256" >&2; exit 64; } ;;
  commit)
    case "$approval" in
      ''|*[!0-9a-f]* ) echo "approval must be 64 lowercase hexadecimal characters" >&2; exit 64 ;;
    esac
    [ "${#approval}" -eq 64 ] || { echo "approval must be 64 lowercase hexadecimal characters" >&2; exit 64; }
    ;;
  *) echo "usage: $0 preview|commit APPROVAL_SHA256" >&2; exit 64 ;;
esac

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
"$directory/validate-acme.sh"

if [ "$action" = preview ]; then
  exec docker compose --env-file "$environment" -f "$compose" exec -T acmed \
    /usr/bin/mrml-acmed renew-now-preview
fi

docker compose --env-file "$environment" -f "$compose" stop acmed
restart=true
trap 'if [ "$restart" = true ]; then docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed; fi' EXIT HUP INT TERM
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  -e MRML_ACMED_OFFLINE_ADMIN=1 acmed /usr/bin/mrml-acmed renew-now "$approval"
docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed
restart=false
trap - EXIT HUP INT TERM
echo "immediate renewal requested; use status-acme.sh to observe completion"
