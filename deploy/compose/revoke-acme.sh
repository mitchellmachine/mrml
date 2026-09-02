#!/bin/sh
set -eu

action=${1-}
reason=${2-}
approval=${3-}
case "$reason" in
  unspecified|key-compromise|affiliation-changed|superseded|cessation-of-operation|privilege-withdrawn) ;;
  *) echo "unsupported revocation reason" >&2; exit 64 ;;
esac
case "$action" in
  preview) [ "$#" -eq 2 ] || { echo "usage: $0 preview REASON|commit REASON APPROVAL_SHA256" >&2; exit 64; } ;;
  commit)
    [ "$#" -eq 3 ] || { echo "usage: $0 preview REASON|commit REASON APPROVAL_SHA256" >&2; exit 64; }
    case "$approval" in ''|*[!0-9a-f]*) echo "approval must be 64 lowercase hexadecimal characters" >&2; exit 64 ;; esac
    [ "${#approval}" -eq 64 ] || { echo "approval must be 64 lowercase hexadecimal characters" >&2; exit 64; }
    ;;
  *) echo "usage: $0 preview REASON|commit REASON APPROVAL_SHA256" >&2; exit 64 ;;
esac

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
"$directory/validate-acme.sh"

if [ "$action" = preview ]; then
  exec docker compose --env-file "$environment" -f "$compose" exec -T acmed \
    /usr/bin/mrml-acmed revoke-preview "$reason"
fi

docker compose --env-file "$environment" -f "$compose" stop acmed
restart=true
trap 'if [ "$restart" = true ]; then docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed; fi' EXIT HUP INT TERM
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  -e MRML_ACMED_OFFLINE_ADMIN=1 acmed \
  /usr/bin/mrml-acmed revoke "$reason" "$approval"
docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never acmed
restart=false
trap - EXIT HUP INT TERM
echo "certificate revocation confirmed; inspect status before retiring any key generation"
