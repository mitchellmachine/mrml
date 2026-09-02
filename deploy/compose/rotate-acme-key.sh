#!/bin/sh
set -eu

kind=${1-}
generation=${2-}
case "$kind" in account|tls) ;; *) echo "usage: $0 account|tls EXPECTED_NEXT_GENERATION" >&2; exit 64 ;; esac
case "$generation" in ''|0|*[!0-9]*) echo "generation must be a nonzero decimal integer" >&2; exit 64 ;; esac
[ "$#" -eq 2 ] || { echo "usage: $0 account|tls EXPECTED_NEXT_GENERATION" >&2; exit 64; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
"$directory/validate-acme.sh"

certd_status=$(docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  certd /usr/bin/mrml-certd config-status)
acmed_status=$(docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  acmed /usr/bin/mrml-acmed config-status)
field=key_generation
[ "$kind" = account ] && field=account_generation
for status in "$certd_status" "$acmed_status"; do
  case " $status " in
    *" $field=$generation "*) ;;
    *) echo "certd and acmed must both configure $field=$generation" >&2; exit 1 ;;
  esac
done

docker compose --env-file "$environment" -f "$compose" stop acmed certd
restart=true
trap 'if [ "$restart" = true ]; then docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never certd acmed; fi' EXIT HUP INT TERM
docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never certd acmed
restart=false
trap - EXIT HUP INT TERM
echo "$kind key rotation started at configured generation $generation; monitor status-acme.sh"
