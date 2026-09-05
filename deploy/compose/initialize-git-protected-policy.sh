#!/bin/sh
set -eu

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
volume_prefix=${MRML_VOLUME_PREFIX:-mrml}
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) echo "invalid MRML_VOLUME_PREFIX" >&2; exit 2 ;; esac
[ "$(printf %s "$volume_prefix" | wc -c)" -le 63 ] || { echo "MRML_VOLUME_PREFIX is too long" >&2; exit 2; }

[ "$#" -eq 3 ] || {
  echo "usage: $0 OWNER/REPOSITORY VALID_FROM VALID_UNTIL" >&2
  exit 64
}
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
case $2:$3 in
  *[!0-9:]*|:*|*:) echo "validity bounds must be decimal integers" >&2; exit 64 ;;
esac
[ "$2" -gt 0 ] && [ "$2" -lt "$3" ] || {
  echo "policy validity must be nonzero and increasing" >&2
  exit 64
}
selected_repository=$(sed -n 's/^MRML_PROTECTED_REPOSITORY=//p' "$environment")
[ "$selected_repository" = "$1" ] || {
  echo "repository does not match MRML_PROTECTED_REPOSITORY" >&2
  exit 1
}
for service in gitd git-authority; do
  [ -z "$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q "$service")" ] || {
    echo "protected policy initialization requires stopped Gitd and authority" >&2
    exit 1
  }
done

docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  -f "$directory/compose.git-policy-init.yaml" \
  run --rm --no-deps \
  --entrypoint /usr/bin/mrml-gitd gitd \
  initialize-protected-policy /etc/mrml/gitd.conf "$1" \
  /run/mrml-bootstrap/openpgp-public.asc /run/mrml-bootstrap/ml-dsa-public.bin "$2" "$3"
