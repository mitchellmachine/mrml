#!/bin/sh
set -eu

action=${1-}
version=${2-}
case "$action" in upgrade|rollback) ;; *) echo "usage: $0 upgrade|rollback VERSION" >&2; exit 64 ;; esac
case "$version" in ''|*[!A-Za-z0-9._-]*) echo "invalid immutable ACME image version" >&2; exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "ACME image switching must run as root" >&2; exit 1; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
deploy_root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
record=$deploy_root/certd/state/deployed-image-version

[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
[ -d "$deploy_root/certd/state" ] && [ ! -L "$deploy_root/certd/state" ] || {
  echo "provisioned certd state directory is required" >&2
  exit 1
}

for image in "mrml/certd:$version" "mrml/acmed:$version"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "required preloaded image is absent: $image" >&2
    exit 1
  }
done

MRML_ACME_VERSION=$version
export MRML_ACME_VERSION
"$directory/test-compose-acme.sh" "$compose"
docker compose --env-file "$environment" -f "$compose" config --quiet
docker compose --env-file "$environment" -f "$compose" \
  up -d --no-build --pull never certd acmed

deadline=120
ready=false
while [ "$deadline" -gt 0 ]; do
  ready=true
  for service in certd acmed; do
    container=$(docker compose --env-file "$environment" -f "$compose" ps -q "$service")
    [ -n "$container" ] || ready=false
    [ -n "$container" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ] || ready=false
  done
  [ "$ready" = true ] && break
  sleep 2
  deadline=$((deadline - 2))
done
[ "$ready" = true ] || {
  echo "$action did not reach healthy state; active durable identity was not rolled back" >&2
  exit 1
}

temporary=$record.new.$$
umask 077
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
printf '%s\n' "$version" >"$temporary"
chmod 0600 "$temporary"
chown 21003:21003 "$temporary"
mv -f "$temporary" "$record"
trap - EXIT HUP INT TERM
sync "$record"
echo "ACME $action completed at immutable image version $version; certificate state was not rolled back"
