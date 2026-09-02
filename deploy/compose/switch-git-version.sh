#!/bin/sh
set -eu

action=${1-}
version=${2-}
case "$action" in upgrade|rollback) ;; *) echo "usage: $0 upgrade|rollback VERSION" >&2; exit 64 ;; esac
case "$version" in ''|*[!A-Za-z0-9._-]*) echo "invalid immutable Git image version" >&2; exit 64 ;; esac

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
deploy_root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
record=$deploy_root/gitd/state/deployed-image-version

[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || {
  echo "missing or unsafe mode-0600 production environment file: $environment" >&2
  exit 1
}
[ -d "$deploy_root/gitd/state" ] && [ ! -L "$deploy_root/gitd/state" ] || {
  echo "provisioned Gitd state directory is required" >&2
  exit 1
}

for image in "mrml/gitd:$version" "mrml/git-authority:$version"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "required preloaded image is absent: $image" >&2
    exit 1
  }
done

MRML_GIT_VERSION=$version
export MRML_GIT_VERSION
"$directory/test-compose-git.sh" "$git_compose"
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" config --quiet
docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  up -d --no-build --pull never git-authority gitd

deadline=60
while [ "$deadline" -gt 0 ]; do
  ready=true
  for service in git-authority gitd; do
    container=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps -q "$service")
    [ -n "$container" ] || ready=false
    [ -n "$container" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ] || ready=false
  done
  [ "$ready" = true ] && break
  sleep 2
  deadline=$((deadline - 2))
done
[ "$ready" = true ] || {
  echo "$action did not reach healthy state; inspect status before any further change" >&2
  exit 1
}

temporary=$record.new.$$
umask 077
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
printf '%s\n' "$version" >"$temporary"
chmod 0600 "$temporary"
mv -f "$temporary" "$record"
trap - EXIT HUP INT TERM
sync "$record"
echo "Git $action completed at immutable image version $version; repository data was not rolled back"
