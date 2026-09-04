#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 GENERATION RESTORE_NAMESPACE" >&2; exit 64; }
generation=$1
namespace=$2
case $generation in ''|0|*[!0-9]*|0*) echo "generation must be canonical nonzero decimal" >&2; exit 64 ;; esac
case $namespace in mrml-git-restore-[a-z0-9]*) ;; *) echo "invalid disposable restore namespace" >&2; exit 64 ;; esac
case $namespace in *[!a-z0-9-]*|*-) echo "invalid disposable restore namespace" >&2; exit 64 ;; esac
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
backup_compose=${MRML_GIT_BACKUP_COMPOSE_FILE:-$directory/compose.git-backup.yaml}
restore_compose=${MRML_GIT_RESTORE_COMPOSE_FILE:-$directory/compose.git-restore.yaml}
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
running=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q gitd git-authority)
[ -z "$running" ] || { echo "restore requires stopped Gitd and authority" >&2; exit 1; }
suffixes='gitd-repos gitd-state gitd-quarantine gitd-cache gitd-receipts gitd-policies gitd-secrets gitd-config authority-state authority-secrets authority-config'
for suffix in $suffixes; do
  volume=$namespace-$suffix
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "restore requires absent Docker volume: $volume" >&2
    exit 1
  fi
done
for suffix in $suffixes; do
  docker volume create --label org.mrml.managed=true --label org.mrml.restore-disposable=true "$namespace-$suffix" >/dev/null
done
docker compose --env-file "$environment" -f "$backup_compose" run --rm --no-deps git-backup verify "$generation"
MRML_GIT_RESTORE_NAMESPACE=$namespace docker compose --env-file "$environment" -f "$restore_compose" run --rm --no-deps git-restore restore "$generation" || {
  echo "restore failed; every $namespace-* volume is invalid and must remain disabled or be removed" >&2
  exit 1
}
echo "authenticated generation $generation restored to disposable named-volume namespace $namespace"
echo "services remain disabled; run recovery and validation before any explicit activation"
