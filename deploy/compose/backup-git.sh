#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 GENERATION" >&2; exit 64; }
generation=$1
case $generation in ''|0|*[!0-9]*|0*) echo "generation must be canonical nonzero decimal" >&2; exit 64 ;; esac
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
backup_compose=${MRML_GIT_BACKUP_COMPOSE_FILE:-$directory/compose.git-backup.yaml}
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
running=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" ps --status running -q gitd git-authority)
[ -z "$running" ] || { echo "cold backup requires Gitd and authority to be stopped" >&2; exit 1; }
docker compose --env-file "$environment" -f "$backup_compose" run --rm --no-deps git-backup ensure-key
docker compose --env-file "$environment" -f "$backup_compose" run --rm --no-deps git-backup create "$generation"
docker compose --env-file "$environment" -f "$backup_compose" run --rm --no-deps git-backup verify "$generation"
echo "authenticated encrypted named-volume backup generation $generation created and verified"
