#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 GENERATION" >&2; exit 64; }
generation=$1
case $generation in ''|0|*[!0-9]*|0*) echo "generation must be canonical nonzero decimal" >&2; exit 64 ;; esac
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
backup_compose=${MRML_GIT_BACKUP_COMPOSE_FILE:-$directory/compose.git-backup.yaml}
runtime=${MRML_CONTAINER_RUNTIME:-docker}
[ "$runtime" = docker ] || [ "$runtime" = podman ] || { echo "container runtime must be docker or podman" >&2; exit 2; }
[ -f "$environment" ] && [ ! -L "$environment" ] && [ "$(stat -c %a "$environment")" = 600 ] || exit 1
volume_prefix=$(sed -n 's/^MRML_VOLUME_PREFIX=//p' "$environment")
[ "$(grep -c '^MRML_VOLUME_PREFIX=' "$environment")" -eq 1 ] || exit 1
case $volume_prefix in ''|*[!a-z0-9-]*|-*|*-|*--*) exit 1 ;; esac
for volume in "$volume_prefix-gitd-state" "$volume_prefix-authority-state"; do
  running=$("$runtime" ps -q --filter volume="$volume") || exit 1
  [ -z "$running" ] || { echo "cold backup requires Gitd and authority to be stopped" >&2; exit 1; }
done
"$runtime" compose --env-file "$environment" --profile admin -f "$backup_compose" run --rm --no-deps git-backup ensure-key
"$runtime" compose --env-file "$environment" --profile admin -f "$backup_compose" run --rm --no-deps git-backup create "$generation"
"$runtime" compose --env-file "$environment" --profile admin -f "$backup_compose" run --rm --no-deps git-backup verify "$generation"
echo "authenticated encrypted named-volume backup generation $generation created and verified"
