#!/bin/sh
set -eu

generation=${1-}
case "$generation" in ''|0|*[!0-9]*) echo "usage: $0 NONZERO_BACKUP_GENERATION" >&2; exit 64 ;; esac
[ "$#" -eq 1 ] || { echo "usage: $0 NONZERO_BACKUP_GENERATION" >&2; exit 64; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
"$directory/validate-acme.sh"
[ ! -e "$root/backups/certd/certd-$generation.mrb" ] || { echo "certd backup component already exists" >&2; exit 1; }
[ ! -e "$root/backups/acmed/acmed-$generation.mrb" ] || { echo "acmed backup component already exists" >&2; exit 1; }

docker compose --env-file "$environment" -f "$compose" stop acmed certd
restart=true
trap 'if [ "$restart" = true ]; then docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never certd acmed; fi' EXIT HUP INT TERM

docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21003:21005 -e MRML_CERTD_OFFLINE_BACKUP=1 \
  -v "$root/secrets/certd/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$root/backups/certd:/var/lib/mrml/backups:rw" \
  certd /usr/bin/mrml-certd backup-create "$generation"
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21004:21005 -e MRML_ACMED_OFFLINE_BACKUP=1 \
  -v "$root/secrets/acmed/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$root/backups/acmed:/var/lib/mrml/backups:rw" \
  acmed /usr/bin/mrml-acmed backup-create "$generation"

docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21003:21005 -e MRML_CERTD_OFFLINE_BACKUP=1 \
  -v "$root/secrets/certd/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$root/backups/certd:/var/lib/mrml/backups:ro" \
  certd /usr/bin/mrml-certd backup-verify "$generation"
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21004:21005 -e MRML_ACMED_OFFLINE_BACKUP=1 \
  -v "$root/secrets/acmed/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$root/backups/acmed:/var/lib/mrml/backups:ro" \
  acmed /usr/bin/mrml-acmed backup-verify "$generation"

docker compose --env-file "$environment" -f "$compose" up -d --no-build --pull never certd acmed
restart=false
trap - EXIT HUP INT TERM
echo "encrypted ACME backup components created and verified at generation $generation"
echo "the authenticated combined manifest and clean-target restore gate remain required"
