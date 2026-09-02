#!/bin/sh
set -eu

usage="usage: $0 NONZERO_BACKUP_GENERATION /mnt/EMPTY_RESTORE_ROOT"
generation=${1-}
target=${2-}
case "$generation" in ''|0|*[!0-9]*) echo "$usage" >&2; exit 64 ;; esac
[ "$#" -eq 2 ] || { echo "$usage" >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "ACME restore requires root" >&2; exit 1; }
case "$target" in /mnt/?*) ;; *) echo "restore target must be an absolute child of /mnt" >&2; exit 64 ;; esac
[ ! -L "$target" ] && [ -d "$target" ] || { echo "restore target must be an existing non-symlink directory" >&2; exit 1; }
[ "$(stat -c %u:%g:%a "$target")" = "0:0:700" ] || { echo "restore target must be root:root mode 0700" >&2; exit 1; }
[ -z "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo "restore target must be empty" >&2; exit 1; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
source_root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
[ "$target" != "$source_root" ] || { echo "restore target cannot be the active deployment root" >&2; exit 1; }

for required in \
  "$source_root/backups/certd/certd-$generation.mrb" \
  "$source_root/backups/acmed/acmed-$generation.mrb" \
  "$source_root/backups/certd/manifest-$generation.mrm" \
  "$source_root/secrets/certd/backup-auth.key" \
  "$source_root/secrets/acmed/backup-auth.key"
do
  [ -f "$required" ] && [ ! -L "$required" ] || { echo "missing regular restore input: $required" >&2; exit 1; }
done

"$directory/validate-acme.sh"
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21003:21005 -e MRML_CERTD_OFFLINE_BACKUP=1 \
  -v "$source_root/secrets/certd/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$source_root/backups:/var/lib/mrml/backups:ro" \
  certd /usr/bin/mrml-certd backup-manifest-verify "$generation"

install -d -o 21003 -g 21003 -m 0700 "$target/.restore-certd"
install -d -o 21004 -g 21004 -m 0700 "$target/.restore-acmed"
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21003:21003 -e MRML_CERTD_OFFLINE_BACKUP=1 \
  -v "$source_root/secrets/certd/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$source_root/backups/certd:/var/lib/mrml/backups:ro" \
  -v "$target/.restore-certd:/restore:rw" \
  certd /usr/bin/mrml-certd backup-restore "$generation"
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21004:21004 -e MRML_ACMED_OFFLINE_BACKUP=1 \
  -v "$source_root/secrets/acmed/backup-auth.key:/run/secrets/backup-auth.key:ro" \
  -v "$source_root/backups/acmed:/var/lib/mrml/backups:ro" \
  -v "$target/.restore-acmed:/restore:rw" \
  acmed /usr/bin/mrml-acmed backup-restore "$generation"

cmp "$target/.restore-certd/secrets/channels/certd-acmed.cap.certd" \
  "$target/.restore-acmed/secrets/channels/certd-acmed.cap.acmed" >/dev/null || {
    echo "restored certd-acmed peer capability copies differ" >&2
    exit 1
  }
install -d -o 0 -g 0 -m 0700 "$target/secrets"
install -d -o 0 -g 0 -m 0700 "$target/secrets/channels"
mv "$target/.restore-certd/certd" "$target/certd"
mv "$target/.restore-acmed/acmed" "$target/acmed"
mv "$target/.restore-certd/secrets/certd" "$target/secrets/certd"
mv "$target/.restore-acmed/secrets/acmed" "$target/secrets/acmed"
mv "$target/.restore-certd/secrets/channels/certd-gitd.cap.certd" "$target/secrets/channels/"
mv "$target/.restore-certd/secrets/channels/certd-acmed.cap.certd" "$target/secrets/channels/"
mv "$target/.restore-acmed/secrets/channels/certd-acmed.cap.acmed" "$target/secrets/channels/"
rmdir "$target/.restore-certd/secrets/channels" "$target/.restore-certd/secrets" "$target/.restore-certd"
rmdir "$target/.restore-acmed/secrets/channels" "$target/.restore-acmed/secrets" "$target/.restore-acmed"

docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21003:21003 -e MRML_CERTD_OFFLINE_RESTORE=1 \
  -v "$target/certd/state:/var/lib/mrml/certd:ro" \
  -v "$target/certd/publications:/var/lib/mrml/publications:ro" \
  -v "$target/secrets/certd/certd-unlock.key:/run/secrets/certd-unlock.key:ro" \
  -v "$target/secrets/channels/certd-gitd.cap.certd:/run/secrets/certd-gitd.cap:ro" \
  certd /usr/bin/mrml-certd restore-check
docker compose --env-file "$environment" -f "$compose" run --rm --no-deps \
  --user 21004:21004 -e MRML_ACMED_OFFLINE_RESTORE=1 \
  -v "$target/acmed/state:/var/lib/mrml/acmed:ro" \
  -v "$target/secrets/acmed/acmed-state.key:/run/secrets/acmed-state.key:ro" \
  -v "$target/secrets/channels/certd-acmed.cap.acmed:/run/secrets/certd-acmed.cap:ro" \
  acmed /usr/bin/mrml-acmed restore-check
sync "$target"

echo "authenticated ACME generation $generation restored to clean target $target"
echo "services remain disabled: install reviewed configuration and Gitd peer capability, then run the activation validation gate"
