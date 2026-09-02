#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /absolute/backup.tar.gz" >&2
  exit 2
fi
output=$1
case $output in /*.tar.gz) ;; *) echo "backup path must be absolute and end in .tar.gz" >&2; exit 2 ;; esac
[ ! -e "$output" ] && [ ! -e "$output.sha256" ] || { echo "backup output already exists" >&2; exit 1; }

directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
environment=${MRML_ENV_FILE:-$directory/.env.production}
git_compose=${MRML_GIT_COMPOSE_FILE:-$directory/compose.git.yaml}
acme_compose=${MRML_ACME_COMPOSE_FILE:-$directory/compose.acme.yaml}
root=${MRML_DEPLOY_ROOT:-/mnt/mrml}
case $root in /mnt/*) ;; *) echo "deployment root must be below /mnt" >&2; exit 1 ;; esac
case $root in *[!A-Za-z0-9_./-]*) echo "deployment root contains unsupported characters" >&2; exit 1 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "managed-volume backup must run as root" >&2; exit 1; }

running=$(docker compose --env-file "$environment" -f "$git_compose" -f "$acme_compose" \
  ps --status running -q gitd git-authority)
[ -z "$running" ] || { echo "cold backup requires Gitd and authority to be stopped" >&2; exit 1; }

host_paths='secrets/git-authority secrets/gitd secrets/channels config/gitd.conf'
for path in $host_paths; do
  [ -e "$root/$path" ] && [ ! -L "$root/$path" ] || { echo "missing or unsafe backup input: $path" >&2; exit 1; }
  if find "$root/$path" -type l -print | grep . >/dev/null; then
    echo "backup inputs must not contain symlinks: $path" >&2
    exit 1
  fi
done

volumes='gitd/repos:mrml-gitd-repos gitd/state:mrml-gitd-state gitd/quarantine:mrml-gitd-quarantine gitd/receipts:mrml-gitd-receipts gitd/policies:mrml-gitd-policies authority/state:mrml-authority-state'
for mapping in $volumes; do
  volume=${mapping#*:}
  mountpoint=$(docker volume inspect --format '{{.Mountpoint}}' "$volume") || { echo "missing backup volume: $volume" >&2; exit 1; }
  case $mountpoint in /*/_data) ;; *) echo "unsafe backup volume mountpoint: $volume" >&2; exit 1 ;; esac
  [ -d "$mountpoint" ] && [ ! -L "$mountpoint" ] || { echo "unsafe backup volume: $volume" >&2; exit 1; }
  if find "$mountpoint" -type l -print | grep . >/dev/null; then
    echo "backup volume must not contain symlinks: $volume" >&2
    exit 1
  fi
done

umask 077
temporary=$output.new.$$
uncompressed=$output.tar.new.$$
trap 'rm -f "$temporary" "$uncompressed"' EXIT HUP INT TERM
tar --sort=name --mtime='UTC 1970-01-01' --numeric-owner -C "$root" -cf "$uncompressed" $host_paths
for mapping in $volumes; do
  archive_path=${mapping%:*}
  volume=${mapping#*:}
  mountpoint=$(docker volume inspect --format '{{.Mountpoint}}' "$volume")
  tar --sort=name --mtime='UTC 1970-01-01' --numeric-owner \
    --transform="s|^\./|$archive_path/|" -C "$mountpoint" -rf "$uncompressed" .
done
gzip -n -c "$uncompressed" > "$temporary"
chmod 0600 "$temporary"
mv "$temporary" "$output"
rm -f "$uncompressed"
trap - EXIT HUP INT TERM
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")") > "$output.sha256"
chmod 0600 "$output.sha256"
echo "cold authenticated-state backup created: $output"
echo "encrypt and store the backup offline; it contains recovery secrets"
