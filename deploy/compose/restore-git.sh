#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /absolute/backup.tar.gz /mnt/new-empty-root" >&2
  exit 2
fi
archive=$1
target=$2
case $archive in /*.tar.gz) ;; *) echo "archive path must be absolute and end in .tar.gz" >&2; exit 2 ;; esac
case $target in /mnt/*) ;; *) echo "restore target must be an absolute path below /mnt" >&2; exit 2 ;; esac
case $target in *[!A-Za-z0-9_./-]*) echo "restore target contains unsupported characters" >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "restore must run as root" >&2; exit 1; }
[ -f "$archive" ] && [ ! -L "$archive" ] && [ -f "$archive.sha256" ] && [ ! -L "$archive.sha256" ] || {
  echo "archive and sidecar checksum must be regular non-symlink files" >&2
  exit 1
}
(cd "$(dirname "$archive")" && sha256sum -c --strict "$(basename "$archive").sha256")

entries=$(tar -tzf "$archive")
[ -n "$entries" ] || { echo "empty backup rejected" >&2; exit 1; }
printf '%s\n' "$entries" | awk '
  /^\// || /(^|\/)\.\.($|\/)/ || /(^|\/)\.($|\/)/ { exit 1 }
' || { echo "unsafe archive path rejected" >&2; exit 1; }
tar -tvzf "$archive" | awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { exit 1 }' || {
  echo "archive links or special files rejected" >&2
  exit 1
}
for required in gitd/repos gitd/state gitd/receipts gitd/policies gitd/secrets gitd/config authority/state authority/secrets authority/config; do
  printf '%s\n' "$entries" | grep -F "$required" >/dev/null || { echo "backup missing $required" >&2; exit 1; }
done

volumes='gitd/repos:mrml-gitd-repos gitd/state:mrml-gitd-state gitd/quarantine:mrml-gitd-quarantine gitd/receipts:mrml-gitd-receipts gitd/policies:mrml-gitd-policies gitd/secrets:mrml-gitd-secrets gitd/config:mrml-gitd-config authority/state:mrml-authority-state authority/secrets:mrml-git-authority-secrets authority/config:mrml-git-authority-config'
required_absent_volumes='mrml-gitd-repos mrml-gitd-state mrml-gitd-quarantine mrml-gitd-cache mrml-gitd-receipts mrml-gitd-policies mrml-gitd-secrets mrml-gitd-config mrml-authority-state mrml-git-authority-secrets mrml-git-authority-config mrml-runtime-git-authority'
for volume in $required_absent_volumes; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "restore requires absent Docker volume: $volume" >&2
    exit 1
  fi
done

if [ -e "$target" ]; then
  [ -d "$target" ] && [ ! -L "$target" ] && [ -z "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo "restore target must be a new empty directory" >&2
    exit 1
  }
else
  install -d -o 0 -g 0 -m 0755 "$target"
fi
provisioner=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/provision-git-host.sh
MRML_DEPLOY_ROOT="$target" "$provisioner"
for mapping in $volumes; do
  archive_path=${mapping%:*}
  volume=${mapping#*:}
  mountpoint=$(docker volume inspect --format '{{.Mountpoint}}' "$volume")
  case $archive_path in gitd/*|authority/*) strip=2 ;; *) exit 1 ;; esac
  tar --numeric-owner --same-permissions -C "$mountpoint" --strip-components="$strip" \
    -xzf "$archive" "$archive_path"
done
MRML_DEPLOY_ROOT="$target" "$provisioner"
echo "restore structurally verified into managed volumes and $target; run authenticated Gitd recovery before activation"
