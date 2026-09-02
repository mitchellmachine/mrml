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
for required in gitd/repos gitd/state gitd/receipts gitd/policies authority/state secrets/git-authority secrets/gitd secrets/channels config/gitd.conf; do
  printf '%s\n' "$entries" | grep -F "$required" >/dev/null || { echo "backup missing $required" >&2; exit 1; }
done

if [ -e "$target" ]; then
  [ -d "$target" ] && [ ! -L "$target" ] && [ -z "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo "restore target must be a new empty directory" >&2
    exit 1
  }
else
  install -d -o 0 -g 0 -m 0755 "$target"
fi
tar --numeric-owner --same-permissions -C "$target" -xzf "$archive"
MRML_DEPLOY_ROOT="$target" "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/provision-git-host.sh"
echo "restore structurally verified at $target; run authenticated Gitd recovery before activation"
