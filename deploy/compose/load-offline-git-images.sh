#!/bin/sh
set -eu

root=${1:-.}
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$root" in /*) bundle=$root ;; *) bundle=$(CDPATH= cd -- "$root" && pwd) ;; esac

"$directory/verify-offline-git-bundle.sh" "$bundle"
version=$(sed -n 's/^version=//p' "$bundle/images.git.lock")
case "$version" in ''|*[!A-Za-z0-9._-]*) echo "invalid image-lock version" >&2; exit 1 ;; esac
[ "$(grep -c '^version=' "$bundle/images.git.lock")" -eq 1 ] || exit 1

for image in git-authority gitd git-protected-signer git-backup; do
  expected=$(grep -F "image=mrml/$image:$version " "$bundle/images.git.lock")
  [ "$(printf '%s\n' "$expected" | wc -l)" -eq 1 ] && [ -n "$expected" ] || exit 1
  expected_archive=$(printf '%s\n' "$expected" | sed -n 's/.* archive_sha256=\([0-9a-f]\{64\}\) .*/\1/p')
  expected_user=$(printf '%s\n' "$expected" | sed -n 's/.* user=\([^ ]*\) .*/\1/p')
  expected_entrypoint=$(printf '%s\n' "$expected" | sed -n 's/.* entrypoint=\([^ ]*\)$/\1/p')
  [ -n "$expected_archive" ] && [ -n "$expected_user" ] && [ -n "$expected_entrypoint" ] || exit 1
  actual_archive=$(sha256sum "$bundle/images/$image.tar" | awk '{print $1}')
  [ "$actual_archive" = "$expected_archive" ] || {
    echo "image archive does not match images.git.lock: mrml/$image:$version" >&2
    exit 1
  }
  docker load -i "$bundle/images/$image.tar" >/dev/null
  if ! docker image inspect "mrml/$image:$version" >/dev/null 2>&1; then
    docker image inspect "localhost/mrml/$image:$version" >/dev/null 2>&1 || {
      echo "loaded archive did not provide its locked image tag: mrml/$image:$version" >&2
      exit 1
    }
    docker tag "localhost/mrml/$image:$version" "mrml/$image:$version"
  fi
  actual=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}}' \
    "mrml/$image:$version")
  [ "$actual" = "linux/amd64 $expected_user [\"$expected_entrypoint\"]" ] || {
    echo "loaded image runtime identity does not match images.git.lock: mrml/$image:$version" >&2
    exit 1
  }
done

echo "offline Git images loaded with exact locked identities: $version"
