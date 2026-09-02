#!/bin/sh
set -eu

root=${1:-.}
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$root" in /*) bundle=$root ;; *) bundle=$(CDPATH= cd -- "$root" && pwd) ;; esac

"$directory/verify-offline-git-bundle.sh" "$bundle"
version=$(sed -n 's/^version=//p' "$bundle/images.git.lock")
case "$version" in ''|*[!A-Za-z0-9._-]*) echo "invalid image-lock version" >&2; exit 1 ;; esac
[ "$(grep -c '^version=' "$bundle/images.git.lock")" -eq 1 ] || exit 1

for image in git-authority gitd; do
  expected=$(grep -F "image=mrml/$image:$version " "$bundle/images.git.lock")
  [ "$(printf '%s\n' "$expected" | wc -l)" -eq 1 ] && [ -n "$expected" ] || exit 1
  docker load -i "$bundle/images/$image.tar" >/dev/null
  actual=$(docker image inspect --format \
    'image={{index .RepoTags 0}} id={{.Id}} repo_digests={{json .RepoDigests}}' \
    "mrml/$image:$version")
  [ "$actual" = "$expected" ] || {
    echo "loaded image identity does not match images.git.lock: mrml/$image:$version" >&2
    exit 1
  }
done

echo "offline Git images loaded with exact locked identities: $version"
