#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi
version=$1
case "$version" in *[!A-Za-z0-9._-]*|'') echo "invalid version" >&2; exit 2;; esac

deploy/compose/test-compose-acme.sh deploy/compose/compose.acme.yaml
./target/release/mrml build org.mrml.service.certificate --target linux --release
./target/release/mrml test org.mrml.service.certificate --target linux --release
./target/release/mrml build org.mrml.service.acme --target linux --release
./target/release/mrml test org.mrml.service.acme --target linux --release
for image in "mrml/certd:$version" "mrml/acmed:$version"; do
  docker image inspect "$image" >/dev/null
  [ "$(docker image inspect --format '{{.Config.User}}' "$image")" != "0" ] || {
    echo "root image rejected: $image" >&2
    exit 1
  }
done
