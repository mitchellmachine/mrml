#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi
version=$1
case "$version" in *[!A-Za-z0-9._-]*|'') echo "invalid version" >&2; exit 2;; esac

for tool in docker sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
./target/release/mrml build org.mrml.service.certificate --target linux --release
./target/release/mrml build org.mrml.service.acme --target linux --release
docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.certd -t "mrml/certd:$version" .
docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.acmed -t "mrml/acmed:$version" .
docker image inspect "mrml/certd:$version" "mrml/acmed:$version" >/dev/null
