#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUTPUT.tar" >&2
  exit 2
fi

version=$1
output=$2
case "$version" in
  *[!A-Za-z0-9._-]*|'') echo "invalid version" >&2; exit 2 ;;
esac
case "$output" in
  /*) ;;
  *) echo "output must be an absolute path" >&2; exit 2 ;;
esac

: "${COSIGN_KEY:?set COSIGN_KEY to an offline cosign private-key path}"
: "${COSIGN_PUBLIC_KEY:?set COSIGN_PUBLIC_KEY to its public-key path}"

for tool in docker syft cosign sha256sum tar; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
[ -f "$COSIGN_KEY" ] && [ ! -L "$COSIGN_KEY" ] || { echo "unsafe cosign key" >&2; exit 1; }
[ -f "$COSIGN_PUBLIC_KEY" ] && [ ! -L "$COSIGN_PUBLIC_KEY" ] || { echo "unsafe cosign public key" >&2; exit 1; }
[ ! -e "$output" ] || { echo "output already exists" >&2; exit 1; }

bundle_root=$(mktemp -d)
trap 'rm -rf "$bundle_root"' EXIT HUP INT TERM
payload=$bundle_root/mrml-git-$version
install -d -m 0700 "$payload/images" "$payload/sbom" "$payload/signatures" "$payload/deploy"

target/release/mrml manifest lock --check
target/release/mrml manifest check
target/release/mrml test org.mrml.service.git-authority --target linux
target/release/mrml test org.mrml.service.gitd --target linux
target/release/mrml build org.mrml.service.git-authority --target linux --release
target/release/mrml build org.mrml.service.gitd --target linux --release

docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.git-authority -t "mrml/git-authority:$version" .
docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.gitd -t "mrml/gitd:$version" .

for image in git-authority gitd; do
  docker image inspect --format '{{json .RepoDigests}} {{.Id}}' \
    "mrml/$image:$version" > "$payload/images/$image.identity"
  docker save -o "$payload/images/$image.tar" "mrml/$image:$version"
  syft "mrml/$image:$version" -o "spdx-json=$payload/sbom/$image.spdx.json"
  cosign sign-blob --key "$COSIGN_KEY" --tlog-upload=false \
    --bundle "$payload/signatures/$image.cosign.bundle" "$payload/images/$image.tar"
done
install -m 0444 "$COSIGN_PUBLIC_KEY" "$payload/signatures/cosign.pub"

install -m 0555 deploy/compose/provision-git-host.sh "$payload/deploy/provision-git-host.sh"
install -m 0555 deploy/compose/verify-offline-git-bundle.sh "$payload/verify-offline-git-bundle.sh"
install -m 0444 deploy/compose/gitd.example.conf "$payload/deploy/gitd.example.conf"

(
  cd "$payload"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$bundle_root" -cf "$output" "mrml-git-$version"
echo "offline bundle created: $output"
