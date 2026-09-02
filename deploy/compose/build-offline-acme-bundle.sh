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

for tool in docker syft cosign sha256sum tar git; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
[ -f "$COSIGN_KEY" ] && [ ! -L "$COSIGN_KEY" ] || { echo "unsafe cosign key" >&2; exit 1; }
[ -f "$COSIGN_PUBLIC_KEY" ] && [ ! -L "$COSIGN_PUBLIC_KEY" ] || { echo "unsafe cosign public key" >&2; exit 1; }
[ ! -e "$output" ] || { echo "output already exists" >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=all)" ] || {
  echo "release source tree must be clean" >&2
  exit 1
}

bundle_root=$(mktemp -d)
trap 'rm -rf "$bundle_root"' EXIT HUP INT TERM
payload=$bundle_root/mrml-acme-$version
install -d -m 0700 "$payload/images" "$payload/sbom" "$payload/signatures" "$payload/deploy" "$payload/evidence"

git rev-parse --verify HEAD > "$payload/SOURCE_COMMIT"
{
  target/release/mrml manifest lock --check
  target/release/mrml manifest check
  target/release/mrml build org.mrml.service.certificate --target linux --release
  target/release/mrml test org.mrml.service.certificate --target linux --release
  target/release/mrml build org.mrml.service.acme --target linux --release
  target/release/mrml test org.mrml.service.acme --target linux --release
} > "$payload/evidence/build-and-test.log" 2>&1
sha256sum \
  target/mrml-native/linux/release/mrml-certd \
  target/mrml-native/linux/release/mrml-acmed \
  > "$payload/evidence/BINARY_SHA256SUMS"

docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.certd -t "mrml/certd:$version" .
docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.acmed -t "mrml/acmed:$version" .

docker image inspect --format '{{json .RepoDigests}} {{.Id}}' "mrml/certd:$version" > "$payload/images/certd.identity"
docker image inspect --format '{{json .RepoDigests}} {{.Id}}' "mrml/acmed:$version" > "$payload/images/acmed.identity"
{
  docker image inspect --format 'mrml/certd:'"$version"' {{.Id}}' "mrml/certd:$version"
  docker image inspect --format 'mrml/acmed:'"$version"' {{.Id}}' "mrml/acmed:$version"
} > "$payload/images.acme.lock"
docker save -o "$payload/images/certd.tar" "mrml/certd:$version"
docker save -o "$payload/images/acmed.tar" "mrml/acmed:$version"
syft "mrml/certd:$version" -o spdx-json="$payload/sbom/certd.spdx.json"
syft "mrml/acmed:$version" -o spdx-json="$payload/sbom/acmed.spdx.json"

for image in certd acmed; do
  cosign sign-blob --key "$COSIGN_KEY" --tlog-upload=false \
    --bundle "$payload/signatures/$image.cosign.bundle" "$payload/images/$image.tar"
done
install -m 0444 "$COSIGN_PUBLIC_KEY" "$payload/signatures/cosign.pub"

install -m 0444 deploy/compose/compose.acme.yaml "$payload/deploy/compose.acme.yaml"
install -m 0555 deploy/compose/provision-acme-host.sh "$payload/deploy/provision-acme-host.sh"
install -m 0555 deploy/compose/validate-acme.sh "$payload/deploy/validate-acme.sh"
install -m 0555 deploy/compose/start-acme.sh "$payload/deploy/start-acme.sh"
install -m 0555 deploy/compose/status-acme.sh "$payload/deploy/status-acme.sh"
install -m 0555 deploy/compose/renew-acme.sh "$payload/deploy/renew-acme.sh"
install -m 0555 deploy/compose/switch-acme-version.sh "$payload/deploy/switch-acme-version.sh"
install -m 0555 deploy/compose/upgrade-acme.sh "$payload/deploy/upgrade-acme.sh"
install -m 0555 deploy/compose/rollback-acme.sh "$payload/deploy/rollback-acme.sh"
install -m 0444 deploy/compose/.env.production.example "$payload/deploy/.env.production.example"
install -m 0555 deploy/compose/verify-offline-acme-bundle.sh "$payload/verify-offline-acme-bundle.sh"
install -m 0444 deploy/compose/README.md "$payload/README.md"
install -m 0444 deploy/compose/certd.example.json "$payload/deploy/certd.example.json"
install -m 0444 deploy/compose/acmed.example.json "$payload/deploy/acmed.example.json"

(
  cd "$payload"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$bundle_root" -cf "$output" "mrml-acme-$version"
echo "offline bundle created: $output"
