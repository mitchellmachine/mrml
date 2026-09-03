#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUTPUT.tar.gz" >&2
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
case "$output" in
  *.tar.gz) ;;
  *) echo "output must end in .tar.gz" >&2; exit 2 ;;
esac

: "${COSIGN_KEY:?set COSIGN_KEY to an offline cosign private-key path}"
: "${COSIGN_PUBLIC_KEY:?set COSIGN_PUBLIC_KEY to its public-key path}"
: "${GIT_STREAMING_EVIDENCE:?set GIT_STREAMING_EVIDENCE to verified 256 MiB measurement evidence}"

for tool in docker syft cosign sha256sum tar gzip git; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
[ -f "$COSIGN_KEY" ] && [ ! -L "$COSIGN_KEY" ] || { echo "unsafe cosign key" >&2; exit 1; }
[ -f "$COSIGN_PUBLIC_KEY" ] && [ ! -L "$COSIGN_PUBLIC_KEY" ] || { echo "unsafe cosign public key" >&2; exit 1; }
[ -d "$GIT_STREAMING_EVIDENCE" ] && [ ! -L "$GIT_STREAMING_EVIDENCE" ] || { echo "unsafe streaming evidence" >&2; exit 1; }
[ -z "$(find "$GIT_STREAMING_EVIDENCE" -type l -print -quit)" ] || { echo "streaming evidence contains a symlink" >&2; exit 1; }
(cd "$GIT_STREAMING_EVIDENCE" && sha256sum -c --strict SHA256SUMS)
[ "$(cat "$GIT_STREAMING_EVIDENCE/source.commit")" = "$(git rev-parse --verify HEAD)" ] || { echo "streaming evidence source commit is stale" >&2; exit 1; }
streaming_bytes=$(sed -n 's/^source_bytes=//p' "$GIT_STREAMING_EVIDENCE/metadata")
[ "${streaming_bytes:-0}" -ge 268435456 ] || { echo "streaming evidence is below 256 MiB" >&2; exit 1; }
[ ! -e "$output" ] || { echo "output already exists" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "release requires a clean source tree" >&2; exit 1; }

bundle_root=$(mktemp -d)
trap 'rm -rf "$bundle_root"' EXIT HUP INT TERM
payload=$bundle_root/mrml-git-$version
install -d -m 0700 "$payload/images" "$payload/sbom" "$payload/signatures" "$payload/deploy" "$payload/evidence/streaming"
for evidence in source.commit metadata configured-limits process.tsv docker-stats.jsonl summary SHA256SUMS; do
  install -m 0444 "$GIT_STREAMING_EVIDENCE/$evidence" "$payload/evidence/streaming/$evidence"
done

# Cosign v3 uses an explicit service configuration. The offline blob profile
# deliberately contains no Fulcio, OIDC, Rekor, or timestamp service, so the
# private key operation cannot initiate a transparency-service request.
cosign signing-config create \
  --no-default-fulcio --no-default-oidc --no-default-rekor --no-default-tsa \
  --out "$payload/signatures/offline-signing-config.json"

target/release/mrml manifest lock --check
target/release/mrml manifest check
target/release/mrml test org.mrml.service.git-authority --target linux
target/release/mrml test org.mrml.service.gitd --target linux
target/release/mrml build org.mrml.service.git-authority --target linux --release
target/release/mrml build org.mrml.service.gitd --target linux --release

git rev-parse --verify HEAD > "$payload/source.commit"
sha256sum \
  target/mrml-native/linux/release/mrml-git-authority \
  target/mrml-native/linux/release/mrml-gitd > "$payload/binaries.sha256"
cat > "$payload/test-evidence.txt" <<'EOF'
PASS target/release/mrml manifest lock --check
PASS target/release/mrml manifest check
PASS target/release/mrml test org.mrml.service.git-authority --target linux
PASS target/release/mrml test org.mrml.service.gitd --target linux
EOF

docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.git-authority -t "mrml/git-authority:$version" .
docker buildx build --platform linux/amd64 --network=none --pull=false --load \
  -f deploy/compose/Dockerfile.gitd -t "mrml/gitd:$version" .

for image in git-authority gitd; do
  docker image inspect --format '{{json .RepoDigests}} {{.Id}}' \
    "mrml/$image:$version" > "$payload/images/$image.identity"
  docker save -o "$payload/images/$image.tar" "mrml/$image:$version"
  # Scan the exact exported artifact rather than relying on a daemon-specific
  # local image-store API. This keeps Docker and Podman-backed offline builds
  # equivalent and binds the SBOM to the bytes that are actually distributed.
  syft "docker-archive:$payload/images/$image.tar" \
    -o "spdx-json=$payload/sbom/$image.spdx.json"
  cosign sign-blob --key "$COSIGN_KEY" \
    --signing-config "$payload/signatures/offline-signing-config.json" \
    --bundle "$payload/signatures/$image.cosign.bundle" "$payload/images/$image.tar"
done
{
  printf '%s\n' 'format=mrml-images-git-v2' "version=$version" "platform=linux/amd64"
  for image in git-authority gitd; do
    archive_digest=$(sha256sum "$payload/images/$image.tar" | awk '{print $1}')
    producer_id=$(docker image inspect --format '{{.Id}}' "mrml/$image:$version")
    case $image in
      git-authority) user=21002:21002 entrypoint=/usr/bin/mrml-git-authority ;;
      gitd) user=21001:21001 entrypoint=/usr/bin/mrml-gitd ;;
      *) exit 1 ;;
    esac
    printf 'image=mrml/%s:%s archive_sha256=%s producer_id=%s user=%s entrypoint=%s\n' \
      "$image" "$version" "$archive_digest" "$producer_id" "$user" "$entrypoint"
  done
} > "$payload/images.git.lock"
install -m 0444 "$COSIGN_PUBLIC_KEY" "$payload/signatures/cosign.pub"

install -m 0555 deploy/compose/provision-git-host.sh "$payload/deploy/provision-git-host.sh"
install -m 0555 deploy/compose/start-git.sh "$payload/deploy/start-git.sh"
install -m 0555 deploy/compose/initialize-git.sh "$payload/deploy/initialize-git.sh"
install -m 0555 deploy/compose/initialize-git-repository.sh "$payload/deploy/initialize-git-repository.sh"
install -m 0555 deploy/compose/initialize-git-protected-policy.sh "$payload/deploy/initialize-git-protected-policy.sh"
install -m 0555 deploy/compose/transition-git-trust.sh "$payload/deploy/transition-git-trust.sh"
install -m 0555 deploy/compose/token-git.sh "$payload/deploy/token-git.sh"
install -m 0555 deploy/compose/recovery-git.sh "$payload/deploy/recovery-git.sh"
install -m 0555 deploy/compose/switch-git-version.sh "$payload/deploy/switch-git-version.sh"
install -m 0555 deploy/compose/upgrade-git.sh "$payload/deploy/upgrade-git.sh"
install -m 0555 deploy/compose/rollback-git.sh "$payload/deploy/rollback-git.sh"
install -m 0555 deploy/compose/status-git.sh "$payload/deploy/status-git.sh"
install -m 0555 deploy/compose/backup-git.sh "$payload/deploy/backup-git.sh"
install -m 0555 deploy/compose/restore-git.sh "$payload/deploy/restore-git.sh"
install -m 0555 deploy/compose/install-volume-inputs.sh "$payload/deploy/install-volume-inputs.sh"
install -m 0555 deploy/compose/validate-git.sh "$payload/deploy/validate-git.sh"
install -m 0555 deploy/compose/test-compose-git.sh "$payload/deploy/test-compose-git.sh"
install -m 0555 deploy/compose/verify-offline-git-bundle.sh "$payload/verify-offline-git-bundle.sh"
install -m 0555 deploy/compose/load-offline-git-images.sh "$payload/load-offline-git-images.sh"
install -m 0444 deploy/compose/gitd.example.conf "$payload/deploy/gitd.example.conf"
install -m 0444 deploy/compose/compose.git.yaml "$payload/deploy/compose.git.yaml"
install -m 0444 deploy/compose/.env.git.production.example "$payload/deploy/.env.production.example"

(
  cd "$payload"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$bundle_root" -cf - "mrml-git-$version" | gzip -n -9 > "$output"
echo "offline bundle created: $output"
