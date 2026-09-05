#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUTPUT.tar" >&2
  exit 2
fi

version=$1
output=$2
case "$version" in
  [.-]*|*[!A-Za-z0-9._-]*|'') echo "invalid version" >&2; exit 2 ;;
esac
[ "${#version}" -le 128 ] || { echo "image version exceeds Docker tag bound" >&2; exit 2; }
case "$output" in
  /*) ;;
  *) echo "output must be an absolute path" >&2; exit 2 ;;
esac
case "$output" in
  *.tar) ;;
  *) echo "output must end in .tar (bounded file-only USTAR)" >&2; exit 2 ;;
esac

: "${COSIGN_KEY:?set COSIGN_KEY to an offline cosign private-key path}"
: "${COSIGN_PUBLIC_KEY:?set COSIGN_PUBLIC_KEY to its public-key path}"
: "${GIT_STREAMING_EVIDENCE:?set GIT_STREAMING_EVIDENCE to verified 256 MiB measurement evidence}"

image_builder=${MRML_IMAGE_BUILDER:-docker}
case $image_builder in docker|podman) ;; *) echo "MRML_IMAGE_BUILDER must be docker or podman" >&2; exit 2 ;; esac
release_profile=${MRML_GIT_RELEASE_PROFILE:-v5}
roles='git-authority gitd git-protected-signer git-credential-agent git-backup'
case $release_profile in
  v5) ;;
  v6) roles="$roles certd git" ;;
  *) echo "MRML_GIT_RELEASE_PROFILE must be v5 or v6" >&2; exit 2 ;;
esac
for tool in "$image_builder" syft cosign sha256sum tar git jq; do
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
for evidence in \
  source.commit metadata configured-limits process.tsv docker-stats.jsonl \
  client.out client.err content.sha256 summary SHA256SUMS
do
  install -m 0444 "$GIT_STREAMING_EVIDENCE/$evidence" "$payload/evidence/streaming/$evidence"
done

# Deployment carries authenticated public operator inputs only. Source and
# local policy-test code belong in the separate source review archive.

# Cosign v3 uses an explicit service configuration. The offline blob profile
# deliberately contains no Fulcio, OIDC, Rekor, or timestamp service, so the
# private key operation cannot initiate a transparency-service request.
cosign signing-config create \
  --no-default-fulcio --no-default-oidc --no-default-rekor --no-default-tsa \
  --out "$payload/signatures/offline-signing-config.json"

target/release/mrml manifest lock --check
target/release/mrml manifest check
deploy/compose/test-git-images.sh
deploy/compose/test-compose-git.sh
deploy/compose/test-compose-signer.sh
deploy/compose/test-compose-credential-agent.sh
target/release/mrml test org.mrml.service.git-authority --target linux
target/release/mrml test org.mrml.service.gitd --target linux
target/release/mrml test org.mrml.tool.git --target linux
target/release/mrml build org.mrml.service.git-authority --target linux --release
target/release/mrml build org.mrml.service.gitd --target linux --release
target/release/mrml build org.mrml.tool.git --target linux --release

if [ "$release_profile" = v6 ]; then
  deploy/compose/test-compose-acme.sh
  target/release/mrml test org.mrml.service.certificate --target linux
  target/release/mrml build org.mrml.service.certificate --target linux --release
  target/release/mrml build org.mrml.test.gitd-certd-fixture --target linux --release
fi

git rev-parse --verify HEAD > "$payload/source.commit"
sha256sum \
  target/mrml-native/linux/release/mrml-git-authority \
  target/mrml-native/linux/release/mrml-gitd \
  target/mrml-native/linux/release/mrml-git-protected-signer \
  target/mrml-native/linux/release/mrml-git-credential-agent \
  target/mrml-native/linux/release/mrml-git-backup \
  target/mrml-native/linux/release/mrml-git-release > "$payload/binaries.sha256"
cat > "$payload/test-evidence.txt" <<'EOF'
PASS target/release/mrml manifest lock --check
PASS target/release/mrml manifest check
PASS deploy/compose/test-git-images.sh
PASS deploy/compose/test-compose-git.sh
PASS deploy/compose/test-compose-signer.sh
PASS deploy/compose/test-compose-credential-agent.sh
PASS target/release/mrml test org.mrml.service.git-authority --target linux
PASS target/release/mrml test org.mrml.service.gitd --target linux
PASS target/release/mrml test org.mrml.tool.git --target linux
EOF

# Export OCI explicitly. Legacy Docker archives can change the manifest identity
# during containerd import; the signed ID is selected from these exported bytes.
for image in $roles; do
  dockerfile=deploy/compose/Dockerfile.$image
  [ "$image" != git ] || dockerfile=tools/containers/Dockerfile.git-completion-client
  archive=$payload/images/$image.tar
  if [ "$image_builder" = podman ]; then
    podman build --platform linux/amd64 --network=none --pull=false \
      -f "$dockerfile" -t "docker.io/mrml/$image:$version" .
    podman save --format oci-archive -o "$archive" "docker.io/mrml/$image:$version"
  else
    docker buildx build --platform linux/amd64 --network=none --pull=false \
      --provenance=false --sbom=false --output "type=oci,dest=$archive" \
      -f "$dockerfile" -t "docker.io/mrml/$image:$version" .
  fi
  producer_id=$(tar -xOf "$archive" index.json | jq -er \
    '.manifests | select(length == 1) | .[0] | select(.mediaType == "application/vnd.oci.image.manifest.v1+json") | .digest')
  printf '%s\n' "$producer_id" > "$payload/images/$image.identity"
  syft "oci-archive:$archive" -o "spdx-json=$payload/sbom/$image.spdx.json"
  cosign sign-blob --key "$COSIGN_KEY" \
    --signing-config "$payload/signatures/offline-signing-config.json" \
    --bundle "$payload/signatures/$image.cosign.bundle" "$payload/images/$image.tar"
done
{
  printf '%s\n' "format=mrml-images-git-$release_profile" "version=$version" "platform=linux/amd64"
  for image in $roles; do
    archive_digest=$(sha256sum "$payload/images/$image.tar" | awk '{print $1}')
    producer_id=$(cat "$payload/images/$image.identity")
    case $image in
      git-authority) user=21002:21002 entrypoint=/usr/bin/mrml-git-authority ;;
      gitd) user=21001:21001 entrypoint=/usr/bin/mrml-gitd ;;
      git-protected-signer) user=21006:21006 entrypoint=/usr/bin/mrml-git-protected-signer ;;
      git-credential-agent) user=21009:21009 entrypoint=/usr/bin/mrml-git-credential-agent ;;
      git-backup) user=0:0 entrypoint=/usr/bin/mrml-git-backup ;;
      certd) user=21003:21003 entrypoint=/usr/bin/mrml-certd ;;
      git) user=21005:21005 entrypoint=/usr/bin/mrml-git ;;
      *) exit 1 ;;
    esac
    printf 'image=mrml/%s:%s archive_sha256=%s producer_id=%s user=%s entrypoint=%s\n' \
      "$image" "$version" "$archive_digest" "$producer_id" "$user" "$entrypoint"
  done
} > "$payload/images.git.lock"
install -m 0444 "$COSIGN_PUBLIC_KEY" "$payload/signatures/cosign.pub"
if [ "$release_profile" = v6 ]; then
  sha256sum target/mrml-native/linux/release/mrml-certd \
    target/mrml-native/linux/release/mrml-git \
    target/mrml-native/linux/release/mrml-gitd-certd-test-probe >> "$payload/binaries.sha256"
  printf '%s\n' 'PASS deploy/compose/test-compose-acme.sh' \
    'PASS target/release/mrml test org.mrml.service.certificate --target linux' \
    >> "$payload/test-evidence.txt"
  for helper in provision-acme-host.sh provision-git-acceptance-host.sh; do
    install -m 0555 "deploy/compose/$helper" "$payload/deploy/$helper"
  done
  for config in compose.acme.yaml compose.git.acceptance.yaml compose.git.acceptance-second.yaml compose.git.restore-acceptance.yaml compose.git-response-loss.yaml; do
    install -m 0444 "deploy/compose/$config" "$payload/deploy/$config"
  done
fi


install -m 0555 deploy/compose/provision-git-host.sh "$payload/deploy/provision-git-host.sh"
install -m 0555 deploy/compose/provision-git-signer-host.sh "$payload/deploy/provision-git-signer-host.sh"
install -m 0555 deploy/compose/generate-git-signer-keys.sh "$payload/deploy/generate-git-signer-keys.sh"
install -m 0555 deploy/compose/provision-git-credential-agent-host.sh "$payload/deploy/provision-git-credential-agent-host.sh"
install -m 0555 deploy/compose/start-git.sh "$payload/deploy/start-git.sh"
install -m 0555 deploy/compose/initialize-git.sh "$payload/deploy/initialize-git.sh"
install -m 0555 deploy/compose/initialize-git-repository.sh "$payload/deploy/initialize-git-repository.sh"
install -m 0555 deploy/compose/initialize-git-protected-policy.sh "$payload/deploy/initialize-git-protected-policy.sh"
install -m 0555 deploy/compose/transition-git-trust.sh "$payload/deploy/transition-git-trust.sh"
install -m 0555 deploy/compose/construct-git-trust-policy.sh "$payload/deploy/construct-git-trust-policy.sh"
install -m 0555 deploy/compose/sign-git-trust-policy.sh "$payload/deploy/sign-git-trust-policy.sh"
install -m 0555 deploy/compose/select-git-signer-key-slot.sh "$payload/deploy/select-git-signer-key-slot.sh"
install -m 0555 deploy/compose/stage-git-trust-transition.sh "$payload/deploy/stage-git-trust-transition.sh"
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
install -m 0555 deploy/compose/verify-offline-git-bundle.sh "$payload/verify-offline-git-bundle.sh"
install -m 0555 deploy/compose/load-offline-git-images.sh "$payload/load-offline-git-images.sh"
install -m 0444 deploy/compose/gitd.example.conf "$payload/deploy/gitd.example.conf"
install -m 0444 deploy/compose/compose.git.yaml "$payload/deploy/compose.git.yaml"
install -m 0444 deploy/compose/compose.git-policy-init.yaml "$payload/deploy/compose.git-policy-init.yaml"
install -m 0444 deploy/compose/compose.signer.yaml "$payload/deploy/compose.signer.yaml"
install -m 0444 deploy/compose/compose.credential-agent.yaml "$payload/deploy/compose.credential-agent.yaml"
install -m 0444 deploy/compose/compose.git-backup.yaml "$payload/deploy/compose.git-backup.yaml"
install -m 0444 deploy/compose/compose.git-restore.yaml "$payload/deploy/compose.git-restore.yaml"
install -m 0444 deploy/compose/.env.git.production.example "$payload/deploy/.env.production.example"
install -m 0444 deploy/compose/.env.signer.production.example "$payload/deploy/.env.signer.production.example"
install -m 0444 deploy/compose/.env.credential-agent.production.example "$payload/deploy/.env.credential-agent.production.example"

(
  cd "$payload"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)
# Normalize public payload modes independently of the invoking umask. Signing
# keys are never copied here. The signed inventory preserves these exact modes.
find "$payload" -type f -perm /111 -exec chmod 0555 {} +
find "$payload" -type f ! -perm /111 -exec chmod 0444 {} +
bootstrap=target/mrml-native/linux/release/mrml-git-release
"$bootstrap" manifest "$payload" "$(git rev-parse --verify HEAD)"
cosign sign-blob --key "$COSIGN_KEY" \
  --signing-config "$payload/signatures/offline-signing-config.json" \
  --bundle "$payload/release.manifest.cosign.bundle" "$payload/release.manifest"
# Verify with the independently selected key, never signatures/cosign.pub.
"$bootstrap" verify "$payload" "$(realpath "$COSIGN_PUBLIC_KEY")" "$(command -v cosign)"
"$bootstrap" pack "$payload" "$output"
echo "offline bundle created: $output"
