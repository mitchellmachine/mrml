#!/bin/sh
set -eu

compose=${1:-deploy/compose/compose.signer.yaml}
dockerfile=${2:-deploy/compose/Dockerfile.git-protected-signer}

require() {
  grep -F -- "$1" "$2" >/dev/null || {
    echo "missing signer isolation policy in $2: $1" >&2
    exit 1
  }
}

reject() {
  if grep -F -- "$1" "$2" >/dev/null; then
    echo "forbidden signer image content in $2: $1" >&2
    exit 1
  fi
}

[ -f "$compose" ] && [ -f "$dockerfile" ]
require 'USER 21006:21006' "$dockerfile"
require 'ENTRYPOINT ["/usr/bin/mrml-git-protected-signer"]' "$dockerfile"
require 'user: "21006:21006"' "$compose"
require 'git-signer-trust-advance:' "$compose"
require 'git-trust-sign-current:' "$compose"
require 'git-trust-sign-next:' "$compose"
require 'mrml-git-signer-next-keys:/keys:ro' "$compose"
require 'mrml-git-trust-construction:/policies:ro' "$compose"
require 'mrml-git-trust-signatures:/signatures:rw' "$compose"
reject '/tmp:rw,noexec,nosuid,nodev,size=8m,uid=21006' "$compose"
require 'profiles: [admin]' "$compose"
require '"mrml-gitd-policies:/var/lib/mrml/git-policies:ro"' "$compose"
require '"mrml-git-authority-transition:/run/mrml-transition:ro"' "$compose"
require 'group_add: ["21906"]' "$compose"
require 'network_mode: none' "$compose"
require 'read_only: true' "$compose"
require 'cap_drop: [ALL]' "$compose"
require 'security_opt: [no-new-privileges:true]' "$compose"
require 'source: mrml-git-signer-state' "$compose"
require 'source: mrml-git-signer-keys' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-git-signer-next-keys"' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-git-trust-signatures"' "$compose"
require 'source: mrml-git-signer-channel' "$compose"
require 'source: mrml-runtime-git-signer' "$compose"
require 'volume: {nocopy: true}' "$compose"
require 'mrml-git-signer-state:' "$compose"
require 'mrml-git-signer-keys:' "$compose"
require 'name: "${MRML_GIT_SIGNER_KEYS_VOLUME:?set MRML_GIT_SIGNER_KEYS_VOLUME}"' "$compose"
require 'mrml-git-signer-channel:' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-git-signer-state"' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-runtime-git-signer"' "$compose"
require 'mrml-runtime-git-signer:' "$compose"
require '/var/lib/mrml/git-protected-signer/state/generation.state' "$compose"
require '/var/lib/mrml/git-protected-signer/keys/authority-receipt-public.bin' "$compose"
if grep -Eq '(^|[[:space:]])ports:' "$compose"; then
  echo "protected signer must publish no ports" >&2
  exit 1
fi
for forbidden in mrml-gitd curl openssh gnupg cargo rustc apt-get; do
  reject "$forbidden" "$dockerfile"
done
require 'docker volume create --label org.mrml.managed=true' deploy/compose/provision-git-signer-host.sh
require 'volume_name git-signer-next-keys' deploy/compose/provision-git-signer-host.sh
require 'volume_name git-trust-signatures' deploy/compose/provision-git-signer-host.sh
require '"$path/.mrml-volume"' deploy/compose/provision-git-signer-host.sh
require 'client and signer UID must differ' deploy/compose/provision-git-signer-host.sh
require 'signer channel copies differ' deploy/compose/provision-git-signer-host.sh
require 'git_volume git-signer-keys' deploy/compose/install-volume-inputs.sh
require 'authority-receipt-public.bin' deploy/compose/install-volume-inputs.sh
require 'generate-key-material 21006 "$openpgp_created_at" /keys' deploy/compose/generate-git-signer-keys.sh
require 'slot=${3:-current}' deploy/compose/generate-git-signer-keys.sh
require 'next) suffix=git-signer-next-keys' deploy/compose/generate-git-signer-keys.sh
require '--network none' deploy/compose/generate-git-signer-keys.sh
require '--read-only' deploy/compose/generate-git-signer-keys.sh
require '--cap-drop ALL' deploy/compose/generate-git-signer-keys.sh
require '--security-opt no-new-privileges' deploy/compose/generate-git-signer-keys.sh
require 'runtime=${MRML_CONTAINER_RUNTIME:-docker}' deploy/compose/generate-git-signer-keys.sh
require 'case $runtime in docker|podman)' deploy/compose/generate-git-signer-keys.sh
require 'if [ "$runtime" = podman ]' deploy/compose/generate-git-signer-keys.sh
for operator in deploy/compose/install-volume-inputs.sh deploy/compose/construct-git-trust-policy.sh deploy/compose/sign-git-trust-policy.sh deploy/compose/select-git-signer-key-slot.sh deploy/compose/stage-git-trust-transition.sh deploy/compose/transition-git-trust.sh; do
  require 'runtime=${MRML_CONTAINER_RUNTIME:-docker}' "$operator"
  require 'case $runtime in docker|podman)' "$operator"
done
for operator in deploy/compose/construct-git-trust-policy.sh deploy/compose/sign-git-trust-policy.sh deploy/compose/select-git-signer-key-slot.sh deploy/compose/transition-git-trust.sh; do
  require 'running=$(podman ps -q --filter volume="$volume")' "$operator"
  require 'running=$(docker compose' "$operator"
  require 'cannot query service state for $service' "$operator"
done
require 'volume_spec=$signer_volume:/keys:nocopy' deploy/compose/generate-git-signer-keys.sh
require 'volume_spec=type=volume,source=$signer_volume,target=/keys,volume-nocopy' deploy/compose/generate-git-signer-keys.sh
require '"21006:21006 400 32 1"' deploy/compose/generate-git-signer-keys.sh
require '"21006:21006 400 4032 1"' deploy/compose/generate-git-signer-keys.sh
require 'previous-policy.bin' deploy/compose/install-volume-inputs.sh
require 'trust transition requires stopped Gitd, authority, and signer' deploy/compose/transition-git-trust.sh
require 'previous-openpgp-public.asc' deploy/compose/transition-git-trust.sh
require 'previous-ml-dsa-public.bin' deploy/compose/transition-git-trust.sh
require '--profile admin run --rm --no-deps git-signer-trust-advance' deploy/compose/transition-git-trust.sh
require 'advance-trust 21006 21001 21002 "$1"' deploy/compose/transition-git-trust.sh
require 'if [ "${1:-}" = --resume-signer ]' deploy/compose/transition-git-trust.sh
require 'if [ "$phase" = select-and-advance ]' deploy/compose/transition-git-trust.sh
require 'git-trust-construction' deploy/compose/transition-git-trust.sh
require 'git-trust-signatures' deploy/compose/transition-git-trust.sh
require 'consumed public transition and workspace inputs removed' deploy/compose/transition-git-trust.sh
require '--profile admin run --rm --no-deps git-trust-sign-current' deploy/compose/sign-git-trust-policy.sh
require '--profile admin run --rm --no-deps git-trust-sign-next' deploy/compose/sign-git-trust-policy.sh
require 'sign-key-rotation 21006 21001' deploy/compose/sign-git-trust-policy.sh
require 'trust policy signing requires stopped Gitd, authority, and signer' deploy/compose/sign-git-trust-policy.sh
require 'signer key selection requires stopped Gitd, authority, and signer' deploy/compose/select-git-signer-key-slot.sh
require 'MRML_GIT_SIGNER_KEYS_VOLUME' deploy/compose/select-git-signer-key-slot.sh
require 'sync -f "$temporary"' deploy/compose/select-git-signer-key-slot.sh
require 'selected signer key volume is outside the managed key slots' deploy/compose/stage-git-trust-transition.sh
require 'install-volume-inputs.sh" authority-transition' deploy/compose/stage-git-trust-transition.sh
require 'git-trust-signatures' deploy/compose/stage-git-trust-transition.sh

echo "protected signer Compose and image isolation policy PASS"
