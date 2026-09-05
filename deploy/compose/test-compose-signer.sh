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
require 'name: "${MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME:?set MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME}"' "$compose"
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
require 'signer-receipt)' deploy/compose/install-volume-inputs.sh
require 'next) signer_suffix=git-signer-next-keys' deploy/compose/install-volume-inputs.sh
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
  require 'running=$("$runtime" ps -q --filter volume="$volume") || exit 1' "$operator"
  reject 'running=$(docker compose' "$operator"
done
for operator in deploy/compose/construct-git-trust-policy.sh deploy/compose/sign-git-trust-policy.sh deploy/compose/select-git-signer-key-slot.sh deploy/compose/stage-git-trust-transition.sh deploy/compose/transition-git-trust.sh; do
  require 'volume_prefix=$(read_environment_value MRML_VOLUME_PREFIX)' "$operator"
  require 'MRML_VOLUME_PREFIX does not match the production environment' "$operator"
done
require 'openpgp_created_at=$(read_environment_value MRML_OPENPGP_CREATED_AT)' deploy/compose/transition-git-trust.sh
reject '"${MRML_OPENPGP_CREATED_AT:?set MRML_OPENPGP_CREATED_AT}"' deploy/compose/transition-git-trust.sh
require 'volume_spec=$signer_volume:/keys:nocopy' deploy/compose/generate-git-signer-keys.sh
require 'volume_spec=type=volume,source=$signer_volume,target=/keys,volume-nocopy' deploy/compose/generate-git-signer-keys.sh
require '"21006:21006 400 32 1"' deploy/compose/generate-git-signer-keys.sh
require '"21006:21006 400 4032 1"' deploy/compose/generate-git-signer-keys.sh
require 'previous-policy.bin' deploy/compose/install-volume-inputs.sh
require 'trust transition requires stopped Gitd, authority, and signer' deploy/compose/transition-git-trust.sh
require 'previous-openpgp-public.asc' deploy/compose/transition-git-trust.sh
require 'previous-ml-dsa-public.bin' deploy/compose/transition-git-trust.sh
require '--profile admin run --rm --no-deps git-signer-trust-advance' deploy/compose/transition-git-trust.sh
require 'verify-selected-policy /var/lib/mrml/git-policies "$1"' deploy/compose/transition-git-trust.sh
require 'advance-trust 21006 21002 21002 "$1"' deploy/compose/transition-git-trust.sh
reject '"/var/lib/mrml/git-policies/$1/trust-policy.current"' deploy/compose/transition-git-trust.sh
require 'if [ "${1:-}" = --resume-signer ]' deploy/compose/transition-git-trust.sh
require 'if [ "$phase" = select-and-advance ]' deploy/compose/transition-git-trust.sh
require '.signer-trust-advance.$transition_id.complete' deploy/compose/transition-git-trust.sh
require 'invalid or stale signer trust-advance completion marker' deploy/compose/transition-git-trust.sh
require 'if [ "$advance_complete" = false ]' deploy/compose/transition-git-trust.sh
require 'sync -f "$temporary_marker"' deploy/compose/transition-git-trust.sh
require 'git-trust-construction' deploy/compose/transition-git-trust.sh
require 'git-trust-signatures' deploy/compose/transition-git-trust.sh
require 'consumed public transition and workspace inputs removed' deploy/compose/transition-git-trust.sh
require '--profile admin run --rm --no-deps git-trust-sign-current' deploy/compose/sign-git-trust-policy.sh
require '--profile admin run --rm --no-deps git-trust-sign-next' deploy/compose/sign-git-trust-policy.sh
require 'sign-key-rotation 21006 21001' deploy/compose/sign-git-trust-policy.sh
require 'case $mode in overlap|retirement)' deploy/compose/sign-git-trust-policy.sh
require 'retirement must use the current key creation time for both authorizations' deploy/compose/sign-git-trust-policy.sh
require 'next_keys_volume=$current_keys_volume' deploy/compose/sign-git-trust-policy.sh
require 'MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=$next_keys_volume' deploy/compose/sign-git-trust-policy.sh
require 'trust policy signing requires stopped Gitd, authority, and signer' deploy/compose/sign-git-trust-policy.sh
require 'signer key selection requires stopped Gitd, authority, and signer' deploy/compose/select-git-signer-key-slot.sh
require 'MRML_GIT_SIGNER_KEYS_VOLUME' deploy/compose/select-git-signer-key-slot.sh
require 'MRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME' deploy/compose/select-git-signer-key-slot.sh
require 'selected and candidate signer key volumes must differ' deploy/compose/stage-git-trust-transition.sh
require 'git-signer-key-slot-' deploy/compose/stage-git-trust-transition.sh
require 'org.mrml.managed' deploy/compose/select-git-signer-key-slot.sh
require 'sync -f "$temporary"' deploy/compose/select-git-signer-key-slot.sh
require 'protected signer key selection already matches trust generation' deploy/compose/select-git-signer-key-slot.sh
require 'signer trust generation must advance monotonically' deploy/compose/select-git-signer-key-slot.sh
require 'signer revocation generation must not roll back' deploy/compose/select-git-signer-key-slot.sh
require 'signer key volume is outside the managed key slots' deploy/compose/stage-git-trust-transition.sh
require 'case $mode in overlap|retirement)' deploy/compose/stage-git-trust-transition.sh
require 'if [ "$mode" = retirement ]' deploy/compose/stage-git-trust-transition.sh
require 'next_keys=$current_keys' deploy/compose/stage-git-trust-transition.sh
require 'install-volume-inputs.sh" authority-transition' deploy/compose/stage-git-trust-transition.sh
require 'git-trust-signatures' deploy/compose/stage-git-trust-transition.sh
deploy/compose/test-transition-git-trust-resume.sh
deploy/compose/test-construct-git-trust-policy-resume.sh
deploy/compose/test-sign-git-trust-policy-modes.sh
deploy/compose/test-select-git-signer-key-slot-resume.sh

# Executable Rust regression for consumers in separately named Compose projects.
guard_test=$(mktemp -d)
trap 'rm -rf "$guard_test"' EXIT HUP INT TERM
rustc --edition 2024 deploy/compose/tests/trust_cold_guard.rs -o "$guard_test/trust-cold-guard"
"$guard_test/trust-cold-guard"
rm -rf "$guard_test"
trap - EXIT HUP INT TERM

echo "protected signer Compose and image isolation policy PASS"
