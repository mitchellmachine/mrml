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
require 'group_add: ["21906"]' "$compose"
require 'network_mode: none' "$compose"
require 'read_only: true' "$compose"
require 'cap_drop: [ALL]' "$compose"
require 'security_opt: [no-new-privileges:true]' "$compose"
require 'mrml-git-signer-state:' "$compose"
require 'mrml-git-signer-keys:' "$compose"
require 'mrml-git-signer-channel:' "$compose"
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
require '"$path/.mrml-volume"' deploy/compose/provision-git-signer-host.sh
require 'client and signer UID must differ' deploy/compose/provision-git-signer-host.sh
require 'signer channel copies differ' deploy/compose/provision-git-signer-host.sh
require 'mrml-git-signer-keys' deploy/compose/install-volume-inputs.sh
require 'authority-receipt-public.bin' deploy/compose/install-volume-inputs.sh

echo "protected signer Compose and image isolation policy PASS"
