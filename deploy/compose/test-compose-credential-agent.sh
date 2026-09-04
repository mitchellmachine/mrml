#!/bin/sh
set -eu

compose=${1:-deploy/compose/compose.credential-agent.yaml}
dockerfile=${2:-deploy/compose/Dockerfile.git-credential-agent}

require() {
  grep -F -- "$1" "$2" >/dev/null || {
    echo "missing credential-agent isolation policy in $2: $1" >&2
    exit 1
  }
}

reject() {
  if grep -F -- "$1" "$2" >/dev/null; then
    echo "forbidden credential-agent image content in $2: $1" >&2
    exit 1
  fi
}

[ -f "$compose" ] && [ -f "$dockerfile" ]
require 'USER 21009:21009' "$dockerfile"
require 'ENTRYPOINT ["/usr/bin/mrml-git-credential-agent"]' "$dockerfile"
require 'user: "21009:21009"' "$compose"
require 'group_add: ["21909"]' "$compose"
require 'network_mode: none' "$compose"
require 'read_only: true' "$compose"
require 'cap_drop: [ALL]' "$compose"
require 'security_opt: [no-new-privileges:true]' "$compose"
require 'source: mrml-git-credential-agent-token' "$compose"
require 'source: mrml-git-credential-agent-channel' "$compose"
require 'source: mrml-runtime-git-credential-agent' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-git-credential-agent-token"' "$compose"
require 'name: "${MRML_VOLUME_PREFIX:-mrml}-runtime-git-credential-agent"' "$compose"
require 'volume: {nocopy: true}' "$compose"
if grep -Eq '(^|[[:space:]])ports:' "$compose"; then
  echo "credential agent must publish no ports" >&2
  exit 1
fi
for forbidden in mrml-gitd mrml-git-protected-signer curl openssh gnupg cargo rustc apt-get; do
  reject "$forbidden" "$dockerfile"
done
require 'docker volume create --label org.mrml.managed=true' deploy/compose/provision-git-credential-agent-host.sh
require 'client and credential-agent UID must differ' deploy/compose/provision-git-credential-agent-host.sh
require 'credential-agent channel copies differ' deploy/compose/provision-git-credential-agent-host.sh
require 'credential-agent)' deploy/compose/install-volume-inputs.sh
require '21009 21009 0400 64' deploy/compose/install-volume-inputs.sh

echo "credential-agent Compose and image isolation policy PASS"
