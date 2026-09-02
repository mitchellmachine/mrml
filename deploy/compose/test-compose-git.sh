#!/bin/sh
set -eu

compose=${1:-deploy/compose/compose.git.yaml}

if grep -F "gitd-certd-test-fixture" "$compose" >/dev/null; then
  echo "test-only certd fixture is forbidden in production Compose" >&2
  exit 1
fi
gitd_dockerfile=${2:-deploy/compose/Dockerfile.gitd}
authority_dockerfile=${3:-deploy/compose/Dockerfile.git-authority}

require() {
  pattern=$1 file=$2
  grep -F -- "$pattern" "$file" >/dev/null || {
    echo "missing required Git deployment invariant: $pattern" >&2
    exit 1
  }
}

reject() {
  pattern=$1 file=$2
  if grep -F -- "$pattern" "$file" >/dev/null; then
    echo "forbidden Git deployment setting: $pattern" >&2
    exit 1
  fi
}

require 'image: "mrml/gitd:' "$compose"
require 'image: "mrml/git-authority:' "$compose"
require 'pull_policy: never' "$compose"
require 'user: "21001:21001"' "$compose"
require 'user: "21002:21002"' "$compose"
require 'network_mode: none' "$compose"
require 'read_only: true' "$compose"
require 'cap_drop: [ALL]' "$compose"
require 'no-new-privileges:true' "$compose"
require '443:8443/tcp' "$compose"
require '443:8443/udp' "$compose"
require 'mrml-runtime-certd-gitd:/run/mrml/certd-gitd:ro' "$compose"
require 'mrml-gitd-policies:/var/lib/mrml/git-policies:ro' "$compose"
require 'mrml-gitd-repos:/mnt/mrml/gitd/repos:rw' "$compose"
require 'name: mrml-gitd-repos' "$compose"
require 'MRML_PROTECTED_REPOSITORY:?set MRML_PROTECTED_REPOSITORY' "$compose"
require 'git-authority.cap.gitd' "$compose"
require 'certd-gitd.cap.gitd' "$compose"
require 'stop_grace_period:' "$compose"
require 'nofile:' "$compose"
require 'listener-health' "$compose"
require 'healthcheck' "$compose"
reject 'build:' "$compose"
reject ':latest' "$compose"
reject '/var/run/docker.sock' "$compose"
reject 'privileged:' "$compose"
reject 'pid: host' "$compose"
reject 'ipc: host' "$compose"
reject 'userns_mode: host' "$compose"
reject 'container_name:' "$compose"
reject '/gitd/repos:/mnt/mrml/gitd/repos' "$compose"
reject '/runtime/git-authority:/run/mrml/git-authority' "$compose"

published=$(grep -c '443:8443/' "$compose")
[ "$published" -eq 2 ] || {
  echo "Gitd must publish exactly TCP and UDP port 443" >&2
  exit 1
}

for dockerfile in "$gitd_dockerfile" "$authority_dockerfile"; do
  require 'FROM docker.io/library/debian@sha256:' "$dockerfile"
  require 'FROM gcr.io/distroless/cc-debian12@sha256:' "$dockerfile"
  reject ':latest' "$dockerfile"
  reject 'apt-get' "$dockerfile"
  reject 'curl' "$dockerfile"
  reject 'wget' "$dockerfile"
  reject 'COPY . ' "$dockerfile"
done
require '/payload/dirs/repos /mnt/mrml/gitd/repos' "$gitd_dockerfile"
require '/payload/dirs/authority /var/lib/mrml/authority' "$authority_dockerfile"
require 'docker volume create --label org.mrml.managed=true' deploy/compose/provision-git-host.sh
require 'wrong owner on Docker volume' deploy/compose/provision-git-host.sh
require 'mrml-runtime-certd-gitd' deploy/compose/provision-git-host.sh

for operator in deploy/compose/initialize-git.sh deploy/compose/initialize-git-repository.sh deploy/compose/initialize-git-protected-policy.sh deploy/compose/token-git.sh deploy/compose/recovery-git.sh deploy/compose/switch-git-version.sh deploy/compose/upgrade-git.sh deploy/compose/rollback-git.sh deploy/compose/load-offline-git-images.sh; do
  [ -x "$operator" ] || {
    echo "missing executable Git deployment operator: $operator" >&2
    exit 1
  }
done
require '--no-build --pull never git-authority gitd' deploy/compose/switch-git-version.sh
require 'repository data was not rolled back' deploy/compose/switch-git-version.sh
require 'docker load -i' deploy/compose/load-offline-git-images.sh
require 'loaded image identity does not match images.git.lock' deploy/compose/load-offline-git-images.sh
require 'run --rm --no-deps' deploy/compose/initialize-git.sh
require 'initialize-token-store' deploy/compose/initialize-git.sh
require 'repository initialization requires stopped Gitd' deploy/compose/initialize-git-repository.sh
require 'initialize-repository /etc/mrml/gitd.conf' deploy/compose/initialize-git-repository.sh
require 'protected policy initialization requires stopped Gitd and authority' deploy/compose/initialize-git-protected-policy.sh
require 'initialize-protected-policy /etc/mrml/gitd.conf' deploy/compose/initialize-git-protected-policy.sh
require 'token administration requires stopped Gitd' deploy/compose/token-git.sh
require 'run -T --rm --no-deps' deploy/compose/token-git.sh
require 'recovery administration requires stopped Gitd' deploy/compose/recovery-git.sh
require 'recover-safe' deploy/compose/recovery-git.sh
require 'GIT_STREAMING_EVIDENCE' deploy/compose/build-offline-git-bundle.sh
require 'docker-archive:$payload/images/$image.tar' deploy/compose/build-offline-git-bundle.sh
require 'offline-signing-config.json' deploy/compose/build-offline-git-bundle.sh
require '--insecure-ignore-tlog' deploy/compose/verify-offline-git-bundle.sh
require 'evidence/streaming' deploy/compose/verify-offline-git-bundle.sh

echo "Git Compose static invariants PASS"
