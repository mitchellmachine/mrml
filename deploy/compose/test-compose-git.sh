#!/bin/sh
set -eu

compose=${1:-deploy/compose/compose.git.yaml}
gitd_dockerfile=${2:-deploy/compose/Dockerfile.gitd}
authority_dockerfile=${3:-deploy/compose/Dockerfile.git-authority}

require() {
  pattern=$1 file=$2
  grep -F "$pattern" "$file" >/dev/null || {
    echo "missing required Git deployment invariant: $pattern" >&2
    exit 1
  }
}

reject() {
  pattern=$1 file=$2
  if grep -F "$pattern" "$file" >/dev/null; then
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
require 'certd-gitd:/run/mrml/certd-gitd:ro' "$compose"
require 'git-authority.cap.gitd' "$compose"
require 'certd-gitd.cap.gitd' "$compose"
require 'stop_grace_period:' "$compose"
require 'nofile:' "$compose"
reject 'build:' "$compose"
reject ':latest' "$compose"
reject '/var/run/docker.sock' "$compose"
reject 'privileged:' "$compose"
reject 'pid: host' "$compose"
reject 'ipc: host' "$compose"
reject 'userns_mode: host' "$compose"
reject 'name:' "$compose"

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

echo "Git Compose static invariants PASS"
