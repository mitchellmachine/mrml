#!/bin/sh
set -eu

compose=${1:-deploy/compose/compose.acme.yaml}
certd_dockerfile=${2:-deploy/compose/Dockerfile.certd}
acmed_dockerfile=${3:-deploy/compose/Dockerfile.acmed}

require() {
  pattern=$1 file=$2
  grep -F "$pattern" "$file" >/dev/null || {
    echo "missing required deployment invariant: $pattern" >&2
    exit 1
  }
}

reject() {
  pattern=$1 file=$2
  if grep -F "$pattern" "$file" >/dev/null; then
    echo "forbidden deployment setting: $pattern" >&2
    exit 1
  fi
}

require 'image: "mrml/certd:' "$compose"
require 'image: "mrml/acmed:' "$compose"
require 'pull_policy: never' "$compose"
require 'network_mode: none' "$compose"
require 'read_only: true' "$compose"
require 'no-new-privileges:true' "$compose"
require '/mnt/mrml}/runtime/certd-gitd' "$compose"
require '/mnt/mrml}/runtime/certd-acmed' "$compose"
require 'certd-gitd.cap.certd' "$compose"
require 'certd-acmed.cap.certd' "$compose"
require 'certd-acmed.cap.acmed' "$compose"
reject 'build:' "$compose"
reject 'ports:' "$compose"
reject '/var/run/docker.sock' "$compose"
reject '/run/secrets/cloudflare-api-token' "$certd_dockerfile"

for dockerfile in "$certd_dockerfile" "$acmed_dockerfile"; do
  require 'FROM docker.io/library/debian@sha256:' "$dockerfile"
  require 'FROM gcr.io/distroless/cc-debian12@sha256:' "$dockerfile"
  reject ':latest' "$dockerfile"
  reject 'apt-get' "$dockerfile"
  reject 'curl' "$dockerfile"
  reject 'wget' "$dockerfile"
done

echo "ACME Compose static invariants PASS"

for operator in deploy/compose/switch-acme-version.sh deploy/compose/upgrade-acme.sh deploy/compose/rollback-acme.sh deploy/compose/renew-acme.sh deploy/compose/cleanup-acme-dns.sh deploy/compose/revoke-acme.sh; do
  sh -n "$operator"
done
require 'up -d --no-build --pull never certd acmed' deploy/compose/switch-acme-version.sh
require 'certificate state was not rolled back' deploy/compose/switch-acme-version.sh
require 'stop acmed' deploy/compose/renew-acme.sh
require 'MRML_ACMED_OFFLINE_ADMIN=1' deploy/compose/renew-acme.sh
require 'confirm-exact-records' deploy/compose/cleanup-acme-dns.sh
require 'MRML_ACMED_OFFLINE_ADMIN=1' deploy/compose/cleanup-acme-dns.sh
require 'stop acmed' deploy/compose/revoke-acme.sh
require 'revoke-preview' deploy/compose/revoke-acme.sh
require 'MRML_ACMED_OFFLINE_ADMIN=1' deploy/compose/revoke-acme.sh
require 'secrets/admin/backup-auth.key' deploy/compose/provision-acme-host.sh
reject 'backup-auth.key' "$compose"
