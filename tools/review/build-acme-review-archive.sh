#!/bin/sh
set -eu

[ "$#" -eq 2 ] || {
  echo "usage: $0 COMMIT /absolute/output.tar.gz" >&2
  exit 64
}
commit=$(git rev-parse --verify "$1^{commit}")
output=$2
case "$output" in
  /*.tar.gz) ;;
  *) echo "output must be an absolute .tar.gz path" >&2; exit 64 ;;
esac
[ ! -e "$output" ] && [ ! -e "$output.sha256" ] || {
  echo "output or digest already exists" >&2
  exit 1
}

paths=$(mktemp)
archive=$(mktemp)
trap 'rm -f -- "$paths" "$archive"' EXIT HUP INT TERM

git ls-tree -r --name-only "$commit" -- \
  AGENTS.md README.md VALUES.md \
  docs/ACME.md docs/ACME_PRODUCTION_EVIDENCE.md docs/SECURITY.md docs/ENGINEERING_CONSTITUTION.md \
  docs/patents/ACME_CERTIFICATE_REVIEW_2026-09-01.md \
  docs/patents/REVIEW_LOG.md docs/gitd/edge/CERTD_CHANNEL.md \
  deploy/compose/Dockerfile.acmed deploy/compose/Dockerfile.certd \
  deploy/compose/acmed.example.json deploy/compose/certd.example.json \
  deploy/compose/compose.acme.yaml deploy/compose/.env.production.example \
  deploy/compose/README.md deploy/compose/provision-acme-host.sh \
  deploy/compose/validate-acme.sh deploy/compose/start-acme.sh \
  deploy/compose/status-acme.sh deploy/compose/test-compose-acme.sh \
  deploy/compose/switch-acme-version.sh deploy/compose/upgrade-acme.sh \
  deploy/compose/rollback-acme.sh \
  deploy/compose/renew-acme.sh \
  deploy/compose/cleanup-acme-dns.sh \
  deploy/compose/revoke-acme.sh \
  deploy/compose/rotate-acme-key.sh \
  deploy/compose/backup-acme.sh \
  deploy/compose/restore-acme.sh \
  deploy/compose/build-offline-acme-bundle.sh \
  deploy/compose/verify-offline-acme-bundle.sh \
  packages/interfaces/certificate packages/libraries/acme \
  packages/services/acme-worker packages/services/certificate \
  tools/containers/build-acme-release.sh \
  tools/containers/test-acme-release.sh \
  tools/containers/export-acme-release.sh \
  tools/containers/verify-acme-release.sh \
  >"$paths"

[ -s "$paths" ] || { echo "review source selection is empty" >&2; exit 1; }
if grep -E '(^|/)(target|backups|state|runtime|secrets)(/|$)|(^|/)\.env\.production$|\.(key|p12|pfx)$' "$paths"; then
  echo "review source contains a forbidden secret, runtime, or build-output path" >&2
  exit 1
fi

xargs git archive --format=tar --prefix="mrml-acme-$commit/" "$commit" \
  <"$paths" >"$archive"
gzip -n -9 <"$archive" >"$output"
sha256sum "$output" >"$output.sha256"
echo "ACME source-only review archive: $output"
cat "$output.sha256"
