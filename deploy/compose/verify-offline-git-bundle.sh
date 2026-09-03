#!/bin/sh
set -eu

root=${1:-.}
cd "$root"
[ -f SHA256SUMS ] && [ ! -L SHA256SUMS ] || exit 1
if find . -type l -print | grep . >/dev/null; then
  echo "offline Git bundle must not contain symlinks" >&2
  exit 1
fi
sha256sum -c --strict SHA256SUMS
[ "$(sed -n '1p' images.git.lock)" = "format=mrml-images-git-v2" ] || exit 1
[ -s source.commit ] && [ "$(wc -l < source.commit)" -eq 1 ] || exit 1
[ -s binaries.sha256 ] && [ -s test-evidence.txt ] || exit 1
[ -s signatures/offline-signing-config.json ] || exit 1
(cd evidence/streaming && sha256sum -c --strict SHA256SUMS)
[ "$(cat evidence/streaming/source.commit)" = "$(cat source.commit)" ] || exit 1
streaming_bytes=$(sed -n 's/^source_bytes=//p' evidence/streaming/metadata)
[ "${streaming_bytes:-0}" -ge 268435456 ] || exit 1
[ -s evidence/streaming/summary ] && [ -s evidence/streaming/process.tsv ] || exit 1
for image in git-authority gitd; do
  [ -s "images/$image.identity" ]
  [ -s "images/$image.tar" ] && [ ! -L "images/$image.tar" ]
  [ -s "sbom/$image.spdx.json" ]
  locked=$(grep -F "image=mrml/$image:" images.git.lock)
  [ "$(printf '%s\n' "$locked" | wc -l)" -eq 1 ] || exit 1
  locked_digest=$(printf '%s\n' "$locked" | sed -n 's/.* archive_sha256=\([0-9a-f]\{64\}\) .*/\1/p')
  [ "$(sha256sum "images/$image.tar" | awk '{print $1}')" = "$locked_digest" ] || exit 1
  cosign verify-blob --key signatures/cosign.pub \
    --bundle "signatures/$image.cosign.bundle" --insecure-ignore-tlog \
    "images/$image.tar"
done
deploy/test-compose-git.sh deploy/compose.git.yaml
echo "offline Git bundle checksums, SBOM presence, and signatures PASS"
