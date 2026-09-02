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
[ "$(sed -n '1p' images.git.lock)" = "format=mrml-images-git-v1" ] || exit 1
[ -s source.commit ] && [ "$(wc -l < source.commit)" -eq 1 ] || exit 1
[ -s binaries.sha256 ] && [ -s test-evidence.txt ] || exit 1
for image in git-authority gitd; do
  [ -s "images/$image.identity" ]
  [ -s "images/$image.tar" ] && [ ! -L "images/$image.tar" ]
  [ -s "sbom/$image.spdx.json" ]
  cosign verify-blob --key signatures/cosign.pub \
    --bundle "signatures/$image.cosign.bundle" "images/$image.tar"
done
deploy/test-compose-git.sh deploy/compose.git.yaml
echo "offline Git bundle checksums, SBOM presence, and signatures PASS"
