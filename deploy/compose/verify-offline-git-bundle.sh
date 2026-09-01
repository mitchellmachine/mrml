#!/bin/sh
set -eu

root=${1:-.}
cd "$root"
sha256sum -c SHA256SUMS
for image in git-authority gitd; do
  [ -s "images/$image.identity" ]
  [ -s "sbom/$image.spdx.json" ]
  cosign verify-blob --key signatures/cosign.pub \
    --bundle "signatures/$image.cosign.bundle" "images/$image.tar"
done
echo "offline Git bundle checksums, SBOM presence, and signatures PASS"
