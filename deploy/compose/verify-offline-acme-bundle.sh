#!/bin/sh
set -eu

root=${1:-.}
cd "$root"
sha256sum -c SHA256SUMS
for image in certd acmed; do
  cosign verify-blob --key signatures/cosign.pub \
    --bundle "signatures/$image.cosign.bundle" "images/$image.tar"
done
echo "offline bundle checksums and signatures PASS"
