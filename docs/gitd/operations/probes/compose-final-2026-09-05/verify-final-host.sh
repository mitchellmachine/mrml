#!/bin/sh
set -eu
base=/var/snap/docker/common/mrml-completion-20260905
input=/home/ubuntu/mrml-git-completion-20260905-config/completion-release.tar
printf '%s\n' "3c99e5bf022dd8bb93bda9faadab089d9ae822a5f882699718bff7327ed9e5fa  $input" | sha256sum -c --strict
"$base/trusted/mrml-git-release-v6" extract "$input" "$base/payload-final-complete" "$base/trusted/test-release.pub" "$base/trusted/cosign"
"$base/trusted/mrml-git-release-v6" load "$base/payload-final-complete" "$base/trusted/test-release.pub" "$base/trusted/cosign" /usr/bin/docker
