#!/bin/sh
set -eu
base=/var/snap/docker/common/mrml-completion-20260905
input=/home/ubuntu/mrml-git-completion-20260905-config/clean-source-candidate.tar
printf '%s\n' "50c6c642f24351bd16a1bfdccb36d0cb29544d275e5a82b053553844559c4d99  $input" | sha256sum -c --strict
"$base/trusted/mrml-git-release-v6" extract "$input" "$base/payload-final-candidate" "$base/trusted/test-release.pub" "$base/trusted/cosign"
"$base/trusted/mrml-git-release-v6" load "$base/payload-final-candidate" "$base/trusted/test-release.pub" "$base/trusted/cosign" /usr/bin/docker
