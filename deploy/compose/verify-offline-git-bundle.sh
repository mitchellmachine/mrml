#!/bin/sh
set -eu
# Trusted-installation compatibility launcher. Never run this from an
# unverified bundle; provision the bootstrap and public key independently.
if [ "$#" -ne 2 ]; then
  echo "usage: $0 BUNDLE_DIRECTORY EXTERNAL_TRUSTED_PUBLIC_KEY" >&2
  exit 2
fi
exec /usr/local/bin/mrml-git-release verify "$1" "$2" /usr/bin/cosign
