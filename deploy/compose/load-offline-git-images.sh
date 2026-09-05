#!/bin/sh
set -eu
# Trusted-installation compatibility launcher. The Rust bootstrap verifies
# and snapshots all payload bytes before calling the independently selected engine.
if [ "$#" -ne 2 ]; then
  echo "usage: $0 BUNDLE_DIRECTORY EXTERNAL_TRUSTED_PUBLIC_KEY" >&2
  exit 2
fi
exec /usr/local/bin/mrml-git-release load "$1" "$2" /usr/bin/cosign /usr/bin/docker
