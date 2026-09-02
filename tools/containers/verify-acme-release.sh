#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 EXTRACTED_BUNDLE_ROOT" >&2
  exit 2
fi
root=$1
[ -d "$root" ] && [ ! -L "$root" ] || { echo "unsafe bundle root" >&2; exit 1; }
exec deploy/compose/verify-offline-acme-bundle.sh "$root"
