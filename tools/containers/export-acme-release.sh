#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION ABSOLUTE_OUTPUT_TAR" >&2
  exit 2
fi
exec deploy/compose/build-offline-acme-bundle.sh "$1" "$2"
