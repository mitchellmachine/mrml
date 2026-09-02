#!/bin/sh
set -eu
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$directory/switch-acme-version.sh" rollback "${1-}"
