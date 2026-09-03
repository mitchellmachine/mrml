#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 COMMIT /absolute/output.tar.gz" >&2; exit 64; }
commit=$(git rev-parse --verify "$1^{commit}")
output=$2
case "$output" in /*.tar.gz) ;; *) echo "output must be an absolute .tar.gz path" >&2; exit 64 ;; esac
[ ! -e "$output" ] || { echo "output already exists" >&2; exit 1; }

paths=$(mktemp)
archive=$(mktemp)
trap 'rm -f -- "$paths" "$archive"' EXIT HUP INT TERM
git ls-tree -r --name-only "$commit" >"$paths"
if grep -E '(^|/)(target|backups|quarantine)(/|$)|(^|/)\.env\.production$|\.(key|p12|pfx)$' "$paths"; then
  echo "review source contains a forbidden secret, runtime, or build-output path" >&2
  exit 1
fi

git archive --format=tar --prefix="mrml-$commit/" "$commit" >"$archive"
gzip -n -9 <"$archive" >"$output"
output_directory=$(dirname -- "$output")
output_name=$(basename -- "$output")
(cd "$output_directory" && sha256sum "$output_name" >"$output_name.sha256")
echo "source-only review archive: $output"
cat "$output.sha256"
