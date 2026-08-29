#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
probe="/tmp/mrml-frontend-compile-elf-$$"
trap 'rm -f "$probe"' EXIT

target/debug/mrml compiler mrml-rustc-experimental compile-elf \
    docs/compiler/probes/frontend_compile_elf.rs --function start \
    -o "$probe" --release
chmod 700 "$probe"
set +e
"$probe"
status=$?
set -e
printf 'frontend-compile-elf exit=%s bytes=%s\n' "$status" "$(wc -c < "$probe")"
test "$status" -eq 133
