#!/bin/sh
set -eu

repo=${1:-/mnt/c/Users/Mitch/Documents/mrml}
cd "$repo"
oracle=nightly-2026-08-29-x86_64-unknown-linux-gnu
probe_dir=${TMPDIR:-/tmp}/mrml-signed-absolute32
mkdir -p "$probe_dir"

rustc "+$oracle" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    docs/compiler/probes/signed_absolute32.rs -o "$probe_dir/probe.o"
readelf -rW "$probe_dir/probe.o" | grep R_X86_64_32S

target/mrml-native/linux/release/mrml-rustc --link-elf \
    target/linker-probe/elf-start.o "$probe_dir/probe.o" --entry start \
    -o "$probe_dir/mrml"
sysroot=$(rustc "+$oracle" --print sysroot)
"$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld" -flavor gnu \
    --eh-frame-hdr -e start -o "$probe_dir/rust-lld" \
    target/linker-probe/elf-start.o "$probe_dir/probe.o"
chmod +x "$probe_dir/mrml" "$probe_dir/rust-lld"

set +e
"$probe_dir/mrml"
mrml_status=$?
"$probe_dir/rust-lld"
lld_status=$?
set -e
test "$mrml_status" -eq 42
test "$lld_status" -eq 42
printf 'mrml_exit=%s rust_lld_exit=%s\n' "$mrml_status" "$lld_status"
wc -c "$probe_dir/mrml" "$probe_dir/rust-lld"
