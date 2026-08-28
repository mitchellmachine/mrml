#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-24-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-initializer-array-$$"
mkdir "$probe"
trap 'rm -rf "$probe"' EXIT

rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 docs/compiler/probes/initializer_array.rs -o "$probe/input.o"
readelf -SW "$probe/input.o" | grep -E '\.init_array .*INIT_ARRAY'
readelf -rW "$probe/input.o" | grep -E '\.rela\.init_array|retained_initializer'

"$mrml" --link-elf "$probe/input.o" --entry start -o "$probe/mrml" >/dev/null
"$lld" -flavor gnu --gc-sections -e start -o "$probe/rust-lld" "$probe/input.o"
chmod 700 "$probe/mrml" "$probe/rust-lld"

set +e
"$probe/mrml"
mrml_status=$?
"$probe/rust-lld"
lld_status=$?
set -e
printf 'initializer-array mrml_exit=%s rust_lld_exit=%s\n' "$mrml_status" "$lld_status"
test "$mrml_status" -eq 42
test "$lld_status" -eq 42

# The retained initializer's exact optimized `mov eax, 7; ret` bytes must
# survive section GC in each stripped executable even though `start` never
# calls it. Hex-stream matching is independent of output section headers.
od -An -v -tx1 "$probe/mrml" | tr -d ' \n' | grep -q 'b807000000c3'
od -An -v -tx1 "$probe/rust-lld" | tr -d ' \n' | grep -q 'b807000000c3'
wc -c "$probe/mrml" "$probe/rust-lld"
