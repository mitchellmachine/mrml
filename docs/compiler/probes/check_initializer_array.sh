#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-29-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-initializer-array-$$"
mkdir "$probe"
trap 'rm -rf "$probe"' EXIT

rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 docs/compiler/probes/initializer_array.rs -o "$probe/input.o"
readelf -SW "$probe/input.o" | grep -E '\.(preinit_array|init_array\.[0-9]+|fini_array\.[0-9]+).*(PREINIT_ARRAY|INIT_ARRAY|FINI_ARRAY)'
test "$(readelf -SW "$probe/input.o" | grep -Ec '\.(preinit_array|init_array\.[0-9]+|fini_array\.[0-9]+).*(PREINIT_ARRAY|INIT_ARRAY|FINI_ARRAY)')" -eq 5
readelf -rW "$probe/input.o" | grep -E '__preinit_array_start|__init_array_start|__fini_array_start'

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

# Exit 42 requires both linkers to synthesize all six boundaries, retain all
# five arrays and callbacks, order init/fini priorities 100 then 200, and let
# the runtime traverse finalizers in reverse.
wc -c "$probe/mrml" "$probe/rust-lld"
