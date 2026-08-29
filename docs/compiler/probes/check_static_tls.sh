#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-29-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-static-tls-$$"
mkdir "$probe"
trap 'rm -rf "$probe"' EXIT

rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/static_tls.rs -o "$probe/static_tls.o"

readelf -SW "$probe/static_tls.o" | grep -E '\.(tdata|tbss).*WAT'
readelf -rW "$probe/static_tls.o" | grep R_X86_64_TPOFF32

"$mrml" --link-elf "$probe/static_tls.o" --entry start -o "$probe/mrml" >/dev/null
"$lld" -flavor gnu --gc-sections -e start -o "$probe/rust-lld" \
    "$probe/static_tls.o"
chmod 700 "$probe/mrml" "$probe/rust-lld"

set +e
"$probe/mrml"
mrml_status=$?
"$probe/rust-lld"
lld_status=$?
set -e
printf 'static-tls mrml_exit=%s rust_lld_exit=%s\n' "$mrml_status" "$lld_status"
test "$mrml_status" -eq 42
test "$lld_status" -eq 42

readelf -lW "$probe/mrml" | grep TLS
readelf -lW "$probe/rust-lld" | grep TLS
wc -c "$probe/mrml" "$probe/rust-lld"
