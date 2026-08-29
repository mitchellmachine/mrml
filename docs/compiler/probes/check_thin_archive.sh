#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-24-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-thin-archive-$$"
mkdir -p "$probe/objects"
trap 'rm -rf "$probe"' EXIT

rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/thin_archive_entry.rs -o "$probe/entry.o"
rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/thin_archive_helper.rs -o "$probe/objects/helper.o"
rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/thin_archive_leaf.rs -o "$probe/objects/leaf.o"
rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/thin_archive_unused.rs -o "$probe/objects/unused.o"
(cd "$probe" && ar crsT helpers.a objects/helper.o objects/leaf.o objects/unused.o)
test "$(head -c 8 "$probe/helpers.a")" = '!<thin>'
(cd "$probe" && test "$(ar t helpers.a)" = "$(printf 'objects/helper.o\nobjects/leaf.o\nobjects/unused.o')")
rm "$probe/objects/unused.o"

"$mrml" --link-elf "$probe/entry.o" "$probe/helpers.a" \
    --entry start -o "$probe/mrml" >/dev/null
rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C opt-level=3 -C relocation-model=static \
    docs/compiler/probes/thin_archive_unused.rs -o "$probe/objects/unused.o"
"$lld" -flavor gnu --gc-sections -e start -o "$probe/rust-lld" \
    "$probe/entry.o" "$probe/helpers.a"
chmod 700 "$probe/mrml" "$probe/rust-lld"

set +e
"$probe/mrml"
mrml_status=$?
"$probe/rust-lld"
lld_status=$?
set -e
printf 'thin-archive mrml_exit=%s rust_lld_exit=%s\n' "$mrml_status" "$lld_status"
test "$mrml_status" -eq 42
test "$lld_status" -eq 42
wc -c "$probe/mrml" "$probe/rust-lld"
