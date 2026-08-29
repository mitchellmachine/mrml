#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-24-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-common-$$"
mkdir "$probe"
trap 'rm -rf "$probe"' EXIT

for source in common_consumer common_small common_large common_strong_consumer common_strong; do
    rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
        -C opt-level=3 "docs/compiler/probes/$source.rs" -o "$probe/$source.o"
done

readelf -sW "$probe/common_small.o" | grep 'COM.*shared_common'
readelf -sW "$probe/common_large.o" | grep 'COM.*shared_common'

for linker in mrml rust-lld; do
    if [ "$linker" = mrml ]; then
        "$mrml" --link-elf "$probe/common_consumer.o" "$probe/common_small.o" \
            "$probe/common_large.o" --entry start -o "$probe/$linker-common" >/dev/null
        "$mrml" --link-elf "$probe/common_strong_consumer.o" "$probe/common_small.o" \
            "$probe/common_strong.o" --entry start -o "$probe/$linker-strong" >/dev/null
    else
        "$lld" -flavor gnu --gc-sections -e start -o "$probe/$linker-common" \
            "$probe/common_consumer.o" "$probe/common_small.o" "$probe/common_large.o"
        "$lld" -flavor gnu --gc-sections -e start -o "$probe/$linker-strong" \
            "$probe/common_strong_consumer.o" "$probe/common_small.o" "$probe/common_strong.o"
    fi
    chmod 700 "$probe/$linker-common" "$probe/$linker-strong"
    set +e
    "$probe/$linker-common"
    common_status=$?
    "$probe/$linker-strong"
    strong_status=$?
    set -e
    printf '%s common_exit=%s strong_exit=%s\n' "$linker" "$common_status" "$strong_status"
    test "$common_status" -eq 42
    test "$strong_status" -eq 42
done

readelf -lW "$probe/mrml-common" | grep 'LOAD.*RW'
wc -c "$probe/mrml-common" "$probe/rust-lld-common" \
    "$probe/mrml-strong" "$probe/rust-lld-strong"
