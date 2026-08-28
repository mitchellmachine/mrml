#!/bin/sh
set -eu

repo=${1:-/mnt/c/Users/Mitch/Documents/mrml}
cd "$repo"
oracle=nightly-2026-08-24-x86_64-unknown-linux-gnu
probe_dir=${TMPDIR:-/tmp}/mrml-comdat-selection
mkdir -p "$probe_dir"

for source in consumer first second loser_unresolved; do
    rustc "+$oracle" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
        "docs/compiler/probes/comdat_$source.rs" -o "$probe_dir/$source.o"
done
readelf -gW "$probe_dir/first.o" | grep 'COMDAT group section'
readelf -gW "$probe_dir/second.o" | grep 'COMDAT group section'
readelf -gW "$probe_dir/loser_unresolved.o" | grep 'COMDAT group section'

sysroot=$(rustc "+$oracle" --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
for order in first-second second-first; do
    case "$order" in
        first-second) expected=42; one=first; two=second ;;
        second-first) expected=7; one=second; two=first ;;
    esac
    target/mrml-native/linux/release/mrml-rustc --link-elf \
        "$probe_dir/consumer.o" "$probe_dir/$one.o" "$probe_dir/$two.o" \
        --entry entry -o "$probe_dir/mrml-$order"
    "$lld" -flavor gnu --eh-frame-hdr -e entry -o "$probe_dir/lld-$order" \
        "$probe_dir/consumer.o" "$probe_dir/$one.o" "$probe_dir/$two.o"
    chmod +x "$probe_dir/mrml-$order" "$probe_dir/lld-$order"
    set +e
    "$probe_dir/mrml-$order"
    mrml_status=$?
    "$probe_dir/lld-$order"
    lld_status=$?
    set -e
    test "$mrml_status" -eq "$expected"
    test "$lld_status" -eq "$expected"
    printf '%s mrml_exit=%s rust_lld_exit=%s\n' \
        "$order" "$mrml_status" "$lld_status"
done

target/mrml-native/linux/release/mrml-rustc --link-elf \
    "$probe_dir/consumer.o" "$probe_dir/first.o" "$probe_dir/loser_unresolved.o" \
    --entry entry -o "$probe_dir/mrml-discarded-unresolved"
"$lld" -flavor gnu --eh-frame-hdr -e entry \
    -o "$probe_dir/lld-discarded-unresolved" \
    "$probe_dir/consumer.o" "$probe_dir/first.o" "$probe_dir/loser_unresolved.o"
chmod +x "$probe_dir/mrml-discarded-unresolved" "$probe_dir/lld-discarded-unresolved"
set +e
"$probe_dir/mrml-discarded-unresolved"
mrml_status=$?
"$probe_dir/lld-discarded-unresolved"
lld_status=$?
set -e
test "$mrml_status" -eq 42
test "$lld_status" -eq 42
printf 'discarded-unresolved mrml_exit=%s rust_lld_exit=%s\n' \
    "$mrml_status" "$lld_status"
