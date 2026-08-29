#!/bin/sh
set -eu

cd /mnt/c/Users/Mitch/Documents/mrml
toolchain=nightly-2026-08-29-x86_64-unknown-linux-gnu
sysroot=$(rustc +$toolchain --print sysroot)
lld="$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mrml=target/mrml-native/linux/release/mrml-rustc
probe="/tmp/mrml-thin-archive-benchmark-$$"
unused_count=${1:-1}
mkdir -p "$probe/objects"
trap 'rm -rf "$probe"' EXIT

for source in entry helper leaf unused; do
    rustc +$toolchain --edition=2024 --crate-type=lib --emit=obj \
        -C panic=abort -C opt-level=3 -C relocation-model=static \
        "docs/compiler/probes/thin_archive_${source}.rs" \
        -o "$probe/objects/${source}.o"
done
index=1
while test "$index" -lt "$unused_count"; do
    cp "$probe/objects/unused.o" "$probe/objects/unused-$index.o"
    index=$((index + 1))
done
(cd "$probe" && ar crsT helpers.a objects/helper.o objects/leaf.o objects/unused*.o)

measure() {
    name=$1
    shift
    samples="$probe/$name.samples"
    : > "$samples"
    iteration=0
    while test "$iteration" -lt 55; do
        rm -f "$probe/$name"
        start=$(date +%s%N)
        "$@" >/dev/null
        end=$(date +%s%N)
        if test "$iteration" -ge 5; then
            awk "BEGIN { print ($end - $start) / 1000000 }" >> "$samples"
        fi
        iteration=$((iteration + 1))
    done
    sort -n "$samples" > "$samples.sorted"
    awk -v name="$name" '
        { values[NR] = $1; total += $1 }
        END {
            median = (values[25] + values[26]) / 2
            printf "%s unused=%s median_ms=%.3f mean_ms=%.3f iterations=50 warmups=5\n", name, count, median, total / NR
        }
    ' count="$unused_count" "$samples.sorted"
}

measure mrml "$mrml" --link-elf "$probe/objects/entry.o" "$probe/helpers.a" \
    --entry start -o "$probe/mrml"
measure rust-lld "$lld" -flavor gnu --gc-sections -e start \
    -o "$probe/rust-lld" "$probe/objects/entry.o" "$probe/helpers.a"
