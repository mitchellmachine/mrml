#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
expected_hash=52d2c50df2cf4dd0b58a70f60d49fc765e461dafc7dea5433b5ea4671460aa5e

test -x "$driver" || {
    echo "missing release driver: run ./target/debug/mrml build org.mrml.compiler.driver --target linux --release" >&2
    exit 1
}
test -f "$rustc" || {
    echo "missing exact $toolchain rustc.exe" >&2
    exit 1
}

find_exact_archive() {
    archive_prefix=$1
    set -- "$library_root"/"$archive_prefix"-*.rlib
    test "$#" -eq 1 && test -f "$1" || {
        echo "expected exactly one $archive_prefix archive in $library_root" >&2
        exit 1
    }
    printf '%s\n' "$1"
}

alloc=$(find_exact_archive liballoc)
core=$(find_exact_archive libcore)
compiler_builtins=$(find_exact_archive libcompiler_builtins)
probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-alloc-execution.XXXXXX")
trap 'rm -rf "$probe"' EXIT HUP INT TERM

wine "$rustc" --edition=2024 --crate-name pinned_alloc_core_execution \
    --crate-type=lib --emit=obj -C panic=abort -C embed-bitcode=no \
    -C opt-level=3 --target x86_64-pc-windows-gnullvm \
    docs/compiler/probes/pinned_alloc_core_execution.rs \
    -o "$probe/consumer.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_alloc_core_execution_stubs.s \
    -o "$probe/stubs.obj"

"$driver" --link-coff "$probe/consumer.obj" "$probe/stubs.obj" \
    "$alloc" "$core" "$compiler_builtins" \
    --entry entry -o "$probe/probe.exe"

actual_size=$(wc -c < "$probe/probe.exe" | tr -d ' ')
test "$actual_size" = 520704 || {
    echo "unexpected PE size: $actual_size" >&2
    exit 1
}
actual_hash=$(sha256sum "$probe/probe.exe" | awk '{print $1}')
test "$actual_hash" = "$expected_hash" || {
    echo "unexpected PE hash: $actual_hash" >&2
    exit 1
}

set +e
wine "$probe/probe.exe"
execution_status=$?
set -e
test "$execution_status" -eq 42 || {
    echo "unexpected hosted execution status: $execution_status" >&2
    exit 1
}

echo "pinned-alloc-core-execution size=$actual_size sha256=$actual_hash exit=42 result=PASS"
