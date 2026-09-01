#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
expected_size=466432
expected_hash=1361ccc72696c0f5c8c20f18f561283d88808bd93dee316cc2adbbd6186195eb

test "$#" -eq 0 || {
    echo "usage: $0" >&2
    exit 1
}
test -x "$driver" || {
    echo "missing release driver: run ./target/debug/mrml build org.mrml.compiler.driver --target linux --release" >&2
    exit 1
}
test -f "$rustc" || {
    echo "missing exact $toolchain rustc.exe" >&2
    exit 1
}
command -v clang >/dev/null || {
    echo "missing clang" >&2
    exit 1
}
command -v wine >/dev/null || {
    echo "missing Wine" >&2
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

core=$(find_exact_archive libcore)
compiler_builtins=$(find_exact_archive libcompiler_builtins)
probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-core-float.XXXXXX")
cleanup() {
    rm -rf "$probe"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$rustc" --edition=2024 --crate-name mrml_core_float_probe \
    --crate-type=lib --emit=obj -C panic=abort -C embed-bitcode=no \
    -C opt-level=3 --target x86_64-pc-windows-gnullvm \
    docs/compiler/probes/pinned_core_float_execution.rs \
    -o "$probe/consumer.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_std_execution_stubs.s \
    -o "$probe/stubs.obj"

ulimit -s 8192
"$driver" --link-coff "$probe/consumer.obj" "$probe/stubs.obj" \
    "$core" "$compiler_builtins" --entry entry -o "$probe/probe.exe"

actual_size=$(wc -c < "$probe/probe.exe" | tr -d ' ')
actual_hash=$(sha256sum "$probe/probe.exe" | awk '{print $1}')
test "$actual_size" = "$expected_size" || {
    echo "unexpected PE size/hash: $actual_size $actual_hash" >&2
    exit 1
}
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

echo "pinned_core_float_execution size=$actual_size sha256=$actual_hash exit=42 result=PASS"
