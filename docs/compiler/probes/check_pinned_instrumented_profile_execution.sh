#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
self_contained="$library_root/self-contained"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
expected_size=60416
expected_hash=5aef132dd500c0e849e4736f4dcddef28f3ae939b639df6df840d12823e3d27b

test "$#" -eq 0 || {
    echo "usage: $0" >&2
    exit 1
}
test -x "$driver" || {
    echo "missing release driver: run target/release/mrml build org.mrml.compiler.driver --target linux --release" >&2
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

find_exact_rlib() {
    archive_prefix=$1
    set -- "$library_root"/"$archive_prefix"-*.rlib
    test "$#" -eq 1 && test -f "$1" || {
        echo "expected exactly one $archive_prefix archive in $library_root" >&2
        exit 1
    }
    printf '%s\n' "$1"
}

require_archive() {
    archive=$1
    test -f "$archive" || {
        echo "missing exact self-contained archive: $archive" >&2
        exit 1
    }
    printf '%s\n' "$archive"
}

profiler_builtins=$(find_exact_rlib libprofiler_builtins)
compiler_builtins=$(find_exact_rlib libcompiler_builtins)
core=$(find_exact_rlib libcore)
kernel32=$(require_archive "$self_contained/libkernel32.a")
ntdll=$(require_archive "$self_contained/libntdll.a")
mingw32=$(require_archive "$self_contained/libmingw32.a")
mingwex=$(require_archive "$self_contained/libmingwex.a")
msvcrt=$(require_archive "$self_contained/libmsvcrt.a")

probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-instrumented-profile.XXXXXX")
cleanup() {
    rm -rf "$probe"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$rustc" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C instrument-coverage --target x86_64-pc-windows-gnullvm \
    docs/compiler/probes/pinned_instrumented_profile.rs \
    -o "$probe/profiled.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_instrumented_profile_entry.s -o "$probe/entry.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_std_execution_stubs.s -o "$probe/stubs.obj"

ulimit -s 8192
"$driver" --link-coff "$probe/entry.obj" "$probe/stubs.obj" "$probe/profiled.obj" \
    "$profiler_builtins" "$compiler_builtins" "$core" \
    "$kernel32" "$ntdll" "$mingw32" "$mingwex" "$msvcrt" \
    --entry entry -o "$probe/probe.exe"

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

echo "pinned_instrumented_profile_execution size=$actual_size sha256=$actual_hash exit=42 result=PASS"
