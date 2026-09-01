#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
self_contained="$library_root/self-contained"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
expected_size=60928
expected_hash=7ce398a8a34bd0595e5bbe2f23f934bf452825c4762e9c7371c07d0b49472ab3
profile_size=336
profile_hash=2578767b7d17d7eca8894b7f0b6097f63df022e8afb756ff8bb0fe0028af1499

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

probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-value-profile.XXXXXX")
cleanup() {
    rm -rf "$probe"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$rustc" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
    -C profile-generate --target x86_64-pc-windows-gnullvm \
    docs/compiler/probes/pinned_value_profile.rs \
    -o "$probe/profiled.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_value_profile_entry.s -o "$probe/entry.obj"
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
(cd "$probe" && wine probe.exe)
execution_status=$?
set -e
test "$execution_status" -eq 42 || {
    echo "unexpected hosted execution status: $execution_status" >&2
    exit 1
}

test -f "$probe/value.profraw" || {
    echo "profile runtime did not emit value.profraw" >&2
    exit 1
}
actual_profile_size=$(wc -c < "$probe/value.profraw" | tr -d ' ')
actual_profile_hash=$(sha256sum "$probe/value.profraw" | awk '{print $1}')
test "$actual_profile_size" = "$profile_size" || {
    echo "unexpected raw profile size/hash: $actual_profile_size $actual_profile_hash" >&2
    exit 1
}
test "$actual_profile_hash" = "$profile_hash" || {
    echo "unexpected raw profile hash: $actual_profile_hash" >&2
    exit 1
}

echo "pinned_value_profile_execution size=$actual_size sha256=$actual_hash profile_size=$actual_profile_size profile_sha256=$actual_profile_hash exit=42 result=PASS"
