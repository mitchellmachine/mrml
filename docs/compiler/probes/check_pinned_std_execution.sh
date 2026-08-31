#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
self_contained="$library_root/self-contained"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
expected_size=2389504
expected_hash=4360294552160ee4365ce81c843872aa0bb039eb60d50cd07217d615e41b04a7

test -x "$driver" || {
    echo "missing release driver: run ./target/debug/mrml build org.mrml.compiler.driver --target linux --release" >&2
    exit 1
}
test -f "$rustc" || {
    echo "missing exact $toolchain rustc.exe" >&2
    exit 1
}
test -d "$self_contained" || {
    echo "missing exact $toolchain self-contained archives" >&2
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

panic_abort=$(find_exact_rlib libpanic_abort)
std=$(find_exact_rlib libstd)
object=$(find_exact_rlib libobject)
memchr=$(find_exact_rlib libmemchr)
addr2line=$(find_exact_rlib libaddr2line)
gimli=$(find_exact_rlib libgimli)
cfg_if=$(find_exact_rlib libcfg_if)
windows_link=$(find_exact_rlib libwindows_link)
rustc_demangle=$(find_exact_rlib librustc_demangle)
std_detect=$(find_exact_rlib libstd_detect)
hashbrown=$(find_exact_rlib libhashbrown)
rustc_std_workspace_alloc=$(find_exact_rlib librustc_std_workspace_alloc)
miniz_oxide=$(find_exact_rlib libminiz_oxide)
adler2=$(find_exact_rlib libadler2)
unwind_rlib=$(find_exact_rlib libunwind)
libc=$(find_exact_rlib liblibc)
rustc_std_workspace_core=$(find_exact_rlib librustc_std_workspace_core)
alloc=$(find_exact_rlib liballoc)
core=$(find_exact_rlib libcore)
compiler_builtins=$(find_exact_rlib libcompiler_builtins)

kernel32=$(require_archive "$self_contained/libkernel32.a")
ntdll=$(require_archive "$self_contained/libntdll.a")
userenv=$(require_archive "$self_contained/libuserenv.a")
ws2_32=$(require_archive "$self_contained/libws2_32.a")
dbghelp=$(require_archive "$self_contained/libdbghelp.a")
unwind_archive=$(require_archive "$self_contained/libunwind.a")
mingw32=$(require_archive "$self_contained/libmingw32.a")
mingwex=$(require_archive "$self_contained/libmingwex.a")
msvcrt=$(require_archive "$self_contained/libmsvcrt.a")
user32=$(require_archive "$self_contained/libuser32.a")

probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-std-execution.XXXXXX")
cleanup() {
    rm -rf "$probe"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wine "$rustc" --edition=2024 --crate-name pinned_std_execution \
    --crate-type=lib --emit=obj -C panic=abort -C embed-bitcode=no \
    -C opt-level=3 --target x86_64-pc-windows-gnullvm \
    docs/compiler/probes/pinned_std_execution.rs \
    -o "$probe/consumer.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_std_execution_stubs.s \
    -o "$probe/stubs.obj"

ulimit -s 8192
"$driver" --link-coff "$probe/consumer.obj" "$probe/stubs.obj" \
    "$panic_abort" "$std" "$object" "$memchr" "$addr2line" "$gimli" \
    "$cfg_if" "$windows_link" "$rustc_demangle" "$std_detect" \
    "$hashbrown" "$rustc_std_workspace_alloc" "$miniz_oxide" "$adler2" \
    "$unwind_rlib" "$libc" "$rustc_std_workspace_core" "$alloc" "$core" \
    "$compiler_builtins" "$kernel32" "$ntdll" "$userenv" "$ws2_32" \
    "$dbghelp" "$unwind_archive" "$mingw32" "$mingwex" "$msvcrt" "$user32" \
    --entry entry -o "$probe/probe.exe"

actual_size=$(wc -c < "$probe/probe.exe" | tr -d ' ')
test "$actual_size" = "$expected_size" || {
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

echo "pinned-std-execution size=$actual_size sha256=$actual_hash exit=42 result=PASS"
