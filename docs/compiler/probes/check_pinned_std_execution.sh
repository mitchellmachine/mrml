#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
self_contained="$library_root/self-contained"
rustc="$sysroot/bin/rustc.exe"
driver=target/mrml-native/linux/release/mrml-rustc
test "$#" -le 1 || {
    echo "usage: $0 [parallelism|time|random|sleep]" >&2
    exit 1
}
case ${1:-parallelism} in
    parallelism)
        probe_name=pinned_std_execution
        probe_source=docs/compiler/probes/pinned_std_execution.rs
        expected_size=2393088
        expected_hash=66492a766c27125d824fd63dbcdc47c0804a37da1b79979b812a06a692a9abc6
        ;;
    time)
        probe_name=pinned_std_time_execution
        probe_source=docs/compiler/probes/pinned_std_time_execution.rs
        expected_size=2393088
        expected_hash=8dd3b4e85476af2be38b6ced952980f4e8d29f103d25d0efa0f9cda90b973d10
        ;;
    random)
        probe_name=pinned_std_random_execution
        probe_source=docs/compiler/probes/pinned_std_random_execution.rs
        expected_size=2393088
        expected_hash=c3716a3dbddcb453b1bcd02f93940d1ccd2ae3093c532d34b6c3ead9dc0c65be
        ;;
    sleep)
        probe_name=pinned_std_sleep_execution
        probe_source=docs/compiler/probes/pinned_std_sleep_execution.rs
        expected_size=2393088
        expected_hash=f044c1c51e5a85a169d1bb39bd88307943fe8be28bec2269f430c93e809644cf
        ;;
    *)
        echo "usage: $0 [parallelism|time|random|sleep]" >&2
        exit 1
        ;;
esac

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

probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-$probe_name.XXXXXX")
cleanup() {
    rm -rf "$probe"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wine "$rustc" --edition=2024 --crate-name "$probe_name" \
    --crate-type=lib --emit=obj -C panic=abort -C embed-bitcode=no \
    -C opt-level=3 --target x86_64-pc-windows-gnullvm \
    "$probe_source" \
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

echo "$probe_name size=$actual_size sha256=$actual_hash exit=42 result=PASS"
