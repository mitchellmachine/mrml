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
    echo "usage: $0 [execute|write|temporal]" >&2
    exit 1
}
case ${1:-execute} in
    execute)
        entry_source=docs/compiler/probes/pinned_instrumented_profile_entry.s
        expected_size=60416
        expected_hash=5aef132dd500c0e849e4736f4dcddef28f3ae939b639df6df840d12823e3d27b
        profile_size=
        profile_hash=
        instrumentation=coverage
        ;;
    write)
        entry_source=docs/compiler/probes/pinned_instrumented_profile_write_entry.s
        expected_size=60416
        expected_hash=a5949787946712c2d9c66a3a6e8c30986aec6ea639c6dc99f2e45ff884534c91
        profile_size=288
        profile_hash=437f3ffa93254a22de0098ab99e84cfd52148f7a7d8a92aafa3a91c80581da50
        instrumentation=coverage
        ;;
    temporal)
        entry_source=docs/compiler/probes/pinned_instrumented_profile_write_entry.s
        expected_size=60416
        expected_hash=79b17c85389aa2804f7d807d352e7444bfd3cd653577058df1c3d02cdcab83cd
        profile_size=296
        profile_hash=98a815c829e47f187341fe363c4a0b506e0ba30cb2ab796142fe14858eb1f933
        instrumentation=temporal
        ;;
    *)
        echo "usage: $0 [execute|write|temporal]" >&2
        exit 1
        ;;
esac
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

if test "$instrumentation" = temporal; then
    "$rustc" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
        -C profile-generate -C llvm-args=-pgo-temporal-instrumentation \
        --target x86_64-pc-windows-gnullvm \
        docs/compiler/probes/pinned_instrumented_profile.rs \
        -o "$probe/profiled.obj"
else
    "$rustc" --edition=2024 --crate-type=lib --emit=obj -C panic=abort \
        -C instrument-coverage --target x86_64-pc-windows-gnullvm \
        docs/compiler/probes/pinned_instrumented_profile.rs \
        -o "$probe/profiled.obj"
fi
clang --target=x86_64-pc-windows-msvc -c \
    "$entry_source" -o "$probe/entry.obj"
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

if test -n "$profile_size"; then
    test -f "$probe/profile.profraw" || {
        echo "profile runtime did not emit profile.profraw" >&2
        exit 1
    }
    actual_profile_size=$(wc -c < "$probe/profile.profraw" | tr -d ' ')
    actual_profile_hash=$(sha256sum "$probe/profile.profraw" | awk '{print $1}')
    test "$actual_profile_size" = "$profile_size" || {
        echo "unexpected raw profile size/hash: $actual_profile_size $actual_profile_hash" >&2
        exit 1
    }
    test "$actual_profile_hash" = "$profile_hash" || {
        echo "unexpected raw profile hash: $actual_profile_hash" >&2
        exit 1
    }
fi

echo "pinned_instrumented_profile_execution mode=${1:-execute} size=$actual_size sha256=$actual_hash exit=42 result=PASS"
