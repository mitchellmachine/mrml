#!/bin/sh
set -eu

toolchain=nightly-2026-08-29-x86_64-pc-windows-gnullvm
rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
sysroot="$rustup_root/toolchains/$toolchain"
library_root="$sysroot/lib/rustlib/x86_64-pc-windows-gnullvm/lib"
driver=target/mrml-native/linux/release/mrml-rustc
expected_hash=54c3457ccc6a56e150a445d041ed00b1d003af4f0d0a9ae0ae2928e4bcb69b33

test -x "$driver" || {
    echo "missing release driver: run ./target/debug/mrml build org.mrml.compiler.driver --target linux --release" >&2
    exit 1
}
test -d "$library_root" || {
    echo "missing exact $toolchain sysroot" >&2
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
probe=$(mktemp -d "${TMPDIR:-/tmp}/mrml-pinned-alloc-core.XXXXXX")
trap 'rm -rf "$probe"' EXIT HUP INT TERM

clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_alloc_core_entry.s -o "$probe/entry.obj"
clang --target=x86_64-pc-windows-msvc -c \
    docs/compiler/probes/pinned_alloc_core_platform_stubs.s -o "$probe/platform.obj"

"$driver" --link-coff \
    "$probe/entry.obj" "$probe/platform.obj" \
    "$alloc" "$core" "$compiler_builtins" \
    --entry entry -o "$probe/probe.exe"

actual_size=$(wc -c < "$probe/probe.exe" | tr -d ' ')
test "$actual_size" = 519168 || {
    echo "unexpected PE size: $actual_size" >&2
    exit 1
}
actual_hash=$(sha256sum "$probe/probe.exe" | awk '{print $1}')
test "$actual_hash" = "$expected_hash" || {
    echo "unexpected PE hash: $actual_hash" >&2
    exit 1
}

echo "pinned-alloc-core-coff size=$actual_size sha256=$actual_hash result=PASS"
