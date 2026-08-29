#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
toolchain_file="$repo_root/rust-toolchain.toml"

die() {
    printf 'setup-oracle: %s\n' "$*" >&2
    return 1 2>/dev/null || exit 1
}

command -v rustup >/dev/null 2>&1 || die "rustup is required"

channel=$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$toolchain_file")
[ -n "$channel" ] || die "could not read one pinned channel from rust-toolchain.toml"
[ "$(printf '%s\n' "$channel" | wc -l)" -eq 1 ] || die "rust-toolchain.toml has multiple channels"

read_toml_array() {
    key=$1
    sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\[\(.*\)\][[:space:]]*$/\1/p" "$toolchain_file" |
        tr ',' '\n' |
        sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//; /^[[:space:]]*$/d'
}

if ! rustup toolchain list | sed 's/ (default)//; s/ (active)//' | grep -Eq "^${channel}(-|$)"; then
    rustup toolchain install "$channel" --profile minimal
fi

installed_components=$(rustup component list --toolchain "$channel" --installed)
while IFS= read -r component; do
    if ! printf '%s\n' "$installed_components" | grep -Eq "^${component}(-|$)"; then
        rustup component add --toolchain "$channel" "$component"
    fi
done < <(read_toml_array components)

installed_targets=$(rustup target list --toolchain "$channel" --installed)
while IFS= read -r target; do
    if ! printf '%s\n' "$installed_targets" | grep -Fxq "$target"; then
        rustup target add --toolchain "$channel" "$target"
    fi
done < <(read_toml_array targets)

oracle_file=$(find "$repo_root/docs/compiler/oracles" -maxdepth 1 -type f -name 'ORACLE-*.md' -printf '%f\n' | sort | tail -n 1)
[ -n "$oracle_file" ] || die "no oracle record found"
expected_commit=$(sed -n 's/^- full commit: `\([0-9a-f][0-9a-f]*\)`$/\1/p' "$repo_root/docs/compiler/oracles/$oracle_file")
[ -n "$expected_commit" ] || die "could not read the full commit from $oracle_file"
actual_commit=$(rustup run "$channel" rustc -Vv | sed -n 's/^commit-hash: //p')
[ "$actual_commit" = "$expected_commit" ] || die "rustc commit $actual_commit does not match $oracle_file ($expected_commit)"

export RUSTUP_TOOLCHAIN="$channel"
export PATH="$HOME/.cargo/bin:$PATH"

printf 'MRML oracle ready: %s (%s)\n' "$channel" "$actual_commit"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    printf 'Run `source tools/toolchain/setup-oracle.sh` to retain RUSTUP_TOOLCHAIN in this shell.\n'
fi
