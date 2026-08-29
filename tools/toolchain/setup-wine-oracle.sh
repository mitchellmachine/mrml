#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
toolchain_file="$repo_root/rust-toolchain.toml"
wine_prefix=${WINEPREFIX:-"$HOME/.wine"}

die() {
    printf 'setup-wine-oracle: %s\n' "$*" >&2
    return 1 2>/dev/null || exit 1
}

command -v wine >/dev/null 2>&1 || die "Wine is required"
command -v winepath >/dev/null 2>&1 || die "winepath is required"

channel=$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$toolchain_file")
[ -n "$channel" ] || die "could not read the pinned channel from rust-toolchain.toml"
windows_toolchain="${channel}-x86_64-pc-windows-gnullvm"

read_toml_array() {
    key=$1
    sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\[\(.*\)\][[:space:]]*$/\1/p" "$toolchain_file" |
        tr ',' '\n' |
        sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//; /^[[:space:]]*$/d'
}

export WINEPREFIX="$wine_prefix"
user_profile_windows=$(WINEDEBUG=-all wine cmd /d /s /c 'echo %USERPROFILE%' | tr -d '\r' | tail -n 1)
[ -n "$user_profile_windows" ] || die "could not resolve Wine USERPROFILE"
user_profile_unix=$(WINEDEBUG=-all winepath -u "$user_profile_windows")
rustup_exe="$user_profile_unix/.cargo/bin/rustup.exe"

if [ ! -f "$rustup_exe" ]; then
    command -v curl >/dev/null 2>&1 || die "curl is required for the initial Wine rustup installation"
    installer_dir=$(mktemp -d)
    trap 'rm -rf -- "$installer_dir"' EXIT
    curl --fail --location --proto '=https' --tlsv1.2 https://win.rustup.rs/x86_64 -o "$installer_dir/rustup-init.exe"
    WINEDEBUG=-all wine "$installer_dir/rustup-init.exe" -y --profile minimal --default-toolchain none
fi

wine_rustup() {
    WINEDEBUG=-all wine "$rustup_exe" "$@"
}

if ! wine_rustup toolchain list | sed 's/ (default)//; s/ (active)//' | grep -Eq "^${windows_toolchain}([[:space:]]|$)"; then
    wine_rustup toolchain install "$windows_toolchain" --profile minimal --component rust-mingw
fi
installed_components=$(wine_rustup component list --toolchain "$windows_toolchain" --installed | tr -d '\r')
while IFS= read -r component; do
    if ! printf '%s\n' "$installed_components" | grep -Eq "^${component}(-|$)"; then
        wine_rustup component add --toolchain "$windows_toolchain" "$component"
    fi
done < <(read_toml_array components)
if ! printf '%s\n' "$installed_components" | grep -Eq '^rust-mingw(-|$)'; then
    wine_rustup component add --toolchain "$windows_toolchain" rust-mingw
fi
installed_targets=$(wine_rustup target list --toolchain "$windows_toolchain" --installed | tr -d '\r')
while IFS= read -r target; do
    if ! printf '%s\n' "$installed_targets" | grep -Fxq "$target"; then
        wine_rustup target add --toolchain "$windows_toolchain" "$target"
    fi
done < <(read_toml_array targets)

oracle_file=$(find "$repo_root/docs/compiler/oracles" -maxdepth 1 -type f -name 'ORACLE-*.md' -printf '%f\n' | sort | tail -n 1)
[ -n "$oracle_file" ] || die "no oracle record found"
expected_commit=$(sed -n 's/^- full commit: `\([0-9a-f][0-9a-f]*\)`$/\1/p' "$repo_root/docs/compiler/oracles/$oracle_file")
actual_commit=$(wine_rustup run "$windows_toolchain" rustc -Vv | tr -d '\r' | sed -n 's/^commit-hash: //p')
[ "$actual_commit" = "$expected_commit" ] || die "Wine rustc commit $actual_commit does not match $oracle_file ($expected_commit)"

cargo_bin_windows="${user_profile_windows}\\.cargo\\bin"
toolchain_bin_windows="${user_profile_windows}\\.rustup\\toolchains\\${windows_toolchain}\\bin"
export WINEPATH="${cargo_bin_windows};${toolchain_bin_windows}${WINEPATH:+;$WINEPATH}"
export MRML_WINE_TOOLCHAIN="$windows_toolchain"

printf 'MRML Wine oracle ready: %s (%s)\n' "$windows_toolchain" "$actual_commit"
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    printf 'Run `source tools/toolchain/setup-wine-oracle.sh` to retain WINEPATH and MRML_WINE_TOOLCHAIN in this shell.\n'
fi
