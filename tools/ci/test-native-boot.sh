#!/usr/bin/env bash
# Disposable QEMU/OVMF boot using an explicitly scoped, one-use test trust root.
set -euo pipefail
umask 077

if [[ $# != 2 && ( $# != 3 || ${3:-} != --fat32-restart ) ]]; then
    printf 'usage: %s OVMF_CODE OVMF_VARS [--fat32-restart]\n' "$0" >&2
    exit 64
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
mrml=./target/debug/mrml
work=$(mktemp -d /tmp/mrml-ci-boot.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT

"$mrml" build org.mrml.tool.sign --target linux --release

sign=./target/mrml-native/linux/release/mrml-sign
kernel=./target/mrml-native/uefi/release/mrml-kernel-pe.efi
service=./target/mrml-native/mrml_native-x86_64-unknown-uefi/release/mrml-service-pe.efi
loader_profile=package_boot
trace_options=()

for role in kernel service kernel-package loader-package configuration-package release; do
    "$sign" keygen "$work/$role.private" "$work/$role.public"
done

kernel_root=$("$sign" key-digest "$work/kernel.public")
service_root=$("$sign" key-digest "$work/service.public")
package_root=$("$sign" key-digest "$work/kernel-package.public")
release_root=$("$sign" key-digest "$work/release.public")

if [[ ${3:-} == --fat32-restart ]]; then
    "$mrml" build org.mrml.system.bootloader --target uefi-x86_64 --release \
        --feature-profile uefi_fat32_restart_probe \
        --compile-env "MRML_SERVICE_ROOT_DIGEST_HEX=$service_root" \
        --compile-env MRML_SERVICE_MIN_VERSION=1
    "$mrml" build org.mrml.library.storage.fat32 --target native --release
    service=./target/mrml-native/mrml_native-x86_64-unknown-uefi/release/mrml-fat32-service.efi
    loader_profile=fat32_restart_boot
    trace_options=(--expect-hex c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d0d1d2d3)
else
    "$mrml" build org.mrml.system.bootloader --target uefi-x86_64 --release
    "$mrml" build org.mrml.system.service-image --target native --release
fi

"$mrml" build org.mrml.library.uefi --target uefi-x86_64 --release \
    --feature-profile "$loader_profile" \
    --compile-env "MRML_KERNEL_ROOT_DIGEST_HEX=$kernel_root" \
    --compile-env MRML_KERNEL_MIN_VERSION=1 \
    --compile-env "MRML_SERVICE_ROOT_DIGEST_HEX=$service_root" \
    --compile-env MRML_SERVICE_MIN_VERSION=1 \
    --compile-env "MRML_KERNEL_PACKAGE_ROOT_DIGEST_HEX=$package_root" \
    --compile-env "MRML_SYSTEM_RELEASE_ROOT_DIGEST_HEX=$release_root"
loader=./target/mrml-native/uefi/release/mrml-loader.efi

"$sign" sign-bundle kernel 1 "$kernel" "$work/kernel.private" "$work/kernel.signed"
"$sign" sign-bundle service 1 "$service" "$work/service.private" "$work/service.signed"

# The authenticated boot fixture checks the exact configuration package bytes,
# but does not treat this payload as a production configuration.
printf 'MRML disposable CI boot fixture\n' > "$work/configuration.bin"
"$mrml" package create org.mrml.library.uefi bootloader 1 x86_64 uefi-loader \
    "$loader" "$work/loader.mrp" --private-key "$work/loader-package.private"
"$mrml" package create org.mrml.system.kernel kernel 1 x86_64 kernel \
    "$work/kernel.signed" "$work/kernel.mrp" --private-key "$work/kernel-package.private"
"$mrml" package create org.mrml.service.config configuration 1 x86_64 configuration \
    "$work/configuration.bin" "$work/configuration.mrp" --private-key "$work/configuration-package.private"
"$mrml" release create 1 "$work/loader.mrp" "$work/kernel.mrp" "$work/configuration.mrp" \
    "$work/release.private" "$work/system.mrs"
"$mrml" release verify "$work/system.mrs" "$work/release.public"
"$mrml" package boot-media-create "$loader" "$work/loader.mrp" "$work/kernel.mrp" \
    "$work/configuration.mrp" "$work/system.mrs" "$work/service.signed" "$work/boot.img" \
    "$(command -v sfdisk)" "$(command -v mformat)" "$(command -v mmd)" "$(command -v mcopy)"
"$mrml" package qemu-boot "$work/boot.img" "$1" "$2" "$(command -v qemu-system-x86_64)" \
    "$work/boot.trace" --accelerator tcg --timeout-seconds 60 "${trace_options[@]}"
