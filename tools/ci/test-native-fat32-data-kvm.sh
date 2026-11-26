#!/usr/bin/env bash
# Run the signed FAT32 file read probe on a host with usable /dev/kvm.
# This proves a signed filesystem read from synthetic media, not restart.
set -euo pipefail
umask 077

if [[ $# != 0 ]]; then
    printf 'usage: %s\n' "$0" >&2
    exit 64
fi
if [[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    printf 'This probe requires readable and writable /dev/kvm.\n' >&2
    exit 69
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
mrml=./target/debug/mrml
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

"$mrml" build org.mrml.tool.sign --target linux --release
"$mrml" build org.mrml.tool.vmm-kvm-run --target linux --release
"$mrml" build org.mrml.library.storage.fat32 --target native --release
"$mrml" build org.mrml.system.bootloader --target uefi-x86_64 --release \
    --feature-profile fat32_data_probe

sign=./target/mrml-native/linux/release/mrml-sign
runner=./target/mrml-native/linux/release/mrml-kvm-run
kernel=./target/mrml-native/uefi/release/mrml-kernel-pe.efi
service=./target/mrml-native/mrml_native-x86_64-unknown-uefi/release/mrml-fat32-service.efi
for role in kernel service kernel-package; do
    "$sign" keygen "$work/$role.private" "$work/$role.public"
done
"$sign" sign-bundle kernel 1 "$kernel" "$work/kernel.private" "$work/kernel.signed"
"$sign" sign-bundle service 1 "$service" "$work/service.private" "$work/service.signed"
"$mrml" package create org.mrml.system.kernel kernel 1 x86_64 kernel \
    "$work/kernel.signed" "$work/kernel.mrp" --private-key "$work/kernel-package.private"

timeout --kill-after=5s 60s "$runner" "$work/kernel.mrp" "$work/kernel-package.public" \
    "$work/kernel.public" 1 fat32-data-probe "$work/service.signed" \
    "$work/service.public" 1 | tee "$work/readiness.log"
grep -Fxq 'verified signed FAT32 PROBE.TXT read under KVM' "$work/readiness.log"
