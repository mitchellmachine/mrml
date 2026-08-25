use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};

use crate::{BootPackageRole, PackageError, PayloadView, ReleaseError, parse, parse_release};

pub const KERNEL_PACKAGE_ID: &str = "org.mrml.system.kernel";
pub const KERNEL_PACKAGE_CLASS: &str = "kernel";
pub const KERNEL_PAYLOAD_PURPOSE: &str = "kernel";
pub const KERNEL_PAYLOAD_ARCHITECTURE: &str = "x86_64";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAdmissionError {
    PackageTrustRoot,
    Package(PackageError),
    ReleaseTrustRoot,
    Release(ReleaseError),
    ReleaseBinding,
    Identity,
    Version,
    Payload(PackageError),
    PayloadSize,
}

pub fn admit_kernel_payload<'a>(
    package_bytes: &'a [u8],
    package_public: &[u8],
    minimum_version: u64,
    maximum_payload_bytes: usize,
    release_binding: Option<(&[u8], &[u8])>,
) -> Result<PayloadView<'a>, KernelAdmissionError> {
    if package_public.len() != LAMPORT_PUBLIC_KEY_BYTES {
        return Err(KernelAdmissionError::PackageTrustRoot);
    }
    let package = parse(package_bytes, true, true).map_err(KernelAdmissionError::Package)?;
    if let Some((release_bytes, release_public)) = release_binding {
        if release_public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(KernelAdmissionError::ReleaseTrustRoot);
        }
        let release = parse_release(release_bytes, true).map_err(KernelAdmissionError::Release)?;
        if release.key_id != Sha3_512::digest(release_public)
            || !release.binds_exact_package(BootPackageRole::Kernel, package.version, package_bytes)
        {
            return Err(KernelAdmissionError::ReleaseBinding);
        }
    }
    if package.id != KERNEL_PACKAGE_ID
        || package.class != KERNEL_PACKAGE_CLASS
        || package.key_id != Sha3_512::digest(package_public)
    {
        return Err(KernelAdmissionError::Identity);
    }
    if minimum_version == 0 || package.version < minimum_version {
        return Err(KernelAdmissionError::Version);
    }
    let payload = package
        .select(KERNEL_PAYLOAD_PURPOSE, KERNEL_PAYLOAD_ARCHITECTURE)
        .map_err(KernelAdmissionError::Payload)?;
    if payload.raw_len == 0 || payload.raw_len > maximum_payload_bytes {
        return Err(KernelAdmissionError::PayloadSize);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_root_and_package_failures_are_distinct_and_bounded() {
        assert_eq!(
            admit_kernel_payload(&[], &[], 1, 1, None),
            Err(KernelAdmissionError::PackageTrustRoot)
        );
        assert_eq!(
            admit_kernel_payload(&[], &[0; LAMPORT_PUBLIC_KEY_BYTES], 1, 1, None),
            Err(KernelAdmissionError::Package(PackageError::Format))
        );
    }
}
