use mrml_package_format::{RuntimeIsolationClass, SystemReleaseError, parse_system_release};

use crate::{
    ObjectId, TotalMicrovmClass, TotalMicrovmInventory, TotalMicrovmInventoryEntry,
    TotalMicrovmRuntimeError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDomainBinding<'a> {
    package_id: &'a str,
    domain: ObjectId,
    class: TotalMicrovmClass,
    reason: &'a str,
}

impl<'a> RuntimeDomainBinding<'a> {
    pub const fn new(
        package_id: &'a str,
        domain: ObjectId,
        class: TotalMicrovmClass,
        reason: &'a str,
    ) -> Result<Self, ReleaseInventoryError> {
        if package_id.is_empty() || domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        Ok(Self {
            package_id,
            domain,
            class,
            reason,
        })
    }

    pub const fn package_id(self) -> &'a str {
        self.package_id
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn class(self) -> TotalMicrovmClass {
        self.class
    }

    pub const fn reason(self) -> &'a str {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseInventoryError {
    Release(SystemReleaseError),
    SignerMismatch,
    MissingRuntimeInventory,
    InvalidBinding,
    BindingCount,
    DuplicateBinding,
    MissingBinding,
    ClassificationMismatch,
    ReasonMismatch,
    Inventory(TotalMicrovmRuntimeError),
}

/// Constructs the kernel's complete strict-Total inventory only from one
/// authenticated SystemRelease v2 and the exact package-to-live-domain bindings
/// created by the normal launch control plane. Package names identify records;
/// neither package metadata nor this translation grants domain authority.
pub fn total_inventory_from_system_release<const N: usize>(
    release_bytes: &[u8],
    expected_key_id: &[u8; 64],
    policy_generation: u64,
    bindings: &[RuntimeDomainBinding<'_>],
) -> Result<TotalMicrovmInventory<N>, ReleaseInventoryError> {
    let release = parse_system_release(release_bytes).map_err(ReleaseInventoryError::Release)?;
    if *expected_key_id == [0; 64] || release.key_id() != *expected_key_id {
        return Err(ReleaseInventoryError::SignerMismatch);
    }
    let runtime = release
        .runtime_inventory()
        .ok_or(ReleaseInventoryError::MissingRuntimeInventory)?;
    if bindings.len() != runtime.package_count() as usize || bindings.len() > N {
        return Err(ReleaseInventoryError::BindingCount);
    }
    for (index, binding) in bindings.iter().enumerate() {
        if binding.package_id.is_empty() || binding.domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        if bindings[..index].iter().any(|present| {
            present.package_id == binding.package_id || present.domain == binding.domain
        }) {
            return Err(ReleaseInventoryError::DuplicateBinding);
        }
    }

    let mut inventory =
        TotalMicrovmInventory::new(release.generation().generation(), policy_generation)
            .map_err(ReleaseInventoryError::Inventory)?;
    for record in runtime.records() {
        let binding = bindings
            .iter()
            .find(|binding| binding.package_id == record.package_id)
            .ok_or(ReleaseInventoryError::MissingBinding)?;
        let class_matches = matches!(
            (record.class, binding.class),
            (
                RuntimeIsolationClass::MicrovmEligible,
                TotalMicrovmClass::MicrovmEligible
            ) | (
                RuntimeIsolationClass::HostSubstrateRequired,
                TotalMicrovmClass::HostSubstrateRequired(_)
            ) | (RuntimeIsolationClass::BootOnly, TotalMicrovmClass::BootOnly)
                | (
                    RuntimeIsolationClass::RecoveryOnly,
                    TotalMicrovmClass::RecoveryOnly
                )
                | (
                    RuntimeIsolationClass::UnsupportedBlocker,
                    TotalMicrovmClass::UnsupportedBlocker
                )
        );
        if !class_matches {
            return Err(ReleaseInventoryError::ClassificationMismatch);
        }
        if binding.reason != record.reason {
            return Err(ReleaseInventoryError::ReasonMismatch);
        }
        inventory
            .insert(
                TotalMicrovmInventoryEntry::new(binding.domain, binding.class, record.must_run)
                    .map_err(ReleaseInventoryError::Inventory)?,
            )
            .map_err(ReleaseInventoryError::Inventory)?;
    }
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, lamport_public_key};
    use mrml_package_format::{
        ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
        MAX_SYSTEM_RELEASE_BYTES, RuntimeInventoryRecord, RuntimeIsolationPlacement,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation, encode_system_release,
        encode_system_release_with_runtime_inventory,
    };

    const POLICY: u64 = 19;

    fn build_release(
        include_runtime: bool,
        runtime_generation: u64,
    ) -> ([u8; MAX_SYSTEM_RELEASE_BYTES], usize, [u8; 64]) {
        let digest = [0x41; 64];
        let generation_record = SystemGenerationDigestRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
        };
        let mut generation = [0; 160];
        let generation_length =
            encode_system_generation(13, &[generation_record], &mut generation).unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(13, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length =
            encode_runtime_inventory(runtime_generation, &[runtime_record], &mut runtime).unwrap();
        let private = [0x67; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = mrml_crypto::Sha3_512::digest(&public);
        let mut output = [0; MAX_SYSTEM_RELEASE_BYTES];
        let length = if include_runtime {
            encode_system_release_with_runtime_inventory(
                &generation[..generation_length],
                &catalog[..catalog_length],
                &runtime[..runtime_length],
                &private,
                &mut output,
            )
        } else {
            encode_system_release(
                &generation[..generation_length],
                &catalog[..catalog_length],
                &private,
                &mut output,
            )
        }
        .unwrap();
        (output, length, key_id)
    }

    #[test]
    fn authenticated_release_constructs_complete_kernel_inventory() {
        let (release, release_length, key_id) = build_release(true, 13);
        let bindings = [RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap()];
        let inventory = total_inventory_from_system_release::<1>(
            &release[..release_length],
            &key_id,
            POLICY,
            &bindings,
        )
        .unwrap();
        let entry = inventory.entries().next().unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(entry.domain(), ObjectId(0x700));
        assert_eq!(entry.class(), TotalMicrovmClass::MicrovmEligible);
        assert!(entry.must_be_running());
    }

    #[test]
    fn v1_wrong_signer_and_binding_substitution_fail_closed() {
        let (release, release_length, key_id) = build_release(false, 13);
        let binding = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[binding]
            ),
            Err(ReleaseInventoryError::MissingRuntimeInventory)
        ));

        let (release, release_length, _) = build_release(true, 13);
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &[0x99; 64],
                POLICY,
                &[binding]
            ),
            Err(ReleaseInventoryError::SignerMismatch)
        ));
        let wrong_package = RuntimeDomainBinding::new(
            "org.mrml.service.other",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_package]
            ),
            Err(ReleaseInventoryError::MissingBinding)
        ));
        let wrong_class = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::BootOnly,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_class]
            ),
            Err(ReleaseInventoryError::ClassificationMismatch)
        ));
        let wrong_reason = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "substituted reason",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_reason]
            ),
            Err(ReleaseInventoryError::ReasonMismatch)
        ));
    }

    #[test]
    fn release_inventory_requires_exact_count_and_unique_domains() {
        let (release, release_length, key_id) = build_release(true, 13);
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[]
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
        let first = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        let duplicate = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x701),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<2>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[first, duplicate]
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
    }
}
