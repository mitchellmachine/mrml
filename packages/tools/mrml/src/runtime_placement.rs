use crate::abi::{AbiOpaqueHandle, InterfaceIdentity};
use crate::binding::{BindingError, InterfaceBindingId, InterfaceBindingTable, ProviderTarget};
use crate::generation::{SystemGeneration, SystemPackage};
use crate::isolation::{EffectivePlacement, IsolationPlacement, PlacementSource};

/// One exact, immutable handoff from generation-bound interface resolution to
/// an already selected isolated-service placement. Package and interface names
/// remain identity data; the generational endpoint is the runtime authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationBoundServicePlacement {
    system_generation: u64,
    binding_id: InterfaceBindingId,
    consumer: SystemPackage,
    provider: SystemPackage,
    interface: InterfaceIdentity,
    fingerprint: [u8; 32],
    endpoint: AbiOpaqueHandle,
    placement: IsolationPlacement,
    source: PlacementSource,
}

impl GenerationBoundServicePlacement {
    pub fn bind<const N: usize>(
        system: &SystemGeneration,
        bindings: &InterfaceBindingTable<N>,
        binding_id: InterfaceBindingId,
        effective: EffectivePlacement,
    ) -> Result<Self, RuntimePlacementError> {
        if effective.source() == PlacementSource::TotalMicrovmException {
            return Err(RuntimePlacementError::TotalMicrovmException);
        }
        if !matches!(
            effective.placement(),
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) {
            return Err(RuntimePlacementError::UnsupportedServicePlacement);
        }
        let binding = bindings
            .get(binding_id)
            .map_err(RuntimePlacementError::Binding)?;
        let endpoint = match binding.target() {
            ProviderTarget::IsolatedService { endpoint } => endpoint,
            ProviderTarget::InProcess { .. } => {
                return Err(RuntimePlacementError::ProviderFormMismatch);
            }
        };
        if system.package(binding.consumer().package_id()) != Some(binding.consumer()) {
            return Err(RuntimePlacementError::ConsumerGenerationMismatch);
        }
        if system.package(binding.provider().package_id()) != Some(binding.provider()) {
            return Err(RuntimePlacementError::ProviderGenerationMismatch);
        }
        Ok(Self {
            system_generation: system.generation(),
            binding_id,
            consumer: binding.consumer().clone(),
            provider: binding.provider().clone(),
            interface: binding.interface().clone(),
            fingerprint: binding.fingerprint(),
            endpoint,
            placement: effective.placement(),
            source: effective.source(),
        })
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn binding_id(&self) -> InterfaceBindingId {
        self.binding_id
    }

    pub fn consumer(&self) -> &SystemPackage {
        &self.consumer
    }

    pub fn provider(&self) -> &SystemPackage {
        &self.provider
    }

    pub fn interface(&self) -> &InterfaceIdentity {
        &self.interface
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn endpoint(&self) -> AbiOpaqueHandle {
        self.endpoint
    }

    pub const fn placement(&self) -> IsolationPlacement {
        self.placement
    }

    pub const fn source(&self) -> PlacementSource {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePlacementError {
    Binding(BindingError),
    TotalMicrovmException,
    UnsupportedServicePlacement,
    ProviderFormMismatch,
    ConsumerGenerationMismatch,
    ProviderGenerationMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::InterfaceBindingTable;
    use crate::isolation::{IsolationPolicy, PlacementRequest};
    use crate::manifest::Document;
    use crate::resolver::{
        InterfaceProvider, InterfaceRequirement, ProviderForm, resolve_interface_providers,
    };

    const ZSTD3: [u8; 32] = [0x3a; 32];

    fn package(id: &str, version: u64, marker: u8) -> SystemPackage {
        SystemPackage::new(id.into(), version, [marker; 64]).unwrap()
    }

    fn system(provider_version: u64, provider_marker: u8) -> SystemGeneration {
        SystemGeneration::new(
            108,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", provider_version, provider_marker),
            ],
        )
        .unwrap()
    }

    fn resolved(
        system: &SystemGeneration,
        form: ProviderForm,
    ) -> crate::resolver::ResolvedInterfaceProvider {
        let interface =
            InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), 3).unwrap();
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface.clone(), ZSTD3).unwrap();
        let provider =
            InterfaceProvider::exact("org.mrml.zstd".into(), interface, ZSTD3, form).unwrap();
        resolve_interface_providers(system, &[requirement], &[provider])
            .unwrap()
            .remove(0)
    }

    fn dual_service_policy() -> IsolationPolicy {
        let document = Document::parse(
            b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.zstd\"\n\n[isolation]\ndefault = \"native-service\"\nminimum = \"native-service\"\nmaximum = \"microvm\"\nsupported = [\"native-service\", \"microvm\"]\n",
        )
        .unwrap();
        IsolationPolicy::parse(&document, "service", "org.mrml.zstd").unwrap()
    }

    #[test]
    fn exact_generation_binding_composes_with_either_service_placement() {
        let system = system(15, 0x2f);
        let mut bindings = InterfaceBindingTable::<2>::new().unwrap();
        let endpoint = AbiOpaqueHandle::new(7, 11).unwrap();
        let id = bindings
            .bind(
                &resolved(&system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService { endpoint },
            )
            .unwrap();
        let policy = dual_service_policy();
        for request in [
            PlacementRequest::PackageDefault,
            PlacementRequest::TotalMicrovm,
        ] {
            let placed = GenerationBoundServicePlacement::bind(
                &system,
                &bindings,
                id,
                policy.resolve(request).unwrap(),
            )
            .unwrap();
            assert_eq!(placed.system_generation(), 108);
            assert_eq!(placed.binding_id(), id);
            assert_eq!(placed.provider().version(), 15);
            assert_eq!(placed.provider().artifact_digest(), &[0x2f; 64]);
            assert_eq!(placed.interface().generation(), 3);
            assert_eq!(placed.fingerprint(), ZSTD3);
            assert_eq!(placed.endpoint(), endpoint);
        }
    }

    #[test]
    fn stale_provider_generation_and_binding_id_fail_closed() {
        let old_system = system(14, 0x2e);
        let current_system = system(15, 0x2f);
        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        let id = bindings
            .bind(
                &resolved(&old_system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService {
                    endpoint: AbiOpaqueHandle::new(4, 1).unwrap(),
                },
            )
            .unwrap();
        let effective = dual_service_policy()
            .resolve(PlacementRequest::PackageDefault)
            .unwrap();
        assert_eq!(
            GenerationBoundServicePlacement::bind(&current_system, &bindings, id, effective),
            Err(RuntimePlacementError::ProviderGenerationMismatch)
        );
        bindings.release(id).unwrap();
        assert_eq!(
            GenerationBoundServicePlacement::bind(&old_system, &bindings, id, effective),
            Err(RuntimePlacementError::Binding(BindingError::InvalidBinding))
        );
    }

    #[test]
    fn total_exception_and_in_process_target_never_become_service_launches() {
        let system = system(15, 0x2f);
        let native_only = IsolationPolicy::default_for_kind("service")
            .resolve(PlacementRequest::TotalMicrovm)
            .unwrap();
        let mut service_bindings = InterfaceBindingTable::<1>::new().unwrap();
        let service_id = service_bindings
            .bind(
                &resolved(&system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService {
                    endpoint: AbiOpaqueHandle::new(4, 1).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(
            GenerationBoundServicePlacement::bind(
                &system,
                &service_bindings,
                service_id,
                native_only,
            ),
            Err(RuntimePlacementError::TotalMicrovmException)
        );

        let mut in_process = InterfaceBindingTable::<1>::new().unwrap();
        let in_process_id = in_process
            .bind(
                &resolved(&system, ProviderForm::InProcess),
                ProviderTarget::InProcess {
                    executable: AbiOpaqueHandle::new(9, 2).unwrap(),
                    entry_operation: 1,
                },
            )
            .unwrap();
        let effective = dual_service_policy()
            .resolve(PlacementRequest::PackageDefault)
            .unwrap();
        assert_eq!(
            GenerationBoundServicePlacement::bind(&system, &in_process, in_process_id, effective,),
            Err(RuntimePlacementError::ProviderFormMismatch)
        );
    }
}
