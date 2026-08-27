use crate::abi::{AbiOpaqueHandle, InterfaceIdentity};
use crate::binding::{BindingError, InterfaceBindingId, InterfaceBindingTable, ProviderTarget};
use crate::component_launch::{
    ComponentServiceLaunchHandoff, ComponentServiceLaunchHandoffError, ComponentServicePlacement,
};
use crate::generation::{SystemGeneration, SystemPackage};
use crate::interface_catalog::{
    InterfaceCatalogView, MAX_SINGLE_INTERFACE_CATALOG_BYTES, encode_interface_catalog,
};
use crate::isolation::{EffectivePlacement, IsolationPlacement, PlacementSource};
use crate::loader::ImmutableLoadPlan;
use crate::resolver::{ProviderForm, ResolvedInterfaceProvider};
use crate::system_generation::{SystemGenerationDigestRecord, system_generation_digest};
use crate::{ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms};

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

/// The complete backend-neutral control-plane result for one independently
/// serviced binding. KVM and WHP consume these already matched immutable load
/// plans; neither backend may choose or substitute package bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationBoundServiceLaunch {
    placement: GenerationBoundServicePlacement,
    consumer: ImmutableLoadPlan,
    provider: ImmutableLoadPlan,
}

impl GenerationBoundServiceLaunch {
    pub fn admit(
        placement: GenerationBoundServicePlacement,
        consumer: ImmutableLoadPlan,
        provider: ImmutableLoadPlan,
    ) -> Result<Self, ServiceLaunchAdmissionError> {
        if consumer.package() != placement.consumer() {
            return Err(ServiceLaunchAdmissionError::ConsumerArtifactMismatch);
        }
        if provider.package() != placement.provider() {
            return Err(ServiceLaunchAdmissionError::ProviderArtifactMismatch);
        }
        Ok(Self {
            placement,
            consumer,
            provider,
        })
    }

    pub const fn placement(&self) -> &GenerationBoundServicePlacement {
        &self.placement
    }

    pub const fn consumer(&self) -> &ImmutableLoadPlan {
        &self.consumer
    }

    pub const fn provider(&self) -> &ImmutableLoadPlan {
        &self.provider
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceLaunchAdmissionError {
    ConsumerArtifactMismatch,
    ProviderArtifactMismatch,
}

/// Linear pre-launch control-plane result. Resolution, policy, and both
/// immutable artifacts are fixed before any backend is allowed to construct an
/// endpoint. Only `publish` can turn a backend-returned opaque endpoint into a
/// live generation-safe interface binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedGenerationBoundServiceLaunch {
    system_generation: u64,
    system_generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    resolved: ResolvedInterfaceProvider,
    placement: IsolationPlacement,
    source: PlacementSource,
    consumer: ImmutableLoadPlan,
    provider: ImmutableLoadPlan,
}

/// Capability-selected kernel object identities and the applied policy
/// generation supplied after package/interface resolution. These values
/// identify the kernel objects for the handoff; constructing this record does
/// not grant either capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelServiceLaunchAuthority {
    policy_generation: u64,
    domain_object: u64,
    interface_object: u64,
}

impl KernelServiceLaunchAuthority {
    pub const fn new(
        policy_generation: u64,
        domain_object: u64,
        interface_object: u64,
    ) -> Result<Self, ComponentServiceLaunchHandoffError> {
        if policy_generation == 0 {
            return Err(ComponentServiceLaunchHandoffError::Generation);
        }
        if domain_object == 0 || interface_object == 0 {
            return Err(ComponentServiceLaunchHandoffError::Object);
        }
        Ok(Self {
            policy_generation,
            domain_object,
            interface_object,
        })
    }
}

impl PreparedGenerationBoundServiceLaunch {
    pub fn prepare(
        system: &SystemGeneration,
        resolved: ResolvedInterfaceProvider,
        effective: EffectivePlacement,
        consumer: ImmutableLoadPlan,
        provider: ImmutableLoadPlan,
    ) -> Result<Self, PreparedServiceLaunchError> {
        if effective.source() == PlacementSource::TotalMicrovmException {
            return Err(PreparedServiceLaunchError::TotalMicrovmException);
        }
        if !matches!(
            effective.placement(),
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) {
            return Err(PreparedServiceLaunchError::UnsupportedServicePlacement);
        }
        if resolved.form() != ProviderForm::IsolatedService {
            return Err(PreparedServiceLaunchError::ProviderFormMismatch);
        }
        if system.package(resolved.consumer().package_id()) != Some(resolved.consumer()) {
            return Err(PreparedServiceLaunchError::ConsumerGenerationMismatch);
        }
        if system.package(resolved.provider().package_id()) != Some(resolved.provider()) {
            return Err(PreparedServiceLaunchError::ProviderGenerationMismatch);
        }
        if consumer.package() != resolved.consumer() {
            return Err(PreparedServiceLaunchError::ConsumerArtifactMismatch);
        }
        if provider.package() != resolved.provider() {
            return Err(PreparedServiceLaunchError::ProviderArtifactMismatch);
        }
        let generation_records = system
            .packages()
            .iter()
            .map(|package| SystemGenerationDigestRecord {
                package_id: package.package_id(),
                version: package.version(),
                artifact_digest: package.artifact_digest(),
            })
            .collect::<Vec<_>>();
        let system_generation_digest =
            system_generation_digest(system.generation(), &generation_records)
                .map_err(|_| PreparedServiceLaunchError::InvalidSystemGeneration)?;
        let requirement = ComponentInterfaceRequirement::exact(
            resolved.consumer().package_id(),
            resolved.interface().name(),
            resolved.interface().generation(),
            resolved.fingerprint(),
        )
        .map_err(|_| PreparedServiceLaunchError::InvalidInterfaceCatalog)?;
        let forms = match effective.placement() {
            IsolationPlacement::NativeService => ComponentProviderForms::NATIVE_SERVICE,
            IsolationPlacement::Microvm => ComponentProviderForms::MICROVM,
            _ => return Err(PreparedServiceLaunchError::InvalidInterfaceCatalog),
        };
        let provider_declaration = ComponentInterfaceProvider::exact(
            resolved.provider().package_id(),
            resolved.interface().name(),
            resolved.interface().generation(),
            resolved.fingerprint(),
            forms,
        )
        .map_err(|_| PreparedServiceLaunchError::InvalidInterfaceCatalog)?;
        let mut catalog = [0u8; MAX_SINGLE_INTERFACE_CATALOG_BYTES];
        let catalog_length = encode_interface_catalog(
            system.generation(),
            &[requirement],
            &[provider_declaration],
            &mut catalog,
        )
        .map_err(|_| PreparedServiceLaunchError::InvalidInterfaceCatalog)?;
        let interface_catalog_digest = InterfaceCatalogView::decode(&catalog[..catalog_length])
            .map_err(|_| PreparedServiceLaunchError::InvalidInterfaceCatalog)?
            .digest();
        Ok(Self {
            system_generation: system.generation(),
            system_generation_digest,
            interface_catalog_digest,
            resolved,
            placement: effective.placement(),
            source: effective.source(),
            consumer,
            provider,
        })
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn placement(&self) -> IsolationPlacement {
        self.placement
    }

    pub fn resolved(&self) -> &ResolvedInterfaceProvider {
        &self.resolved
    }

    pub fn consumer(&self) -> &ImmutableLoadPlan {
        &self.consumer
    }

    pub fn provider(&self) -> &ImmutableLoadPlan {
        &self.provider
    }

    /// Emits the one canonical pointer-free handoff consumed by kernel
    /// isolation admission. Package generations, digests, interface identity,
    /// fingerprint, and selected placement come only from this already
    /// prepared immutable launch; the caller supplies only capability-selected
    /// kernel object identities and the applied policy generation.
    pub fn kernel_handoff(
        &self,
        authority: KernelServiceLaunchAuthority,
    ) -> Result<ComponentServiceLaunchHandoff, ComponentServiceLaunchHandoffError> {
        let placement = match self.placement {
            IsolationPlacement::NativeService => ComponentServicePlacement::NativeService,
            IsolationPlacement::Microvm => ComponentServicePlacement::Microvm,
            _ => return Err(ComponentServiceLaunchHandoffError::Placement),
        };
        ComponentServiceLaunchHandoff::new(
            self.system_generation,
            authority.policy_generation,
            authority.domain_object,
            authority.interface_object,
            self.resolved.interface().generation(),
            self.resolved.provider().version(),
            placement,
            self.system_generation_digest,
            self.interface_catalog_digest,
            self.resolved.fingerprint(),
            *self.consumer.package().artifact_digest(),
            *self.provider.package().artifact_digest(),
        )
    }

    /// Publishes the first live endpoint reference only after the selected
    /// backend has returned it. All fallible generation/artifact checks happen
    /// in `prepare`; publication can fail only at the bounded binding table.
    pub fn publish<const N: usize>(
        self,
        bindings: &mut InterfaceBindingTable<N>,
        endpoint: AbiOpaqueHandle,
    ) -> Result<
        (InterfaceBindingId, GenerationBoundServiceLaunch),
        Box<PreparedServicePublicationError>,
    > {
        let binding_id =
            match bindings.bind(&self.resolved, ProviderTarget::IsolatedService { endpoint }) {
                Ok(binding_id) => binding_id,
                Err(error) => {
                    return Err(Box::new(PreparedServicePublicationError {
                        prepared: self,
                        endpoint,
                        error,
                    }));
                }
            };
        let placement = GenerationBoundServicePlacement {
            system_generation: self.system_generation,
            binding_id,
            consumer: self.resolved.consumer().clone(),
            provider: self.resolved.provider().clone(),
            interface: self.resolved.interface().clone(),
            fingerprint: self.resolved.fingerprint(),
            endpoint,
            placement: self.placement,
            source: self.source,
        };
        Ok((
            binding_id,
            GenerationBoundServiceLaunch {
                placement,
                consumer: self.consumer,
                provider: self.provider,
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedServiceLaunchError {
    InvalidSystemGeneration,
    InvalidInterfaceCatalog,
    TotalMicrovmException,
    UnsupportedServicePlacement,
    ProviderFormMismatch,
    ConsumerGenerationMismatch,
    ProviderGenerationMismatch,
    ConsumerArtifactMismatch,
    ProviderArtifactMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedServicePublicationError {
    prepared: PreparedGenerationBoundServiceLaunch,
    endpoint: AbiOpaqueHandle,
    error: BindingError,
}

impl PreparedServicePublicationError {
    pub const fn endpoint(&self) -> AbiOpaqueHandle {
        self.endpoint
    }

    pub const fn error(&self) -> BindingError {
        self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        PreparedGenerationBoundServiceLaunch,
        AbiOpaqueHandle,
        BindingError,
    ) {
        (self.prepared, self.endpoint, self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::InterfaceBindingTable;
    use crate::isolation::{IsolationPolicy, PlacementRequest};
    use crate::loader::{COMPONENT_PAGE_BYTES, ImageSection, SectionPermissions};
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

    fn load_plan(package: SystemPackage) -> ImmutableLoadPlan {
        ImmutableLoadPlan::admit(
            package,
            COMPONENT_PAGE_BYTES,
            64,
            vec![
                ImageSection::pages(
                    0,
                    COMPONENT_PAGE_BYTES,
                    SectionPermissions::new(true, false, true).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
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

    #[test]
    fn exact_placement_admits_only_its_two_immutable_package_generations() {
        let system = system(15, 0x2f);
        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        let id = bindings
            .bind(
                &resolved(&system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService {
                    endpoint: AbiOpaqueHandle::new(7, 11).unwrap(),
                },
            )
            .unwrap();
        let placement = GenerationBoundServicePlacement::bind(
            &system,
            &bindings,
            id,
            dual_service_policy()
                .resolve(PlacementRequest::TotalMicrovm)
                .unwrap(),
        )
        .unwrap();
        let launch = GenerationBoundServiceLaunch::admit(
            placement,
            load_plan(system.package("org.mrml.zim").unwrap().clone()),
            load_plan(system.package("org.mrml.zstd").unwrap().clone()),
        )
        .unwrap();
        assert_eq!(launch.placement().placement(), IsolationPlacement::Microvm);
        assert_eq!(launch.consumer().package().package_id(), "org.mrml.zim");
        assert_eq!(launch.provider().package().package_id(), "org.mrml.zstd");
    }

    #[test]
    fn either_artifact_generation_mismatch_fails_before_backend_launch() {
        let system = system(15, 0x2f);
        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        let id = bindings
            .bind(
                &resolved(&system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService {
                    endpoint: AbiOpaqueHandle::new(7, 11).unwrap(),
                },
            )
            .unwrap();
        let effective = dual_service_policy()
            .resolve(PlacementRequest::TotalMicrovm)
            .unwrap();
        let placement =
            GenerationBoundServicePlacement::bind(&system, &bindings, id, effective).unwrap();
        assert_eq!(
            GenerationBoundServiceLaunch::admit(
                placement,
                load_plan(package("org.mrml.zim", 9, 0x19)),
                load_plan(system.package("org.mrml.zstd").unwrap().clone()),
            ),
            Err(ServiceLaunchAdmissionError::ConsumerArtifactMismatch)
        );

        let placement =
            GenerationBoundServicePlacement::bind(&system, &bindings, id, effective).unwrap();
        assert_eq!(
            GenerationBoundServiceLaunch::admit(
                placement,
                load_plan(system.package("org.mrml.zim").unwrap().clone()),
                load_plan(package("org.mrml.zstd", 16, 0x30)),
            ),
            Err(ServiceLaunchAdmissionError::ProviderArtifactMismatch)
        );
    }

    #[test]
    fn resolved_launch_publishes_endpoint_only_after_all_prelaunch_checks() {
        let system = system(15, 0x2f);
        let effective = dual_service_policy()
            .resolve(PlacementRequest::PackageDefault)
            .unwrap();
        let prepared = PreparedGenerationBoundServiceLaunch::prepare(
            &system,
            resolved(&system, ProviderForm::IsolatedService),
            effective,
            load_plan(system.package("org.mrml.zim").unwrap().clone()),
            load_plan(system.package("org.mrml.zstd").unwrap().clone()),
        )
        .unwrap();
        assert_eq!(prepared.system_generation(), 108);
        assert_eq!(prepared.placement(), IsolationPlacement::NativeService);
        assert_eq!(prepared.resolved().provider().version(), 15);
        let handoff = prepared
            .kernel_handoff(KernelServiceLaunchAuthority::new(7, 0x500, 0x406).unwrap())
            .unwrap();
        assert_eq!(handoff.system_generation(), 108);
        assert_eq!(handoff.policy_generation(), 7);
        assert_eq!(handoff.interface_generation(), 3);
        assert_eq!(handoff.provider_generation(), 15);
        assert_eq!(
            handoff.system_generation_digest(),
            &system_generation_digest(
                system.generation(),
                &system
                    .packages()
                    .iter()
                    .map(|package| SystemGenerationDigestRecord {
                        package_id: package.package_id(),
                        version: package.version(),
                        artifact_digest: package.artifact_digest(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        );
        assert_eq!(handoff.interface_fingerprint(), &ZSTD3);
        assert_eq!(
            ComponentServiceLaunchHandoff::decode(&handoff.encode()),
            Ok(handoff)
        );

        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        assert_eq!(bindings.bindings().count(), 0);
        let endpoint = AbiOpaqueHandle::new(7, 11).unwrap();
        let (binding_id, launch) = prepared.publish(&mut bindings, endpoint).unwrap();
        assert_eq!(bindings.bindings().count(), 1);
        assert_eq!(
            bindings.get(binding_id).unwrap().target(),
            ProviderTarget::IsolatedService { endpoint }
        );
        assert_eq!(launch.placement().binding_id(), binding_id);
        assert_eq!(launch.placement().endpoint(), endpoint);
        assert_eq!(launch.provider().package().artifact_digest(), &[0x2f; 64]);
    }

    #[test]
    fn failed_prelaunch_checks_publish_no_binding_or_endpoint() {
        let system = system(15, 0x2f);
        let effective = dual_service_policy()
            .resolve(PlacementRequest::TotalMicrovm)
            .unwrap();
        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        assert_eq!(
            PreparedGenerationBoundServiceLaunch::prepare(
                &system,
                resolved(&system, ProviderForm::IsolatedService),
                effective,
                load_plan(system.package("org.mrml.zim").unwrap().clone()),
                load_plan(package("org.mrml.zstd", 16, 0x30)),
            ),
            Err(PreparedServiceLaunchError::ProviderArtifactMismatch)
        );
        assert_eq!(bindings.bindings().count(), 0);

        let prepared = PreparedGenerationBoundServiceLaunch::prepare(
            &system,
            resolved(&system, ProviderForm::IsolatedService),
            effective,
            load_plan(system.package("org.mrml.zim").unwrap().clone()),
            load_plan(system.package("org.mrml.zstd").unwrap().clone()),
        )
        .unwrap();
        let occupied = bindings
            .bind(
                &resolved(&system, ProviderForm::IsolatedService),
                ProviderTarget::IsolatedService {
                    endpoint: AbiOpaqueHandle::new(3, 1).unwrap(),
                },
            )
            .unwrap();
        let endpoint = AbiOpaqueHandle::new(7, 11).unwrap();
        let failure = prepared.publish(&mut bindings, endpoint).unwrap_err();
        assert_eq!(failure.endpoint(), endpoint);
        assert_eq!(failure.error(), BindingError::CapacityExhausted);
        let (prepared, returned_endpoint, error) = (*failure).into_parts();
        assert_eq!(prepared.system_generation(), 108);
        assert_eq!(prepared.resolved().provider().version(), 15);
        assert_eq!(returned_endpoint, endpoint);
        assert_eq!(error, BindingError::CapacityExhausted);
        assert_eq!(bindings.bindings().count(), 1);
        assert_eq!(bindings.get(occupied).unwrap().provider().version(), 15);
    }
}
