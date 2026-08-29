//! Exact-generation runtime bindings for isolated storage module providers.

use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION: u32 = 1;
pub const STORAGE_FILESYSTEM_INTERFACE_GENERATION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageModuleClass {
    BlockProvider,
    Filesystem,
}

impl StorageModuleClass {
    const fn interface_generation(self) -> u32 {
        match self {
            Self::BlockProvider => STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION,
            Self::Filesystem => STORAGE_FILESYSTEM_INTERFACE_GENERATION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageModuleBinding {
    pub class: StorageModuleClass,
    pub interface_object: ObjectId,
    pub provider_object: ObjectId,
    pub endpoint_object: ObjectId,
    pub interface_generation: u32,
    pub provider_generation: u64,
    pub system_generation: u64,
    pub binding_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageModuleState {
    Active(StorageModuleBinding),
    Replacing {
        old: StorageModuleBinding,
        candidate: StorageModuleBinding,
    },
    Quarantined(StorageModuleBinding),
    Unavailable(StorageModuleBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageModuleError {
    Capability(CapabilityError),
    WrongAuthorityObject,
    InvalidBinding,
    Capacity,
    AlreadyBound,
    Missing,
    NotActive,
    StaleReplacement,
    CleanupFailed,
    LaunchFailed,
}

pub trait StorageModuleBackend {
    /// Revoke all sessions, derived handles, DMA, mappings, IPC, and device
    /// state, then destroy and erase the old provider domain before success.
    fn revoke_cleanup_and_erase(&mut self, old: StorageModuleBinding) -> Result<(), ()>;

    /// Launch the exact candidate in a fresh domain and complete its bounded
    /// interface health check before success.
    fn launch_and_healthcheck(&mut self, candidate: StorageModuleBinding) -> Result<(), ()>;
}

pub struct StorageModuleRegistry<const N: usize> {
    slots: [Option<StorageModuleState>; N],
}

impl<const N: usize> StorageModuleRegistry<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    pub fn state(&self, class: StorageModuleClass) -> Option<StorageModuleState> {
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|state| state.class() == class)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bind_initial<const C: usize>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        interface_capability: Capability,
        provider_capability: Capability,
        endpoint_capability: Capability,
        binding: StorageModuleBinding,
    ) -> Result<(), StorageModuleError> {
        authorize_binding(
            capabilities,
            interface_capability,
            provider_capability,
            endpoint_capability,
            binding,
        )?;
        validate_binding(binding)?;
        if self.state(binding.class).is_some() {
            return Err(StorageModuleError::AlreadyBound);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(StorageModuleError::Capacity)?;
        *slot = Some(StorageModuleState::Active(binding));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replace<const C: usize, B: StorageModuleBackend>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        interface_capability: Capability,
        provider_capability: Capability,
        endpoint_capability: Capability,
        expected_current_binding_generation: u64,
        candidate: StorageModuleBinding,
        backend: &mut B,
    ) -> Result<StorageModuleBinding, StorageModuleError> {
        authorize_binding(
            capabilities,
            interface_capability,
            provider_capability,
            endpoint_capability,
            candidate,
        )?;
        validate_binding(candidate)?;
        let index = self
            .index(candidate.class)
            .ok_or(StorageModuleError::Missing)?;
        let old = match self.slots[index] {
            Some(StorageModuleState::Active(old)) => old,
            _ => return Err(StorageModuleError::NotActive),
        };
        if old.binding_generation != expected_current_binding_generation
            || candidate.binding_generation
                != old
                    .binding_generation
                    .checked_add(1)
                    .ok_or(StorageModuleError::InvalidBinding)?
            || candidate.system_generation < old.system_generation
            || (candidate.provider_object == old.provider_object
                && candidate.provider_generation == old.provider_generation)
        {
            return Err(StorageModuleError::StaleReplacement);
        }
        self.slots[index] = Some(StorageModuleState::Replacing { old, candidate });
        if backend.revoke_cleanup_and_erase(old).is_err() {
            self.slots[index] = Some(StorageModuleState::Quarantined(old));
            return Err(StorageModuleError::CleanupFailed);
        }
        if backend.launch_and_healthcheck(candidate).is_err() {
            self.slots[index] = Some(StorageModuleState::Unavailable(candidate));
            return Err(StorageModuleError::LaunchFailed);
        }
        self.slots[index] = Some(StorageModuleState::Active(candidate));
        Ok(candidate)
    }

    pub fn retry_unavailable<B: StorageModuleBackend>(
        &mut self,
        class: StorageModuleClass,
        backend: &mut B,
    ) -> Result<StorageModuleBinding, StorageModuleError> {
        let index = self.index(class).ok_or(StorageModuleError::Missing)?;
        let candidate = match self.slots[index] {
            Some(StorageModuleState::Unavailable(candidate)) => candidate,
            _ => return Err(StorageModuleError::NotActive),
        };
        if backend.launch_and_healthcheck(candidate).is_err() {
            return Err(StorageModuleError::LaunchFailed);
        }
        self.slots[index] = Some(StorageModuleState::Active(candidate));
        Ok(candidate)
    }

    fn index(&self, class: StorageModuleClass) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.is_some_and(|state| state.class() == class))
    }
}

impl<const N: usize> Default for StorageModuleRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageModuleState {
    const fn class(self) -> StorageModuleClass {
        match self {
            Self::Active(binding) | Self::Quarantined(binding) | Self::Unavailable(binding) => {
                binding.class
            }
            Self::Replacing { old, .. } => old.class,
        }
    }
}

fn validate_binding(binding: StorageModuleBinding) -> Result<(), StorageModuleError> {
    if binding.interface_object.0 == 0
        || binding.provider_object.0 == 0
        || binding.endpoint_object.0 == 0
        || binding.interface_object == binding.provider_object
        || binding.interface_object == binding.endpoint_object
        || binding.provider_object == binding.endpoint_object
        || binding.interface_generation != binding.class.interface_generation()
        || binding.provider_generation == 0
        || binding.system_generation == 0
        || binding.binding_generation == 0
    {
        return Err(StorageModuleError::InvalidBinding);
    }
    Ok(())
}

fn authorize_binding<const C: usize>(
    capabilities: &CapabilitySpace<C>,
    interface_capability: Capability,
    provider_capability: Capability,
    endpoint_capability: Capability,
    binding: StorageModuleBinding,
) -> Result<(), StorageModuleError> {
    for (capability, rights, expected) in [
        (
            interface_capability,
            Rights::INSPECT,
            binding.interface_object,
        ),
        (
            provider_capability,
            Rights::CONTROL,
            binding.provider_object,
        ),
        (endpoint_capability, Rights::SIGNAL, binding.endpoint_object),
    ] {
        let actual = capabilities
            .authorize_exact(capability, rights)
            .map_err(StorageModuleError::Capability)?;
        if actual != expected {
            return Err(StorageModuleError::WrongAuthorityObject);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_filesystem_v1::{
        decode_probe_response, encode_probe_request, BorrowedReadView, FilesystemServiceEndpoint,
        FilesystemTransport, IsolatedFilesystemTransport, OpaqueHandle, ProtocolError,
        PROBE_REQUEST_BYTES, PROBE_RESPONSE_BYTES,
    };
    use mrml_storage_fat32::Fat32Provider;

    struct Backend {
        cleanup: bool,
        launch: bool,
        calls: [u8; 2],
    }
    impl StorageModuleBackend for Backend {
        fn revoke_cleanup_and_erase(&mut self, _: StorageModuleBinding) -> Result<(), ()> {
            self.calls[0] += 1;
            if self.cleanup { Ok(()) } else { Err(()) }
        }
        fn launch_and_healthcheck(&mut self, _: StorageModuleBinding) -> Result<(), ()> {
            self.calls[1] += 1;
            if self.launch { Ok(()) } else { Err(()) }
        }
    }

    fn binding(
        provider: u64,
        provider_generation: u64,
        system_generation: u64,
        binding_generation: u64,
    ) -> StorageModuleBinding {
        StorageModuleBinding {
            class: StorageModuleClass::BlockProvider,
            interface_object: ObjectId(10),
            provider_object: ObjectId(provider),
            endpoint_object: ObjectId(provider + 1),
            interface_generation: 1,
            provider_generation,
            system_generation,
            binding_generation,
        }
    }

    fn capabilities(binding: StorageModuleBinding) -> (CapabilitySpace<3>, [Capability; 3]) {
        let mut capabilities = CapabilitySpace::new();
        let handles = [
            capabilities
                .insert(binding.interface_object, Rights::INSPECT)
                .unwrap(),
            capabilities
                .insert(binding.provider_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(binding.endpoint_object, Rights::SIGNAL)
                .unwrap(),
        ];
        (capabilities, handles)
    }

    fn filesystem_binding(
        provider: u64,
        provider_generation: u64,
        system_generation: u64,
        binding_generation: u64,
    ) -> StorageModuleBinding {
        StorageModuleBinding {
            class: StorageModuleClass::Filesystem,
            interface_object: ObjectId(10),
            provider_object: ObjectId(provider),
            endpoint_object: ObjectId(provider + 1),
            interface_generation: STORAGE_FILESYSTEM_INTERFACE_GENERATION,
            provider_generation,
            system_generation,
            binding_generation,
        }
    }

    fn fat32_header() -> [u8; 512] {
        let mut sector = [0; 512];
        sector[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        sector[11..13].copy_from_slice(&512_u16.to_le_bytes());
        sector[13] = 8;
        sector[14..16].copy_from_slice(&32_u16.to_le_bytes());
        sector[16] = 2;
        sector[32..36].copy_from_slice(&1_048_576_u32.to_le_bytes());
        sector[36..40].copy_from_slice(&1024_u32.to_le_bytes());
        sector[44..48].copy_from_slice(&2_u32.to_le_bytes());
        sector[48..50].copy_from_slice(&1_u16.to_le_bytes());
        sector[50..52].copy_from_slice(&6_u16.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        sector
    }

    struct RestartBackend {
        current: Option<StorageModuleBinding>,
        erased: Option<StorageModuleBinding>,
        healthchecks: u8,
        kernel_epoch: u64,
    }

    impl RestartBackend {
        fn endpoint(binding: StorageModuleBinding) -> OpaqueHandle {
            OpaqueHandle::new(
                u32::try_from(binding.endpoint_object.0).unwrap(),
                u32::try_from(binding.provider_generation).unwrap(),
            )
            .unwrap()
        }
    }

    impl FilesystemServiceEndpoint for RestartBackend {
        fn invoke_probe(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; PROBE_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError> {
            let current = self.current.ok_or(ProtocolError::Transport)?;
            if endpoint != Self::endpoint(current) {
                return Err(ProtocolError::Transport);
            }
            Fat32Provider.probe(request, memory)
        }
    }

    impl FilesystemServiceEndpoint for &mut RestartBackend {
        fn invoke_probe(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; PROBE_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError> {
            (**self).invoke_probe(endpoint, request, memory)
        }
    }

    impl StorageModuleBackend for RestartBackend {
        fn revoke_cleanup_and_erase(&mut self, old: StorageModuleBinding) -> Result<(), ()> {
            if self.current != Some(old) {
                return Err(());
            }
            self.current = None;
            self.erased = Some(old);
            Ok(())
        }

        fn launch_and_healthcheck(&mut self, candidate: StorageModuleBinding) -> Result<(), ()> {
            if self.current.is_some() || self.erased.is_none() {
                return Err(());
            }
            self.current = Some(candidate);
            let request = encode_probe_request(
                OpaqueHandle::new(4, 1).unwrap(),
                BorrowedReadView::within(0, 512, 512).unwrap(),
            )
            .map_err(|_| ())?;
            let mut memory = fat32_header();
            let response = self
                .invoke_probe(Self::endpoint(candidate), &request, &mut memory)
                .map_err(|_| ())?;
            if decode_probe_response(&response) != Ok(Ok(100)) {
                self.current = None;
                return Err(());
            }
            self.healthchecks += 1;
            Ok(())
        }
    }

    #[test]
    fn replacement_cleans_old_before_launch_and_publishes_fresh_generation() {
        let old = binding(20, 3, 7, 1);
        let candidate = binding(30, 4, 8, 2);
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = StorageModuleRegistry::<2>::new();
        registry
            .bind_initial(
                &old_caps,
                old_handles[0],
                old_handles[1],
                old_handles[2],
                old,
            )
            .unwrap();
        let mut backend = Backend {
            cleanup: true,
            launch: true,
            calls: [0; 2],
        };
        assert_eq!(
            registry
                .replace(
                    &new_caps,
                    new_handles[0],
                    new_handles[1],
                    new_handles[2],
                    1,
                    candidate,
                    &mut backend
                )
                .unwrap(),
            candidate
        );
        assert_eq!(
            registry.state(StorageModuleClass::BlockProvider),
            Some(StorageModuleState::Active(candidate))
        );
        assert_eq!(backend.calls, [1, 1]);
    }

    #[test]
    fn compatible_fat32_generation_restarts_without_kernel_reboot() {
        let old = filesystem_binding(40, 3, 7, 1);
        let candidate = filesystem_binding(50, 4, 8, 2);
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = StorageModuleRegistry::<2>::new();
        registry
            .bind_initial(
                &old_caps,
                old_handles[0],
                old_handles[1],
                old_handles[2],
                old,
            )
            .unwrap();
        let mut backend = RestartBackend {
            current: Some(old),
            erased: None,
            healthchecks: 0,
            kernel_epoch: 99,
        };
        let request = encode_probe_request(
            OpaqueHandle::new(4, 1).unwrap(),
            BorrowedReadView::within(0, 512, 512).unwrap(),
        )
        .unwrap();
        let mut old_transport =
            IsolatedFilesystemTransport::new(RestartBackend::endpoint(old), 512, &mut backend)
                .unwrap();
        assert_eq!(
            decode_probe_response(&old_transport.probe(&request, &mut fat32_header()).unwrap()),
            Ok(Ok(100))
        );
        drop(old_transport);

        registry
            .replace(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                old.binding_generation,
                candidate,
                &mut backend,
            )
            .unwrap();
        assert_eq!(backend.erased, Some(old));
        assert_eq!(backend.healthchecks, 1);
        assert_eq!(backend.kernel_epoch, 99);
        assert_eq!(
            backend.invoke_probe(RestartBackend::endpoint(old), &request, &mut fat32_header()),
            Err(ProtocolError::Transport)
        );
        let mut new_transport = IsolatedFilesystemTransport::new(
            RestartBackend::endpoint(candidate),
            512,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            decode_probe_response(&new_transport.probe(&request, &mut fat32_header()).unwrap()),
            Ok(Ok(100))
        );
        assert_eq!(
            registry.state(StorageModuleClass::Filesystem),
            Some(StorageModuleState::Active(candidate))
        );
    }

    #[test]
    fn cleanup_uncertainty_quarantines_and_never_launches_candidate() {
        let old = binding(20, 3, 7, 1);
        let candidate = binding(30, 4, 8, 2);
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = StorageModuleRegistry::<1>::new();
        registry
            .bind_initial(
                &old_caps,
                old_handles[0],
                old_handles[1],
                old_handles[2],
                old,
            )
            .unwrap();
        let mut backend = Backend {
            cleanup: false,
            launch: true,
            calls: [0; 2],
        };
        assert_eq!(
            registry.replace(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                1,
                candidate,
                &mut backend
            ),
            Err(StorageModuleError::CleanupFailed)
        );
        assert_eq!(
            registry.state(StorageModuleClass::BlockProvider),
            Some(StorageModuleState::Quarantined(old))
        );
        assert_eq!(backend.calls, [1, 0]);
    }

    #[test]
    fn failed_launch_leaves_unavailable_until_explicit_retry() {
        let old = binding(20, 3, 7, 1);
        let candidate = binding(30, 4, 8, 2);
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = StorageModuleRegistry::<1>::new();
        registry
            .bind_initial(
                &old_caps,
                old_handles[0],
                old_handles[1],
                old_handles[2],
                old,
            )
            .unwrap();
        let mut backend = Backend {
            cleanup: true,
            launch: false,
            calls: [0; 2],
        };
        assert_eq!(
            registry.replace(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                1,
                candidate,
                &mut backend
            ),
            Err(StorageModuleError::LaunchFailed)
        );
        assert_eq!(
            registry.state(StorageModuleClass::BlockProvider),
            Some(StorageModuleState::Unavailable(candidate))
        );
        backend.launch = true;
        assert_eq!(
            registry.retry_unavailable(StorageModuleClass::BlockProvider, &mut backend),
            Ok(candidate)
        );
    }

    #[test]
    fn stale_generation_and_substituted_authority_fail_before_backend() {
        let old = binding(20, 3, 7, 1);
        let candidate = binding(30, 4, 8, 3);
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = StorageModuleRegistry::<1>::new();
        registry
            .bind_initial(
                &old_caps,
                old_handles[0],
                old_handles[1],
                old_handles[2],
                old,
            )
            .unwrap();
        let mut backend = Backend {
            cleanup: true,
            launch: true,
            calls: [0; 2],
        };
        assert_eq!(
            registry.replace(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                1,
                candidate,
                &mut backend
            ),
            Err(StorageModuleError::StaleReplacement)
        );
        assert!(matches!(
            registry.replace(
                &new_caps,
                new_handles[0],
                new_handles[0],
                new_handles[2],
                1,
                binding(30, 4, 8, 2),
                &mut backend
            ),
            Err(StorageModuleError::Capability(_))
        ));
        assert_eq!(backend.calls, [0, 0]);
    }
}
