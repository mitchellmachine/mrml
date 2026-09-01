//! Exact-generation runtime bindings for isolated storage module providers.

use mrml_interface_storage_block_provider_v1::{
    BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES, BlockProviderDependencyHandoff,
    BlockProviderDependencyHandoffError, OpaqueHandle as BlockOpaqueHandle,
};
use mrml_interface_storage_filesystem_v3::OpaqueHandle as FilesystemOpaqueHandle;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION: u32 = 1;
pub const STORAGE_FILESYSTEM_INTERFACE_GENERATION: u32 = 3;
pub const FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES: usize =
    BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemBlockAssociation {
    pub filesystem_binding: StorageModuleBinding,
    pub block_binding: StorageModuleBinding,
    pub volume: FilesystemOpaqueHandle,
    pub block_session: BlockOpaqueHandle,
    pub logical_block_bytes: u32,
    pub association_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemBlockAssociationHandoff {
    dependency: BlockProviderDependencyHandoff,
    volume: FilesystemOpaqueHandle,
    block_session: BlockOpaqueHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemBlockAssociationHandoffError {
    Format,
    Reserved,
    InvalidIdentity,
    InvalidGeneration,
    InvalidGeometry,
    WrongInterfaceGeneration,
}

impl FilesystemBlockAssociation {
    pub fn handoff(self) -> FilesystemBlockAssociationHandoff {
        let dependency = BlockProviderDependencyHandoff::new(
            self.association_generation,
            self.filesystem_binding.system_generation,
            self.filesystem_binding.module_object.0,
            self.filesystem_binding.binding_generation,
            self.filesystem_binding.provider_generation,
            self.block_binding.module_object.0,
            self.block_binding.binding_generation,
            self.block_binding.provider_generation,
            self.block_binding.endpoint_object.0,
            self.volume.index(),
            self.volume.generation(),
            self.block_session.index(),
            self.block_session.generation(),
            self.logical_block_bytes,
            self.filesystem_binding.interface_object.0,
            self.filesystem_binding.interface_generation,
            self.block_binding.interface_object.0,
        )
        .expect("validated filesystem/block association must produce a valid handoff");
        FilesystemBlockAssociationHandoff {
            dependency,
            volume: self.volume,
            block_session: self.block_session,
        }
    }
}

impl FilesystemBlockAssociationHandoff {
    pub fn encode(self) -> [u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES] {
        self.dependency.encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FilesystemBlockAssociationHandoffError> {
        let dependency =
            BlockProviderDependencyHandoff::decode(bytes).map_err(map_handoff_error)?;
        if dependency.consumer_interface_generation() != STORAGE_FILESYSTEM_INTERFACE_GENERATION {
            return Err(FilesystemBlockAssociationHandoffError::WrongInterfaceGeneration);
        }
        let volume = FilesystemOpaqueHandle::new(
            dependency.consumer_volume_index(),
            dependency.consumer_volume_generation(),
        )
        .ok_or(FilesystemBlockAssociationHandoffError::InvalidIdentity)?;
        let block_session = BlockOpaqueHandle::new(
            dependency.block_session_index(),
            dependency.block_session_generation(),
        )
        .ok_or(FilesystemBlockAssociationHandoffError::InvalidIdentity)?;
        Ok(Self {
            dependency,
            volume,
            block_session,
        })
    }

    pub const fn association_generation(self) -> u64 {
        self.dependency.association_generation()
    }
    pub const fn system_generation(self) -> u64 {
        self.dependency.system_generation()
    }
    pub const fn filesystem_provider_generation(self) -> u64 {
        self.dependency.consumer_provider_generation()
    }
    pub const fn block_provider_generation(self) -> u64 {
        self.dependency.block_provider_generation()
    }
    pub const fn block_endpoint_object(self) -> u64 {
        self.dependency.block_endpoint_object()
    }
    pub const fn volume(self) -> FilesystemOpaqueHandle {
        self.volume
    }
    pub const fn block_session(self) -> BlockOpaqueHandle {
        self.block_session
    }
    pub const fn logical_block_bytes(self) -> u32 {
        self.dependency.logical_block_bytes()
    }
}

const fn map_handoff_error(
    error: BlockProviderDependencyHandoffError,
) -> FilesystemBlockAssociationHandoffError {
    match error {
        BlockProviderDependencyHandoffError::Format => {
            FilesystemBlockAssociationHandoffError::Format
        }
        BlockProviderDependencyHandoffError::Reserved => {
            FilesystemBlockAssociationHandoffError::Reserved
        }
        BlockProviderDependencyHandoffError::InvalidIdentity => {
            FilesystemBlockAssociationHandoffError::InvalidIdentity
        }
        BlockProviderDependencyHandoffError::InvalidGeneration => {
            FilesystemBlockAssociationHandoffError::InvalidGeneration
        }
        BlockProviderDependencyHandoffError::InvalidGeometry => {
            FilesystemBlockAssociationHandoffError::InvalidGeometry
        }
        BlockProviderDependencyHandoffError::WrongBlockInterfaceGeneration => {
            FilesystemBlockAssociationHandoffError::WrongInterfaceGeneration
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemBlockAssociationError {
    Capability(CapabilityError),
    WrongAuthorityObject,
    Missing,
    NotActive,
    StaleBinding,
    WrongClass,
    IncoherentSystemGeneration,
    InvalidGeometry,
    InvalidGeneration,
}

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
    /// Stable identity of this independently replaceable provider slot.
    pub module_object: ObjectId,
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
    StaleRetry,
    ObjectCollision,
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

    fn state(&self, module_object: ObjectId) -> Option<StorageModuleState> {
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|state| state.module_object() == module_object)
    }

    #[cfg(test)]
    fn states_for_class(
        &self,
        class: StorageModuleClass,
    ) -> impl Iterator<Item = StorageModuleState> + '_ {
        self.slots
            .iter()
            .flatten()
            .copied()
            .filter(move |state| state.class() == class)
    }

    pub fn inspect<const C: usize>(
        &self,
        capabilities: &CapabilitySpace<C>,
        module_capability: Capability,
        module_object: ObjectId,
    ) -> Result<Option<StorageModuleState>, StorageModuleError> {
        let actual = capabilities
            .authorize_exact(module_capability, Rights::INSPECT)
            .map_err(StorageModuleError::Capability)?;
        if actual != module_object {
            return Err(StorageModuleError::WrongAuthorityObject);
        }
        Ok(self.state(module_object))
    }

    /// Binds one filesystem volume identity to the exact live block-provider
    /// session proven by the storage runtime.
    ///
    /// # Safety
    ///
    /// The caller must have authenticated that `block_session` is the exact
    /// backing storage for `volume`. Numeric equality, catalog position, names,
    /// paths, labels, and media metadata are insufficient evidence.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bind_filesystem_block_association<const C: usize>(
        &self,
        capabilities: &CapabilitySpace<C>,
        filesystem_module_capability: Capability,
        block_module_capability: Capability,
        filesystem_module: ObjectId,
        filesystem_binding_generation: u64,
        block_module: ObjectId,
        block_binding_generation: u64,
        volume: FilesystemOpaqueHandle,
        block_session: BlockOpaqueHandle,
        logical_block_bytes: u32,
        association_generation: u64,
    ) -> Result<FilesystemBlockAssociation, FilesystemBlockAssociationError> {
        for (capability, expected) in [
            (filesystem_module_capability, filesystem_module),
            (block_module_capability, block_module),
        ] {
            let actual = capabilities
                .authorize_exact(capability, Rights::CONTROL)
                .map_err(FilesystemBlockAssociationError::Capability)?;
            if actual != expected {
                return Err(FilesystemBlockAssociationError::WrongAuthorityObject);
            }
        }
        let filesystem_binding = match self.state(filesystem_module) {
            Some(StorageModuleState::Active(binding)) => binding,
            Some(_) => return Err(FilesystemBlockAssociationError::NotActive),
            None => return Err(FilesystemBlockAssociationError::Missing),
        };
        let block_binding = match self.state(block_module) {
            Some(StorageModuleState::Active(binding)) => binding,
            Some(_) => return Err(FilesystemBlockAssociationError::NotActive),
            None => return Err(FilesystemBlockAssociationError::Missing),
        };
        if filesystem_binding.binding_generation != filesystem_binding_generation
            || block_binding.binding_generation != block_binding_generation
        {
            return Err(FilesystemBlockAssociationError::StaleBinding);
        }
        if filesystem_binding.class != StorageModuleClass::Filesystem
            || block_binding.class != StorageModuleClass::BlockProvider
        {
            return Err(FilesystemBlockAssociationError::WrongClass);
        }
        if filesystem_binding.system_generation != block_binding.system_generation {
            return Err(FilesystemBlockAssociationError::IncoherentSystemGeneration);
        }
        if logical_block_bytes < 512
            || logical_block_bytes > 65_536
            || !logical_block_bytes.is_power_of_two()
        {
            return Err(FilesystemBlockAssociationError::InvalidGeometry);
        }
        if association_generation == 0 {
            return Err(FilesystemBlockAssociationError::InvalidGeneration);
        }
        Ok(FilesystemBlockAssociation {
            filesystem_binding,
            block_binding,
            volume,
            block_session,
            logical_block_bytes,
            association_generation,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bind_initial<const C: usize>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        module_capability: Capability,
        interface_capability: Capability,
        provider_capability: Capability,
        endpoint_capability: Capability,
        binding: StorageModuleBinding,
    ) -> Result<(), StorageModuleError> {
        authorize_binding(
            capabilities,
            module_capability,
            interface_capability,
            provider_capability,
            endpoint_capability,
            binding,
        )?;
        validate_binding(binding)?;
        if self.state(binding.module_object).is_some() {
            return Err(StorageModuleError::AlreadyBound);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|state| state.conflicts_with(binding))
        {
            return Err(StorageModuleError::ObjectCollision);
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
        module_capability: Capability,
        interface_capability: Capability,
        provider_capability: Capability,
        endpoint_capability: Capability,
        expected_current_binding_generation: u64,
        candidate: StorageModuleBinding,
        backend: &mut B,
    ) -> Result<StorageModuleBinding, StorageModuleError> {
        authorize_binding(
            capabilities,
            module_capability,
            interface_capability,
            provider_capability,
            endpoint_capability,
            candidate,
        )?;
        validate_binding(candidate)?;
        let index = self
            .index(candidate.module_object)
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
            || candidate.class != old.class
            || candidate.module_object != old.module_object
            || candidate.interface_object != old.interface_object
            || (candidate.provider_object == old.provider_object
                && candidate.provider_generation == old.provider_generation)
        {
            return Err(StorageModuleError::StaleReplacement);
        }
        if self.slots.iter().flatten().any(|state| {
            state.module_object() != candidate.module_object && state.conflicts_with(candidate)
        }) {
            return Err(StorageModuleError::ObjectCollision);
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

    #[allow(clippy::too_many_arguments)]
    pub fn retry_unavailable<const C: usize, B: StorageModuleBackend>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        module_capability: Capability,
        interface_capability: Capability,
        provider_capability: Capability,
        endpoint_capability: Capability,
        candidate: StorageModuleBinding,
        backend: &mut B,
    ) -> Result<StorageModuleBinding, StorageModuleError> {
        authorize_binding(
            capabilities,
            module_capability,
            interface_capability,
            provider_capability,
            endpoint_capability,
            candidate,
        )?;
        validate_binding(candidate)?;
        let index = self
            .index(candidate.module_object)
            .ok_or(StorageModuleError::Missing)?;
        match self.slots[index] {
            Some(StorageModuleState::Unavailable(expected)) if expected == candidate => {}
            Some(StorageModuleState::Unavailable(_)) => {
                return Err(StorageModuleError::StaleRetry);
            }
            _ => return Err(StorageModuleError::NotActive),
        }
        if backend.launch_and_healthcheck(candidate).is_err() {
            return Err(StorageModuleError::LaunchFailed);
        }
        self.slots[index] = Some(StorageModuleState::Active(candidate));
        Ok(candidate)
    }

    fn index(&self, module_object: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.is_some_and(|state| state.module_object() == module_object))
    }
}

impl<const N: usize> Default for StorageModuleRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageModuleState {
    const fn module_object(self) -> ObjectId {
        match self {
            Self::Active(binding) | Self::Quarantined(binding) | Self::Unavailable(binding) => {
                binding.module_object
            }
            Self::Replacing { old, .. } => old.module_object,
        }
    }

    fn conflicts_with(self, candidate: StorageModuleBinding) -> bool {
        match self {
            Self::Active(binding) | Self::Quarantined(binding) | Self::Unavailable(binding) => {
                bindings_conflict(binding, candidate)
            }
            Self::Replacing {
                old,
                candidate: next,
            } => bindings_conflict(old, candidate) || bindings_conflict(next, candidate),
        }
    }

    #[cfg(test)]
    const fn class(self) -> StorageModuleClass {
        match self {
            Self::Active(binding) | Self::Quarantined(binding) | Self::Unavailable(binding) => {
                binding.class
            }
            Self::Replacing { old, .. } => old.class,
        }
    }
}

fn bindings_conflict(left: StorageModuleBinding, right: StorageModuleBinding) -> bool {
    let left_objects = [
        left.module_object,
        left.interface_object,
        left.provider_object,
        left.endpoint_object,
    ];
    let right_objects = [
        right.module_object,
        right.interface_object,
        right.provider_object,
        right.endpoint_object,
    ];
    left_objects.iter().enumerate().any(|(left_kind, left)| {
        right_objects
            .iter()
            .enumerate()
            .any(|(right_kind, right)| left == right && !(left_kind == 1 && right_kind == 1))
    })
}

fn validate_binding(binding: StorageModuleBinding) -> Result<(), StorageModuleError> {
    if binding.module_object.0 == 0
        || binding.interface_object.0 == 0
        || binding.provider_object.0 == 0
        || binding.endpoint_object.0 == 0
        || binding.module_object == binding.interface_object
        || binding.module_object == binding.provider_object
        || binding.module_object == binding.endpoint_object
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
    module_capability: Capability,
    interface_capability: Capability,
    provider_capability: Capability,
    endpoint_capability: Capability,
    binding: StorageModuleBinding,
) -> Result<(), StorageModuleError> {
    for (capability, rights, expected) in [
        (module_capability, Rights::CONTROL, binding.module_object),
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
    use mrml_interface_storage_filesystem_v3::{
        BorrowedReadView, FilesystemServiceEndpoint, FilesystemTransport,
        IsolatedFilesystemTransport, OpaqueHandle, PROBE_REQUEST_BYTES, PROBE_RESPONSE_BYTES,
        ProtocolError, decode_probe_response, encode_probe_request,
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
        binding_in(
            11,
            provider,
            provider_generation,
            system_generation,
            binding_generation,
        )
    }

    fn binding_in(
        module: u64,
        provider: u64,
        provider_generation: u64,
        system_generation: u64,
        binding_generation: u64,
    ) -> StorageModuleBinding {
        StorageModuleBinding {
            class: StorageModuleClass::BlockProvider,
            module_object: ObjectId(module),
            interface_object: ObjectId(10),
            provider_object: ObjectId(provider),
            endpoint_object: ObjectId(provider + 1),
            interface_generation: 1,
            provider_generation,
            system_generation,
            binding_generation,
        }
    }

    #[test]
    fn multiple_block_provider_slots_coexist_and_replace_independently() {
        let ahci = binding_in(11, 20, 3, 7, 1);
        let nvme = binding_in(12, 30, 5, 7, 1);
        let ide = binding_in(13, 50, 2, 7, 1);
        let nvme_next = binding_in(12, 40, 6, 8, 2);
        let (ahci_caps, ahci_handles) = capabilities(ahci);
        let (nvme_caps, nvme_handles) = capabilities(nvme);
        let (next_caps, next_handles) = capabilities(nvme_next);
        let (ide_caps, ide_handles) = capabilities(ide);
        let mut registry = StorageModuleRegistry::<4>::new();
        registry
            .bind_initial(
                &ahci_caps,
                ahci_handles[0],
                ahci_handles[1],
                ahci_handles[2],
                ahci_handles[3],
                ahci,
            )
            .unwrap();
        registry
            .bind_initial(
                &ide_caps,
                ide_handles[0],
                ide_handles[1],
                ide_handles[2],
                ide_handles[3],
                ide,
            )
            .unwrap();
        registry
            .bind_initial(
                &nvme_caps,
                nvme_handles[0],
                nvme_handles[1],
                nvme_handles[2],
                nvme_handles[3],
                nvme,
            )
            .unwrap();
        let colliding_slot = binding_in(14, ahci.endpoint_object.0, 1, 7, 1);
        let (collision_caps, collision_handles) = capabilities(colliding_slot);
        assert_eq!(
            registry.bind_initial(
                &collision_caps,
                collision_handles[0],
                collision_handles[1],
                collision_handles[2],
                collision_handles[3],
                colliding_slot,
            ),
            Err(StorageModuleError::ObjectCollision)
        );
        assert_eq!(
            registry
                .states_for_class(StorageModuleClass::BlockProvider)
                .count(),
            3
        );

        let mut backend = Backend {
            cleanup: true,
            launch: true,
            calls: [0; 2],
        };
        let colliding_replacement = binding_in(12, ahci.endpoint_object.0, 6, 8, 2);
        let (collision_caps, collision_handles) = capabilities(colliding_replacement);
        assert_eq!(
            registry.replace(
                &collision_caps,
                collision_handles[0],
                collision_handles[1],
                collision_handles[2],
                collision_handles[3],
                nvme.binding_generation,
                colliding_replacement,
                &mut backend,
            ),
            Err(StorageModuleError::ObjectCollision)
        );
        assert_eq!(backend.calls, [0, 0]);
        registry
            .replace(
                &next_caps,
                next_handles[0],
                next_handles[1],
                next_handles[2],
                next_handles[3],
                nvme.binding_generation,
                nvme_next,
                &mut backend,
            )
            .unwrap();
        assert_eq!(
            registry.state(ahci.module_object),
            Some(StorageModuleState::Active(ahci))
        );
        assert_eq!(
            registry.state(nvme.module_object),
            Some(StorageModuleState::Active(nvme_next))
        );
        assert_eq!(
            registry.state(ide.module_object),
            Some(StorageModuleState::Active(ide))
        );
        assert_eq!(backend.calls, [1, 1]);
    }

    fn capabilities(binding: StorageModuleBinding) -> (CapabilitySpace<5>, [Capability; 5]) {
        let mut capabilities = CapabilitySpace::new();
        let handles = [
            capabilities
                .insert(binding.module_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(binding.interface_object, Rights::INSPECT)
                .unwrap(),
            capabilities
                .insert(binding.provider_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(binding.endpoint_object, Rights::SIGNAL)
                .unwrap(),
            capabilities
                .insert(binding.module_object, Rights::INSPECT)
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
            module_object: ObjectId(12),
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
                old_handles[3],
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
                    new_handles[3],
                    1,
                    candidate,
                    &mut backend
                )
                .unwrap(),
            candidate
        );
        assert_eq!(
            registry.state(old.module_object),
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
                old_handles[3],
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
                new_handles[3],
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
            registry.state(old.module_object),
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
                old_handles[3],
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
                new_handles[3],
                1,
                candidate,
                &mut backend
            ),
            Err(StorageModuleError::CleanupFailed)
        );
        assert_eq!(
            registry.state(old.module_object),
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
                old_handles[3],
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
                new_handles[3],
                1,
                candidate,
                &mut backend
            ),
            Err(StorageModuleError::LaunchFailed)
        );
        assert_eq!(
            registry.state(old.module_object),
            Some(StorageModuleState::Unavailable(candidate))
        );
        backend.launch = true;
        assert!(matches!(
            registry.retry_unavailable(
                &new_caps,
                new_handles[1],
                new_handles[1],
                new_handles[2],
                new_handles[3],
                candidate,
                &mut backend,
            ),
            Err(StorageModuleError::Capability(_))
        ));
        let stale = StorageModuleBinding {
            binding_generation: candidate.binding_generation + 1,
            ..candidate
        };
        assert_eq!(
            registry.retry_unavailable(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                new_handles[3],
                stale,
                &mut backend,
            ),
            Err(StorageModuleError::StaleRetry)
        );
        assert_eq!(backend.calls, [1, 1]);
        assert_eq!(
            registry.retry_unavailable(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                new_handles[3],
                candidate,
                &mut backend,
            ),
            Ok(candidate)
        );
        assert_eq!(backend.calls, [1, 2]);
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
                old_handles[3],
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
                new_handles[3],
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
                new_handles[3],
                1,
                binding(30, 4, 8, 2),
                &mut backend
            ),
            Err(StorageModuleError::Capability(_))
        ));
        assert_eq!(backend.calls, [0, 0]);
    }

    fn association_filesystem_binding(system_generation: u64) -> StorageModuleBinding {
        StorageModuleBinding {
            class: StorageModuleClass::Filesystem,
            module_object: ObjectId(41),
            interface_object: ObjectId(42),
            provider_object: ObjectId(43),
            endpoint_object: ObjectId(44),
            interface_generation: STORAGE_FILESYSTEM_INTERFACE_GENERATION,
            provider_generation: 5,
            system_generation,
            binding_generation: 3,
        }
    }

    fn association_fixture(
        block_system_generation: u64,
    ) -> (
        StorageModuleRegistry<2>,
        CapabilitySpace<8>,
        [Capability; 8],
    ) {
        let filesystem = association_filesystem_binding(9);
        let block = binding_in(11, 20, 7, block_system_generation, 4);
        let mut capabilities = CapabilitySpace::new();
        let handles = [
            capabilities
                .insert(filesystem.module_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(filesystem.interface_object, Rights::INSPECT)
                .unwrap(),
            capabilities
                .insert(filesystem.provider_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(filesystem.endpoint_object, Rights::SIGNAL)
                .unwrap(),
            capabilities
                .insert(block.module_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(block.interface_object, Rights::INSPECT)
                .unwrap(),
            capabilities
                .insert(block.provider_object, Rights::CONTROL)
                .unwrap(),
            capabilities
                .insert(block.endpoint_object, Rights::SIGNAL)
                .unwrap(),
        ];
        let mut registry = StorageModuleRegistry::new();
        registry
            .bind_initial(
                &capabilities,
                handles[0],
                handles[1],
                handles[2],
                handles[3],
                filesystem,
            )
            .unwrap();
        registry
            .bind_initial(
                &capabilities,
                handles[4],
                handles[5],
                handles[6],
                handles[7],
                block,
            )
            .unwrap();
        (registry, capabilities, handles)
    }

    #[test]
    fn exact_active_modules_create_one_generation_bound_filesystem_block_association() {
        let (registry, capabilities, handles) = association_fixture(9);
        let volume = FilesystemOpaqueHandle::new(2, 6).unwrap();
        let session = BlockOpaqueHandle::new(8, 10).unwrap();
        let association = unsafe {
            registry.bind_filesystem_block_association(
                &capabilities,
                handles[0],
                handles[4],
                ObjectId(41),
                3,
                ObjectId(11),
                4,
                volume,
                session,
                4096,
                12,
            )
        }
        .unwrap();
        assert_eq!(association.volume, volume);
        assert_eq!(association.block_session, session);
        assert_eq!(association.logical_block_bytes, 4096);
        assert_eq!(association.association_generation, 12);
        assert_eq!(association.filesystem_binding.interface_generation, 3);
        let handoff = association.handoff();
        let encoded = handoff.encode();
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&encoded),
            Ok(handoff)
        );
        assert_eq!(handoff.volume(), volume);
        assert_eq!(handoff.block_session(), session);
        assert_eq!(handoff.block_endpoint_object(), 21);
        assert_eq!(handoff.filesystem_provider_generation(), 5);
        assert_eq!(handoff.block_provider_generation(), 7);
        assert_eq!(handoff.system_generation(), 9);
    }

    #[test]
    fn stale_substituted_incoherent_or_invalid_associations_fail_closed() {
        let (registry, capabilities, handles) = association_fixture(8);
        let volume = FilesystemOpaqueHandle::new(2, 6).unwrap();
        let session = BlockOpaqueHandle::new(8, 10).unwrap();
        let bind = |filesystem_capability, filesystem_generation, logical_block_bytes| unsafe {
            registry.bind_filesystem_block_association(
                &capabilities,
                filesystem_capability,
                handles[4],
                ObjectId(41),
                filesystem_generation,
                ObjectId(11),
                4,
                volume,
                session,
                logical_block_bytes,
                12,
            )
        };
        assert_eq!(
            bind(handles[0], 2, 4096),
            Err(FilesystemBlockAssociationError::StaleBinding)
        );
        assert_eq!(
            bind(handles[4], 3, 4096),
            Err(FilesystemBlockAssociationError::WrongAuthorityObject)
        );
        assert_eq!(
            bind(handles[0], 3, 4096),
            Err(FilesystemBlockAssociationError::IncoherentSystemGeneration)
        );

        let (registry, capabilities, handles) = association_fixture(9);
        assert_eq!(
            unsafe {
                registry.bind_filesystem_block_association(
                    &capabilities,
                    handles[0],
                    handles[4],
                    ObjectId(41),
                    3,
                    ObjectId(11),
                    4,
                    volume,
                    session,
                    1000,
                    12,
                )
            },
            Err(FilesystemBlockAssociationError::InvalidGeometry)
        );
    }

    #[test]
    fn association_handoff_rejects_truncation_reserved_data_and_identity_substitution() {
        let (registry, capabilities, handles) = association_fixture(9);
        let association = unsafe {
            registry.bind_filesystem_block_association(
                &capabilities,
                handles[0],
                handles[4],
                ObjectId(41),
                3,
                ObjectId(11),
                4,
                FilesystemOpaqueHandle::new(2, 6).unwrap(),
                BlockOpaqueHandle::new(8, 10).unwrap(),
                4096,
                12,
            )
        }
        .unwrap();
        let bytes = association.handoff().encode();
        for length in [0, 8, FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES - 1] {
            assert_eq!(
                FilesystemBlockAssociationHandoff::decode(&bytes[..length]),
                Err(FilesystemBlockAssociationHandoffError::Format)
            );
        }
        let mut reserved = bytes;
        reserved[100] = 1;
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&reserved),
            Err(FilesystemBlockAssociationHandoffError::Reserved)
        );
        let mut zero_generation = bytes;
        zero_generation[64..72].fill(0);
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&zero_generation),
            Err(FilesystemBlockAssociationHandoffError::InvalidGeneration)
        );
        let mut same_module = bytes;
        let filesystem_module: [u8; 8] = same_module[24..32].try_into().unwrap();
        same_module[48..56].copy_from_slice(&filesystem_module);
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&same_module),
            Err(FilesystemBlockAssociationHandoffError::InvalidIdentity)
        );
        let mut wrong_interface = bytes;
        wrong_interface[112..116].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&wrong_interface),
            Err(FilesystemBlockAssociationHandoffError::WrongInterfaceGeneration)
        );
    }
}
