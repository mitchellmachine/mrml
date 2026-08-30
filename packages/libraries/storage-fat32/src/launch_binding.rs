use crate::Fat32BlockBinding;
use mrml_interface_storage_block_provider_v1::{
    BlockProviderDependencyHandoff, BlockProviderDependencyHandoffError,
    OpaqueHandle as BlockOpaqueHandle,
};
use mrml_interface_storage_filesystem_v3::{
    INTERFACE_GENERATION as FILESYSTEM_INTERFACE_GENERATION, OpaqueHandle,
};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32LaunchBinding {
    block: Fat32BlockBinding,
    block_endpoint: ObjectId,
    block_endpoint_capability: Capability,
    association_generation: u64,
    system_generation: u64,
    filesystem_provider_generation: u64,
    block_provider_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32LaunchBindingError {
    Handoff(BlockProviderDependencyHandoffError),
    WrongFilesystemInterfaceGeneration,
    WrongFilesystemModule,
    WrongFilesystemProviderGeneration,
    Capability(CapabilityError),
    WrongBlockEndpoint,
    InvalidHandle,
    InvalidGeometry,
}

impl Fat32LaunchBinding {
    /// Consumes a kernel-projected dependency record and its separately
    /// attenuated block endpoint capability.
    ///
    /// # Safety
    ///
    /// The runtime must have projected `bytes` read-only from the exact launch
    /// data object authorized for this provider domain. It must also preserve
    /// the authoritative association between the encoded filesystem volume and
    /// block session. The record contains identity, not authority; only
    /// `block_endpoint_capability` authorizes signaling the dependency.
    pub unsafe fn from_projected_handoff<const C: usize>(
        capabilities: &CapabilitySpace<C>,
        block_endpoint_capability: Capability,
        filesystem_module: ObjectId,
        filesystem_provider_generation: u64,
        bytes: &[u8],
    ) -> Result<Self, Fat32LaunchBindingError> {
        let handoff = validate_handoff(bytes, filesystem_module, filesystem_provider_generation)?;
        let block_endpoint = capabilities
            .authorize_exact(block_endpoint_capability, Rights::SIGNAL)
            .map_err(Fat32LaunchBindingError::Capability)?;
        if block_endpoint.0 != handoff.block_endpoint_object() {
            return Err(Fat32LaunchBindingError::WrongBlockEndpoint);
        }
        let volume = OpaqueHandle::new(
            handoff.consumer_volume_index(),
            handoff.consumer_volume_generation(),
        )
        .ok_or(Fat32LaunchBindingError::InvalidHandle)?;
        let session = BlockOpaqueHandle::new(
            handoff.block_session_index(),
            handoff.block_session_generation(),
        )
        .ok_or(Fat32LaunchBindingError::InvalidHandle)?;
        let block =
            unsafe { Fat32BlockBinding::new(volume, session, handoff.logical_block_bytes()) }
                .ok_or(Fat32LaunchBindingError::InvalidGeometry)?;
        Ok(Self {
            block,
            block_endpoint,
            block_endpoint_capability,
            association_generation: handoff.association_generation(),
            system_generation: handoff.system_generation(),
            filesystem_provider_generation,
            block_provider_generation: handoff.block_provider_generation(),
        })
    }

    /// Consumes entry data after the kernel has projected the handoff and
    /// dependency capability into this exact service domain.
    ///
    /// # Safety
    ///
    /// The caller must be the installed entry path created from
    /// `NativeComponentServiceEntry`. `bytes` must have been copied through its
    /// exact read-only launch-data capability, and `block_endpoint_capability`
    /// must be its separately projected exact-`SIGNAL` dependency capability.
    pub unsafe fn from_installed_projection(
        bytes: &[u8],
        filesystem_module: ObjectId,
        filesystem_provider_generation: u64,
        block_endpoint_capability: Capability,
    ) -> Result<Self, Fat32LaunchBindingError> {
        let handoff = validate_handoff(bytes, filesystem_module, filesystem_provider_generation)?;
        let volume = OpaqueHandle::new(
            handoff.consumer_volume_index(),
            handoff.consumer_volume_generation(),
        )
        .ok_or(Fat32LaunchBindingError::InvalidHandle)?;
        let session = BlockOpaqueHandle::new(
            handoff.block_session_index(),
            handoff.block_session_generation(),
        )
        .ok_or(Fat32LaunchBindingError::InvalidHandle)?;
        let block =
            unsafe { Fat32BlockBinding::new(volume, session, handoff.logical_block_bytes()) }
                .ok_or(Fat32LaunchBindingError::InvalidGeometry)?;
        Ok(Self {
            block,
            block_endpoint: ObjectId(handoff.block_endpoint_object()),
            block_endpoint_capability,
            association_generation: handoff.association_generation(),
            system_generation: handoff.system_generation(),
            filesystem_provider_generation,
            block_provider_generation: handoff.block_provider_generation(),
        })
    }

    pub const fn block(self) -> Fat32BlockBinding {
        self.block
    }

    pub const fn block_endpoint(self) -> ObjectId {
        self.block_endpoint
    }

    pub const fn block_endpoint_capability(self) -> Capability {
        self.block_endpoint_capability
    }

    pub const fn association_generation(self) -> u64 {
        self.association_generation
    }

    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn filesystem_provider_generation(self) -> u64 {
        self.filesystem_provider_generation
    }

    pub const fn block_provider_generation(self) -> u64 {
        self.block_provider_generation
    }
}

fn validate_handoff(
    bytes: &[u8],
    filesystem_module: ObjectId,
    filesystem_provider_generation: u64,
) -> Result<BlockProviderDependencyHandoff, Fat32LaunchBindingError> {
    let handoff =
        BlockProviderDependencyHandoff::decode(bytes).map_err(Fat32LaunchBindingError::Handoff)?;
    if handoff.consumer_interface_generation() != FILESYSTEM_INTERFACE_GENERATION {
        return Err(Fat32LaunchBindingError::WrongFilesystemInterfaceGeneration);
    }
    if handoff.consumer_module_object() != filesystem_module.0 {
        return Err(Fat32LaunchBindingError::WrongFilesystemModule);
    }
    if handoff.consumer_provider_generation() != filesystem_provider_generation {
        return Err(Fat32LaunchBindingError::WrongFilesystemProviderGeneration);
    }
    Ok(handoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES;

    fn handoff() -> [u8; BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES] {
        BlockProviderDependencyHandoff::new(
            12,
            9,
            41,
            3,
            5,
            11,
            4,
            7,
            21,
            2,
            6,
            8,
            10,
            4096,
            42,
            FILESYSTEM_INTERFACE_GENERATION,
            10,
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn exact_projected_handoff_and_endpoint_create_launch_binding() {
        let mut capabilities = CapabilitySpace::<2>::new();
        let endpoint = capabilities.insert(ObjectId(21), Rights::SIGNAL).unwrap();
        let binding = unsafe {
            Fat32LaunchBinding::from_projected_handoff(
                &capabilities,
                endpoint,
                ObjectId(41),
                5,
                &handoff(),
            )
        }
        .unwrap();
        assert_eq!(binding.block().volume(), OpaqueHandle::new(2, 6).unwrap());
        assert_eq!(
            binding.block().session(),
            BlockOpaqueHandle::new(8, 10).unwrap()
        );
        assert_eq!(binding.block_endpoint(), ObjectId(21));
        assert_eq!(binding.block_endpoint_capability(), endpoint);
        assert_eq!(binding.association_generation(), 12);
        assert_eq!(binding.system_generation(), 9);
        assert_eq!(binding.filesystem_provider_generation(), 5);
        assert_eq!(binding.block_provider_generation(), 7);
    }

    #[test]
    fn installed_projection_retains_only_kernel_projected_dependency_capability() {
        let endpoint = Capability::from_token((9_u64 << 32) | 4);
        let binding = unsafe {
            Fat32LaunchBinding::from_installed_projection(&handoff(), ObjectId(41), 5, endpoint)
        }
        .unwrap();
        assert_eq!(binding.block_endpoint(), ObjectId(21));
        assert_eq!(binding.block_endpoint_capability(), endpoint);
        assert_eq!(binding.block().volume(), OpaqueHandle::new(2, 6).unwrap());
        assert_eq!(
            binding.block().session(),
            BlockOpaqueHandle::new(8, 10).unwrap()
        );
    }

    #[test]
    fn substituted_module_provider_or_endpoint_fail_before_binding() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities.insert(ObjectId(21), Rights::SIGNAL).unwrap();
        let substituted = capabilities.insert(ObjectId(22), Rights::SIGNAL).unwrap();
        let read_only = capabilities.insert(ObjectId(21), Rights::READ).unwrap();
        let bind = |capability, module, generation| unsafe {
            Fat32LaunchBinding::from_projected_handoff(
                &capabilities,
                capability,
                module,
                generation,
                &handoff(),
            )
        };
        assert_eq!(
            bind(endpoint, ObjectId(40), 5),
            Err(Fat32LaunchBindingError::WrongFilesystemModule)
        );
        assert_eq!(
            bind(endpoint, ObjectId(41), 6),
            Err(Fat32LaunchBindingError::WrongFilesystemProviderGeneration)
        );
        assert_eq!(
            bind(substituted, ObjectId(41), 5),
            Err(Fat32LaunchBindingError::WrongBlockEndpoint)
        );
        assert_eq!(
            bind(read_only, ObjectId(41), 5),
            Err(Fat32LaunchBindingError::Capability(
                CapabilityError::PermissionDenied
            ))
        );
        let mut wrong_interface = handoff();
        wrong_interface[112..116].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            unsafe {
                Fat32LaunchBinding::from_projected_handoff(
                    &capabilities,
                    endpoint,
                    ObjectId(41),
                    5,
                    &wrong_interface,
                )
            },
            Err(Fat32LaunchBindingError::WrongFilesystemInterfaceGeneration)
        );
    }
}
