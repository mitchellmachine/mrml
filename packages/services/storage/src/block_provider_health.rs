use crate::storage_module::STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION;
use crate::{StorageModuleBackend, StorageModuleBinding, StorageModuleClass};
use mrml_interface_storage_block_provider_v1::{
    BlockProviderServiceEndpoint, BorrowedWriteView, MAX_DEVICE_CATALOG_BYTES, OpaqueHandle,
    ProtocolError, decode_enumerate_response, encode_enumerate_request,
    validate_block_device_catalog,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockProviderHealthReceipt {
    pub binding: StorageModuleBinding,
    pub device_count: u32,
    pub catalog_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockProviderHealthError {
    InvalidBinding,
    ScratchTooSmall,
    Protocol(ProtocolError),
    ProviderRejected,
}

pub trait BlockProviderModuleSupervisor {
    fn revoke_cleanup_and_erase(&mut self, binding: StorageModuleBinding) -> Result<(), ()>;
    fn launch(&mut self, candidate: StorageModuleBinding) -> Result<(), ()>;
}

pub struct ValidatedBlockProviderBackend<'a, S> {
    supervisor: &'a mut S,
    scratch: &'a mut [u8],
}

impl<'a, S> ValidatedBlockProviderBackend<'a, S> {
    pub fn new(supervisor: &'a mut S, scratch: &'a mut [u8]) -> Self {
        Self {
            supervisor,
            scratch,
        }
    }
}

impl<S: BlockProviderModuleSupervisor + BlockProviderServiceEndpoint> StorageModuleBackend
    for ValidatedBlockProviderBackend<'_, S>
{
    fn revoke_cleanup_and_erase(&mut self, old: StorageModuleBinding) -> Result<(), ()> {
        self.supervisor.revoke_cleanup_and_erase(old)
    }

    fn launch_and_healthcheck(&mut self, candidate: StorageModuleBinding) -> Result<(), ()> {
        self.supervisor.launch(candidate)?;
        if healthcheck_block_provider(candidate, self.supervisor, self.scratch).is_ok() {
            return Ok(());
        }
        let _ = self.supervisor.revoke_cleanup_and_erase(candidate);
        Err(())
    }
}

pub fn healthcheck_block_provider<E: BlockProviderServiceEndpoint>(
    binding: StorageModuleBinding,
    endpoint_service: &mut E,
    scratch: &mut [u8],
) -> Result<BlockProviderHealthReceipt, BlockProviderHealthError> {
    scratch.fill(0);
    let result = healthcheck_inner(binding, endpoint_service, scratch);
    scratch.fill(0);
    result
}

fn healthcheck_inner<E: BlockProviderServiceEndpoint>(
    binding: StorageModuleBinding,
    endpoint_service: &mut E,
    scratch: &mut [u8],
) -> Result<BlockProviderHealthReceipt, BlockProviderHealthError> {
    if binding.class != StorageModuleClass::BlockProvider
        || binding.interface_generation != STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION
    {
        return Err(BlockProviderHealthError::InvalidBinding);
    }
    let endpoint = OpaqueHandle::new(
        u32::try_from(binding.endpoint_object.0)
            .map_err(|_| BlockProviderHealthError::InvalidBinding)?,
        u32::try_from(binding.provider_generation)
            .map_err(|_| BlockProviderHealthError::InvalidBinding)?,
    )
    .ok_or(BlockProviderHealthError::InvalidBinding)?;
    if scratch.len() < 16 || scratch.len() > MAX_DEVICE_CATALOG_BYTES as usize {
        return Err(BlockProviderHealthError::ScratchTooSmall);
    }
    let output = BorrowedWriteView::within(0, scratch.len() as u64, scratch.len() as u64)
        .ok_or(BlockProviderHealthError::ScratchTooSmall)?;
    let request = encode_enumerate_request(output).map_err(BlockProviderHealthError::Protocol)?;
    let response = endpoint_service
        .invoke_enumerate(endpoint, &request, scratch)
        .map_err(BlockProviderHealthError::Protocol)?;
    let written = decode_enumerate_response(&response, scratch.len() as u64)
        .map_err(BlockProviderHealthError::Protocol)?
        .map_err(|_| BlockProviderHealthError::ProviderRejected)?;
    let written_usize = usize::try_from(written)
        .map_err(|_| BlockProviderHealthError::Protocol(ProtocolError::InvalidResponse))?;
    let device_count = validate_block_device_catalog(scratch.get(..written_usize).ok_or(
        BlockProviderHealthError::Protocol(ProtocolError::InvalidResponse),
    )?)
    .map_err(BlockProviderHealthError::Protocol)?;
    Ok(BlockProviderHealthReceipt {
        binding,
        device_count,
        catalog_bytes: written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_FLUSH, BlockProviderDevice, ENUMERATE_REQUEST_BYTES,
        ENUMERATE_RESPONSE_BYTES, OpaqueHandle, decode_enumerate_request,
        encode_block_device_catalog, encode_enumerate_response,
    };
    use mrml_kernel::{Capability, CapabilitySpace, ObjectId, Rights};

    struct Endpoint {
        expected: OpaqueHandle,
        malformed: bool,
        calls: usize,
    }

    impl BlockProviderServiceEndpoint for Endpoint {
        fn invoke_enumerate(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; ENUMERATE_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
            if endpoint != self.expected {
                return Err(ProtocolError::Transport);
            }
            self.calls += 1;
            let request = decode_enumerate_request(request, memory.len() as u64)?;
            let device = BlockProviderDevice {
                session: OpaqueHandle::new(9, 12).unwrap(),
                logical_block_bytes: 4096,
                flags: BLOCK_DEVICE_FLAG_FLUSH,
                logical_block_count: 1024,
                media_generation: 17,
            };
            let written = encode_block_device_catalog(&[device], request.output, memory)?;
            if self.malformed {
                memory[20..24].fill(0);
            }
            Ok(encode_enumerate_response(Ok(written)))
        }
    }

    struct Supervisor {
        current: Option<StorageModuleBinding>,
        malformed: bool,
        cleanups: usize,
        launches: usize,
    }

    impl BlockProviderModuleSupervisor for Supervisor {
        fn revoke_cleanup_and_erase(&mut self, binding: StorageModuleBinding) -> Result<(), ()> {
            if self.current != Some(binding) {
                return Err(());
            }
            self.current = None;
            self.cleanups += 1;
            Ok(())
        }

        fn launch(&mut self, candidate: StorageModuleBinding) -> Result<(), ()> {
            if self.current.is_some() {
                return Err(());
            }
            self.current = Some(candidate);
            self.launches += 1;
            Ok(())
        }
    }

    impl BlockProviderServiceEndpoint for Supervisor {
        fn invoke_enumerate(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; ENUMERATE_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
            let current = self.current.ok_or(ProtocolError::Transport)?;
            let expected = OpaqueHandle::new(
                u32::try_from(current.endpoint_object.0).map_err(|_| ProtocolError::Transport)?,
                u32::try_from(current.provider_generation).map_err(|_| ProtocolError::Transport)?,
            )
            .ok_or(ProtocolError::Transport)?;
            if endpoint != expected {
                return Err(ProtocolError::Transport);
            }
            let request = decode_enumerate_request(request, memory.len() as u64)?;
            let device = BlockProviderDevice {
                session: OpaqueHandle::new(9, 12).unwrap(),
                logical_block_bytes: 4096,
                flags: BLOCK_DEVICE_FLAG_FLUSH,
                logical_block_count: 1024,
                media_generation: 17,
            };
            let written = encode_block_device_catalog(&[device], request.output, memory)?;
            if self.malformed {
                memory[20..24].fill(0);
            }
            Ok(encode_enumerate_response(Ok(written)))
        }
    }

    fn binding() -> StorageModuleBinding {
        StorageModuleBinding {
            class: StorageModuleClass::BlockProvider,
            module_object: ObjectId(11),
            interface_object: ObjectId(10),
            provider_object: ObjectId(20),
            endpoint_object: ObjectId(21),
            interface_generation: STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION,
            provider_generation: 7,
            system_generation: 8,
            binding_generation: 2,
        }
    }

    fn old_binding() -> StorageModuleBinding {
        StorageModuleBinding {
            provider_object: ObjectId(30),
            endpoint_object: ObjectId(31),
            provider_generation: 6,
            system_generation: 7,
            binding_generation: 1,
            ..binding()
        }
    }

    fn capabilities(binding: StorageModuleBinding) -> (CapabilitySpace<4>, [Capability; 4]) {
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
        ];
        (capabilities, handles)
    }

    #[test]
    fn exact_candidate_catalog_is_validated_then_scratch_is_wiped() {
        let mut endpoint = Endpoint {
            expected: OpaqueHandle::new(21, 7).unwrap(),
            malformed: false,
            calls: 0,
        };
        let mut scratch = [0xa5; 64];
        let receipt = healthcheck_block_provider(binding(), &mut endpoint, &mut scratch).unwrap();
        assert_eq!((receipt.device_count, receipt.catalog_bytes), (1, 48));
        assert_eq!(receipt.binding, binding());
        assert_eq!(endpoint.calls, 1);
        assert_eq!(scratch, [0; 64]);
    }

    #[test]
    fn malformed_catalog_fails_healthcheck_and_wipes_scratch() {
        let mut endpoint = Endpoint {
            expected: OpaqueHandle::new(21, 7).unwrap(),
            malformed: true,
            calls: 0,
        };
        let mut scratch = [0xa5; 64];
        assert_eq!(
            healthcheck_block_provider(binding(), &mut endpoint, &mut scratch),
            Err(BlockProviderHealthError::Protocol(
                ProtocolError::InvalidResponse
            ))
        );
        assert_eq!(scratch, [0; 64]);
    }

    #[test]
    fn wrong_class_or_unrepresentable_generation_never_reaches_endpoint() {
        let mut endpoint = Endpoint {
            expected: OpaqueHandle::new(21, 7).unwrap(),
            malformed: false,
            calls: 0,
        };
        let mut wrong = binding();
        wrong.class = StorageModuleClass::Filesystem;
        assert_eq!(
            healthcheck_block_provider(wrong, &mut endpoint, &mut [0; 64]),
            Err(BlockProviderHealthError::InvalidBinding)
        );
        wrong = binding();
        wrong.provider_generation = u64::from(u32::MAX) + 1;
        assert_eq!(
            healthcheck_block_provider(wrong, &mut endpoint, &mut [0; 64]),
            Err(BlockProviderHealthError::InvalidBinding)
        );
        assert_eq!(endpoint.calls, 0);
    }

    #[test]
    fn registry_publishes_only_after_validated_launch() {
        let old = old_binding();
        let candidate = binding();
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = crate::StorageModuleRegistry::<1>::new();
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
        let mut supervisor = Supervisor {
            current: Some(old),
            malformed: false,
            cleanups: 0,
            launches: 0,
        };
        let mut scratch = [0xa5; 64];
        let mut backend = ValidatedBlockProviderBackend::new(&mut supervisor, &mut scratch);
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
        assert_eq!(
            registry.state(candidate.module_object),
            Some(crate::StorageModuleState::Active(candidate))
        );
        assert_eq!(
            (supervisor.current, supervisor.cleanups, supervisor.launches),
            (Some(candidate), 1, 1)
        );
        assert_eq!(scratch, [0; 64]);
    }

    #[test]
    fn failed_healthcheck_erases_candidate_and_leaves_slot_unavailable() {
        let old = old_binding();
        let candidate = binding();
        let (old_caps, old_handles) = capabilities(old);
        let (new_caps, new_handles) = capabilities(candidate);
        let mut registry = crate::StorageModuleRegistry::<1>::new();
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
        let mut supervisor = Supervisor {
            current: Some(old),
            malformed: true,
            cleanups: 0,
            launches: 0,
        };
        let mut scratch = [0xa5; 64];
        let mut backend = ValidatedBlockProviderBackend::new(&mut supervisor, &mut scratch);
        assert_eq!(
            registry.replace(
                &new_caps,
                new_handles[0],
                new_handles[1],
                new_handles[2],
                new_handles[3],
                old.binding_generation,
                candidate,
                &mut backend,
            ),
            Err(crate::StorageModuleError::LaunchFailed)
        );
        assert_eq!(
            registry.state(candidate.module_object),
            Some(crate::StorageModuleState::Unavailable(candidate))
        );
        assert_eq!(
            (supervisor.current, supervisor.cleanups, supervisor.launches),
            (None, 2, 1)
        );
        assert_eq!(scratch, [0; 64]);
    }
}
