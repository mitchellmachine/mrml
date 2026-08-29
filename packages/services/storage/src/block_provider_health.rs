use crate::storage_module::STORAGE_BLOCK_PROVIDER_INTERFACE_GENERATION;
use crate::{StorageModuleBinding, StorageModuleClass};
use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_response, encode_enumerate_request, validate_block_device_catalog,
    BlockProviderServiceEndpoint, BorrowedWriteView, OpaqueHandle, ProtocolError,
    MAX_DEVICE_CATALOG_BYTES,
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
        decode_enumerate_request, encode_block_device_catalog, encode_enumerate_response,
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, ENUMERATE_REQUEST_BYTES,
        ENUMERATE_RESPONSE_BYTES,
    };
    use mrml_kernel::ObjectId;

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
}
