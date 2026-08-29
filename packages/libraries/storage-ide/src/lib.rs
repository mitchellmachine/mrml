#![no_std]

//! Isolated legacy IDE block-provider mechanisms for MRML storage.
//!
//! Legacy compatibility is opt-in. PCI identity and fixed port numbers never
//! authorize I/O; the storage service retains authority and policy.

mod ide_discovery;
mod ide_dma;
mod ide_dma_command;
mod ide_identify;
mod ide_pio;
mod ide_ports;
mod ide_reset;

use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, encode_block_device_catalog, encode_enumerate_response,
    BlockProviderDevice, BlockProviderTransport, EnumerateError, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};

pub use ide_discovery::{
    IdeChannelDescriptor, IdeChannelMode, IdeControllerDescriptor, IdeDiscoveryError,
    IdePciFunctionSnapshot, PciFunctionLocation, IDE_PCI_CLASS, IDE_PCI_SUBCLASS,
};
pub use ide_dma::{
    prepare_ide_dma, revoke_ide_dma, IdeDmaBackend, IdeDmaDirection, IdeDmaError, IdeDmaFailure,
    IdeDmaLayout, IdeDmaMemoryIo, IdeDmaRegion, IdeDmaRequest, IdeDmaRevocationError,
    PreparedIdeDma, IDE_PRD_ENTRY_LIMIT, IDE_PRD_TABLE_BYTES,
};
pub use ide_dma_command::{
    execute_ide_dma, CompletedIdeDma, IdeDmaCommandError, IdeDmaCommandFailure, IdeDmaCommandIo,
    IdeDmaCommandRequest, IdeDmaOperation,
};
pub use ide_identify::{
    identify_ide_device, IdeDevice, IdeDeviceIdentity, IdeIdentifyError, IdeIdentifyFailure,
    IdePortIo,
};
pub use ide_pio::{
    execute_ide_pio, CompletedIdePio, IdePioBuffer, IdePioError, IdePioFailure, IdePioIo,
    IdePioOperation, IdePioRequest,
};
pub use ide_ports::{
    prepare_ide_channel_ports, revoke_ide_channel_ports, IdeChannel, IdeChannelPortGrant,
    IdePortGrantBackend, IdePortGrantError, IdePortGrantRequest, IdePortRange,
    IdePortRevocationError,
};
pub use ide_reset::{reset_ide_channel, IdeResetError, IdeResetFailure};

pub struct IdeBlockProvider<'a> {
    devices: &'a [BlockProviderDevice],
}

impl<'a> IdeBlockProvider<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self { devices }
    }
}

impl BlockProviderTransport for IdeBlockProvider<'_> {
    fn enumerate(
        &mut self,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_enumerate_request(request, memory.len() as u64)?;
        let result = encode_block_device_catalog(self.devices, request.output, memory)
            .map_err(|_| EnumerateError::InvalidRequest);
        Ok(encode_enumerate_response(result))
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        decode_enumerate_response, encode_enumerate_request, BorrowedWriteView, OpaqueHandle,
        BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };

    #[test]
    fn provider_enumerates_exact_device_and_media_generations() {
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(2, 5).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 131_072,
            media_generation: 11,
        }];
        let mut provider = IdeBlockProvider::new(&devices);
        let output = BorrowedWriteView::within(16, 48, 64).unwrap();
        let request = encode_enumerate_request(output).unwrap();
        let mut memory = [0xa5; 64];
        let response = provider.enumerate(&request, &mut memory).unwrap();
        assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(48)));
        assert_eq!(&memory[16..24], b"MRMLBLK\0");
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(memory[36..40].try_into().unwrap()), 5);
        assert_eq!(u64::from_le_bytes(memory[56..64].try_into().unwrap()), 11);
    }
}
