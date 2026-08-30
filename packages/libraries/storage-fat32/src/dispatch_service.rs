use mrml_interface_storage_filesystem_v3::{MOUNT_RESPONSE_BYTES, READ_REQUEST_BYTES};
use mrml_kernel::Capability;

pub const FAT32_DISPATCH_REQUEST_BYTES: usize = READ_REQUEST_BYTES;
pub const FAT32_DISPATCH_RESPONSE_BYTES: usize = MOUNT_RESPONSE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32DispatchEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Unified runtime boundary for the isolated FAT32 service entry.
///
/// # Safety
///
/// Receive and reply must remain bound to the authenticated launch caller.
/// Shared access must resolve only the exact transferred capability, and
/// release must enter transitive revocation for that received leaf.
pub unsafe trait Fat32DispatchSyscalls {
    type Error;

    fn receive_dispatch(
        &mut self,
        request: &mut [u8; FAT32_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32DispatchEnvelope, Self::Error>;

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;

    fn send_dispatch_response(&mut self, response: &[u8]) -> Result<(), Self::Error>;
}
