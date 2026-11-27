//! Bounded USB diagnostic partition endpoint. Normal USB enumeration stays
//! read-only. The supervisor must authorize the exclusive, exact media
//! assignment separately from the controller and DMA lease.

use super::block_provider::UsbReadProvider;
use crate::{BulkTransport, SECTOR_BYTES};
use mrml_interface_storage_block_provider_v1::{
    OpaqueHandle, ProtocolError, WRITE_REQUEST_BYTES, WRITE_RESPONSE_BYTES, WriteError,
    decode_write_request, encode_write_response,
};
use mrml_kernel::{Capability, CapabilitySpace, ObjectId, Rights};

/// Supervisor-selected binding, never sourced from queue bytes. The caller
/// must hold the exact controller/media lease throughout this borrow and use
/// the authenticated principal's own capability space for every request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticPartitionAssignment {
    pub disk_session: OpaqueHandle,
    pub partition_session: OpaqueHandle,
    pub media_generation: u64,
    pub partition: ObjectId,
    pub first_lba: u32,
    pub sectors: u32,
    pub file_sector: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticPartitionError {
    StaleSession,
    Denied,
    InvalidExtent,
    InvalidPartitionTable,
    IoFailure,
}

/// An exclusive temporary view of one provider. Reads use partition-relative
/// addresses; write dispatch accepts exactly one canonical sector write to the
/// assigned file sector. This is not a filesystem, IPC endpoint, or grant issuer.
pub struct DiagnosticPartition<'a, T: BulkTransport> {
    provider: &'a mut UsbReadProvider<T>,
    assignment: DiagnosticPartitionAssignment,
    capability: Capability,
}

impl<'a, T: BulkTransport> DiagnosticPartition<'a, T> {
    pub fn open<const C: usize>(
        provider: &'a mut UsbReadProvider<T>,
        assignment: DiagnosticPartitionAssignment,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, DiagnosticPartitionError> {
        use DiagnosticPartitionError::*;
        if !provider
            .diagnostic_session_is_live(assignment.disk_session, assignment.media_generation)
        {
            return Err(StaleSession);
        }
        if assignment.partition_session == assignment.disk_session {
            return Err(InvalidExtent);
        }
        let view = Self {
            provider,
            assignment,
            capability,
        };
        if !view.authorized(capabilities, Rights::READ.union(Rights::WRITE)) {
            return Err(Denied);
        }
        let capacity = view.provider.capacity();
        if assignment.first_lba == 0
            || assignment.file_sector == 0
            || assignment.file_sector >= assignment.sectors
            || u64::from(assignment.first_lba) + u64::from(assignment.sectors) > capacity
        {
            return Err(InvalidExtent);
        }
        let mut mbr = [0; SECTOR_BYTES];
        view.provider
            .diagnostic_read(0, &mut mbr)
            .map_err(|_| IoFailure)?;
        if !matches_mbr(&mbr, assignment.first_lba, assignment.sectors) {
            return Err(InvalidPartitionTable);
        }
        Ok(view)
    }

    /// Read for layout validation or file verification. Failure does not
    /// publish any partial sector and retires a faulted transport session.
    pub fn read<const C: usize>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        sector: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), DiagnosticPartitionError> {
        use DiagnosticPartitionError::*;
        if !self.provider.diagnostic_session_is_live(
            self.assignment.disk_session,
            self.assignment.media_generation,
        ) {
            return Err(StaleSession);
        }
        if !self.authorized(capabilities, Rights::READ) {
            return Err(Denied);
        }
        if sector >= self.assignment.sectors {
            return Err(InvalidExtent);
        }
        self.provider
            .diagnostic_read(self.absolute(sector), output)
            .map_err(|_| IoFailure)
    }

    /// The memory slice must be an independently authenticated read view.
    /// On an uncertain write the underlying transport is retired, not retried.
    pub fn write<const C: usize>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        wire: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_write_request(wire, memory.len() as u64)?;
        if request.session != self.assignment.partition_session
            || !self.provider.diagnostic_session_is_live(
                self.assignment.disk_session,
                self.assignment.media_generation,
            )
        {
            return Ok(encode_write_response(Err(WriteError::StaleObject)));
        }
        if !self.authorized(capabilities, Rights::WRITE) {
            return Ok(encode_write_response(Err(WriteError::PermissionDenied)));
        }
        if request.lba != u64::from(self.assignment.file_sector)
            || request.sector_count != 1
            || request.input.length() != SECTOR_BYTES as u64
        {
            return Ok(encode_write_response(Err(WriteError::InvalidRequest)));
        }
        let start =
            usize::try_from(request.input.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let input: &[u8; SECTOR_BYTES] = memory
            .get(
                start
                    ..start
                        .checked_add(SECTOR_BYTES)
                        .ok_or(ProtocolError::InvalidRequest)?,
            )
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ProtocolError::InvalidRequest)?;
        let result = self
            .provider
            .diagnostic_write(self.absolute(self.assignment.file_sector), input)
            .map(|()| SECTOR_BYTES as u64)
            .map_err(|_| WriteError::IoFailure);
        Ok(encode_write_response(result))
    }

    fn authorized<const C: usize>(
        &self,
        capabilities: &CapabilitySpace<C>,
        rights: Rights,
    ) -> bool {
        self.assignment.partition.0 != 0
            && capabilities.authorize(self.capability, rights) == Ok(self.assignment.partition)
    }

    fn absolute(&self, sector: u32) -> u64 {
        u64::from(self.assignment.first_lba) + u64::from(sector)
    }
}

fn matches_mbr(mbr: &[u8; SECTOR_BYTES], start: u32, sectors: u32) -> bool {
    mbr[510..] == [0x55, 0xaa]
        && mbr[446] == 0
        && mbr[450] == 0x0c
        && mbr[454..458] == start.to_le_bytes()
        && mbr[458..462] == sectors.to_le_bytes()
        && mbr[462..510].iter().all(|&byte| byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_single_matching_inactive_fat32_mbr_entry() {
        let mut mbr = [0; SECTOR_BYTES];
        mbr[510..].copy_from_slice(&[0x55, 0xaa]);
        mbr[450] = 0x0c;
        mbr[454..458].copy_from_slice(&32u32.to_le_bytes());
        mbr[458..462].copy_from_slice(&100u32.to_le_bytes());
        assert!(matches_mbr(&mbr, 32, 100));
        assert!(!matches_mbr(&mbr, 31, 100));
        assert!(!matches_mbr(&mbr, 32, 99));
        for offset in [446, 450, 462, 509, 510] {
            let mut changed = mbr;
            changed[offset] ^= 0x80;
            assert!(!matches_mbr(&changed, 32, 100));
        }
    }
}
