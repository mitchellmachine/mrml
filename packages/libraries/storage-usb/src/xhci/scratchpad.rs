//! CPU-only staging for xHCI scratchpads. This module never maps memory,
//! writes a register, publishes DCBAA slot zero, or authorizes activation.
use super::{DmaAssignment, Platform};

const PAGE: u64 = 4096;
const POINTER_BYTES: usize = 8;
const MAX_COUNT: u16 = (PAGE as usize / POINTER_BYTES) as u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScratchpadError {
    UnsupportedGeometry,
    InvalidAperture,
    AssignmentChanged,
    StagingLength,
}

/// A pointer-table page followed by one 4 KiB buffer per hardware entry.
/// The entire range is bound to one assignment identity and generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchpadPlan {
    assignment: DmaAssignment,
    table: u64,
    count: u16,
}

impl ScratchpadPlan {
    /// Reserve pages immediately after the complete, page-aligned prefix used
    /// by every other DMA object. No aperture or mapping is created here.
    pub fn plan(
        assignment: DmaAssignment,
        occupied_prefix_bytes: u64,
        count: u16,
        page_mask: u16,
        address64: bool,
    ) -> Result<Self, ScratchpadError> {
        if count == 0 || count > MAX_COUNT || page_mask & 1 == 0 {
            return Err(ScratchpadError::UnsupportedGeometry);
        }
        if !assignment.valid() || occupied_prefix_bytes == 0 || occupied_prefix_bytes % PAGE != 0 {
            return Err(ScratchpadError::InvalidAperture);
        }
        let bytes = (u64::from(count) + 1) * PAGE;
        let table = assignment
            .device_base
            .checked_add(occupied_prefix_bytes)
            .filter(|&base| assignment.contains(base, bytes))
            .filter(|&base| address64 || base + bytes <= 1u64 << 32)
            .ok_or(ScratchpadError::InvalidAperture)?;
        Ok(Self {
            assignment,
            table,
            count,
        })
    }

    pub fn table_device_address(self) -> u64 {
        self.table
    }

    pub fn staging_bytes(self) -> usize {
        (usize::from(self.count) + 1) * PAGE as usize
    }

    pub(super) fn admit(
        self,
        assignment: DmaAssignment,
        count: u16,
        page_mask: u32,
        address64: bool,
    ) -> Result<DmaAssignment, ScratchpadError> {
        if assignment != self.assignment {
            return Err(ScratchpadError::AssignmentChanged);
        }
        let mask = u16::try_from(page_mask).map_err(|_| ScratchpadError::UnsupportedGeometry)?;
        let prefix = self.table - assignment.device_base;
        if self != Self::plan(assignment, prefix, count, mask, address64)? {
            return Err(ScratchpadError::UnsupportedGeometry);
        }
        Ok(DmaAssignment {
            bytes: prefix,
            ..assignment
        })
    }

    /// Initialize only the already checked assignment while the device is
    /// stopped and bus mastering is still disabled. The caller publishes
    /// DCBAA slot zero only on success.
    pub(super) fn publish_pages<P: Platform>(self, platform: &mut P) -> Result<(), P::Error> {
        let mut chunk = [0; 256];
        // Zero all buffers before writing any pointer to them.
        for offset in (PAGE..self.staging_bytes() as u64).step_by(chunk.len()) {
            platform.dma_write(self.table + offset, &chunk)?;
        }
        for offset in (0..PAGE as usize).step_by(chunk.len()) {
            self.encode_table_chunk(offset, &mut chunk);
            platform.dma_write(self.table + offset as u64, &chunk)?;
        }
        Ok(())
    }

    fn encode_table_chunk(self, offset: usize, bytes: &mut [u8]) {
        for (index, entry) in bytes.chunks_exact_mut(POINTER_BYTES).enumerate() {
            let index = offset / POINTER_BYTES + index;
            let address = if index < usize::from(self.count) {
                self.table + (index as u64 + 1) * PAGE
            } else {
                0
            };
            entry.copy_from_slice(&address.to_le_bytes());
        }
    }

    /// Encode into an ordinary CPU staging buffer. The supervisor must later
    /// verify that installed backing matches this assignment before publishing.
    /// On error the supplied bytes remain unchanged.
    pub fn stage(self, assignment: DmaAssignment, bytes: &mut [u8]) -> Result<(), ScratchpadError> {
        if assignment != self.assignment {
            return Err(ScratchpadError::AssignmentChanged);
        }
        if bytes.len() != self.staging_bytes() {
            return Err(ScratchpadError::StagingLength);
        }
        bytes.fill(0);
        self.encode_table_chunk(0, &mut bytes[..PAGE as usize]);
        Ok(())
    }
}
