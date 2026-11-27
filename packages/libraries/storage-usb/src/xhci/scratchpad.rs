//! CPU-only staging for xHCI scratchpads. This module never maps memory,
//! writes a register, publishes DCBAA slot zero, or authorizes activation.
use super::DmaAssignment;

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
        for (i, entry) in bytes[..usize::from(self.count) * POINTER_BYTES]
            .chunks_exact_mut(POINTER_BYTES)
            .enumerate()
        {
            let page = self.table + (i as u64 + 1) * PAGE;
            entry.copy_from_slice(&page.to_le_bytes());
        }
        Ok(())
    }
}
