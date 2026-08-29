//! Bounded parsing of hostile NVMe Identify Namespace data.

use crate::{NvmeControllerIdentity, NvmeControllerSnapshot, NVME_IDENTIFY_BYTES};

pub const NVME_MAX_LBA_FORMATS: u8 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeNamespaceIdentity {
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub namespace_id: u32,
    pub block_count: u64,
    pub capacity_blocks: u64,
    pub utilized_blocks: u64,
    pub logical_block_bytes: u32,
    pub maximum_transfer_blocks: u32,
    pub thin_provisioning: bool,
    pub relative_performance: u8,
    pub namespace_guid: [u8; 16],
    pub ieee_extended_unique_identifier: [u8; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeNamespaceParseError {
    ControllerGenerationMismatch,
    NamespaceId,
    EmptyNamespace,
    CapacityRange,
    FormatCount,
    ActiveFormat,
    MetadataUnsupported,
    LogicalBlockSize,
    NamespaceSizeOverflow,
    TransferLimit,
}

pub fn parse_nvme_namespace_identity(
    controller: NvmeControllerSnapshot,
    identity: &NvmeControllerIdentity,
    namespace_id: u32,
    data: &[u8; NVME_IDENTIFY_BYTES as usize],
) -> Result<NvmeNamespaceIdentity, NvmeNamespaceParseError> {
    if controller.configuration_generation != identity.configuration_generation
        || controller.mapping_generation != identity.mapping_generation
    {
        return Err(NvmeNamespaceParseError::ControllerGenerationMismatch);
    }
    if namespace_id == 0 || namespace_id > identity.namespace_count {
        return Err(NvmeNamespaceParseError::NamespaceId);
    }
    let block_count = read_u64(data, 0);
    let capacity_blocks = read_u64(data, 8);
    let utilized_blocks = read_u64(data, 16);
    if block_count == 0 {
        return Err(NvmeNamespaceParseError::EmptyNamespace);
    }
    if capacity_blocks == 0 || capacity_blocks > block_count || utilized_blocks > capacity_blocks {
        return Err(NvmeNamespaceParseError::CapacityRange);
    }

    let format_count = data[25]
        .checked_add(1)
        .ok_or(NvmeNamespaceParseError::FormatCount)?;
    if format_count == 0 || format_count > NVME_MAX_LBA_FORMATS {
        return Err(NvmeNamespaceParseError::FormatCount);
    }
    let formatted = data[26];
    if formatted & 0xe0 != 0 {
        return Err(NvmeNamespaceParseError::ActiveFormat);
    }
    let active_format = formatted & 0x0f;
    if active_format >= format_count {
        return Err(NvmeNamespaceParseError::ActiveFormat);
    }
    let format_offset = 128 + usize::from(active_format) * 4;
    let metadata_bytes = read_u16(data, format_offset);
    if metadata_bytes != 0 || formatted & (1 << 4) != 0 {
        return Err(NvmeNamespaceParseError::MetadataUnsupported);
    }
    let logical_block_shift = data[format_offset + 2];
    if !(9..=16).contains(&logical_block_shift) {
        return Err(NvmeNamespaceParseError::LogicalBlockSize);
    }
    let logical_block_bytes = 1_u32 << logical_block_shift;
    block_count
        .checked_mul(u64::from(logical_block_bytes))
        .ok_or(NvmeNamespaceParseError::NamespaceSizeOverflow)?;
    let maximum_transfer_blocks = identity.maximum_transfer_bytes / u64::from(logical_block_bytes);
    if maximum_transfer_blocks == 0 || maximum_transfer_blocks > u64::from(u32::MAX) {
        return Err(NvmeNamespaceParseError::TransferLimit);
    }

    let mut namespace_guid = [0; 16];
    namespace_guid.copy_from_slice(&data[104..120]);
    let mut ieee_extended_unique_identifier = [0; 8];
    ieee_extended_unique_identifier.copy_from_slice(&data[120..128]);
    Ok(NvmeNamespaceIdentity {
        configuration_generation: controller.configuration_generation,
        mapping_generation: controller.mapping_generation,
        namespace_id,
        block_count,
        capacity_blocks,
        utilized_blocks,
        logical_block_bytes,
        maximum_transfer_blocks: u32::try_from(maximum_transfer_blocks).unwrap(),
        thin_provisioning: data[24] & 1 != 0,
        relative_performance: data[format_offset + 3] & 0x3,
        namespace_guid,
        ieee_extended_unique_identifier,
    })
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_nvme_controller_identity;

    fn controller() -> NvmeControllerSnapshot {
        NvmeControllerSnapshot {
            configuration_generation: 11,
            mapping_generation: 9,
            version: 0x0002_0000,
            maximum_queue_entries: 64,
            contiguous_queues_required: true,
            timeout_500ms_units: 2,
            doorbell_stride_bytes: 4,
            minimum_page_bytes: 4096,
            maximum_page_bytes: 8192,
        }
    }

    fn controller_data() -> [u8; 4096] {
        let mut data = [0; 4096];
        data[0..2].copy_from_slice(&0x144d_u16.to_le_bytes());
        data[4..24].fill(b' ');
        data[4] = b'S';
        data[24..64].fill(b' ');
        data[24] = b'M';
        data[64..72].fill(b' ');
        data[64] = b'F';
        data[516..520].copy_from_slice(&4_u32.to_le_bytes());
        data
    }

    fn identity() -> NvmeControllerIdentity {
        parse_nvme_controller_identity(controller(), &controller_data()).unwrap()
    }

    fn namespace_data() -> [u8; 4096] {
        let mut data = [0; 4096];
        data[0..8].copy_from_slice(&1_000_000_u64.to_le_bytes());
        data[8..16].copy_from_slice(&900_000_u64.to_le_bytes());
        data[16..24].copy_from_slice(&400_000_u64.to_le_bytes());
        data[24] = 1;
        data[25] = 1;
        data[26] = 1;
        data[104..120].copy_from_slice(&[0x55; 16]);
        data[120..128].copy_from_slice(&[0xaa; 8]);
        data[128 + 2] = 9;
        data[132 + 2] = 12;
        data[132 + 3] = 2;
        data
    }

    #[test]
    fn parses_active_format_capacity_and_generation_bound_identity() {
        let namespace =
            parse_nvme_namespace_identity(controller(), &identity(), 2, &namespace_data()).unwrap();
        assert_eq!(namespace.namespace_id, 2);
        assert_eq!(namespace.logical_block_bytes, 4096);
        assert_eq!(namespace.maximum_transfer_blocks, 256);
        assert_eq!(namespace.block_count, 1_000_000);
        assert!(namespace.thin_provisioning);
        assert_eq!(namespace.relative_performance, 2);
        assert_eq!(namespace.namespace_guid, [0x55; 16]);
    }

    #[test]
    fn rejects_namespace_ids_generations_and_capacity_inconsistency() {
        for namespace_id in [0, 5] {
            assert_eq!(
                parse_nvme_namespace_identity(
                    controller(),
                    &identity(),
                    namespace_id,
                    &namespace_data()
                ),
                Err(NvmeNamespaceParseError::NamespaceId)
            );
        }
        let mut stale = controller();
        stale.mapping_generation += 1;
        assert_eq!(
            parse_nvme_namespace_identity(stale, &identity(), 1, &namespace_data()),
            Err(NvmeNamespaceParseError::ControllerGenerationMismatch)
        );
        let mut data = namespace_data();
        data[8..16].copy_from_slice(&1_000_001_u64.to_le_bytes());
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::CapacityRange)
        );
    }

    #[test]
    fn rejects_format_count_index_metadata_and_block_size() {
        let mut data = namespace_data();
        data[25] = NVME_MAX_LBA_FORMATS;
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::FormatCount)
        );
        data = namespace_data();
        data[26] = 2;
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::ActiveFormat)
        );
        data = namespace_data();
        data[132..134].copy_from_slice(&8_u16.to_le_bytes());
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::MetadataUnsupported)
        );
        data = namespace_data();
        data[132 + 2] = 8;
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::LogicalBlockSize)
        );
    }

    #[test]
    fn rejects_empty_and_overflowing_namespace_geometry() {
        let mut data = namespace_data();
        data[0..8].fill(0);
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::EmptyNamespace)
        );
        data = namespace_data();
        data[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        data[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            parse_nvme_namespace_identity(controller(), &identity(), 1, &data),
            Err(NvmeNamespaceParseError::NamespaceSizeOverflow)
        );
    }
}
