//! Bounded parsing of hostile NVMe Identify Controller data.

use crate::{NvmeControllerSnapshot, NVME_IDENTIFY_BYTES};

pub const NVME_NAMESPACE_LIMIT: u32 = 1024;
pub const NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerIdentity {
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    serial: [u8; 20],
    serial_len: u8,
    model: [u8; 40],
    model_len: u8,
    firmware_revision: [u8; 8],
    firmware_revision_len: u8,
    pub ieee_oui: [u8; 3],
    pub controller_id: u16,
    pub namespace_count: u32,
    pub maximum_transfer_bytes: u64,
    pub compare_supported: bool,
    pub write_zeroes_supported: bool,
    pub dataset_management_supported: bool,
    pub volatile_write_cache_present: bool,
}

impl NvmeControllerIdentity {
    pub fn serial(&self) -> &[u8] {
        &self.serial[..usize::from(self.serial_len)]
    }

    pub fn model(&self) -> &[u8] {
        &self.model[..usize::from(self.model_len)]
    }

    pub fn firmware_revision(&self) -> &[u8] {
        &self.firmware_revision[..usize::from(self.firmware_revision_len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeIdentifyError {
    InvalidControllerGeneration,
    InvalidVendor,
    InvalidSerial,
    InvalidModel,
    InvalidFirmwareRevision,
    NamespaceCount,
    TransferLimitOverflow,
}

pub fn parse_nvme_controller_identity(
    controller: NvmeControllerSnapshot,
    data: &[u8; NVME_IDENTIFY_BYTES as usize],
) -> Result<NvmeControllerIdentity, NvmeIdentifyError> {
    if controller.configuration_generation == 0
        || controller.mapping_generation == 0
        || controller.minimum_page_bytes == 0
        || !controller.minimum_page_bytes.is_power_of_two()
    {
        return Err(NvmeIdentifyError::InvalidControllerGeneration);
    }
    let vendor_id = read_u16(data, 0);
    let subsystem_vendor_id = read_u16(data, 2);
    if vendor_id == 0 || vendor_id == u16::MAX {
        return Err(NvmeIdentifyError::InvalidVendor);
    }
    let (serial, serial_len) = parse_label::<20>(data, 4, NvmeIdentifyError::InvalidSerial)?;
    let (model, model_len) = parse_label::<40>(data, 24, NvmeIdentifyError::InvalidModel)?;
    let (firmware_revision, firmware_revision_len) =
        parse_label::<8>(data, 64, NvmeIdentifyError::InvalidFirmwareRevision)?;
    let namespace_count = read_u32(data, 516);
    if namespace_count == 0 || namespace_count > NVME_NAMESPACE_LIMIT {
        return Err(NvmeIdentifyError::NamespaceCount);
    }
    let mdts = data[77];
    let maximum_transfer_bytes = if mdts == 0 {
        NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES
    } else {
        controller
            .minimum_page_bytes
            .checked_shl(u32::from(mdts))
            .ok_or(NvmeIdentifyError::TransferLimitOverflow)?
            .min(NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES)
    };
    let optional_nvm_commands = read_u16(data, 520);

    Ok(NvmeControllerIdentity {
        configuration_generation: controller.configuration_generation,
        mapping_generation: controller.mapping_generation,
        vendor_id,
        subsystem_vendor_id,
        serial,
        serial_len,
        model,
        model_len,
        firmware_revision,
        firmware_revision_len,
        ieee_oui: [data[73], data[74], data[75]],
        controller_id: read_u16(data, 78),
        namespace_count,
        maximum_transfer_bytes,
        compare_supported: optional_nvm_commands & 1 != 0,
        write_zeroes_supported: optional_nvm_commands & (1 << 3) != 0,
        dataset_management_supported: optional_nvm_commands & (1 << 2) != 0,
        volatile_write_cache_present: data[525] & 1 != 0,
    })
}

fn parse_label<const N: usize>(
    data: &[u8],
    offset: usize,
    error: NvmeIdentifyError,
) -> Result<([u8; N], u8), NvmeIdentifyError> {
    let mut output = [0; N];
    output.copy_from_slice(&data[offset..offset + N]);
    if output.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return Err(error);
    }
    let length = output
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|index| index + 1)
        .unwrap_or(0);
    if length == 0 {
        return Err(error);
    }
    Ok((output, u8::try_from(length).unwrap()))
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn identify() -> [u8; 4096] {
        let mut data = [0; 4096];
        data[0..2].copy_from_slice(&0x144d_u16.to_le_bytes());
        data[2..4].copy_from_slice(&0x144d_u16.to_le_bytes());
        data[4..24].fill(b' ');
        data[4..14].copy_from_slice(b"SERIAL1234");
        data[24..64].fill(b' ');
        data[24..34].copy_from_slice(b"MRML NVME ");
        data[64..72].fill(b' ');
        data[64..69].copy_from_slice(b"1.2.3");
        data[73..76].copy_from_slice(&[0x00, 0x25, 0x38]);
        data[77] = 5;
        data[78..80].copy_from_slice(&7_u16.to_le_bytes());
        data[516..520].copy_from_slice(&4_u32.to_le_bytes());
        data[520..522].copy_from_slice(&(1_u16 | (1 << 2) | (1 << 3)).to_le_bytes());
        data[525] = 1;
        data
    }

    #[test]
    fn parses_fixed_labels_generations_limits_and_feature_data() {
        let identity = parse_nvme_controller_identity(controller(), &identify()).unwrap();
        assert_eq!(identity.vendor_id, 0x144d);
        assert_eq!(identity.serial(), b"SERIAL1234");
        assert_eq!(identity.model(), b"MRML NVME");
        assert_eq!(identity.firmware_revision(), b"1.2.3");
        assert_eq!(identity.namespace_count, 4);
        assert_eq!(identity.maximum_transfer_bytes, 128 * 1024);
        assert!(identity.compare_supported);
        assert!(identity.write_zeroes_supported);
        assert!(identity.dataset_management_supported);
        assert!(identity.volatile_write_cache_present);
    }

    #[test]
    fn rejects_non_ascii_empty_or_control_character_labels() {
        for (offset, value, expected) in [
            (4, 0, NvmeIdentifyError::InvalidSerial),
            (24, 0x7f, NvmeIdentifyError::InvalidModel),
            (64, b'\n', NvmeIdentifyError::InvalidFirmwareRevision),
        ] {
            let mut data = identify();
            data[offset] = value;
            assert_eq!(
                parse_nvme_controller_identity(controller(), &data),
                Err(expected)
            );
        }
        let mut data = identify();
        data[4..24].fill(b' ');
        assert_eq!(
            parse_nvme_controller_identity(controller(), &data),
            Err(NvmeIdentifyError::InvalidSerial)
        );
    }

    #[test]
    fn rejects_absent_vendor_and_unbounded_namespace_counts() {
        let mut data = identify();
        data[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            parse_nvme_controller_identity(controller(), &data),
            Err(NvmeIdentifyError::InvalidVendor)
        );
        for count in [0, NVME_NAMESPACE_LIMIT + 1] {
            let mut data = identify();
            data[516..520].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                parse_nvme_controller_identity(controller(), &data),
                Err(NvmeIdentifyError::NamespaceCount)
            );
        }
    }

    #[test]
    fn rejects_transfer_overflow_and_caps_unlimited_or_large_values() {
        let mut data = identify();
        data[77] = u8::MAX;
        assert_eq!(
            parse_nvme_controller_identity(controller(), &data),
            Err(NvmeIdentifyError::TransferLimitOverflow)
        );
        data[77] = 0;
        assert_eq!(
            parse_nvme_controller_identity(controller(), &data)
                .unwrap()
                .maximum_transfer_bytes,
            NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES
        );
        data[77] = 20;
        assert_eq!(
            parse_nvme_controller_identity(controller(), &data)
                .unwrap()
                .maximum_transfer_bytes,
            NVME_BLOCK_INTERFACE_MAX_TRANSFER_BYTES
        );
    }
}
