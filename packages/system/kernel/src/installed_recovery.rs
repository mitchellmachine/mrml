pub const INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES: usize = 104;
pub const INSTALLED_RECOVERY_SATA_ROUTE_BYTES: usize = 128;
pub const MAX_INSTALLED_RECOVERY_PCI_HOPS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InstalledRecoveryPciHop {
    device: u8,
    function: u8,
}

impl InstalledRecoveryPciHop {
    pub const fn new(device: u8, function: u8) -> Option<Self> {
        if device > 31 || function > 7 {
            None
        } else {
            Some(Self { device, function })
        }
    }

    pub const fn device(self) -> u8 {
        self.device
    }

    pub const fn function(self) -> u8 {
        self.function
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledRecoveryHardDriveMedia {
    partition_number: u32,
    partition_start: u64,
    partition_size: u64,
    signature: [u8; 16],
    mbr_type: u8,
    signature_type: u8,
}

impl InstalledRecoveryHardDriveMedia {
    pub fn new(
        partition_number: u32,
        partition_start: u64,
        partition_size: u64,
        signature: [u8; 16],
        mbr_type: u8,
        signature_type: u8,
    ) -> Option<Self> {
        let media = Self {
            partition_number,
            partition_start,
            partition_size,
            signature,
            mbr_type,
            signature_type,
        };
        installed_media_valid(media).then_some(media)
    }

    pub const fn partition_number(self) -> u32 {
        self.partition_number
    }

    pub const fn partition_start(self) -> u64 {
        self.partition_start
    }

    pub const fn partition_size(self) -> u64 {
        self.partition_size
    }

    pub const fn signature(self) -> [u8; 16] {
        self.signature
    }

    pub const fn mbr_type(self) -> u8 {
        self.mbr_type
    }

    pub const fn signature_type(self) -> u8 {
        self.signature_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledRecoverySataRoute {
    root_hid: u32,
    root_uid: u32,
    pci_hops: [InstalledRecoveryPciHop; MAX_INSTALLED_RECOVERY_PCI_HOPS],
    pci_hop_count: u8,
    hba_port: u16,
    port_multiplier_port: u16,
    logical_unit: u16,
    media: Option<InstalledRecoveryHardDriveMedia>,
    stable_id: [u8; 32],
}

impl InstalledRecoverySataRoute {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_hid: u32,
        root_uid: u32,
        pci_hops: &[InstalledRecoveryPciHop],
        hba_port: u16,
        port_multiplier_port: u16,
        logical_unit: u16,
        media: Option<InstalledRecoveryHardDriveMedia>,
        stable_id: [u8; 32],
    ) -> Result<Self, InstalledRecoverySataRouteError> {
        if pci_hops.is_empty()
            || pci_hops.len() > MAX_INSTALLED_RECOVERY_PCI_HOPS
            || hba_port == u16::MAX
            || stable_id.iter().all(|byte| *byte == 0)
            || media.is_some_and(|value| !installed_media_valid(value))
        {
            return Err(InstalledRecoverySataRouteError::NonCanonical);
        }
        if pci_hops
            .iter()
            .any(|hop| hop.device > 31 || hop.function > 7)
        {
            return Err(InstalledRecoverySataRouteError::NonCanonical);
        }
        let mut stored_hops = [InstalledRecoveryPciHop::default(); MAX_INSTALLED_RECOVERY_PCI_HOPS];
        stored_hops[..pci_hops.len()].copy_from_slice(pci_hops);
        Ok(Self {
            root_hid,
            root_uid,
            pci_hops: stored_hops,
            pci_hop_count: pci_hops.len() as u8,
            hba_port,
            port_multiplier_port,
            logical_unit,
            media,
            stable_id,
        })
    }

    pub const fn root_hid(self) -> u32 {
        self.root_hid
    }
    pub const fn root_uid(self) -> u32 {
        self.root_uid
    }
    pub fn pci_hops(&self) -> &[InstalledRecoveryPciHop] {
        &self.pci_hops[..usize::from(self.pci_hop_count)]
    }
    pub const fn hba_port(self) -> u16 {
        self.hba_port
    }
    pub const fn port_multiplier_port(self) -> u16 {
        self.port_multiplier_port
    }
    pub const fn logical_unit(self) -> u16 {
        self.logical_unit
    }
    pub const fn media(self) -> Option<InstalledRecoveryHardDriveMedia> {
        self.media
    }
    pub const fn stable_id(self) -> [u8; 32] {
        self.stable_id
    }

    pub fn encode(self) -> [u8; INSTALLED_RECOVERY_SATA_ROUTE_BYTES] {
        let mut output = [0; INSTALLED_RECOVERY_SATA_ROUTE_BYTES];
        output[0] = 1;
        output[1] = self.pci_hop_count;
        output[2] = u8::from(self.media.is_some());
        output[4..8].copy_from_slice(&self.root_hid.to_le_bytes());
        output[8..12].copy_from_slice(&self.root_uid.to_le_bytes());
        output[12..14].copy_from_slice(&self.hba_port.to_le_bytes());
        output[14..16].copy_from_slice(&self.port_multiplier_port.to_le_bytes());
        output[16..18].copy_from_slice(&self.logical_unit.to_le_bytes());
        for (index, hop) in self.pci_hops().iter().enumerate() {
            output[24 + index * 2] = hop.device;
            output[25 + index * 2] = hop.function;
        }
        if let Some(media) = self.media {
            output[40..44].copy_from_slice(&media.partition_number.to_le_bytes());
            output[44..52].copy_from_slice(&media.partition_start.to_le_bytes());
            output[52..60].copy_from_slice(&media.partition_size.to_le_bytes());
            output[60..76].copy_from_slice(&media.signature);
            output[76] = media.mbr_type;
            output[77] = media.signature_type;
        }
        output[96..128].copy_from_slice(&self.stable_id);
        output
    }

    pub fn decode(
        input: &[u8; INSTALLED_RECOVERY_SATA_ROUTE_BYTES],
    ) -> Result<Self, InstalledRecoverySataRouteError> {
        let hop_count = usize::from(input[1]);
        let media_present = match input[2] {
            0 => false,
            1 => true,
            _ => return Err(InstalledRecoverySataRouteError::NonCanonical),
        };
        if input[0] != 1
            || hop_count == 0
            || hop_count > MAX_INSTALLED_RECOVERY_PCI_HOPS
            || input[3] != 0
            || input[18..24].iter().any(|byte| *byte != 0)
            || input[24 + hop_count * 2..40].iter().any(|byte| *byte != 0)
            || input[78..96].iter().any(|byte| *byte != 0)
        {
            return Err(InstalledRecoverySataRouteError::NonCanonical);
        }
        let mut hops = [InstalledRecoveryPciHop::default(); MAX_INSTALLED_RECOVERY_PCI_HOPS];
        for (index, hop) in hops[..hop_count].iter_mut().enumerate() {
            *hop = InstalledRecoveryPciHop::new(input[24 + index * 2], input[25 + index * 2])
                .ok_or(InstalledRecoverySataRouteError::NonCanonical)?;
        }
        let media = if media_present {
            let mut signature = [0; 16];
            signature.copy_from_slice(&input[60..76]);
            Some(
                InstalledRecoveryHardDriveMedia::new(
                    read_u32(input, 40),
                    read_u64(input, 44),
                    read_u64(input, 52),
                    signature,
                    input[76],
                    input[77],
                )
                .ok_or(InstalledRecoverySataRouteError::NonCanonical)?,
            )
        } else {
            if input[40..78].iter().any(|byte| *byte != 0) {
                return Err(InstalledRecoverySataRouteError::NonCanonical);
            }
            None
        };
        let mut stable_id = [0; 32];
        stable_id.copy_from_slice(&input[96..128]);
        Self::new(
            read_u32(input, 4),
            read_u32(input, 8),
            &hops[..hop_count],
            read_u16(input, 12),
            read_u16(input, 14),
            read_u16(input, 16),
            media,
            stable_id,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledRecoverySataRouteError {
    NonCanonical,
}

fn installed_media_valid(media: InstalledRecoveryHardDriveMedia) -> bool {
    media.partition_number != 0
        && media.partition_size != 0
        && media
            .partition_start
            .checked_add(media.partition_size)
            .is_some()
        && media.signature.iter().any(|byte| *byte != 0)
        && matches!((media.mbr_type, media.signature_type), (1, 1) | (2, 2))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledRecoverySource {
    Uefi,
    Ahci,
    Usb,
    Virtio,
    Hosted,
}

/// Non-authorizing identity of the exact installed recovery source validated
/// by the boot control plane. It intentionally excludes firmware handles,
/// service-local device IDs, sessions, capabilities, and pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledRecoveryBootIdentity {
    source: InstalledRecoverySource,
    stable_id: [u8; 32],
    controller_generation: u64,
    media_generation: u64,
    block_size: u32,
    block_count: u64,
    volume: [u8; 16],
    root_block: u64,
    root_generation: u64,
}

impl InstalledRecoveryBootIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: InstalledRecoverySource,
        stable_id: [u8; 32],
        controller_generation: u64,
        media_generation: u64,
        block_size: u32,
        block_count: u64,
        volume: [u8; 16],
        root_block: u64,
        root_generation: u64,
    ) -> Result<Self, InstalledRecoveryBootIdentityError> {
        if stable_id.iter().all(|byte| *byte == 0)
            || controller_generation == 0
            || media_generation == 0
            || block_size < 4096
            || block_size > 65_536
            || !block_size.is_power_of_two()
            || block_count == 0
            || volume.iter().all(|byte| *byte == 0)
        {
            return Err(InstalledRecoveryBootIdentityError::NonCanonical);
        }
        if root_generation == 0 || root_block >= block_count {
            return Err(InstalledRecoveryBootIdentityError::InvalidRoot);
        }
        Ok(Self {
            source,
            stable_id,
            controller_generation,
            media_generation,
            block_size,
            block_count,
            volume,
            root_block,
            root_generation,
        })
    }

    pub const fn source(self) -> InstalledRecoverySource {
        self.source
    }
    pub const fn stable_id(self) -> [u8; 32] {
        self.stable_id
    }
    pub const fn controller_generation(self) -> u64 {
        self.controller_generation
    }
    pub const fn media_generation(self) -> u64 {
        self.media_generation
    }
    pub const fn block_size(self) -> u32 {
        self.block_size
    }
    pub const fn block_count(self) -> u64 {
        self.block_count
    }
    pub const fn volume(self) -> [u8; 16] {
        self.volume
    }
    pub const fn root_block(self) -> u64 {
        self.root_block
    }
    pub const fn root_generation(self) -> u64 {
        self.root_generation
    }

    pub fn encode(self) -> [u8; INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES] {
        let mut output = [0; INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES];
        output[0] = encode_source(self.source);
        output[8..40].copy_from_slice(&self.stable_id);
        output[40..48].copy_from_slice(&self.controller_generation.to_le_bytes());
        output[48..56].copy_from_slice(&self.media_generation.to_le_bytes());
        output[56..60].copy_from_slice(&self.block_size.to_le_bytes());
        output[64..72].copy_from_slice(&self.block_count.to_le_bytes());
        output[72..88].copy_from_slice(&self.volume);
        output[88..96].copy_from_slice(&self.root_block.to_le_bytes());
        output[96..104].copy_from_slice(&self.root_generation.to_le_bytes());
        output
    }

    pub fn decode(
        input: &[u8; INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES],
    ) -> Result<Self, InstalledRecoveryBootIdentityError> {
        if input[1..8].iter().any(|byte| *byte != 0) || input[60..64].iter().any(|byte| *byte != 0)
        {
            return Err(InstalledRecoveryBootIdentityError::NonCanonical);
        }
        Self::new(
            decode_source(input[0])?,
            input[8..40].try_into().unwrap(),
            read_u64(input, 40),
            read_u64(input, 48),
            u32::from_le_bytes(input[56..60].try_into().unwrap()),
            read_u64(input, 64),
            input[72..88].try_into().unwrap(),
            read_u64(input, 88),
            read_u64(input, 96),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledRecoveryBootIdentityError {
    NonCanonical,
    InvalidRoot,
}

const fn encode_source(source: InstalledRecoverySource) -> u8 {
    match source {
        InstalledRecoverySource::Uefi => 1,
        InstalledRecoverySource::Ahci => 2,
        InstalledRecoverySource::Usb => 3,
        InstalledRecoverySource::Virtio => 4,
        InstalledRecoverySource::Hosted => 5,
    }
}

fn decode_source(value: u8) -> Result<InstalledRecoverySource, InstalledRecoveryBootIdentityError> {
    match value {
        1 => Ok(InstalledRecoverySource::Uefi),
        2 => Ok(InstalledRecoverySource::Ahci),
        3 => Ok(InstalledRecoverySource::Usb),
        4 => Ok(InstalledRecoverySource::Virtio),
        5 => Ok(InstalledRecoverySource::Hosted),
        _ => Err(InstalledRecoveryBootIdentityError::NonCanonical),
    }
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> InstalledRecoveryBootIdentity {
        InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Uefi,
            [0x51; 32],
            3,
            9,
            4096,
            128,
            [0x61; 16],
            2,
            17,
        )
        .unwrap()
    }

    fn sata_route() -> InstalledRecoverySataRoute {
        let hops = [
            InstalledRecoveryPciHop::new(3, 0).unwrap(),
            InstalledRecoveryPciHop::new(5, 2).unwrap(),
        ];
        let media = InstalledRecoveryHardDriveMedia::new(2, 2048, 4096, [0x5a; 16], 2, 2).unwrap();
        InstalledRecoverySataRoute::new(
            0x0a03_41d0,
            7,
            &hops,
            3,
            u16::MAX,
            1,
            Some(media),
            [0x51; 32],
        )
        .unwrap()
    }

    #[test]
    fn canonical_identity_excludes_local_authority_and_round_trips() {
        let expected = identity();
        let encoded = expected.encode();
        assert_eq!(encoded.len(), INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES);
        assert_eq!(
            InstalledRecoveryBootIdentity::decode(&encoded),
            Ok(expected)
        );
        assert_eq!(encoded[0], 1);
        assert!(encoded[1..8].iter().all(|byte| *byte == 0));
        assert_eq!(&encoded[8..40], &[0x51; 32]);
        assert!(encoded[60..64].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn decoder_rejects_reserved_identity_generation_geometry_and_root_changes() {
        let encoded = identity().encode();
        for index in [1usize, 60] {
            let mut malformed = encoded;
            malformed[index] = 1;
            assert_eq!(
                InstalledRecoveryBootIdentity::decode(&malformed),
                Err(InstalledRecoveryBootIdentityError::NonCanonical)
            );
        }
        for range in [8..40, 40..48, 48..56, 56..60, 64..72, 72..88, 96..104] {
            let mut malformed = encoded;
            malformed[range].fill(0);
            assert!(InstalledRecoveryBootIdentity::decode(&malformed).is_err());
        }
        let mut malformed = encoded;
        malformed[88..96].copy_from_slice(&128u64.to_le_bytes());
        assert_eq!(
            InstalledRecoveryBootIdentity::decode(&malformed),
            Err(InstalledRecoveryBootIdentityError::InvalidRoot)
        );
        let mut malformed = encoded;
        malformed[0] = 0xff;
        assert_eq!(
            InstalledRecoveryBootIdentity::decode(&malformed),
            Err(InstalledRecoveryBootIdentityError::NonCanonical)
        );
    }

    #[test]
    fn canonical_sata_route_round_trips_without_authority_or_local_handles() {
        let route = sata_route();
        let encoded = route.encode();
        assert_eq!(InstalledRecoverySataRoute::decode(&encoded), Ok(route));
        assert_eq!(route.pci_hops().len(), 2);
        assert_eq!(route.pci_hops()[1].device(), 5);
        assert_eq!(route.hba_port(), 3);
        assert_eq!(route.media().unwrap().signature(), [0x5a; 16]);
        assert_eq!(route.stable_id(), [0x51; 32]);
        assert!(encoded[18..24].iter().all(|byte| *byte == 0));
        assert!(encoded[28..40].iter().all(|byte| *byte == 0));
        assert!(encoded[78..96].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sata_route_decoder_rejects_reserved_hop_media_and_identity_substitution() {
        let encoded = sata_route().encode();
        for index in [3usize, 18, 28, 78] {
            let mut malformed = encoded;
            malformed[index] = 1;
            assert_eq!(
                InstalledRecoverySataRoute::decode(&malformed),
                Err(InstalledRecoverySataRouteError::NonCanonical)
            );
        }
        for (index, value) in [(0usize, 2u8), (1, 0), (2, 2), (24, 32), (25, 8)] {
            let mut malformed = encoded;
            malformed[index] = value;
            assert!(InstalledRecoverySataRoute::decode(&malformed).is_err());
        }
        let mut malformed = encoded;
        malformed[40..44].fill(0);
        assert!(InstalledRecoverySataRoute::decode(&malformed).is_err());
        let mut malformed = encoded;
        malformed[96..128].fill(0);
        assert!(InstalledRecoverySataRoute::decode(&malformed).is_err());

        let mut no_media = encoded;
        no_media[2] = 0;
        assert!(InstalledRecoverySataRoute::decode(&no_media).is_err());
        no_media[40..78].fill(0);
        assert!(InstalledRecoverySataRoute::decode(&no_media).is_ok());
    }
}
