pub const INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES: usize = 104;

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
}
