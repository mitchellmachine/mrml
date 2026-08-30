use crate::INTERFACE_GENERATION;

pub const BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES: usize = 144;
const MAGIC: [u8; 8] = *b"MRMLFBA1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockProviderDependencyHandoff {
    association_generation: u64,
    system_generation: u64,
    consumer_module_object: u64,
    consumer_binding_generation: u64,
    consumer_provider_generation: u64,
    block_module_object: u64,
    block_binding_generation: u64,
    block_provider_generation: u64,
    block_endpoint_object: u64,
    consumer_volume_index: u32,
    consumer_volume_generation: u32,
    block_session_index: u32,
    block_session_generation: u32,
    logical_block_bytes: u32,
    consumer_interface_object: u64,
    consumer_interface_generation: u32,
    block_interface_object: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockProviderDependencyHandoffError {
    Format,
    Reserved,
    InvalidIdentity,
    InvalidGeneration,
    InvalidGeometry,
    WrongBlockInterfaceGeneration,
}

impl BlockProviderDependencyHandoff {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        association_generation: u64,
        system_generation: u64,
        consumer_module_object: u64,
        consumer_binding_generation: u64,
        consumer_provider_generation: u64,
        block_module_object: u64,
        block_binding_generation: u64,
        block_provider_generation: u64,
        block_endpoint_object: u64,
        consumer_volume_index: u32,
        consumer_volume_generation: u32,
        block_session_index: u32,
        block_session_generation: u32,
        logical_block_bytes: u32,
        consumer_interface_object: u64,
        consumer_interface_generation: u32,
        block_interface_object: u64,
    ) -> Result<Self, BlockProviderDependencyHandoffError> {
        let handoff = Self {
            association_generation,
            system_generation,
            consumer_module_object,
            consumer_binding_generation,
            consumer_provider_generation,
            block_module_object,
            block_binding_generation,
            block_provider_generation,
            block_endpoint_object,
            consumer_volume_index,
            consumer_volume_generation,
            block_session_index,
            block_session_generation,
            logical_block_bytes,
            consumer_interface_object,
            consumer_interface_generation,
            block_interface_object,
        };
        handoff.validate()?;
        Ok(handoff)
    }

    pub fn encode(self) -> [u8; BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES] {
        let mut bytes = [0; BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES];
        bytes[0..8].copy_from_slice(&MAGIC);
        bytes[8..16].copy_from_slice(&self.association_generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.system_generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.consumer_module_object.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.consumer_binding_generation.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.consumer_provider_generation.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.block_module_object.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.block_binding_generation.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.block_provider_generation.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.block_endpoint_object.to_le_bytes());
        bytes[80..84].copy_from_slice(&self.consumer_volume_index.to_le_bytes());
        bytes[84..88].copy_from_slice(&self.consumer_volume_generation.to_le_bytes());
        bytes[88..92].copy_from_slice(&self.block_session_index.to_le_bytes());
        bytes[92..96].copy_from_slice(&self.block_session_generation.to_le_bytes());
        bytes[96..100].copy_from_slice(&self.logical_block_bytes.to_le_bytes());
        bytes[104..112].copy_from_slice(&self.consumer_interface_object.to_le_bytes());
        bytes[112..116].copy_from_slice(&self.consumer_interface_generation.to_le_bytes());
        bytes[120..128].copy_from_slice(&self.block_interface_object.to_le_bytes());
        bytes[128..132].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BlockProviderDependencyHandoffError> {
        if bytes.len() != BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES || bytes[0..8] != MAGIC {
            return Err(BlockProviderDependencyHandoffError::Format);
        }
        if bytes[100..104] != [0; 4] || bytes[116..120] != [0; 4] || bytes[132..144] != [0; 12] {
            return Err(BlockProviderDependencyHandoffError::Reserved);
        }
        if read_u32(bytes, 128)? != INTERFACE_GENERATION {
            return Err(BlockProviderDependencyHandoffError::WrongBlockInterfaceGeneration);
        }
        Self::new(
            read_u64(bytes, 8)?,
            read_u64(bytes, 16)?,
            read_u64(bytes, 24)?,
            read_u64(bytes, 32)?,
            read_u64(bytes, 40)?,
            read_u64(bytes, 48)?,
            read_u64(bytes, 56)?,
            read_u64(bytes, 64)?,
            read_u64(bytes, 72)?,
            read_u32(bytes, 80)?,
            read_u32(bytes, 84)?,
            read_u32(bytes, 88)?,
            read_u32(bytes, 92)?,
            read_u32(bytes, 96)?,
            read_u64(bytes, 104)?,
            read_u32(bytes, 112)?,
            read_u64(bytes, 120)?,
        )
    }

    fn validate(self) -> Result<(), BlockProviderDependencyHandoffError> {
        if self.association_generation == 0
            || self.system_generation == 0
            || self.consumer_binding_generation == 0
            || self.consumer_provider_generation == 0
            || self.block_binding_generation == 0
            || self.block_provider_generation == 0
            || self.consumer_volume_generation == 0
            || self.block_session_generation == 0
            || self.consumer_interface_generation == 0
        {
            return Err(BlockProviderDependencyHandoffError::InvalidGeneration);
        }
        if self.consumer_module_object == 0
            || self.block_module_object == 0
            || self.consumer_interface_object == 0
            || self.block_interface_object == 0
            || self.block_endpoint_object == 0
            || self.consumer_module_object == self.block_module_object
        {
            return Err(BlockProviderDependencyHandoffError::InvalidIdentity);
        }
        if self.logical_block_bytes < 512
            || self.logical_block_bytes > 65_536
            || !self.logical_block_bytes.is_power_of_two()
        {
            return Err(BlockProviderDependencyHandoffError::InvalidGeometry);
        }
        Ok(())
    }

    pub const fn association_generation(self) -> u64 {
        self.association_generation
    }
    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }
    pub const fn consumer_module_object(self) -> u64 {
        self.consumer_module_object
    }
    pub const fn consumer_binding_generation(self) -> u64 {
        self.consumer_binding_generation
    }
    pub const fn consumer_provider_generation(self) -> u64 {
        self.consumer_provider_generation
    }
    pub const fn block_module_object(self) -> u64 {
        self.block_module_object
    }
    pub const fn block_binding_generation(self) -> u64 {
        self.block_binding_generation
    }
    pub const fn block_provider_generation(self) -> u64 {
        self.block_provider_generation
    }
    pub const fn block_endpoint_object(self) -> u64 {
        self.block_endpoint_object
    }
    pub const fn consumer_volume_index(self) -> u32 {
        self.consumer_volume_index
    }
    pub const fn consumer_volume_generation(self) -> u32 {
        self.consumer_volume_generation
    }
    pub const fn block_session_index(self) -> u32 {
        self.block_session_index
    }
    pub const fn block_session_generation(self) -> u32 {
        self.block_session_generation
    }
    pub const fn logical_block_bytes(self) -> u32 {
        self.logical_block_bytes
    }
    pub const fn consumer_interface_object(self) -> u64 {
        self.consumer_interface_object
    }
    pub const fn consumer_interface_generation(self) -> u32 {
        self.consumer_interface_generation
    }
    pub const fn block_interface_object(self) -> u64 {
        self.block_interface_object
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlockProviderDependencyHandoffError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(BlockProviderDependencyHandoffError::Format)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BlockProviderDependencyHandoffError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(BlockProviderDependencyHandoffError::Format)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff() -> BlockProviderDependencyHandoff {
        BlockProviderDependencyHandoff::new(
            12, 9, 41, 3, 5, 11, 4, 7, 21, 2, 6, 8, 10, 4096, 42, 3, 10,
        )
        .unwrap()
    }

    #[test]
    fn dependency_handoff_round_trips_exact_zero_reserved_identity() {
        let handoff = handoff();
        let bytes = handoff.encode();
        assert_eq!(BlockProviderDependencyHandoff::decode(&bytes), Ok(handoff));
        assert_eq!(handoff.consumer_provider_generation(), 5);
        assert_eq!(handoff.block_provider_generation(), 7);
        assert_eq!(handoff.consumer_volume_generation(), 6);
        assert_eq!(handoff.block_session_generation(), 10);
    }

    #[test]
    fn dependency_handoff_rejects_truncation_reserved_and_substituted_fields() {
        let bytes = handoff().encode();
        assert_eq!(
            BlockProviderDependencyHandoff::decode(&bytes[..bytes.len() - 1]),
            Err(BlockProviderDependencyHandoffError::Format)
        );
        let mut reserved = bytes;
        reserved[132] = 1;
        assert_eq!(
            BlockProviderDependencyHandoff::decode(&reserved),
            Err(BlockProviderDependencyHandoffError::Reserved)
        );
        let mut wrong_block_interface = bytes;
        wrong_block_interface[128..132].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            BlockProviderDependencyHandoff::decode(&wrong_block_interface),
            Err(BlockProviderDependencyHandoffError::WrongBlockInterfaceGeneration)
        );
        let mut overbroad_geometry = bytes;
        overbroad_geometry[96..100].copy_from_slice(&1000_u32.to_le_bytes());
        assert_eq!(
            BlockProviderDependencyHandoff::decode(&overbroad_geometry),
            Err(BlockProviderDependencyHandoffError::InvalidGeometry)
        );
    }
}
