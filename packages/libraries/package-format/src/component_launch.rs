pub const COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES: usize = 280;
const MAGIC: [u8; 8] = *b"MRMLCSL2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ComponentServicePlacement {
    NativeService = 1,
    Microvm = 2,
}

impl ComponentServicePlacement {
    const fn decode(value: u8) -> Result<Self, ComponentServiceLaunchHandoffError> {
        match value {
            1 => Ok(Self::NativeService),
            2 => Ok(Self::Microvm),
            _ => Err(ComponentServiceLaunchHandoffError::Placement),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentServiceLaunchHandoff {
    system_generation: u64,
    policy_generation: u64,
    domain_object: u64,
    interface_object: u64,
    interface_generation: u32,
    provider_generation: u64,
    placement: ComponentServicePlacement,
    system_generation_digest: [u8; 64],
    interface_fingerprint: [u8; 32],
    consumer_artifact: [u8; 64],
    provider_artifact: [u8; 64],
}

impl ComponentServiceLaunchHandoff {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        system_generation: u64,
        policy_generation: u64,
        domain_object: u64,
        interface_object: u64,
        interface_generation: u32,
        provider_generation: u64,
        placement: ComponentServicePlacement,
        system_generation_digest: [u8; 64],
        interface_fingerprint: [u8; 32],
        consumer_artifact: [u8; 64],
        provider_artifact: [u8; 64],
    ) -> Result<Self, ComponentServiceLaunchHandoffError> {
        if system_generation == 0 || policy_generation == 0 {
            return Err(ComponentServiceLaunchHandoffError::Generation);
        }
        if domain_object == 0 || interface_object == 0 {
            return Err(ComponentServiceLaunchHandoffError::Object);
        }
        if interface_generation == 0 || provider_generation == 0 {
            return Err(ComponentServiceLaunchHandoffError::Generation);
        }
        if all_zero_64(&system_generation_digest) {
            return Err(ComponentServiceLaunchHandoffError::SystemGenerationDigest);
        }
        if all_zero_32(&interface_fingerprint) {
            return Err(ComponentServiceLaunchHandoffError::Fingerprint);
        }
        if all_zero_64(&consumer_artifact) || all_zero_64(&provider_artifact) {
            return Err(ComponentServiceLaunchHandoffError::Artifact);
        }
        if equal_64(&consumer_artifact, &provider_artifact) {
            return Err(ComponentServiceLaunchHandoffError::ArtifactSubstitution);
        }
        Ok(Self {
            system_generation,
            policy_generation,
            domain_object,
            interface_object,
            interface_generation,
            provider_generation,
            placement,
            system_generation_digest,
            interface_fingerprint,
            consumer_artifact,
            provider_artifact,
        })
    }

    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
    pub const fn domain_object(self) -> u64 {
        self.domain_object
    }
    pub const fn interface_object(self) -> u64 {
        self.interface_object
    }
    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }
    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }
    pub const fn placement(self) -> ComponentServicePlacement {
        self.placement
    }
    pub const fn system_generation_digest(&self) -> &[u8; 64] {
        &self.system_generation_digest
    }
    pub const fn interface_fingerprint(&self) -> &[u8; 32] {
        &self.interface_fingerprint
    }
    pub const fn consumer_artifact(&self) -> &[u8; 64] {
        &self.consumer_artifact
    }
    pub const fn provider_artifact(&self) -> &[u8; 64] {
        &self.provider_artifact
    }

    pub fn encode(self) -> [u8; COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES] {
        let mut bytes = [0; COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..16].copy_from_slice(&self.system_generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.policy_generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.domain_object.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.interface_object.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.interface_generation.to_le_bytes());
        bytes[44] = self.placement as u8;
        bytes[48..56].copy_from_slice(&self.provider_generation.to_le_bytes());
        bytes[56..120].copy_from_slice(&self.system_generation_digest);
        bytes[120..152].copy_from_slice(&self.interface_fingerprint);
        bytes[152..216].copy_from_slice(&self.consumer_artifact);
        bytes[216..280].copy_from_slice(&self.provider_artifact);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComponentServiceLaunchHandoffError> {
        if bytes.len() != COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES || bytes[..8] != MAGIC {
            return Err(ComponentServiceLaunchHandoffError::Format);
        }
        if bytes[45..48] != [0; 3] {
            return Err(ComponentServiceLaunchHandoffError::Reserved);
        }
        let mut fingerprint = [0; 32];
        let mut system_generation_digest = [0; 64];
        system_generation_digest.copy_from_slice(&bytes[56..120]);
        fingerprint.copy_from_slice(&bytes[120..152]);
        let mut consumer = [0; 64];
        consumer.copy_from_slice(&bytes[152..216]);
        let mut provider = [0; 64];
        provider.copy_from_slice(&bytes[216..280]);
        Self::new(
            read_u64(bytes, 8)?,
            read_u64(bytes, 16)?,
            read_u64(bytes, 24)?,
            read_u64(bytes, 32)?,
            read_u32(bytes, 40)?,
            read_u64(bytes, 48)?,
            ComponentServicePlacement::decode(bytes[44])?,
            system_generation_digest,
            fingerprint,
            consumer,
            provider,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentServiceLaunchHandoffError {
    Format,
    Reserved,
    Placement,
    Generation,
    Object,
    SystemGenerationDigest,
    Fingerprint,
    Artifact,
    ArtifactSubstitution,
}

const fn all_zero_32(value: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn all_zero_64(value: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn equal_64(left: &[u8; 64], right: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ComponentServiceLaunchHandoffError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ComponentServiceLaunchHandoffError::Format)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ComponentServiceLaunchHandoffError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ComponentServiceLaunchHandoffError::Format)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff() -> ComponentServiceLaunchHandoff {
        ComponentServiceLaunchHandoff::new(
            108,
            7,
            0x500,
            0x406,
            3,
            11,
            ComponentServicePlacement::Microvm,
            [0x51; 64],
            [0x3a; 32],
            [0x18; 64],
            [0x2f; 64],
        )
        .unwrap()
    }

    #[test]
    fn canonical_round_trip_preserves_every_authority_binding() {
        let handoff = handoff();
        let bytes = handoff.encode();
        assert_eq!(bytes.len(), COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES);
        assert_eq!(ComponentServiceLaunchHandoff::decode(&bytes), Ok(handoff));
    }

    #[test]
    fn malformed_or_ambiguous_handoffs_fail_closed() {
        let bytes = handoff().encode();
        for length in [0, 8, COMPONENT_SERVICE_LAUNCH_HANDOFF_BYTES - 1] {
            assert_eq!(
                ComponentServiceLaunchHandoff::decode(&bytes[..length]),
                Err(ComponentServiceLaunchHandoffError::Format)
            );
        }
        let mut reserved = bytes;
        reserved[45] = 1;
        assert_eq!(
            ComponentServiceLaunchHandoff::decode(&reserved),
            Err(ComponentServiceLaunchHandoffError::Reserved)
        );
        let mut placement = bytes;
        placement[44] = 3;
        assert_eq!(
            ComponentServiceLaunchHandoff::decode(&placement),
            Err(ComponentServiceLaunchHandoffError::Placement)
        );
    }
}
