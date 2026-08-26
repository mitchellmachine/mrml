use crate::SystemReleaseIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivatedSystemGeneration {
    generation: u64,
    generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    activation_sequence: u64,
    source_object: u64,
    source_generation: u64,
}

impl ActivatedSystemGeneration {
    pub const fn new(
        generation: u64,
        generation_digest: [u8; 64],
        interface_catalog_digest: [u8; 64],
        activation_sequence: u64,
        source_object: u64,
        source_generation: u64,
    ) -> Result<Self, ActivatedSystemGenerationError> {
        if generation == 0 || activation_sequence == 0 || source_generation == 0 {
            return Err(ActivatedSystemGenerationError::Generation);
        }
        if source_object == 0 {
            return Err(ActivatedSystemGenerationError::SourceObject);
        }
        if all_zero(&generation_digest) || all_zero(&interface_catalog_digest) {
            return Err(ActivatedSystemGenerationError::Digest);
        }
        Ok(Self {
            generation,
            generation_digest,
            interface_catalog_digest,
            activation_sequence,
            source_object,
            source_generation,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn generation_digest(&self) -> &[u8; 64] {
        &self.generation_digest
    }

    pub const fn interface_catalog_digest(&self) -> &[u8; 64] {
        &self.interface_catalog_digest
    }

    pub const fn activation_sequence(self) -> u64 {
        self.activation_sequence
    }

    pub const fn source_object(self) -> u64 {
        self.source_object
    }

    pub const fn source_generation(self) -> u64 {
        self.source_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivatedSystemGenerationError {
    Generation,
    Digest,
    SourceObject,
}

/// Exact SystemRelease identity paired with an immutable activated generation.
/// Deployment creates this only from a verified release or an authenticated
/// checkpoint. Like all identity metadata, the pair identifies but grants no
/// authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivatedSystemRelease {
    generation: ActivatedSystemGeneration,
    release: SystemReleaseIdentity,
}

impl ActivatedSystemRelease {
    pub const fn new(
        generation: ActivatedSystemGeneration,
        release: SystemReleaseIdentity,
    ) -> Self {
        Self {
            generation,
            release,
        }
    }

    pub const fn generation(self) -> ActivatedSystemGeneration {
        self.generation
    }

    pub const fn release(self) -> SystemReleaseIdentity {
        self.release
    }
}

const fn all_zero(value: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_generation_requires_exact_nonzero_identity() {
        let active =
            ActivatedSystemGeneration::new(8, [0x51; 64], [0x72; 64], 3, 0x400, 9).unwrap();
        assert_eq!(active.generation(), 8);
        assert_eq!(active.generation_digest(), &[0x51; 64]);
        assert_eq!(active.interface_catalog_digest(), &[0x72; 64]);
        assert_eq!(active.activation_sequence(), 3);
        assert_eq!(active.source_object(), 0x400);
        assert_eq!(active.source_generation(), 9);
        assert_eq!(
            ActivatedSystemGeneration::new(8, [0; 64], [0x72; 64], 3, 0x400, 9),
            Err(ActivatedSystemGenerationError::Digest)
        );
        assert_eq!(
            ActivatedSystemGeneration::new(8, [0x51; 64], [0; 64], 3, 0x400, 9),
            Err(ActivatedSystemGenerationError::Digest)
        );
    }
}
