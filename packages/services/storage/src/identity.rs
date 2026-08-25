#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VolumeId([u8; 16]);

impl VolumeId {
    pub const fn new(bytes: [u8; 16]) -> Result<Self, StorageIdentityError> {
        let mut index = 0;
        let mut nonzero = false;
        while index < bytes.len() {
            nonzero |= bytes[index] != 0;
            index += 1;
        }
        if !nonzero {
            return Err(StorageIdentityError::ZeroVolume);
        }
        Ok(Self(bytes))
    }

    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StorageObjectId {
    volume: VolumeId,
    local: u64,
}

impl StorageObjectId {
    pub const fn new(volume: VolumeId, local: u64) -> Result<Self, StorageIdentityError> {
        if local == 0 {
            return Err(StorageIdentityError::ZeroObject);
        }
        Ok(Self { volume, local })
    }

    pub const fn volume(self) -> VolumeId {
        self.volume
    }

    pub const fn local(self) -> u64 {
        self.local
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageIdentityError {
    ZeroVolume,
    ZeroObject,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_identities_reject_zero_and_preserve_volume_binding() {
        assert_eq!(
            VolumeId::new([0; 16]),
            Err(StorageIdentityError::ZeroVolume)
        );
        let volume = VolumeId::new([7; 16]).unwrap();
        assert_eq!(
            StorageObjectId::new(volume, 0),
            Err(StorageIdentityError::ZeroObject)
        );
        let object = StorageObjectId::new(volume, 9).unwrap();
        assert_eq!(object.volume(), volume);
        assert_eq!(object.local(), 9);
    }
}
