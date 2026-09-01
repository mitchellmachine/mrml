pub const MAX_PROFILE_NAME: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Empty,
    TooLong,
    InvalidCharacter,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertificateProfile {
    bytes: [u8; MAX_PROFILE_NAME],
    len: u8,
    directory_generation: u64,
}
impl CertificateProfile {
    pub fn parse(name: &str, directory_generation: u64) -> Result<Self, ProfileError> {
        if name.is_empty() {
            return Err(ProfileError::Empty);
        }
        if name.len() > MAX_PROFILE_NAME {
            return Err(ProfileError::TooLong);
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ProfileError::InvalidCharacter);
        }
        let mut bytes = [0; MAX_PROFILE_NAME];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: name.len() as u8,
            directory_generation,
        })
    }
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
    pub const fn directory_generation(&self) -> u64 {
        self.directory_generation
    }
}
