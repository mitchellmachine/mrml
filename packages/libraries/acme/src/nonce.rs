pub const MAX_NONCES: usize = 8;
pub const MAX_SEEN_NONCES: usize = 64;
pub const MAX_NONCE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceError {
    Empty,
    TooLong,
    InvalidEncoding,
    PoolFull,
    Unavailable,
    WrongDirectoryGeneration,
    ReplayDetected,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplayNonce {
    bytes: [u8; MAX_NONCE_BYTES],
    len: u8,
}
impl ReplayNonce {
    pub fn parse(value: &str) -> Result<Self, NonceError> {
        if value.is_empty() {
            return Err(NonceError::Empty);
        }
        if value.len() > MAX_NONCE_BYTES {
            return Err(NonceError::TooLong);
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NonceError::InvalidEncoding);
        }
        let mut bytes = [0; MAX_NONCE_BYTES];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}
pub struct NoncePool {
    generation: u64,
    entries: [Option<ReplayNonce>; MAX_NONCES],
    seen: [Option<ReplayNonce>; MAX_SEEN_NONCES],
}
impl NoncePool {
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            entries: [None; MAX_NONCES],
            seen: [None; MAX_SEEN_NONCES],
        }
    }
    pub fn replace_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.entries = [None; MAX_NONCES];
        self.seen = [None; MAX_SEEN_NONCES];
    }
    pub fn insert(&mut self, generation: u64, nonce: ReplayNonce) -> Result<(), NonceError> {
        if generation != self.generation {
            return Err(NonceError::WrongDirectoryGeneration);
        }
        if self.seen.iter().flatten().any(|seen| seen == &nonce) {
            return Err(NonceError::ReplayDetected);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|n| n.is_none())
            .ok_or(NonceError::PoolFull)?;
        let seen = self
            .seen
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(NonceError::PoolFull)?;
        *slot = Some(nonce);
        *seen = Some(nonce);
        Ok(())
    }
    pub fn consume(&mut self, generation: u64) -> Result<ReplayNonce, NonceError> {
        if generation != self.generation {
            return Err(NonceError::WrongDirectoryGeneration);
        }
        for slot in &mut self.entries {
            if slot.is_some() {
                return slot.take().ok_or(NonceError::Unavailable);
            }
        }
        Err(NonceError::Unavailable)
    }
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|n| n.is_some()).count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumes_once_and_clears_on_generation_change() {
        let mut p = NoncePool::new(2);
        p.insert(2, ReplayNonce::parse("abc_123").unwrap()).unwrap();
        assert_eq!(p.consume(2).unwrap().as_str(), "abc_123");
        assert!(matches!(p.consume(2), Err(NonceError::Unavailable)));
        p.insert(2, ReplayNonce::parse("next").unwrap()).unwrap();
        p.replace_generation(3);
        assert!(p.is_empty());
        assert!(matches!(
            p.consume(2),
            Err(NonceError::WrongDirectoryGeneration)
        ));
    }

    #[test]
    fn consumed_nonce_cannot_be_reintroduced_in_same_directory_generation() {
        let mut pool = NoncePool::new(4);
        let nonce = ReplayNonce::parse("single-use").unwrap();
        pool.insert(4, nonce).unwrap();
        assert_eq!(pool.consume(4).unwrap().as_str(), "single-use");
        assert_eq!(pool.insert(4, nonce), Err(NonceError::ReplayDetected));
        pool.replace_generation(5);
        assert_eq!(pool.insert(5, nonce), Ok(()));
    }
}
