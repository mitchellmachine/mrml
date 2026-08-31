//! Bounded cache for an already-unlocked signing key.
//!
//! This deliberately never stores a passphrase. A trusted prompt and key
//! provider unlock the key once, zeroize the prompt buffer, and place only the
//! non-exported key material here. Callers receive scoped signing operations,
//! never a reference to the cached bytes.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyCacheError {
    Expired,
    WrongScope,
    ClockRollback,
    InvalidLifetime,
}

pub struct UnlockedSigningKeyCache<const N: usize> {
    secret: [u8; N],
    scope: [u8; 32],
    created_at: u64,
    last_used_at: u64,
    idle_timeout: u64,
    absolute_timeout: u64,
    valid: bool,
}

impl<const N: usize> UnlockedSigningKeyCache<N> {
    pub const fn empty() -> Self {
        Self {
            secret: [0; N],
            scope: [0; 32],
            created_at: 0,
            last_used_at: 0,
            idle_timeout: 0,
            absolute_timeout: 0,
            valid: false,
        }
    }

    pub fn unlock(
        &mut self,
        secret: &[u8; N],
        scope: [u8; 32],
        now: u64,
        idle_timeout: u64,
        absolute_timeout: u64,
    ) -> Result<(), SigningKeyCacheError> {
        if idle_timeout == 0 || absolute_timeout < idle_timeout {
            return Err(SigningKeyCacheError::InvalidLifetime);
        }
        self.lock();
        self.secret.copy_from_slice(secret);
        self.scope = scope;
        self.created_at = now;
        self.last_used_at = now;
        self.idle_timeout = idle_timeout;
        self.absolute_timeout = absolute_timeout;
        self.valid = true;
        Ok(())
    }

    /// Perform one scoped operation without exposing the cached key.
    pub fn use_key<R>(
        &mut self,
        scope: &[u8; 32],
        now: u64,
        operation: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SigningKeyCacheError> {
        if !self.valid {
            return Err(SigningKeyCacheError::Expired);
        }
        if now < self.created_at || now < self.last_used_at {
            self.lock();
            return Err(SigningKeyCacheError::ClockRollback);
        }
        if now - self.created_at >= self.absolute_timeout
            || now - self.last_used_at >= self.idle_timeout
        {
            self.lock();
            return Err(SigningKeyCacheError::Expired);
        }
        if !constant_time_equal(scope, &self.scope) {
            return Err(SigningKeyCacheError::WrongScope);
        }
        self.last_used_at = now;
        Ok(operation(&self.secret))
    }

    pub fn lock(&mut self) {
        self.secret.fill(0);
        self.scope.fill(0);
        self.created_at = 0;
        self.last_used_at = 0;
        self.idle_timeout = 0;
        self.absolute_timeout = 0;
        self.valid = false;
    }

    pub const fn is_unlocked(&self) -> bool {
        self.valid
    }
}

impl<const N: usize> Drop for UnlockedSigningKeyCache<N> {
    fn drop(&mut self) {
        self.lock();
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_expires_and_explicitly_locks() {
        let mut cache = UnlockedSigningKeyCache::<32>::empty();
        cache
            .unlock(&[7; 32], [1; 32], 10, 15 * 60, 60 * 60)
            .unwrap();
        assert_eq!(cache.use_key(&[1; 32], 20, |key| key[0]), Ok(7));
        assert_eq!(
            cache.use_key(&[2; 32], 21, |_| ()),
            Err(SigningKeyCacheError::WrongScope)
        );
        assert_eq!(
            cache.use_key(&[1; 32], 20 + 15 * 60, |_| ()),
            Err(SigningKeyCacheError::Expired)
        );
        assert!(!cache.is_unlocked());
    }

    #[test]
    fn fails_closed_on_clock_rollback_and_absolute_expiry() {
        let mut cache = UnlockedSigningKeyCache::<4>::empty();
        cache.unlock(&[9; 4], [3; 32], 100, 50, 100).unwrap();
        assert_eq!(
            cache.use_key(&[3; 32], 99, |_| ()),
            Err(SigningKeyCacheError::ClockRollback)
        );
        cache.unlock(&[9; 4], [3; 32], 100, 50, 100).unwrap();
        assert_eq!(cache.use_key(&[3; 32], 149, |_| ()), Ok(()));
        assert_eq!(
            cache.use_key(&[3; 32], 200, |_| ()),
            Err(SigningKeyCacheError::Expired)
        );
    }
}
