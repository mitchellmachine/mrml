use mrml_crypto::{Sha256, aes128_gcm_open, aes128_gcm_seal};
use mrml_runtime::{SocketAddress, Vector};

use crate::QuicError;

const TOKEN_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const FIXED_PLAINTEXT_LENGTH: usize = 1 + 8 + 4 + 2 + 1;
const MAX_CONNECTION_ID_LENGTH: usize = 20;
const MAX_TOKEN_LENGTH: usize =
    1 + 8 + NONCE_LENGTH + FIXED_PLAINTEXT_LENGTH + MAX_CONNECTION_ID_LENGTH + TAG_LENGTH;
const MAX_CONSUMED_TOKENS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum QuicRetryPurpose {
    AddressValidation = 1,
}

#[derive(Clone, Copy)]
pub struct QuicRetryKey {
    pub generation: u64,
    pub key: [u8; 16],
}

#[derive(Clone)]
struct ConsumedToken {
    digest: [u8; 32],
    expires_at: u64,
}

/// Bounded Retry-token authority. Tokens bind the exact IPv4 endpoint, original
/// destination connection ID, issue time, key generation, and purpose. A token
/// is consumed once; key rotation retains at most one explicitly supplied prior
/// generation.
pub struct QuicRetryTokenManager {
    current: QuicRetryKey,
    previous: Option<QuicRetryKey>,
    lifetime_seconds: u64,
    consumed: Vector<ConsumedToken>,
}

impl QuicRetryTokenManager {
    pub fn new(current: QuicRetryKey, lifetime_seconds: u64) -> Result<Self, QuicError> {
        if lifetime_seconds == 0 {
            return Err(QuicError::Limit);
        }
        Ok(Self {
            current,
            previous: None,
            lifetime_seconds,
            consumed: Vector::new(),
        })
    }

    pub fn rotate(&mut self, next: QuicRetryKey) -> Result<(), QuicError> {
        if next.generation <= self.current.generation {
            return Err(QuicError::ProtocolViolation);
        }
        self.previous = Some(self.current);
        self.current = next;
        Ok(())
    }

    pub fn issue(
        &self,
        peer: SocketAddress,
        original_destination_id: &[u8],
        issued_at: u64,
        purpose: QuicRetryPurpose,
    ) -> Result<Vector<u8>, QuicError> {
        let mut nonce = [0; NONCE_LENGTH];
        mrml_runtime::fill_random(&mut nonce).map_err(|_| QuicError::Crypto)?;
        self.issue_with_nonce(peer, original_destination_id, issued_at, purpose, nonce)
    }

    fn issue_with_nonce(
        &self,
        peer: SocketAddress,
        original_destination_id: &[u8],
        issued_at: u64,
        purpose: QuicRetryPurpose,
        nonce: [u8; NONCE_LENGTH],
    ) -> Result<Vector<u8>, QuicError> {
        if original_destination_id.len() > MAX_CONNECTION_ID_LENGTH {
            return Err(QuicError::ConnectionId);
        }
        let mut plain = Vector::new();
        plain
            .try_push(purpose as u8)
            .map_err(|_| QuicError::Allocation)?;
        plain
            .try_extend_from_slice(&issued_at.to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        plain
            .try_extend_from_slice(&peer.ip)
            .map_err(|_| QuicError::Allocation)?;
        plain
            .try_extend_from_slice(&peer.port.to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        plain
            .try_push(original_destination_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        plain
            .try_extend_from_slice(original_destination_id)
            .map_err(|_| QuicError::Allocation)?;

        let mut token = Vector::new();
        token
            .try_push(TOKEN_VERSION)
            .map_err(|_| QuicError::Allocation)?;
        token
            .try_extend_from_slice(&self.current.generation.to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        token
            .try_extend_from_slice(&nonce)
            .map_err(|_| QuicError::Allocation)?;
        let aad_length = token.len();
        let mut encrypted = Vector::new();
        encrypted
            .try_resize(plain.len(), 0)
            .map_err(|_| QuicError::Allocation)?;
        let mut tag = [0; TAG_LENGTH];
        if !aes128_gcm_seal(
            &self.current.key,
            &nonce,
            &token[..aad_length],
            &plain,
            &mut encrypted,
            &mut tag,
        ) {
            return Err(QuicError::Crypto);
        }
        token
            .try_extend_from_slice(&encrypted)
            .map_err(|_| QuicError::Allocation)?;
        token
            .try_extend_from_slice(&tag)
            .map_err(|_| QuicError::Allocation)?;
        Ok(token)
    }

    pub fn verify_and_consume(
        &mut self,
        token: &[u8],
        peer: SocketAddress,
        original_destination_id: &[u8],
        now: u64,
        purpose: QuicRetryPurpose,
    ) -> Result<(), QuicError> {
        if token.len() < 1 + 8 + NONCE_LENGTH + FIXED_PLAINTEXT_LENGTH + TAG_LENGTH
            || token.len() > MAX_TOKEN_LENGTH
            || original_destination_id.len() > MAX_CONNECTION_ID_LENGTH
            || token[0] != TOKEN_VERSION
        {
            return Err(QuicError::InvalidPacket);
        }
        let generation = u64::from_be_bytes(
            token[1..9]
                .try_into()
                .map_err(|_| QuicError::InvalidPacket)?,
        );
        let key = if generation == self.current.generation {
            self.current.key
        } else if self.previous.map(|key| key.generation) == Some(generation) {
            self.previous.ok_or(QuicError::Crypto)?.key
        } else {
            return Err(QuicError::Crypto);
        };
        let nonce: [u8; NONCE_LENGTH] = token[9..21]
            .try_into()
            .map_err(|_| QuicError::InvalidPacket)?;
        let encrypted_end = token.len() - TAG_LENGTH;
        let mut plain = Vector::new();
        plain
            .try_resize(encrypted_end - 21, 0)
            .map_err(|_| QuicError::Allocation)?;
        let tag: [u8; TAG_LENGTH] = token[encrypted_end..]
            .try_into()
            .map_err(|_| QuicError::InvalidPacket)?;
        if !aes128_gcm_open(
            &key,
            &nonce,
            &token[..21],
            &token[21..encrypted_end],
            &tag,
            &mut plain,
        ) {
            return Err(QuicError::Crypto);
        }
        let issued_at = u64::from_be_bytes(
            plain[1..9]
                .try_into()
                .map_err(|_| QuicError::InvalidPacket)?,
        );
        let expires_at = issued_at
            .checked_add(self.lifetime_seconds)
            .ok_or(QuicError::Limit)?;
        let id_length = plain[15] as usize;
        if plain[0] != purpose as u8
            || plain[9..13] != peer.ip
            || plain[13..15] != peer.port.to_be_bytes()
            || plain.len() != FIXED_PLAINTEXT_LENGTH + id_length
            || plain[16..] != *original_destination_id
            || now < issued_at
            || now > expires_at
        {
            return Err(QuicError::ProtocolViolation);
        }

        let mut index = 0;
        while index < self.consumed.len() {
            if self.consumed[index].expires_at < now {
                self.consumed.remove(index);
            } else {
                index += 1;
            }
        }
        let mut hash = Sha256::new();
        hash.update(token);
        let digest = hash.finalize();
        if self.consumed.iter().any(|entry| entry.digest == digest) {
            return Err(QuicError::ProtocolViolation);
        }
        if self.consumed.len() >= MAX_CONSUMED_TOKENS {
            return Err(QuicError::Limit);
        }
        self.consumed
            .try_push(ConsumedToken { digest, expires_at })
            .map_err(|_| QuicError::Allocation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddress {
        SocketAddress {
            ip: [192, 0, 2, 7],
            port,
        }
    }

    #[test]
    fn token_binds_peer_dcid_time_generation_and_single_use() {
        let key = QuicRetryKey {
            generation: 4,
            key: [0x51; 16],
        };
        let mut manager = QuicRetryTokenManager::new(key, 30).unwrap();
        let token = manager
            .issue_with_nonce(
                peer(4433),
                b"original",
                100,
                QuicRetryPurpose::AddressValidation,
                [7; 12],
            )
            .unwrap();
        let mut changed = token.clone();
        changed[24] ^= 1;
        assert_eq!(
            manager.verify_and_consume(
                &changed,
                peer(4433),
                b"original",
                110,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::Crypto)
        );
        assert_eq!(
            manager.verify_and_consume(
                &token,
                peer(4434),
                b"original",
                110,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::ProtocolViolation)
        );
        assert_eq!(
            manager.verify_and_consume(
                &token,
                peer(4433),
                b"other",
                110,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::ProtocolViolation)
        );
        assert_eq!(
            manager.verify_and_consume(
                &token,
                peer(4433),
                b"original",
                131,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::ProtocolViolation)
        );
        assert_eq!(
            manager.verify_and_consume(
                &token,
                peer(4433),
                b"original",
                110,
                QuicRetryPurpose::AddressValidation
            ),
            Ok(())
        );
        assert_eq!(
            manager.verify_and_consume(
                &token,
                peer(4433),
                b"original",
                110,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::ProtocolViolation)
        );
    }

    #[test]
    fn rotation_accepts_only_current_and_one_previous_generation() {
        let first = QuicRetryKey {
            generation: 1,
            key: [1; 16],
        };
        let mut manager = QuicRetryTokenManager::new(first, 30).unwrap();
        let old = manager
            .issue_with_nonce(
                peer(443),
                b"a",
                10,
                QuicRetryPurpose::AddressValidation,
                [1; 12],
            )
            .unwrap();
        manager
            .rotate(QuicRetryKey {
                generation: 2,
                key: [2; 16],
            })
            .unwrap();
        assert_eq!(
            manager.verify_and_consume(
                &old,
                peer(443),
                b"a",
                11,
                QuicRetryPurpose::AddressValidation
            ),
            Ok(())
        );
        manager
            .rotate(QuicRetryKey {
                generation: 3,
                key: [3; 16],
            })
            .unwrap();
        let stale = QuicRetryTokenManager::new(first, 30)
            .unwrap()
            .issue_with_nonce(
                peer(443),
                b"b",
                10,
                QuicRetryPurpose::AddressValidation,
                [2; 12],
            )
            .unwrap();
        assert_eq!(
            manager.verify_and_consume(
                &stale,
                peer(443),
                b"b",
                11,
                QuicRetryPurpose::AddressValidation
            ),
            Err(QuicError::Crypto)
        );
    }
}
