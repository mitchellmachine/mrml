use crate::{BackupError, SealedKeyProvider, SecretHandle, MAX_SEALED_KEY_BYTES};
use mrml_crypto::Sha256;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SealKeyCapabilityReceipt {
    pub key_identity: [u8; 32],
    pub provider_generation: u64,
    pub recovery_policy_digest: [u8; 32],
    pub written: u16,
    pub sealed_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RestoreKeyCapabilityReceipt {
    pub key_identity: [u8; 32],
    pub provider_generation: u64,
    pub recovery_policy_digest: [u8; 32],
    pub sealed_digest: [u8; 32],
}

/// Attenuated route to a platform key service. The backend sees only an opaque
/// key handle for sealing and returns only a new opaque use-only handle on
/// restore; this interface has no private-key export operation.
pub trait SealedKeyCapabilityBackend {
    type Error;

    fn seal(
        &mut self,
        handle: SecretHandle,
        recovery_policy_digest: [u8; 32],
        output: &mut [u8],
    ) -> Result<SealKeyCapabilityReceipt, Self::Error>;

    fn restore(
        &mut self,
        expected_identity: [u8; 32],
        recovery_policy_digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<RestoreKeyCapabilityReceipt, Self::Error>;
}

pub struct CapabilitySealedKeyProvider<B> {
    backend: B,
}

impl<B> CapabilitySealedKeyProvider<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: SealedKeyCapabilityBackend> SealedKeyProvider for CapabilitySealedKeyProvider<B> {
    fn seal_key(
        &mut self,
        handle: SecretHandle,
        recovery_policy_digest: [u8; 32],
        output: &mut [u8],
    ) -> Result<usize, BackupError> {
        if handle.identity == [0; 32]
            || handle.provider_generation == 0
            || recovery_policy_digest == [0; 32]
            || output.is_empty()
            || output.len() > MAX_SEALED_KEY_BYTES
        {
            output.fill(0);
            return Err(BackupError::InvalidSealedKey);
        }
        output.fill(0);
        let receipt = match self.backend.seal(handle, recovery_policy_digest, output) {
            Ok(receipt) => receipt,
            Err(_) => {
                output.fill(0);
                return Err(BackupError::SealingUnavailable);
            }
        };
        let written = usize::from(receipt.written);
        if receipt.key_identity != handle.identity
            || receipt.provider_generation != handle.provider_generation
            || receipt.recovery_policy_digest != recovery_policy_digest
            || written == 0
            || written > output.len()
            || receipt.sealed_digest != Sha256::digest(&output[..written])
        {
            output.fill(0);
            return Err(BackupError::RestoreBindingMismatch);
        }
        output[written..].fill(0);
        Ok(written)
    }

    fn restore_key(
        &mut self,
        expected_identity: [u8; 32],
        recovery_policy_digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<SecretHandle, BackupError> {
        if expected_identity == [0; 32]
            || recovery_policy_digest == [0; 32]
            || sealed.is_empty()
            || sealed.len() > MAX_SEALED_KEY_BYTES
        {
            return Err(BackupError::InvalidSealedKey);
        }
        let receipt = self
            .backend
            .restore(expected_identity, recovery_policy_digest, sealed)
            .map_err(|_| BackupError::SealingUnavailable)?;
        if receipt.key_identity != expected_identity
            || receipt.provider_generation == 0
            || receipt.recovery_policy_digest != recovery_policy_digest
            || receipt.sealed_digest != Sha256::digest(sealed)
        {
            return Err(BackupError::RestoreBindingMismatch);
        }
        Ok(SecretHandle {
            identity: receipt.key_identity,
            provider_generation: receipt.provider_generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend {
        substitute: bool,
        fail: bool,
    }
    impl SealedKeyCapabilityBackend for Backend {
        type Error = ();
        fn seal(
            &mut self,
            handle: SecretHandle,
            policy: [u8; 32],
            output: &mut [u8],
        ) -> Result<SealKeyCapabilityReceipt, Self::Error> {
            if self.fail {
                return Err(());
            }
            output[..4].copy_from_slice(b"seal");
            Ok(SealKeyCapabilityReceipt {
                key_identity: if self.substitute {
                    [9; 32]
                } else {
                    handle.identity
                },
                provider_generation: handle.provider_generation,
                recovery_policy_digest: policy,
                written: 4,
                sealed_digest: Sha256::digest(b"seal"),
            })
        }
        fn restore(
            &mut self,
            identity: [u8; 32],
            policy: [u8; 32],
            sealed: &[u8],
        ) -> Result<RestoreKeyCapabilityReceipt, Self::Error> {
            if self.fail {
                return Err(());
            }
            Ok(RestoreKeyCapabilityReceipt {
                key_identity: if self.substitute { [9; 32] } else { identity },
                provider_generation: 17,
                recovery_policy_digest: policy,
                sealed_digest: Sha256::digest(sealed),
            })
        }
    }

    #[test]
    fn capability_provider_binds_seal_and_restore_receipts_without_key_export() {
        let mut provider = CapabilitySealedKeyProvider::new(Backend {
            substitute: false,
            fail: false,
        });
        let handle = SecretHandle {
            identity: [3; 32],
            provider_generation: 8,
        };
        let mut output = [0xa5; 64];
        assert_eq!(provider.seal_key(handle, [4; 32], &mut output), Ok(4));
        assert_eq!(&output[..4], b"seal");
        assert!(output[4..].iter().all(|byte| *byte == 0));
        let restored = provider.restore_key([3; 32], [4; 32], b"seal").unwrap();
        assert!(
            restored
                == SecretHandle {
                    identity: [3; 32],
                    provider_generation: 17,
                }
        );
    }

    #[test]
    fn substituted_or_unavailable_capability_fails_and_clears_output() {
        let mut provider = CapabilitySealedKeyProvider::new(Backend {
            substitute: true,
            fail: false,
        });
        let mut output = [0xa5; 64];
        assert_eq!(
            provider.seal_key(
                SecretHandle {
                    identity: [3; 32],
                    provider_generation: 8,
                },
                [4; 32],
                &mut output,
            ),
            Err(BackupError::RestoreBindingMismatch)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            provider.restore_key([3; 32], [4; 32], b"seal"),
            Err(BackupError::RestoreBindingMismatch)
        ));
        let mut unavailable = CapabilitySealedKeyProvider::new(Backend {
            substitute: false,
            fail: true,
        });
        assert!(matches!(
            unavailable.restore_key([3; 32], [4; 32], b"seal"),
            Err(BackupError::SealingUnavailable)
        ));
    }
}
