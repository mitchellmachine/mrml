use crate::{ApprovedTls13CertificateVerify, TlsCertificateSigningKey, TlsSigningRoute};
use mrml_crypto::encode_der_signature;
use mrml_runtime::SpinMutex;
use mrml_tls::{ECDSA_SECP256R1_SHA256, MAX_TLS13_SIGNATURE_BYTES, TlsError, TlsServerSigningKey};

/// Hosted adapter from the shared generation-bound certificate-key role to the
/// first-party TLS stack. The TLS server receives no key bytes and can request
/// only the fixed TLS 1.3 server CertificateVerify purpose.
pub struct IdentityTlsSigningAdapter<K> {
    route: TlsSigningRoute,
    key: SpinMutex<K>,
}

impl<K> IdentityTlsSigningAdapter<K> {
    pub const fn new(route: TlsSigningRoute, key: K) -> Self {
        Self {
            route,
            key: SpinMutex::new(key),
        }
    }
}

impl<K: TlsCertificateSigningKey + Send> TlsServerSigningKey for IdentityTlsSigningAdapter<K> {
    fn signature_scheme(&self) -> u16 {
        ECDSA_SECP256R1_SHA256
    }

    fn sign_certificate_verify_transcript(
        &self,
        transcript_digest: &[u8; 32],
        output: &mut [u8; MAX_TLS13_SIGNATURE_BYTES],
    ) -> Result<usize, TlsError> {
        let approved = ApprovedTls13CertificateVerify::new(*transcript_digest, self.route);
        let signature = self
            .key
            .lock()
            .sign_tls13_certificate_verify(&approved)
            .map_err(|_| TlsError::AuthenticationFailed)?;
        let encoded = encode_der_signature(signature.as_bytes(), output)
            .map_err(|_| TlsError::AuthenticationFailed)?;
        Ok(encoded.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityError, TlsIdentityId, TlsKeyIdentity};
    use mrml_acme::Es256Signature;

    struct Key {
        expected: TlsSigningRoute,
    }
    impl TlsCertificateSigningKey for Key {
        fn describe_public_key(
            &mut self,
            _: TlsSigningRoute,
            _: &mut [u8],
        ) -> Result<usize, IdentityError> {
            Err(IdentityError::InvalidState)
        }
        fn sign_tls13_certificate_verify(
            &mut self,
            approved: &ApprovedTls13CertificateVerify,
        ) -> Result<Es256Signature, IdentityError> {
            if approved.identity != self.expected.identity
                || approved.identity_generation != self.expected.identity_generation
                || approved.key_identity != self.expected.key_identity
                || approved.route_generation != self.expected.route_generation
            {
                return Err(IdentityError::ReceiptMismatch);
            }
            let mut raw = [1; 64];
            raw[0] = 2;
            Es256Signature::from_raw(raw).map_err(|_| IdentityError::InvalidState)
        }
    }

    #[test]
    fn binds_tls_context_to_exact_use_only_route_and_der_encodes() {
        let route = TlsSigningRoute {
            identity: TlsIdentityId([1; 16]),
            identity_generation: 4,
            key_identity: TlsKeyIdentity([2; 32]),
            route_generation: 7,
            capability_id: [3; 16],
        };
        let adapter = IdentityTlsSigningAdapter::new(route, Key { expected: route });
        let mut output = [0; MAX_TLS13_SIGNATURE_BYTES];
        let written = adapter
            .sign_certificate_verify_transcript(&[9; 32], &mut output)
            .unwrap();
        assert_eq!(adapter.signature_scheme(), ECDSA_SECP256R1_SHA256);
        assert_eq!(output[0], 0x30);
        assert_eq!(written, usize::from(output[1]) + 2);
    }
}
