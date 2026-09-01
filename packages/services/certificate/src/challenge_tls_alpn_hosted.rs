use crate::{ApprovedTls13CertificateVerify, TlsCertificateSigningKey, TlsSigningRoute};
use mrml_acme::{
    ACME_TLS_ALPN_PROTOCOL, AcmeIdentifier, ChallengeKind, ChallengePublicationRequest,
};
use mrml_crypto::encode_der_signature;
use mrml_runtime::{NetError, SpinMutex, TcpListener};
use mrml_tls::{
    ECDSA_SECP256R1_SHA256, MAX_TLS13_SIGNATURE_BYTES, TlsError, TlsServerConfig,
    TlsServerSigningKey, TlsServerStream,
};

pub const TLS_ALPN01_READ_TIMEOUT_MILLIS: u64 = 2_000;
pub const TLS_ALPN01_WRITE_TIMEOUT_MILLIS: u64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedTlsAlpn01Error {
    InvalidChallenge,
    NotActive,
    Expired,
    Network(NetError),
    Tls(TlsError),
}

pub trait TemporaryTlsAlpnSigningKey: TlsCertificateSigningKey + Send {
    /// Irreversibly retires and zeroizes the temporary key-provider object.
    fn retire(&mut self);
}

struct TemporarySigningAdapter<K: TemporaryTlsAlpnSigningKey> {
    route: TlsSigningRoute,
    key: SpinMutex<K>,
}

impl<K: TemporaryTlsAlpnSigningKey> TemporarySigningAdapter<K> {
    const fn new(route: TlsSigningRoute, key: K) -> Self {
        Self {
            route,
            key: SpinMutex::new(key),
        }
    }
}

impl<K: TemporaryTlsAlpnSigningKey> TlsServerSigningKey for TemporarySigningAdapter<K> {
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

impl<K: TemporaryTlsAlpnSigningKey> Drop for TemporarySigningAdapter<K> {
    fn drop(&mut self) {
        self.key.lock().retire();
    }
}

pub struct HostedTlsAlpn01Challenge {
    request: ChallengePublicationRequest,
    config: TlsServerConfig,
}

impl HostedTlsAlpn01Challenge {
    pub fn new<K: TemporaryTlsAlpnSigningKey + 'static>(
        request: ChallengePublicationRequest,
        certificate_der: &[u8],
        route: TlsSigningRoute,
        mut key: K,
    ) -> Result<Self, HostedTlsAlpn01Error> {
        let AcmeIdentifier::Dns(identifier) = request.identifier else {
            key.retire();
            return Err(HostedTlsAlpn01Error::InvalidChallenge);
        };
        if request.kind != ChallengeKind::TlsAlpn01
            || request.identifier.is_wildcard()
            || certificate_der.is_empty()
            || route.identity_generation != request.challenge_generation
        {
            key.retire();
            return Err(HostedTlsAlpn01Error::InvalidChallenge);
        }
        if mrml_tls::Certificate::parse(certificate_der)
            .and_then(|certificate| {
                certificate
                    .require_tls_alpn01(identifier.as_str(), &request.key_authorization_digest)
            })
            .is_err()
        {
            key.retire();
            return Err(HostedTlsAlpn01Error::InvalidChallenge);
        }
        let protocol = match core::str::from_utf8(ACME_TLS_ALPN_PROTOCOL) {
            Ok(value) => value,
            Err(_) => {
                key.retire();
                return Err(HostedTlsAlpn01Error::InvalidChallenge);
            }
        };
        let config = match TlsServerConfig::from_der_chain(&[certificate_der]) {
            Ok(value) => value,
            Err(error) => {
                key.retire();
                return Err(HostedTlsAlpn01Error::Tls(error));
            }
        };
        let config = match config.require_server_name(identifier.as_str()) {
            Ok(value) => value,
            Err(error) => {
                key.retire();
                return Err(HostedTlsAlpn01Error::Tls(error));
            }
        };
        let config = match config.with_protocols(&[protocol]) {
            Ok(value) => value,
            Err(error) => {
                key.retire();
                return Err(HostedTlsAlpn01Error::Tls(error));
            }
        }
        .with_signing_key(TemporarySigningAdapter::new(route, key));
        Ok(Self { request, config })
    }

    pub fn serve_one(
        &self,
        listener: &TcpListener,
        now_unix: u64,
    ) -> Result<(), HostedTlsAlpn01Error> {
        if now_unix < self.request.not_before_unix {
            return Err(HostedTlsAlpn01Error::NotActive);
        }
        if now_unix >= self.request.expires_unix {
            return Err(HostedTlsAlpn01Error::Expired);
        }
        let stream = listener.accept().map_err(HostedTlsAlpn01Error::Network)?;
        stream
            .set_read_timeout_millis(TLS_ALPN01_READ_TIMEOUT_MILLIS)
            .map_err(HostedTlsAlpn01Error::Network)?;
        stream
            .set_write_timeout_millis(TLS_ALPN01_WRITE_TIMEOUT_MILLIS)
            .map_err(HostedTlsAlpn01Error::Network)?;
        let tls =
            TlsServerStream::accept(stream, &self.config).map_err(HostedTlsAlpn01Error::Tls)?;
        if tls.negotiated_protocol() != core::str::from_utf8(ACME_TLS_ALPN_PROTOCOL).ok() {
            return Err(HostedTlsAlpn01Error::InvalidChallenge);
        }
        Ok(())
    }

    pub const fn challenge_generation(&self) -> u64 {
        self.request.challenge_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityError, TlsIdentityId, TlsKeyIdentity};
    use core::sync::atomic::{AtomicBool, Ordering};
    use mrml_acme::{
        AcmeUrl, ChallengeLifecycle, ChallengeToken, DnsIdentifier, Es256Signature, JwkThumbprint,
    };
    use mrml_runtime::Shared;

    struct Key {
        retired: Shared<AtomicBool>,
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
            _: &ApprovedTls13CertificateVerify,
        ) -> Result<mrml_acme::Es256Signature, IdentityError> {
            Es256Signature::from_raw([1; 64]).map_err(|_| IdentityError::InvalidState)
        }
    }
    impl TemporaryTlsAlpnSigningKey for Key {
        fn retire(&mut self) {
            self.retired.store(true, Ordering::SeqCst);
        }
    }

    fn request() -> ChallengePublicationRequest {
        ChallengeLifecycle::new(
            4,
            &AcmeUrl::parse("https://ca.example/order/1", false).unwrap(),
            &AcmeUrl::parse("https://ca.example/authz/1", false).unwrap(),
            mrml_acme::AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap()),
            ChallengeKind::TlsAlpn01,
            ChallengeToken::parse("tls-token").unwrap(),
            JwkThumbprint([3; 32]),
            10,
            20,
            1,
        )
        .unwrap()
        .request
    }

    #[test]
    fn activation_is_exact_sni_alpn_and_retires_temporary_key() {
        let retired = Shared::new(AtomicBool::new(false));
        let route = TlsSigningRoute {
            identity: TlsIdentityId([1; 16]),
            identity_generation: 4,
            key_identity: TlsKeyIdentity([2; 32]),
            route_generation: 5,
            capability_id: [6; 16],
        };
        assert!(matches!(
            HostedTlsAlpn01Challenge::new(
                request(),
                &[0x30, 0x00],
                route,
                Key {
                    retired: retired.clone(),
                },
            ),
            Err(HostedTlsAlpn01Error::InvalidChallenge)
        ));
        assert!(retired.load(Ordering::SeqCst));
        let wrong_route = TlsSigningRoute {
            identity_generation: 3,
            ..route
        };
        assert!(matches!(
            HostedTlsAlpn01Challenge::new(
                request(),
                &[0x30, 0x00],
                wrong_route,
                Key {
                    retired: Shared::new(AtomicBool::new(false))
                }
            ),
            Err(HostedTlsAlpn01Error::InvalidChallenge)
        ));
    }

    #[cfg(unix)]
    struct OpenSslTestKey {
        private_key_path: mrml_runtime::Text,
        digest_path: mrml_runtime::Text,
        signature_path: mrml_runtime::Text,
        retired: Shared<AtomicBool>,
    }

    #[cfg(unix)]
    impl TlsCertificateSigningKey for OpenSslTestKey {
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
            mrml_runtime::write_file(&self.digest_path, approved.digest())
                .map_err(|_| IdentityError::SigningUnavailable)?;
            let result = mrml_runtime::Command::new("openssl")
                .args(["pkeyutl", "-sign", "-inkey"])
                .arg(&self.private_key_path)
                .args(["-in"])
                .arg(&self.digest_path)
                .args(["-pkeyopt", "digest:sha256", "-out"])
                .arg(&self.signature_path)
                .output()
                .map_err(|_| IdentityError::SigningUnavailable)?;
            if !result.status.success() {
                return Err(IdentityError::SigningUnavailable);
            }
            let der = mrml_runtime::read_file(&self.signature_path)
                .map_err(|_| IdentityError::SigningUnavailable)?;
            let raw = decode_test_ecdsa_der(&der).ok_or(IdentityError::SigningUnavailable)?;
            Es256Signature::from_raw(raw).map_err(|_| IdentityError::SigningUnavailable)
        }
    }

    #[cfg(unix)]
    impl TemporaryTlsAlpnSigningKey for OpenSslTestKey {
        fn retire(&mut self) {
            let _ = mrml_runtime::remove_file(&self.private_key_path);
            let _ = mrml_runtime::remove_file(&self.digest_path);
            let _ = mrml_runtime::remove_file(&self.signature_path);
            self.retired.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    fn decode_test_ecdsa_der(der: &[u8]) -> Option<[u8; 64]> {
        if der.len() < 8 || der[0] != 0x30 || usize::from(der[1]) + 2 != der.len() {
            return None;
        }
        let mut at = 2usize;
        let mut raw = [0; 64];
        for output_offset in [0usize, 32] {
            if der.get(at) != Some(&2) {
                return None;
            }
            let length = usize::from(*der.get(at + 1)?);
            at += 2;
            let mut value = der.get(at..at.checked_add(length)?)?;
            at += length;
            if value.first() == Some(&0) {
                value = &value[1..];
            }
            if value.is_empty() || value.len() > 32 {
                return None;
            }
            let start = output_offset + 32 - value.len();
            raw[start..output_offset + 32].copy_from_slice(value);
        }
        (at == der.len()).then_some(raw)
    }

    #[cfg(unix)]
    fn test_hex(value: &[u8; 32]) -> [u8; 64] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = [0; 64];
        for (index, byte) in value.iter().enumerate() {
            output[index * 2] = HEX[usize::from(byte >> 4)];
            output[index * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        output
    }

    #[cfg(unix)]
    #[test]
    fn tcp_443_role_completes_exact_acme_tls_1_loopback() {
        let stem =
            mrml_runtime::mrml_format!("/tmp/mrml-certd-tls-alpn-{}", mrml_runtime::process_id());
        let key_path = mrml_runtime::mrml_format!("{stem}.key.pem");
        let cert_path = mrml_runtime::mrml_format!("{stem}.cert.pem");
        let der_path = mrml_runtime::mrml_format!("{stem}.cert.der");
        let digest_path = mrml_runtime::mrml_format!("{stem}.digest");
        let signature_path = mrml_runtime::mrml_format!("{stem}.signature");
        let challenge_request = request();
        let digest_hex = test_hex(&challenge_request.key_authorization_digest);
        let digest_hex = core::str::from_utf8(&digest_hex).unwrap();
        let acme_extension =
            mrml_runtime::mrml_format!("1.3.6.1.5.5.7.1.31=critical,DER:0420{digest_hex}");
        let generated = mrml_runtime::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-subj",
                "/CN=git.example",
                "-days",
                "1",
                "-addext",
                "subjectAltName=critical,DNS:git.example",
                "-addext",
            ])
            .arg(&acme_extension)
            .args(["-keyout"])
            .arg(&key_path)
            .args(["-out"])
            .arg(&cert_path)
            .output()
            .unwrap();
        assert!(generated.status.success());
        let converted = mrml_runtime::Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&cert_path)
            .args(["-outform", "DER", "-out"])
            .arg(&der_path)
            .output()
            .unwrap();
        assert!(converted.status.success());
        let certificate_der = mrml_runtime::read_file(&der_path).unwrap();
        let retired = Shared::new(AtomicBool::new(false));
        let route = TlsSigningRoute {
            identity: TlsIdentityId([1; 16]),
            identity_generation: 4,
            key_identity: TlsKeyIdentity([2; 32]),
            route_generation: 5,
            capability_id: [6; 16],
        };
        let challenge = HostedTlsAlpn01Challenge::new(
            challenge_request,
            &certificate_der,
            route,
            OpenSslTestKey {
                private_key_path: key_path.clone(),
                digest_path: digest_path.clone(),
                signature_path: signature_path.clone(),
                retired: retired.clone(),
            },
        )
        .unwrap();
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let completed = Shared::new(AtomicBool::new(false));
        let completed_server = completed.clone();
        let server_error = Shared::new(SpinMutex::new(None));
        let server_error_writer = server_error.clone();
        assert!(
            mrml_runtime::spawn_detached(move || {
                *server_error_writer.lock() = challenge.serve_one(&listener, 15).err();
                completed_server.store(true, Ordering::SeqCst);
            })
            .is_ok()
        );
        let client_result = mrml_tls::TlsClientStream::connect_resolved_for_acme_tls_alpn01(
            "git.example",
            [127, 0, 0, 1],
            port,
            challenge_request.key_authorization_digest,
        );
        while !completed.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        assert!(
            client_result.is_ok(),
            "client={:?} server={:?}",
            client_result.as_ref().err(),
            *server_error.lock()
        );
        let client = client_result.unwrap();
        assert_eq!(client.negotiated_protocol(), Some("acme-tls/1"));
        drop(client);
        for _ in 0..1000 {
            if completed.load(Ordering::SeqCst) && retired.load(Ordering::SeqCst) {
                break;
            }
            core::hint::spin_loop();
        }
        assert!(completed.load(Ordering::SeqCst));
        assert!(retired.load(Ordering::SeqCst));
        let _ = mrml_runtime::remove_file(&cert_path);
        let _ = mrml_runtime::remove_file(&der_path);
    }
}
