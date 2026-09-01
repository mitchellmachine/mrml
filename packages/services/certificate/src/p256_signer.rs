use crate::{
    ApprovedTls13CertificateVerify, IdentityError, TlsCertificateSigningKey, TlsKeyIdentity,
    TlsSigningRoute,
};
use mrml_acme::{
    AcmeJwsSigner, ApprovedAcmeJwsDigest, ApprovedCsrDigest, CsrError, Es256Signature, JoseError,
    P256Jwk, Pkcs10Signer,
};
use mrml_crypto::{P256Error, P256SecretKey, Sha256};

pub struct AccountP256SigningKey {
    key: P256SecretKey,
    directory_generation: u64,
    account_generation: u64,
}

impl AccountP256SigningKey {
    pub fn generate(
        directory_generation: u64,
        account_generation: u64,
        entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<Self, P256Error> {
        Ok(Self {
            key: P256SecretKey::generate_with(entropy)?,
            directory_generation,
            account_generation,
        })
    }

    pub fn public_jwk(&self) -> Result<P256Jwk, P256Error> {
        let public = self.key.public_key()?;
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&public[1..33]);
        y.copy_from_slice(&public[33..]);
        P256Jwk::from_coordinates(x, y).map_err(|_| P256Error::InvalidKey)
    }

    pub fn authorize_generation(&mut self, directory_generation: u64, account_generation: u64) {
        self.directory_generation = directory_generation;
        self.account_generation = account_generation;
    }
}

impl AcmeJwsSigner for AccountP256SigningKey {
    fn sign_acme_jws(
        &mut self,
        approved: &ApprovedAcmeJwsDigest,
    ) -> Result<Es256Signature, JoseError> {
        if approved.directory_generation != self.directory_generation
            || approved.account_generation != self.account_generation
        {
            return Err(JoseError::SigningUnavailable);
        }
        let raw = self
            .key
            .sign_digest_raw(approved.digest())
            .map_err(|_| JoseError::SigningUnavailable)?;
        Es256Signature::from_raw(raw)
    }
}

pub struct CertificateP256SigningKey {
    key: P256SecretKey,
    key_generation: u64,
    policy_generation: u64,
    identifier_set_digest: [u8; 32],
    route: TlsSigningRoute,
}

impl CertificateP256SigningKey {
    pub fn generate(
        key_generation: u64,
        policy_generation: u64,
        identifier_set_digest: [u8; 32],
        mut route: TlsSigningRoute,
        entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<Self, P256Error> {
        let key = P256SecretKey::generate_with(entropy)?;
        let public = key.public_key()?;
        route.key_identity = derive_key_identity(&public);
        Ok(Self {
            key,
            key_generation,
            policy_generation,
            identifier_set_digest,
            route,
        })
    }

    pub fn route(&self) -> TlsSigningRoute {
        self.route
    }

    pub fn public_jwk(&self) -> Result<P256Jwk, P256Error> {
        let public = self.key.public_key()?;
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&public[1..33]);
        y.copy_from_slice(&public[33..]);
        P256Jwk::from_coordinates(x, y).map_err(|_| P256Error::InvalidKey)
    }
}

impl Pkcs10Signer for CertificateP256SigningKey {
    fn sign_pkcs10(&mut self, approved: &ApprovedCsrDigest) -> Result<Es256Signature, CsrError> {
        if approved.key_generation != self.key_generation
            || approved.policy_generation != self.policy_generation
            || approved.identifier_set_digest != self.identifier_set_digest
        {
            return Err(CsrError::SigningUnavailable);
        }
        let raw = self
            .key
            .sign_digest_raw(approved.digest())
            .map_err(|_| CsrError::SigningUnavailable)?;
        Es256Signature::from_raw(raw).map_err(|_| CsrError::InvalidSignature)
    }
}

impl TlsCertificateSigningKey for CertificateP256SigningKey {
    fn describe_public_key(
        &mut self,
        route: TlsSigningRoute,
        output: &mut [u8],
    ) -> Result<usize, IdentityError> {
        if route != self.route {
            return Err(IdentityError::ReceiptMismatch);
        }
        let public = self
            .key
            .public_key()
            .map_err(|_| IdentityError::SigningUnavailable)?;
        if output.len() < public.len() {
            return Err(IdentityError::OutputTooSmall);
        }
        output[..public.len()].copy_from_slice(&public);
        Ok(public.len())
    }

    fn sign_tls13_certificate_verify(
        &mut self,
        approved: &ApprovedTls13CertificateVerify,
    ) -> Result<Es256Signature, IdentityError> {
        if approved.identity != self.route.identity
            || approved.identity_generation != self.route.identity_generation
            || approved.key_identity != self.route.key_identity
            || approved.route_generation != self.route.route_generation
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let raw = self
            .key
            .sign_digest_raw(approved.digest())
            .map_err(|_| IdentityError::SigningUnavailable)?;
        Es256Signature::from_raw(raw).map_err(|_| IdentityError::SigningUnavailable)
    }
}

fn derive_key_identity(public: &[u8; 65]) -> TlsKeyIdentity {
    let mut digest = Sha256::new();
    digest.update(b"mrml-tls-p256-key-identity-v1\0");
    digest.update(public);
    TlsKeyIdentity(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TlsIdentityId;
    use mrml_acme::{
        AcmeExchange, DeterministicAcmeAuthority, FirstPartyP256JwsVerifier, LOCAL_DIRECTORY_URL,
        ProtectedKey, fetch_directory, post_jws, write_pkcs10_csr,
    };
    use mrml_crypto::ecdsa_p256_digest_verify_raw;

    #[test]
    fn account_and_certificate_keys_are_distinct_use_only_signers() {
        let mut account_draw = [1u8; 32];
        account_draw[31] = 3;
        let mut account = AccountP256SigningKey::generate(5, 0, |output| {
            output.copy_from_slice(&account_draw);
            Ok(())
        })
        .unwrap();
        let route = TlsSigningRoute {
            identity: TlsIdentityId([7; 16]),
            identity_generation: 2,
            key_identity: TlsKeyIdentity([0; 32]),
            route_generation: 4,
            capability_id: [8; 16],
        };
        let mut certificate_draw = [2u8; 32];
        certificate_draw[31] = 9;
        let mut certificate = CertificateP256SigningKey::generate(3, 6, [9; 32], route, |output| {
            output.copy_from_slice(&certificate_draw);
            Ok(())
        })
        .unwrap();
        let account_public = account.public_jwk().unwrap().sec1_uncompressed();
        let certificate_public = certificate.public_jwk().unwrap().sec1_uncompressed();
        assert_ne!(account_public, certificate_public);
        let approved = ApprovedTls13CertificateVerify::new([4; 32], certificate.route());
        let signature = certificate
            .sign_tls13_certificate_verify(&approved)
            .unwrap();
        assert!(
            ecdsa_p256_digest_verify_raw(
                &certificate_public,
                approved.digest(),
                signature.as_bytes()
            )
            .is_ok()
        );
        let mut wrong = certificate.route();
        wrong.identity_generation += 1;
        let wrong = ApprovedTls13CertificateVerify::new([4; 32], wrong);
        assert!(certificate.sign_tls13_certificate_verify(&wrong).is_err());
        account.authorize_generation(6, 1);
    }

    #[test]
    fn account_signer_completes_real_es256_jws_and_certificate_signer_emits_csr() {
        let mut draw = [3u8; 32];
        draw[31] = 11;
        let mut account = AccountP256SigningKey::generate(11, 0, |output| {
            output.copy_from_slice(&draw);
            Ok(())
        })
        .unwrap();
        let public = account.public_jwk().unwrap();
        let directory_url = mrml_acme::AcmeUrl::parse(LOCAL_DIRECTORY_URL, false).unwrap();
        let mut exchange = AcmeExchange::new(11, directory_url);
        let mut authority = DeterministicAcmeAuthority::new(FirstPartyP256JwsVerifier, public);
        let mut response = [0u8; 65_536];
        let mut jws = [0u8; 49_152];
        let directory = fetch_directory(
            &directory_url,
            11,
            &mut exchange,
            &mut authority,
            &mut response,
        )
        .unwrap();
        let result = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &directory.new_account,
            ProtectedKey::Jwk(&public),
            b"{}",
            0,
            &mut account,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(result.metadata.status, 201);

        let identifier = mrml_acme::DnsIdentifier::parse("git.example", false).unwrap();
        let mut identifier_hasher = mrml_crypto::Sha256::new();
        identifier_hasher.update(b"mrml-acme-csr-identifiers-v1\0");
        identifier_hasher.update(&(identifier.as_str().len() as u16).to_be_bytes());
        identifier_hasher.update(identifier.as_str().as_bytes());
        let identifier_digest = identifier_hasher.finalize();
        let route = TlsSigningRoute {
            identity: TlsIdentityId([4; 16]),
            identity_generation: 1,
            key_identity: TlsKeyIdentity([0; 32]),
            route_generation: 1,
            capability_id: [5; 16],
        };
        let mut certificate =
            CertificateP256SigningKey::generate(7, 9, identifier_digest, route, |output| {
                output.copy_from_slice(&[4; 32]);
                Ok(())
            })
            .unwrap();
        let public = certificate.public_jwk().unwrap();
        let mut csr = [0u8; mrml_acme::MAX_CSR_BYTES];
        let written = write_pkcs10_csr(
            &public,
            &[identifier],
            false,
            7,
            9,
            &mut certificate,
            &mut csr,
        );
        assert!(written.is_ok());
        assert_eq!(csr[0], 0x30);
    }
}
