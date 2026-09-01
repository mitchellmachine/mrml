use mrml_acme::{
    AccountLifecycle, AcmeDirectory, AcmeExchange, AcmeJwsSigner, AcmePostError, AcmeProblem,
    AcmeResponseType, AcmeTransport, AriCertificateId, CaClass, CertificateProfile, DnsIdentifier,
    OrderLifecycle, OrderState, P256Jwk, ProtectedKey, post_jws,
};
use mrml_crypto::Sha256;

pub const MAX_CERTIFICATE_CHAIN_BYTES: usize = 65_536;
pub const MAX_CERTIFICATE_DER_BYTES: usize = 16_384;
pub const MAX_CERTIFICATES: usize = 8;
pub const MAX_IDENTITY_NAMES: usize = 16;
pub const MAX_ALTERNATE_CHAINS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateValidationError {
    Oversized,
    MalformedPem,
    InvalidBase64,
    TooManyCertificates,
    EmptyChain,
    InvalidPolicy,
    InvalidCertificate,
    PublicKeyMismatch,
    IdentifierMismatch,
    InvalidPurpose,
    InvalidValidity,
    UntrustedChain,
    StagingProductionMismatch,
    AlternateChainNotApproved,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CertificateRetrievalError<E> {
    ResourceMismatch,
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    UnexpectedContentType,
    Validation(CertificateValidationError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Range {
    start: u16,
    len: u16,
}

pub struct PemCertificateChain {
    bytes: [u8; MAX_CERTIFICATE_CHAIN_BYTES],
    used: u16,
    ranges: [Option<Range>; MAX_CERTIFICATES],
    count: u8,
}

impl PemCertificateChain {
    pub fn parse(pem: &[u8]) -> Result<Self, CertificateValidationError> {
        if pem.len() > MAX_CERTIFICATE_CHAIN_BYTES {
            return Err(CertificateValidationError::Oversized);
        }
        let mut chain = Self {
            bytes: [0; MAX_CERTIFICATE_CHAIN_BYTES],
            used: 0,
            ranges: [None; MAX_CERTIFICATES],
            count: 0,
        };
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const END: &[u8] = b"-----END CERTIFICATE-----";
        let mut cursor = 0usize;
        while cursor < pem.len() {
            while pem.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if cursor == pem.len() {
                break;
            }
            if pem.get(cursor..cursor + BEGIN.len()) != Some(BEGIN) {
                return Err(CertificateValidationError::MalformedPem);
            }
            cursor += BEGIN.len();
            let end = find_bytes(&pem[cursor..], END)
                .map(|offset| cursor + offset)
                .ok_or(CertificateValidationError::MalformedPem)?;
            if usize::from(chain.count) >= MAX_CERTIFICATES {
                return Err(CertificateValidationError::TooManyCertificates);
            }
            let start = usize::from(chain.used);
            let remaining = chain
                .bytes
                .get_mut(start..)
                .ok_or(CertificateValidationError::Oversized)?;
            let limit = remaining.len().min(MAX_CERTIFICATE_DER_BYTES);
            let written = decode_pem_base64(&pem[cursor..end], &mut remaining[..limit])?;
            if written == 0 || written > MAX_CERTIFICATE_DER_BYTES {
                return Err(CertificateValidationError::MalformedPem);
            }
            chain.ranges[usize::from(chain.count)] = Some(Range {
                start: start as u16,
                len: written as u16,
            });
            chain.count += 1;
            chain.used = chain
                .used
                .checked_add(written as u16)
                .ok_or(CertificateValidationError::Oversized)?;
            cursor = end + END.len();
        }
        if chain.count == 0 {
            return Err(CertificateValidationError::EmptyChain);
        }
        Ok(chain)
    }

    pub fn count(&self) -> usize {
        usize::from(self.count)
    }

    pub fn certificate(&self, index: usize) -> Option<&[u8]> {
        let range = self.ranges.get(index).copied().flatten()?;
        self.bytes
            .get(usize::from(range.start)..usize::from(range.start) + usize::from(range.len))
    }

    pub fn chain_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"mrml-certificate-chain-v1\0");
        for index in 0..self.count() {
            let certificate = self.certificate(index).unwrap_or(&[]);
            digest.update(&(certificate.len() as u32).to_be_bytes());
            digest.update(certificate);
        }
        digest.finalize()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertificateValidationPolicy {
    pub policy_generation: u64,
    pub ca_class: CaClass,
    pub profile: CertificateProfile,
    pub order_url_digest: [u8; 32],
    pub expected_key: P256Jwk,
    pub identifiers: [Option<DnsIdentifier>; MAX_IDENTITY_NAMES],
    pub identifier_count: u8,
    pub now_unix: u64,
    pub maximum_validity_seconds: u64,
    pub maximum_chain_length: u8,
    pub trust_store_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifiedCertificateReceipt {
    pub policy_generation: u64,
    pub ca_class: CaClass,
    pub profile: CertificateProfile,
    pub order_url_digest: [u8; 32],
    pub chain_digest: [u8; 32],
    pub leaf_spki_digest: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub trust_store_digest: [u8; 32],
    pub ari_certificate_id: AriCertificateId,
}

pub struct RetrievedCertificate {
    pub chain: PemCertificateChain,
    pub receipt: VerifiedCertificateReceipt,
}

pub trait CertificateChainVerifier {
    fn verify(
        &mut self,
        chain: &PemCertificateChain,
        policy: &CertificateValidationPolicy,
    ) -> Result<VerifiedCertificateReceipt, CertificateValidationError>;
}

#[allow(clippy::too_many_arguments)]
pub fn retrieve_and_verify_certificate<T: AcmeTransport, V: CertificateChainVerifier>(
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    order: &OrderLifecycle,
    policy: &CertificateValidationPolicy,
    exchange: &mut AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    verifier: &mut V,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<RetrievedCertificate, CertificateRetrievalError<T::Error>> {
    let certificate_url = order
        .certificate_url
        .as_ref()
        .ok_or(CertificateRetrievalError::ResourceMismatch)?;
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(CertificateRetrievalError::ResourceMismatch)?;
    if !account.active
        || order.state != OrderState::Valid
        || directory.generation != order.directory_generation
        || account.generation != order.account_generation
        || account.key != order.account_key
        || policy.profile != order.profile
        || policy.order_url_digest != Sha256::digest(order.order_url.as_str().as_bytes())
        || usize::from(policy.identifier_count) != order.identifiers().count()
        || !policy.identifiers[..usize::from(policy.identifier_count)]
            .iter()
            .zip(order.identifiers())
            .all(|(provided, expected)| provided.as_ref() == Some(expected))
    {
        return Err(CertificateRetrievalError::ResourceMismatch);
    }
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        certificate_url,
        ProtectedKey::Kid(account_url),
        b"",
        account.generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(CertificateRetrievalError::Post)?;
    if let Some(problem) = result.problem {
        return Err(CertificateRetrievalError::Server(problem));
    }
    if result.metadata.status != 200 {
        return Err(CertificateRetrievalError::UnexpectedStatus);
    }
    if result.metadata.response_type != AcmeResponseType::PemCertificateChain {
        return Err(CertificateRetrievalError::UnexpectedContentType);
    }
    let chain = PemCertificateChain::parse(&response_body[..result.metadata.body_length])
        .map_err(CertificateRetrievalError::Validation)?;
    let receipt = verifier
        .verify(&chain, policy)
        .map_err(CertificateRetrievalError::Validation)?;
    Ok(RetrievedCertificate { chain, receipt })
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AlternateChainPolicy {
    /// Exact chain digests in descending owner preference. Empty policy means
    /// alternate-chain selection is disabled rather than trusting response
    /// order.
    pub preferred_chain_digests: [Option<[u8; 32]>; MAX_ALTERNATE_CHAINS],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SelectedCertificateChain {
    pub candidate_index: u8,
    pub preference_index: u8,
    pub receipt: VerifiedCertificateReceipt,
}

pub fn select_alternate_chain<V: CertificateChainVerifier>(
    candidates: &[&PemCertificateChain],
    policy: &CertificateValidationPolicy,
    alternate_policy: &AlternateChainPolicy,
    verifier: &mut V,
) -> Result<SelectedCertificateChain, CertificateValidationError> {
    if candidates.is_empty() || candidates.len() > MAX_ALTERNATE_CHAINS {
        return Err(CertificateValidationError::AlternateChainNotApproved);
    }
    let mut selected = None;
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let digest = candidate.chain_digest();
        let Some(preference_index) = alternate_policy
            .preferred_chain_digests
            .iter()
            .position(|approved| *approved == Some(digest))
        else {
            continue;
        };
        let receipt = verifier.verify(candidate, policy)?;
        let choice = SelectedCertificateChain {
            candidate_index: candidate_index as u8,
            preference_index: preference_index as u8,
            receipt,
        };
        if selected
            .as_ref()
            .is_none_or(|current: &SelectedCertificateChain| {
                choice.preference_index < current.preference_index
                    || (choice.preference_index == current.preference_index
                        && choice.receipt.chain_digest < current.receipt.chain_digest)
            })
        {
            selected = Some(choice);
        }
    }
    selected.ok_or(CertificateValidationError::AlternateChainNotApproved)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct HostedCertificateChainVerifier<'a> {
    pub ca_class: CaClass,
    pub trust_store_digest: [u8; 32],
    pub approved_roots: &'a [&'a [u8]],
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl CertificateChainVerifier for HostedCertificateChainVerifier<'_> {
    fn verify(
        &mut self,
        chain: &PemCertificateChain,
        policy: &CertificateValidationPolicy,
    ) -> Result<VerifiedCertificateReceipt, CertificateValidationError> {
        if policy.ca_class != self.ca_class || policy.trust_store_digest != self.trust_store_digest
        {
            return Err(CertificateValidationError::StagingProductionMismatch);
        }
        if policy.identifier_count == 0
            || usize::from(policy.identifier_count) > MAX_IDENTITY_NAMES
            || policy.maximum_chain_length == 0
            || chain.count() > usize::from(policy.maximum_chain_length)
        {
            return Err(CertificateValidationError::InvalidPolicy);
        }
        let leaf_der = chain
            .certificate(0)
            .ok_or(CertificateValidationError::EmptyChain)?;
        let leaf = mrml_tls::Certificate::parse(leaf_der)
            .map_err(|_| CertificateValidationError::InvalidCertificate)?;
        leaf.require_server_auth()
            .map_err(|_| CertificateValidationError::InvalidPurpose)?;
        leaf.verify_time(policy.now_unix)
            .map_err(|_| CertificateValidationError::InvalidValidity)?;
        if leaf.not_after().saturating_sub(leaf.not_before()) > policy.maximum_validity_seconds {
            return Err(CertificateValidationError::InvalidValidity);
        }
        leaf.require_p256_public_key(&policy.expected_key.sec1_uncompressed())
            .map_err(|_| CertificateValidationError::PublicKeyMismatch)?;
        let mut names = [""; MAX_IDENTITY_NAMES];
        for (index, identifier) in policy.identifiers[..usize::from(policy.identifier_count)]
            .iter()
            .enumerate()
        {
            names[index] = identifier
                .as_ref()
                .ok_or(CertificateValidationError::InvalidPolicy)?
                .as_str();
        }
        for pair in names[..usize::from(policy.identifier_count)].windows(2) {
            if pair[0] >= pair[1] {
                return Err(CertificateValidationError::InvalidPolicy);
            }
        }
        leaf.require_exact_dns_names(&names[..usize::from(policy.identifier_count)])
            .map_err(|_| CertificateValidationError::IdentifierMismatch)?;
        let mut chain_refs = [&[][..]; MAX_CERTIFICATES];
        for (index, slot) in chain_refs.iter_mut().enumerate().take(chain.count()) {
            *slot = chain
                .certificate(index)
                .ok_or(CertificateValidationError::InvalidCertificate)?;
        }
        mrml_tls::verify_server_chain_at(
            &chain_refs[..chain.count()],
            self.approved_roots,
            policy.now_unix,
            usize::from(policy.maximum_chain_length),
        )
        .map_err(|_| CertificateValidationError::UntrustedChain)?;
        Ok(VerifiedCertificateReceipt {
            policy_generation: policy.policy_generation,
            ca_class: policy.ca_class,
            profile: policy.profile,
            order_url_digest: policy.order_url_digest,
            chain_digest: chain.chain_digest(),
            leaf_spki_digest: leaf.spki_sha256(),
            not_before: leaf.not_before(),
            not_after: leaf.not_after(),
            trust_store_digest: policy.trust_store_digest,
            ari_certificate_id: AriCertificateId::derive(
                leaf.authority_key_identifier()
                    .map_err(|_| CertificateValidationError::InvalidCertificate)?,
                leaf.serial(),
            )
            .map_err(|_| CertificateValidationError::InvalidCertificate)?,
        })
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_pem_base64(input: &[u8], output: &mut [u8]) -> Result<usize, CertificateValidationError> {
    let mut quartet = [0u8; 4];
    let mut used = 0usize;
    let mut written = 0usize;
    let mut ended = false;
    for byte in input.iter().copied() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if ended {
            return Err(CertificateValidationError::InvalidBase64);
        }
        quartet[used] = byte;
        used += 1;
        if used == 4 {
            let a = pem_value(quartet[0]).ok_or(CertificateValidationError::InvalidBase64)?;
            let b = pem_value(quartet[1]).ok_or(CertificateValidationError::InvalidBase64)?;
            let padding = usize::from(quartet[2] == b'=') + usize::from(quartet[3] == b'=');
            if padding > 2 || (quartet[2] == b'=' && quartet[3] != b'=') {
                return Err(CertificateValidationError::InvalidBase64);
            }
            let c = if quartet[2] == b'=' {
                0
            } else {
                pem_value(quartet[2]).ok_or(CertificateValidationError::InvalidBase64)?
            };
            let d = if quartet[3] == b'=' {
                0
            } else {
                pem_value(quartet[3]).ok_or(CertificateValidationError::InvalidBase64)?
            };
            if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
                return Err(CertificateValidationError::InvalidBase64);
            }
            let value =
                (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
            for shift in [16, 8, 0].into_iter().take(3 - padding) {
                *output
                    .get_mut(written)
                    .ok_or(CertificateValidationError::Oversized)? = (value >> shift) as u8;
                written += 1;
            }
            ended = padding != 0;
            used = 0;
        }
    }
    if used != 0 {
        return Err(CertificateValidationError::InvalidBase64);
    }
    Ok(written)
}

fn pem_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::{
        AccountPolicy, AcmeHttpMethod, AcmeTransportRequest, AcmeTransportResponse,
        ApprovedAcmeJwsDigest, Es256Signature, JoseError, account_contacts_digest,
    };
    #[test]
    fn pem_chain_is_bounded_strict_and_digest_ordered() {
        let chain=PemCertificateChain::parse(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n").unwrap();
        assert_eq!(chain.count(), 2);
        assert_eq!(chain.certificate(0), Some(&[1, 2, 3][..]));
        assert_ne!(chain.chain_digest(), [0; 32]);
        assert!(
            PemCertificateChain::parse(
                b"-----BEGIN CERTIFICATE-----\nAQI=AAAA\n-----END CERTIFICATE-----"
            )
            .is_err()
        );
    }

    struct ReceiptVerifier;

    impl CertificateChainVerifier for ReceiptVerifier {
        fn verify(
            &mut self,
            chain: &PemCertificateChain,
            policy: &CertificateValidationPolicy,
        ) -> Result<VerifiedCertificateReceipt, CertificateValidationError> {
            Ok(VerifiedCertificateReceipt {
                policy_generation: policy.policy_generation,
                ca_class: policy.ca_class,
                profile: policy.profile,
                order_url_digest: policy.order_url_digest,
                chain_digest: chain.chain_digest(),
                leaf_spki_digest: [0; 32],
                not_before: 1,
                not_after: 2,
                trust_store_digest: policy.trust_store_digest,
                ari_certificate_id: AriCertificateId::derive(&[1], &[1]).unwrap(),
            })
        }
    }

    struct Signer;
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            _: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            Es256Signature::from_raw([1; 64])
        }
    }

    struct CertificateTransport;
    impl AcmeTransport for CertificateTransport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("certificate-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            let pem = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
            output[..pem.len()].copy_from_slice(pem);
            Ok(AcmeTransportResponse {
                status: 200,
                effective_url: "https://ca.example/certificate/1",
                replay_nonce: Some("certificate-nonce-2"),
                retry_after: None,
                location: None,
                content_type: Some("application/pem-certificate-chain"),
                body_length: pem.len(),
            })
        }
    }

    fn test_key() -> P256Jwk {
        P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap()
    }

    #[test]
    fn retrieval_requires_exact_pem_resource_and_verification_receipt() {
        let directory_url =
            mrml_acme::AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let directory = AcmeDirectory::parse(
            r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change","meta":{"profiles":{"classic":"https://docs.example/classic"}}}"#,
            &directory_url,
            7,
        )
        .unwrap();
        let key = test_key();
        let (mut account, account_receipt) = AccountLifecycle::prepare_create(
            &directory,
            AccountPolicy {
                ca_class: CaClass::Staging,
                policy_generation: 2,
                contact_digest: account_contacts_digest(&[]).unwrap(),
            },
            &key,
            None,
            false,
        )
        .unwrap();
        account
            .commit_created(
                account_receipt,
                mrml_acme::AcmeUrl::parse("https://ca.example/account/1", false).unwrap(),
                &directory,
            )
            .unwrap();
        let identifiers = [DnsIdentifier::parse("example.com", false).unwrap()];
        let profile = directory.profiles().next().unwrap().profile;
        let mut order = OrderLifecycle::create(
            &directory,
            account.generation,
            account.key,
            mrml_acme::AcmeUrl::parse("https://ca.example/order/1", false).unwrap(),
            mrml_acme::AcmeUrl::parse("https://ca.example/order/1/finalize", false).unwrap(),
            profile,
            &identifiers,
            200,
            3,
        )
        .unwrap();
        order
            .apply_order_response(1, OrderState::Ready, None, 100)
            .unwrap();
        order
            .apply_order_response(2, OrderState::Processing, None, 100)
            .unwrap();
        order
            .apply_order_response(
                3,
                OrderState::Valid,
                Some(mrml_acme::AcmeUrl::parse("https://ca.example/certificate/1", false).unwrap()),
                100,
            )
            .unwrap();
        let mut policy_identifiers = [None; MAX_IDENTITY_NAMES];
        policy_identifiers[0] = Some(identifiers[0]);
        let policy = CertificateValidationPolicy {
            policy_generation: 3,
            ca_class: CaClass::Staging,
            profile,
            order_url_digest: Sha256::digest(order.order_url.as_str().as_bytes()),
            expected_key: key,
            identifiers: policy_identifiers,
            identifier_count: 1,
            now_unix: 100,
            maximum_validity_seconds: 100,
            maximum_chain_length: 2,
            trust_store_digest: [8; 32],
        };
        let mut exchange = AcmeExchange::new(directory.generation, directory_url);
        let mut transport = CertificateTransport;
        let mut signer = Signer;
        let mut verifier = ReceiptVerifier;
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let retrieved = retrieve_and_verify_certificate(
            &directory,
            &account,
            &order,
            &policy,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut verifier,
            &mut response,
            &mut jws,
        );
        let retrieved = match retrieved {
            Ok(retrieved) => retrieved,
            Err(_) => panic!("certificate retrieval failed"),
        };
        assert_eq!(retrieved.chain.certificate(0), Some(&[1, 2, 3][..]));
        assert_eq!(
            retrieved.receipt.chain_digest,
            retrieved.chain.chain_digest()
        );
    }

    #[test]
    fn alternate_chain_selection_uses_owner_preference_not_response_order() {
        let first = PemCertificateChain::parse(
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let preferred = PemCertificateChain::parse(
            b"-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let policy = CertificateValidationPolicy {
            policy_generation: 1,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("test", 1).unwrap(),
            order_url_digest: [1; 32],
            expected_key: P256Jwk::from_coordinates(
                [
                    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                    0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
                    0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                ],
                [
                    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
                    0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6,
                    0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
                ],
            )
            .unwrap(),
            identifiers: [None; MAX_IDENTITY_NAMES],
            identifier_count: 1,
            now_unix: 1,
            maximum_validity_seconds: 1,
            maximum_chain_length: 1,
            trust_store_digest: [2; 32],
        };
        let mut preferred_chain_digests = [None; MAX_ALTERNATE_CHAINS];
        preferred_chain_digests[0] = Some(preferred.chain_digest());
        preferred_chain_digests[1] = Some(first.chain_digest());
        let selected = select_alternate_chain(
            &[&first, &preferred],
            &policy,
            &AlternateChainPolicy {
                preferred_chain_digests,
            },
            &mut ReceiptVerifier,
        )
        .unwrap();
        assert_eq!(selected.candidate_index, 1);
        assert_eq!(selected.preference_index, 0);
        assert!(matches!(
            select_alternate_chain(
                &[&first],
                &policy,
                &AlternateChainPolicy {
                    preferred_chain_digests: [None; MAX_ALTERNATE_CHAINS]
                },
                &mut ReceiptVerifier,
            ),
            Err(CertificateValidationError::AlternateChainNotApproved)
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn independently_generated_chain_binds_key_names_purpose_and_root() {
        let chain =
            PemCertificateChain::parse(include_bytes!("../tests/fixtures/pkix-leaf.pem")).unwrap();
        let root =
            PemCertificateChain::parse(include_bytes!("../tests/fixtures/pkix-root.pem")).unwrap();
        let root_der = root.certificate(0).unwrap();
        let leaf = mrml_tls::Certificate::parse(chain.certificate(0).unwrap()).unwrap();
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(DnsIdentifier::parse("git.example", false).unwrap());
        identifiers[1] = Some(DnsIdentifier::parse("raw.example", false).unwrap());
        let key = P256Jwk::from_coordinates(
            [
                0x83, 0x28, 0x77, 0xd9, 0x3d, 0x62, 0x0b, 0x0e, 0xec, 0x22, 0x03, 0xcd, 0x56, 0x95,
                0x78, 0xb9, 0x34, 0xeb, 0xb3, 0xb7, 0x80, 0xbc, 0xe0, 0x4a, 0x8a, 0xff, 0xef, 0x63,
                0xa1, 0x68, 0x10, 0xb0,
            ],
            [
                0xf6, 0x0c, 0xee, 0x38, 0xea, 0x5e, 0x9f, 0xb2, 0x8b, 0xbf, 0x73, 0xc3, 0xef, 0xae,
                0xd0, 0x86, 0xb2, 0xdf, 0x73, 0xce, 0x30, 0x15, 0x45, 0x14, 0xde, 0x2b, 0x43, 0xf9,
                0xe8, 0x56, 0x1a, 0xed,
            ],
        )
        .unwrap();
        let policy = CertificateValidationPolicy {
            policy_generation: 4,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("classic", 7).unwrap(),
            order_url_digest: [3; 32],
            expected_key: key,
            identifiers,
            identifier_count: 2,
            now_unix: leaf.not_before(),
            maximum_validity_seconds: 366 * 86_400,
            maximum_chain_length: 3,
            trust_store_digest: [5; 32],
        };
        let roots = [root_der];
        let mut verifier = HostedCertificateChainVerifier {
            ca_class: CaClass::Staging,
            trust_store_digest: [5; 32],
            approved_roots: &roots,
        };
        let receipt = verifier.verify(&chain, &policy).unwrap();
        assert_eq!(receipt.chain_digest, chain.chain_digest());
        let mut wrong = policy;
        wrong.ca_class = CaClass::Production;
        assert!(matches!(
            verifier.verify(&chain, &wrong),
            Err(CertificateValidationError::StagingProductionMismatch)
        ));
        wrong = policy;
        wrong.identifiers[1] = Some(DnsIdentifier::parse("wrong.example", false).unwrap());
        assert!(matches!(
            verifier.verify(&chain, &wrong),
            Err(CertificateValidationError::IdentifierMismatch)
        ));
    }
}
