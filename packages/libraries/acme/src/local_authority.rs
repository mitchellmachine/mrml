use crate::{
    AcmeContentType, AcmeHttpMethod, AcmeTransport, AcmeTransportRequest, AcmeTransportResponse,
    P256Jwk, decode_base64url, encode_base64url,
};
use mrml_crypto::{Sha256, ecdsa_p256_digest_verify_raw};
pub const LOCAL_DIRECTORY_URL: &str = "https://local-ca.invalid/acme/directory";
pub const LOCAL_NEW_NONCE_URL: &str = "https://local-ca.invalid/acme/new-nonce";
pub const LOCAL_NEW_ACCOUNT_URL: &str = "https://local-ca.invalid/acme/new-account";
pub const LOCAL_ACCOUNT_URL: &str = "https://local-ca.invalid/acme/account/1";
pub const LOCAL_NEW_ORDER_URL: &str = "https://local-ca.invalid/acme/new-order";
pub const LOCAL_ORDER_URL: &str = "https://local-ca.invalid/acme/order/1";
pub const LOCAL_AUTHORIZATION_URL: &str = "https://local-ca.invalid/acme/authz/1";
pub const LOCAL_CHALLENGE_URL: &str = "https://local-ca.invalid/acme/challenge/1";
pub const LOCAL_FINALIZE_URL: &str = "https://local-ca.invalid/acme/order/1/finalize";
pub const LOCAL_CERTIFICATE_URL: &str = "https://local-ca.invalid/acme/certificate/1";
pub const LOCAL_REVOKE_URL: &str = "https://local-ca.invalid/acme/revoke-cert";
const DIRECTORY: &str = r#"{"newNonce":"https://local-ca.invalid/acme/new-nonce","newAccount":"https://local-ca.invalid/acme/new-account","newOrder":"https://local-ca.invalid/acme/new-order","revokeCert":"https://local-ca.invalid/acme/revoke-cert","keyChange":"https://local-ca.invalid/acme/key-change","renewalInfo":"https://local-ca.invalid/acme/renewal-info","meta":{"termsOfService":"https://local-ca.invalid/terms/v1","website":"https://local-ca.invalid/","caaIdentities":["local-ca.invalid"],"profiles":{"classic":"https://local-ca.invalid/profiles/classic"}}}"#;
const ACCOUNT: &str =
    r#"{"status":"valid","contact":[],"orders":"https://local-ca.invalid/acme/orders/1"}"#;
const ACCOUNT_DEACTIVATED: &str =
    r#"{"status":"deactivated","contact":[],"orders":"https://local-ca.invalid/acme/orders/1"}"#;
const ORDER_PENDING: &str = r#"{"status":"pending","identifiers":[{"type":"dns","value":"git.example"}],"authorizations":["https://local-ca.invalid/acme/authz/1"],"finalize":"https://local-ca.invalid/acme/order/1/finalize","profile":"classic"}"#;
const ORDER_READY: &str = r#"{"status":"ready","identifiers":[{"type":"dns","value":"git.example"}],"authorizations":["https://local-ca.invalid/acme/authz/1"],"finalize":"https://local-ca.invalid/acme/order/1/finalize","profile":"classic"}"#;
const ORDER_VALID: &str = r#"{"status":"valid","identifiers":[{"type":"dns","value":"git.example"}],"authorizations":["https://local-ca.invalid/acme/authz/1"],"finalize":"https://local-ca.invalid/acme/order/1/finalize","certificate":"https://local-ca.invalid/acme/certificate/1","profile":"classic"}"#;
const AUTH_PENDING: &str = r#"{"identifier":{"type":"dns","value":"git.example"},"status":"pending","wildcard":false,"challenges":[{"type":"http-01","url":"https://local-ca.invalid/acme/challenge/1","status":"pending","token":"local-token"}]}"#;
const AUTH_VALID: &str = r#"{"identifier":{"type":"dns","value":"git.example"},"status":"valid","wildcard":false,"challenges":[{"type":"http-01","url":"https://local-ca.invalid/acme/challenge/1","status":"valid","token":"local-token"}]}"#;
const SYNTHETIC_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nTUlNRS1CT1VOREVELUxPQ0FMLUNBLUZJWFRVUkU=\n-----END CERTIFICATE-----\n";
const NONCES: [&str; 16] = [
    "local-nonce-01",
    "local-nonce-02",
    "local-nonce-03",
    "local-nonce-04",
    "local-nonce-05",
    "local-nonce-06",
    "local-nonce-07",
    "local-nonce-08",
    "local-nonce-09",
    "local-nonce-10",
    "local-nonce-11",
    "local-nonce-12",
    "local-nonce-13",
    "local-nonce-14",
    "local-nonce-15",
    "local-nonce-16",
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAuthorityState {
    Empty,
    AccountValid,
    OrderPending,
    AuthorizationValid,
    OrderValid,
    Revoked,
    AccountDeactivated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAuthorityFault {
    None,
    BadNonceOnce,
    DropResponseOnce,
    DelayOrderOnce,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAuthorityError {
    WrongMethod,
    WrongEndpoint,
    WrongContentType,
    OutputTooSmall,
    MalformedJws,
    InvalidNonce,
    InvalidProtectedHeader,
    InvalidSignature,
    InvalidState,
    InjectedDrop,
}
pub trait LocalJwsVerifier {
    fn verify(&mut self, key: &P256Jwk, digest: &[u8; 32], signature: &[u8; 64]) -> bool;
}
pub struct FirstPartyP256JwsVerifier;
impl LocalJwsVerifier for FirstPartyP256JwsVerifier {
    fn verify(&mut self, key: &P256Jwk, digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        let public = key.sec1_uncompressed();
        ecdsa_p256_digest_verify_raw(&public, digest, signature).is_ok()
    }
}
pub struct DeterministicAcmeAuthority<V> {
    verifier: V,
    key: P256Jwk,
    state: LocalAuthorityState,
    nonce: usize,
    nonce_live: bool,
    fault: LocalAuthorityFault,
    fault_used: bool,
    certificate: &'static str,
}
impl<V> DeterministicAcmeAuthority<V> {
    pub const fn new(verifier: V, key: P256Jwk) -> Self {
        Self {
            verifier,
            key,
            state: LocalAuthorityState::Empty,
            nonce: 0,
            nonce_live: false,
            fault: LocalAuthorityFault::None,
            fault_used: false,
            certificate: SYNTHETIC_CERTIFICATE,
        }
    }
    pub const fn state(&self) -> LocalAuthorityState {
        self.state
    }
    pub fn inject(&mut self, fault: LocalAuthorityFault) {
        self.fault = fault;
        self.fault_used = false
    }
    pub fn with_certificate(mut self, pem_chain: &'static str) -> Self {
        self.certificate = pem_chain;
        self
    }
    fn issue_nonce(&mut self) -> &'static str {
        self.nonce = (self.nonce + 1) % NONCES.len();
        self.nonce_live = true;
        NONCES[self.nonce]
    }
}
impl<V: LocalJwsVerifier> AcmeTransport for DeterministicAcmeAuthority<V> {
    type Error = LocalAuthorityError;
    fn exchange(
        &mut self,
        r: AcmeTransportRequest<'_>,
        out: &mut [u8],
    ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
        let url = r.url.as_str();
        if r.method == AcmeHttpMethod::Get && url == LOCAL_DIRECTORY_URL {
            return reply(
                out,
                200,
                LOCAL_DIRECTORY_URL,
                None,
                None,
                Some("application/json"),
                DIRECTORY,
            );
        }
        if r.method == AcmeHttpMethod::Head && url == LOCAL_NEW_NONCE_URL {
            return Ok(AcmeTransportResponse {
                status: 200,
                effective_url: LOCAL_NEW_NONCE_URL,
                replay_nonce: Some(self.issue_nonce()),
                retry_after: None,
                location: None,
                content_type: None,
                body_length: 0,
            });
        }
        if r.method != AcmeHttpMethod::Post {
            return Err(LocalAuthorityError::WrongMethod);
        }
        if r.content_type != AcmeContentType::JoseJson {
            return Err(LocalAuthorityError::WrongContentType);
        }
        let effective = canonical_endpoint(url).ok_or(LocalAuthorityError::WrongEndpoint)?;
        if self.fault == LocalAuthorityFault::DropResponseOnce && !self.fault_used {
            self.fault_used = true;
            return Err(LocalAuthorityError::InjectedDrop);
        }
        let mut payload_buffer = [0u8; 8192];
        let payload_len = validate_jws(
            &mut self.verifier,
            &self.key,
            url,
            r.body,
            NONCES[self.nonce],
            self.nonce_live,
            &mut payload_buffer,
        )?;
        let payload = &payload_buffer[..payload_len];
        self.nonce_live = false;
        if self.fault == LocalAuthorityFault::BadNonceOnce && !self.fault_used {
            self.fault_used = true;
            return reply(
                out,
                400,
                effective,
                Some(self.issue_nonce()),
                None,
                Some("application/problem+json"),
                r#"{"type":"urn:ietf:params:acme:error:badNonce","status":400}"#,
            );
        }
        let next = Some(self.issue_nonce());
        match url {
            LOCAL_NEW_ACCOUNT_URL => {
                if self.state == LocalAuthorityState::AccountValid
                    && contains(payload, r#""onlyReturnExisting":true"#)
                {
                    return reply(
                        out,
                        200,
                        effective,
                        next,
                        Some(LOCAL_ACCOUNT_URL),
                        Some("application/json"),
                        ACCOUNT,
                    );
                }
                if self.state != LocalAuthorityState::Empty || !contains(payload, b"{") {
                    return Err(LocalAuthorityError::InvalidState);
                }
                self.state = LocalAuthorityState::AccountValid;
                reply(
                    out,
                    201,
                    effective,
                    next,
                    Some(LOCAL_ACCOUNT_URL),
                    Some("application/json"),
                    ACCOUNT,
                )
            }
            LOCAL_ACCOUNT_URL => {
                if self.state != LocalAuthorityState::AccountValid {
                    return Err(LocalAuthorityError::InvalidState);
                }
                if payload.is_empty() || contains(payload, r#""contact":"#) {
                    return reply(
                        out,
                        200,
                        effective,
                        next,
                        None,
                        Some("application/json"),
                        ACCOUNT,
                    );
                }
                if contains(payload, r#""status":"deactivated""#) {
                    self.state = LocalAuthorityState::AccountDeactivated;
                    return reply(
                        out,
                        200,
                        effective,
                        next,
                        None,
                        Some("application/json"),
                        ACCOUNT_DEACTIVATED,
                    );
                }
                Err(LocalAuthorityError::InvalidState)
            }
            LOCAL_NEW_ORDER_URL => {
                if self.state != LocalAuthorityState::AccountValid
                    || !contains(payload, r#""value":"git.example""#)
                {
                    return Err(LocalAuthorityError::InvalidState);
                }
                self.state = LocalAuthorityState::OrderPending;
                reply(
                    out,
                    201,
                    effective,
                    next,
                    Some(LOCAL_ORDER_URL),
                    Some("application/json"),
                    ORDER_PENDING,
                )
            }
            LOCAL_AUTHORIZATION_URL => {
                let body = if self.state == LocalAuthorityState::OrderPending {
                    AUTH_PENDING
                } else if matches!(
                    self.state,
                    LocalAuthorityState::AuthorizationValid | LocalAuthorityState::OrderValid
                ) {
                    AUTH_VALID
                } else {
                    return Err(LocalAuthorityError::InvalidState);
                };
                reply(
                    out,
                    200,
                    effective,
                    next,
                    None,
                    Some("application/json"),
                    body,
                )
            }
            LOCAL_CHALLENGE_URL => {
                if self.state != LocalAuthorityState::OrderPending || payload != b"{}" {
                    return Err(LocalAuthorityError::InvalidState);
                }
                self.state = LocalAuthorityState::AuthorizationValid;
                reply(
                    out,
                    200,
                    effective,
                    next,
                    None,
                    Some("application/json"),
                    AUTH_VALID,
                )
            }
            LOCAL_ORDER_URL => {
                let body = match self.state {
                    LocalAuthorityState::OrderPending => ORDER_PENDING,
                    LocalAuthorityState::AuthorizationValid => ORDER_READY,
                    LocalAuthorityState::OrderValid => ORDER_VALID,
                    _ => return Err(LocalAuthorityError::InvalidState),
                };
                if self.fault == LocalAuthorityFault::DelayOrderOnce && !self.fault_used {
                    self.fault_used = true;
                    return reply(
                        out,
                        200,
                        effective,
                        next,
                        None,
                        Some("application/json"),
                        ORDER_PENDING,
                    );
                }
                reply(
                    out,
                    200,
                    effective,
                    next,
                    None,
                    Some("application/json"),
                    body,
                )
            }
            LOCAL_FINALIZE_URL => {
                if self.state != LocalAuthorityState::AuthorizationValid
                    || !contains(payload, "csr")
                {
                    return Err(LocalAuthorityError::InvalidState);
                }
                self.state = LocalAuthorityState::OrderValid;
                reply(
                    out,
                    200,
                    effective,
                    next,
                    None,
                    Some("application/json"),
                    ORDER_VALID,
                )
            }
            LOCAL_CERTIFICATE_URL => {
                if self.state != LocalAuthorityState::OrderValid || !payload.is_empty() {
                    return Err(LocalAuthorityError::InvalidState);
                }
                reply(
                    out,
                    200,
                    effective,
                    next,
                    None,
                    Some("application/pem-certificate-chain"),
                    self.certificate,
                )
            }
            LOCAL_REVOKE_URL => {
                if self.state != LocalAuthorityState::OrderValid
                    || !contains(payload, "certificate")
                {
                    return Err(LocalAuthorityError::InvalidState);
                }
                self.state = LocalAuthorityState::Revoked;
                reply(out, 200, effective, next, None, None, "")
            }
            _ => Err(LocalAuthorityError::WrongEndpoint),
        }
    }
}
fn validate_jws(
    v: &mut impl LocalJwsVerifier,
    key: &P256Jwk,
    url: &str,
    body: &[u8],
    nonce: &str,
    live: bool,
    payload: &mut [u8; 8192],
) -> Result<usize, LocalAuthorityError> {
    if !live {
        return Err(LocalAuthorityError::InvalidNonce);
    }
    let text = core::str::from_utf8(body).map_err(|_| LocalAuthorityError::MalformedJws)?;
    let (protected64, payload64, signature64) = jws_fields(text)?;
    let mut protected = [0u8; 2048];
    let protected = decode_base64url(protected64, &mut protected)
        .map_err(|_| LocalAuthorityError::MalformedJws)?;
    let protected =
        core::str::from_utf8(protected).map_err(|_| LocalAuthorityError::MalformedJws)?;
    let jwk_form = url == LOCAL_NEW_ACCOUNT_URL;
    if !contains(protected, "\"alg\":\"ES256\"")
        || !contains_json_string_field(protected, "nonce", nonce)
        || !contains_json_string_field(protected, "url", url)
        || (jwk_form && (!contains(protected, "\"jwk\":") || contains(protected, "\"kid\":")))
        || (!jwk_form
            && (!contains_json_string_field(protected, "kid", LOCAL_ACCOUNT_URL)
                || contains(protected, "\"jwk\":")))
    {
        return Err(LocalAuthorityError::InvalidProtectedHeader);
    }
    if jwk_form {
        let public = key.sec1_uncompressed();
        let mut x = [0u8; 43];
        let mut y = [0u8; 43];
        let x = encode_base64url(&public[1..33], &mut x)
            .map_err(|_| LocalAuthorityError::InvalidProtectedHeader)?;
        let y = encode_base64url(&public[33..], &mut y)
            .map_err(|_| LocalAuthorityError::InvalidProtectedHeader)?;
        if !contains_json_string_field(protected, "x", x)
            || !contains_json_string_field(protected, "y", y)
            || !contains_json_string_field(protected, "crv", "P-256")
            || !contains_json_string_field(protected, "kty", "EC")
        {
            return Err(LocalAuthorityError::InvalidProtectedHeader);
        }
    }
    let payload_len = decode_base64url(payload64, payload)
        .map_err(|_| LocalAuthorityError::MalformedJws)?
        .len();
    let mut signature = [0u8; 64];
    let decoded = decode_base64url(signature64, &mut signature)
        .map_err(|_| LocalAuthorityError::MalformedJws)?;
    if decoded.len() != 64 {
        return Err(LocalAuthorityError::MalformedJws);
    }
    let mut h = Sha256::new();
    h.update(protected64.as_bytes());
    h.update(b".");
    h.update(payload64.as_bytes());
    if !v.verify(key, &h.finalize(), &signature) {
        return Err(LocalAuthorityError::InvalidSignature);
    }
    Ok(payload_len)
}
fn jws_fields(text: &str) -> Result<(&str, &str, &str), LocalAuthorityError> {
    let rest = text
        .strip_prefix("{\"protected\":\"")
        .ok_or(LocalAuthorityError::MalformedJws)?;
    let (p, rest) = rest
        .split_once("\",\"payload\":\"")
        .ok_or(LocalAuthorityError::MalformedJws)?;
    let (d, rest) = rest
        .split_once("\",\"signature\":\"")
        .ok_or(LocalAuthorityError::MalformedJws)?;
    let s = rest
        .strip_suffix("\"}")
        .ok_or(LocalAuthorityError::MalformedJws)?;
    Ok((p, d, s))
}
fn canonical_endpoint(value: &str) -> Option<&'static str> {
    Some(match value {
        LOCAL_NEW_ACCOUNT_URL => LOCAL_NEW_ACCOUNT_URL,
        LOCAL_ACCOUNT_URL => LOCAL_ACCOUNT_URL,
        LOCAL_NEW_ORDER_URL => LOCAL_NEW_ORDER_URL,
        LOCAL_ORDER_URL => LOCAL_ORDER_URL,
        LOCAL_AUTHORIZATION_URL => LOCAL_AUTHORIZATION_URL,
        LOCAL_CHALLENGE_URL => LOCAL_CHALLENGE_URL,
        LOCAL_FINALIZE_URL => LOCAL_FINALIZE_URL,
        LOCAL_CERTIFICATE_URL => LOCAL_CERTIFICATE_URL,
        LOCAL_REVOKE_URL => LOCAL_REVOKE_URL,
        _ => return None,
    })
}
fn contains(source: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
    let s = source.as_ref();
    let n = needle.as_ref();
    !n.is_empty() && s.windows(n.len()).any(|w| w == n)
}
fn contains_json_string_field(source: &str, name: &str, value: &str) -> bool {
    let mut field = [0u8; 2120];
    let required = name.len().saturating_add(value.len()).saturating_add(5);
    let Some(out) = field.get_mut(..required) else {
        return false;
    };
    out[0] = b'"';
    out[1..1 + name.len()].copy_from_slice(name.as_bytes());
    out[1 + name.len()..4 + name.len()].copy_from_slice(b"\":\"");
    out[4 + name.len()..4 + name.len() + value.len()].copy_from_slice(value.as_bytes());
    out[required - 1] = b'"';
    contains(source, out)
}
fn reply<'a>(
    out: &mut [u8],
    status: u16,
    effective: &'static str,
    nonce: Option<&'static str>,
    location: Option<&'static str>,
    content: Option<&'static str>,
    body: &str,
) -> Result<AcmeTransportResponse<'a>, LocalAuthorityError> {
    if out.len() < body.len() {
        return Err(LocalAuthorityError::OutputTooSmall);
    }
    out[..body.len()].copy_from_slice(body.as_bytes());
    Ok(AcmeTransportResponse {
        status,
        effective_url: effective,
        replay_nonce: nonce,
        retry_after: None,
        location,
        content_type: content,
        body_length: body.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AcmeExchange, AcmeJwsSigner, ApprovedAcmeJwsDigest, Es256Signature, ProtectedKey,
        fetch_directory, post_jws,
    };
    struct Verifier;
    impl LocalJwsVerifier for Verifier {
        fn verify(&mut self, _: &P256Jwk, d: &[u8; 32], s: &[u8; 64]) -> bool {
            *d != [0; 32] && *s == [1; 64]
        }
    }
    struct Signer;
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            _: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, crate::JoseError> {
            Es256Signature::from_raw([1; 64])
        }
    }
    fn key() -> P256Jwk {
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
    fn url(v: &str) -> crate::AcmeUrl {
        crate::AcmeUrl::parse(v, false).unwrap()
    }
    #[test]
    fn complete_deterministic_transport_flow_and_bad_nonce_retry() {
        let directory_url = url(LOCAL_DIRECTORY_URL);
        let mut exchange = AcmeExchange::new(1, directory_url);
        let mut authority = DeterministicAcmeAuthority::new(Verifier, key());
        let mut response = [0u8; 65536];
        let directory = fetch_directory(
            &directory_url,
            1,
            &mut exchange,
            &mut authority,
            &mut response,
        )
        .unwrap();
        assert_eq!(directory.new_order.as_str(), LOCAL_NEW_ORDER_URL);
        authority.inject(LocalAuthorityFault::BadNonceOnce);
        let mut signer = Signer;
        let mut jws = [0u8; 49152];
        let public_key = key();
        let account = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &directory.new_account,
            ProtectedKey::Jwk(&public_key),
            b"{}",
            0,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(account.metadata.status, 201);
        let kid = url(LOCAL_ACCOUNT_URL);
        for (endpoint, payload, status) in [
            (
                LOCAL_NEW_ORDER_URL,
                br#"{"identifiers":[{"type":"dns","value":"git.example"}],"profile":"classic"}"#
                    .as_slice(),
                201,
            ),
            (LOCAL_AUTHORIZATION_URL, b"".as_slice(), 200),
            (LOCAL_CHALLENGE_URL, b"{}".as_slice(), 200),
            (LOCAL_ORDER_URL, b"".as_slice(), 200),
            (LOCAL_FINALIZE_URL, br#"{"csr":"AA"}"#.as_slice(), 200),
            (LOCAL_CERTIFICATE_URL, b"".as_slice(), 200),
            (LOCAL_REVOKE_URL, br#"{"certificate":"AA"}"#.as_slice(), 200),
        ] {
            let result = post_jws(
                &mut exchange,
                &mut authority,
                &directory.new_nonce,
                &url(endpoint),
                ProtectedKey::Kid(&kid),
                payload,
                1,
                &mut signer,
                &mut response,
                &mut jws,
            )
            .unwrap();
            assert_eq!(result.metadata.status, status)
        }
        assert_eq!(authority.state(), LocalAuthorityState::Revoked);
        assert!(jws.iter().all(|b| *b == 0));
    }

    #[test]
    fn existing_account_lookup_update_and_deactivation_are_explicit() {
        let directory_url = url(LOCAL_DIRECTORY_URL);
        let mut exchange = AcmeExchange::new(2, directory_url);
        let public_key = key();
        let mut authority = DeterministicAcmeAuthority::new(Verifier, public_key);
        let mut response = [0u8; 65_536];
        let mut jws = [0u8; 49_152];
        let directory = fetch_directory(
            &directory_url,
            2,
            &mut exchange,
            &mut authority,
            &mut response,
        )
        .unwrap();
        let mut signer = Signer;
        let created = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &directory.new_account,
            ProtectedKey::Jwk(&public_key),
            b"{}",
            0,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(created.metadata.status, 201);
        let recovered = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &directory.new_account,
            ProtectedKey::Jwk(&public_key),
            br#"{"onlyReturnExisting":true}"#,
            0,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(recovered.metadata.status, 200);
        assert_eq!(
            recovered.metadata.location.unwrap().as_str(),
            LOCAL_ACCOUNT_URL
        );
        let account_url = url(LOCAL_ACCOUNT_URL);
        let updated = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &account_url,
            ProtectedKey::Kid(&account_url),
            br#"{"contact":["mailto:owner@example.test"]}"#,
            1,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(updated.metadata.status, 200);
        let deactivated = post_jws(
            &mut exchange,
            &mut authority,
            &directory.new_nonce,
            &account_url,
            ProtectedKey::Kid(&account_url),
            br#"{"status":"deactivated"}"#,
            1,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(deactivated.metadata.status, 200);
        assert_eq!(authority.state(), LocalAuthorityState::AccountDeactivated);
    }
}
