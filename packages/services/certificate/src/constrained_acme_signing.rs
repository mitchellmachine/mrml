use crate::AccountP256SigningKey;
use mrml_acme::{
    AcmeUrl, MAX_JWS_PAYLOAD, P256Jwk, ProtectedKey, ReplayNonce, write_flattened_jws,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmeJwsOperation {
    NewAccount = 1,
    AccountUpdate = 2,
    NewOrder = 3,
    Authorization = 4,
    Challenge = 5,
    Finalize = 6,
    Order = 7,
    Certificate = 8,
    RevokeCertificate = 9,
    KeyChange = 10,
}

impl AcmeJwsOperation {
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::NewAccount,
            2 => Self::AccountUpdate,
            3 => Self::NewOrder,
            4 => Self::Authorization,
            5 => Self::Challenge,
            6 => Self::Finalize,
            7 => Self::Order,
            8 => Self::Certificate,
            9 => Self::RevokeCertificate,
            10 => Self::KeyChange,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
pub struct ConstrainedAcmeJwsPolicy {
    pub directory_url: AcmeUrl,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub account_identity: [u8; 16],
}

pub struct ConstrainedAcmeJwsRequest<'a> {
    pub operation: AcmeJwsOperation,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub account_identity: [u8; 16],
    pub protected_url: AcmeUrl,
    pub nonce: ReplayNonce,
    pub account_url: Option<AcmeUrl>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstrainedAcmeJwsError {
    PolicyMismatch,
    OriginMismatch,
    AccountUrlRequired,
    AccountUrlForbidden,
    EmptyPayload,
    PayloadTooLarge,
    OutputTooSmall,
    SigningUnavailable,
}

pub fn write_constrained_acme_jws<'a>(
    policy: ConstrainedAcmeJwsPolicy,
    request: ConstrainedAcmeJwsRequest<'_>,
    account_public_key: &P256Jwk,
    signer: &mut AccountP256SigningKey,
    output: &'a mut [u8],
) -> Result<&'a [u8], ConstrainedAcmeJwsError> {
    if policy.directory_generation == 0
        || policy.account_generation == 0
        || policy.account_identity == [0; 16]
        || request.directory_generation != policy.directory_generation
        || request.account_generation != policy.account_generation
        || request.account_identity != policy.account_identity
    {
        return Err(ConstrainedAcmeJwsError::PolicyMismatch);
    }
    request
        .protected_url
        .require_origin(policy.directory_url.origin())
        .map_err(|_| ConstrainedAcmeJwsError::OriginMismatch)?;
    if request.payload.len() > MAX_JWS_PAYLOAD {
        return Err(ConstrainedAcmeJwsError::PayloadTooLarge);
    }
    if request.payload.is_empty()
        && !matches!(
            request.operation,
            AcmeJwsOperation::Authorization
                | AcmeJwsOperation::Order
                | AcmeJwsOperation::Certificate
        )
    {
        return Err(ConstrainedAcmeJwsError::EmptyPayload);
    }
    let protected_key = match (request.operation, request.account_url.as_ref()) {
        (AcmeJwsOperation::NewAccount, None) => ProtectedKey::Jwk(account_public_key),
        (AcmeJwsOperation::NewAccount, Some(_)) => {
            return Err(ConstrainedAcmeJwsError::AccountUrlForbidden);
        }
        (_, Some(account_url)) => {
            account_url
                .require_origin(policy.directory_url.origin())
                .map_err(|_| ConstrainedAcmeJwsError::OriginMismatch)?;
            ProtectedKey::Kid(account_url)
        }
        (_, None) => return Err(ConstrainedAcmeJwsError::AccountUrlRequired),
    };
    write_flattened_jws(
        protected_key,
        &request.nonce,
        &request.protected_url,
        request.payload,
        request.directory_generation,
        request.account_generation,
        signer,
        output,
    )
    .map_err(|error| match error {
        mrml_acme::JoseError::OutputTooSmall => ConstrainedAcmeJwsError::OutputTooSmall,
        mrml_acme::JoseError::PayloadTooLarge => ConstrainedAcmeJwsError::PayloadTooLarge,
        _ => ConstrainedAcmeJwsError::SigningUnavailable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::P256Error;

    fn signer() -> AccountP256SigningKey {
        let mut scalar = [0u8; 32];
        scalar[31] = 9;
        AccountP256SigningKey::generate(3, 4, |output| {
            output.copy_from_slice(&scalar);
            Ok::<(), P256Error>(())
        })
        .unwrap()
    }

    fn policy() -> ConstrainedAcmeJwsPolicy {
        ConstrainedAcmeJwsPolicy {
            directory_url: AcmeUrl::parse("https://ca.example/directory", false).unwrap(),
            directory_generation: 3,
            account_generation: 4,
            account_identity: [5; 16],
        }
    }

    #[test]
    fn certd_constructs_new_account_jws_and_binds_every_generation() {
        let mut signer = signer();
        let public = signer.public_jwk().unwrap();
        let mut output = [0u8; 4096];
        let request = ConstrainedAcmeJwsRequest {
            operation: AcmeJwsOperation::NewAccount,
            directory_generation: 3,
            account_generation: 4,
            account_identity: [5; 16],
            protected_url: AcmeUrl::parse("https://ca.example/new-account", false).unwrap(),
            nonce: ReplayNonce::parse("nonce-1").unwrap(),
            account_url: None,
            payload: br#"{"termsOfServiceAgreed":true}"#,
        };
        let jws = write_constrained_acme_jws(policy(), request, &public, &mut signer, &mut output)
            .unwrap();
        assert!(jws.starts_with(b"{\"protected\":\""));
        assert!(jws.ends_with(b"\"}"));
    }

    #[test]
    fn cross_origin_account_confusion_and_arbitrary_empty_signing_fail_closed() {
        let mut signer = signer();
        let public = signer.public_jwk().unwrap();
        let mut output = [0u8; 4096];
        fn make<'a>(
            operation: AcmeJwsOperation,
            protected: &str,
            account_url: Option<&str>,
            payload: &'a [u8],
        ) -> ConstrainedAcmeJwsRequest<'a> {
            ConstrainedAcmeJwsRequest {
                operation,
                directory_generation: 3,
                account_generation: 4,
                account_identity: [5; 16],
                protected_url: AcmeUrl::parse(protected, false).unwrap(),
                nonce: ReplayNonce::parse("nonce-2").unwrap(),
                account_url: account_url.map(|url| AcmeUrl::parse(url, false).unwrap()),
                payload,
            }
        }
        assert_eq!(
            write_constrained_acme_jws(
                policy(),
                make(
                    AcmeJwsOperation::NewOrder,
                    "https://evil.example/order",
                    Some("https://ca.example/acct/1"),
                    b"{}"
                ),
                &public,
                &mut signer,
                &mut output
            )
            .err(),
            Some(ConstrainedAcmeJwsError::OriginMismatch)
        );
        assert_eq!(
            write_constrained_acme_jws(
                policy(),
                make(
                    AcmeJwsOperation::NewOrder,
                    "https://ca.example/order",
                    Some("https://other.example/acct/1"),
                    b"{}"
                ),
                &public,
                &mut signer,
                &mut output
            )
            .err(),
            Some(ConstrainedAcmeJwsError::OriginMismatch)
        );
        assert_eq!(
            write_constrained_acme_jws(
                policy(),
                make(
                    AcmeJwsOperation::Challenge,
                    "https://ca.example/challenge",
                    Some("https://ca.example/acct/1"),
                    b""
                ),
                &public,
                &mut signer,
                &mut output
            )
            .err(),
            Some(ConstrainedAcmeJwsError::EmptyPayload)
        );
    }
}
