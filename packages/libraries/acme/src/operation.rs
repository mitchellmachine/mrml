use crate::{
    AccountError, AccountLifecycle, AcmeDirectory, AcmeJwsSigner, AcmePostError, AcmeProblem,
    AcmeTransport, AcmeUrl, P256Jwk, ParsedAccountStatus, PayloadError, PreparedAccountAction,
    ResponseError, account_contacts_digest, parse_account_response, post_jws,
    write_new_account_payload,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CreateAccountError<E> {
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Response(ResponseError),
    Lifecycle(AccountError),
    Server(AcmeProblem),
    UnexpectedStatus,
    MissingLocation,
    AccountNotValid,
    ContactMismatch,
    KeyMismatch,
}

pub struct AccountCreateBuffers<'a> {
    pub payload: &'a mut [u8],
    pub response: &'a mut [u8],
    pub jws: &'a mut [u8],
}

pub fn execute_prepared_account_create<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    contacts: &[&str],
    external_account_binding: Option<&str>,
    public_key: &P256Jwk,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: AccountCreateBuffers<'_>,
) -> Result<AcmeUrl, CreateAccountError<T::Error>> {
    let expected_contacts =
        account_contacts_digest(contacts).map_err(CreateAccountError::Payload)?;
    if expected_contacts != receipt.contact_digest {
        return Err(CreateAccountError::ContactMismatch);
    }
    if public_key.thumbprint().ok() != receipt.new_key {
        return Err(CreateAccountError::KeyMismatch);
    }
    let payload = write_new_account_payload(
        contacts,
        directory.terms_of_service.is_some(),
        false,
        external_account_binding,
        buffers.payload,
    )
    .map_err(CreateAccountError::Payload)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.new_account,
        crate::ProtectedKey::Jwk(public_key),
        payload.as_bytes(),
        0,
        signer,
        buffers.response,
        buffers.jws,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            lifecycle
                .mark_uncertain()
                .map_err(CreateAccountError::Lifecycle)?;
            return Err(CreateAccountError::Post(error));
        }
    };
    if let Some(problem) = result.problem {
        lifecycle
            .abort_prepared(receipt)
            .map_err(CreateAccountError::Lifecycle)?;
        return Err(CreateAccountError::Server(problem));
    }
    let account_url = match result.metadata.location {
        Some(url) if result.metadata.status == 201 => url,
        Some(_) => return uncertain(lifecycle, CreateAccountError::UnexpectedStatus),
        None if result.metadata.status == 201 => {
            return uncertain(lifecycle, CreateAccountError::MissingLocation);
        }
        None => return uncertain(lifecycle, CreateAccountError::UnexpectedStatus),
    };
    let body = core::str::from_utf8(&buffers.response[..result.metadata.body_length])
        .map_err(|_| CreateAccountError::Response(ResponseError::Malformed));
    let body = match body {
        Ok(body) => body,
        Err(error) => return uncertain(lifecycle, error),
    };
    let parsed = match parse_account_response(body, directory.new_account.origin()) {
        Ok(parsed) => parsed,
        Err(error) => return uncertain(lifecycle, CreateAccountError::Response(error)),
    };
    if parsed.status != ParsedAccountStatus::Valid {
        return uncertain(lifecycle, CreateAccountError::AccountNotValid);
    }
    if parsed.contacts_digest != expected_contacts {
        return uncertain(lifecycle, CreateAccountError::ContactMismatch);
    }
    if let Err(error) = lifecycle.commit_created(receipt, account_url, directory) {
        return uncertain(lifecycle, CreateAccountError::Lifecycle(error));
    }
    Ok(account_url)
}

fn uncertain<E>(
    lifecycle: &mut AccountLifecycle,
    error: CreateAccountError<E>,
) -> Result<AcmeUrl, CreateAccountError<E>> {
    lifecycle
        .mark_uncertain()
        .map_err(CreateAccountError::Lifecycle)?;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountOperation, AccountPolicy, AcmeHttpMethod, AcmeTransportRequest,
        AcmeTransportResponse, ApprovedAcmeJwsDigest, CaClass, Es256Signature, JoseError,
    };

    struct Signer;
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            _: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            Es256Signature::from_raw([1; 64])
        }
    }

    struct Transport {
        fail_post: bool,
    }
    impl AcmeTransport for Transport {
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
                    replay_nonce: Some("nonce-1"),
                    retry_after: None,
                    location: None,
                    body_length: 0,
                });
            }
            if self.fail_post {
                return Err(());
            }
            let body = br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 201,
                effective_url: "https://ca.example/new-account",
                replay_nonce: Some("nonce-2"),
                retry_after: None,
                location: Some("https://ca.example/account/1"),
                body_length: body.len(),
            })
        }
    }

    fn directory() -> AcmeDirectory {
        let url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        AcmeDirectory::parse(
            r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change"}"#,
            &url,
            9,
        )
        .unwrap()
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

    fn prepared() -> (
        AcmeDirectory,
        P256Jwk,
        AccountLifecycle,
        PreparedAccountAction,
    ) {
        let directory = directory();
        let key = key();
        let contacts = ["mailto:owner@example.com"];
        let policy = AccountPolicy {
            ca_class: CaClass::Staging,
            policy_generation: 4,
            contact_digest: account_contacts_digest(&contacts).unwrap(),
        };
        let (lifecycle, receipt) =
            AccountLifecycle::prepare_create(&directory, policy, &key, None, false).unwrap();
        (directory, key, lifecycle, receipt)
    }

    #[test]
    fn creation_binds_signed_response_location_and_contacts() {
        let (directory, key, mut lifecycle, receipt) = prepared();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = Transport { fail_post: false };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let result = execute_prepared_account_create(
            &mut lifecycle,
            receipt,
            &directory,
            &["mailto:owner@example.com"],
            None,
            &key,
            &mut exchange,
            &mut transport,
            &mut signer,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        let url = match result {
            Ok(url) => url,
            Err(_) => panic!("prepared account creation failed"),
        };
        assert_eq!(url.as_str(), "https://ca.example/account/1");
        assert!(lifecycle.active);
        assert_eq!(lifecycle.generation, 1);
        assert_eq!(lifecycle.operation, AccountOperation::None);
    }

    #[test]
    fn ambiguous_post_failure_enters_uncertain_state() {
        let (directory, key, mut lifecycle, receipt) = prepared();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = Transport { fail_post: true };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        assert!(
            execute_prepared_account_create(
                &mut lifecycle,
                receipt,
                &directory,
                &["mailto:owner@example.com"],
                None,
                &key,
                &mut exchange,
                &mut transport,
                &mut signer,
                AccountCreateBuffers {
                    payload: &mut payload,
                    response: &mut response,
                    jws: &mut jws,
                },
            )
            .is_err()
        );
        assert_eq!(lifecycle.operation, AccountOperation::Uncertain);
    }
}
