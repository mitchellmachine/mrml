use crate::{
    write_flattened_jws, AcmeContentType, AcmeExchange, AcmeHttpMethod, AcmeJwsSigner, AcmeProblem,
    AcmeResponseMetadata, AcmeTransport, AcmeTransportRequest, AcmeUrl, BadNonceRetry, JoseError,
    ProblemError, ProtectedKey, TransportError,
};

pub const MAX_JWS_REQUEST_BYTES: usize = 48 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmePostError<E> {
    Transport(TransportError<E>),
    Jose(JoseError),
    Problem(ProblemError),
    InvalidProblemEncoding,
    BadNonceRetryExhausted,
}

pub struct AcmePostResponse {
    pub metadata: AcmeResponseMetadata,
    pub problem: Option<AcmeProblem>,
}

pub fn post_jws<T: AcmeTransport>(
    exchange: &mut AcmeExchange,
    transport: &mut T,
    new_nonce_url: &AcmeUrl,
    url: &AcmeUrl,
    key: ProtectedKey<'_>,
    payload: &[u8],
    account_generation: u64,
    signer: &mut impl AcmeJwsSigner,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<AcmePostResponse, AcmePostError<T::Error>> {
    if jws_scratch.len() > MAX_JWS_REQUEST_BYTES {
        return Err(AcmePostError::Jose(JoseError::OutputTooSmall));
    }
    let mut retries = BadNonceRetry::new();
    loop {
        let nonce = exchange
            .acquire_nonce(transport, new_nonce_url)
            .map_err(AcmePostError::Transport)?;
        let directory_generation = exchange.directory_generation();
        let jws = write_flattened_jws(
            key,
            &nonce,
            url,
            payload,
            directory_generation,
            account_generation,
            signer,
            jws_scratch,
        )
        .map_err(AcmePostError::Jose)?;
        let jws_len = jws.len();
        let metadata = exchange
            .execute(
                transport,
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Post,
                    url,
                    content_type: AcmeContentType::JoseJson,
                    body: &jws_scratch[..jws_len],
                },
                response_body,
            )
            .map_err(AcmePostError::Transport);
        jws_scratch[..jws_len].fill(0);
        let metadata = metadata?;
        let problem = if (400..=599).contains(&metadata.status) {
            let text = core::str::from_utf8(&response_body[..metadata.body_length])
                .map_err(|_| AcmePostError::InvalidProblemEncoding)?;
            Some(AcmeProblem::parse(text).map_err(AcmePostError::Problem)?)
        } else {
            None
        };
        if problem.as_ref().is_some_and(AcmeProblem::is_bad_nonce) {
            retries
                .retry()
                .map_err(|_| AcmePostError::BadNonceRetryExhausted)?;
            response_body[..metadata.body_length].fill(0);
            continue;
        }
        return Ok(AcmePostResponse { metadata, problem });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcmeTransportResponse, ApprovedAcmeJwsDigest, Es256Signature};

    struct Signer {
        calls: usize,
    }
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            approved: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            assert_ne!(approved.digest(), &[0; 32]);
            self.calls += 1;
            Es256Signature::from_raw([1; 64])
        }
    }

    struct Transport {
        calls: usize,
    }
    impl AcmeTransport for Transport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            let (status, nonce, body) = match self.calls {
                1 => (200, Some("nonce-1"), ""),
                2 => (
                    400,
                    Some("nonce-2"),
                    r#"{"type":"urn:ietf:params:acme:error:badNonce","status":400}"#,
                ),
                _ => (201, Some("nonce-3"), r#"{"status":"valid"}"#),
            };
            output[..body.len()].copy_from_slice(body.as_bytes());
            Ok(AcmeTransportResponse {
                status,
                effective_url: if request.method == AcmeHttpMethod::Head {
                    "https://ca.example/new-nonce"
                } else {
                    "https://ca.example/new-order"
                },
                replay_nonce: nonce,
                retry_after: None,
                location: None,
                body_length: body.len(),
            })
        }
    }

    #[test]
    fn bad_nonce_rebuilds_and_resigns_with_fresh_nonce() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let nonce_url = AcmeUrl::parse("https://ca.example/new-nonce", false).unwrap();
        let account_url = AcmeUrl::parse("https://ca.example/account/1", false).unwrap();
        let order_url = AcmeUrl::parse("https://ca.example/new-order", false).unwrap();
        let mut exchange = AcmeExchange::new(7, directory);
        let mut transport = Transport { calls: 0 };
        let mut signer = Signer { calls: 0 };
        let mut response = [0; 1024];
        let mut jws = [0; 8192];
        let result = post_jws(
            &mut exchange,
            &mut transport,
            &nonce_url,
            &order_url,
            ProtectedKey::Kid(&account_url),
            b"{}",
            3,
            &mut signer,
            &mut response,
            &mut jws,
        )
        .unwrap();
        assert_eq!(result.metadata.status, 201);
        assert!(result.problem.is_none());
        assert_eq!(transport.calls, 3);
        assert_eq!(signer.calls, 2);
        assert!(jws.iter().all(|byte| *byte == 0));
    }
}
