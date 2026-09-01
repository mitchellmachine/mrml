use crate::{AcmeUrl, NonceError, NoncePool, ReplayNonce, UrlError};

pub const MAX_ACME_RESPONSE_BODY: usize = 64 * 1024;
pub const MAX_RETRY_AFTER_BYTES: usize = 64;
pub const MAX_CONTENT_TYPE_BYTES: usize = 128;
pub const MAX_BAD_NONCE_RETRIES: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeHttpMethod {
    Get,
    Head,
    Post,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeContentType {
    Empty,
    JoseJson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeResponseType {
    Missing,
    Json,
    ProblemJson,
    PemCertificateChain,
    Other,
}

/// A request whose endpoint has already been admitted by the current directory
/// generation. The transport adapter may resolve and connect only to `url`.
pub struct AcmeTransportRequest<'a> {
    pub method: AcmeHttpMethod,
    pub url: &'a AcmeUrl,
    pub content_type: AcmeContentType,
    pub body: &'a [u8],
}

/// Bounded response metadata returned by a platform HTTPS adapter. Header
/// parsing stays in the adapter, but singleton enforcement is part of its
/// contract and is independently checked by shared state below.
pub struct AcmeTransportResponse<'a> {
    pub status: u16,
    pub effective_url: &'a str,
    pub replay_nonce: Option<&'a str>,
    pub retry_after: Option<&'a str>,
    pub location: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub body_length: usize,
}

/// Authenticated HTTPS and bounded I/O boundary for all ACME operations.
///
/// Implementations must authenticate the configured peer, reject duplicate
/// singleton headers, never follow redirects, write at most `body.len()` bytes,
/// and report the exact effective request URL. DNS resolution and connection
/// reuse must not broaden the admitted origin.
pub trait AcmeTransport {
    type Error;

    fn exchange(
        &mut self,
        request: AcmeTransportRequest<'_>,
        body: &mut [u8],
    ) -> Result<AcmeTransportResponse<'_>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError<E> {
    Adapter(E),
    Url(UrlError),
    RedirectForbidden,
    ResponseTooLarge,
    InvalidStatus,
    InvalidContentType,
    MissingReplayNonce,
    Nonce(NonceError),
    BadNonceRetryExhausted,
    RetryAfterTooLong,
}

pub struct AcmeExchange {
    directory_generation: u64,
    origin_url: AcmeUrl,
    nonces: NoncePool,
}

impl AcmeExchange {
    pub const fn new(directory_generation: u64, origin_url: AcmeUrl) -> Self {
        Self {
            directory_generation,
            origin_url,
            nonces: NoncePool::new(directory_generation),
        }
    }

    pub fn replace_directory(&mut self, generation: u64, origin_url: AcmeUrl) {
        self.directory_generation = generation;
        self.origin_url = origin_url;
        self.nonces.replace_generation(generation);
    }

    pub const fn directory_generation(&self) -> u64 {
        self.directory_generation
    }

    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }

    pub fn consume_nonce(
        &mut self,
    ) -> Result<ReplayNonce, TransportError<core::convert::Infallible>> {
        self.nonces
            .consume(self.directory_generation)
            .map_err(TransportError::Nonce)
    }

    pub fn execute<T: AcmeTransport>(
        &mut self,
        transport: &mut T,
        request: AcmeTransportRequest<'_>,
        output: &mut [u8],
    ) -> Result<AcmeResponseMetadata, TransportError<T::Error>> {
        request
            .url
            .require_origin(self.origin_url.origin())
            .map_err(TransportError::Url)?;
        if output.len() > MAX_ACME_RESPONSE_BODY {
            return Err(TransportError::ResponseTooLarge);
        }
        if request.method != AcmeHttpMethod::Post && !request.body.is_empty() {
            return Err(TransportError::InvalidContentType);
        }
        if request.method == AcmeHttpMethod::Post
            && request.content_type != AcmeContentType::JoseJson
        {
            return Err(TransportError::InvalidContentType);
        }
        let expected_url = request.url.as_str();
        let response = transport
            .exchange(request, output)
            .map_err(TransportError::Adapter)?;
        if response.body_length > output.len() || response.body_length > MAX_ACME_RESPONSE_BODY {
            return Err(TransportError::ResponseTooLarge);
        }
        if response.effective_url != expected_url || (300..=399).contains(&response.status) {
            return Err(TransportError::RedirectForbidden);
        }
        if !(100..=599).contains(&response.status) {
            return Err(TransportError::InvalidStatus);
        }
        if response
            .retry_after
            .is_some_and(|value| value.len() > MAX_RETRY_AFTER_BYTES)
        {
            return Err(TransportError::RetryAfterTooLong);
        }
        if let Some(value) = response.replay_nonce {
            let nonce = ReplayNonce::parse(value).map_err(TransportError::Nonce)?;
            self.nonces
                .insert(self.directory_generation, nonce)
                .map_err(TransportError::Nonce)?;
        }
        let location = response
            .location
            .map(|value| {
                let url = AcmeUrl::parse(value, true).map_err(TransportError::Url)?;
                url.require_origin(self.origin_url.origin())
                    .map_err(TransportError::Url)?;
                Ok(url)
            })
            .transpose()?;
        let response_type = classify_response_type(response.content_type)?;
        Ok(AcmeResponseMetadata {
            status: response.status,
            body_length: response.body_length,
            has_retry_after: response.retry_after.is_some(),
            location,
            response_type,
        })
    }

    pub fn acquire_nonce<T: AcmeTransport>(
        &mut self,
        transport: &mut T,
        new_nonce_url: &AcmeUrl,
    ) -> Result<ReplayNonce, TransportError<T::Error>> {
        if let Ok(nonce) = self.nonces.consume(self.directory_generation) {
            return Ok(nonce);
        }
        let mut empty = [];
        self.execute(
            transport,
            AcmeTransportRequest {
                method: AcmeHttpMethod::Head,
                url: new_nonce_url,
                content_type: AcmeContentType::Empty,
                body: &[],
            },
            &mut empty,
        )?;
        self.nonces
            .consume(self.directory_generation)
            .map_err(|error| match error {
                NonceError::Unavailable => TransportError::MissingReplayNonce,
                other => TransportError::Nonce(other),
            })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmeResponseMetadata {
    pub status: u16,
    pub body_length: usize,
    pub has_retry_after: bool,
    pub location: Option<AcmeUrl>,
    pub response_type: AcmeResponseType,
}

fn classify_response_type<E>(value: Option<&str>) -> Result<AcmeResponseType, TransportError<E>> {
    let Some(value) = value else {
        return Ok(AcmeResponseType::Missing);
    };
    if value.len() > MAX_CONTENT_TYPE_BYTES || !value.is_ascii() {
        return Err(TransportError::InvalidContentType);
    }
    let essence = value.split(';').next().unwrap_or("").trim();
    Ok(if essence.eq_ignore_ascii_case("application/json") {
        AcmeResponseType::Json
    } else if essence.eq_ignore_ascii_case("application/problem+json") {
        AcmeResponseType::ProblemJson
    } else if essence.eq_ignore_ascii_case("application/pem-certificate-chain") {
        AcmeResponseType::PemCertificateChain
    } else {
        AcmeResponseType::Other
    })
}

pub struct BadNonceRetry {
    attempts: u8,
}

impl Default for BadNonceRetry {
    fn default() -> Self {
        Self::new()
    }
}

impl BadNonceRetry {
    pub const fn new() -> Self {
        Self { attempts: 0 }
    }

    /// Records a typed `badNonce` response. The caller must rebuild and resign
    /// the complete JWS with a newly consumed nonce before the next attempt.
    pub fn retry(&mut self) -> Result<(), TransportError<core::convert::Infallible>> {
        if self.attempts >= MAX_BAD_NONCE_RETRIES {
            return Err(TransportError::BadNonceRetryExhausted);
        }
        self.attempts += 1;
        Ok(())
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_bounded_acme_media_types() {
        assert_eq!(
            classify_response_type::<()>(Some("Application/JSON; charset=utf-8")).unwrap(),
            AcmeResponseType::Json
        );
        assert_eq!(
            classify_response_type::<()>(Some("application/problem+json")).unwrap(),
            AcmeResponseType::ProblemJson
        );
        assert_eq!(
            classify_response_type::<()>(Some("application/pem-certificate-chain")).unwrap(),
            AcmeResponseType::PemCertificateChain
        );
        assert_eq!(
            classify_response_type::<()>(Some("text/plain")).unwrap(),
            AcmeResponseType::Other
        );
    }

    struct Adapter<'a> {
        effective_url: &'a str,
        nonce: Option<&'a str>,
        location: Option<&'a str>,
        status: u16,
        calls: usize,
    }

    impl AcmeTransport for Adapter<'_> {
        type Error = ();

        fn exchange(
            &mut self,
            _: AcmeTransportRequest<'_>,
            body: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            if !body.is_empty() {
                body[0] = b'{'
            }
            Ok(AcmeTransportResponse {
                status: self.status,
                effective_url: self.effective_url,
                replay_nonce: self.nonce,
                retry_after: None,
                location: self.location,
                content_type: None,
                body_length: usize::from(!body.is_empty()),
            })
        }
    }

    #[test]
    fn acquires_and_consumes_each_nonce_once() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let nonce_url = AcmeUrl::parse("https://ca.example/new-nonce", false).unwrap();
        let mut state = AcmeExchange::new(7, directory);
        let mut adapter = Adapter {
            effective_url: nonce_url.as_str(),
            nonce: Some("nonce_1"),
            location: None,
            calls: 0,
            status: 200,
        };
        assert_eq!(
            state
                .acquire_nonce(&mut adapter, &nonce_url)
                .unwrap()
                .as_str(),
            "nonce_1"
        );
        assert_eq!(adapter.calls, 1);
        assert_eq!(state.nonce_count(), 0);
    }

    #[test]
    fn rejects_redirect_and_cross_origin_before_trusting_response() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let endpoint = AcmeUrl::parse("https://ca.example/new-order", false).unwrap();
        let foreign = AcmeUrl::parse("https://metadata.example/x", false).unwrap();
        let mut state = AcmeExchange::new(1, directory);
        let mut redirected = Adapter {
            effective_url: endpoint.as_str(),
            nonce: None,
            location: Some("https://other.example/x"),
            calls: 0,
            status: 302,
        };
        let mut body = [0; 8];
        assert!(matches!(
            state.execute(
                &mut redirected,
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &endpoint,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            ),
            Err(TransportError::RedirectForbidden)
        ));
        assert!(matches!(
            state.execute(
                &mut redirected,
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &foreign,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            ),
            Err(TransportError::Url(UrlError::OriginMismatch))
        ));
        assert_eq!(redirected.calls, 1);
    }

    #[test]
    fn accepts_same_origin_resource_location_but_rejects_scheme_change() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let endpoint = AcmeUrl::parse("https://ca.example/new-account", false).unwrap();
        let mut state = AcmeExchange::new(1, directory);
        let mut created = Adapter {
            effective_url: endpoint.as_str(),
            nonce: Some("next"),
            location: Some("https://ca.example/account/1"),
            calls: 0,
            status: 201,
        };
        let mut body = [0; 8];
        let metadata = state
            .execute(
                &mut created,
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &endpoint,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            )
            .unwrap();
        assert_eq!(
            metadata.location.unwrap().as_str(),
            "https://ca.example/account/1"
        );
        created.location = Some("http://ca.example:443/account/2");
        assert!(matches!(
            state.execute(
                &mut created,
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &endpoint,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            ),
            Err(TransportError::Url(UrlError::OriginMismatch))
        ));
    }

    #[test]
    fn bounds_bad_nonce_retries() {
        let mut retry = BadNonceRetry::new();
        assert!(retry.retry().is_ok());
        assert!(retry.retry().is_ok());
        assert!(matches!(
            retry.retry(),
            Err(TransportError::BadNonceRetryExhausted)
        ));
    }
}
