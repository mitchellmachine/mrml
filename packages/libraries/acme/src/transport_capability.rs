use crate::{
    AcmeContentType, AcmeHttpMethod, AcmeTransport, AcmeTransportRequest, AcmeTransportResponse,
    AcmeUrl, MAX_ALTERNATE_LINK_BYTES, MAX_ALTERNATE_LINKS, MAX_CONTENT_TYPE_BYTES,
    MAX_NONCE_BYTES, MAX_RETRY_AFTER_BYTES, MAX_URL_BYTES,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmeHttpsRoute {
    pub capability_identity: [u8; 16],
    pub route_generation: u64,
    pub directory_generation: u64,
    pub origin: AcmeUrl,
}

#[derive(Clone, Copy)]
pub struct CapabilityHttpsRequest<'a> {
    pub route: AcmeHttpsRoute,
    pub method: AcmeHttpMethod,
    pub url: &'a str,
    pub content_type: AcmeContentType,
    pub body: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct CapabilityHttpsResponse {
    pub capability_identity: [u8; 16],
    pub route_generation: u64,
    pub directory_generation: u64,
    pub status: u16,
    pub body_length: usize,
    pub effective_url: [u8; MAX_URL_BYTES],
    pub effective_url_length: u16,
    pub replay_nonce: [u8; MAX_NONCE_BYTES],
    pub replay_nonce_length: u16,
    pub retry_after: [u8; MAX_RETRY_AFTER_BYTES],
    pub retry_after_length: u8,
    pub location: [u8; MAX_URL_BYTES],
    pub location_length: u16,
    pub content_type: [u8; MAX_CONTENT_TYPE_BYTES],
    pub content_type_length: u8,
    pub alternate_links: [[u8; MAX_ALTERNATE_LINK_BYTES]; MAX_ALTERNATE_LINKS],
    pub alternate_link_lengths: [u16; MAX_ALTERNATE_LINKS],
    pub alternate_link_count: u8,
}

impl CapabilityHttpsResponse {
    pub const fn empty(route: AcmeHttpsRoute) -> Self {
        Self {
            capability_identity: route.capability_identity,
            route_generation: route.route_generation,
            directory_generation: route.directory_generation,
            status: 0,
            body_length: 0,
            effective_url: [0; MAX_URL_BYTES],
            effective_url_length: 0,
            replay_nonce: [0; MAX_NONCE_BYTES],
            replay_nonce_length: 0,
            retry_after: [0; MAX_RETRY_AFTER_BYTES],
            retry_after_length: 0,
            location: [0; MAX_URL_BYTES],
            location_length: 0,
            content_type: [0; MAX_CONTENT_TYPE_BYTES],
            content_type_length: 0,
            alternate_links: [[0; MAX_ALTERNATE_LINK_BYTES]; MAX_ALTERNATE_LINKS],
            alternate_link_lengths: [0; MAX_ALTERNATE_LINKS],
            alternate_link_count: 0,
        }
    }
}

pub trait AcmeHttpsCapability {
    type Error;

    /// Performs one authenticated HTTPS exchange through this capability.
    /// Implementations must not broaden the exact URL or route in `request`.
    fn exchange(
        &mut self,
        request: CapabilityHttpsRequest<'_>,
        response_body: &mut [u8],
    ) -> Result<CapabilityHttpsResponse, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityTransportError<E> {
    Backend(E),
    InvalidRoute,
    RouteSubstitution,
    InvalidReceipt,
}

pub struct CapabilityAcmeTransport<B> {
    route: AcmeHttpsRoute,
    backend: B,
    response: CapabilityHttpsResponse,
}

impl<B> CapabilityAcmeTransport<B> {
    pub fn new(route: AcmeHttpsRoute, backend: B) -> Result<Self, CapabilityTransportError<()>> {
        if route.capability_identity == [0; 16]
            || route.route_generation == 0
            || route.directory_generation == 0
            || route.origin.origin().scheme != crate::AcmeScheme::Https
        {
            return Err(CapabilityTransportError::InvalidRoute);
        }
        Ok(Self {
            route,
            backend,
            response: CapabilityHttpsResponse::empty(route),
        })
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

impl<B: AcmeHttpsCapability> AcmeTransport for CapabilityAcmeTransport<B> {
    type Error = CapabilityTransportError<B::Error>;

    fn exchange(
        &mut self,
        request: AcmeTransportRequest<'_>,
        output: &mut [u8],
    ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
        request
            .url
            .require_origin(self.route.origin.origin())
            .map_err(|_| CapabilityTransportError::RouteSubstitution)?;
        let response = self
            .backend
            .exchange(
                CapabilityHttpsRequest {
                    route: self.route,
                    method: request.method,
                    url: request.url.as_str(),
                    content_type: request.content_type,
                    body: request.body,
                },
                output,
            )
            .map_err(CapabilityTransportError::Backend)?;
        validate_response(self.route, request.url.as_str(), output.len(), &response)?;
        self.response = response;
        Ok(AcmeTransportResponse {
            status: response.status,
            effective_url: text(
                &self.response.effective_url,
                usize::from(self.response.effective_url_length),
            )?,
            replay_nonce: optional_text(
                &self.response.replay_nonce,
                usize::from(self.response.replay_nonce_length),
            )?,
            retry_after: optional_text(
                &self.response.retry_after,
                usize::from(self.response.retry_after_length),
            )?,
            location: optional_text(
                &self.response.location,
                usize::from(self.response.location_length),
            )?,
            content_type: optional_text(
                &self.response.content_type,
                usize::from(self.response.content_type_length),
            )?,
            body_length: response.body_length,
        })
    }

    fn response_alternate_link(&self, index: usize) -> Option<&str> {
        if index >= usize::from(self.response.alternate_link_count) {
            return None;
        }
        let length = usize::from(self.response.alternate_link_lengths[index]);
        core::str::from_utf8(&self.response.alternate_links[index][..length]).ok()
    }
}

fn validate_response<E>(
    route: AcmeHttpsRoute,
    requested_url: &str,
    output_length: usize,
    response: &CapabilityHttpsResponse,
) -> Result<(), CapabilityTransportError<E>> {
    if response.capability_identity != route.capability_identity
        || response.route_generation != route.route_generation
        || response.directory_generation != route.directory_generation
    {
        return Err(CapabilityTransportError::RouteSubstitution);
    }
    let effective_url = text(
        &response.effective_url,
        usize::from(response.effective_url_length),
    )?;
    if effective_url != requested_url
        || response.body_length > output_length
        || !(100..=599).contains(&response.status)
        || usize::from(response.alternate_link_count) > MAX_ALTERNATE_LINKS
    {
        return Err(CapabilityTransportError::InvalidReceipt);
    }
    optional_text(
        &response.replay_nonce,
        usize::from(response.replay_nonce_length),
    )?;
    optional_text(
        &response.retry_after,
        usize::from(response.retry_after_length),
    )?;
    optional_text(&response.location, usize::from(response.location_length))?;
    optional_text(
        &response.content_type,
        usize::from(response.content_type_length),
    )?;
    for index in 0..usize::from(response.alternate_link_count) {
        let length = usize::from(response.alternate_link_lengths[index]);
        let value = text(&response.alternate_links[index], length)?;
        if value.is_empty()
            || response.alternate_link_lengths[..index]
                .iter()
                .enumerate()
                .any(|(prior, prior_length)| {
                    usize::from(*prior_length) == length
                        && response.alternate_links[prior][..length]
                            == response.alternate_links[index][..length]
                })
        {
            return Err(CapabilityTransportError::InvalidReceipt);
        }
    }
    if response.alternate_link_lengths[usize::from(response.alternate_link_count)..]
        .iter()
        .any(|length| *length != 0)
    {
        return Err(CapabilityTransportError::InvalidReceipt);
    }
    Ok(())
}

fn text<E>(bytes: &[u8], length: usize) -> Result<&str, CapabilityTransportError<E>> {
    let value = bytes
        .get(..length)
        .ok_or(CapabilityTransportError::InvalidReceipt)?;
    if value.is_empty() || !value.is_ascii() {
        return Err(CapabilityTransportError::InvalidReceipt);
    }
    core::str::from_utf8(value).map_err(|_| CapabilityTransportError::InvalidReceipt)
}

fn optional_text<E>(
    bytes: &[u8],
    length: usize,
) -> Result<Option<&str>, CapabilityTransportError<E>> {
    if length == 0 {
        Ok(None)
    } else {
        text(bytes, length).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend {
        substitute_route: bool,
    }

    impl AcmeHttpsCapability for Backend {
        type Error = ();

        fn exchange(
            &mut self,
            request: CapabilityHttpsRequest<'_>,
            body: &mut [u8],
        ) -> Result<CapabilityHttpsResponse, Self::Error> {
            assert_eq!(request.method, AcmeHttpMethod::Get);
            assert!(request.body.is_empty());
            body[..2].copy_from_slice(b"{}");
            let mut response = CapabilityHttpsResponse::empty(request.route);
            if self.substitute_route {
                response.route_generation += 1;
            }
            response.status = 200;
            response.body_length = 2;
            response.effective_url[..request.url.len()].copy_from_slice(request.url.as_bytes());
            response.effective_url_length = request.url.len() as u16;
            response.replay_nonce[..5].copy_from_slice(b"nonce");
            response.replay_nonce_length = 5;
            response.content_type[..16].copy_from_slice(b"application/json");
            response.content_type_length = 16;
            Ok(response)
        }
    }

    fn route() -> AcmeHttpsRoute {
        AcmeHttpsRoute {
            capability_identity: [7; 16],
            route_generation: 4,
            directory_generation: 9,
            origin: AcmeUrl::parse("https://ca.example/directory", false).unwrap(),
        }
    }

    #[test]
    fn capability_adapter_binds_exact_route_and_authenticated_receipt() {
        let url = AcmeUrl::parse("https://ca.example/new-order", false).unwrap();
        let mut transport = CapabilityAcmeTransport::new(
            route(),
            Backend {
                substitute_route: false,
            },
        )
        .unwrap();
        let mut body = [0u8; 16];
        let response = transport
            .exchange(
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &url,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            )
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.replay_nonce, Some("nonce"));
        assert_eq!(&body[..response.body_length], b"{}");
    }

    #[test]
    fn capability_adapter_rejects_origin_and_route_substitution() {
        let other = AcmeUrl::parse("https://other.example/order", false).unwrap();
        let mut transport = CapabilityAcmeTransport::new(
            route(),
            Backend {
                substitute_route: false,
            },
        )
        .unwrap();
        let mut body = [0u8; 16];
        assert!(matches!(
            transport.exchange(
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &other,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            ),
            Err(CapabilityTransportError::RouteSubstitution)
        ));
        let url = AcmeUrl::parse("https://ca.example/order", false).unwrap();
        let mut transport = CapabilityAcmeTransport::new(
            route(),
            Backend {
                substitute_route: true,
            },
        )
        .unwrap();
        assert!(matches!(
            transport.exchange(
                AcmeTransportRequest {
                    method: AcmeHttpMethod::Get,
                    url: &url,
                    content_type: AcmeContentType::Empty,
                    body: &[],
                },
                &mut body,
            ),
            Err(CapabilityTransportError::RouteSubstitution)
        ));
    }
}
