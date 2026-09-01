use crate::{
    AcmeContentType, AcmeHttpMethod, AcmeTransport, AcmeTransportRequest, AcmeTransportResponse,
    MAX_ALTERNATE_LINK_BYTES, MAX_ALTERNATE_LINKS, MAX_CONTENT_TYPE_BYTES, MAX_NONCE_BYTES,
    MAX_RETRY_AFTER_BYTES, MAX_URL_BYTES,
};
use mrml_http::{Client, Header, HttpError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedTransportError {
    Http(HttpError),
    DuplicateSingletonHeader,
    HeaderTooLong,
    BodyTooLarge,
}

pub struct HostedAcmeTransport {
    client: Client,
    effective_url: [u8; MAX_URL_BYTES],
    effective_url_len: usize,
    replay_nonce: [u8; MAX_NONCE_BYTES],
    replay_nonce_len: usize,
    retry_after: [u8; MAX_RETRY_AFTER_BYTES],
    retry_after_len: usize,
    location: [u8; MAX_URL_BYTES],
    location_len: usize,
    content_type: [u8; MAX_CONTENT_TYPE_BYTES],
    content_type_len: usize,
    alternate_links: [[u8; MAX_ALTERNATE_LINK_BYTES]; MAX_ALTERNATE_LINKS],
    alternate_link_lens: [u16; MAX_ALTERNATE_LINKS],
    alternate_link_count: u8,
}

impl Default for HostedAcmeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HostedAcmeTransport {
    pub fn new() -> Self {
        Self {
            client: Client::new().user_agent("mrml-certd/0.1"),
            effective_url: [0; MAX_URL_BYTES],
            effective_url_len: 0,
            replay_nonce: [0; MAX_NONCE_BYTES],
            replay_nonce_len: 0,
            retry_after: [0; MAX_RETRY_AFTER_BYTES],
            retry_after_len: 0,
            location: [0; MAX_URL_BYTES],
            location_len: 0,
            content_type: [0; MAX_CONTENT_TYPE_BYTES],
            content_type_len: 0,
            alternate_links: [[0; MAX_ALTERNATE_LINK_BYTES]; MAX_ALTERNATE_LINKS],
            alternate_link_lens: [0; MAX_ALTERNATE_LINKS],
            alternate_link_count: 0,
        }
    }

    fn clear_metadata(&mut self) {
        self.effective_url.fill(0);
        self.effective_url_len = 0;
        self.replay_nonce.fill(0);
        self.replay_nonce_len = 0;
        self.retry_after.fill(0);
        self.retry_after_len = 0;
        self.location.fill(0);
        self.location_len = 0;
        self.content_type.fill(0);
        self.content_type_len = 0;
        self.alternate_links.fill([0; MAX_ALTERNATE_LINK_BYTES]);
        self.alternate_link_lens.fill(0);
        self.alternate_link_count = 0;
    }

    fn copy_singleton(
        headers: &[Header],
        name: &str,
        output: &mut [u8],
    ) -> Result<usize, HostedTransportError> {
        let mut value = None;
        for header in headers.iter().filter(|header| header.name == name) {
            if value.is_some() {
                return Err(HostedTransportError::DuplicateSingletonHeader);
            }
            value = Some(header.value.as_bytes());
        }
        let Some(value) = value else {
            return Ok(0);
        };
        if value.len() > output.len() {
            return Err(HostedTransportError::HeaderTooLong);
        }
        output[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }

    fn text(bytes: &[u8], length: usize) -> &str {
        core::str::from_utf8(&bytes[..length]).unwrap_or("")
    }

    fn capture_alternate_links(&mut self, headers: &[Header]) -> Result<(), HostedTransportError> {
        for header in headers.iter().filter(|header| header.name == "link") {
            for value in header.value.split(',') {
                let value = value.trim();
                let Some(target_end) = value.find('>') else {
                    return Err(HostedTransportError::HeaderTooLong);
                };
                if !value.starts_with('<')
                    || !value[target_end + 1..]
                        .split(';')
                        .map(str::trim)
                        .any(|parameter| {
                            parameter.eq_ignore_ascii_case("rel=\"alternate\"")
                                || parameter.eq_ignore_ascii_case("rel=alternate")
                        })
                {
                    continue;
                }
                let target = &value[1..target_end];
                if target.is_empty()
                    || target.len() > MAX_ALTERNATE_LINK_BYTES
                    || usize::from(self.alternate_link_count) == MAX_ALTERNATE_LINKS
                    || self.alternate_link_lens[..usize::from(self.alternate_link_count)]
                        .iter()
                        .enumerate()
                        .any(|(index, length)| {
                            &self.alternate_links[index][..usize::from(*length)]
                                == target.as_bytes()
                        })
                {
                    return Err(HostedTransportError::HeaderTooLong);
                }
                let index = usize::from(self.alternate_link_count);
                self.alternate_links[index][..target.len()].copy_from_slice(target.as_bytes());
                self.alternate_link_lens[index] = target.len() as u16;
                self.alternate_link_count += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_runtime::Text;

    #[test]
    fn captures_only_bounded_unique_alternate_links() {
        let headers = [
            Header {
                name: Text::from("link"),
                value: Text::from(
                    "<https://ca.example/a>; rel=\"alternate\", <https://ca.example/up>; rel=up",
                ),
            },
            Header {
                name: Text::from("link"),
                value: Text::from("<https://ca.example/b>; rel=alternate"),
            },
        ];
        let mut transport = HostedAcmeTransport::new();
        transport.capture_alternate_links(&headers).unwrap();
        assert_eq!(
            transport.response_alternate_link(0),
            Some("https://ca.example/a")
        );
        assert_eq!(
            transport.response_alternate_link(1),
            Some("https://ca.example/b")
        );
        assert_eq!(transport.response_alternate_link(2), None);
    }

    #[test]
    fn duplicate_or_malformed_alternate_links_fail_closed() {
        let duplicate = [Header {
            name: Text::from("link"),
            value: Text::from(
                "<https://ca.example/a>; rel=alternate, <https://ca.example/a>; rel=alternate",
            ),
        }];
        assert_eq!(
            HostedAcmeTransport::new()
                .capture_alternate_links(&duplicate)
                .err(),
            Some(HostedTransportError::HeaderTooLong)
        );
        let malformed = [Header {
            name: Text::from("link"),
            value: Text::from("https://ca.example/a; rel=alternate"),
        }];
        assert_eq!(
            HostedAcmeTransport::new()
                .capture_alternate_links(&malformed)
                .err(),
            Some(HostedTransportError::HeaderTooLong)
        );
    }
}

impl AcmeTransport for HostedAcmeTransport {
    type Error = HostedTransportError;

    fn exchange(
        &mut self,
        request: AcmeTransportRequest<'_>,
        output: &mut [u8],
    ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
        self.clear_metadata();
        let url = request.url.as_str();
        self.effective_url[..url.len()].copy_from_slice(url.as_bytes());
        self.effective_url_len = url.len();
        let mut response = match request.method {
            AcmeHttpMethod::Get => self.client.get(url, &[]),
            AcmeHttpMethod::Head => self.client.head(url, &[]),
            AcmeHttpMethod::Post => {
                if request.content_type != AcmeContentType::JoseJson {
                    return Err(HostedTransportError::Http(HttpError::InvalidUrl));
                }
                self.client.post(
                    url,
                    &[
                        ("Content-Type", "application/jose+json"),
                        (
                            "Accept",
                            "application/json, application/problem+json, application/pem-certificate-chain",
                        ),
                    ],
                    request.body,
                )
            }
        }
        .map_err(HostedTransportError::Http)?;
        self.replay_nonce_len =
            Self::copy_singleton(&response.headers, "replay-nonce", &mut self.replay_nonce)?;
        self.retry_after_len =
            Self::copy_singleton(&response.headers, "retry-after", &mut self.retry_after)?;
        self.location_len =
            Self::copy_singleton(&response.headers, "location", &mut self.location)?;
        self.content_type_len =
            Self::copy_singleton(&response.headers, "content-type", &mut self.content_type)?;
        self.capture_alternate_links(&response.headers)?;
        let status = response.status;
        let body = if request.method == AcmeHttpMethod::Head {
            mrml_runtime::Vector::new()
        } else {
            response
                .read_to_end(output.len())
                .map_err(|error| match error {
                    HttpError::BodyTooLarge => HostedTransportError::BodyTooLarge,
                    other => HostedTransportError::Http(other),
                })?
        };
        output[..body.len()].copy_from_slice(&body);
        Ok(AcmeTransportResponse {
            status,
            effective_url: Self::text(&self.effective_url, self.effective_url_len),
            replay_nonce: (self.replay_nonce_len != 0)
                .then(|| Self::text(&self.replay_nonce, self.replay_nonce_len)),
            retry_after: (self.retry_after_len != 0)
                .then(|| Self::text(&self.retry_after, self.retry_after_len)),
            location: (self.location_len != 0)
                .then(|| Self::text(&self.location, self.location_len)),
            content_type: (self.content_type_len != 0)
                .then(|| Self::text(&self.content_type, self.content_type_len)),
            body_length: body.len(),
        })
    }

    fn response_alternate_link(&self, index: usize) -> Option<&str> {
        if index >= usize::from(self.alternate_link_count) {
            return None;
        }
        Some(Self::text(
            &self.alternate_links[index],
            usize::from(self.alternate_link_lens[index]),
        ))
    }
}
