use mrml_acme::{
    ChallengeKind, ChallengePublicationRequest, MAX_HTTP01_REQUEST, MAX_KEY_AUTHORIZATION,
    validate_http01_identifier_request,
};
use mrml_crypto::Sha256;
use mrml_runtime::{NetError, TcpListener, TcpStream};

pub const HTTP01_READ_TIMEOUT_MILLIS: u64 = 2_000;
pub const HTTP01_WRITE_TIMEOUT_MILLIS: u64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedHttp01Error {
    InvalidChallenge,
    KeyAuthorizationMismatch,
    NotActive,
    Expired,
    RequestTooLarge,
    Network(NetError),
}

pub struct HostedHttp01Challenge {
    request: ChallengePublicationRequest,
    key_authorization: [u8; MAX_KEY_AUTHORIZATION],
    key_authorization_len: u8,
}

impl HostedHttp01Challenge {
    pub fn new(
        request: ChallengePublicationRequest,
        key_authorization: &[u8],
    ) -> Result<Self, HostedHttp01Error> {
        if request.kind != ChallengeKind::Http01
            || key_authorization.is_empty()
            || key_authorization.len() > MAX_KEY_AUTHORIZATION
            || Sha256::digest(key_authorization) != request.key_authorization_digest
        {
            return Err(HostedHttp01Error::KeyAuthorizationMismatch);
        }
        let mut stored = [0; MAX_KEY_AUTHORIZATION];
        stored[..key_authorization.len()].copy_from_slice(key_authorization);
        Ok(Self {
            request,
            key_authorization: stored,
            key_authorization_len: key_authorization.len() as u8,
        })
    }

    pub fn serve_one(
        &self,
        listener: &TcpListener,
        now_unix: u64,
    ) -> Result<bool, HostedHttp01Error> {
        let stream = listener.accept().map_err(HostedHttp01Error::Network)?;
        self.serve_stream(stream, now_unix)
    }

    pub fn serve_stream(
        &self,
        mut stream: TcpStream,
        now_unix: u64,
    ) -> Result<bool, HostedHttp01Error> {
        if now_unix < self.request.not_before_unix {
            return Err(HostedHttp01Error::NotActive);
        }
        if now_unix >= self.request.expires_unix {
            return Err(HostedHttp01Error::Expired);
        }
        stream
            .set_read_timeout_millis(HTTP01_READ_TIMEOUT_MILLIS)
            .map_err(HostedHttp01Error::Network)?;
        stream
            .set_write_timeout_millis(HTTP01_WRITE_TIMEOUT_MILLIS)
            .map_err(HostedHttp01Error::Network)?;
        let mut request = [0; MAX_HTTP01_REQUEST];
        let mut used = 0usize;
        loop {
            if used == request.len() {
                return Err(HostedHttp01Error::RequestTooLarge);
            }
            let read = stream
                .read(&mut request[used..])
                .map_err(HostedHttp01Error::Network)?;
            if read == 0 {
                break;
            }
            used += read;
            if request[..used].ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let valid = validate_http01_identifier_request(
            &request[..used],
            &self.request.identifier,
            &self.request.token,
        )
        .is_ok();
        if valid {
            let body = &self.key_authorization[..usize::from(self.key_authorization_len)];
            let mut length = [0u8; 20];
            let length = decimal(body.len(), &mut length);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ")
                .map_err(HostedHttp01Error::Network)?;
            stream
                .write_all(length)
                .map_err(HostedHttp01Error::Network)?;
            stream
                .write_all(b"\r\n\r\n")
                .map_err(HostedHttp01Error::Network)?;
            stream.write_all(body).map_err(HostedHttp01Error::Network)?;
        } else {
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .map_err(HostedHttp01Error::Network)?;
        }
        Ok(valid)
    }
}

impl Drop for HostedHttp01Challenge {
    fn drop(&mut self) {
        self.key_authorization.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

fn decimal(value: usize, output: &mut [u8; 20]) -> &[u8] {
    let mut value = value;
    let mut cursor = output.len();
    loop {
        cursor -= 1;
        output[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &output[cursor..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::{AcmeUrl, ChallengeLifecycle, ChallengeToken, DnsIdentifier, JwkThumbprint};

    fn challenge() -> (HostedHttp01Challenge, [u8; MAX_KEY_AUTHORIZATION], usize) {
        let token = ChallengeToken::parse("exact-token").unwrap();
        let thumbprint = JwkThumbprint([3; 32]);
        let mut key_authorization = [0; MAX_KEY_AUTHORIZATION];
        let written =
            mrml_acme::write_key_authorization(&token, thumbprint, &mut key_authorization).unwrap();
        let lifecycle = ChallengeLifecycle::new(
            1,
            &AcmeUrl::parse("https://ca.example/order/1", false).unwrap(),
            &AcmeUrl::parse("https://ca.example/authz/1", false).unwrap(),
            mrml_acme::AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap()),
            ChallengeKind::Http01,
            token,
            thumbprint,
            10,
            20,
            1,
        )
        .unwrap();
        (
            HostedHttp01Challenge::new(lifecycle.request, &key_authorization[..written]).unwrap(),
            key_authorization,
            written,
        )
    }

    #[test]
    fn loopback_serves_only_exact_active_token() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let (challenge, key_authorization, key_authorization_len) = challenge();
        assert!(
            mrml_runtime::spawn_detached(move || {
                assert_eq!(challenge.serve_one(&listener, 15), Ok(true));
            })
            .is_ok()
        );
        let mut client = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        client.set_read_timeout_millis(1000).unwrap();
        client
            .write_all(b"GET /.well-known/acme-challenge/exact-token HTTP/1.1\r\nHost: git.example\r\n\r\n")
            .unwrap();
        let mut response = [0; 512];
        let mut used = 0usize;
        loop {
            let read = client.read(&mut response[used..]).unwrap();
            if read == 0 {
                break;
            }
            used += read;
        }
        assert!(response[..used].starts_with(b"HTTP/1.1 200 OK\r\n"));
        let start = response[..used]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert_eq!(
            &response[start..used],
            &key_authorization[..key_authorization_len]
        );
    }

    #[test]
    fn loopback_serves_exact_ipv4_identifier_authority() {
        let token = ChallengeToken::parse("ip-token").unwrap();
        let thumbprint = JwkThumbprint([4; 32]);
        let mut key_authorization = [0; MAX_KEY_AUTHORIZATION];
        let written =
            mrml_acme::write_key_authorization(&token, thumbprint, &mut key_authorization).unwrap();
        let lifecycle = ChallengeLifecycle::new(
            2,
            &AcmeUrl::parse("https://ca.example/order/ip", false).unwrap(),
            &AcmeUrl::parse("https://ca.example/authz/ip", false).unwrap(),
            mrml_acme::AcmeIdentifier::Ip(mrml_acme::IpIdentifier::parse("127.0.0.1").unwrap()),
            ChallengeKind::Http01,
            token,
            thumbprint,
            10,
            20,
            1,
        )
        .unwrap();
        let challenge =
            HostedHttp01Challenge::new(lifecycle.request, &key_authorization[..written]).unwrap();
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        assert!(
            mrml_runtime::spawn_detached(move || {
                assert_eq!(challenge.serve_one(&listener, 15), Ok(true));
            })
            .is_ok()
        );
        let mut client = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        client.set_read_timeout_millis(1000).unwrap();
        client
            .write_all(
                b"GET /.well-known/acme-challenge/ip-token HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n",
            )
            .unwrap();
        let mut response = [0; 512];
        let mut used = 0usize;
        loop {
            let read = client.read(&mut response[used..]).unwrap();
            if read == 0 {
                break;
            }
            used += read;
        }
        assert!(response[..used].starts_with(b"HTTP/1.1 200 OK\r\n"));
    }
}
