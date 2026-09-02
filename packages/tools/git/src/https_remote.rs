use core::fmt;
use mrml_http::{Header, Http2ClientConnection, Http3ClientConnection, Url};
use mrml_runtime::{Text, Vector};

const MAX_DISCOVERY_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsTransport {
    Http2,
    Http3V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmartGitService {
    UploadPack,
    ReceivePack,
}

impl SmartGitService {
    fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRemote {
    pub host: Text,
    pub port: u16,
    pub repository_path: Text,
    pub transport: HttpsTransport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsDiscovery {
    pub ls_refs_unborn: bool,
    pub fetch_ofs_delta: bool,
}

impl HttpsRemote {
    pub fn parse(input: &str, transport: HttpsTransport) -> Result<Self, HttpsRemoteError> {
        let url = Url::parse(input).map_err(|_| HttpsRemoteError::InvalidUrl)?;
        if url.target.contains(['?', '#', '%'])
            || url.target.len() > 1024
            || !url.target.starts_with('/')
            || !url.target.ends_with(".git")
        {
            return Err(HttpsRemoteError::InvalidRepositoryPath);
        }
        let path = &url.target[1..];
        let mut segments = path.split('/');
        let owner = segments
            .next()
            .ok_or(HttpsRemoteError::InvalidRepositoryPath)?;
        let repository = segments
            .next()
            .ok_or(HttpsRemoteError::InvalidRepositoryPath)?;
        if segments.next().is_some()
            || !valid_identity_component(owner)
            || !repository
                .strip_suffix(".git")
                .is_some_and(valid_identity_component)
        {
            return Err(HttpsRemoteError::InvalidRepositoryPath);
        }
        Ok(Self {
            host: url.host,
            port: url.port,
            repository_path: url.target,
            transport,
        })
    }

    pub fn authority(&self) -> Text {
        if self.port == 443 {
            self.host.clone()
        } else {
            mrml_runtime::mrml_format!("{}:{}", self.host, self.port)
        }
    }

    pub fn discovery_target(&self, service: SmartGitService) -> Text {
        mrml_runtime::mrml_format!(
            "{}/info/refs?service={}",
            self.repository_path,
            service.name()
        )
    }

    pub fn service_target(&self, service: SmartGitService) -> Text {
        mrml_runtime::mrml_format!("{}/{}", self.repository_path, service.name())
    }

    pub fn discover_upload_pack(&self) -> Result<HttpsDiscovery, HttpsRemoteError> {
        let target = self.discovery_target(SmartGitService::UploadPack);
        let authority = self.authority();
        let headers = [
            ("accept", "application/x-git-upload-pack-advertisement"),
            ("git-protocol", "version=2"),
        ];
        let (status, response_headers, body) = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(|_| HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(|_| HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(|_| HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(|_| HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
        };
        validate_discovery_response(status, &response_headers, &body)
    }
}

fn validate_discovery_response(
    status: u16,
    headers: &[Header],
    body: &[u8],
) -> Result<HttpsDiscovery, HttpsRemoteError> {
    if status != 200 {
        return Err(HttpsRemoteError::HttpStatus);
    }
    let mut content_type = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-type"));
    if content_type.next().map(|header| header.value.as_str())
        != Some("application/x-git-upload-pack-advertisement")
        || content_type.next().is_some()
    {
        return Err(HttpsRemoteError::ContentType);
    }
    parse_v2_discovery(body)
}

fn parse_v2_discovery(body: &[u8]) -> Result<HttpsDiscovery, HttpsRemoteError> {
    if body.len() > MAX_DISCOVERY_BYTES {
        return Err(HttpsRemoteError::TooLarge);
    }
    let packets = crate::decode_packets(body).map_err(|_| HttpsRemoteError::Protocol)?;
    if packets.len() != 5 || packets.last() != Some(&None) {
        return Err(HttpsRemoteError::Protocol);
    }
    let mut lines = Vector::new();
    for packet in &packets[..packets.len() - 1] {
        let line = packet.as_deref().ok_or(HttpsRemoteError::Protocol)?;
        let line = core::str::from_utf8(line).map_err(|_| HttpsRemoteError::Protocol)?;
        let line = line.strip_suffix('\n').ok_or(HttpsRemoteError::Protocol)?;
        lines
            .try_push(line)
            .map_err(|_| HttpsRemoteError::TooLarge)?;
    }
    if lines.first() != Some(&"version 2")
        || lines.iter().filter(|line| **line == "version 2").count() != 1
        || lines
            .iter()
            .filter(|line| **line == "object-format=sha256")
            .count()
            != 1
        || lines.iter().any(|line| {
            !matches!(
                *line,
                "version 2" | "ls-refs=unborn" | "fetch=ofs-delta" | "object-format=sha256"
            )
        })
    {
        return Err(HttpsRemoteError::Protocol);
    }
    Ok(HttpsDiscovery {
        ls_refs_unborn: lines.contains(&"ls-refs=unborn"),
        fetch_ofs_delta: lines.contains(&"fetch=ofs-delta"),
    })
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsRemoteError {
    InvalidUrl,
    InvalidRepositoryPath,
    Transport,
    HttpStatus,
    ContentType,
    Protocol,
    TooLarge,
}

impl fmt::Display for HttpsRemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid HTTPS remote URL",
            Self::InvalidRepositoryPath => "invalid HTTPS repository path",
            Self::Transport => "HTTPS transport failed",
            Self::HttpStatus => "Git service returned an unsuccessful status",
            Self::ContentType => "Git service returned an invalid content type",
            Self::Protocol => "Git protocol-v2 discovery is invalid",
            Self::TooLarge => "Git discovery response exceeds its limit",
        })
    }
}

impl core::error::Error for HttpsRemoteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_https_repository_identity_and_transport() {
        let remote = HttpsRemote::parse(
            "https://Git.Example:8443/owner/project.git",
            HttpsTransport::Http3V2,
        )
        .unwrap();
        assert_eq!(remote.host, "git.example");
        assert_eq!(remote.port, 8443);
        assert_eq!(remote.repository_path, "/owner/project.git");
        assert_eq!(remote.authority(), "git.example:8443");
        assert_eq!(
            remote.discovery_target(SmartGitService::UploadPack),
            "/owner/project.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            remote.service_target(SmartGitService::ReceivePack),
            "/owner/project.git/git-receive-pack"
        );
    }

    #[test]
    fn rejects_credentials_queries_fragments_encoding_and_ambiguous_paths() {
        for value in [
            "http://git.example/owner/project.git",
            "https://token@git.example/owner/project.git",
            "https://git.example/owner/project.git?token=secret",
            "https://git.example/owner/project.git#fragment",
            "https://git.example/owner%2fproject.git",
            "https://git.example/owner/project",
            "https://git.example/owner/extra/project.git",
            "https://git.example//project.git",
            "https://git.example/.owner/project.git",
            "https://git.example/owner/../project.git",
        ] {
            assert!(
                HttpsRemote::parse(value, HttpsTransport::Http2).is_err(),
                "{value}"
            );
        }
    }

    fn discovery_body(lines: &[&str]) -> Vector<u8> {
        let mut body = Vector::new();
        for line in lines {
            crate::encode_packet(line.as_bytes(), &mut body).unwrap();
        }
        crate::encode_flush(&mut body);
        body
    }

    #[test]
    fn exact_v2_discovery_is_shared_by_h2_and_h3() {
        let body = discovery_body(&[
            "version 2\n",
            "ls-refs=unborn\n",
            "fetch=ofs-delta\n",
            "object-format=sha256\n",
        ]);
        let headers = [Header {
            name: "content-type".into(),
            value: "application/x-git-upload-pack-advertisement".into(),
        }];
        assert_eq!(
            validate_discovery_response(200, &headers, &body).unwrap(),
            HttpsDiscovery {
                ls_refs_unborn: true,
                fetch_ofs_delta: true,
            }
        );
    }

    #[test]
    fn discovery_rejects_status_media_type_duplicates_sha1_and_unknown_features() {
        let valid = discovery_body(&[
            "version 2\n",
            "ls-refs=unborn\n",
            "fetch=ofs-delta\n",
            "object-format=sha256\n",
        ]);
        let good = Header {
            name: "content-type".into(),
            value: "application/x-git-upload-pack-advertisement".into(),
        };
        assert_eq!(
            validate_discovery_response(401, core::slice::from_ref(&good), &valid),
            Err(HttpsRemoteError::HttpStatus)
        );
        let duplicate = [good.clone(), good.clone()];
        assert_eq!(
            validate_discovery_response(200, &duplicate, &valid),
            Err(HttpsRemoteError::ContentType)
        );
        for lines in [
            [
                "version 2\n",
                "ls-refs=unborn\n",
                "fetch=ofs-delta\n",
                "object-format=sha1\n",
            ],
            [
                "version 2\n",
                "ls-refs=unborn\n",
                "fetch=filter\n",
                "object-format=sha256\n",
            ],
        ] {
            assert_eq!(
                parse_v2_discovery(&discovery_body(&lines)),
                Err(HttpsRemoteError::Protocol)
            );
        }
    }
}
