use core::fmt;
use mrml_http::Url;
use mrml_runtime::Text;

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
        let owner = segments.next().ok_or(HttpsRemoteError::InvalidRepositoryPath)?;
        let repository = segments.next().ok_or(HttpsRemoteError::InvalidRepositoryPath)?;
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
}

impl fmt::Display for HttpsRemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid HTTPS remote URL",
            Self::InvalidRepositoryPath => "invalid HTTPS repository path",
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
            assert!(HttpsRemote::parse(value, HttpsTransport::Http2).is_err(), "{value}");
        }
    }
}
