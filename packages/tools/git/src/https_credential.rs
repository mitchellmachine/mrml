use core::fmt;
use mrml_runtime::{Text, Vector};

const ENCODED_TOKEN_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsCredentialAction {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsCredentialScope {
    pub host: Text,
    pub port: u16,
    pub repository_path: Text,
    pub action: HttpsCredentialAction,
}

impl HttpsCredentialScope {
    pub fn new(
        host: &str,
        port: u16,
        repository_path: &str,
        action: HttpsCredentialAction,
    ) -> Result<Self, HttpsCredentialError> {
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || !repository_path.starts_with('/')
            || !repository_path.ends_with(".git")
            || repository_path.len() > 1024
            || host
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-'))
            || repository_path
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'?' | b'#' | b'%' | b'\\'))
        {
            return Err(HttpsCredentialError::InvalidScope);
        }
        Ok(Self {
            host: host.into(),
            port,
            repository_path: repository_path.into(),
            action,
        })
    }
}

/// A single exact Bearer use. It is deliberately non-cloneable and exposes
/// the header only to the Git HTTPS implementation for its bound scope.
pub struct ScopedBearerCredential {
    scope: HttpsCredentialScope,
    authorization: Vector<u8>,
}

impl ScopedBearerCredential {
    pub fn from_provider_token(
        scope: HttpsCredentialScope,
        encoded_token: &[u8],
    ) -> Result<Self, HttpsCredentialError> {
        if encoded_token.len() != ENCODED_TOKEN_BYTES
            || encoded_token
                .iter()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(HttpsCredentialError::InvalidCredential);
        }
        let mut authorization = Vector::new();
        authorization
            .try_extend_from_slice(b"Bearer ")
            .map_err(|_| HttpsCredentialError::Resource)?;
        authorization
            .try_extend_from_slice(encoded_token)
            .map_err(|_| HttpsCredentialError::Resource)?;
        Ok(Self {
            scope,
            authorization,
        })
    }

    pub(crate) fn authorization_for(
        &self,
        scope: &HttpsCredentialScope,
    ) -> Result<&str, HttpsCredentialError> {
        if &self.scope != scope {
            return Err(HttpsCredentialError::ScopeMismatch);
        }
        core::str::from_utf8(&self.authorization)
            .map_err(|_| HttpsCredentialError::InvalidCredential)
    }
}

impl fmt::Debug for ScopedBearerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedBearerCredential(<redacted>)")
    }
}

impl Drop for ScopedBearerCredential {
    fn drop(&mut self) {
        for byte in &mut self.authorization {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

pub trait HttpsCredentialProvider {
    fn credential(
        &mut self,
        scope: &HttpsCredentialScope,
    ) -> Result<ScopedBearerCredential, HttpsCredentialError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsCredentialError {
    InvalidScope,
    InvalidCredential,
    ScopeMismatch,
    Unavailable,
    Denied,
    Resource,
}

impl fmt::Display for HttpsCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidScope => "HTTPS credential scope is invalid",
            Self::InvalidCredential => "HTTPS credential is invalid",
            Self::ScopeMismatch => "HTTPS credential scope does not match the request",
            Self::Unavailable => "HTTPS credential provider is unavailable",
            Self::Denied => "HTTPS credential use was denied",
            Self::Resource => "HTTPS credential resource limit was reached",
        })
    }
}

impl core::error::Error for HttpsCredentialError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(action: HttpsCredentialAction) -> HttpsCredentialScope {
        HttpsCredentialScope::new("git.example", 443, "/owner/repo.git", action).unwrap()
    }

    #[test]
    fn credential_is_exact_scoped_noncloneable_and_redacted() {
        let read = scope(HttpsCredentialAction::Read);
        let credential =
            ScopedBearerCredential::from_provider_token(read.clone(), &[b'a'; 64]).unwrap();
        let expected = mrml_runtime::mrml_format!("Bearer {}", "a".repeat(64));
        assert_eq!(
            credential.authorization_for(&read).unwrap(),
            expected.as_str()
        );
        assert_eq!(
            credential.authorization_for(&scope(HttpsCredentialAction::Write)),
            Err(HttpsCredentialError::ScopeMismatch)
        );
        assert_eq!(
            mrml_runtime::mrml_format!("{credential:?}"),
            "ScopedBearerCredential(<redacted>)"
        );
    }

    #[test]
    fn malformed_scope_and_token_fail_without_secret_diagnostics() {
        assert!(
            HttpsCredentialScope::new("git/example", 443, "/o/r.git", HttpsCredentialAction::Read)
                .is_err()
        );
        for token in [&b"a"[..], &[b'A'; 64], &[b'g'; 64], &[b'a'; 65]] {
            let error = ScopedBearerCredential::from_provider_token(
                scope(HttpsCredentialAction::Read),
                token,
            )
            .unwrap_err();
            assert!(!mrml_runtime::mrml_format!("{error:?}").contains(&"a".repeat(64)));
        }
    }
}
