use crate::{Client, HttpError, Url};
use mrml_runtime::Text;

pub const CHROMIUM_COMPONENT_UPDATE_URL: &str =
    "https://update.googleapis.com/service/update2/json";
pub const CHROMIUM_CRLSET_COMPONENT_ID: &str = "hfnkpimlhhgieaddgfemjhofmfblmnib";
pub const CHROMIUM_CRLSET_COMPONENT_SPKI_SHA256: [u8; 32] = [
    0x75, 0xda, 0xf8, 0xcb, 0x77, 0x68, 0x40, 0x33, 0x65, 0x4c, 0x97, 0xe5, 0xc5, 0x1b, 0xcd, 0x81,
    0x7b, 0x1e, 0xeb, 0x11, 0x2c, 0xe1, 0xa4, 0x33, 0x8c, 0xf5, 0x72, 0x5e, 0xed, 0xb8, 0x43, 0x97,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromiumCrlSetPackage {
    pub download_url: Text,
    pub sha256_hex: Text,
}

/// Discovers the current CRLSet CRX through Chromium's Omaha component API.
/// Installation must additionally verify the CRX3 signature against
/// `CHROMIUM_CRLSET_COMPONENT_SPKI_SHA256`, its package hash, freshness, and a
/// monotonic CRLSet sequence before atomically replacing owner-approved state.
pub struct ChromiumCrlSetUpdater {
    endpoint: Text,
}

impl ChromiumCrlSetUpdater {
    pub fn new() -> Self {
        Self {
            endpoint: CHROMIUM_COMPONENT_UPDATE_URL.into(),
        }
    }

    pub fn with_endpoint(endpoint: &str) -> Result<Self, HttpError> {
        let parsed = Url::parse(endpoint)?;
        if parsed.host != "update.googleapis.com" {
            return Err(HttpError::InvalidUrl);
        }
        Ok(Self {
            endpoint: endpoint.into(),
        })
    }

    pub fn discover(&self, current_version: &str) -> Result<ChromiumCrlSetPackage, HttpError> {
        if current_version.len() > 64
            || !current_version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(HttpError::InvalidUrl);
        }
        let request = mrml_runtime::mrml_format!(
            "{{\"request\":{{\"@os\":\"{}\",\"@updater\":\"mrml\",\"acceptformat\":\"crx3\",\"app\":[{{\"appid\":\"{}\",\"version\":\"{}\",\"updatecheck\":{{}}}}],\"arch\":\"x64\",\"ismachine\":false,\"lang\":\"en-CA\",\"os\":{{\"arch\":\"x86_64\",\"platform\":\"{}\",\"version\":\"0\"}},\"prodversion\":\"0.4.0.0\",\"protocol\":\"3.1\",\"updaterversion\":\"0.4.0.0\"}}}}",
            platform_short(),
            CHROMIUM_CRLSET_COMPONENT_ID,
            current_version,
            platform_long(),
        );
        let mut response = Client::new().post(
            &self.endpoint,
            &[
                ("Content-Type", "application/json"),
                ("X-Goog-Update-Interactivity", "bg"),
                ("X-Goog-Update-AppId", CHROMIUM_CRLSET_COMPONENT_ID),
                ("X-Goog-Update-Updater", "mrml-0.4.0.0"),
            ],
            request.as_bytes(),
        )?;
        if response.status != 200 {
            return Err(HttpError::InvalidResponse);
        }
        let body = response.read_to_end(1024 * 1024)?;
        let json = core::str::from_utf8(&body).map_err(|_| HttpError::InvalidResponse)?;
        Self::parse_response(json)
    }

    pub fn parse_response(json: &str) -> Result<ChromiumCrlSetPackage, HttpError> {
        let expected_app =
            mrml_runtime::mrml_format!("\"appid\":\"{}\"", CHROMIUM_CRLSET_COMPONENT_ID);
        if json.len() > 1024 * 1024
            || !json.contains(expected_app.as_str())
            || !json.contains("\"updatecheck\"")
            || !json.contains("\"status\":\"ok\"")
        {
            return Err(HttpError::InvalidResponse);
        }
        let codebase = https_codebase(json)?;
        let name = json_field(json, "name")?;
        let hash = json_field(json, "hash_sha256")?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HttpError::InvalidResponse);
        }
        let mut url = Text::from(codebase);
        if !url.ends_with('/') {
            url.push('/');
        }
        if name.contains(['/', '\\', '?', '#']) || name.is_empty() {
            return Err(HttpError::InvalidResponse);
        }
        url.push_str(name);
        let parsed = Url::parse(&url)?;
        if parsed.host != "redirector.gvt1.com"
            && parsed.host != "edgedl.me.gvt1.com"
            && parsed.host != "dl.google.com"
            && parsed.host != "www.google.com"
            && !parsed.host.ends_with(".googleusercontent.com")
        {
            return Err(HttpError::InvalidResponse);
        }
        Ok(ChromiumCrlSetPackage {
            download_url: url,
            sha256_hex: Text::from(hash).to_ascii_lowercase(),
        })
    }
}

fn platform_short() -> &'static str {
    #[cfg(windows)]
    return "win";
    #[cfg(unix)]
    return "linux";
}

fn platform_long() -> &'static str {
    #[cfg(windows)]
    return "Windows";
    #[cfg(unix)]
    return "Linux";
}

fn https_codebase(json: &str) -> Result<&str, HttpError> {
    let mut remaining = json;
    while let Ok(value) = json_field(remaining, "codebase") {
        if value.starts_with("https://") {
            return Ok(value);
        }
        let needle = "\"codebase\":\"";
        let start = remaining.find(needle).ok_or(HttpError::InvalidResponse)? + needle.len();
        let end = remaining[start..]
            .find('"')
            .ok_or(HttpError::InvalidResponse)?;
        remaining = &remaining[start + end + 1..];
    }
    Err(HttpError::InvalidResponse)
}

impl Default for ChromiumCrlSetUpdater {
    fn default() -> Self {
        Self::new()
    }
}

fn json_field<'a>(json: &'a str, name: &str) -> Result<&'a str, HttpError> {
    let needle = mrml_runtime::mrml_format!("\"{}\":\"", name);
    let start = json
        .find(needle.as_str())
        .ok_or(HttpError::InvalidResponse)?
        + needle.len();
    let rest = &json[start..];
    let end = rest.find('"').ok_or(HttpError::InvalidResponse)?;
    if rest[..end].contains('\\') {
        return Err(HttpError::InvalidResponse);
    }
    Ok(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_signed_component_identity_and_parses_discovery() {
        let response = r#"{"response":{"app":[{"appid":"hfnkpimlhhgieaddgfemjhofmfblmnib","status":"ok","updatecheck":{"status":"ok","urls":{"url":[{"codebase":"http://redirector.gvt1.com/edgedl/release2/"},{"codebase":"https://redirector.gvt1.com/edgedl/release2/"}]},"manifest":{"packages":{"package":[{"name":"crl-set.crx3","hash_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}}}}]}}"#;
        let package = ChromiumCrlSetUpdater::parse_response(response).unwrap();
        assert_eq!(
            package.download_url,
            "https://redirector.gvt1.com/edgedl/release2/crl-set.crx3"
        );
        assert_eq!(CHROMIUM_CRLSET_COMPONENT_SPKI_SHA256[0], 0x75);
    }

    #[test]
    fn rejects_unapproved_download_hosts() {
        let response = r#"{"appid":"hfnkpimlhhgieaddgfemjhofmfblmnib","status":"ok","updatecheck":{"codebase":"https://evil.example/","name":"x.crx3","hash_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#;
        assert!(ChromiumCrlSetUpdater::parse_response(response).is_err());
    }
}
