use core::fmt;
use mrml_http::{
    Header, Http2ClientConnection, Http3ClientConnection, HttpError, RequestBodySource,
    ResponseBodySink, Url,
};
use mrml_runtime::{File, Text, Vector};

const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_LS_REFS_BYTES: usize = 16 * 1024 * 1024;
const MAX_LS_REFS: usize = 1_000_000;
const MAX_PUSH_PACK_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PUSH_REPORT_BYTES: usize = 1024 * 1024;
pub const MAX_FETCH_WANTS_PER_REQUEST: usize = 32;
pub const MAX_FETCH_HAVES_PER_REQUEST: usize = 16;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedReceiveDiscovery {
    pub repository_generation: crate::RepositoryGeneration,
    pub trust_generation: crate::TrustGeneration,
    pub revocation_generation: crate::RevocationGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRefAdvertisement {
    pub refs: Vector<crate::RemoteRef>,
    pub default_branch: Option<Text>,
    pub unborn: bool,
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

    pub fn repository_identity(&self) -> Result<crate::RepositoryIdentity, HttpsRemoteError> {
        crate::RepositoryIdentity::parse(
            self.repository_path
                .strip_prefix('/')
                .and_then(|path| path.strip_suffix(".git"))
                .ok_or(HttpsRemoteError::InvalidRepositoryPath)?,
        )
        .map_err(|_| HttpsRemoteError::InvalidRepositoryPath)
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
        self.discover_upload_pack_with_authorization(None)
    }

    pub fn discover_upload_pack_authenticated<P: crate::HttpsCredentialProvider + ?Sized>(
        &self,
        provider: &mut P,
    ) -> Result<HttpsDiscovery, HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Read)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        self.discover_upload_pack_with_authorization(Some(authorization))
    }

    fn discover_upload_pack_with_authorization(
        &self,
        authorization: Option<&str>,
    ) -> Result<HttpsDiscovery, HttpsRemoteError> {
        let target = self.discovery_target(SmartGitService::UploadPack);
        let authority = self.authority();
        let headers = request_headers(
            "application/x-git-upload-pack-advertisement",
            None,
            authorization,
        );
        let (status, response_headers, body) = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
        };
        validate_discovery_response(status, &response_headers, &body)
    }

    fn discover_receive_pack_with_authorization(
        &self,
        authorization: &str,
    ) -> Result<ProtectedReceiveDiscovery, HttpsRemoteError> {
        let target = self.discovery_target(SmartGitService::ReceivePack);
        let authority = self.authority();
        let headers = request_headers(
            "application/x-git-receive-pack-advertisement",
            None,
            Some(authorization),
        );
        let (status, response_headers, body) = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request("GET", &authority, &target, &headers)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
        };
        validate_service_response(
            status,
            &response_headers,
            &body,
            "application/x-git-receive-pack-advertisement",
        )?;
        parse_protected_receive_discovery(&body)
    }

    pub fn discover_receive_pack_authenticated<
        P: crate::HttpsCredentialProvider + ?Sized,
    >(
        &self,
        provider: &mut P,
    ) -> Result<ProtectedReceiveDiscovery, HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Write)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        self.discover_receive_pack_with_authorization(authorization)
    }

    pub fn list_refs(&self) -> Result<HttpsRefAdvertisement, HttpsRemoteError> {
        self.list_refs_with_authorization(None)
    }

    pub fn list_refs_authenticated<P: crate::HttpsCredentialProvider + ?Sized>(
        &self,
        provider: &mut P,
    ) -> Result<HttpsRefAdvertisement, HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Read)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        self.list_refs_with_authorization(Some(authorization))
    }

    fn list_refs_with_authorization(
        &self,
        authorization: Option<&str>,
    ) -> Result<HttpsRefAdvertisement, HttpsRemoteError> {
        let discovery = self.discover_upload_pack_with_authorization(authorization)?;
        if !discovery.ls_refs_unborn {
            return Err(HttpsRemoteError::Protocol);
        }
        let body = ls_refs_request()?;
        let target = self.service_target(SmartGitService::UploadPack);
        let authority = self.authority();
        let headers = request_headers(
            "application/x-git-upload-pack-result",
            Some("application/x-git-upload-pack-request"),
            authorization,
        );
        let (status, response_headers, response_body) = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request_with_body("POST", &authority, &target, &headers, &body)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                let response = connection
                    .request_control_with_body("POST", &authority, &target, &headers, &body)
                    .map_err(HttpsRemoteError::Transport)?;
                (response.status, response.headers, response.body)
            }
        };
        validate_service_response(
            status,
            &response_headers,
            &response_body,
            "application/x-git-upload-pack-result",
        )?;
        parse_ls_refs(&response_body)
    }

    pub fn fetch_pack_to_file(
        &self,
        wants: &[crate::ObjectId],
        haves: &[crate::ObjectId],
        pack_path: &str,
        maximum_pack_bytes: u64,
    ) -> Result<u64, HttpsRemoteError> {
        self.fetch_pack_to_file_with_authorization(
            wants,
            haves,
            pack_path,
            maximum_pack_bytes,
            None,
        )
    }

    pub fn fetch_pack_to_file_authenticated<P: crate::HttpsCredentialProvider + ?Sized>(
        &self,
        wants: &[crate::ObjectId],
        haves: &[crate::ObjectId],
        pack_path: &str,
        maximum_pack_bytes: u64,
        provider: &mut P,
    ) -> Result<u64, HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Read)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        self.fetch_pack_to_file_with_authorization(
            wants,
            haves,
            pack_path,
            maximum_pack_bytes,
            Some(authorization),
        )
    }

    fn fetch_pack_to_file_with_authorization(
        &self,
        wants: &[crate::ObjectId],
        haves: &[crate::ObjectId],
        pack_path: &str,
        maximum_pack_bytes: u64,
        authorization: Option<&str>,
    ) -> Result<u64, HttpsRemoteError> {
        if !self
            .discover_upload_pack_with_authorization(authorization)?
            .fetch_ofs_delta
        {
            return Err(HttpsRemoteError::Protocol);
        }
        let body = fetch_request(wants, haves)?;
        let target = self.service_target(SmartGitService::UploadPack);
        let authority = self.authority();
        let headers = request_headers(
            "application/x-git-upload-pack-result",
            Some("application/x-git-upload-pack-request"),
            authorization,
        );
        let output = crate::FilePackOutput::create_new(pack_path, maximum_pack_bytes)
            .map_err(map_pack_error)?;
        let mut decoder = crate::V2PackResponseDecoder::new(output);
        let head = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                connection
                    .request_with_body_to(
                        "POST",
                        &authority,
                        &target,
                        &headers,
                        &body,
                        &mut decoder,
                    )
                    .map_err(HttpsRemoteError::Transport)?
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                connection
                    .request_control_with_body_to(
                        "POST",
                        &authority,
                        &target,
                        &headers,
                        &body,
                        &mut decoder,
                    )
                    .map_err(HttpsRemoteError::Transport)?
            }
        };
        validate_service_response(
            head.status,
            &head.headers,
            &[],
            "application/x-git-upload-pack-result",
        )?;
        let (output, bytes) = decoder.finish().map_err(map_pack_error)?;
        if output.bytes_written() != bytes {
            return Err(HttpsRemoteError::Protocol);
        }
        Ok(bytes)
    }

    pub fn push_pack_file_authenticated<P: crate::HttpsCredentialProvider + ?Sized>(
        &self,
        old: crate::ObjectId,
        new: crate::ObjectId,
        reference: &str,
        pack_path: &str,
        provider: &mut P,
    ) -> Result<(), HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Write)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        self.discover_receive_pack_with_authorization(authorization)?;
        let prefix = crate::protected_push_command_prefix(old, new, reference)
            .map_err(|_| HttpsRemoteError::Protocol)?;
        self.push_pack_file_with_authorization(
            reference,
            pack_path,
            authorization,
            prefix,
            false,
        )
        .map(|_| ())
    }

    pub fn push_protected_pack_file_authenticated<
        P: crate::HttpsCredentialProvider + ?Sized,
    >(
        &self,
        old: crate::ObjectId,
        new: crate::ObjectId,
        reference: &str,
        pack_path: &str,
        expected: ProtectedReceiveDiscovery,
        candidate_id: crate::QuarantineTransactionId,
        proofs: &[crate::DetachedCommitProofRecord],
        provider: &mut P,
    ) -> Result<Vector<u8>, HttpsRemoteError> {
        let scope = self.credential_scope(crate::HttpsCredentialAction::Write)?;
        let credential = provider
            .credential(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        let authorization = credential
            .authorization_for(&scope)
            .map_err(|_| HttpsRemoteError::Credential)?;
        if self.discover_receive_pack_with_authorization(authorization)? != expected {
            return Err(HttpsRemoteError::Protocol);
        }
        let prefix = crate::protected_push_command_with_proofs(
            old,
            new,
            reference,
            candidate_id,
            proofs,
        )
        .map_err(|_| HttpsRemoteError::Protocol)?;
        self.push_pack_file_with_authorization(
            reference,
            pack_path,
            authorization,
            prefix,
            true,
        )
        .and_then(|receipt| receipt.ok_or(HttpsRemoteError::Protocol))
    }

    fn push_pack_file_with_authorization(
        &self,
        reference: &str,
        pack_path: &str,
        authorization: &str,
        prefix: Vector<u8>,
        protected: bool,
    ) -> Result<Option<Vector<u8>>, HttpsRemoteError> {
        let file = File::open_regular(pack_path).map_err(|_| HttpsRemoteError::Storage)?;
        let pack_bytes = file.len().map_err(|_| HttpsRemoteError::Storage)?;
        if pack_bytes == 0 || pack_bytes > MAX_PUSH_PACK_BYTES {
            return Err(HttpsRemoteError::TooLarge);
        }
        let mut source = PushBodySource::new(prefix, file, pack_bytes)?;
        let target = self.service_target(SmartGitService::ReceivePack);
        let authority = self.authority();
        let content_length = mrml_runtime::mrml_format!("{}", source.remaining());
        let mut headers = request_headers(
            "application/x-git-receive-pack-result",
            Some("application/x-git-receive-pack-request"),
            Some(authorization),
        );
        headers.push(("content-length", content_length.as_str()));
        let mut report = LimitedResponseBody::new(MAX_PUSH_REPORT_BYTES);
        let head = match self.transport {
            HttpsTransport::Http2 => {
                let mut connection = Http2ClientConnection::connect(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                connection
                    .request_streaming_body_to(
                        "POST",
                        &authority,
                        &target,
                        &headers,
                        &mut source,
                        &mut report,
                    )
                    .map_err(HttpsRemoteError::Transport)?
            }
            HttpsTransport::Http3V2 => {
                let mut connection = Http3ClientConnection::connect_v2(&self.host, self.port)
                    .map_err(HttpsRemoteError::Transport)?;
                connection
                    .request_streaming_body_to(
                        "POST",
                        &authority,
                        &target,
                        &headers,
                        &mut source,
                        &mut report,
                    )
                    .map_err(HttpsRemoteError::Transport)?
            }
        };
        validate_service_response(
            head.status,
            &head.headers,
            &report.bytes,
            "application/x-git-receive-pack-result",
        )?;
        if protected {
            crate::parse_protected_push_response_mode(&report.bytes, reference, true)
                .map(Some)
                .map_err(|_| HttpsRemoteError::Protocol)
        } else {
            crate::parse_push_response_mode(&report.bytes, reference, true)
                .map(|()| None)
                .map_err(|_| HttpsRemoteError::Protocol)
        }
    }

    fn credential_scope(
        &self,
        action: crate::HttpsCredentialAction,
    ) -> Result<crate::HttpsCredentialScope, HttpsRemoteError> {
        crate::HttpsCredentialScope::new(&self.host, self.port, &self.repository_path, action)
            .map_err(|_| HttpsRemoteError::Credential)
    }
}

struct PushBodySource {
    prefix: Vector<u8>,
    prefix_offset: usize,
    file: File,
    file_remaining: u64,
}

impl PushBodySource {
    fn new(prefix: Vector<u8>, file: File, file_remaining: u64) -> Result<Self, HttpsRemoteError> {
        prefix
            .len()
            .checked_add(usize::try_from(file_remaining).map_err(|_| HttpsRemoteError::TooLarge)?)
            .ok_or(HttpsRemoteError::TooLarge)?;
        Ok(Self {
            prefix,
            prefix_offset: 0,
            file,
            file_remaining,
        })
    }
}

impl RequestBodySource for PushBodySource {
    fn remaining(&self) -> u64 {
        (self.prefix.len() - self.prefix_offset) as u64 + self.file_remaining
    }

    fn read(&mut self, output: &mut [u8]) -> Result<usize, HttpError> {
        let prefix_remaining = &self.prefix[self.prefix_offset..];
        let copied = prefix_remaining.len().min(output.len());
        output[..copied].copy_from_slice(&prefix_remaining[..copied]);
        self.prefix_offset += copied;
        if copied == output.len() || self.file_remaining == 0 {
            return Ok(copied);
        }
        let maximum = usize::try_from(self.file_remaining.min((output.len() - copied) as u64))
            .map_err(|_| HttpError::BodyTooLarge)?;
        let read = self
            .file
            .read(&mut output[copied..copied + maximum])
            .map_err(|_| HttpError::Io)?;
        self.file_remaining = self.file_remaining.saturating_sub(read as u64);
        Ok(copied + read)
    }
}

struct LimitedResponseBody {
    bytes: Vector<u8>,
    maximum: usize,
}

impl LimitedResponseBody {
    const fn new(maximum: usize) -> Self {
        Self {
            bytes: Vector::new(),
            maximum,
        }
    }
}

impl ResponseBodySink for LimitedResponseBody {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.maximum)
        {
            return Err(HttpError::BodyTooLarge);
        }
        self.bytes
            .try_extend_from_slice(bytes)
            .map_err(|_| HttpError::Allocation)
    }
}

fn request_headers<'a>(
    accept: &'a str,
    content_type: Option<&'a str>,
    authorization: Option<&'a str>,
) -> Vector<(&'a str, &'a str)> {
    let mut headers = Vector::from([("accept", accept), ("git-protocol", "version=2")]);
    if let Some(value) = content_type {
        headers.push(("content-type", value));
    }
    if let Some(value) = authorization {
        headers.push(("authorization", value));
    }
    headers
}

fn map_pack_error(error: crate::HttpsPackError) -> HttpsRemoteError {
    match error {
        crate::HttpsPackError::TooLarge => HttpsRemoteError::TooLarge,
        crate::HttpsPackError::Storage => HttpsRemoteError::Storage,
        _ => HttpsRemoteError::Protocol,
    }
}

fn fetch_request(
    wants: &[crate::ObjectId],
    haves: &[crate::ObjectId],
) -> Result<Vector<u8>, HttpsRemoteError> {
    if wants.is_empty()
        || wants.len() > MAX_FETCH_WANTS_PER_REQUEST
        || haves.len() > MAX_FETCH_HAVES_PER_REQUEST
        || wants
            .iter()
            .chain(haves)
            .any(|id| id.format() != crate::ObjectFormat::Sha256 || id.is_zero())
    {
        return Err(HttpsRemoteError::Protocol);
    }
    let mut body = Vector::new();
    for line in [b"command=fetch\n".as_slice(), b"object-format=sha256\n"] {
        crate::encode_packet(line, &mut body).map_err(|_| HttpsRemoteError::Protocol)?;
    }
    body.try_extend_from_slice(b"0001")
        .map_err(|_| HttpsRemoteError::TooLarge)?;
    for id in wants {
        crate::encode_packet(
            mrml_runtime::mrml_format!("want {}\n", id.to_hex()).as_bytes(),
            &mut body,
        )
        .map_err(|_| HttpsRemoteError::Protocol)?;
    }
    for id in haves {
        crate::encode_packet(
            mrml_runtime::mrml_format!("have {}\n", id.to_hex()).as_bytes(),
            &mut body,
        )
        .map_err(|_| HttpsRemoteError::Protocol)?;
    }
    for line in [b"done\n".as_slice(), b"ofs-delta\n"] {
        crate::encode_packet(line, &mut body).map_err(|_| HttpsRemoteError::Protocol)?;
    }
    crate::encode_flush(&mut body);
    if body.len() > 4096 {
        return Err(HttpsRemoteError::TooLarge);
    }
    Ok(body)
}

fn ls_refs_request() -> Result<Vector<u8>, HttpsRemoteError> {
    let mut body = Vector::new();
    for line in [b"command=ls-refs\n".as_slice(), b"object-format=sha256\n"] {
        crate::encode_packet(line, &mut body).map_err(|_| HttpsRemoteError::Protocol)?;
    }
    body.try_extend_from_slice(b"0001")
        .map_err(|_| HttpsRemoteError::TooLarge)?;
    for line in [
        b"peel\n".as_slice(),
        b"symrefs\n",
        b"unborn\n",
        b"ref-prefix HEAD\n",
        b"ref-prefix refs/heads/\n",
        b"ref-prefix refs/tags/\n",
    ] {
        crate::encode_packet(line, &mut body).map_err(|_| HttpsRemoteError::Protocol)?;
    }
    crate::encode_flush(&mut body);
    Ok(body)
}

fn validate_service_response(
    status: u16,
    headers: &[Header],
    _body: &[u8],
    expected_content_type: &str,
) -> Result<(), HttpsRemoteError> {
    if status != 200 {
        return Err(HttpsRemoteError::HttpStatus);
    }
    let mut content_type = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-type"));
    if content_type.next().map(|header| header.value.as_str()) != Some(expected_content_type)
        || content_type.next().is_some()
    {
        return Err(HttpsRemoteError::ContentType);
    }
    Ok(())
}

fn parse_ls_refs(body: &[u8]) -> Result<HttpsRefAdvertisement, HttpsRemoteError> {
    if body.len() > MAX_LS_REFS_BYTES {
        return Err(HttpsRemoteError::TooLarge);
    }
    let packets = crate::decode_packets(body).map_err(|_| HttpsRemoteError::Protocol)?;
    if packets.last() != Some(&None)
        || packets[..packets.len().saturating_sub(1)]
            .iter()
            .any(Option::is_none)
    {
        return Err(HttpsRemoteError::Protocol);
    }
    let mut refs = Vector::new();
    let mut default_branch = None;
    let mut unborn = false;
    let mut previous: Option<Text> = None;
    for packet in &packets[..packets.len() - 1] {
        if refs.len() >= MAX_LS_REFS {
            return Err(HttpsRemoteError::TooLarge);
        }
        let bytes = packet.as_deref().ok_or(HttpsRemoteError::Protocol)?;
        let line = core::str::from_utf8(bytes).map_err(|_| HttpsRemoteError::Protocol)?;
        let line = line.strip_suffix('\n').ok_or(HttpsRemoteError::Protocol)?;
        let mut fields = line.split(' ');
        let id = fields.next().ok_or(HttpsRemoteError::Protocol)?;
        let name = fields.next().ok_or(HttpsRemoteError::Protocol)?;
        if name == "HEAD" {
            if default_branch.is_some() || unborn {
                return Err(HttpsRemoteError::Protocol);
            }
            let symref = fields.next().ok_or(HttpsRemoteError::Protocol)?;
            if fields.next().is_some() {
                return Err(HttpsRemoteError::Protocol);
            }
            let target = symref
                .strip_prefix("symref-target:")
                .ok_or(HttpsRemoteError::Protocol)?;
            crate::FullRefName::parse(target).map_err(|_| HttpsRemoteError::Protocol)?;
            if id == "unborn" {
                unborn = true;
            } else {
                crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, id)
                    .ok_or(HttpsRemoteError::Protocol)?;
            }
            default_branch = Some(target.into());
            continue;
        }
        let parsed_name =
            crate::FullRefName::parse(name).map_err(|_| HttpsRemoteError::Protocol)?;
        if !name.starts_with("refs/heads/") && !name.starts_with("refs/tags/") {
            return Err(HttpsRemoteError::Protocol);
        }
        if previous
            .as_ref()
            .is_some_and(|value| value.as_str() >= name)
        {
            return Err(HttpsRemoteError::Protocol);
        }
        previous = Some(name.into());
        let id = crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, id)
            .ok_or(HttpsRemoteError::Protocol)?;
        if let Some(attribute) = fields.next() {
            let peeled = attribute
                .strip_prefix("peeled:")
                .ok_or(HttpsRemoteError::Protocol)?;
            if !name.starts_with("refs/tags/")
                || crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, peeled).is_none()
                || fields.next().is_some()
            {
                return Err(HttpsRemoteError::Protocol);
            }
        }
        refs.try_push(crate::RemoteRef {
            name: parsed_name.as_str().into(),
            id,
        })
        .map_err(|_| HttpsRemoteError::TooLarge)?;
    }
    Ok(HttpsRefAdvertisement {
        refs,
        default_branch,
        unborn,
    })
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

fn parse_protected_receive_discovery(
    body: &[u8],
) -> Result<ProtectedReceiveDiscovery, HttpsRemoteError> {
    if body.len() > MAX_DISCOVERY_BYTES {
        return Err(HttpsRemoteError::TooLarge);
    }
    let packets = crate::decode_packets(body).map_err(|_| HttpsRemoteError::Protocol)?;
    if packets.len() != 5 || packets.last() != Some(&None) {
        return Err(HttpsRemoteError::Protocol);
    }
    let line = |index: usize| -> Result<&str, HttpsRemoteError> {
        core::str::from_utf8(
            packets[index]
                .as_deref()
                .ok_or(HttpsRemoteError::Protocol)?,
        )
        .map_err(|_| HttpsRemoteError::Protocol)?
        .strip_suffix('\n')
        .ok_or(HttpsRemoteError::Protocol)
    };
    if line(0)? != "version 2"
        || line(1)? != "object-format=sha256"
        || line(2)?
            != "receive=report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1 mrml-receipt-v1 mrml-candidate-v1"
    {
        return Err(HttpsRemoteError::Protocol);
    }
    let context = line(3)?
        .strip_prefix("mrml-receive-context=")
        .ok_or(HttpsRemoteError::Protocol)?;
    let mut values = context.split(':');
    let repository_generation = parse_nonzero_generation(values.next())?;
    let trust_generation = parse_nonzero_generation(values.next())?;
    let revocation_generation = parse_nonzero_generation(values.next())?;
    if values.next().is_some() {
        return Err(HttpsRemoteError::Protocol);
    }
    Ok(ProtectedReceiveDiscovery {
        repository_generation: crate::RepositoryGeneration(repository_generation),
        trust_generation: crate::TrustGeneration(trust_generation),
        revocation_generation: crate::RevocationGeneration(revocation_generation),
    })
}

fn parse_nonzero_generation(value: Option<&str>) -> Result<u64, HttpsRemoteError> {
    let value = value.ok_or(HttpsRemoteError::Protocol)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(HttpsRemoteError::Protocol);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation != 0)
        .ok_or(HttpsRemoteError::Protocol)
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
    Transport(HttpError),
    HttpStatus,
    ContentType,
    Protocol,
    TooLarge,
    Storage,
    Credential,
}

impl fmt::Display for HttpsRemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUrl => "invalid HTTPS remote URL",
            Self::InvalidRepositoryPath => "invalid HTTPS repository path",
            Self::Transport(error) => return write!(formatter, "HTTPS transport failed: {error}"),
            Self::HttpStatus => "Git service returned an unsuccessful status",
            Self::ContentType => "Git service returned an invalid content type",
            Self::Protocol => "Git protocol-v2 discovery is invalid",
            Self::TooLarge => "Git discovery response exceeds its limit",
            Self::Storage => "Git fetch quarantine storage failed",
            Self::Credential => "HTTPS credential use failed",
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
    fn protected_receive_discovery_binds_exact_nonzero_generations() {
        let body = discovery_body(&[
            "version 2\n",
            "object-format=sha256\n",
            "receive=report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1 mrml-receipt-v1 mrml-candidate-v1\n",
            "mrml-receive-context=7:11:13\n",
        ]);
        assert_eq!(
            parse_protected_receive_discovery(&body),
            Ok(ProtectedReceiveDiscovery {
                repository_generation: crate::RepositoryGeneration(7),
                trust_generation: crate::TrustGeneration(11),
                revocation_generation: crate::RevocationGeneration(13),
            })
        );
        for context in ["0:11:13", "07:11:13", "7:11", "7:11:13:17", "7:x:13"] {
            let malformed = mrml_runtime::mrml_format!("mrml-receive-context={context}\n");
            assert_eq!(
                parse_protected_receive_discovery(&discovery_body(&[
                    "version 2\n",
                    "object-format=sha256\n",
                    "receive=report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1 mrml-receipt-v1 mrml-candidate-v1\n",
                    malformed.as_str(),
                ])),
                Err(HttpsRemoteError::Protocol)
            );
        }
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

    #[test]
    fn ls_refs_request_and_sha256_response_are_exact() {
        let request = ls_refs_request().unwrap();
        assert!(
            request
                .windows(b"command=ls-refs\n".len())
                .any(|v| v == b"command=ls-refs\n")
        );
        assert!(
            request
                .windows(b"object-format=sha256\n".len())
                .any(|v| v == b"object-format=sha256\n")
        );
        assert!(request.windows(4).any(|value| value == b"0001"));
        let main = "11".repeat(32);
        let tag = "22".repeat(32);
        let peeled = "33".repeat(32);
        let response = discovery_body(&[
            &mrml_runtime::mrml_format!("{main} HEAD symref-target:refs/heads/main\n"),
            &mrml_runtime::mrml_format!("{main} refs/heads/main\n"),
            &mrml_runtime::mrml_format!("{tag} refs/tags/v1 peeled:{peeled}\n"),
        ]);
        let parsed = parse_ls_refs(&response).unwrap();
        assert_eq!(parsed.default_branch.as_deref(), Some("refs/heads/main"));
        assert!(!parsed.unborn);
        assert_eq!(parsed.refs.len(), 2);
    }

    #[test]
    fn ls_refs_rejects_sha1_unknown_attributes_duplicates_and_unsorted_refs() {
        let sha256 = "11".repeat(32);
        for lines in [
            Vector::from([mrml_runtime::mrml_format!(
                "{} refs/heads/main\n",
                "11".repeat(20)
            )]),
            Vector::from([mrml_runtime::mrml_format!(
                "{sha256} refs/heads/main hidden:value\n"
            )]),
            Vector::from([
                mrml_runtime::mrml_format!("{sha256} refs/heads/main\n"),
                mrml_runtime::mrml_format!("{sha256} refs/heads/main\n"),
            ]),
            Vector::from([
                mrml_runtime::mrml_format!("{sha256} refs/tags/v1\n"),
                mrml_runtime::mrml_format!("{sha256} refs/heads/main\n"),
            ]),
        ] {
            let borrowed: Vector<&str> = lines.iter().map(Text::as_str).collect();
            assert_eq!(
                parse_ls_refs(&discovery_body(&borrowed)),
                Err(HttpsRemoteError::Protocol)
            );
        }
    }

    #[test]
    fn fetch_request_is_exact_sha256_v2_and_control_bounded() {
        let want =
            crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, &"11".repeat(32)).unwrap();
        let have =
            crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, &"22".repeat(32)).unwrap();
        let request = fetch_request(&[want], &[have]).unwrap();
        for required in [
            "command=fetch\n",
            "object-format=sha256\n",
            "done\n",
            "ofs-delta\n",
        ] {
            assert!(
                request
                    .windows(required.len())
                    .any(|window| window == required.as_bytes())
            );
        }
        assert!(!request.windows(13).any(|window| window == b"sideband-all\n"));
        assert!(request.windows(4).any(|window| window == b"0001"));
        assert!(request.ends_with(b"0000"));
        assert!(request.len() <= 4096);
    }

    #[test]
    fn fetch_request_rejects_empty_zero_sha1_and_excess_batches() {
        let sha256 =
            crate::ObjectId::parse_for(crate::ObjectFormat::Sha256, &"11".repeat(32)).unwrap();
        let sha1 = crate::ObjectId::parse_for(crate::ObjectFormat::Sha1, &"11".repeat(20)).unwrap();
        assert!(fetch_request(&[], &[]).is_err());
        assert!(fetch_request(&[crate::ObjectId::zero(crate::ObjectFormat::Sha256)], &[]).is_err());
        assert!(fetch_request(&[sha1], &[]).is_err());
        assert!(fetch_request(&[sha256; MAX_FETCH_WANTS_PER_REQUEST + 1], &[]).is_err());
    }

    #[test]
    fn authenticated_headers_are_single_exact_and_never_ambient() {
        let anonymous = request_headers("application/test", None, None);
        assert!(!anonymous.iter().any(|(name, _)| *name == "authorization"));
        let authenticated = request_headers(
            "application/test",
            Some("application/request"),
            Some("Bearer redacted-test-value"),
        );
        assert_eq!(
            authenticated
                .iter()
                .filter(|(name, _)| *name == "authorization")
                .count(),
            1
        );
        assert_eq!(
            authenticated
                .iter()
                .find(|(name, _)| *name == "authorization")
                .map(|(_, value)| *value),
            Some("Bearer redacted-test-value")
        );
    }

    #[test]
    fn push_body_source_streams_prefix_then_exact_file_and_bounds_report() {
        let path =
            mrml_runtime::mrml_format!("/tmp/mrml-git-push-source-{}", mrml_runtime::process_id());
        let _ = mrml_runtime::remove_file(&path);
        mrml_runtime::write_new_file(&path, b"PACK-file-bytes").unwrap();
        let file = File::open_regular(&path).unwrap();
        let mut source = PushBodySource::new(Vector::from(*b"prefix-"), file, 15).unwrap();
        assert_eq!(source.remaining(), 22);
        let mut received = Vector::new();
        let mut chunk = [0u8; 5];
        while source.remaining() != 0 {
            let maximum = (source.remaining() as usize).min(chunk.len());
            let read = source.read(&mut chunk[..maximum]).unwrap();
            assert!(read != 0);
            received.try_extend_from_slice(&chunk[..read]).unwrap();
        }
        assert_eq!(&received[..], b"prefix-PACK-file-bytes");
        mrml_runtime::remove_file(&path).unwrap();

        let mut report = LimitedResponseBody::new(4);
        assert!(report.write(b"okay").is_ok());
        assert_eq!(report.write(b"!"), Err(HttpError::BodyTooLarge));
    }
}
