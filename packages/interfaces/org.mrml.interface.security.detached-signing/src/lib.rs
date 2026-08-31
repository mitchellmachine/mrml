#![no_std]

//! Canonical use-only boundary for MRML's reusable OpenPGP Git-signing key.
//!
//! Generation 1 has exactly one signature profile: an ASCII-armored detached
//! OpenPGP version-4 binary-document signature made by an Ed25519Legacy primary
//! key. The only purposes are a canonical Git commit payload and a canonical
//! Git annotated-tag payload. The provider, not the caller, selects signature
//! creation time from its trusted time source and validates the selected Git
//! payload grammar before using the key.
//!
//! The authorized service route binds one exact generational key projection.
//! The expected primary fingerprint in a request identifies that projection and
//! protects against wrong-key routing; it grants no authority. The route also
//! attenuates permitted purposes and digest algorithms. This interface creates,
//! imports, exports, rotates, revokes, or destroys no key. Those lifecycle
//! operations require a separate owner-authorized interface, and secret export
//! must remain distinct from signing use.
//!
//! Calls are synchronous uses of a reusable key. Retrying or replaying a call is
//! a new signing use and has no at-most-once guarantee in this protocol. The
//! runtime must revalidate the route capability on every invocation and enforce
//! revocation, expiry, quotas, and audit policy. This protocol must not be used
//! for Lamport or any other one-time signing key.
//!
//! A successful service response is untrusted output, not proof of correct key
//! use. Before publishing a Git object, the caller must strictly parse and
//! cryptographically verify the returned armor over the exact input with the
//! independently pinned expected primary key and owner-selected policy.

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES: u64 = 20;
pub const MAX_SIGNING_INPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DETACHED_SIGNATURE_BYTES: u64 = 1024;
pub const MAX_PUBLIC_KEY_DESCRIPTION_BYTES: u64 = 64 * 1024;
pub const MAX_SIGNING_SHARED_MEMORY_BYTES: u64 =
    OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES + MAX_SIGNING_INPUT_BYTES + MAX_DETACHED_SIGNATURE_BYTES;
pub const MAX_PUBLIC_KEY_DESCRIPTION_SHARED_MEMORY_BYTES: u64 =
    OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES + MAX_PUBLIC_KEY_DESCRIPTION_BYTES;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const SIGN_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 64;
pub const SIGN_RESPONSE_BYTES: usize = 16;
pub const DESCRIBE_PUBLIC_KEY_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 40;
pub const DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES: usize = 16;
pub const OPENPGP_SIGNATURE_ARMOR_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
pub const OPENPGP_SIGNATURE_ARMOR_END: &[u8] = b"-----END PGP SIGNATURE-----";
pub const OPENPGP_PUBLIC_KEY_ARMOR_BEGIN: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----";
pub const OPENPGP_PUBLIC_KEY_ARMOR_END: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----";

const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;

/// Exact signature packet and armor profile selected by generation 1.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpSignatureProfile {
    /// Canonical ASCII armor containing exactly one old-format, one-octet-length
    /// version-4 signature packet. Its body uses binary-document type 0x00,
    /// EdDSA public-key algorithm 22, the selected digest, then hashed issuer-
    /// fingerprint and creation-time subpackets in that order, an unhashed
    /// issuer-key-ID subpacket, the two digest-prefix octets, and two canonical
    /// Ed25519Legacy MPIs. Armor has no headers, uses LF, 64-column Base64, one
    /// CRC24 line, and one final LF after the end marker.
    V4Ed25519LegacyBinaryDocumentAsciiArmor = 1,
}

impl OpenPgpSignatureProfile {
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::V4Ed25519LegacyBinaryDocumentAsciiArmor),
            _ => None,
        }
    }

    pub const fn wire(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpGitSigningPurpose {
    GitCommit = 1,
    GitAnnotatedTag = 2,
}

impl OpenPgpGitSigningPurpose {
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::GitCommit),
            2 => Some(Self::GitAnnotatedTag),
            _ => None,
        }
    }

    pub const fn wire(self) -> u32 {
        self as u32
    }

    pub const fn mask(self) -> u32 {
        1 << (self as u32 - 1)
    }
}

pub const OPENPGP_GIT_SIGNING_PURPOSE_MASK_ALL: u32 =
    OpenPgpGitSigningPurpose::GitCommit.mask() | OpenPgpGitSigningPurpose::GitAnnotatedTag.mask();

/// Values are the OpenPGP hash-algorithm registry identifiers.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpDigestAlgorithm {
    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
}

impl OpenPgpDigestAlgorithm {
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            8 => Some(Self::Sha256),
            9 => Some(Self::Sha384),
            10 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub const fn wire(self) -> u32 {
        self as u32
    }

    pub const fn mask(self) -> u32 {
        match self {
            Self::Sha256 => 1 << 0,
            Self::Sha384 => 1 << 1,
            Self::Sha512 => 1 << 2,
        }
    }
}

pub const OPENPGP_DIGEST_MASK_ALL: u32 = OpenPgpDigestAlgorithm::Sha256.mask()
    | OpenPgpDigestAlgorithm::Sha384.mask()
    | OpenPgpDigestAlgorithm::Sha512.mask();

/// Compatibility name for callers that referred to the pre-profile enum.
pub type DetachedSigningDigestAlgorithm = OpenPgpDigestAlgorithm;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpPublicKeyDescriptionFormat {
    /// Canonical ASCII armor containing exactly one old-format, one-octet-length
    /// 51-byte version-4 primary-public-key packet using algorithm 22, the
    /// Ed25519Legacy OID `1.3.6.1.4.1.11591.15.1`, and one canonical 263-bit
    /// point MPI. It contains no user IDs, subkeys, certification signatures, or
    /// secret-key packets. Armor has no headers, uses LF, 64-column Base64, one
    /// CRC24 line, and one final LF after the end marker.
    V4Ed25519LegacyPrimaryKeyAsciiArmor = 1,
}

impl OpenPgpPublicKeyDescriptionFormat {
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::V4Ed25519LegacyPrimaryKeyAsciiArmor),
            _ => None,
        }
    }

    pub const fn wire(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
    Transport,
}

/// Raw isolated-service call mechanism supplied by the runtime.
///
/// `endpoint` identifies a generational route; it is not itself authority. The
/// runtime capability used by the implementation must bind the exact key and
/// attenuation policy recorded by `IsolatedDetachedSigningTransport`.
pub trait DetachedSigningServiceEndpoint {
    fn invoke_sign(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; SIGN_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; SIGN_RESPONSE_BYTES], ProtocolError>;
}

pub trait PublicKeyDescriptionServiceEndpoint {
    fn invoke_describe_public_key(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES], ProtocolError>;
}

pub trait DetachedSigningTransport {
    fn sign(
        &mut self,
        request: &[u8; SIGN_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; SIGN_RESPONSE_BYTES], ProtocolError>;
}

pub trait PublicKeyDescriptionTransport {
    fn describe_public_key(
        &mut self,
        request: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES], ProtocolError>;
}

pub struct IsolatedDetachedSigningTransport<E> {
    endpoint: OpaqueHandle,
    expected_primary_fingerprint: [u8; 20],
    allowed_purpose_mask: u32,
    allowed_digest_mask: u32,
    maximum_memory_bytes: usize,
    service: E,
}

impl<E> IsolatedDetachedSigningTransport<E> {
    pub fn new(
        endpoint: OpaqueHandle,
        expected_primary_fingerprint: [u8; 20],
        allowed_purpose_mask: u32,
        allowed_digest_mask: u32,
        maximum_memory_bytes: usize,
        service: E,
    ) -> Result<Self, ProtocolError> {
        let maximum =
            u64::try_from(maximum_memory_bytes).map_err(|_| ProtocolError::InvalidRequest)?;
        if maximum == 0
            || maximum > MAX_SIGNING_SHARED_MEMORY_BYTES
            || expected_primary_fingerprint == [0; 20]
            || allowed_purpose_mask == 0
            || allowed_purpose_mask & !OPENPGP_GIT_SIGNING_PURPOSE_MASK_ALL != 0
            || allowed_digest_mask == 0
            || allowed_digest_mask & !OPENPGP_DIGEST_MASK_ALL != 0
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            expected_primary_fingerprint,
            allowed_purpose_mask,
            allowed_digest_mask,
            maximum_memory_bytes,
            service,
        })
    }

    pub const fn endpoint(&self) -> OpaqueHandle {
        self.endpoint
    }

    pub const fn expected_primary_fingerprint(&self) -> [u8; 20] {
        self.expected_primary_fingerprint
    }

    pub fn into_service(self) -> E {
        self.service
    }
}

impl<E: DetachedSigningServiceEndpoint> DetachedSigningTransport
    for IsolatedDetachedSigningTransport<E>
{
    fn sign(
        &mut self,
        request_bytes: &[u8; SIGN_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; SIGN_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        let request = decode_sign_request(request_bytes, memory.len() as u64)?;
        if OpenPgpSignatureProfile::from_wire(request.signature_profile)
            != Some(OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor)
        {
            return Err(ProtocolError::InvalidRequest);
        }
        let purpose = OpenPgpGitSigningPurpose::from_wire(request.purpose)
            .ok_or(ProtocolError::InvalidRequest)?;
        let digest = OpenPgpDigestAlgorithm::from_wire(request.digest_algorithm)
            .ok_or(ProtocolError::InvalidRequest)?;
        if self.allowed_purpose_mask & purpose.mask() == 0
            || self.allowed_digest_mask & digest.mask() == 0
            || read_fingerprint(memory, request.expected_primary_fingerprint)?
                != self.expected_primary_fingerprint
        {
            return Err(ProtocolError::InvalidRequest);
        }
        let response = self
            .service
            .invoke_sign(self.endpoint, request_bytes, memory)?;
        let _ = decode_sign_response(&response, request.output.length())?;
        Ok(response)
    }
}

pub struct IsolatedPublicKeyDescriptionTransport<E> {
    endpoint: OpaqueHandle,
    expected_primary_fingerprint: [u8; 20],
    maximum_memory_bytes: usize,
    service: E,
}

impl<E> IsolatedPublicKeyDescriptionTransport<E> {
    pub fn new(
        endpoint: OpaqueHandle,
        expected_primary_fingerprint: [u8; 20],
        maximum_memory_bytes: usize,
        service: E,
    ) -> Result<Self, ProtocolError> {
        let maximum =
            u64::try_from(maximum_memory_bytes).map_err(|_| ProtocolError::InvalidRequest)?;
        if maximum == 0
            || maximum > MAX_PUBLIC_KEY_DESCRIPTION_SHARED_MEMORY_BYTES
            || expected_primary_fingerprint == [0; 20]
        {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            expected_primary_fingerprint,
            maximum_memory_bytes,
            service,
        })
    }

    pub const fn endpoint(&self) -> OpaqueHandle {
        self.endpoint
    }

    pub fn into_service(self) -> E {
        self.service
    }
}

impl<E: PublicKeyDescriptionServiceEndpoint> PublicKeyDescriptionTransport
    for IsolatedPublicKeyDescriptionTransport<E>
{
    fn describe_public_key(
        &mut self,
        request_bytes: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        let request = decode_describe_public_key_request(request_bytes, memory.len() as u64)?;
        if OpenPgpPublicKeyDescriptionFormat::from_wire(request.description_format)
            != Some(OpenPgpPublicKeyDescriptionFormat::V4Ed25519LegacyPrimaryKeyAsciiArmor)
            || read_fingerprint(memory, request.expected_primary_fingerprint)?
                != self.expected_primary_fingerprint
        {
            return Err(ProtocolError::InvalidRequest);
        }
        let response =
            self.service
                .invoke_describe_public_key(self.endpoint, request_bytes, memory)?;
        let _ = decode_describe_public_key_response(&response, request.output.length())?;
        Ok(response)
    }
}

/// Provider-side typed boundary. Implementations receive no mutable access to
/// the fingerprint or signed input and no access to shared-memory gaps.
pub trait OpenPgpV4Ed25519LegacySigningProvider {
    fn primary_fingerprint(&self) -> [u8; 20];

    /// The provider must validate that `input` is the canonical payload for
    /// `purpose`, choose creation time from trusted provider state, and emit the
    /// exact generation-1 signature profile.
    fn sign_git_binary_document(
        &mut self,
        purpose: OpenPgpGitSigningPurpose,
        digest_algorithm: OpenPgpDigestAlgorithm,
        expected_primary_fingerprint: &[u8; 20],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, SignError>;
}

pub trait OpenPgpV4Ed25519LegacyPublicKeyProvider {
    fn primary_fingerprint(&self) -> [u8; 20];

    fn describe_primary_public_key(
        &mut self,
        expected_primary_fingerprint: &[u8; 20],
        output: &mut [u8],
    ) -> Result<usize, DescribePublicKeyError>;
}

/// Decode one untrusted service request and expose only its typed read regions
/// and exact write region to a provider. The output must follow both read views,
/// which permits this separation without unsafe code.
pub fn dispatch_sign_request<P: OpenPgpV4Ed25519LegacySigningProvider>(
    provider: &mut P,
    request_bytes: &[u8; SIGN_REQUEST_BYTES],
    memory: &mut [u8],
) -> [u8; SIGN_RESPONSE_BYTES] {
    let request = match decode_sign_request(request_bytes, memory.len() as u64) {
        Ok(request) => request,
        Err(_) => return encode_sign_response(Err(SignError::InvalidRequest)),
    };
    let profile = match OpenPgpSignatureProfile::from_wire(request.signature_profile) {
        Some(profile) => profile,
        None => return encode_sign_response(Err(SignError::UnsupportedProfile)),
    };
    if profile != OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor {
        return encode_sign_response(Err(SignError::UnsupportedProfile));
    }
    let purpose = match OpenPgpGitSigningPurpose::from_wire(request.purpose) {
        Some(purpose) => purpose,
        None => return encode_sign_response(Err(SignError::UnsupportedPurpose)),
    };
    let digest = match OpenPgpDigestAlgorithm::from_wire(request.digest_algorithm) {
        Some(digest) => digest,
        None => return encode_sign_response(Err(SignError::UnsupportedDigest)),
    };

    let output_offset = request.output.offset() as usize;
    let output_length = request.output.length() as usize;
    let (read_memory, write_memory) = memory.split_at_mut(output_offset);
    let output = &mut write_memory[..output_length];
    output.fill(0);
    let read_memory: &[u8] = read_memory;
    let fingerprint_start = request.expected_primary_fingerprint.offset() as usize;
    let fingerprint_end = fingerprint_start + 20;
    let expected_primary_fingerprint: &[u8; 20] = read_memory[fingerprint_start..fingerprint_end]
        .try_into()
        .unwrap();
    if *expected_primary_fingerprint != provider.primary_fingerprint() {
        return encode_sign_response(Err(SignError::FingerprintMismatch));
    }
    let input_start = request.input.offset() as usize;
    let input_end = input_start + request.input.length() as usize;
    let input = &read_memory[input_start..input_end];
    match provider.sign_git_binary_document(
        purpose,
        digest,
        expected_primary_fingerprint,
        input,
        output,
    ) {
        Ok(written) if written != 0 && written <= output.len() => {
            encode_sign_response(Ok(written as u64))
        }
        Ok(_) => {
            output.fill(0);
            encode_sign_response(Err(SignError::SigningFailed))
        }
        Err(error) => {
            output.fill(0);
            encode_sign_response(Err(error))
        }
    }
}

pub fn dispatch_describe_public_key_request<P: OpenPgpV4Ed25519LegacyPublicKeyProvider>(
    provider: &mut P,
    request_bytes: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
    memory: &mut [u8],
) -> [u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES] {
    let request = match decode_describe_public_key_request(request_bytes, memory.len() as u64) {
        Ok(request) => request,
        Err(_) => {
            return encode_describe_public_key_response(Err(
                DescribePublicKeyError::InvalidRequest,
            ));
        }
    };
    if OpenPgpPublicKeyDescriptionFormat::from_wire(request.description_format)
        != Some(OpenPgpPublicKeyDescriptionFormat::V4Ed25519LegacyPrimaryKeyAsciiArmor)
    {
        return encode_describe_public_key_response(Err(DescribePublicKeyError::UnsupportedFormat));
    }

    let output_offset = request.output.offset() as usize;
    let output_length = request.output.length() as usize;
    let (read_memory, write_memory) = memory.split_at_mut(output_offset);
    let output = &mut write_memory[..output_length];
    output.fill(0);
    let read_memory: &[u8] = read_memory;
    let fingerprint_start = request.expected_primary_fingerprint.offset() as usize;
    let fingerprint_end = fingerprint_start + 20;
    let expected_primary_fingerprint: &[u8; 20] = read_memory[fingerprint_start..fingerprint_end]
        .try_into()
        .unwrap();
    if *expected_primary_fingerprint != provider.primary_fingerprint() {
        return encode_describe_public_key_response(Err(
            DescribePublicKeyError::FingerprintMismatch,
        ));
    }
    match provider.describe_primary_public_key(expected_primary_fingerprint, output) {
        Ok(written) if written != 0 && written <= output.len() => {
            encode_describe_public_key_response(Ok(written as u64))
        }
        Ok(_) => {
            output.fill(0);
            encode_describe_public_key_response(Err(DescribePublicKeyError::KeyUnavailable))
        }
        Err(error) => {
            output.fill(0);
            encode_describe_public_key_response(Err(error))
        }
    }
}

pub fn encode_sign_request(
    signature_profile: OpenPgpSignatureProfile,
    purpose: OpenPgpGitSigningPurpose,
    digest_algorithm: OpenPgpDigestAlgorithm,
    expected_primary_fingerprint: BorrowedReadView,
    input: BorrowedReadView,
    output: BorrowedWriteView,
) -> Result<[u8; SIGN_REQUEST_BYTES], ProtocolError> {
    let request = SignRequest {
        signature_profile: signature_profile.wire(),
        purpose: purpose.wire(),
        digest_algorithm: digest_algorithm.wire(),
        expected_primary_fingerprint,
        input,
        output,
    };
    validate_sign_request(&request)?;
    let mut bytes = [0; SIGN_REQUEST_BYTES];
    encode_header(&mut bytes, OP_SIGN, 64, SIGN_RESPONSE_BYTES)?;
    bytes[72..76].copy_from_slice(&signature_profile.wire().to_le_bytes());
    bytes[76..80].copy_from_slice(&purpose.wire().to_le_bytes());
    bytes[80..84].copy_from_slice(&digest_algorithm.wire().to_le_bytes());
    bytes[88..96].copy_from_slice(&expected_primary_fingerprint.offset().to_le_bytes());
    bytes[96..104].copy_from_slice(&expected_primary_fingerprint.length().to_le_bytes());
    bytes[104..112].copy_from_slice(&input.offset().to_le_bytes());
    bytes[112..120].copy_from_slice(&input.length().to_le_bytes());
    bytes[120..128].copy_from_slice(&output.offset().to_le_bytes());
    bytes[128..136].copy_from_slice(&output.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_sign_request(
    bytes: &[u8; SIGN_REQUEST_BYTES],
    memory_length: u64,
) -> Result<SignRequest, ProtocolError> {
    validate_header(bytes, OP_SIGN, 64, SIGN_RESPONSE_BYTES)?;
    if bytes[84..88] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let expected_primary_fingerprint =
        BorrowedReadView::within(read_u64(bytes, 88), read_u64(bytes, 96), memory_length)
            .ok_or(ProtocolError::InvalidRequest)?;
    let input = BorrowedReadView::within(read_u64(bytes, 104), read_u64(bytes, 112), memory_length)
        .ok_or(ProtocolError::InvalidRequest)?;
    let output =
        BorrowedWriteView::within(read_u64(bytes, 120), read_u64(bytes, 128), memory_length)
            .ok_or(ProtocolError::InvalidRequest)?;
    let request = SignRequest {
        signature_profile: read_u32(bytes, 72),
        purpose: read_u32(bytes, 76),
        digest_algorithm: read_u32(bytes, 80),
        expected_primary_fingerprint,
        input,
        output,
    };
    validate_sign_request(&request)?;
    Ok(request)
}

pub fn encode_sign_response(result: Result<SignResponse, SignError>) -> [u8; SIGN_RESPONSE_BYTES] {
    encode_response(result.map_err(|error| error as u32))
}

pub fn decode_sign_response(
    bytes: &[u8; SIGN_RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<SignResponse, SignError>, ProtocolError> {
    let (status, written) = decode_response(bytes)?;
    match status {
        0 if valid_written(written, output_length, MAX_DETACHED_SIGNATURE_BYTES) => Ok(Ok(written)),
        1 if written == 0 => Ok(Err(SignError::InvalidRequest)),
        2 if written == 0 => Ok(Err(SignError::StaleKey)),
        3 if written == 0 => Ok(Err(SignError::PermissionDenied)),
        4 if written == 0 => Ok(Err(SignError::UnsupportedProfile)),
        5 if written == 0 => Ok(Err(SignError::UnsupportedPurpose)),
        6 if written == 0 => Ok(Err(SignError::UnsupportedDigest)),
        7 if written == 0 => Ok(Err(SignError::FingerprintMismatch)),
        8 if written == 0 => Ok(Err(SignError::OutputTooSmall)),
        9 if written == 0 => Ok(Err(SignError::KeyUnavailable)),
        10 if written == 0 => Ok(Err(SignError::SigningFailed)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_describe_public_key_request(
    description_format: OpenPgpPublicKeyDescriptionFormat,
    expected_primary_fingerprint: BorrowedReadView,
    output: BorrowedWriteView,
) -> Result<[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES], ProtocolError> {
    let request = DescribePublicKeyRequest {
        description_format: description_format.wire(),
        expected_primary_fingerprint,
        output,
    };
    validate_describe_public_key_request(&request)?;
    let mut bytes = [0; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES];
    encode_header(
        &mut bytes,
        OP_DESCRIBE_PUBLIC_KEY,
        40,
        DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES,
    )?;
    bytes[72..76].copy_from_slice(&description_format.wire().to_le_bytes());
    bytes[80..88].copy_from_slice(&expected_primary_fingerprint.offset().to_le_bytes());
    bytes[88..96].copy_from_slice(&expected_primary_fingerprint.length().to_le_bytes());
    bytes[96..104].copy_from_slice(&output.offset().to_le_bytes());
    bytes[104..112].copy_from_slice(&output.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_describe_public_key_request(
    bytes: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
    memory_length: u64,
) -> Result<DescribePublicKeyRequest, ProtocolError> {
    validate_header(
        bytes,
        OP_DESCRIBE_PUBLIC_KEY,
        40,
        DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES,
    )?;
    if bytes[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let expected_primary_fingerprint =
        BorrowedReadView::within(read_u64(bytes, 80), read_u64(bytes, 88), memory_length)
            .ok_or(ProtocolError::InvalidRequest)?;
    let output =
        BorrowedWriteView::within(read_u64(bytes, 96), read_u64(bytes, 104), memory_length)
            .ok_or(ProtocolError::InvalidRequest)?;
    let request = DescribePublicKeyRequest {
        description_format: read_u32(bytes, 72),
        expected_primary_fingerprint,
        output,
    };
    validate_describe_public_key_request(&request)?;
    Ok(request)
}

pub fn encode_describe_public_key_response(
    result: Result<DescribePublicKeyResponse, DescribePublicKeyError>,
) -> [u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES] {
    encode_response(result.map_err(|error| error as u32))
}

pub fn decode_describe_public_key_response(
    bytes: &[u8; DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<DescribePublicKeyResponse, DescribePublicKeyError>, ProtocolError> {
    let (status, written) = decode_response(bytes)?;
    match status {
        0 if valid_written(written, output_length, MAX_PUBLIC_KEY_DESCRIPTION_BYTES) => {
            Ok(Ok(written))
        }
        1 if written == 0 => Ok(Err(DescribePublicKeyError::InvalidRequest)),
        2 if written == 0 => Ok(Err(DescribePublicKeyError::StaleKey)),
        3 if written == 0 => Ok(Err(DescribePublicKeyError::PermissionDenied)),
        4 if written == 0 => Ok(Err(DescribePublicKeyError::UnsupportedFormat)),
        5 if written == 0 => Ok(Err(DescribePublicKeyError::FingerprintMismatch)),
        6 if written == 0 => Ok(Err(DescribePublicKeyError::OutputTooSmall)),
        7 if written == 0 => Ok(Err(DescribePublicKeyError::KeyUnavailable)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

fn validate_sign_request(request: &SignRequest) -> Result<(), ProtocolError> {
    if !request.validate()
        || request.expected_primary_fingerprint.length() != OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES
        || request.input.length() == 0
        || request.output.length() == 0
        || read_end(request.expected_primary_fingerprint)? > request.output.offset()
        || read_end(request.input)? > request.output.offset()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn validate_describe_public_key_request(
    request: &DescribePublicKeyRequest,
) -> Result<(), ProtocolError> {
    if !request.validate()
        || request.expected_primary_fingerprint.length() != OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES
        || request.output.length() == 0
        || read_end(request.expected_primary_fingerprint)? > request.output.offset()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn read_end(view: BorrowedReadView) -> Result<u64, ProtocolError> {
    view.offset()
        .checked_add(view.length())
        .ok_or(ProtocolError::InvalidRequest)
}

fn read_fingerprint(memory: &[u8], view: BorrowedReadView) -> Result<[u8; 20], ProtocolError> {
    let start = usize::try_from(view.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
    let end = start.checked_add(20).ok_or(ProtocolError::InvalidRequest)?;
    memory
        .get(start..end)
        .ok_or(ProtocolError::InvalidRequest)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidRequest)
}

fn encode_header<const N: usize>(
    bytes: &mut [u8; N],
    operation: u32,
    payload_bytes: u64,
    response_bytes: usize,
) -> Result<(), ProtocolError> {
    if N != ABI_CALL_HEADER_BYTES + payload_bytes as usize {
        return Err(ProtocolError::InvalidRequest);
    }
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&operation.to_le_bytes());
    bytes[56..64].copy_from_slice(&payload_bytes.to_le_bytes());
    bytes[64..72].copy_from_slice(&(response_bytes as u64).to_le_bytes());
    Ok(())
}

fn validate_header(
    bytes: &[u8],
    operation: u32,
    payload_bytes: u64,
    response_bytes: usize,
) -> Result<(), ProtocolError> {
    if bytes.len() != ABI_CALL_HEADER_BYTES + payload_bytes as usize
        || bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || read_u32(bytes, 48) != INTERFACE_GENERATION
        || read_u32(bytes, 52) != operation
        || read_u64(bytes, 56) != payload_bytes
        || read_u64(bytes, 64) != response_bytes as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    Ok(())
}

fn encode_response<const N: usize>(result: Result<u64, u32>) -> [u8; N] {
    let mut bytes = [0; N];
    let (status, written) = match result {
        Ok(written) => (0, written),
        Err(status) => (status, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&written.to_le_bytes());
    bytes
}

fn decode_response(bytes: &[u8]) -> Result<(u32, u64), ProtocolError> {
    if bytes.len() != 16 || bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok((read_u32(bytes, 0), read_u64(bytes, 8)))
}

fn valid_written(written: u64, output_length: u64, maximum: u64) -> bool {
    written != 0 && written <= output_length && written <= maximum
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: [u8; 20] = [0x5a; 20];

    fn key(index: u32, generation: u32) -> OpaqueHandle {
        OpaqueHandle::new(index, generation).unwrap()
    }

    fn sign_views(memory_length: u64) -> (BorrowedReadView, BorrowedReadView, BorrowedWriteView) {
        (
            BorrowedReadView::within(0, 20, memory_length).unwrap(),
            BorrowedReadView::within(20, 16, memory_length).unwrap(),
            BorrowedWriteView::within(36, memory_length - 36, memory_length).unwrap(),
        )
    }

    fn sign_request(memory_length: u64) -> [u8; SIGN_REQUEST_BYTES] {
        let (fingerprint, input, output) = sign_views(memory_length);
        encode_sign_request(
            OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor,
            OpenPgpGitSigningPurpose::GitCommit,
            OpenPgpDigestAlgorithm::Sha512,
            fingerprint,
            input,
            output,
        )
        .unwrap()
    }

    #[test]
    fn canonical_request_and_response_round_trip() {
        let request = sign_request(100);
        let decoded = decode_sign_request(&request, 100).unwrap();
        assert_eq!(
            decoded.signature_profile,
            OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor.wire()
        );
        assert_eq!(decoded.purpose, OpenPgpGitSigningPurpose::GitCommit.wire());
        assert_eq!(
            decoded.digest_algorithm,
            OpenPgpDigestAlgorithm::Sha512.wire()
        );
        assert_eq!(decoded.expected_primary_fingerprint.length(), 20);
        assert_eq!(decoded.output.offset(), 36);
        assert_eq!(
            decode_sign_response(&encode_sign_response(Ok(63)), decoded.output.length()),
            Ok(Ok(63))
        );
    }

    #[test]
    fn request_requires_exact_fingerprint_and_output_after_all_reads() {
        let fingerprint = BorrowedReadView::within(0, 19, 80).unwrap();
        let input = BorrowedReadView::within(20, 20, 80).unwrap();
        let output = BorrowedWriteView::within(40, 40, 80).unwrap();
        assert_eq!(
            encode_sign_request(
                OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor,
                OpenPgpGitSigningPurpose::GitCommit,
                OpenPgpDigestAlgorithm::Sha256,
                fingerprint,
                input,
                output,
            ),
            Err(ProtocolError::InvalidRequest)
        );
        let fingerprint = BorrowedReadView::within(0, 20, 80).unwrap();
        let early_output = BorrowedWriteView::within(32, 16, 80).unwrap();
        assert_eq!(
            encode_sign_request(
                OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor,
                OpenPgpGitSigningPurpose::GitCommit,
                OpenPgpDigestAlgorithm::Sha256,
                fingerprint,
                input,
                early_output,
            ),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[derive(Default)]
    struct RecordingService {
        calls: usize,
        malformed_response: bool,
    }

    impl DetachedSigningServiceEndpoint for RecordingService {
        fn invoke_sign(
            &mut self,
            _endpoint: OpaqueHandle,
            _request: &[u8; SIGN_REQUEST_BYTES],
            _memory: &mut [u8],
        ) -> Result<[u8; SIGN_RESPONSE_BYTES], ProtocolError> {
            self.calls += 1;
            let mut response = encode_sign_response(Ok(8));
            if self.malformed_response {
                response[4] = 1;
            }
            Ok(response)
        }
    }

    #[test]
    fn isolated_route_binds_fingerprint_purpose_and_digest() {
        let mut memory = [0u8; 100];
        memory[..20].copy_from_slice(&FINGERPRINT);
        let mut transport = IsolatedDetachedSigningTransport::new(
            key(8, 3),
            FINGERPRINT,
            OpenPgpGitSigningPurpose::GitCommit.mask(),
            OpenPgpDigestAlgorithm::Sha512.mask(),
            memory.len(),
            RecordingService::default(),
        )
        .unwrap();
        let request = sign_request(memory.len() as u64);
        assert_eq!(
            decode_sign_response(&transport.sign(&request, &mut memory).unwrap(), 64),
            Ok(Ok(8))
        );

        let mut wrong_purpose = request;
        wrong_purpose[76..80].copy_from_slice(
            &OpenPgpGitSigningPurpose::GitAnnotatedTag
                .wire()
                .to_le_bytes(),
        );
        assert_eq!(
            transport.sign(&wrong_purpose, &mut memory),
            Err(ProtocolError::InvalidRequest)
        );
        let mut wrong_digest = request;
        wrong_digest[80..84].copy_from_slice(&OpenPgpDigestAlgorithm::Sha256.wire().to_le_bytes());
        assert_eq!(
            transport.sign(&wrong_digest, &mut memory),
            Err(ProtocolError::InvalidRequest)
        );
        memory[0] ^= 1;
        assert_eq!(
            transport.sign(&request, &mut memory),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(transport.into_service().calls, 1);
    }

    #[test]
    fn isolated_route_rejects_unknown_profile_and_malformed_response() {
        let mut memory = [0u8; 100];
        memory[..20].copy_from_slice(&FINGERPRINT);
        let request = sign_request(memory.len() as u64);
        let mut unknown = request;
        unknown[72..76].copy_from_slice(&99u32.to_le_bytes());
        let mut transport = IsolatedDetachedSigningTransport::new(
            key(8, 3),
            FINGERPRINT,
            OPENPGP_GIT_SIGNING_PURPOSE_MASK_ALL,
            OPENPGP_DIGEST_MASK_ALL,
            memory.len(),
            RecordingService::default(),
        )
        .unwrap();
        assert_eq!(
            transport.sign(&unknown, &mut memory),
            Err(ProtocolError::InvalidRequest)
        );

        let mut malformed = IsolatedDetachedSigningTransport::new(
            key(8, 3),
            FINGERPRINT,
            OPENPGP_GIT_SIGNING_PURPOSE_MASK_ALL,
            OPENPGP_DIGEST_MASK_ALL,
            memory.len(),
            RecordingService {
                calls: 0,
                malformed_response: true,
            },
        )
        .unwrap();
        assert_eq!(
            malformed.sign(&request, &mut memory),
            Err(ProtocolError::InvalidResponse)
        );
    }

    struct RecordingProvider {
        fingerprint: [u8; 20],
        calls: usize,
    }

    impl OpenPgpV4Ed25519LegacySigningProvider for RecordingProvider {
        fn primary_fingerprint(&self) -> [u8; 20] {
            self.fingerprint
        }

        fn sign_git_binary_document(
            &mut self,
            purpose: OpenPgpGitSigningPurpose,
            digest_algorithm: OpenPgpDigestAlgorithm,
            expected_primary_fingerprint: &[u8; 20],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, SignError> {
            assert_eq!(purpose, OpenPgpGitSigningPurpose::GitCommit);
            assert_eq!(digest_algorithm, OpenPgpDigestAlgorithm::Sha512);
            assert_eq!(expected_primary_fingerprint, &FINGERPRINT);
            assert_eq!(input, &[0x33; 16]);
            self.calls += 1;
            output[..4].copy_from_slice(b"sig\n");
            Ok(4)
        }
    }

    #[test]
    fn provider_dispatch_exposes_only_read_slices_and_exact_output() {
        let mut memory = [0xa5u8; 108];
        memory[..20].copy_from_slice(&FINGERPRINT);
        memory[20..36].fill(0x33);
        let fingerprint_before: [u8; 20] = memory[..20].try_into().unwrap();
        let input_before: [u8; 16] = memory[20..36].try_into().unwrap();
        let request = {
            let fingerprint = BorrowedReadView::within(0, 20, 108).unwrap();
            let input = BorrowedReadView::within(20, 16, 108).unwrap();
            let output = BorrowedWriteView::within(36, 64, 108).unwrap();
            encode_sign_request(
                OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor,
                OpenPgpGitSigningPurpose::GitCommit,
                OpenPgpDigestAlgorithm::Sha512,
                fingerprint,
                input,
                output,
            )
            .unwrap()
        };
        let mut provider = RecordingProvider {
            fingerprint: FINGERPRINT,
            calls: 0,
        };
        let response = dispatch_sign_request(&mut provider, &request, &mut memory);
        assert_eq!(decode_sign_response(&response, 64), Ok(Ok(4)));
        assert_eq!(provider.calls, 1);
        assert_eq!(memory[..20], fingerprint_before);
        assert_eq!(memory[20..36], input_before);
        assert_eq!(&memory[36..40], b"sig\n");
        assert!(memory[40..100].iter().all(|byte| *byte == 0));
        assert!(memory[100..].iter().all(|byte| *byte == 0xa5));

        memory[..20].fill(0x77);
        let mismatch = dispatch_sign_request(&mut provider, &request, &mut memory);
        assert_eq!(
            decode_sign_response(&mismatch, 64),
            Ok(Err(SignError::FingerprintMismatch))
        );
        assert_eq!(provider.calls, 1);
        assert!(memory[36..100].iter().all(|byte| *byte == 0));
    }

    struct PublicProvider;

    impl OpenPgpV4Ed25519LegacyPublicKeyProvider for PublicProvider {
        fn primary_fingerprint(&self) -> [u8; 20] {
            FINGERPRINT
        }

        fn describe_primary_public_key(
            &mut self,
            expected_primary_fingerprint: &[u8; 20],
            output: &mut [u8],
        ) -> Result<usize, DescribePublicKeyError> {
            assert_eq!(expected_primary_fingerprint, &FINGERPRINT);
            output[..3].copy_from_slice(b"key");
            Ok(3)
        }
    }

    #[test]
    fn public_description_format_is_exact_and_bounded() {
        let mut memory = [0xa5u8; 96];
        memory[..20].copy_from_slice(&FINGERPRINT);
        let fingerprint = BorrowedReadView::within(0, 20, 96).unwrap();
        let output = BorrowedWriteView::within(20, 64, 96).unwrap();
        let request = encode_describe_public_key_request(
            OpenPgpPublicKeyDescriptionFormat::V4Ed25519LegacyPrimaryKeyAsciiArmor,
            fingerprint,
            output,
        )
        .unwrap();
        let response =
            dispatch_describe_public_key_request(&mut PublicProvider, &request, &mut memory);
        assert_eq!(
            decode_describe_public_key_response(&response, 64),
            Ok(Ok(3))
        );
        assert_eq!(&memory[20..23], b"key");
        assert!(memory[23..84].iter().all(|byte| *byte == 0));
        assert!(memory[84..].iter().all(|byte| *byte == 0xa5));

        let mut unknown = request;
        unknown[72..76].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            decode_describe_public_key_response(
                &dispatch_describe_public_key_request(&mut PublicProvider, &unknown, &mut memory,),
                64,
            ),
            Ok(Err(DescribePublicKeyError::UnsupportedFormat))
        );
    }

    #[test]
    fn malformed_responses_fail_closed() {
        let mut success = encode_sign_response(Ok(5));
        success[4] = 1;
        assert_eq!(
            decode_sign_response(&success, 8),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_sign_response(&encode_sign_response(Ok(9)), 8),
            Err(ProtocolError::InvalidResponse)
        );
        let mut error = encode_sign_response(Err(SignError::SigningFailed));
        error[8..16].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            decode_sign_response(&error, 8),
            Err(ProtocolError::InvalidResponse)
        );
    }
}
