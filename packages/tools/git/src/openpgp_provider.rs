use core::fmt;

use mrml_interface_detached_signing_v1::{
    BorrowedReadView, BorrowedWriteView, DescribePublicKeyError, DetachedSigningServiceEndpoint,
    DetachedSigningTransport, IsolatedDetachedSigningTransport,
    IsolatedPublicKeyDescriptionTransport, MAX_DETACHED_SIGNATURE_BYTES,
    MAX_PUBLIC_KEY_DESCRIPTION_BYTES, OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES, OpaqueHandle,
    OpenPgpDigestAlgorithm, OpenPgpGitSigningPurpose, OpenPgpPublicKeyDescriptionFormat,
    OpenPgpSignatureProfile, OpenPgpV4Ed25519LegacyPublicKeyProvider,
    OpenPgpV4Ed25519LegacySigningProvider, ProtocolError, PublicKeyDescriptionServiceEndpoint,
    PublicKeyDescriptionTransport, SignError, decode_sign_response,
    dispatch_describe_public_key_request, dispatch_sign_request,
    encode_describe_public_key_request, encode_sign_request,
};
use mrml_openpgp::{
    DigestAlgorithm, Error as OpenPgpError, PublicKey, SigningKey, sign_detached_ascii,
};
use mrml_runtime::Vector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpServiceError {
    InputTooLarge,
    InvalidPolicy,
    Protocol,
    Signing(SignError),
    PublicKey(DescribePublicKeyError),
}

impl fmt::Display for OpenPgpServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => formatter.write_str("Git signing payload exceeds its limit"),
            Self::InvalidPolicy => formatter.write_str("OpenPGP signing policy is invalid"),
            Self::Protocol => formatter.write_str("detached-signing interface failed closed"),
            Self::Signing(error) => {
                write!(formatter, "detached-signing service returned {error:?}")
            }
            Self::PublicKey(error) => {
                write!(formatter, "public-key service returned {error:?}")
            }
        }
    }
}

impl core::error::Error for OpenPgpServiceError {}

struct InProcessOpenPgpSigningEndpoint<C> {
    endpoint: OpaqueHandle,
    key: SigningKey,
    allowed_purpose_mask: u32,
    allowed_digest_mask: u32,
    key_not_after: Option<u64>,
    key_revoked: bool,
    trusted_time: C,
}

impl<C: FnMut() -> Option<u64>> OpenPgpV4Ed25519LegacySigningProvider
    for InProcessOpenPgpSigningEndpoint<C>
{
    fn primary_fingerprint(&self) -> [u8; 20] {
        *self.key.public_key().fingerprint().as_bytes()
    }

    fn sign_git_binary_document(
        &mut self,
        purpose: OpenPgpGitSigningPurpose,
        digest_algorithm: OpenPgpDigestAlgorithm,
        expected_primary_fingerprint: &[u8; 20],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, SignError> {
        if self.allowed_purpose_mask & purpose.mask() == 0
            || self.allowed_digest_mask & digest_algorithm.mask() == 0
        {
            return Err(SignError::PermissionDenied);
        }
        if expected_primary_fingerprint != self.key.public_key().fingerprint().as_bytes() {
            return Err(SignError::FingerprintMismatch);
        }
        if !valid_git_payload(purpose, input) {
            return Err(SignError::InvalidRequest);
        }
        if self.key_revoked {
            return Err(SignError::PermissionDenied);
        }
        let created_at = (self.trusted_time)().ok_or(SignError::KeyUnavailable)?;
        if created_at == 0
            || created_at < u64::from(self.key.public_key().created_at())
            || self
                .key_not_after
                .is_some_and(|not_after| created_at >= not_after)
        {
            return Err(SignError::PermissionDenied);
        }
        let digest = match digest_algorithm {
            OpenPgpDigestAlgorithm::Sha256 => DigestAlgorithm::Sha256,
            OpenPgpDigestAlgorithm::Sha384 => DigestAlgorithm::Sha384,
            OpenPgpDigestAlgorithm::Sha512 => DigestAlgorithm::Sha512,
        };
        sign_detached_ascii(&self.key, input, digest, created_at, output).map_err(|error| {
            if error == OpenPgpError::OutputTooSmall {
                SignError::OutputTooSmall
            } else {
                SignError::SigningFailed
            }
        })
    }
}

impl<C: FnMut() -> Option<u64>> DetachedSigningServiceEndpoint
    for InProcessOpenPgpSigningEndpoint<C>
{
    fn invoke_sign(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; mrml_interface_detached_signing_v1::SIGN_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; mrml_interface_detached_signing_v1::SIGN_RESPONSE_BYTES], ProtocolError> {
        if endpoint != self.endpoint {
            return Ok(mrml_interface_detached_signing_v1::encode_sign_response(
                Err(SignError::StaleKey),
            ));
        }
        Ok(dispatch_sign_request(self, request, memory))
    }
}

struct InProcessOpenPgpPublicKeyEndpoint {
    endpoint: OpaqueHandle,
    public_key: PublicKey,
}

impl OpenPgpV4Ed25519LegacyPublicKeyProvider for InProcessOpenPgpPublicKeyEndpoint {
    fn primary_fingerprint(&self) -> [u8; 20] {
        *self.public_key.fingerprint().as_bytes()
    }

    fn describe_primary_public_key(
        &mut self,
        expected_primary_fingerprint: &[u8; 20],
        output: &mut [u8],
    ) -> Result<usize, DescribePublicKeyError> {
        if expected_primary_fingerprint != self.public_key.fingerprint().as_bytes() {
            return Err(DescribePublicKeyError::FingerprintMismatch);
        }
        self.public_key.encode_ascii(output).map_err(|error| {
            if error == OpenPgpError::OutputTooSmall {
                DescribePublicKeyError::OutputTooSmall
            } else {
                DescribePublicKeyError::KeyUnavailable
            }
        })
    }
}

impl PublicKeyDescriptionServiceEndpoint for InProcessOpenPgpPublicKeyEndpoint {
    fn invoke_describe_public_key(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; mrml_interface_detached_signing_v1::DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<
        [u8; mrml_interface_detached_signing_v1::DESCRIBE_PUBLIC_KEY_RESPONSE_BYTES],
        ProtocolError,
    > {
        if endpoint != self.endpoint {
            return Ok(
                mrml_interface_detached_signing_v1::encode_describe_public_key_response(Err(
                    DescribePublicKeyError::StaleKey,
                )),
            );
        }
        Ok(dispatch_describe_public_key_request(self, request, memory))
    }
}

pub fn sign_git_payload_via_interface<C: FnMut() -> Option<u64>>(
    key: SigningKey,
    purpose: OpenPgpGitSigningPurpose,
    digest_algorithm: OpenPgpDigestAlgorithm,
    key_not_after: Option<u64>,
    key_revoked: bool,
    input: &[u8],
    trusted_time: C,
) -> Result<Vector<u8>, OpenPgpServiceError> {
    let fingerprint = *key.public_key().fingerprint().as_bytes();
    if input.is_empty()
        || input.len() > mrml_openpgp::MAX_OPENPGP_PAYLOAD_BYTES
        || key_not_after
            .is_some_and(|not_after| not_after <= u64::from(key.public_key().created_at()))
    {
        return Err(
            if input.is_empty() || input.len() > mrml_openpgp::MAX_OPENPGP_PAYLOAD_BYTES {
                OpenPgpServiceError::InputTooLarge
            } else {
                OpenPgpServiceError::InvalidPolicy
            },
        );
    }
    let fingerprint_length = OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES as usize;
    let output_length = MAX_DETACHED_SIGNATURE_BYTES as usize;
    let output_offset = fingerprint_length
        .checked_add(input.len())
        .ok_or(OpenPgpServiceError::InputTooLarge)?;
    let memory_length = output_offset
        .checked_add(output_length)
        .ok_or(OpenPgpServiceError::InputTooLarge)?;
    let mut memory = Vector::new();
    memory.resize(memory_length, 0);
    memory[..fingerprint_length].copy_from_slice(&fingerprint);
    memory[fingerprint_length..output_offset].copy_from_slice(input);

    let fingerprint_view = BorrowedReadView::within(0, 20, memory_length as u64)
        .ok_or(OpenPgpServiceError::Protocol)?;
    let input_view = BorrowedReadView::within(
        fingerprint_length as u64,
        input.len() as u64,
        memory_length as u64,
    )
    .ok_or(OpenPgpServiceError::Protocol)?;
    let output_view = BorrowedWriteView::within(
        output_offset as u64,
        output_length as u64,
        memory_length as u64,
    )
    .ok_or(OpenPgpServiceError::Protocol)?;
    let request = encode_sign_request(
        OpenPgpSignatureProfile::V4Ed25519LegacyBinaryDocumentAsciiArmor,
        purpose,
        digest_algorithm,
        fingerprint_view,
        input_view,
        output_view,
    )
    .map_err(|_| OpenPgpServiceError::Protocol)?;
    let endpoint = OpaqueHandle::new(1, 1).expect("fixed signing endpoint generation");
    let service = InProcessOpenPgpSigningEndpoint {
        endpoint,
        key,
        allowed_purpose_mask: purpose.mask(),
        allowed_digest_mask: digest_algorithm.mask(),
        key_not_after,
        key_revoked,
        trusted_time,
    };
    let mut transport = IsolatedDetachedSigningTransport::new(
        endpoint,
        fingerprint,
        purpose.mask(),
        digest_algorithm.mask(),
        memory_length,
        service,
    )
    .map_err(|_| OpenPgpServiceError::Protocol)?;
    let response = transport
        .sign(&request, &mut memory)
        .map_err(|_| OpenPgpServiceError::Protocol)?;
    let written = decode_sign_response(&response, output_length as u64)
        .map_err(|_| OpenPgpServiceError::Protocol)?
        .map_err(OpenPgpServiceError::Signing)? as usize;
    let mut signature = Vector::new();
    signature.extend(
        memory[output_offset..output_offset + written]
            .iter()
            .copied(),
    );
    Ok(signature)
}

pub fn describe_public_key_via_interface(
    public_key: PublicKey,
) -> Result<Vector<u8>, OpenPgpServiceError> {
    let fingerprint = *public_key.fingerprint().as_bytes();
    let fingerprint_length = OPENPGP_V4_PRIMARY_FINGERPRINT_BYTES as usize;
    let output_length = MAX_PUBLIC_KEY_DESCRIPTION_BYTES as usize;
    let memory_length = fingerprint_length + output_length;
    let mut memory = Vector::new();
    memory.resize(memory_length, 0);
    memory[..fingerprint_length].copy_from_slice(&fingerprint);
    let fingerprint_view = BorrowedReadView::within(0, 20, memory_length as u64)
        .ok_or(OpenPgpServiceError::Protocol)?;
    let output_view = BorrowedWriteView::within(
        fingerprint_length as u64,
        output_length as u64,
        memory_length as u64,
    )
    .ok_or(OpenPgpServiceError::Protocol)?;
    let request = encode_describe_public_key_request(
        OpenPgpPublicKeyDescriptionFormat::V4Ed25519LegacyPrimaryKeyAsciiArmor,
        fingerprint_view,
        output_view,
    )
    .map_err(|_| OpenPgpServiceError::Protocol)?;
    let endpoint = OpaqueHandle::new(2, 1).expect("fixed public-key endpoint generation");
    let service = InProcessOpenPgpPublicKeyEndpoint {
        endpoint,
        public_key,
    };
    let mut transport =
        IsolatedPublicKeyDescriptionTransport::new(endpoint, fingerprint, memory_length, service)
            .map_err(|_| OpenPgpServiceError::Protocol)?;
    let response = transport
        .describe_public_key(&request, &mut memory)
        .map_err(|_| OpenPgpServiceError::Protocol)?;
    let written = mrml_interface_detached_signing_v1::decode_describe_public_key_response(
        &response,
        output_length as u64,
    )
    .map_err(|_| OpenPgpServiceError::Protocol)?
    .map_err(OpenPgpServiceError::PublicKey)? as usize;
    let mut description = Vector::new();
    description.extend(
        memory[fingerprint_length..fingerprint_length + written]
            .iter()
            .copied(),
    );
    Ok(description)
}

fn valid_git_payload(purpose: OpenPgpGitSigningPurpose, input: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(input) else {
        return false;
    };
    let Some((headers, message)) = text.split_once("\n\n") else {
        return false;
    };
    if headers.bytes().any(|byte| matches!(byte, b'\0' | b'\r')) || !valid_message(message) {
        return false;
    }
    match purpose {
        OpenPgpGitSigningPurpose::GitCommit => valid_commit_headers(headers),
        OpenPgpGitSigningPurpose::GitAnnotatedTag => valid_tag_headers(headers),
    }
}

fn valid_commit_headers(headers: &str) -> bool {
    let mut lines = headers.lines().peekable();
    let Some(object_id_width) = lines
        .next()
        .and_then(|line| line.strip_prefix("tree "))
        .and_then(object_id_width)
    else {
        return false;
    };
    while lines.peek().is_some_and(|line| line.starts_with("parent ")) {
        if !lines
            .next()
            .and_then(|line| line.strip_prefix("parent "))
            .is_some_and(|value| valid_object_id(value, object_id_width))
        {
            return false;
        }
    }
    lines
        .next()
        .is_some_and(|line| valid_person_header(line, "author "))
        && lines
            .next()
            .is_some_and(|line| valid_person_header(line, "committer "))
        && lines.next().is_none()
}

fn valid_tag_headers(headers: &str) -> bool {
    let mut lines = headers.lines();
    lines
        .next()
        .and_then(|line| line.strip_prefix("object "))
        .and_then(object_id_width)
        .is_some()
        && lines.next() == Some("type commit")
        && lines
            .next()
            .and_then(|line| line.strip_prefix("tag "))
            .is_some_and(|tag| {
                !tag.is_empty() && !tag.bytes().any(|byte| byte.is_ascii_whitespace())
            })
        && lines
            .next()
            .is_some_and(|line| valid_person_header(line, "tagger "))
        && lines.next().is_none()
}

fn valid_person_header(line: &str, prefix: &str) -> bool {
    line.strip_prefix(prefix).is_some_and(|value| {
        let Some((identity_and_timestamp, timezone)) = value.rsplit_once(' ') else {
            return false;
        };
        let Some((identity, timestamp)) = identity_and_timestamp.rsplit_once(' ') else {
            return false;
        };
        let Some(identity) = identity.strip_suffix('>') else {
            return false;
        };
        let Some((name, email)) = identity.rsplit_once(" <") else {
            return false;
        };
        valid_identity_component(name, true)
            && valid_identity_component(email, false)
            && valid_timestamp(timestamp)
            && valid_timezone(timezone)
    })
}

fn object_id_width(value: &str) -> Option<usize> {
    let width = value.len();
    if matches!(width, 40 | 64) && valid_object_id(value, width) {
        Some(width)
    } else {
        None
    }
}

fn valid_object_id(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_identity_component(value: &str, permits_space: bool) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && !value.contains(['<', '>'])
        && !value.chars().any(char::is_control)
        && (permits_space || !value.chars().any(char::is_whitespace))
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn valid_timezone(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || !matches!(bytes[0], b'+' | b'-')
        || !bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let hours = (bytes[1] - b'0') * 10 + bytes[2] - b'0';
    let minutes = (bytes[3] - b'0') * 10 + bytes[4] - b'0';
    minutes < 60 && (hours < 14 || (hours == 14 && minutes == 0))
}

fn valid_message(message: &str) -> bool {
    let Some(body) = message.strip_suffix('\n') else {
        return false;
    };
    !body.trim().is_empty()
        && body == body.trim()
        && !body.bytes().any(|byte| matches!(byte, b'\0' | b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_openpgp::{VerificationPolicy, parse_public_key_ascii, verify_detached_ascii};

    const SEED: [u8; 32] = [0x42; 32];
    const CREATED_AT: u32 = 1_700_000_000;
    const SIGNED_AT: u64 = 1_700_000_001;
    const COMMIT: &[u8] =
        b"tree 1111111111111111111111111111111111111111111111111111111111111111\n\
author MRML <mrml@example.invalid> 1700000000 +0000\n\
committer MRML <mrml@example.invalid> 1700000000 +0000\n\
\nmessage\n";
    const TAG: &[u8] = b"object 1111111111111111111111111111111111111111\n\
type commit\n\
tag v1\n\
tagger MRML <mrml@example.invalid> 1700000000 +0000\n\
\nrelease\n";

    fn key() -> SigningKey {
        SigningKey::from_seed(SEED, CREATED_AT).unwrap()
    }

    #[test]
    fn interface_signs_and_independent_library_verifies_each_digest() {
        for digest in [
            OpenPgpDigestAlgorithm::Sha256,
            OpenPgpDigestAlgorithm::Sha384,
            OpenPgpDigestAlgorithm::Sha512,
        ] {
            let public = key().public_key();
            let signature = sign_git_payload_via_interface(
                key(),
                OpenPgpGitSigningPurpose::GitCommit,
                digest,
                Some(SIGNED_AT + 1),
                false,
                COMMIT,
                || Some(SIGNED_AT),
            )
            .unwrap();
            let mut scratch = [0; 1024];
            assert!(
                verify_detached_ascii(
                    &public,
                    COMMIT,
                    &signature,
                    &VerificationPolicy {
                        expected_primary_fingerprint: public.fingerprint(),
                        validation_time: Some(SIGNED_AT),
                        key_not_after: Some(SIGNED_AT + 1),
                        key_revoked: false,
                        enforce_signature_expiration: true,
                    },
                    &mut scratch,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn purpose_payload_and_owner_policy_fail_closed() {
        assert_eq!(
            sign_git_payload_via_interface(
                key(),
                OpenPgpGitSigningPurpose::GitAnnotatedTag,
                OpenPgpDigestAlgorithm::Sha512,
                None,
                false,
                COMMIT,
                || Some(SIGNED_AT),
            ),
            Err(OpenPgpServiceError::Signing(SignError::InvalidRequest))
        );
        assert_eq!(
            sign_git_payload_via_interface(
                key(),
                OpenPgpGitSigningPurpose::GitCommit,
                OpenPgpDigestAlgorithm::Sha512,
                None,
                true,
                COMMIT,
                || Some(SIGNED_AT),
            ),
            Err(OpenPgpServiceError::Signing(SignError::PermissionDenied))
        );
        assert_eq!(
            sign_git_payload_via_interface(
                key(),
                OpenPgpGitSigningPurpose::GitCommit,
                OpenPgpDigestAlgorithm::Sha512,
                Some(SIGNED_AT),
                false,
                COMMIT,
                || Some(SIGNED_AT),
            ),
            Err(OpenPgpServiceError::Signing(SignError::PermissionDenied))
        );
        assert!(
            sign_git_payload_via_interface(
                key(),
                OpenPgpGitSigningPurpose::GitAnnotatedTag,
                OpenPgpDigestAlgorithm::Sha512,
                None,
                false,
                TAG,
                || Some(SIGNED_AT),
            )
            .is_ok()
        );
    }

    #[test]
    fn public_description_crosses_the_distinct_interface_route() {
        let public = key().public_key();
        let description = describe_public_key_via_interface(public).unwrap();
        let mut scratch = [0; 1024];
        let reparsed = parse_public_key_ascii(&description, &mut scratch).unwrap();
        assert_eq!(reparsed.fingerprint(), public.fingerprint());
    }

    #[test]
    fn canonical_git_payload_profiles_are_narrow() {
        assert!(valid_git_payload(
            OpenPgpGitSigningPurpose::GitCommit,
            COMMIT
        ));
        assert!(valid_git_payload(
            OpenPgpGitSigningPurpose::GitAnnotatedTag,
            TAG
        ));
        assert!(!valid_git_payload(
            OpenPgpGitSigningPurpose::GitCommit,
            b"arbitrary\n\nbytes"
        ));
    }

    #[test]
    fn payload_profile_rejects_mixed_noncanonical_or_zero_object_ids() {
        assert!(!valid_git_payload(
            OpenPgpGitSigningPurpose::GitCommit,
            b"tree 1111111111111111111111111111111111111111111111111111111111111111\n\
parent 2222222222222222222222222222222222222222\n\
author MRML <mrml@example.invalid> 1700000000 +0000\n\
committer MRML <mrml@example.invalid> 1700000000 +0000\n\
\nmessage\n"
        ));
        assert!(!valid_git_payload(
            OpenPgpGitSigningPurpose::GitCommit,
            b"tree A111111111111111111111111111111111111111\n\
author MRML <mrml@example.invalid> 1700000000 +0000\n\
committer MRML <mrml@example.invalid> 1700000000 +0000\n\
\nmessage\n"
        ));
        assert!(!valid_git_payload(
            OpenPgpGitSigningPurpose::GitAnnotatedTag,
            b"object 0000000000000000000000000000000000000000\n\
type commit\n\
tag v1\n\
tagger MRML <mrml@example.invalid> 1700000000 +0000\n\
\nrelease\n"
        ));
    }

    #[test]
    fn payload_profile_rejects_malformed_identity_time_and_timezone() {
        for author in [
            "MRML <mrml@example.invalid> trailing 1700000000 +0000",
            "MRML <mrml@example.invalid>  +0000",
            "MRML <mrml@example.invalid> 18446744073709551616 +0000",
            "MRML <mrml@example.invalid> 1700000000 +1360",
            "MRML <mrml@example.invalid> 1700000000 +1460",
            "MRML <mrml@example.invalid> 1700000000 +1401",
            "MRML <mrml@example.invalid> 1700000000 +1500",
            "MRML <mrml @example.invalid> 1700000000 +0000",
            " MRML <mrml@example.invalid> 1700000000 +0000",
        ] {
            assert!(!valid_person_header(
                &mrml_runtime::mrml_format!("author {author}"),
                "author "
            ));
        }
        assert!(valid_person_header(
            "author MRML User <mrml@example.invalid> 0 -0330",
            "author "
        ));
        assert!(valid_person_header(
            "author MRML User <mrml@example.invalid> 1700000000 +1400",
            "author "
        ));
    }

    #[test]
    fn payload_profile_rejects_noncanonical_messages() {
        const PREFIX: &[u8] = b"tree 1111111111111111111111111111111111111111\n\
author MRML <mrml@example.invalid> 1700000000 +0000\n\
committer MRML <mrml@example.invalid> 1700000000 +0000\n\n";
        for message in [
            &b""[..],
            &b"message"[..],
            &b"message\r\n"[..],
            &b"message\0\n"[..],
            &b" \n"[..],
            &b"message\n\n"[..],
        ] {
            let mut payload = Vector::new();
            payload.extend(PREFIX.iter().copied());
            payload.extend(message.iter().copied());
            assert!(!valid_git_payload(
                OpenPgpGitSigningPurpose::GitCommit,
                &payload
            ));
        }
    }
}
