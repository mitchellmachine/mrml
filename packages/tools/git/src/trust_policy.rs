//! Canonical policy binding for `MRML-GIT-HYBRID-V1`.
//!
//! This module deliberately does not parse repository configuration.  A caller
//! must supply an already-authorized exact key pair and exact policy
//! generations.  Successful verification is represented by a type whose fields
//! cannot be constructed outside this module.

use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, Sha3_512, ml_dsa_65_verify};
use mrml_openpgp::{FingerprintV6, PublicKeyV6, VerificationPolicyV6, verify_detached_v6_ascii};
use mrml_runtime::Vector;

use crate::{
    ObjectFormat, RepositoryIdentity, RevocationGeneration, SignaturePurpose, TrustGeneration,
};

pub const HYBRID_PROFILE_NAME: &str = "MRML-GIT-HYBRID-V1";
pub const MAX_HYBRID_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
const DOMAIN: &[u8] = b"MRML-GIT-HYBRID-V1\0";
const ML_DSA_CONTEXT: &[u8] = b"mrml.git.hybrid.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitObjectType {
    Commit,
    AnnotatedTag,
    SourceManifest,
    SourceLock,
    BuildReceipt,
    KeyRotation,
    KeyRevocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridPolicyError {
    InvalidPurpose,
    InputTooLarge,
    PolicyGenerationMismatch,
    RevocationGenerationMismatch,
    OpenPgpKeyMismatch,
    MlDsaKeyMismatch,
    OpenPgpVerification,
    MlDsaVerification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedHybridPair {
    openpgp_fingerprint: FingerprintV6,
    openpgp_key_digest: [u8; 64],
    ml_dsa_key_digest: [u8; 64],
}

impl AuthorizedHybridPair {
    pub fn bind(openpgp: &PublicKeyV6, ml_dsa: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES]) -> Self {
        Self {
            openpgp_fingerprint: openpgp.fingerprint(),
            openpgp_key_digest: openpgp_key_digest(openpgp),
            ml_dsa_key_digest: Sha3_512::digest(ml_dsa),
        }
    }

    pub const fn openpgp_fingerprint(&self) -> FingerprintV6 {
        self.openpgp_fingerprint
    }

    pub const fn openpgp_key_digest(&self) -> &[u8; 64] {
        &self.openpgp_key_digest
    }

    pub const fn ml_dsa_key_digest(&self) -> &[u8; 64] {
        &self.ml_dsa_key_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridTrustPolicy {
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub authorized_pair: AuthorizedHybridPair,
    pub validation_time: Option<u64>,
    pub openpgp_not_after: Option<u64>,
    pub enforce_signature_expiration: bool,
}

pub struct HybridVerificationRequest<'a> {
    pub repository: &'a RepositoryIdentity,
    pub object_format: ObjectFormat,
    pub object_type: GitObjectType,
    pub purpose: SignaturePurpose,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub payload: &'a [u8],
    pub openpgp_signature: &'a [u8],
    pub ml_dsa_signature: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedHybridSignature {
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    pair: AuthorizedHybridPair,
}

impl VerifiedHybridSignature {
    pub const fn trust_generation(&self) -> TrustGeneration {
        self.trust_generation
    }

    pub const fn revocation_generation(&self) -> RevocationGeneration {
        self.revocation_generation
    }

    pub const fn pair(&self) -> AuthorizedHybridPair {
        self.pair
    }
}

pub fn canonical_hybrid_transcript(
    repository: &RepositoryIdentity,
    object_format: ObjectFormat,
    object_type: GitObjectType,
    purpose: SignaturePurpose,
    generation: TrustGeneration,
    pair: AuthorizedHybridPair,
    payload: &[u8],
) -> Result<Vector<u8>, HybridPolicyError> {
    if payload.len() > MAX_HYBRID_PAYLOAD_BYTES {
        return Err(HybridPolicyError::InputTooLarge);
    }
    if !purpose_matches_type(purpose, object_type) {
        return Err(HybridPolicyError::InvalidPurpose);
    }
    let repository_len =
        u16::try_from(repository.as_str().len()).map_err(|_| HybridPolicyError::InputTooLarge)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| HybridPolicyError::InputTooLarge)?;
    let capacity = DOMAIN
        .len()
        .checked_add(1 + 2 + repository.as_str().len() + 1 + 1 + 8 + 32 + 64 + 64 + 8)
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(HybridPolicyError::InputTooLarge)?;
    let mut output =
        Vector::with_capacity(capacity).map_err(|_| HybridPolicyError::InputTooLarge)?;
    append(&mut output, DOMAIN)?;
    output.push(purpose_code(purpose));
    append(&mut output, &repository_len.to_be_bytes())?;
    append(&mut output, repository.as_str().as_bytes())?;
    output.push(match object_format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    });
    output.push(object_type_code(object_type));
    append(&mut output, &generation.0.to_be_bytes())?;
    append(&mut output, pair.openpgp_fingerprint.as_bytes())?;
    append(&mut output, &pair.openpgp_key_digest)?;
    append(&mut output, &pair.ml_dsa_key_digest)?;
    append(&mut output, &payload_len.to_be_bytes())?;
    append(&mut output, payload)?;
    Ok(output)
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), HybridPolicyError> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| HybridPolicyError::InputTooLarge)
}

pub fn verify_hybrid_signature(
    policy: &HybridTrustPolicy,
    openpgp_key: &PublicKeyV6,
    ml_dsa_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    request: &HybridVerificationRequest<'_>,
    openpgp_scratch: &mut [u8],
) -> Result<VerifiedHybridSignature, HybridPolicyError> {
    if request.trust_generation != policy.trust_generation {
        return Err(HybridPolicyError::PolicyGenerationMismatch);
    }
    if request.revocation_generation != policy.revocation_generation {
        return Err(HybridPolicyError::RevocationGenerationMismatch);
    }
    let actual_pair = AuthorizedHybridPair::bind(openpgp_key, ml_dsa_key);
    if actual_pair.openpgp_fingerprint != policy.authorized_pair.openpgp_fingerprint
        || actual_pair.openpgp_key_digest != policy.authorized_pair.openpgp_key_digest
    {
        return Err(HybridPolicyError::OpenPgpKeyMismatch);
    }
    if actual_pair.ml_dsa_key_digest != policy.authorized_pair.ml_dsa_key_digest {
        return Err(HybridPolicyError::MlDsaKeyMismatch);
    }
    let transcript = canonical_hybrid_transcript(
        request.repository,
        request.object_format,
        request.object_type,
        request.purpose,
        request.trust_generation,
        actual_pair,
        request.payload,
    )?;
    verify_detached_v6_ascii(
        openpgp_key,
        &transcript,
        request.openpgp_signature,
        &VerificationPolicyV6 {
            expected_primary_fingerprint: actual_pair.openpgp_fingerprint,
            validation_time: policy.validation_time,
            key_not_after: policy.openpgp_not_after,
            key_revoked: false,
            enforce_signature_expiration: policy.enforce_signature_expiration,
        },
        openpgp_scratch,
    )
    .map_err(|_| HybridPolicyError::OpenPgpVerification)?;
    ml_dsa_65_verify(
        ml_dsa_key,
        ML_DSA_CONTEXT,
        &transcript,
        request.ml_dsa_signature,
    )
    .map_err(|_| HybridPolicyError::MlDsaVerification)?;
    Ok(VerifiedHybridSignature {
        trust_generation: policy.trust_generation,
        revocation_generation: policy.revocation_generation,
        pair: actual_pair,
    })
}

fn openpgp_key_digest(key: &PublicKeyV6) -> [u8; 64] {
    let mut canonical = [0u8; 42];
    canonical[0] = 6;
    canonical[1..5].copy_from_slice(&key.created_at().to_be_bytes());
    canonical[5] = 27;
    canonical[6..10].copy_from_slice(&32u32.to_be_bytes());
    canonical[10..].copy_from_slice(key.public_bytes());
    Sha3_512::digest(&canonical)
}

const fn purpose_matches_type(purpose: SignaturePurpose, object_type: GitObjectType) -> bool {
    matches!(
        (purpose, object_type),
        (SignaturePurpose::GitCommit, GitObjectType::Commit)
            | (
                SignaturePurpose::GitAnnotatedTag,
                GitObjectType::AnnotatedTag
            )
            | (
                SignaturePurpose::SourceManifest,
                GitObjectType::SourceManifest
            )
            | (SignaturePurpose::SourceLock, GitObjectType::SourceLock)
            | (SignaturePurpose::BuildReceipt, GitObjectType::BuildReceipt)
            | (SignaturePurpose::KeyRotation, GitObjectType::KeyRotation)
            | (
                SignaturePurpose::KeyRevocation,
                GitObjectType::KeyRevocation
            )
    )
}

const fn purpose_code(purpose: SignaturePurpose) -> u8 {
    match purpose {
        SignaturePurpose::GitCommit => 1,
        SignaturePurpose::GitAnnotatedTag => 2,
        SignaturePurpose::SourceManifest => 3,
        SignaturePurpose::SourceLock => 4,
        SignaturePurpose::BuildReceipt => 5,
        SignaturePurpose::KeyRotation => 6,
        SignaturePurpose::KeyRevocation => 7,
    }
}

const fn object_type_code(object_type: GitObjectType) -> u8 {
    match object_type {
        GitObjectType::Commit => 1,
        GitObjectType::AnnotatedTag => 2,
        GitObjectType::SourceManifest => 3,
        GitObjectType::SourceLock => 4,
        GitObjectType::BuildReceipt => 5,
        GitObjectType::KeyRotation => 6,
        GitObjectType::KeyRevocation => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{ML_DSA_65_SECRET_KEY_BYTES, ml_dsa_65_keygen, ml_dsa_65_sign};
    use mrml_openpgp::{DigestAlgorithm, SigningKeyV6, sign_detached_v6_ascii_with_salt};

    #[test]
    fn exact_pair_and_all_context_fields_are_required() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let openpgp = SigningKeyV6::from_seed([7u8; 32], 1_700_000_000).unwrap();
        let mut ml_public = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0u8; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9u8; 32], &mut ml_public, &mut ml_secret).unwrap();
        let pair = AuthorizedHybridPair::bind(&openpgp.public_key(), &ml_public);
        let transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::Commit,
            SignaturePurpose::GitCommit,
            TrustGeneration(4),
            pair,
            b"canonical commit payload",
        )
        .unwrap();
        let mut openpgp_signature = [0u8; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
        let openpgp_len = sign_detached_v6_ascii_with_salt(
            &openpgp,
            &transcript,
            DigestAlgorithm::Sha512,
            1_700_000_001,
            &[11u8; 32],
            &mut openpgp_signature,
        )
        .unwrap();
        let mut ml_signature = [0u8; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &ml_secret,
            ML_DSA_CONTEXT,
            &transcript,
            &[13u8; 32],
            &mut ml_signature,
        )
        .unwrap();
        let policy = HybridTrustPolicy {
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            authorized_pair: pair,
            validation_time: Some(1_700_000_002),
            openpgp_not_after: None,
            enforce_signature_expiration: true,
        };
        let request = HybridVerificationRequest {
            repository: &repository,
            object_format: ObjectFormat::Sha256,
            object_type: GitObjectType::Commit,
            purpose: SignaturePurpose::GitCommit,
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            payload: b"canonical commit payload",
            openpgp_signature: &openpgp_signature[..openpgp_len],
            ml_dsa_signature: &ml_signature,
        };
        let mut scratch = [0u8; mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES];
        verify_hybrid_signature(
            &policy,
            &openpgp.public_key(),
            &ml_public,
            &request,
            &mut scratch,
        )
        .unwrap();

        let wrong_repository = RepositoryIdentity::parse("owner/other").unwrap();
        let wrong = HybridVerificationRequest {
            repository: &wrong_repository,
            ..request
        };
        assert_eq!(
            verify_hybrid_signature(
                &policy,
                &openpgp.public_key(),
                &ml_public,
                &wrong,
                &mut scratch,
            ),
            Err(HybridPolicyError::OpenPgpVerification)
        );
    }

    #[test]
    fn purpose_mismatch_and_conventional_only_fail_closed() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([1u8; 32]),
            openpgp_key_digest: [2u8; 64],
            ml_dsa_key_digest: [3u8; 64],
        };
        assert_eq!(
            canonical_hybrid_transcript(
                &repository,
                ObjectFormat::Sha256,
                GitObjectType::Commit,
                SignaturePurpose::GitAnnotatedTag,
                TrustGeneration(1),
                pair,
                b"payload",
            ),
            Err(HybridPolicyError::InvalidPurpose)
        );

        let transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::Commit,
            SignaturePurpose::GitCommit,
            TrustGeneration(4),
            AuthorizedHybridPair {
                openpgp_fingerprint: FingerprintV6::from_bytes([0u8; 32]),
                openpgp_key_digest: [0u8; 64],
                ml_dsa_key_digest: [0u8; 64],
            },
            b"payload",
        )
        .unwrap();
        assert_eq!(transcript.len(), 223);
        assert_eq!(
            Sha3_512::digest(&transcript),
            [
                0x99, 0xac, 0xd2, 0x26, 0xd5, 0xb4, 0x9f, 0x39, 0x12, 0x65, 0xc3, 0x14, 0x3c, 0x2c,
                0x9f, 0x7d, 0xf4, 0xa1, 0x13, 0xa4, 0xdd, 0xe7, 0x7e, 0x23, 0x4d, 0xd5, 0xd9, 0x69,
                0x32, 0x82, 0x6d, 0x71, 0x01, 0x7e, 0x02, 0xe8, 0xfd, 0x17, 0x0f, 0xf1, 0x8a, 0xee,
                0x33, 0x8b, 0x29, 0x39, 0xd1, 0xb6, 0xd3, 0x0e, 0xb8, 0xc2, 0xdc, 0xe8, 0x0c, 0x6a,
                0xb3, 0x39, 0xbf, 0xf4, 0xef, 0x7a, 0x1b, 0x48,
            ]
        );
    }
}
