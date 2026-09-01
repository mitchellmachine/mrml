//! Canonical policy binding for `MRML-GIT-HYBRID-V1`.
//!
//! This module deliberately does not parse repository configuration.  A caller
//! must supply an already-authorized exact key pair and exact policy
//! generations.  Successful verification is represented by a type whose fields
//! cannot be constructed outside this module.

use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, Sha3_512, ml_dsa_65_verify};
use mrml_openpgp::{
    DigestAlgorithmSet, FingerprintV6, PublicKeyV6, VerificationPolicyV6, verify_detached_v6_ascii,
};
use mrml_runtime::Vector;

use crate::{
    FullRefName, ObjectFormat, ObjectId, RepositoryIdentity, RevocationGeneration,
    SignaturePurpose, TrustGeneration,
    verification::{ProtectedHistoryContext, VerifiedCommitProof},
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
    InvalidPolicy,
    PolicyRollback,
    PreviousPolicyMismatch,
    TrustRootBroadened,
    RevocationRollback,
    RevokedKeyReactivated,
    HybridDowngrade,
    MissingPreviousAuthorization,
    MissingNewAuthorization,
    CutoverRollback,
    EmergencyPolicyChanged,
    KeyOutsideValidity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedHybridPair {
    openpgp_fingerprint: FingerprintV6,
    openpgp_key_digest: [u8; 64],
    ml_dsa_key_digest: [u8; 64],
}

/// Exact pair identity and its bounded authorization lifetime. `valid_until`
/// is exclusive. Retirement may shorten authority but never extend it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyPairStatus {
    pair: AuthorizedHybridPair,
    valid_from: u64,
    valid_until: u64,
    retired_at: Option<u64>,
}

impl PolicyPairStatus {
    pub fn new(
        pair: AuthorizedHybridPair,
        valid_from: u64,
        valid_until: u64,
        retired_at: Option<u64>,
    ) -> Result<Self, HybridPolicyError> {
        if valid_from >= valid_until || retired_at.is_some_and(|retired| retired >= valid_until) {
            return Err(HybridPolicyError::InvalidPolicy);
        }
        Ok(Self {
            pair,
            valid_from,
            valid_until,
            retired_at,
        })
    }

    pub const fn pair(self) -> AuthorizedHybridPair {
        self.pair
    }
    pub const fn valid_from(self) -> u64 {
        self.valid_from
    }
    pub const fn valid_until(self) -> u64 {
        self.valid_until
    }
    pub const fn retired_at(self) -> Option<u64> {
        self.retired_at
    }

    pub const fn authorizes_at(self, time: u64) -> bool {
        time >= self.valid_from
            && time < self.valid_until
            && match self.retired_at {
                Some(retired) => time < retired,
                None => true,
            }
    }
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
    repository_digest: [u8; 64],
    payload_digest: [u8; 64],
    purpose: SignaturePurpose,
    object_type: GitObjectType,
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

    pub const fn purpose(&self) -> SignaturePurpose {
        self.purpose
    }
}

pub const MAX_POLICY_PAIRS: usize = 64;
pub const MAX_POLICY_REVOKED_KEYS: usize = 256;
pub const MAX_POLICY_PROTECTED_REFS: usize = 256;
pub const MAX_ENCODED_TRUST_POLICY_BYTES: usize = 512 * 1024;
pub const MAX_KEY_REVOCATION_STATEMENT_BYTES: usize = 64 * 1024;
pub const MAX_KEY_REVOCATION_REASON_BYTES: usize = 512;
const POLICY_MAGIC: &[u8; 8] = b"MRMLGTP2";
const REVOCATION_MAGIC: &[u8; 8] = b"MRGREV01";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRevocationStatement {
    repository: RepositoryIdentity,
    previous_generation: RevocationGeneration,
    next_generation: RevocationGeneration,
    effective_at: u64,
    reason: Vector<u8>,
    openpgp: Vector<FingerprintV6>,
    ml_dsa: Vector<[u8; 64]>,
}

impl KeyRevocationStatement {
    pub fn new(
        repository: RepositoryIdentity,
        previous_generation: RevocationGeneration,
        next_generation: RevocationGeneration,
        effective_at: u64,
        reason: Vector<u8>,
        openpgp: Vector<FingerprintV6>,
        ml_dsa: Vector<[u8; 64]>,
    ) -> Result<Self, HybridPolicyError> {
        let statement = Self {
            repository,
            previous_generation,
            next_generation,
            effective_at,
            reason,
            openpgp,
            ml_dsa,
        };
        validate_revocation_statement(&statement)?;
        Ok(statement)
    }

    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }
    pub const fn previous_generation(&self) -> RevocationGeneration {
        self.previous_generation
    }
    pub const fn next_generation(&self) -> RevocationGeneration {
        self.next_generation
    }
    pub const fn effective_at(&self) -> u64 {
        self.effective_at
    }
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }
    pub fn openpgp(&self) -> &[FingerprintV6] {
        &self.openpgp
    }
    pub fn ml_dsa(&self) -> &[[u8; 64]] {
        &self.ml_dsa
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPolicyState {
    repository: RepositoryIdentity,
    generation: TrustGeneration,
    previous_policy_digest: [u8; 64],
    revocation_generation: RevocationGeneration,
    protected_refs: Vector<FullRefName>,
    allowed_object_formats: u8,
    hybrid_required: bool,
    legacy_checkpoint: Option<ObjectId>,
    hybrid_cutover: Option<ObjectId>,
    emergency_policy_digest: Option<[u8; 64]>,
    active_pairs: Vector<AuthorizedHybridPair>,
    pair_statuses: Vector<PolicyPairStatus>,
    revoked_openpgp: Vector<FingerprintV6>,
    revoked_ml_dsa: Vector<[u8; 64]>,
}

pub struct TrustPolicyCandidate {
    pub repository: RepositoryIdentity,
    pub generation: TrustGeneration,
    pub previous_policy_digest: [u8; 64],
    pub revocation_generation: RevocationGeneration,
    pub protected_refs: Vector<FullRefName>,
    pub allow_sha1: bool,
    pub allow_sha256: bool,
    pub hybrid_required: bool,
    pub legacy_checkpoint: Option<ObjectId>,
    pub hybrid_cutover: Option<ObjectId>,
    pub emergency_policy_digest: Option<[u8; 64]>,
    pub active_pairs: Vector<AuthorizedHybridPair>,
    pub pair_statuses: Vector<PolicyPairStatus>,
    pub revoked_openpgp: Vector<FingerprintV6>,
    pub revoked_ml_dsa: Vector<[u8; 64]>,
}

pub fn encode_trust_policy(policy: &TrustPolicyState) -> Result<Vector<u8>, HybridPolicyError> {
    let mut output = Vector::with_capacity(512).map_err(|_| HybridPolicyError::InputTooLarge)?;
    append(&mut output, POLICY_MAGIC)?;
    append_counted_bytes(&mut output, policy.repository.as_str().as_bytes())?;
    append(&mut output, &policy.generation.0.to_be_bytes())?;
    append(&mut output, &policy.previous_policy_digest)?;
    append(&mut output, &policy.revocation_generation.0.to_be_bytes())?;
    output.push(policy.allowed_object_formats);
    output.push(u8::from(policy.hybrid_required));
    append_optional_object(&mut output, policy.legacy_checkpoint)?;
    append_optional_object(&mut output, policy.hybrid_cutover)?;
    match policy.emergency_policy_digest {
        Some(digest) => {
            output.push(1);
            append(&mut output, &digest)?;
        }
        None => output.push(0),
    }
    append_u16(&mut output, policy.protected_refs.len())?;
    append_u16(&mut output, policy.active_pairs.len())?;
    append_u16(&mut output, policy.pair_statuses.len())?;
    append_u16(&mut output, policy.revoked_openpgp.len())?;
    append_u16(&mut output, policy.revoked_ml_dsa.len())?;
    for reference in &policy.protected_refs {
        append_counted_bytes(&mut output, reference.as_str().as_bytes())?;
    }
    for pair in &policy.active_pairs {
        append(&mut output, pair.openpgp_fingerprint.as_bytes())?;
        append(&mut output, &pair.openpgp_key_digest)?;
        append(&mut output, &pair.ml_dsa_key_digest)?;
    }
    for status in &policy.pair_statuses {
        append_pair(&mut output, &status.pair)?;
        append(&mut output, &status.valid_from.to_be_bytes())?;
        append(&mut output, &status.valid_until.to_be_bytes())?;
        match status.retired_at {
            Some(retired) => {
                output.push(1);
                append(&mut output, &retired.to_be_bytes())?;
            }
            None => output.push(0),
        }
    }
    for fingerprint in &policy.revoked_openpgp {
        append(&mut output, fingerprint.as_bytes())?;
    }
    for digest in &policy.revoked_ml_dsa {
        append(&mut output, digest)?;
    }
    if output.len() > MAX_ENCODED_TRUST_POLICY_BYTES {
        return Err(HybridPolicyError::InputTooLarge);
    }
    Ok(output)
}

pub fn parse_trust_policy(input: &[u8]) -> Result<TrustPolicyState, HybridPolicyError> {
    if input.is_empty() || input.len() > MAX_ENCODED_TRUST_POLICY_BYTES {
        return Err(HybridPolicyError::InputTooLarge);
    }
    let mut cursor = PolicyCursor::new(input);
    if cursor.take(POLICY_MAGIC.len())? != POLICY_MAGIC {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let repository_bytes = cursor.take_counted_bytes()?;
    let repository_text =
        core::str::from_utf8(repository_bytes).map_err(|_| HybridPolicyError::InvalidPolicy)?;
    let repository =
        RepositoryIdentity::parse(repository_text).map_err(|_| HybridPolicyError::InvalidPolicy)?;
    let generation = TrustGeneration(cursor.u64()?);
    let mut previous_policy_digest = [0u8; 64];
    previous_policy_digest.copy_from_slice(cursor.take(64)?);
    let revocation_generation = RevocationGeneration(cursor.u64()?);
    let allowed_object_formats = cursor.u8()?;
    let hybrid_required = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HybridPolicyError::InvalidPolicy),
    };
    let legacy_checkpoint = cursor.optional_object()?;
    let hybrid_cutover = cursor.optional_object()?;
    let emergency_policy_digest = match cursor.u8()? {
        0 => None,
        1 => {
            let mut digest = [0u8; 64];
            digest.copy_from_slice(cursor.take(64)?);
            Some(digest)
        }
        _ => return Err(HybridPolicyError::InvalidPolicy),
    };
    let ref_count = usize::from(cursor.u16()?);
    let pair_count = usize::from(cursor.u16()?);
    let pair_status_count = usize::from(cursor.u16()?);
    let revoked_openpgp_count = usize::from(cursor.u16()?);
    let revoked_ml_dsa_count = usize::from(cursor.u16()?);
    if ref_count > MAX_POLICY_PROTECTED_REFS
        || pair_count > MAX_POLICY_PAIRS
        || pair_status_count > MAX_POLICY_PAIRS * 2
        || revoked_openpgp_count > MAX_POLICY_REVOKED_KEYS
        || revoked_ml_dsa_count > MAX_POLICY_REVOKED_KEYS
    {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let mut protected_refs =
        Vector::with_capacity(ref_count).map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..ref_count {
        let bytes = cursor.take_counted_bytes()?;
        let text = core::str::from_utf8(bytes).map_err(|_| HybridPolicyError::InvalidPolicy)?;
        protected_refs
            .push(FullRefName::parse(text).map_err(|_| HybridPolicyError::InvalidPolicy)?);
    }
    let mut active_pairs =
        Vector::with_capacity(pair_count).map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..pair_count {
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(cursor.take(32)?);
        let mut openpgp_key_digest = [0u8; 64];
        openpgp_key_digest.copy_from_slice(cursor.take(64)?);
        let mut ml_dsa_key_digest = [0u8; 64];
        ml_dsa_key_digest.copy_from_slice(cursor.take(64)?);
        active_pairs.push(AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes(fingerprint),
            openpgp_key_digest,
            ml_dsa_key_digest,
        });
    }
    let mut pair_statuses =
        Vector::with_capacity(pair_status_count).map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..pair_status_count {
        let pair = cursor.pair()?;
        let valid_from = cursor.u64()?;
        let valid_until = cursor.u64()?;
        let retired_at = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.u64()?),
            _ => return Err(HybridPolicyError::InvalidPolicy),
        };
        pair_statuses.push(PolicyPairStatus::new(
            pair,
            valid_from,
            valid_until,
            retired_at,
        )?);
    }
    let mut revoked_openpgp = Vector::with_capacity(revoked_openpgp_count)
        .map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..revoked_openpgp_count {
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(cursor.take(32)?);
        revoked_openpgp.push(FingerprintV6::from_bytes(fingerprint));
    }
    let mut revoked_ml_dsa = Vector::with_capacity(revoked_ml_dsa_count)
        .map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..revoked_ml_dsa_count {
        let mut digest = [0u8; 64];
        digest.copy_from_slice(cursor.take(64)?);
        revoked_ml_dsa.push(digest);
    }
    if !cursor.is_complete() {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let candidate = TrustPolicyCandidate {
        repository,
        generation,
        previous_policy_digest,
        revocation_generation,
        protected_refs,
        allow_sha1: allowed_object_formats & 1 != 0,
        allow_sha256: allowed_object_formats & 2 != 0,
        hybrid_required,
        legacy_checkpoint,
        hybrid_cutover,
        emergency_policy_digest,
        active_pairs,
        pair_statuses,
        revoked_openpgp,
        revoked_ml_dsa,
    };
    if allowed_object_formats & !3 != 0 {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    validate_candidate(&candidate)?;
    let policy = TrustPolicyState::from_candidate(candidate);
    if &*encode_trust_policy(&policy)? != input {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    Ok(policy)
}

pub fn encode_key_revocation_statement(
    statement: &KeyRevocationStatement,
) -> Result<Vector<u8>, HybridPolicyError> {
    validate_revocation_statement(statement)?;
    let mut output = Vector::new();
    append(&mut output, REVOCATION_MAGIC)?;
    append_counted_bytes(&mut output, statement.repository.as_str().as_bytes())?;
    append(&mut output, &statement.previous_generation.0.to_be_bytes())?;
    append(&mut output, &statement.next_generation.0.to_be_bytes())?;
    append(&mut output, &statement.effective_at.to_be_bytes())?;
    append_counted_bytes(&mut output, &statement.reason)?;
    append_u16(&mut output, statement.openpgp.len())?;
    append_u16(&mut output, statement.ml_dsa.len())?;
    for fingerprint in &statement.openpgp {
        append(&mut output, fingerprint.as_bytes())?;
    }
    for digest in &statement.ml_dsa {
        append(&mut output, digest)?;
    }
    if output.len() > MAX_KEY_REVOCATION_STATEMENT_BYTES {
        return Err(HybridPolicyError::InputTooLarge);
    }
    Ok(output)
}

pub fn parse_key_revocation_statement(
    input: &[u8],
) -> Result<KeyRevocationStatement, HybridPolicyError> {
    if input.is_empty() || input.len() > MAX_KEY_REVOCATION_STATEMENT_BYTES {
        return Err(HybridPolicyError::InputTooLarge);
    }
    let mut cursor = PolicyCursor::new(input);
    if cursor.take(REVOCATION_MAGIC.len())? != REVOCATION_MAGIC {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let repository = RepositoryIdentity::parse(
        core::str::from_utf8(cursor.take_counted_bytes()?)
            .map_err(|_| HybridPolicyError::InvalidPolicy)?,
    )
    .map_err(|_| HybridPolicyError::InvalidPolicy)?;
    let previous_generation = RevocationGeneration(cursor.u64()?);
    let next_generation = RevocationGeneration(cursor.u64()?);
    let effective_at = cursor.u64()?;
    let reason_bytes = cursor.take_counted_bytes()?;
    let mut reason = Vector::new();
    reason
        .try_extend_from_slice(reason_bytes)
        .map_err(|_| HybridPolicyError::InputTooLarge)?;
    let openpgp_count = usize::from(cursor.u16()?);
    let ml_dsa_count = usize::from(cursor.u16()?);
    if openpgp_count > MAX_POLICY_REVOKED_KEYS || ml_dsa_count > MAX_POLICY_REVOKED_KEYS {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let mut openpgp =
        Vector::with_capacity(openpgp_count).map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..openpgp_count {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(cursor.take(32)?);
        openpgp.push(FingerprintV6::from_bytes(bytes));
    }
    let mut ml_dsa =
        Vector::with_capacity(ml_dsa_count).map_err(|_| HybridPolicyError::InputTooLarge)?;
    for _ in 0..ml_dsa_count {
        let mut bytes = [0; 64];
        bytes.copy_from_slice(cursor.take(64)?);
        ml_dsa.push(bytes);
    }
    if !cursor.is_complete() {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let statement = KeyRevocationStatement::new(
        repository,
        previous_generation,
        next_generation,
        effective_at,
        reason,
        openpgp,
        ml_dsa,
    )?;
    if &*encode_key_revocation_statement(&statement)? != input {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    Ok(statement)
}

pub fn key_revocation_statement_digest(
    statement: &KeyRevocationStatement,
) -> Result<[u8; 64], HybridPolicyError> {
    Ok(Sha3_512::digest(&encode_key_revocation_statement(
        statement,
    )?))
}

fn validate_revocation_statement(
    statement: &KeyRevocationStatement,
) -> Result<(), HybridPolicyError> {
    if statement.previous_generation.0 == 0
        || statement.next_generation.0 <= statement.previous_generation.0
        || statement.effective_at == 0
        || statement.reason.is_empty()
        || statement.reason.len() > MAX_KEY_REVOCATION_REASON_BYTES
        || statement
            .reason
            .iter()
            .any(|byte| !(b' '..=b'~').contains(byte))
        || statement.openpgp.len() > MAX_POLICY_REVOKED_KEYS
        || statement.ml_dsa.len() > MAX_POLICY_REVOKED_KEYS
        || statement.openpgp.is_empty() && statement.ml_dsa.is_empty()
        || !strictly_ordered_by(&statement.openpgp, |left, right| {
            left.as_bytes() < right.as_bytes()
        })
        || !strictly_ordered_by(&statement.ml_dsa, |left, right| left < right)
    {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    Ok(())
}

fn append_u16(output: &mut Vector<u8>, value: usize) -> Result<(), HybridPolicyError> {
    let value = u16::try_from(value).map_err(|_| HybridPolicyError::InputTooLarge)?;
    append(output, &value.to_be_bytes())
}

fn append_pair(
    output: &mut Vector<u8>,
    pair: &AuthorizedHybridPair,
) -> Result<(), HybridPolicyError> {
    append(output, pair.openpgp_fingerprint.as_bytes())?;
    append(output, &pair.openpgp_key_digest)?;
    append(output, &pair.ml_dsa_key_digest)
}

fn append_counted_bytes(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), HybridPolicyError> {
    append_u16(output, bytes.len())?;
    append(output, bytes)
}

fn append_optional_object(
    output: &mut Vector<u8>,
    object: Option<ObjectId>,
) -> Result<(), HybridPolicyError> {
    match object {
        Some(object) => {
            output.push(object_format_code(object.format()));
            append(output, object.as_bytes())
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

struct PolicyCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> PolicyCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HybridPolicyError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HybridPolicyError::InvalidPolicy)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(HybridPolicyError::InvalidPolicy)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, HybridPolicyError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HybridPolicyError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| HybridPolicyError::InvalidPolicy)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, HybridPolicyError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| HybridPolicyError::InvalidPolicy)?,
        ))
    }

    fn pair(&mut self) -> Result<AuthorizedHybridPair, HybridPolicyError> {
        let mut fingerprint = [0; 32];
        fingerprint.copy_from_slice(self.take(32)?);
        let mut openpgp_key_digest = [0; 64];
        openpgp_key_digest.copy_from_slice(self.take(64)?);
        let mut ml_dsa_key_digest = [0; 64];
        ml_dsa_key_digest.copy_from_slice(self.take(64)?);
        Ok(AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes(fingerprint),
            openpgp_key_digest,
            ml_dsa_key_digest,
        })
    }

    fn take_counted_bytes(&mut self) -> Result<&'a [u8], HybridPolicyError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn optional_object(&mut self) -> Result<Option<ObjectId>, HybridPolicyError> {
        let format = match self.u8()? {
            0 => return Ok(None),
            1 => ObjectFormat::Sha1,
            2 => ObjectFormat::Sha256,
            _ => return Err(HybridPolicyError::InvalidPolicy),
        };
        ObjectId::from_bytes(format, self.take(format.hash_len())?)
            .map(Some)
            .ok_or(HybridPolicyError::InvalidPolicy)
    }

    const fn is_complete(&self) -> bool {
        self.offset == self.input.len()
    }
}

impl TrustPolicyState {
    pub fn establish(candidate: TrustPolicyCandidate) -> Result<Self, HybridPolicyError> {
        validate_candidate(&candidate)?;
        if candidate.generation.0 == 0 || candidate.previous_policy_digest != [0u8; 64] {
            return Err(HybridPolicyError::InvalidPolicy);
        }
        Ok(Self::from_candidate(candidate))
    }

    pub fn transition(
        &self,
        candidate: TrustPolicyCandidate,
        previous_authorization: &VerifiedHybridSignature,
        new_authorization: &VerifiedHybridSignature,
    ) -> Result<Self, HybridPolicyError> {
        validate_candidate(&candidate)?;
        if candidate.repository != self.repository {
            return Err(HybridPolicyError::TrustRootBroadened);
        }
        if candidate.generation.0 <= self.generation.0 {
            return Err(HybridPolicyError::PolicyRollback);
        }
        if candidate.previous_policy_digest != self.digest() {
            return Err(HybridPolicyError::PreviousPolicyMismatch);
        }
        if candidate.revocation_generation.0 < self.revocation_generation.0 {
            return Err(HybridPolicyError::RevocationRollback);
        }
        if self.hybrid_required && !candidate.hybrid_required {
            return Err(HybridPolicyError::HybridDowngrade);
        }
        if self.hybrid_cutover.is_some() && candidate.hybrid_cutover != self.hybrid_cutover {
            return Err(HybridPolicyError::CutoverRollback);
        }
        if candidate.legacy_checkpoint != self.legacy_checkpoint {
            return Err(HybridPolicyError::CutoverRollback);
        }
        if candidate.emergency_policy_digest != self.emergency_policy_digest {
            return Err(HybridPolicyError::EmergencyPolicyChanged);
        }
        if candidate.allowed_format_mask() & !self.allowed_object_formats != 0
            || self
                .protected_refs
                .iter()
                .any(|reference| !candidate.protected_refs.contains(reference))
        {
            return Err(HybridPolicyError::TrustRootBroadened);
        }
        if self
            .revoked_openpgp
            .iter()
            .any(|key| !candidate.revoked_openpgp.contains(key))
            || self
                .revoked_ml_dsa
                .iter()
                .any(|key| !candidate.revoked_ml_dsa.contains(key))
        {
            return Err(HybridPolicyError::RevocationRollback);
        }
        for previous in &self.pair_statuses {
            let Some(next) = candidate
                .pair_statuses
                .iter()
                .find(|status| status.pair == previous.pair)
            else {
                return Err(HybridPolicyError::PolicyRollback);
            };
            if next.valid_from != previous.valid_from
                || next.valid_until > previous.valid_until
                || match (previous.retired_at, next.retired_at) {
                    (Some(old), Some(new)) => new > old,
                    (Some(_), None) => true,
                    _ => false,
                }
            {
                return Err(HybridPolicyError::PolicyRollback);
            }
        }
        if candidate.active_pairs.iter().any(|pair| {
            candidate
                .revoked_openpgp
                .contains(&pair.openpgp_fingerprint)
                || candidate.revoked_ml_dsa.contains(&pair.ml_dsa_key_digest)
        }) {
            return Err(HybridPolicyError::RevokedKeyReactivated);
        }
        let expected_repository = repository_digest(&self.repository);
        if previous_authorization.repository_digest != expected_repository
            || previous_authorization.purpose != SignaturePurpose::KeyRotation
            || previous_authorization.object_type != GitObjectType::KeyRotation
            || previous_authorization.trust_generation != self.generation
            || !self.active_pairs.contains(&previous_authorization.pair)
        {
            return Err(HybridPolicyError::MissingPreviousAuthorization);
        }
        if new_authorization.repository_digest != expected_repository
            || new_authorization.purpose != SignaturePurpose::KeyRotation
            || new_authorization.object_type != GitObjectType::KeyRotation
            || new_authorization.trust_generation != candidate.generation
            || !candidate.active_pairs.contains(&new_authorization.pair)
        {
            return Err(HybridPolicyError::MissingNewAuthorization);
        }
        Ok(Self::from_candidate(candidate))
    }

    pub fn apply_key_revocation(
        &self,
        statement: &KeyRevocationStatement,
        authorization: &VerifiedHybridSignature,
    ) -> Result<Self, HybridPolicyError> {
        validate_revocation_statement(statement)?;
        if statement.repository != self.repository
            || statement.previous_generation != self.revocation_generation
            || statement.next_generation.0 <= self.revocation_generation.0
        {
            return Err(HybridPolicyError::RevocationRollback);
        }
        let encoded = encode_key_revocation_statement(statement)?;
        if authorization.repository_digest != repository_digest(&self.repository)
            || authorization.purpose != SignaturePurpose::KeyRevocation
            || authorization.object_type != GitObjectType::KeyRevocation
            || authorization.trust_generation != self.generation
            || authorization.revocation_generation != self.revocation_generation
            || authorization.payload_digest != Sha3_512::digest(&encoded)
            || !self.active_pairs.contains(&authorization.pair)
            || !self.pair_authorized_at(authorization.pair, statement.effective_at)
        {
            return Err(HybridPolicyError::MissingPreviousAuthorization);
        }
        let adds_identity = statement
            .openpgp
            .iter()
            .any(|value| !self.revoked_openpgp.contains(value))
            || statement
                .ml_dsa
                .iter()
                .any(|value| !self.revoked_ml_dsa.contains(value));
        if !adds_identity {
            return Err(HybridPolicyError::RevocationRollback);
        }
        let mut next = self.clone();
        next.revocation_generation = statement.next_generation;
        for fingerprint in &statement.openpgp {
            if !next.revoked_openpgp.contains(fingerprint) {
                next.revoked_openpgp.push(*fingerprint);
            }
        }
        for digest in &statement.ml_dsa {
            if !next.revoked_ml_dsa.contains(digest) {
                next.revoked_ml_dsa.push(*digest);
            }
        }
        next.revoked_openpgp
            .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        next.revoked_ml_dsa.sort_unstable();
        for status in &mut next.pair_statuses {
            if statement.openpgp.contains(&status.pair.openpgp_fingerprint)
                || statement.ml_dsa.contains(&status.pair.ml_dsa_key_digest)
            {
                let latest = statement
                    .effective_at
                    .min(status.valid_until.saturating_sub(1));
                status.retired_at = Some(status.retired_at.map_or(latest, |old| old.min(latest)));
            }
        }
        next.active_pairs = next
            .pair_statuses
            .iter()
            .filter(|status| status.retired_at.is_none())
            .map(|status| status.pair)
            .collect();
        if next.active_pairs.is_empty() {
            return Err(HybridPolicyError::InvalidPolicy);
        }
        validate_candidate(&TrustPolicyCandidate {
            repository: next.repository.clone(),
            generation: next.generation,
            previous_policy_digest: next.previous_policy_digest,
            revocation_generation: next.revocation_generation,
            protected_refs: next.protected_refs.clone(),
            allow_sha1: next.allowed_object_formats & 1 != 0,
            allow_sha256: next.allowed_object_formats & 2 != 0,
            hybrid_required: next.hybrid_required,
            legacy_checkpoint: next.legacy_checkpoint,
            hybrid_cutover: next.hybrid_cutover,
            emergency_policy_digest: next.emergency_policy_digest,
            active_pairs: next.active_pairs.clone(),
            pair_statuses: next.pair_statuses.clone(),
            revoked_openpgp: next.revoked_openpgp.clone(),
            revoked_ml_dsa: next.revoked_ml_dsa.clone(),
        })?;
        Ok(next)
    }

    pub fn digest(&self) -> [u8; 64] {
        let mut hash = Sha3_512::new();
        hash.update(b"MRML-GIT-TRUST-POLICY-V1\0");
        hash.update(&(self.repository.as_str().len() as u16).to_be_bytes());
        hash.update(self.repository.as_str().as_bytes());
        hash.update(&self.generation.0.to_be_bytes());
        hash.update(&self.previous_policy_digest);
        hash.update(&self.revocation_generation.0.to_be_bytes());
        hash.update(&[self.allowed_object_formats, u8::from(self.hybrid_required)]);
        hash_optional_object(&mut hash, self.legacy_checkpoint);
        hash_optional_object(&mut hash, self.hybrid_cutover);
        match self.emergency_policy_digest {
            Some(digest) => {
                hash.update(&[1]);
                hash.update(&digest);
            }
            None => hash.update(&[0]),
        }
        hash.update(&(self.protected_refs.len() as u16).to_be_bytes());
        for reference in &self.protected_refs {
            hash.update(&(reference.as_str().len() as u16).to_be_bytes());
            hash.update(reference.as_str().as_bytes());
        }
        hash.update(&(self.active_pairs.len() as u16).to_be_bytes());
        for pair in &self.active_pairs {
            hash.update(pair.openpgp_fingerprint.as_bytes());
            hash.update(&pair.openpgp_key_digest);
            hash.update(&pair.ml_dsa_key_digest);
        }
        hash.update(&(self.pair_statuses.len() as u16).to_be_bytes());
        for status in &self.pair_statuses {
            hash.update(status.pair.openpgp_fingerprint.as_bytes());
            hash.update(&status.pair.openpgp_key_digest);
            hash.update(&status.pair.ml_dsa_key_digest);
            hash.update(&status.valid_from.to_be_bytes());
            hash.update(&status.valid_until.to_be_bytes());
            match status.retired_at {
                Some(retired) => {
                    hash.update(&[1]);
                    hash.update(&retired.to_be_bytes());
                }
                None => hash.update(&[0]),
            }
        }
        hash.update(&(self.revoked_openpgp.len() as u16).to_be_bytes());
        for fingerprint in &self.revoked_openpgp {
            hash.update(fingerprint.as_bytes());
        }
        hash.update(&(self.revoked_ml_dsa.len() as u16).to_be_bytes());
        for digest in &self.revoked_ml_dsa {
            hash.update(digest);
        }
        hash.finalize()
    }

    pub const fn generation(&self) -> TrustGeneration {
        self.generation
    }

    pub fn active_pairs(&self) -> &[AuthorizedHybridPair] {
        &self.active_pairs
    }

    pub fn pair_statuses(&self) -> &[PolicyPairStatus] {
        &self.pair_statuses
    }

    /// Authorizes an exact pair only inside its half-open validity interval.
    /// Retired pairs remain recorded for historical verification but cease to
    /// authorize at their retirement instant.
    pub fn pair_authorized_at(&self, pair: AuthorizedHybridPair, time: u64) -> bool {
        self.pair_statuses
            .iter()
            .find(|status| status.pair == pair)
            .is_some_and(|status| status.authorizes_at(time))
    }

    /// Selects the exact current pair policy consumed by cryptographic
    /// verification. A recorded historical identity is not sufficient: the
    /// pair must still be active, unrevoked, and inside its half-open interval
    /// at the caller's trusted validation time.
    pub fn active_verification_policy_at(
        &self,
        pair: AuthorizedHybridPair,
        validation_time: u64,
        enforce_signature_expiration: bool,
    ) -> Result<HybridTrustPolicy, HybridPolicyError> {
        let status = self
            .pair_statuses
            .iter()
            .find(|status| status.pair == pair)
            .ok_or(HybridPolicyError::KeyOutsideValidity)?;
        if !self.active_pairs.contains(&pair)
            || !status.authorizes_at(validation_time)
            || self.revoked_openpgp.contains(&pair.openpgp_fingerprint)
            || self.revoked_ml_dsa.contains(&pair.ml_dsa_key_digest)
        {
            return Err(HybridPolicyError::KeyOutsideValidity);
        }
        let not_after = status.retired_at.unwrap_or(status.valid_until);
        Ok(HybridTrustPolicy {
            trust_generation: self.generation,
            revocation_generation: self.revocation_generation,
            authorized_pair: pair,
            validation_time: Some(validation_time),
            openpgp_not_after: Some(not_after),
            enforce_signature_expiration,
        })
    }

    fn from_candidate(candidate: TrustPolicyCandidate) -> Self {
        let allowed_object_formats = candidate.allowed_format_mask();
        Self {
            repository: candidate.repository,
            generation: candidate.generation,
            previous_policy_digest: candidate.previous_policy_digest,
            revocation_generation: candidate.revocation_generation,
            protected_refs: candidate.protected_refs,
            allowed_object_formats,
            hybrid_required: candidate.hybrid_required,
            legacy_checkpoint: candidate.legacy_checkpoint,
            hybrid_cutover: candidate.hybrid_cutover,
            emergency_policy_digest: candidate.emergency_policy_digest,
            active_pairs: candidate.active_pairs,
            pair_statuses: candidate.pair_statuses,
            revoked_openpgp: candidate.revoked_openpgp,
            revoked_ml_dsa: candidate.revoked_ml_dsa,
        }
    }
}

impl TrustPolicyCandidate {
    fn allowed_format_mask(&self) -> u8 {
        u8::from(self.allow_sha1) | (u8::from(self.allow_sha256) << 1)
    }
}

fn validate_candidate(candidate: &TrustPolicyCandidate) -> Result<(), HybridPolicyError> {
    if candidate.generation.0 == 0
        || candidate.revocation_generation.0 == 0
        || candidate.active_pairs.is_empty()
        || candidate.active_pairs.len() > MAX_POLICY_PAIRS
        || candidate.pair_statuses.is_empty()
        || candidate.pair_statuses.len() > MAX_POLICY_PAIRS * 2
        || candidate.protected_refs.is_empty()
        || candidate.protected_refs.len() > MAX_POLICY_PROTECTED_REFS
        || candidate.revoked_openpgp.len() > MAX_POLICY_REVOKED_KEYS
        || candidate.revoked_ml_dsa.len() > MAX_POLICY_REVOKED_KEYS
        || candidate.allowed_format_mask() == 0
        || !strictly_ordered_by(&candidate.active_pairs, pair_less)
        || !strictly_ordered_by(&candidate.pair_statuses, status_less)
        || !strictly_ordered_by(&candidate.protected_refs, |left, right| left < right)
        || !strictly_ordered_by(&candidate.revoked_openpgp, |left, right| {
            left.as_bytes() < right.as_bytes()
        })
        || !strictly_ordered_by(&candidate.revoked_ml_dsa, |left, right| left < right)
        || candidate.hybrid_required && candidate.hybrid_cutover.is_none()
        || candidate.legacy_checkpoint.is_some() && candidate.hybrid_cutover.is_none()
        || [candidate.legacy_checkpoint, candidate.hybrid_cutover]
            .into_iter()
            .flatten()
            .any(|id| {
                id.is_zero()
                    || match id.format() {
                        ObjectFormat::Sha1 => !candidate.allow_sha1,
                        ObjectFormat::Sha256 => !candidate.allow_sha256,
                    }
            })
    {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    let active_statuses = candidate
        .pair_statuses
        .iter()
        .filter(|status| status.retired_at.is_none())
        .map(|status| status.pair)
        .collect::<Vector<_>>();
    if active_statuses != candidate.active_pairs {
        return Err(HybridPolicyError::InvalidPolicy);
    }
    Ok(())
}

fn hash_optional_object(hash: &mut Sha3_512, object: Option<ObjectId>) {
    match object {
        Some(object) => {
            hash.update(&[1, object_format_code(object.format())]);
            hash.update(object.as_bytes());
        }
        None => hash.update(&[0]),
    }
}

const fn object_format_code(format: ObjectFormat) -> u8 {
    match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    }
}

fn strictly_ordered_by<T>(values: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less(&pair[0], &pair[1]))
}

fn pair_less(left: &AuthorizedHybridPair, right: &AuthorizedHybridPair) -> bool {
    left.openpgp_fingerprint
        .as_bytes()
        .cmp(right.openpgp_fingerprint.as_bytes())
        .then(left.openpgp_key_digest.cmp(&right.openpgp_key_digest))
        .then(left.ml_dsa_key_digest.cmp(&right.ml_dsa_key_digest))
        .is_lt()
}

fn status_less(left: &PolicyPairStatus, right: &PolicyPairStatus) -> bool {
    pair_less(&left.pair, &right.pair)
}

fn repository_digest(repository: &RepositoryIdentity) -> [u8; 64] {
    Sha3_512::digest(repository.as_str().as_bytes())
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
            allowed_digests: DigestAlgorithmSet::SHA256_AND_SHA512,
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
        repository_digest: repository_digest(request.repository),
        payload_digest: Sha3_512::digest(request.payload),
        purpose: request.purpose,
        object_type: request.object_type,
    })
}

/// Bind a successful hybrid verification to the exact commit and authority
/// context consumed by protected-history admission.
pub fn bind_verified_commit_proof(
    signature: &VerifiedHybridSignature,
    commit: ObjectId,
    commit_contents: &[u8],
    context: ProtectedHistoryContext<'_>,
) -> Result<VerifiedCommitProof, HybridPolicyError> {
    if commit.is_zero()
        || commit.format() != context.object_format
        || context.repository_generation.0 == 0
        || signature.repository_digest != repository_digest(context.repository)
        || signature.payload_digest != Sha3_512::digest(commit_contents)
        || hash_commit(context.object_format, commit_contents) != commit
        || signature.trust_generation != context.trust_generation
        || signature.revocation_generation != context.revocation_generation
        || signature.purpose != SignaturePurpose::GitCommit
        || signature.object_type != GitObjectType::Commit
        || context.purpose != SignaturePurpose::GitCommit
    {
        return Err(HybridPolicyError::InvalidPurpose);
    }
    Ok(VerifiedCommitProof {
        commit,
        repository: context.repository.clone(),
        repository_generation: context.repository_generation,
        trust_generation: context.trust_generation,
        revocation_generation: context.revocation_generation,
        purpose: context.purpose,
        object_format: context.object_format,
    })
}

fn hash_commit(format: ObjectFormat, contents: &[u8]) -> ObjectId {
    crate::object::encode_loose_object_with_format(
        format,
        crate::object::ObjectKind::Commit,
        contents,
    )
    .0
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
        let verified = verify_hybrid_signature(
            &policy,
            &openpgp.public_key(),
            &ml_public,
            &request,
            &mut scratch,
        )
        .unwrap();
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: crate::RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let commit = hash_commit(ObjectFormat::Sha256, request.payload);
        assert!(bind_verified_commit_proof(&verified, commit, request.payload, context).is_ok());
        assert_eq!(
            bind_verified_commit_proof(
                &verified,
                ObjectId::Sha256([99; 32]),
                request.payload,
                context
            ),
            Err(HybridPolicyError::InvalidPurpose)
        );
        assert_eq!(
            bind_verified_commit_proof(&verified, commit, b"different commit", context),
            Err(HybridPolicyError::InvalidPurpose)
        );

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

    #[test]
    fn policy_rotation_requires_old_and_new_pairs_and_never_broadens() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old_pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([1u8; 32]),
            openpgp_key_digest: [2u8; 64],
            ml_dsa_key_digest: [3u8; 64],
        };
        let new_pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([4u8; 32]),
            openpgp_key_digest: [5u8; 64],
            ml_dsa_key_digest: [6u8; 64],
        };
        let initial = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(1),
            previous_policy_digest: [0u8; 64],
            revocation_generation: RevocationGeneration(1),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: true,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: Some(ObjectId::Sha256([7u8; 32])),
            hybrid_cutover: Some(ObjectId::Sha256([8u8; 32])),
            emergency_policy_digest: Some([9u8; 64]),
            active_pairs: [old_pair].into(),
            pair_statuses: [PolicyPairStatus::new(old_pair, 100, 300, None).unwrap()].into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        assert_eq!(
            initial.active_verification_policy_at(old_pair, 99, true),
            Err(HybridPolicyError::KeyOutsideValidity)
        );
        let at_start = initial
            .active_verification_policy_at(old_pair, 100, true)
            .unwrap();
        assert_eq!(at_start.validation_time, Some(100));
        assert_eq!(at_start.openpgp_not_after, Some(300));
        assert!(
            initial
                .active_verification_policy_at(old_pair, 299, true)
                .is_ok()
        );
        assert_eq!(
            initial.active_verification_policy_at(old_pair, 300, true),
            Err(HybridPolicyError::KeyOutsideValidity)
        );
        let encoded = encode_trust_policy(&initial).unwrap();
        assert_eq!(parse_trust_policy(&encoded), Ok(initial.clone()));
        for length in 0..encoded.len() {
            assert!(parse_trust_policy(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            parse_trust_policy(&trailing),
            Err(HybridPolicyError::InvalidPolicy)
        );
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            parse_trust_policy(&wrong_magic),
            Err(HybridPolicyError::InvalidPolicy)
        );
        let old_proof = rotation_proof(&repository, TrustGeneration(1), old_pair);
        let new_proof = rotation_proof(&repository, TrustGeneration(2), new_pair);
        let candidate = TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(2),
            previous_policy_digest: initial.digest(),
            revocation_generation: RevocationGeneration(2),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: Some(ObjectId::Sha256([7u8; 32])),
            hybrid_cutover: Some(ObjectId::Sha256([8u8; 32])),
            emergency_policy_digest: Some([9u8; 64]),
            active_pairs: [new_pair].into(),
            pair_statuses: [
                PolicyPairStatus::new(old_pair, 100, 300, Some(200)).unwrap(),
                PolicyPairStatus::new(new_pair, 200, 400, None).unwrap(),
            ]
            .into(),
            revoked_openpgp: [old_pair.openpgp_fingerprint].into(),
            revoked_ml_dsa: [old_pair.ml_dsa_key_digest].into(),
        };
        let rotated = initial
            .transition(candidate, &old_proof, &new_proof)
            .unwrap();
        assert_eq!(rotated.generation(), TrustGeneration(2));

        let downgrade = TrustPolicyCandidate {
            repository,
            generation: TrustGeneration(3),
            previous_policy_digest: rotated.digest(),
            revocation_generation: RevocationGeneration(2),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: false,
            legacy_checkpoint: Some(ObjectId::Sha256([7u8; 32])),
            hybrid_cutover: Some(ObjectId::Sha256([8u8; 32])),
            emergency_policy_digest: Some([9u8; 64]),
            active_pairs: [new_pair].into(),
            pair_statuses: [
                PolicyPairStatus::new(old_pair, 100, 300, Some(200)).unwrap(),
                PolicyPairStatus::new(new_pair, 200, 400, None).unwrap(),
            ]
            .into(),
            revoked_openpgp: [old_pair.openpgp_fingerprint].into(),
            revoked_ml_dsa: [old_pair.ml_dsa_key_digest].into(),
        };
        assert_eq!(
            rotated.transition(downgrade, &new_proof, &new_proof),
            Err(HybridPolicyError::HybridDowngrade)
        );
        assert!(rotated.pair_authorized_at(old_pair, 199));
        assert!(!rotated.pair_authorized_at(old_pair, 200));
        assert!(!rotated.pair_authorized_at(new_pair, 199));
        assert!(rotated.pair_authorized_at(new_pair, 200));
        assert!(!rotated.pair_authorized_at(new_pair, 400));
    }

    #[test]
    fn pair_status_encoding_and_transition_narrowing_fail_closed() {
        let pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([10; 32]),
            openpgp_key_digest: [11; 64],
            ml_dsa_key_digest: [12; 64],
        };
        assert!(PolicyPairStatus::new(pair, 10, 10, None).is_err());
        assert!(PolicyPairStatus::new(pair, 10, 20, Some(20)).is_err());

        let repository = RepositoryIdentity::parse("owner/status").unwrap();
        let initial = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(1),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(1),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(ObjectId::Sha256([1; 32])),
            emergency_policy_digest: None,
            active_pairs: [pair].into(),
            pair_statuses: [PolicyPairStatus::new(pair, 10, 100, None).unwrap()].into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        let encoded = encode_trust_policy(&initial).unwrap();
        assert_eq!(parse_trust_policy(&encoded), Ok(initial.clone()));
        for end in 0..encoded.len() {
            assert!(parse_trust_policy(&encoded[..end]).is_err());
        }

        let proof = rotation_proof(&repository, TrustGeneration(1), pair);
        let next_proof = rotation_proof(&repository, TrustGeneration(2), pair);
        let candidate = |status| TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(2),
            previous_policy_digest: initial.digest(),
            revocation_generation: RevocationGeneration(1),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(ObjectId::Sha256([1; 32])),
            emergency_policy_digest: None,
            active_pairs: [pair].into(),
            pair_statuses: [status].into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        };
        assert_eq!(
            initial.transition(
                candidate(PolicyPairStatus::new(pair, 10, 101, None).unwrap()),
                &proof,
                &next_proof
            ),
            Err(HybridPolicyError::PolicyRollback)
        );
        assert!(
            initial
                .transition(
                    candidate(PolicyPairStatus::new(pair, 10, 90, None).unwrap()),
                    &proof,
                    &next_proof
                )
                .is_ok()
        );

        let retired = PolicyPairStatus::new(pair, 10, 100, Some(60)).unwrap();
        let retired_state = TrustPolicyState {
            pair_statuses: [retired].into(),
            active_pairs: Vector::new(),
            ..initial.clone()
        };
        let reversal = TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(2),
            previous_policy_digest: retired_state.digest(),
            revocation_generation: RevocationGeneration(1),
            protected_refs: retired_state.protected_refs.clone(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(ObjectId::Sha256([1; 32])),
            emergency_policy_digest: None,
            active_pairs: [pair].into(),
            pair_statuses: [PolicyPairStatus::new(pair, 10, 100, None).unwrap()].into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        };
        assert_eq!(
            retired_state.transition(reversal, &proof, &next_proof),
            Err(HybridPolicyError::PolicyRollback)
        );

        let other = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([9; 32]),
            openpgp_key_digest: [9; 64],
            ml_dsa_key_digest: [9; 64],
        };
        let mut unordered = [
            PolicyPairStatus::new(pair, 10, 20, None).unwrap(),
            PolicyPairStatus::new(other, 10, 20, None).unwrap(),
        ];
        unordered.sort_unstable_by(|a, b| {
            if status_less(a, b) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        let ordered_active = [unordered[0].pair(), unordered[1].pair()];
        unordered.swap(0, 1);
        let invalid = TrustPolicyCandidate {
            repository,
            generation: TrustGeneration(1),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(1),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(ObjectId::Sha256([1; 32])),
            emergency_policy_digest: None,
            active_pairs: ordered_active.into(),
            pair_statuses: unordered.into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        };
        assert_eq!(
            TrustPolicyState::establish(invalid),
            Err(HybridPolicyError::InvalidPolicy)
        );
    }

    #[test]
    fn canonical_key_revocation_only_adds_and_retires_exact_identities() {
        let repository = RepositoryIdentity::parse("owner/revocations").unwrap();
        let revoked_pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([1; 32]),
            openpgp_key_digest: [2; 64],
            ml_dsa_key_digest: [3; 64],
        };
        let authorizing_pair = AuthorizedHybridPair {
            openpgp_fingerprint: FingerprintV6::from_bytes([4; 32]),
            openpgp_key_digest: [5; 64],
            ml_dsa_key_digest: [6; 64],
        };
        let state = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(7),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(9),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(ObjectId::Sha256([8; 32])),
            emergency_policy_digest: None,
            active_pairs: [revoked_pair, authorizing_pair].into(),
            pair_statuses: [
                PolicyPairStatus::new(revoked_pair, 100, 1000, None).unwrap(),
                PolicyPairStatus::new(authorizing_pair, 100, 1000, None).unwrap(),
            ]
            .into(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        let statement = KeyRevocationStatement::new(
            repository.clone(),
            RevocationGeneration(9),
            RevocationGeneration(10),
            500,
            Vector::from(*b"owner-confirmed compromise"),
            [revoked_pair.openpgp_fingerprint].into(),
            [revoked_pair.ml_dsa_key_digest].into(),
        )
        .unwrap();
        let encoded = encode_key_revocation_statement(&statement).unwrap();
        assert_eq!(
            parse_key_revocation_statement(&encoded),
            Ok(statement.clone())
        );
        for end in 0..encoded.len() {
            assert!(parse_key_revocation_statement(&encoded[..end]).is_err());
        }
        let mut tampered = encoded.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered_statement = parse_key_revocation_statement(&tampered).unwrap();
        assert_ne!(
            key_revocation_statement_digest(&tampered_statement).unwrap(),
            key_revocation_statement_digest(&statement).unwrap()
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(parse_key_revocation_statement(&trailing).is_err());

        let authorization = revocation_proof(&state, &statement, authorizing_pair);
        assert_eq!(
            state.apply_key_revocation(&tampered_statement, &authorization),
            Err(HybridPolicyError::MissingPreviousAuthorization)
        );
        let next = state
            .apply_key_revocation(&statement, &authorization)
            .unwrap();
        assert_eq!(next.revocation_generation, RevocationGeneration(10));
        assert!(!next.pair_authorized_at(revoked_pair, 500));
        assert!(next.pair_authorized_at(revoked_pair, 499));
        assert!(next.pair_authorized_at(authorizing_pair, 500));
        assert!(
            next.revoked_openpgp
                .contains(&revoked_pair.openpgp_fingerprint)
        );
        assert!(
            next.revoked_ml_dsa
                .contains(&revoked_pair.ml_dsa_key_digest)
        );
        assert_eq!(
            next.apply_key_revocation(&statement, &authorization),
            Err(HybridPolicyError::RevocationRollback)
        );

        let mut unauthorized = authorization;
        unauthorized.payload_digest[0] ^= 1;
        assert_eq!(
            state.apply_key_revocation(&statement, &unauthorized),
            Err(HybridPolicyError::MissingPreviousAuthorization)
        );
        let mut wrong_purpose = authorization;
        wrong_purpose.purpose = SignaturePurpose::KeyRotation;
        wrong_purpose.object_type = GitObjectType::KeyRotation;
        assert_eq!(
            state.apply_key_revocation(&statement, &wrong_purpose),
            Err(HybridPolicyError::MissingPreviousAuthorization)
        );
        let duplicate = KeyRevocationStatement::new(
            repository,
            RevocationGeneration(9),
            RevocationGeneration(10),
            500,
            Vector::from(*b"duplicate"),
            [
                revoked_pair.openpgp_fingerprint,
                revoked_pair.openpgp_fingerprint,
            ]
            .into(),
            Vector::new(),
        );
        assert_eq!(duplicate, Err(HybridPolicyError::InvalidPolicy));
        let unordered = KeyRevocationStatement::new(
            RepositoryIdentity::parse("owner/revocations").unwrap(),
            RevocationGeneration(9),
            RevocationGeneration(10),
            500,
            Vector::from(*b"unordered"),
            [
                FingerprintV6::from_bytes([8; 32]),
                FingerprintV6::from_bytes([7; 32]),
            ]
            .into(),
            Vector::new(),
        );
        assert_eq!(unordered, Err(HybridPolicyError::InvalidPolicy));
    }

    fn revocation_proof(
        state: &TrustPolicyState,
        statement: &KeyRevocationStatement,
        pair: AuthorizedHybridPair,
    ) -> VerifiedHybridSignature {
        VerifiedHybridSignature {
            trust_generation: state.generation,
            revocation_generation: state.revocation_generation,
            pair,
            repository_digest: repository_digest(&state.repository),
            payload_digest: key_revocation_statement_digest(statement).unwrap(),
            purpose: SignaturePurpose::KeyRevocation,
            object_type: GitObjectType::KeyRevocation,
        }
    }

    fn rotation_proof(
        repository: &RepositoryIdentity,
        generation: TrustGeneration,
        pair: AuthorizedHybridPair,
    ) -> VerifiedHybridSignature {
        VerifiedHybridSignature {
            trust_generation: generation,
            revocation_generation: RevocationGeneration(generation.0),
            pair,
            repository_digest: repository_digest(repository),
            payload_digest: [0; 64],
            purpose: SignaturePurpose::KeyRotation,
            object_type: GitObjectType::KeyRotation,
        }
    }
}
