//! Canonical payloads carried by the authenticated Git authority channel.

use mrml_runtime::Vector;

use crate::gitd_core::{MAX_REF_NAME_BYTES, MAX_REPOSITORY_IDENTITY_BYTES};
use crate::{
    AuthorityCandidateContext, AuthorityCandidateRecord, AuthorityCandidateStatus,
    CandidateRefTransaction, CandidateRefUpdate, DetachedCommitProofRecord, FullRefName,
    GitdCoreError, ObjectFormat, ObjectId, ProtectedHistoryContext, ProtectedReceiveAuthorization,
    QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    SignaturePurpose, TrustGeneration,
};

const RECEIVE_MAGIC: &[u8; 8] = b"MRGARCV1";
const REFS_MAGIC: &[u8; 8] = b"MRGARFV1";
const COMMIT_MAGIC: &[u8; 8] = b"MRGACMV1";
const PROOF_MAGIC: &[u8; 8] = b"MRGAPF01";
const CANDIDATE_PROOF_MAGIC: &[u8; 8] = b"MRGCPF01";
const RECEIPT_MAGIC: &[u8; 8] = b"MRGARPV1";
const CANDIDATE_MAGIC: &[u8; 8] = b"MRGACD01";
const CANDIDATE_STATUS_MAGIC: &[u8; 8] = b"MRGACS01";
const CANDIDATE_LOOKUP_MAGIC: &[u8; 8] = b"MRGACL01";
const CANDIDATE_RESULT_MAGIC: &[u8; 8] = b"MRGCSR01";
const GENERATION_QUERY_MAGIC: &[u8; 8] = b"MRGAGQ01";
const GENERATION_RESULT_MAGIC: &[u8; 8] = b"MRGAGR01";
const MAX_AUTHORITY_CANDIDATE_BYTES: usize = 1024;
pub const MAX_AUTHORITY_COMMIT_BYTES: usize = 1024 * 1024;
pub const MAX_AUTHORITY_RECEIPT_TRANSCRIPT_BYTES: usize = 128 * 1024;

pub fn encode_authority_generation_query(
    repository: &RepositoryIdentity,
) -> Result<Vector<u8>, GitdCoreError> {
    let mut output = Vector::new();
    append(&mut output, GENERATION_QUERY_MAGIC)?;
    append_counted(&mut output, repository.as_str().as_bytes())?;
    Ok(output)
}

pub fn parse_authority_generation_query(input: &[u8]) -> Result<RepositoryIdentity, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(GENERATION_QUERY_MAGIC)?;
    let repository =
        RepositoryIdentity::parse(cursor.counted_text(MAX_REPOSITORY_IDENTITY_BYTES)?)?;
    cursor.finish()?;
    Ok(repository)
}

pub fn encode_authority_generation_result(
    repository: RepositoryGeneration,
    trust: TrustGeneration,
    revocation: RevocationGeneration,
) -> Result<Vector<u8>, GitdCoreError> {
    if repository.0 == 0 || trust.0 == 0 || revocation.0 == 0 {
        return Err(GitdCoreError::Authorization);
    }
    let mut output = Vector::new();
    append(&mut output, GENERATION_RESULT_MAGIC)?;
    append(&mut output, &repository.0.to_be_bytes())?;
    append(&mut output, &trust.0.to_be_bytes())?;
    append(&mut output, &revocation.0.to_be_bytes())?;
    Ok(output)
}

pub fn parse_authority_generation_result(
    input: &[u8],
) -> Result<(RepositoryGeneration, TrustGeneration, RevocationGeneration), GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(GENERATION_RESULT_MAGIC)?;
    let result = (
        RepositoryGeneration(cursor.u64()?),
        TrustGeneration(cursor.u64()?),
        RevocationGeneration(cursor.u64()?),
    );
    cursor.finish()?;
    if result.0.0 == 0 || result.1.0 == 0 || result.2.0 == 0 {
        return Err(GitdCoreError::Authorization);
    }
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCommitRequest {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub purpose: SignaturePurpose,
    pub object_format: ObjectFormat,
    pub commit: ObjectId,
    pub exact_contents: Vector<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityProofInstallRequest {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub purpose: SignaturePurpose,
    pub object_format: ObjectFormat,
    pub commit: ObjectId,
    pub exact_contents: Vector<u8>,
    pub proof: DetachedCommitProofRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateProofRequest {
    pub candidate: AuthorityCandidateContext,
    pub proof: AuthorityProofInstallRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateLookup {
    pub repository: RepositoryIdentity,
    pub id: QuarantineTransactionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateStatusResult {
    pub record: AuthorityCandidateRecord,
    pub authenticated_receipt: Option<Vector<u8>>,
}

pub fn encode_authority_candidate_status_result(
    result: &AuthorityCandidateStatusResult,
) -> Result<Vector<u8>, GitdCoreError> {
    validate_candidate_status_result(result)?;
    let record = encode_authority_candidate_record(&result.record)?;
    let receipt = result.authenticated_receipt.as_deref().unwrap_or(&[]);
    let mut output = Vector::new();
    append(&mut output, CANDIDATE_RESULT_MAGIC)?;
    append_counted(&mut output, &record)?;
    append(&mut output, &(receipt.len() as u32).to_be_bytes())?;
    append(&mut output, receipt)?;
    Ok(output)
}

pub fn parse_authority_candidate_status_result(
    input: &[u8],
) -> Result<AuthorityCandidateStatusResult, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(CANDIDATE_RESULT_MAGIC)?;
    let record =
        parse_authority_candidate_record(cursor.counted_bytes(MAX_AUTHORITY_CANDIDATE_BYTES)?)?;
    let receipt_length = usize::try_from(cursor.u32()?).map_err(|_| GitdCoreError::Resource)?;
    if receipt_length > crate::MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES {
        return Err(GitdCoreError::Resource);
    }
    let receipt = cursor.take(receipt_length)?;
    cursor.finish()?;
    let mut authenticated_receipt = None;
    if !receipt.is_empty() {
        let mut owned = Vector::new();
        append(&mut owned, receipt)?;
        authenticated_receipt = Some(owned);
    }
    let result = AuthorityCandidateStatusResult {
        record,
        authenticated_receipt,
    };
    validate_candidate_status_result(&result)?;
    Ok(result)
}

fn validate_candidate_status_result(
    result: &AuthorityCandidateStatusResult,
) -> Result<(), GitdCoreError> {
    let requires_receipt = matches!(
        result.record.status,
        AuthorityCandidateStatus::ReceiptPersisted | AuthorityCandidateStatus::Completed
    );
    if requires_receipt != result.authenticated_receipt.is_some() {
        return Err(GitdCoreError::Authorization);
    }
    if let Some(encoded) = result.authenticated_receipt.as_deref() {
        let receipt = crate::parse_authenticated_audit_receipt(encoded)
            .map_err(|_| GitdCoreError::Authorization)?;
        if receipt.receipt.transaction != result.record.context.id
            || receipt.receipt.repository != result.record.context.repository
        {
            return Err(GitdCoreError::Authorization);
        }
    }
    Ok(())
}

pub fn encode_authority_candidate_lookup(
    repository: &RepositoryIdentity,
    id: QuarantineTransactionId,
) -> Result<Vector<u8>, GitdCoreError> {
    if id.0 == [0; 16] {
        return Err(GitdCoreError::Authorization);
    }
    let mut output = Vector::new();
    append(&mut output, CANDIDATE_LOOKUP_MAGIC)?;
    append_counted(&mut output, repository.as_str().as_bytes())?;
    append(&mut output, &id.0)?;
    Ok(output)
}

pub fn parse_authority_candidate_lookup(
    input: &[u8],
) -> Result<AuthorityCandidateLookup, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(CANDIDATE_LOOKUP_MAGIC)?;
    let repository =
        RepositoryIdentity::parse(cursor.counted_text(MAX_REPOSITORY_IDENTITY_BYTES)?)?;
    let mut id = [0; 16];
    id.copy_from_slice(cursor.take(16)?);
    cursor.finish()?;
    if id == [0; 16] {
        return Err(GitdCoreError::Authorization);
    }
    Ok(AuthorityCandidateLookup {
        repository,
        id: QuarantineTransactionId(id),
    })
}

pub fn encode_authority_candidate_proof(
    candidate: &AuthorityCandidateContext,
    context: ProtectedHistoryContext<'_>,
    commit: ObjectId,
    exact_contents: &[u8],
    proof: &DetachedCommitProofRecord,
) -> Result<Vector<u8>, GitdCoreError> {
    let candidate = encode_authority_candidate(candidate)?;
    let proof = encode_authority_proof_install(context, commit, exact_contents, proof)?;
    let mut output = Vector::new();
    append(&mut output, CANDIDATE_PROOF_MAGIC)?;
    append_counted(&mut output, &candidate)?;
    append_large_counted(&mut output, &proof)?;
    Ok(output)
}

pub fn parse_authority_candidate_proof(
    input: &[u8],
) -> Result<AuthorityCandidateProofRequest, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(CANDIDATE_PROOF_MAGIC)?;
    let candidate = cursor.counted_bytes(1024)?;
    let proof = cursor.large_counted_bytes(MAX_AUTHORITY_COMMIT_BYTES + 8 * 1024)?;
    cursor.finish()?;
    Ok(AuthorityCandidateProofRequest {
        candidate: parse_authority_candidate(&candidate)?,
        proof: parse_authority_proof_install(&proof)?,
    })
}

pub fn encode_authority_proof_install(
    context: ProtectedHistoryContext<'_>,
    commit: ObjectId,
    exact_contents: &[u8],
    proof: &DetachedCommitProofRecord,
) -> Result<Vector<u8>, GitdCoreError> {
    if proof.commit() != commit {
        return Err(GitdCoreError::Authorization);
    }
    let mut output = encode_authority_commit(context, commit, exact_contents)?;
    output[..8].copy_from_slice(PROOF_MAGIC);
    append_counted(&mut output, proof.openpgp_signature())?;
    append_counted(&mut output, proof.ml_dsa_signature())?;
    Ok(output)
}

pub fn parse_authority_proof_install(
    input: &[u8],
) -> Result<AuthorityProofInstallRequest, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(PROOF_MAGIC)?;
    let (repository, repository_generation, trust_generation, revocation_generation) =
        cursor.context()?;
    let purpose = parse_purpose(cursor.byte()?)?;
    if cursor.byte()? != 2 {
        return Err(GitdCoreError::Authorization);
    }
    let commit = ObjectId::from_bytes(ObjectFormat::Sha256, cursor.take(32)?)
        .ok_or(GitdCoreError::MalformedInput)?;
    let length = usize::try_from(cursor.u32()?).map_err(|_| GitdCoreError::Resource)?;
    if length == 0 || length > MAX_AUTHORITY_COMMIT_BYTES {
        return Err(GitdCoreError::Resource);
    }
    let mut exact_contents = Vector::new();
    exact_contents
        .try_extend_from_slice(cursor.take(length)?)
        .map_err(|_| GitdCoreError::Resource)?;
    let openpgp = cursor.counted_bytes(mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES)?;
    let ml_dsa = cursor.counted_bytes(mrml_crypto::ML_DSA_65_SIGNATURE_BYTES)?;
    cursor.finish()?;
    let proof = DetachedCommitProofRecord::new(commit, openpgp, ml_dsa)
        .map_err(|_| GitdCoreError::Authorization)?;
    Ok(AuthorityProofInstallRequest {
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        purpose,
        object_format: ObjectFormat::Sha256,
        commit,
        exact_contents,
        proof,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRefTransactionRequest {
    pub transaction: CandidateRefTransaction,
    pub policy_digest: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityReceiptRequest {
    pub transcript: Vector<u8>,
    pub signature: Vector<u8>,
}

pub fn encode_authority_candidate(
    context: &AuthorityCandidateContext,
) -> Result<Vector<u8>, GitdCoreError> {
    validate_candidate_context(context)?;
    let mut output = Vector::new();
    append(&mut output, CANDIDATE_MAGIC)?;
    append(&mut output, &context.id.0)?;
    encode_context(
        &mut output,
        &context.repository,
        context.current_generation,
        context.trust_generation,
        context.revocation_generation,
    )?;
    append(&mut output, &context.next_generation.0.to_be_bytes())?;
    append(&mut output, &context.policy_digest)?;
    append(&mut output, &context.ref_update_digest)?;
    append(&mut output, &context.introduced_commit_set_digest)?;
    append(&mut output, &context.arrival_pack_digest)?;
    append(&mut output, &context.proof_set_digest)?;
    append(&mut output, &context.activation_digest)?;
    Ok(output)
}

pub fn parse_authority_candidate(input: &[u8]) -> Result<AuthorityCandidateContext, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(CANDIDATE_MAGIC)?;
    let mut id = [0; 16];
    id.copy_from_slice(cursor.take(16)?);
    let (repository, current_generation, trust_generation, revocation_generation) =
        cursor.context()?;
    let next_generation = RepositoryGeneration(cursor.u64()?);
    let mut digest = || -> Result<[u8; 64], GitdCoreError> {
        cursor
            .take(64)?
            .try_into()
            .map_err(|_| GitdCoreError::MalformedInput)
    };
    let context = AuthorityCandidateContext {
        id: QuarantineTransactionId(id),
        repository,
        current_generation,
        next_generation,
        trust_generation,
        revocation_generation,
        policy_digest: digest()?,
        ref_update_digest: digest()?,
        introduced_commit_set_digest: digest()?,
        arrival_pack_digest: digest()?,
        proof_set_digest: digest()?,
        activation_digest: digest()?,
    };
    cursor.finish()?;
    validate_candidate_context(&context)?;
    Ok(context)
}

pub fn encode_authority_candidate_record(
    record: &AuthorityCandidateRecord,
) -> Result<Vector<u8>, GitdCoreError> {
    let mut output = encode_authority_candidate(&record.context)?;
    output[..8].copy_from_slice(CANDIDATE_STATUS_MAGIC);
    output.push(record.status as u8);
    Ok(output)
}

pub fn parse_authority_candidate_record(
    input: &[u8],
) -> Result<AuthorityCandidateRecord, GitdCoreError> {
    if input.len() < 9 || &input[..8] != CANDIDATE_STATUS_MAGIC {
        return Err(GitdCoreError::MalformedInput);
    }
    let status =
        AuthorityCandidateStatus::from_code(*input.last().ok_or(GitdCoreError::MalformedInput)?)
            .ok_or(GitdCoreError::MalformedInput)?;
    let mut context = Vector::new();
    context
        .try_extend_from_slice(&input[..input.len() - 1])
        .map_err(|_| GitdCoreError::Resource)?;
    context[..8].copy_from_slice(CANDIDATE_MAGIC);
    Ok(AuthorityCandidateRecord {
        context: parse_authority_candidate(&context)?,
        status,
    })
}

fn validate_candidate_context(context: &AuthorityCandidateContext) -> Result<(), GitdCoreError> {
    if context.id.0 == [0; 16]
        || context.current_generation.0 == 0
        || context.current_generation.0.checked_add(1) != Some(context.next_generation.0)
        || context.policy_digest == [0; 64]
        || context.ref_update_digest == [0; 64]
        || context.introduced_commit_set_digest == [0; 64]
        || context.arrival_pack_digest == [0; 64]
        || context.proof_set_digest == [0; 64]
        || context.activation_digest == [0; 64]
    {
        return Err(GitdCoreError::Authorization);
    }
    Ok(())
}

pub fn encode_authority_receive(
    request: &ProtectedReceiveAuthorization,
) -> Result<Vector<u8>, GitdCoreError> {
    let mut output = Vector::new();
    append(&mut output, RECEIVE_MAGIC)?;
    encode_context(
        &mut output,
        &request.repository,
        request.repository_generation,
        request.trust_generation,
        request.revocation_generation,
    )?;
    append(&mut output, &request.policy_digest)?;
    Ok(output)
}

pub fn parse_authority_receive(
    input: &[u8],
) -> Result<ProtectedReceiveAuthorization, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(RECEIVE_MAGIC)?;
    let (repository, repository_generation, trust_generation, revocation_generation) =
        cursor.context()?;
    let mut policy_digest = [0u8; 64];
    policy_digest.copy_from_slice(cursor.take(64)?);
    cursor.finish()?;
    Ok(ProtectedReceiveAuthorization {
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        policy_digest,
    })
}

pub fn encode_authority_ref_transaction(
    transaction: &CandidateRefTransaction,
    policy_digest: [u8; 64],
) -> Result<Vector<u8>, GitdCoreError> {
    if transaction.updates.is_empty() || transaction.updates.len() > crate::MAX_REFS_PER_TRANSACTION
    {
        return Err(GitdCoreError::Resource);
    }
    let mut output = Vector::new();
    append(&mut output, REFS_MAGIC)?;
    encode_context(
        &mut output,
        &transaction.repository,
        transaction.repository_generation,
        transaction.trust_generation,
        transaction.revocation_generation,
    )?;
    append(&mut output, &policy_digest)?;
    append(
        &mut output,
        &u16::try_from(transaction.updates.len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    )?;
    for update in &transaction.updates {
        append_counted(&mut output, update.name.as_str().as_bytes())?;
        encode_optional_object(&mut output, update.expected_old)?;
        encode_optional_object(&mut output, update.proposed_new)?;
    }
    Ok(output)
}

pub fn parse_authority_ref_transaction(
    input: &[u8],
) -> Result<AuthorityRefTransactionRequest, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(REFS_MAGIC)?;
    let (repository, repository_generation, trust_generation, revocation_generation) =
        cursor.context()?;
    let mut policy_digest = [0u8; 64];
    policy_digest.copy_from_slice(cursor.take(64)?);
    let count = usize::from(cursor.u16()?);
    if count == 0 || count > crate::MAX_REFS_PER_TRANSACTION {
        return Err(GitdCoreError::Resource);
    }
    let mut updates = Vector::new();
    updates
        .try_reserve_exact(count)
        .map_err(|_| GitdCoreError::Resource)?;
    for _ in 0..count {
        let name = FullRefName::parse(cursor.counted_text(MAX_REF_NAME_BYTES)?)?;
        updates.push(CandidateRefUpdate {
            name,
            expected_old: cursor.optional_object(ObjectFormat::Sha256)?,
            proposed_new: cursor.optional_object(ObjectFormat::Sha256)?,
        });
    }
    cursor.finish()?;
    Ok(AuthorityRefTransactionRequest {
        transaction: CandidateRefTransaction {
            repository,
            repository_generation,
            trust_generation,
            revocation_generation,
            updates,
        },
        policy_digest,
    })
}

pub fn encode_authority_commit(
    context: ProtectedHistoryContext<'_>,
    commit: ObjectId,
    exact_contents: &[u8],
) -> Result<Vector<u8>, GitdCoreError> {
    if context.object_format != ObjectFormat::Sha256
        || commit.format() != ObjectFormat::Sha256
        || commit.is_zero()
        || exact_contents.is_empty()
        || exact_contents.len() > MAX_AUTHORITY_COMMIT_BYTES
    {
        return Err(GitdCoreError::Authorization);
    }
    let mut output = Vector::new();
    append(&mut output, COMMIT_MAGIC)?;
    encode_context(
        &mut output,
        context.repository,
        context.repository_generation,
        context.trust_generation,
        context.revocation_generation,
    )?;
    output.push(purpose_byte(context.purpose)?);
    output.push(2);
    append(&mut output, commit.as_bytes())?;
    append(
        &mut output,
        &u32::try_from(exact_contents.len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    )?;
    append(&mut output, exact_contents)?;
    Ok(output)
}

pub fn parse_authority_commit(input: &[u8]) -> Result<AuthorityCommitRequest, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(COMMIT_MAGIC)?;
    let (repository, repository_generation, trust_generation, revocation_generation) =
        cursor.context()?;
    let purpose = parse_purpose(cursor.byte()?)?;
    if cursor.byte()? != 2 {
        return Err(GitdCoreError::Authorization);
    }
    let commit = ObjectId::from_bytes(ObjectFormat::Sha256, cursor.take(32)?)
        .ok_or(GitdCoreError::MalformedInput)?;
    let length = usize::try_from(cursor.u32()?).map_err(|_| GitdCoreError::Resource)?;
    if length == 0 || length > MAX_AUTHORITY_COMMIT_BYTES {
        return Err(GitdCoreError::Resource);
    }
    let mut exact_contents = Vector::new();
    exact_contents
        .try_extend_from_slice(cursor.take(length)?)
        .map_err(|_| GitdCoreError::Resource)?;
    cursor.finish()?;
    Ok(AuthorityCommitRequest {
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        purpose,
        object_format: ObjectFormat::Sha256,
        commit,
        exact_contents,
    })
}

pub fn encode_authority_receipt(
    transcript: &[u8],
    signature: &[u8],
) -> Result<Vector<u8>, GitdCoreError> {
    if transcript.is_empty()
        || transcript.len() > MAX_AUTHORITY_RECEIPT_TRANSCRIPT_BYTES
        || signature.len() > 64
    {
        return Err(GitdCoreError::Resource);
    }
    let mut output = Vector::new();
    append(&mut output, RECEIPT_MAGIC)?;
    append(
        &mut output,
        &u32::try_from(transcript.len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    )?;
    append(&mut output, transcript)?;
    output.push(u8::try_from(signature.len()).map_err(|_| GitdCoreError::Resource)?);
    append(&mut output, signature)?;
    Ok(output)
}

pub fn parse_authority_receipt(input: &[u8]) -> Result<AuthorityReceiptRequest, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(RECEIPT_MAGIC)?;
    let transcript_length = usize::try_from(cursor.u32()?).map_err(|_| GitdCoreError::Resource)?;
    if transcript_length == 0 || transcript_length > MAX_AUTHORITY_RECEIPT_TRANSCRIPT_BYTES {
        return Err(GitdCoreError::Resource);
    }
    let mut transcript = Vector::new();
    transcript
        .try_extend_from_slice(cursor.take(transcript_length)?)
        .map_err(|_| GitdCoreError::Resource)?;
    let signature_length = usize::from(cursor.byte()?);
    if signature_length > 64 {
        return Err(GitdCoreError::Resource);
    }
    let mut signature = Vector::new();
    signature
        .try_extend_from_slice(cursor.take(signature_length)?)
        .map_err(|_| GitdCoreError::Resource)?;
    cursor.finish()?;
    Ok(AuthorityReceiptRequest {
        transcript,
        signature,
    })
}

fn encode_context(
    output: &mut Vector<u8>,
    repository: &RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
) -> Result<(), GitdCoreError> {
    if repository_generation.0 == 0 || trust_generation.0 == 0 || revocation_generation.0 == 0 {
        return Err(GitdCoreError::Authorization);
    }
    append_counted(output, repository.as_str().as_bytes())?;
    append(output, &repository_generation.0.to_be_bytes())?;
    append(output, &trust_generation.0.to_be_bytes())?;
    append(output, &revocation_generation.0.to_be_bytes())
}

fn encode_optional_object(
    output: &mut Vector<u8>,
    object: Option<ObjectId>,
) -> Result<(), GitdCoreError> {
    match object {
        Some(object) if object.format() == ObjectFormat::Sha256 && !object.is_zero() => {
            output.push(1);
            append(output, object.as_bytes())
        }
        Some(_) => Err(GitdCoreError::Authorization),
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn append_counted(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), GitdCoreError> {
    if bytes.is_empty() || bytes.len() > u16::MAX as usize {
        return Err(GitdCoreError::Resource);
    }
    append(output, &(bytes.len() as u16).to_be_bytes())?;
    append(output, bytes)
}

fn append_large_counted(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), GitdCoreError> {
    if bytes.is_empty() || bytes.len() > u32::MAX as usize {
        return Err(GitdCoreError::Resource);
    }
    append(output, &(bytes.len() as u32).to_be_bytes())?;
    append(output, bytes)
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), GitdCoreError> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| GitdCoreError::Resource)
}

fn purpose_byte(purpose: SignaturePurpose) -> Result<u8, GitdCoreError> {
    match purpose {
        SignaturePurpose::GitCommit => Ok(1),
        _ => Err(GitdCoreError::Authorization),
    }
}

fn parse_purpose(value: u8) -> Result<SignaturePurpose, GitdCoreError> {
    match value {
        1 => Ok(SignaturePurpose::GitCommit),
        _ => Err(GitdCoreError::Authorization),
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], GitdCoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(GitdCoreError::Resource)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(GitdCoreError::MalformedInput)?;
        self.offset = end;
        Ok(value)
    }
    fn magic(&mut self, magic: &[u8]) -> Result<(), GitdCoreError> {
        if self.take(magic.len())? == magic {
            Ok(())
        } else {
            Err(GitdCoreError::MalformedInput)
        }
    }
    fn byte(&mut self) -> Result<u8, GitdCoreError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, GitdCoreError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GitdCoreError::MalformedInput)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, GitdCoreError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| GitdCoreError::MalformedInput)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, GitdCoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GitdCoreError::MalformedInput)?,
        ))
    }
    fn counted_text(&mut self, maximum: usize) -> Result<&'a str, GitdCoreError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(GitdCoreError::Resource);
        }
        core::str::from_utf8(self.take(length)?).map_err(|_| GitdCoreError::MalformedInput)
    }
    fn counted_bytes(&mut self, maximum: usize) -> Result<&'a [u8], GitdCoreError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(GitdCoreError::Resource);
        }
        self.take(length)
    }
    fn large_counted_bytes(&mut self, maximum: usize) -> Result<&'a [u8], GitdCoreError> {
        let length = usize::try_from(self.u32()?).map_err(|_| GitdCoreError::Resource)?;
        if length == 0 || length > maximum {
            return Err(GitdCoreError::Resource);
        }
        self.take(length)
    }
    fn context(
        &mut self,
    ) -> Result<
        (
            RepositoryIdentity,
            RepositoryGeneration,
            TrustGeneration,
            RevocationGeneration,
        ),
        GitdCoreError,
    > {
        let repository =
            RepositoryIdentity::parse(self.counted_text(MAX_REPOSITORY_IDENTITY_BYTES)?)?;
        let repository_generation = RepositoryGeneration(self.u64()?);
        let trust_generation = TrustGeneration(self.u64()?);
        let revocation_generation = RevocationGeneration(self.u64()?);
        if repository_generation.0 == 0 || trust_generation.0 == 0 || revocation_generation.0 == 0 {
            return Err(GitdCoreError::Authorization);
        }
        Ok((
            repository,
            repository_generation,
            trust_generation,
            revocation_generation,
        ))
    }
    fn optional_object(&mut self, format: ObjectFormat) -> Result<Option<ObjectId>, GitdCoreError> {
        match self.byte()? {
            0 => Ok(None),
            1 => ObjectId::from_bytes(format, self.take(format.hash_len())?)
                .map(Some)
                .ok_or(GitdCoreError::MalformedInput),
            _ => Err(GitdCoreError::MalformedInput),
        }
    }
    fn finish(self) -> Result<(), GitdCoreError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(GitdCoreError::MalformedInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> AuthorityCandidateContext {
        AuthorityCandidateContext {
            id: QuarantineTransactionId([7; 16]),
            repository: RepositoryIdentity::parse("owner/repository").unwrap(),
            current_generation: RepositoryGeneration(3),
            next_generation: RepositoryGeneration(4),
            trust_generation: TrustGeneration(5),
            revocation_generation: RevocationGeneration(6),
            policy_digest: [1; 64],
            ref_update_digest: [2; 64],
            introduced_commit_set_digest: [3; 64],
            arrival_pack_digest: [4; 64],
            proof_set_digest: [5; 64],
            activation_digest: [6; 64],
        }
    }

    #[test]
    fn exact_candidate_context_and_status_round_trip() {
        let candidate = candidate();
        assert_eq!(
            parse_authority_candidate_lookup(
                &encode_authority_candidate_lookup(&candidate.repository, candidate.id).unwrap()
            )
            .unwrap(),
            AuthorityCandidateLookup {
                repository: candidate.repository.clone(),
                id: candidate.id,
            }
        );
        let status = AuthorityCandidateStatusResult {
            record: AuthorityCandidateRecord {
                context: candidate.clone(),
                status: AuthorityCandidateStatus::Receiving,
            },
            authenticated_receipt: None,
        };
        let encoded_status = encode_authority_candidate_status_result(&status).unwrap();
        assert_eq!(
            parse_authority_candidate_status_result(&encoded_status).unwrap(),
            status
        );
        for end in 0..encoded_status.len() {
            assert!(parse_authority_candidate_status_result(&encoded_status[..end]).is_err());
        }
        let encoded = encode_authority_candidate(&candidate).unwrap();
        assert_eq!(parse_authority_candidate(&encoded).unwrap(), candidate);
        for end in 0..encoded.len() {
            assert!(parse_authority_candidate(&encoded[..end]).is_err());
        }
        let record = AuthorityCandidateRecord {
            context: candidate.clone(),
            status: AuthorityCandidateStatus::Activated,
        };
        assert_eq!(
            parse_authority_candidate_record(&encode_authority_candidate_record(&record).unwrap())
                .unwrap(),
            record
        );
        let mut conflicting = candidate;
        conflicting.next_generation = RepositoryGeneration(5);
        assert!(encode_authority_candidate(&conflicting).is_err());
    }

    #[test]
    fn candidate_proof_binds_complete_candidate_and_commit_request() {
        let candidate = candidate();
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[8; 32]).unwrap();
        let context = ProtectedHistoryContext {
            repository: &candidate.repository,
            repository_generation: candidate.current_generation,
            trust_generation: candidate.trust_generation,
            revocation_generation: candidate.revocation_generation,
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let proof = DetachedCommitProofRecord::new(
            commit,
            &[3; 64],
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let encoded =
            encode_authority_candidate_proof(&candidate, context, commit, b"tree contents", &proof)
                .unwrap();
        let parsed = parse_authority_candidate_proof(&encoded).unwrap();
        assert_eq!(parsed.candidate, candidate);
        assert_eq!(parsed.proof.commit, commit);
        assert_eq!(&parsed.proof.exact_contents[..], b"tree contents");
        assert_eq!(parsed.proof.proof, proof);
        for end in 0..encoded.len() {
            assert!(parse_authority_candidate_proof(&encoded[..end]).is_err());
        }
    }

    #[test]
    fn exact_receive_and_ref_transactions_round_trip() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let receive = ProtectedReceiveAuthorization {
            repository: repository.clone(),
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
            policy_digest: [7; 64],
        };
        assert_eq!(
            parse_authority_receive(&encode_authority_receive(&receive).unwrap()).unwrap(),
            receive
        );
        let object = ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap();
        let transaction = CandidateRefTransaction {
            repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
            updates: [CandidateRefUpdate {
                name: FullRefName::parse("refs/heads/main").unwrap(),
                expected_old: Some(object),
                proposed_new: Some(object),
            }]
            .into(),
        };
        assert_eq!(
            parse_authority_ref_transaction(
                &encode_authority_ref_transaction(&transaction, [6; 64]).unwrap()
            )
            .unwrap(),
            AuthorityRefTransactionRequest {
                transaction,
                policy_digest: [6; 64]
            }
        );
    }

    #[test]
    fn commit_and_receipt_payloads_are_exact_and_bounded() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let object = ObjectId::from_bytes(ObjectFormat::Sha256, &[8; 32]).unwrap();
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(1),
            trust_generation: TrustGeneration(2),
            revocation_generation: RevocationGeneration(3),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let commit = parse_authority_commit(
            &encode_authority_commit(context, object, b"tree contents").unwrap(),
        )
        .unwrap();
        assert_eq!(commit.commit, object);
        assert_eq!(&commit.exact_contents[..], b"tree contents");
        let proof = DetachedCommitProofRecord::new(
            object,
            &[3; 64],
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let installed = parse_authority_proof_install(
            &encode_authority_proof_install(context, object, b"tree contents", &proof).unwrap(),
        )
        .unwrap();
        assert_eq!(installed.commit, object);
        assert_eq!(installed.proof, proof);
        assert_eq!(&installed.exact_contents[..], b"tree contents");
        let receipt =
            parse_authority_receipt(&encode_authority_receipt(b"transcript", &[4; 32]).unwrap())
                .unwrap();
        assert_eq!(&receipt.transcript[..], b"transcript");
        assert_eq!(&receipt.signature[..], &[4; 32]);
        assert!(
            encode_authority_commit(context, object, &[0; MAX_AUTHORITY_COMMIT_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn truncation_trailing_bytes_and_sha1_fail_closed() {
        let receive = ProtectedReceiveAuthorization {
            repository: RepositoryIdentity::parse("owner/repository").unwrap(),
            repository_generation: RepositoryGeneration(1),
            trust_generation: TrustGeneration(2),
            revocation_generation: RevocationGeneration(3),
            policy_digest: [1; 64],
        };
        let encoded = encode_authority_receive(&receive).unwrap();
        for end in 0..encoded.len() {
            assert!(parse_authority_receive(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(parse_authority_receive(&trailing).is_err());
        let sha1 = ObjectId::from_bytes(ObjectFormat::Sha1, &[1; 20]).unwrap();
        let context = ProtectedHistoryContext {
            repository: &receive.repository,
            repository_generation: RepositoryGeneration(1),
            trust_generation: TrustGeneration(2),
            revocation_generation: RevocationGeneration(3),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha1,
        };
        assert!(encode_authority_commit(context, sha1, b"commit").is_err());
    }

    #[test]
    fn generation_query_and_result_are_exact_bounded_and_nonzero() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let query = encode_authority_generation_query(&repository).unwrap();
        assert_eq!(parse_authority_generation_query(&query), Ok(repository));
        let result = encode_authority_generation_result(
            RepositoryGeneration(9),
            TrustGeneration(5),
            RevocationGeneration(7),
        )
        .unwrap();
        assert_eq!(
            parse_authority_generation_result(&result),
            Ok((
                RepositoryGeneration(9),
                TrustGeneration(5),
                RevocationGeneration(7)
            ))
        );
        assert!(
            encode_authority_generation_result(
                RepositoryGeneration(0),
                TrustGeneration(5),
                RevocationGeneration(7)
            )
            .is_err()
        );
        for end in 0..query.len() {
            assert!(parse_authority_generation_query(&query[..end]).is_err());
        }
    }
}
