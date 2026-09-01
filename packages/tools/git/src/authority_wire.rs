//! Canonical payloads carried by the authenticated Git authority channel.

use mrml_runtime::Vector;

use crate::gitd_core::{MAX_REF_NAME_BYTES, MAX_REPOSITORY_IDENTITY_BYTES};
use crate::{
    CandidateRefTransaction, CandidateRefUpdate, FullRefName, GitdCoreError, ObjectFormat,
    ObjectId, ProtectedHistoryContext, ProtectedReceiveAuthorization, RepositoryGeneration,
    RepositoryIdentity, RevocationGeneration, SignaturePurpose, TrustGeneration,
};

const RECEIVE_MAGIC: &[u8; 8] = b"MRGARCV1";
const REFS_MAGIC: &[u8; 8] = b"MRGARFV1";
const COMMIT_MAGIC: &[u8; 8] = b"MRGACMV1";
const RECEIPT_MAGIC: &[u8; 8] = b"MRGARPV1";
pub const MAX_AUTHORITY_COMMIT_BYTES: usize = 1024 * 1024;
pub const MAX_AUTHORITY_RECEIPT_TRANSCRIPT_BYTES: usize = 128 * 1024;

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
pub struct AuthorityReceiptRequest {
    pub transcript: Vector<u8>,
    pub signature: Vector<u8>,
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
) -> Result<CandidateRefTransaction, GitdCoreError> {
    let mut cursor = Cursor::new(input);
    cursor.magic(REFS_MAGIC)?;
    let (repository, repository_generation, trust_generation, revocation_generation) =
        cursor.context()?;
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
    Ok(CandidateRefTransaction {
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        updates,
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
                &encode_authority_ref_transaction(&transaction).unwrap()
            )
            .unwrap(),
            transaction
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
}
