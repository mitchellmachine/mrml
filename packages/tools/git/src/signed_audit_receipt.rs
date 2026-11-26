//! Purpose-separated authenticated audit receipts for protected receive.

use crate::git_file_root::GitFileRoot;
use mrml_crypto::{Sha256, ed25519_verify};
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_is_directory,
};

use crate::{
    ActivationSnapshot, AuditReceipt, AuthorityCandidateContext, DurableFailure,
    DurableReceiveStore, LinuxDurableReceiveStore, ProtectedReceiveAuthority,
    QuarantineTransaction, QuarantineTransactionId, VerifiedRefTransaction, encode_audit_receipt,
    parse_audit_receipt,
};

const MAGIC: &[u8; 8] = b"MRARCP01";
const DOMAIN: &[u8] = b"MRML-GIT-AUDIT-RECEIPT-V1\0";
const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"MRML git authority receipt signing v1";
const MAX_SIGNATURE_BYTES: usize = 32 * 1024;
pub const MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES: usize =
    crate::MAX_AUDIT_RECEIPT_BYTES + MAX_SIGNATURE_BYTES + 128;

pub trait AuditReceiptAuthority {
    fn signer_identity(&self) -> [u8; 64];
    fn sign(&mut self, transcript: &[u8], output: &mut [u8]) -> Result<usize, ()>;
    fn verify(&mut self, transcript: &[u8], signature: &[u8]) -> Result<(), ()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAuditReceipt {
    pub receipt: AuditReceipt,
    pub signer_identity: [u8; 64],
    pub signature: Vector<u8>,
}

/// Verify that an authority-authenticated receipt advances exactly the signer
/// state that authorized the just-completed protected push. Receipt bytes are
/// data until this check succeeds; the relay has no generation authority.
pub fn verify_signer_generation_advancement(
    encoded: &[u8],
    authority_public_key: &[u8; 32],
    authority_identity: &[u8; 64],
    repository: &crate::RepositoryIdentity,
    repository_generation: crate::RepositoryGeneration,
    trust_generation: crate::TrustGeneration,
    revocation_generation: crate::RevocationGeneration,
) -> Result<crate::RepositoryGeneration, DurableFailure> {
    let authenticated = parse_authenticated_audit_receipt(encoded)?;
    if &authenticated.signer_identity != authority_identity
        || &authenticated.receipt.repository != repository
        || authenticated.receipt.repository_generation != repository_generation
        || authenticated.receipt.trust_generation != trust_generation
        || authenticated.receipt.revocation_generation != revocation_generation
        || authenticated.receipt.activated_repository_generation.0
            != repository_generation
                .0
                .checked_add(1)
                .ok_or(DurableFailure::AuditReceipt)?
    {
        return Err(DurableFailure::AuditReceipt);
    }
    let signature: &[u8; 64] = (&authenticated.signature[..])
        .try_into()
        .map_err(|_| DurableFailure::AuditReceipt)?;
    let canonical =
        encode_audit_receipt(&authenticated.receipt).map_err(|_| DurableFailure::AuditReceipt)?;
    let transcript = authenticated_audit_receipt_transcript(&canonical)
        .and_then(|transcript| authority_receipt_signature_transcript(&transcript))
        .map_err(|_| DurableFailure::AuditReceipt)?;
    if !ed25519_verify(authority_public_key, &transcript, signature) {
        return Err(DurableFailure::AuditReceipt);
    }
    Ok(authenticated.receipt.activated_repository_generation)
}

pub struct AuthenticatedAuditReceiptDirectory {
    root: Text,
    retained: GitFileRoot,
}

impl AuthenticatedAuditReceiptDirectory {
    pub fn open(path: &str) -> Result<Self, DurableFailure> {
        create_dir_all(path).map_err(|_| DurableFailure::DiskFull)?;
        let root = canonical_path(path).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&root) {
            return Err(DurableFailure::Rename);
        }
        Ok(Self {
            root,
            retained: GitFileRoot::Ambient,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn open_capability(
        root: mrml_runtime::DirectoryCapability,
    ) -> Result<Self, DurableFailure> {
        let metadata = root.metadata().map_err(|_| DurableFailure::AuditReceipt)?;
        if metadata.mode & 0o777 != 0o700 {
            return Err(DurableFailure::AuditReceipt);
        }
        Ok(Self {
            root: Text::new(),
            retained: GitFileRoot::Retained(root),
        })
    }

    pub fn append(
        &self,
        receipt: &AuditReceipt,
        authority: &mut dyn AuditReceiptAuthority,
    ) -> Result<(), DurableFailure> {
        let canonical = encode_audit_receipt(receipt).map_err(|_| DurableFailure::AuditReceipt)?;
        let transcript = authenticated_audit_receipt_transcript(&canonical)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        let mut signature = [0u8; MAX_SIGNATURE_BYTES];
        let signature_len = authority
            .sign(&transcript, &mut signature)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        if signature_len == 0 || signature_len > signature.len() {
            return Err(DurableFailure::AuditReceipt);
        }
        authority
            .verify(&transcript, &signature[..signature_len])
            .map_err(|_| DurableFailure::AuditReceipt)?;
        let encoded = encode_authenticated(
            &canonical,
            authority.signer_identity(),
            &signature[..signature_len],
        )?;
        let name = receipt_name(receipt.transaction);
        let mut file = self.create_file(&name)?;
        file.write_all(&encoded)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        file.sync().map_err(|_| DurableFailure::AuditReceipt)?;
        drop(file);
        self.sync()?;
        let reopened = self.load(receipt.transaction, authority)?;
        if reopened.receipt != *receipt || reopened.signer_identity != authority.signer_identity() {
            return Err(DurableFailure::AuditReceipt);
        }
        Ok(())
    }

    pub fn load(
        &self,
        transaction: QuarantineTransactionId,
        authority: &mut dyn AuditReceiptAuthority,
    ) -> Result<AuthenticatedAuditReceipt, DurableFailure> {
        let mut file = self.open_file(&receipt_name(transaction))?;
        let length = usize::try_from(file.len().map_err(|_| DurableFailure::AuditReceipt)?)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        if length > MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES {
            return Err(DurableFailure::AuditReceipt);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        let authenticated = parse_authenticated_audit_receipt(&bytes)?;
        if authenticated.receipt.transaction != transaction
            || authenticated.signer_identity != authority.signer_identity()
        {
            return Err(DurableFailure::AuditReceipt);
        }
        let canonical = encode_audit_receipt(&authenticated.receipt)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        authority
            .verify(
                &authenticated_audit_receipt_transcript(&canonical)
                    .map_err(|_| DurableFailure::AuditReceipt)?,
                &authenticated.signature,
            )
            .map_err(|_| DurableFailure::AuditReceipt)?;
        Ok(authenticated)
    }

    fn create_file(&self, name: &str) -> Result<File, DurableFailure> {
        match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => {
                let file = root
                    .create_new_file(name, 0o600)
                    .map_err(|_| DurableFailure::AuditReceipt)?;
                validate_authenticated_receipt_file(root, &file)?;
                Ok(file)
            }
            GitFileRoot::Ambient => File::create_new(&join_path(&self.root, name))
                .map_err(|_| DurableFailure::AuditReceipt),
        }
    }

    fn open_file(&self, name: &str) -> Result<File, DurableFailure> {
        match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => {
                let file = root
                    .open_regular(name)
                    .map_err(|_| DurableFailure::AuditReceipt)?;
                validate_authenticated_receipt_file(root, &file)?;
                Ok(file)
            }
            GitFileRoot::Ambient => File::open_regular(&join_path(&self.root, name))
                .map_err(|_| DurableFailure::AuditReceipt),
        }
    }

    fn sync(&self) -> Result<(), DurableFailure> {
        match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => root.sync().map_err(|_| DurableFailure::AuditReceipt),
            GitFileRoot::Ambient => sync_directory(&self.root),
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_authenticated_receipt_file(
    root: &mrml_runtime::DirectoryCapability,
    file: &File,
) -> Result<(), DurableFailure> {
    let parent = root.metadata().map_err(|_| DurableFailure::AuditReceipt)?;
    let metadata = file.metadata().map_err(|_| DurableFailure::AuditReceipt)?;
    if metadata.uid != parent.uid
        || metadata.gid != parent.gid
        || metadata.mode & 0o777 != 0o600
        || metadata.links != 1
    {
        return Err(DurableFailure::AuditReceipt);
    }
    Ok(())
}

pub struct AuthenticatedReceiveStore<'a> {
    inner: &'a mut LinuxDurableReceiveStore,
    receipts: AuthenticatedAuditReceiptDirectory,
    authority: ReceiveReceiptAuthority<'a>,
    last_authenticated_receipt: Option<Vector<u8>>,
}

enum ReceiveReceiptAuthority<'a> {
    Receipt(&'a mut dyn AuditReceiptAuthority),
    Candidate {
        authority: &'a mut dyn ProtectedReceiveAuthority,
        context: AuthorityCandidateContext,
        completed: bool,
    },
}

impl ReceiveReceiptAuthority<'_> {
    fn receipt(&mut self) -> &mut dyn AuditReceiptAuthority {
        match self {
            Self::Receipt(authority) => *authority,
            Self::Candidate { authority, .. } => *authority,
        }
    }
}

impl<'a> AuthenticatedReceiveStore<'a> {
    pub fn new_with_receipts(
        inner: &'a mut LinuxDurableReceiveStore,
        receipts: AuthenticatedAuditReceiptDirectory,
        authority: &'a mut dyn AuditReceiptAuthority,
    ) -> Self {
        Self {
            inner,
            receipts,
            authority: ReceiveReceiptAuthority::Receipt(authority),
            last_authenticated_receipt: None,
        }
    }

    pub fn new(
        inner: &'a mut LinuxDurableReceiveStore,
        signed_receipts_path: &str,
        authority: &'a mut dyn AuditReceiptAuthority,
    ) -> Result<Self, DurableFailure> {
        Ok(Self::new_with_receipts(
            inner,
            AuthenticatedAuditReceiptDirectory::open(signed_receipts_path)?,
            authority,
        ))
    }

    pub fn new_candidate(
        inner: &'a mut LinuxDurableReceiveStore,
        signed_receipts_path: &str,
        authority: &'a mut dyn ProtectedReceiveAuthority,
        context: AuthorityCandidateContext,
    ) -> Result<Self, DurableFailure> {
        Ok(Self::new_candidate_with_receipts(
            inner,
            AuthenticatedAuditReceiptDirectory::open(signed_receipts_path)?,
            authority,
            context,
        ))
    }

    pub(crate) fn new_candidate_with_receipts(
        inner: &'a mut LinuxDurableReceiveStore,
        receipts: AuthenticatedAuditReceiptDirectory,
        authority: &'a mut dyn ProtectedReceiveAuthority,
        context: AuthorityCandidateContext,
    ) -> Self {
        Self {
            inner,
            receipts,
            authority: ReceiveReceiptAuthority::Candidate {
                authority,
                context,
                completed: false,
            },
            last_authenticated_receipt: None,
        }
    }

    /// Recovers only a post-activation receipt after the concrete store has
    /// re-read and exact-matched live generations and refs. An existing signed
    /// receipt must verify byte-for-byte; journal contents never authorize a
    /// ref transition or a new signer identity.
    pub fn recover_audit_receipt(
        &mut self,
        journal: &crate::ReceiveJournalRecord,
    ) -> Result<AuthenticatedAuditReceipt, DurableFailure> {
        let receipt = self.inner.recovery_audit_receipt(journal)?;
        match self
            .receipts
            .load(journal.transaction, self.authority.receipt())
        {
            Ok(existing) if existing.receipt == receipt => return Ok(existing),
            Ok(_) => return Err(DurableFailure::AuditReceipt),
            Err(DurableFailure::AuditReceipt) => {}
            Err(error) => return Err(error),
        }
        self.receipts.append(&receipt, self.authority.receipt())?;
        let recovered = self
            .receipts
            .load(journal.transaction, self.authority.receipt())?;
        if recovered.receipt != receipt {
            return Err(DurableFailure::AuditReceipt);
        }
        Ok(recovered)
    }
}

impl DurableReceiveStore for AuthenticatedReceiveStore<'_> {
    fn persist_journal_and_fsync(
        &mut self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        self.inner.persist_journal_and_fsync(transaction, verified)
    }

    fn install_arrival_pack_and_fsync(
        &mut self,
        transaction: QuarantineTransactionId,
    ) -> Result<(), DurableFailure> {
        self.inner.install_arrival_pack_and_fsync(transaction)
    }

    fn reread_activation_snapshot(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActivationSnapshot, DurableFailure> {
        self.inner.reread_activation_snapshot(verified)
    }

    fn activate_refs_atomically_and_fsync(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        if let ReceiveReceiptAuthority::Candidate {
            authority, context, ..
        } = &mut self.authority
        {
            authority
                .start_candidate_activation(context)
                .map_err(|_| DurableFailure::AuditReceipt)?;
            self.inner.activate_refs_atomically_and_fsync(verified)?;
            authority
                .commit_candidate(context)
                .map_err(|_| DurableFailure::AuditReceipt)
        } else {
            self.inner.activate_refs_atomically_and_fsync(verified)
        }
    }

    fn append_audit_receipt_and_fsync(
        &mut self,
        receipt: &AuditReceipt,
    ) -> Result<(), DurableFailure> {
        self.receipts.append(receipt, self.authority.receipt())?;
        let canonical = encode_audit_receipt(receipt).map_err(|_| DurableFailure::AuditReceipt)?;
        let authenticated = self
            .receipts
            .load(receipt.transaction, self.authority.receipt())?;
        self.last_authenticated_receipt = Some(encode_authenticated(
            &canonical,
            authenticated.signer_identity,
            &authenticated.signature,
        )?);
        Ok(())
    }

    fn authenticated_audit_receipt(&self, transaction: QuarantineTransactionId) -> Option<&[u8]> {
        self.last_authenticated_receipt
            .as_ref()
            .filter(|_| {
                self.last_authenticated_receipt
                    .as_ref()
                    .and_then(|bytes| parse_authenticated_audit_receipt(bytes).ok())
                    .is_some_and(|receipt| receipt.receipt.transaction == transaction)
            })
            .map(|bytes| &bytes[..])
    }

    fn mark_complete_and_fsync(
        &mut self,
        transaction: QuarantineTransactionId,
    ) -> Result<(), DurableFailure> {
        if let ReceiveReceiptAuthority::Candidate {
            authority,
            context,
            completed,
        } = &mut self.authority
        {
            authority
                .complete_candidate(context)
                .map_err(|_| DurableFailure::AuditReceipt)?;
            *completed = true;
        }
        self.inner.mark_complete_and_fsync(transaction)
    }
}

impl Drop for AuthenticatedReceiveStore<'_> {
    fn drop(&mut self) {
        if let ReceiveReceiptAuthority::Candidate {
            authority,
            context,
            completed: false,
        } = &mut self.authority
        {
            let _ = authority.abort_candidate(context);
        }
    }
}

pub fn authenticated_audit_receipt_transcript(canonical: &[u8]) -> Result<Vector<u8>, ()> {
    let length = u32::try_from(canonical.len()).map_err(|_| ())?;
    let mut output = Vector::new();
    output.try_extend_from_slice(DOMAIN).map_err(|_| ())?;
    output
        .try_extend_from_slice(&length.to_be_bytes())
        .map_err(|_| ())?;
    output.try_extend_from_slice(canonical).map_err(|_| ())?;
    Ok(output)
}

pub fn parse_authenticated_audit_receipt_transcript(
    transcript: &[u8],
) -> Result<AuditReceipt, DurableFailure> {
    let header = DOMAIN
        .len()
        .checked_add(4)
        .ok_or(DurableFailure::AuditReceipt)?;
    if transcript.len() < header || !transcript.starts_with(DOMAIN) {
        return Err(DurableFailure::AuditReceipt);
    }
    let length = u32::from_be_bytes(
        transcript[DOMAIN.len()..header]
            .try_into()
            .map_err(|_| DurableFailure::AuditReceipt)?,
    ) as usize;
    if header.checked_add(length) != Some(transcript.len()) {
        return Err(DurableFailure::AuditReceipt);
    }
    parse_audit_receipt(&transcript[header..]).map_err(|_| DurableFailure::AuditReceipt)
}

pub fn authority_receipt_signature_transcript(payload: &[u8]) -> Result<Vector<u8>, ()> {
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    let mut output = Vector::new();
    output
        .try_extend_from_slice(AUTHORITY_SIGNATURE_DOMAIN)
        .and_then(|_| output.try_extend_from_slice(&length.to_be_bytes()))
        .and_then(|_| output.try_extend_from_slice(payload))
        .map_err(|_| ())?;
    Ok(output)
}

pub fn encode_authenticated_audit_receipt(
    authenticated: &AuthenticatedAuditReceipt,
) -> Result<Vector<u8>, DurableFailure> {
    let canonical =
        encode_audit_receipt(&authenticated.receipt).map_err(|_| DurableFailure::AuditReceipt)?;
    encode_authenticated(
        &canonical,
        authenticated.signer_identity,
        &authenticated.signature,
    )
}

fn encode_authenticated(
    canonical: &[u8],
    signer_identity: [u8; 64],
    signature: &[u8],
) -> Result<Vector<u8>, DurableFailure> {
    if canonical.len() > crate::MAX_AUDIT_RECEIPT_BYTES
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(DurableFailure::AuditReceipt);
    }
    let mut output = Vector::new();
    output
        .try_extend_from_slice(MAGIC)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    output
        .try_extend_from_slice(&signer_identity)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    output
        .try_extend_from_slice(&(canonical.len() as u32).to_be_bytes())
        .map_err(|_| DurableFailure::AuditReceipt)?;
    output
        .try_extend_from_slice(canonical)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    output
        .try_extend_from_slice(&(signature.len() as u16).to_be_bytes())
        .map_err(|_| DurableFailure::AuditReceipt)?;
    output
        .try_extend_from_slice(signature)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    let checksum = Sha256::digest(&output);
    output
        .try_extend_from_slice(&checksum)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    Ok(output)
}

pub fn parse_authenticated_audit_receipt(
    input: &[u8],
) -> Result<AuthenticatedAuditReceipt, DurableFailure> {
    if input.len() < 8 + 64 + 4 + 2 + 32 || input.len() > MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES {
        return Err(DurableFailure::AuditReceipt);
    }
    let body_len = input.len() - 32;
    if Sha256::digest(&input[..body_len]) != input[body_len..] {
        return Err(DurableFailure::AuditReceipt);
    }
    let mut cursor = 0usize;
    if take(input, &mut cursor, 8)? != MAGIC {
        return Err(DurableFailure::AuditReceipt);
    }
    let mut signer_identity = [0u8; 64];
    signer_identity.copy_from_slice(take(input, &mut cursor, 64)?);
    if signer_identity == [0u8; 64] {
        return Err(DurableFailure::AuditReceipt);
    }
    let receipt_len = u32::from_be_bytes(
        take(input, &mut cursor, 4)?
            .try_into()
            .map_err(|_| DurableFailure::AuditReceipt)?,
    ) as usize;
    let receipt = parse_audit_receipt(take(input, &mut cursor, receipt_len)?)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    let signature_len = u16::from_be_bytes(
        take(input, &mut cursor, 2)?
            .try_into()
            .map_err(|_| DurableFailure::AuditReceipt)?,
    ) as usize;
    if signature_len == 0 || signature_len > MAX_SIGNATURE_BYTES {
        return Err(DurableFailure::AuditReceipt);
    }
    let mut signature = Vector::new();
    signature
        .try_extend_from_slice(take(input, &mut cursor, signature_len)?)
        .map_err(|_| DurableFailure::AuditReceipt)?;
    if cursor != body_len {
        return Err(DurableFailure::AuditReceipt);
    }
    Ok(AuthenticatedAuditReceipt {
        receipt,
        signer_identity,
        signature,
    })
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], DurableFailure> {
    let end = cursor
        .checked_add(length)
        .ok_or(DurableFailure::AuditReceipt)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(DurableFailure::AuditReceipt)?;
    *cursor = end;
    Ok(bytes)
}

fn receipt_name(transaction: QuarantineTransactionId) -> Text {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Text::new();
    for byte in transaction.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output.push_str(".authenticated-receipt");
    output
}

#[cfg(unix)]
fn sync_directory(path: &str) -> Result<(), DurableFailure> {
    mrml_runtime::sync_directory(path).map_err(|_| DurableFailure::AuditReceipt)
}

#[cfg(not(unix))]
fn sync_directory(_: &str) -> Result<(), DurableFailure> {
    Err(DurableFailure::AuditReceipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::{
        ActiveRefFile, ActiveRefState, FullRefName, LinuxDurableReceiveStore, ObjectFormat,
        ObjectId, PackGeneration, QuarantinePhase, ReceiveJournalRecord, RepositoryGeneration,
        RepositoryIdentity, RevocationGeneration, TrustGeneration,
    };

    struct DigestAuthority {
        identity: [u8; 64],
    }

    impl AuditReceiptAuthority for DigestAuthority {
        fn signer_identity(&self) -> [u8; 64] {
            self.identity
        }

        fn sign(&mut self, transcript: &[u8], output: &mut [u8]) -> Result<usize, ()> {
            let signature = Sha256::digest(transcript);
            output
                .get_mut(..signature.len())
                .ok_or(())?
                .copy_from_slice(&signature);
            Ok(signature.len())
        }

        fn verify(&mut self, transcript: &[u8], signature: &[u8]) -> Result<(), ()> {
            (Sha256::digest(transcript).as_slice() == signature)
                .then_some(())
                .ok_or(())
        }
    }

    fn fixture() -> AuditReceipt {
        AuditReceipt {
            transaction: QuarantineTransactionId([29u8; 16]),
            repository: RepositoryIdentity::parse("owner/repository").unwrap(),
            repository_generation: RepositoryGeneration(41),
            activated_repository_generation: RepositoryGeneration(42),
            trust_generation: TrustGeneration(43),
            revocation_generation: RevocationGeneration(44),
            updates: [(
                FullRefName::parse("refs/heads/main").unwrap(),
                ObjectId::Sha256([1u8; 32]),
                ObjectId::Sha256([2u8; 32]),
            )]
            .into(),
        }
    }

    #[test]
    fn authenticated_encoding_rejects_storage_and_signature_tampering() {
        let receipt = fixture();
        let canonical = encode_audit_receipt(&receipt).unwrap();
        let signed_transcript = authenticated_audit_receipt_transcript(&canonical).unwrap();
        assert_eq!(
            parse_authenticated_audit_receipt_transcript(&signed_transcript),
            Ok(receipt.clone())
        );
        let mut malformed_transcript = signed_transcript.clone();
        malformed_transcript.push(0);
        assert_eq!(
            parse_authenticated_audit_receipt_transcript(&malformed_transcript),
            Err(DurableFailure::AuditReceipt)
        );
        let mut authority = DigestAuthority {
            identity: [7u8; 64],
        };
        let mut signature = [0u8; 32];
        authority.sign(&signed_transcript, &mut signature).unwrap();
        let encoded = encode_authenticated(&canonical, authority.identity, &signature).unwrap();
        let parsed = parse_authenticated_audit_receipt(&encoded).unwrap();
        assert_eq!(parsed.receipt, receipt);
        authority
            .verify(&signed_transcript, &parsed.signature)
            .unwrap();

        let mut storage_tamper = encoded.clone();
        storage_tamper[20] ^= 1;
        assert_eq!(
            parse_authenticated_audit_receipt(&storage_tamper),
            Err(DurableFailure::AuditReceipt)
        );

        let mut signature_tamper = signature;
        signature_tamper[0] ^= 1;
        let resigned_container =
            encode_authenticated(&canonical, authority.identity, &signature_tamper).unwrap();
        let parsed = parse_authenticated_audit_receipt(&resigned_container).unwrap();
        assert_eq!(
            authority.verify(&signed_transcript, &parsed.signature),
            Err(())
        );
    }

    #[test]
    fn signer_advancement_requires_exact_state_and_authority_signature() {
        let receipt = fixture();
        let canonical = encode_audit_receipt(&receipt).unwrap();
        let transcript = authenticated_audit_receipt_transcript(&canonical).unwrap();
        let seed = [91u8; 32];
        let public = mrml_crypto::ed25519_public(&seed);
        let authority_transcript = authority_receipt_signature_transcript(&transcript).unwrap();
        let signature = mrml_crypto::ed25519_sign(&seed, &authority_transcript);
        let identity = [17u8; 64];
        let encoded = encode_authenticated(&canonical, identity, &signature).unwrap();
        assert_eq!(
            verify_signer_generation_advancement(
                &encoded,
                &public,
                &identity,
                &receipt.repository,
                receipt.repository_generation,
                receipt.trust_generation,
                receipt.revocation_generation,
            ),
            Ok(receipt.activated_repository_generation)
        );
        assert_eq!(
            verify_signer_generation_advancement(
                &encoded,
                &public,
                &identity,
                &receipt.repository,
                receipt.activated_repository_generation,
                receipt.trust_generation,
                receipt.revocation_generation,
            ),
            Err(DurableFailure::AuditReceipt)
        );
        let mut wrong_public = public;
        wrong_public[0] ^= 1;
        assert_eq!(
            verify_signer_generation_advancement(
                &encoded,
                &wrong_public,
                &identity,
                &receipt.repository,
                receipt.repository_generation,
                receipt.trust_generation,
                receipt.revocation_generation,
            ),
            Err(DurableFailure::AuditReceipt)
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_directory_persists_and_reopens_only_self_verified_receipts() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!(
                "mrml-authenticated-receipts-{}",
                mrml_runtime::process_id()
            ),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let directory = AuthenticatedAuditReceiptDirectory::open(&root).unwrap();
        let receipt = fixture();
        let mut authority = DigestAuthority {
            identity: [7u8; 64],
        };
        directory.append(&receipt, &mut authority).unwrap();
        assert_eq!(
            directory
                .load(receipt.transaction, &mut authority)
                .unwrap()
                .receipt,
            receipt
        );
        assert_eq!(
            directory.append(&receipt, &mut authority),
            Err(DurableFailure::AuditReceipt)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn retained_authenticated_receipt_root_survives_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!(
                "mrml-authenticated-receipts-retained-{}",
                mrml_runtime::process_id()
            ),
        );
        let displaced = mrml_runtime::mrml_format!("{root}-displaced");
        let _ = mrml_runtime::remove_dir_all(&root);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        mrml_runtime::create_dir_all(&root).unwrap();
        std::fs::set_permissions(root.as_str(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let capability = mrml_runtime::DirectoryCapability::open_root(&root).unwrap();
        let directory = AuthenticatedAuditReceiptDirectory::open_capability(capability).unwrap();
        mrml_runtime::rename_file(&root, &displaced).unwrap();
        mrml_runtime::create_dir_all(&root).unwrap();
        std::fs::set_permissions(root.as_str(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let receipt = fixture();
        let mut authority = DigestAuthority {
            identity: [7u8; 64],
        };
        directory.append(&receipt, &mut authority).unwrap();
        assert_eq!(
            directory
                .load(receipt.transaction, &mut authority)
                .unwrap()
                .receipt,
            receipt
        );
        assert!(mrml_runtime::path_exists(&join_path(
            &displaced,
            &receipt_name(receipt.transaction),
        )));
        assert!(!mrml_runtime::path_exists(&join_path(
            &root,
            &receipt_name(receipt.transaction),
        )));
        mrml_runtime::remove_dir_all(&root).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn protected_recovery_exact_matches_live_state_and_is_idempotently_signed() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!(
                "mrml-authenticated-recovery-{}",
                mrml_runtime::process_id()
            ),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let name = FullRefName::parse("refs/heads/main").unwrap();
        let old = ObjectId::Sha256([1u8; 32]);
        let new = ObjectId::Sha256([2u8; 32]);
        let refs_path = join_path(&root, "refs");
        ActiveRefFile::initialize(
            &refs_path,
            &ActiveRefState {
                repository: repository.clone(),
                repository_generation: RepositoryGeneration(42),
                trust_generation: TrustGeneration(43),
                revocation_generation: RevocationGeneration(44),
                pack_generation: PackGeneration(2),
                pack_set_digest: [3u8; 32],
                object_format: ObjectFormat::Sha256,
                default_branch: name.clone(),
                refs: [(name.clone(), new)].into(),
            },
        )
        .unwrap();
        let journal = ReceiveJournalRecord {
            transaction: QuarantineTransactionId([29u8; 16]),
            repository,
            repository_generation: RepositoryGeneration(41),
            trust_generation: TrustGeneration(43),
            revocation_generation: RevocationGeneration(44),
            phase: QuarantinePhase::RefsAtomicallyActivated,
            failure: None,
            updates: [crate::JournalRefUpdate {
                name,
                expected_old: old,
                proposed_new: new,
            }]
            .into(),
        };
        let mut inner = LinuxDurableReceiveStore::open(
            &join_path(&root, "journals"),
            &join_path(&root, "packs"),
            &refs_path,
            &join_path(&root, "plain-receipts"),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        let mut authority = DigestAuthority {
            identity: [7u8; 64],
        };
        let mut protected = AuthenticatedReceiveStore::new(
            &mut inner,
            &join_path(&root, "signed-receipts"),
            &mut authority,
        )
        .unwrap();
        let first = protected.recover_audit_receipt(&journal).unwrap();
        let second = protected.recover_audit_receipt(&journal).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.receipt, fixture());
        assert_eq!(first.signer_identity, [7u8; 64]);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
