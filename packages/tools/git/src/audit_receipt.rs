//! Canonical bounded audit-receipt transcript and immutable persistence.

use mrml_crypto::Sha256;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
};

use crate::{
    AuditReceipt, DurableFailure, FullRefName, GitdCoreError, ObjectFormat, ObjectId,
    QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    TrustGeneration,
};

const MAGIC: &[u8; 8] = b"MRRCPT01";
const DIGEST_BYTES: usize = 32;
pub const MAX_AUDIT_RECEIPT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReceiptError {
    Resource,
    Malformed,
    Integrity,
    Mismatch,
}

pub fn encode_audit_receipt(receipt: &AuditReceipt) -> Result<Vector<u8>, AuditReceiptError> {
    validate(receipt)?;
    let mut output = Vector::new();
    append(&mut output, MAGIC)?;
    append(&mut output, &receipt.transaction.0)?;
    append_text(&mut output, receipt.repository.as_str())?;
    for generation in [
        receipt.repository_generation.0,
        receipt.activated_repository_generation.0,
        receipt.trust_generation.0,
        receipt.revocation_generation.0,
    ] {
        append(&mut output, &generation.to_be_bytes())?;
    }
    append(
        &mut output,
        &u16::try_from(receipt.updates.len())
            .map_err(|_| AuditReceiptError::Resource)?
            .to_be_bytes(),
    )?;
    for (name, old, new) in &receipt.updates {
        append_text(&mut output, name.as_str())?;
        append(
            &mut output,
            &[match old.format() {
                ObjectFormat::Sha1 => 1,
                ObjectFormat::Sha256 => 2,
            }],
        )?;
        append(&mut output, old.as_bytes())?;
        append(&mut output, new.as_bytes())?;
    }
    if output
        .len()
        .checked_add(DIGEST_BYTES)
        .ok_or(AuditReceiptError::Resource)?
        > MAX_AUDIT_RECEIPT_BYTES
    {
        return Err(AuditReceiptError::Resource);
    }
    let digest = Sha256::digest(&output);
    append(&mut output, &digest)?;
    Ok(output)
}

pub fn parse_audit_receipt(input: &[u8]) -> Result<AuditReceipt, AuditReceiptError> {
    if input.len() < MAGIC.len() + DIGEST_BYTES || input.len() > MAX_AUDIT_RECEIPT_BYTES {
        return Err(AuditReceiptError::Malformed);
    }
    let body_len = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..body_len]) != input[body_len..] {
        return Err(AuditReceiptError::Integrity);
    }
    let mut cursor = Cursor::new(&input[..body_len]);
    if cursor.take(MAGIC.len())? != MAGIC {
        return Err(AuditReceiptError::Malformed);
    }
    let mut transaction = [0u8; 16];
    transaction.copy_from_slice(cursor.take(16)?);
    if transaction == [0u8; 16] {
        return Err(AuditReceiptError::Malformed);
    }
    let repository = RepositoryIdentity::parse(cursor.text()?).map_err(map_identifier)?;
    let repository_generation = RepositoryGeneration(cursor.nonzero_u64()?);
    let activated_repository_generation = RepositoryGeneration(cursor.nonzero_u64()?);
    let trust_generation = TrustGeneration(cursor.nonzero_u64()?);
    let revocation_generation = RevocationGeneration(cursor.nonzero_u64()?);
    let count = usize::from(cursor.u16()?);
    if count == 0 || count > crate::MAX_REFS_PER_TRANSACTION {
        return Err(AuditReceiptError::Malformed);
    }
    let mut updates = Vector::new();
    updates
        .try_reserve_exact(count)
        .map_err(|_| AuditReceiptError::Resource)?;
    for _ in 0..count {
        let name = FullRefName::parse(cursor.text()?).map_err(map_identifier)?;
        let format = match cursor.u8()? {
            1 => ObjectFormat::Sha1,
            2 => ObjectFormat::Sha256,
            _ => return Err(AuditReceiptError::Malformed),
        };
        let old = ObjectId::from_bytes(format, cursor.take(format.hash_len())?)
            .ok_or(AuditReceiptError::Malformed)?;
        let new = ObjectId::from_bytes(format, cursor.take(format.hash_len())?)
            .ok_or(AuditReceiptError::Malformed)?;
        updates.push((name, old, new));
    }
    if !cursor.is_empty() {
        return Err(AuditReceiptError::Malformed);
    }
    let receipt = AuditReceipt {
        transaction: QuarantineTransactionId(transaction),
        repository,
        repository_generation,
        activated_repository_generation,
        trust_generation,
        revocation_generation,
        updates,
    };
    validate(&receipt)?;
    Ok(receipt)
}

fn validate(receipt: &AuditReceipt) -> Result<(), AuditReceiptError> {
    if receipt.transaction.0 == [0u8; 16]
        || receipt.repository_generation.0 == 0
        || receipt.activated_repository_generation.0
            != receipt
                .repository_generation
                .0
                .checked_add(1)
                .ok_or(AuditReceiptError::Resource)?
        || receipt.trust_generation.0 == 0
        || receipt.revocation_generation.0 == 0
        || receipt.updates.is_empty()
        || receipt.updates.len() > crate::MAX_REFS_PER_TRANSACTION
    {
        return Err(AuditReceiptError::Mismatch);
    }
    for (index, (name, old, new)) in receipt.updates.iter().enumerate() {
        if old.format() != new.format()
            || old.is_zero()
            || new.is_zero()
            || old == new
            || index > 0 && receipt.updates[index - 1].0.as_str() >= name.as_str()
        {
            return Err(AuditReceiptError::Mismatch);
        }
    }
    Ok(())
}

pub struct AuditReceiptDirectory {
    root: Text,
}
impl AuditReceiptDirectory {
    pub fn open(path: &str) -> Result<Self, DurableFailure> {
        create_dir_all(path).map_err(|_| DurableFailure::DiskFull)?;
        let root = canonical_path(path).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&root) {
            return Err(DurableFailure::Rename);
        }
        Ok(Self { root })
    }
    pub fn append(&self, receipt: &AuditReceipt) -> Result<(), DurableFailure> {
        let encoded = encode_audit_receipt(receipt).map_err(|_| DurableFailure::AuditReceipt)?;
        let path = join_path(&self.root, &receipt_name(receipt.transaction));
        if path_exists(&path) {
            return Err(DurableFailure::AuditReceipt);
        }
        let mut file = File::create_new(&path).map_err(|_| DurableFailure::AuditReceipt)?;
        file.write_all(&encoded)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        file.sync().map_err(|_| DurableFailure::AuditReceipt)?;
        drop(file);
        sync_receipt_directory(&self.root)?;
        if self
            .load(receipt.transaction)
            .map_err(|_| DurableFailure::AuditReceipt)?
            != *receipt
        {
            return Err(DurableFailure::AuditReceipt);
        }
        Ok(())
    }
    pub fn load(
        &self,
        transaction: QuarantineTransactionId,
    ) -> Result<AuditReceipt, AuditReceiptError> {
        let path = join_path(&self.root, &receipt_name(transaction));
        let mut file = File::open_regular(&path).map_err(|_| AuditReceiptError::Malformed)?;
        let length = usize::try_from(file.len().map_err(|_| AuditReceiptError::Malformed)?)
            .map_err(|_| AuditReceiptError::Resource)?;
        if length > MAX_AUDIT_RECEIPT_BYTES {
            return Err(AuditReceiptError::Resource);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| AuditReceiptError::Resource)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| AuditReceiptError::Malformed)?;
        let receipt = parse_audit_receipt(&bytes)?;
        if receipt.transaction != transaction {
            return Err(AuditReceiptError::Mismatch);
        }
        Ok(receipt)
    }
}

fn receipt_name(transaction: QuarantineTransactionId) -> Text {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Text::new();
    for byte in transaction.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output.push_str(".receipt");
    output
}
#[cfg(unix)]
fn sync_receipt_directory(path: &str) -> Result<(), DurableFailure> {
    mrml_runtime::sync_directory(path).map_err(|_| DurableFailure::AuditReceipt)
}
#[cfg(not(unix))]
fn sync_receipt_directory(_: &str) -> Result<(), DurableFailure> {
    Err(DurableFailure::AuditReceipt)
}
fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), AuditReceiptError> {
    if output
        .len()
        .checked_add(bytes.len())
        .ok_or(AuditReceiptError::Resource)?
        > MAX_AUDIT_RECEIPT_BYTES
    {
        return Err(AuditReceiptError::Resource);
    }
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| AuditReceiptError::Resource)
}
fn append_text(output: &mut Vector<u8>, text: &str) -> Result<(), AuditReceiptError> {
    append(
        output,
        &u16::try_from(text.len())
            .map_err(|_| AuditReceiptError::Resource)?
            .to_be_bytes(),
    )?;
    append(output, text.as_bytes())
}
fn map_identifier(_: GitdCoreError) -> AuditReceiptError {
    AuditReceiptError::Malformed
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], AuditReceiptError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AuditReceiptError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuditReceiptError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, AuditReceiptError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AuditReceiptError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| AuditReceiptError::Malformed)?,
        ))
    }
    fn nonzero_u64(&mut self) -> Result<u64, AuditReceiptError> {
        let value = u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| AuditReceiptError::Malformed)?,
        );
        if value == 0 {
            Err(AuditReceiptError::Malformed)
        } else {
            Ok(value)
        }
    }
    fn text(&mut self) -> Result<&'a str, AuditReceiptError> {
        let length = usize::from(self.u16()?);
        core::str::from_utf8(self.take(length)?).map_err(|_| AuditReceiptError::Malformed)
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> AuditReceipt {
        AuditReceipt {
            transaction: QuarantineTransactionId([13u8; 16]),
            repository: RepositoryIdentity::parse("owner/repository").unwrap(),
            repository_generation: RepositoryGeneration(7),
            activated_repository_generation: RepositoryGeneration(8),
            trust_generation: TrustGeneration(9),
            revocation_generation: RevocationGeneration(10),
            updates: [(
                FullRefName::parse("refs/heads/main").unwrap(),
                ObjectId::Sha256([1u8; 32]),
                ObjectId::Sha256([2u8; 32]),
            )]
            .into(),
        }
    }

    #[test]
    fn receipt_transcript_is_canonical_and_integrity_checked() {
        let receipt = fixture();
        let encoded = encode_audit_receipt(&receipt).unwrap();
        assert_eq!(parse_audit_receipt(&encoded), Ok(receipt));
        let mut tampered = encoded;
        tampered[20] ^= 1;
        assert_eq!(
            parse_audit_receipt(&tampered),
            Err(AuditReceiptError::Integrity)
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_receipt_is_immutable_fsynced_and_reopened() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-receipts-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let store = AuditReceiptDirectory::open(&root).unwrap();
        let receipt = fixture();
        store.append(&receipt).unwrap();
        assert_eq!(store.load(receipt.transaction), Ok(receipt.clone()));
        assert_eq!(store.append(&receipt), Err(DurableFailure::AuditReceipt));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
