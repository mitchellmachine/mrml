//! Purpose-separated authenticated audit receipts for protected receive.

use mrml_crypto::Sha256;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
};

use crate::{
    ActivationSnapshot, AuditReceipt, DurableFailure, DurableReceiveStore,
    LinuxDurableReceiveStore, QuarantineTransaction, QuarantineTransactionId,
    VerifiedRefTransaction, encode_audit_receipt, parse_audit_receipt,
};

const MAGIC: &[u8; 8] = b"MRARCP01";
const DOMAIN: &[u8] = b"MRML-GIT-AUDIT-RECEIPT-V1\0";
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

pub struct AuthenticatedAuditReceiptDirectory {
    root: Text,
}

impl AuthenticatedAuditReceiptDirectory {
    pub fn open(path: &str) -> Result<Self, DurableFailure> {
        create_dir_all(path).map_err(|_| DurableFailure::DiskFull)?;
        let root = canonical_path(path).map_err(|_| DurableFailure::Rename)?;
        if !path_is_directory(&root) {
            return Err(DurableFailure::Rename);
        }
        Ok(Self { root })
    }

    pub fn append(
        &self,
        receipt: &AuditReceipt,
        authority: &mut dyn AuditReceiptAuthority,
    ) -> Result<(), DurableFailure> {
        let canonical = encode_audit_receipt(receipt).map_err(|_| DurableFailure::AuditReceipt)?;
        let transcript = transcript(&canonical).map_err(|_| DurableFailure::AuditReceipt)?;
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
        let path = join_path(&self.root, &receipt_name(receipt.transaction));
        if path_exists(&path) {
            return Err(DurableFailure::AuditReceipt);
        }
        let mut file = File::create_new(&path).map_err(|_| DurableFailure::AuditReceipt)?;
        file.write_all(&encoded)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        file.sync().map_err(|_| DurableFailure::AuditReceipt)?;
        drop(file);
        sync_directory(&self.root)?;
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
        let path = join_path(&self.root, &receipt_name(transaction));
        let mut file = File::open_regular(&path).map_err(|_| DurableFailure::AuditReceipt)?;
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
        let authenticated = parse_authenticated(&bytes)?;
        if authenticated.receipt.transaction != transaction
            || authenticated.signer_identity != authority.signer_identity()
        {
            return Err(DurableFailure::AuditReceipt);
        }
        let canonical = encode_audit_receipt(&authenticated.receipt)
            .map_err(|_| DurableFailure::AuditReceipt)?;
        authority
            .verify(
                &transcript(&canonical).map_err(|_| DurableFailure::AuditReceipt)?,
                &authenticated.signature,
            )
            .map_err(|_| DurableFailure::AuditReceipt)?;
        Ok(authenticated)
    }
}

pub struct AuthenticatedReceiveStore<'a> {
    inner: &'a mut LinuxDurableReceiveStore,
    receipts: AuthenticatedAuditReceiptDirectory,
    authority: &'a mut dyn AuditReceiptAuthority,
}

impl<'a> AuthenticatedReceiveStore<'a> {
    pub fn new(
        inner: &'a mut LinuxDurableReceiveStore,
        signed_receipts_path: &str,
        authority: &'a mut dyn AuditReceiptAuthority,
    ) -> Result<Self, DurableFailure> {
        Ok(Self {
            inner,
            receipts: AuthenticatedAuditReceiptDirectory::open(signed_receipts_path)?,
            authority,
        })
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
        self.inner.activate_refs_atomically_and_fsync(verified)
    }

    fn append_audit_receipt_and_fsync(
        &mut self,
        receipt: &AuditReceipt,
    ) -> Result<(), DurableFailure> {
        self.receipts.append(receipt, self.authority)
    }
}

fn transcript(canonical: &[u8]) -> Result<Vector<u8>, ()> {
    let length = u32::try_from(canonical.len()).map_err(|_| ())?;
    let mut output = Vector::new();
    output.try_extend_from_slice(DOMAIN).map_err(|_| ())?;
    output
        .try_extend_from_slice(&length.to_be_bytes())
        .map_err(|_| ())?;
    output.try_extend_from_slice(canonical).map_err(|_| ())?;
    Ok(output)
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

fn parse_authenticated(input: &[u8]) -> Result<AuthenticatedAuditReceipt, DurableFailure> {
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
    use crate::{
        FullRefName, ObjectId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        TrustGeneration,
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
        let signed_transcript = transcript(&canonical).unwrap();
        let mut authority = DigestAuthority {
            identity: [7u8; 64],
        };
        let mut signature = [0u8; 32];
        authority.sign(&signed_transcript, &mut signature).unwrap();
        let encoded = encode_authenticated(&canonical, authority.identity, &signature).unwrap();
        let parsed = parse_authenticated(&encoded).unwrap();
        assert_eq!(parsed.receipt, receipt);
        authority
            .verify(&signed_transcript, &parsed.signature)
            .unwrap();

        let mut storage_tamper = encoded.clone();
        storage_tamper[20] ^= 1;
        assert_eq!(
            parse_authenticated(&storage_tamper),
            Err(DurableFailure::AuditReceipt)
        );

        let mut signature_tamper = signature;
        signature_tamper[0] ^= 1;
        let resigned_container =
            encode_authenticated(&canonical, authority.identity, &signature_tamper).unwrap();
        let parsed = parse_authenticated(&resigned_container).unwrap();
        assert_eq!(
            authority.verify(&signed_transcript, &parsed.signature),
            Err(())
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
}
