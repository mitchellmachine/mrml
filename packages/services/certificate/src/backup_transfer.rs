use crate::{
    BackupDescriptor, BackupError, BackupRestoreTarget, DurableAuthenticator, MAX_BACKUP_BYTES,
    restore_backup, verify_backup,
};
use mrml_crypto::Sha256;

pub const MAX_BACKUP_TRANSFER_CHUNK: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupTransferError {
    InvalidTransfer,
    TransferInProgress,
    StaleTransfer,
    OutOfOrder,
    Incomplete,
    DigestMismatch,
    Backup(BackupError),
}

impl From<BackupError> for BackupTransferError {
    fn from(value: BackupError) -> Self {
        Self::Backup(value)
    }
}

#[derive(Clone, Copy)]
struct Upload {
    transfer_generation: u64,
    policy_generation: u64,
    total_bytes: usize,
    written: usize,
    expected_digest: [u8; 32],
    verified: Option<BackupDescriptor>,
}

/// Bounded sequential assembly for a backup carried through the 4 KiB
/// lifecycle request window. A transfer generation is authority-neutral replay
/// binding; the lifecycle route and authorizer still carry authority.
pub struct BackupUploadSession<'a> {
    bytes: &'a mut [u8],
    upload: Option<Upload>,
}

impl<'a> BackupUploadSession<'a> {
    pub fn new(storage: &'a mut [u8]) -> Result<Self, BackupTransferError> {
        let bytes = storage
            .get_mut(..MAX_BACKUP_BYTES)
            .ok_or(BackupTransferError::InvalidTransfer)?;
        bytes.fill(0);
        Ok(Self {
            bytes,
            upload: None,
        })
    }

    pub fn begin(
        &mut self,
        transfer_generation: u64,
        policy_generation: u64,
        total_bytes: usize,
        expected_digest: [u8; 32],
    ) -> Result<(), BackupTransferError> {
        if self.upload.is_some() {
            return Err(BackupTransferError::TransferInProgress);
        }
        if transfer_generation == 0
            || policy_generation == 0
            || total_bytes == 0
            || total_bytes > MAX_BACKUP_BYTES
            || expected_digest == [0; 32]
        {
            return Err(BackupTransferError::InvalidTransfer);
        }
        self.upload = Some(Upload {
            transfer_generation,
            policy_generation,
            total_bytes,
            written: 0,
            expected_digest,
            verified: None,
        });
        Ok(())
    }

    pub fn append(
        &mut self,
        transfer_generation: u64,
        offset: usize,
        chunk: &[u8],
    ) -> Result<usize, BackupTransferError> {
        let upload = self
            .upload
            .as_mut()
            .ok_or(BackupTransferError::StaleTransfer)?;
        if transfer_generation != upload.transfer_generation {
            return Err(BackupTransferError::StaleTransfer);
        }
        if upload.verified.is_some()
            || offset != upload.written
            || chunk.is_empty()
            || chunk.len() > MAX_BACKUP_TRANSFER_CHUNK
        {
            return Err(BackupTransferError::OutOfOrder);
        }
        let end = offset
            .checked_add(chunk.len())
            .filter(|end| *end <= upload.total_bytes)
            .ok_or(BackupTransferError::OutOfOrder)?;
        self.bytes[offset..end].copy_from_slice(chunk);
        upload.written = end;
        Ok(end)
    }

    pub fn verify(
        &mut self,
        transfer_generation: u64,
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<BackupDescriptor, BackupTransferError> {
        let upload = self
            .upload
            .as_mut()
            .ok_or(BackupTransferError::StaleTransfer)?;
        if transfer_generation != upload.transfer_generation {
            return Err(BackupTransferError::StaleTransfer);
        }
        if upload.written != upload.total_bytes {
            return Err(BackupTransferError::Incomplete);
        }
        let input = &self.bytes[..upload.total_bytes];
        if Sha256::digest(input) != upload.expected_digest {
            return Err(BackupTransferError::DigestMismatch);
        }
        let descriptor = verify_backup(input, authenticator)?;
        if descriptor.policy_generation != upload.policy_generation
            || descriptor.backup_digest != upload.expected_digest
        {
            return Err(BackupTransferError::DigestMismatch);
        }
        upload.verified = Some(descriptor);
        Ok(descriptor)
    }

    pub fn restore(
        &mut self,
        transfer_generation: u64,
        authenticator: &mut impl DurableAuthenticator,
        target: &mut impl BackupRestoreTarget,
    ) -> Result<BackupDescriptor, BackupTransferError> {
        let upload = self.upload.ok_or(BackupTransferError::StaleTransfer)?;
        if transfer_generation != upload.transfer_generation {
            return Err(BackupTransferError::StaleTransfer);
        }
        let expected = upload.verified.ok_or(BackupTransferError::Incomplete)?;
        let restored = restore_backup(&self.bytes[..upload.total_bytes], authenticator, target)?;
        if restored != expected {
            return Err(BackupTransferError::DigestMismatch);
        }
        self.clear();
        Ok(restored)
    }

    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.upload = None;
    }
}

impl Drop for BackupUploadSession<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{
        DurableError, DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
        create_backup,
    };

    struct Auth;
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError> {
            let mut hash = Sha256::new();
            hash.update(b"backup-transfer-test-key");
            hash.update(record);
            Ok(hash.finalize())
        }

        fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(self.authenticate(record)? == *tag)
        }
    }

    #[derive(Default)]
    struct Target {
        empty: bool,
        begun: bool,
        imported: usize,
        committed: bool,
    }

    impl BackupRestoreTarget for Target {
        fn require_empty(&mut self) -> Result<(), BackupError> {
            self.empty.then_some(()).ok_or(BackupError::TargetNotEmpty)
        }

        fn begin(&mut self, _: BackupDescriptor) -> Result<(), BackupError> {
            self.begun = true;
            Ok(())
        }

        fn import(&mut self, _: &DurableRecord) -> Result<(), BackupError> {
            self.imported += 1;
            Ok(())
        }

        fn commit(&mut self, _: BackupDescriptor) -> Result<(), BackupError> {
            self.committed = true;
            Ok(())
        }

        fn abort(&mut self) {
            self.begun = false;
        }
    }

    fn fixture() -> (std::vec::Vec<u8>, BackupDescriptor) {
        let mut auth = Auth;
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Account,
            DurableObjectId([7; 16]),
            0,
            &[0x33; 4096],
            &mut auth,
        )
        .unwrap();
        let mut encoded = std::vec![0; MAX_BACKUP_BYTES];
        let (written, descriptor) = create_backup(9, &[&record], &mut encoded, &mut auth).unwrap();
        encoded.truncate(written);
        (encoded, descriptor)
    }

    #[test]
    fn chunked_backup_verifies_then_restores_only_to_clean_target() {
        let (encoded, descriptor) = fixture();
        assert!(encoded.len() > MAX_BACKUP_TRANSFER_CHUNK);
        let mut storage = std::vec![0; MAX_BACKUP_BYTES];
        let mut session = BackupUploadSession::new(&mut storage).unwrap();
        session
            .begin(11, 9, encoded.len(), descriptor.backup_digest)
            .unwrap();
        for (index, chunk) in encoded.chunks(MAX_BACKUP_TRANSFER_CHUNK).enumerate() {
            session
                .append(11, index * MAX_BACKUP_TRANSFER_CHUNK, chunk)
                .unwrap();
        }
        assert!(session.verify(11, &mut Auth).unwrap() == descriptor);
        let mut nonempty = Target::default();
        assert!(matches!(
            session.restore(11, &mut Auth, &mut nonempty),
            Err(BackupTransferError::Backup(BackupError::TargetNotEmpty))
        ));
        let mut clean = Target {
            empty: true,
            ..Target::default()
        };
        assert!(session.restore(11, &mut Auth, &mut clean).unwrap() == descriptor);
        assert!(clean.begun && clean.committed && clean.imported == 1);
        assert!(matches!(
            session.verify(11, &mut Auth),
            Err(BackupTransferError::StaleTransfer)
        ));
    }

    #[test]
    fn transfer_rejects_replay_reordering_truncation_and_digest_substitution() {
        let (encoded, descriptor) = fixture();
        let mut storage = std::vec![0; MAX_BACKUP_BYTES];
        let mut session = BackupUploadSession::new(&mut storage).unwrap();
        session
            .begin(3, 9, encoded.len(), descriptor.backup_digest)
            .unwrap();
        assert!(matches!(
            session.append(4, 0, &encoded[..16]),
            Err(BackupTransferError::StaleTransfer)
        ));
        assert!(matches!(
            session.append(3, 1, &encoded[..16]),
            Err(BackupTransferError::OutOfOrder)
        ));
        session.append(3, 0, &encoded[..16]).unwrap();
        assert!(matches!(
            session.verify(3, &mut Auth),
            Err(BackupTransferError::Incomplete)
        ));
        session.clear();
        session.begin(5, 9, encoded.len(), [8; 32]).unwrap();
        for (index, chunk) in encoded.chunks(MAX_BACKUP_TRANSFER_CHUNK).enumerate() {
            session
                .append(5, index * MAX_BACKUP_TRANSFER_CHUNK, chunk)
                .unwrap();
        }
        assert!(matches!(
            session.verify(5, &mut Auth),
            Err(BackupTransferError::DigestMismatch)
        ));
    }
}
