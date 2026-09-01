use crate::{
    BackupDescriptor, BackupError, BackupRestoreTarget, DurableAuthenticator, MAX_BACKUP_BYTES,
    restore_backup, verify_backup,
};
use mrml_crypto::Sha256;

pub const MAX_BACKUP_TRANSFER_CHUNK: usize = 4096;
pub const BACKUP_TRANSFER_HEADER_BYTES: usize = 72;
pub const MAX_BACKUP_WIRE_CHUNK: usize = 4096 - BACKUP_TRANSFER_HEADER_BYTES;
const TRANSFER_MAGIC: &[u8; 8] = b"MRMLBT01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackupTransferPurpose {
    VerifyOnly = 1,
    Restore = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupTransferCommand<'a> {
    Begin {
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
        policy_generation: u64,
        total_bytes: usize,
        expected_digest: [u8; 32],
    },
    Append {
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
        offset: usize,
        chunk: &'a [u8],
    },
    Verify {
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
    },
    Restore {
        transfer_generation: u64,
    },
    Cancel {
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupTransferError {
    InvalidTransfer,
    TransferInProgress,
    StaleTransfer,
    OutOfOrder,
    Incomplete,
    DigestMismatch,
    PurposeMismatch,
    MalformedCommand,
    Backup(BackupError),
}

impl From<BackupError> for BackupTransferError {
    fn from(value: BackupError) -> Self {
        Self::Backup(value)
    }
}

#[derive(Clone, Copy)]
struct Upload {
    purpose: BackupTransferPurpose,
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
        purpose: BackupTransferPurpose,
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
            purpose,
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
        purpose: BackupTransferPurpose,
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
        if purpose != upload.purpose {
            return Err(BackupTransferError::PurposeMismatch);
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
        purpose: BackupTransferPurpose,
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
        if purpose != upload.purpose {
            return Err(BackupTransferError::PurposeMismatch);
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
        if upload.purpose != BackupTransferPurpose::Restore {
            return Err(BackupTransferError::PurposeMismatch);
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

    pub fn cancel(
        &mut self,
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
    ) -> Result<(), BackupTransferError> {
        let upload = self.upload.ok_or(BackupTransferError::StaleTransfer)?;
        if upload.transfer_generation != transfer_generation {
            return Err(BackupTransferError::StaleTransfer);
        }
        if upload.purpose != purpose {
            return Err(BackupTransferError::PurposeMismatch);
        }
        self.clear();
        Ok(())
    }
}

impl Drop for BackupUploadSession<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn encode_backup_transfer_command(
    command: BackupTransferCommand<'_>,
    output: &mut [u8],
) -> Result<usize, BackupTransferError> {
    let (purpose, action, transfer, policy, total, offset, digest, chunk) = match command {
        BackupTransferCommand::Begin {
            purpose,
            transfer_generation,
            policy_generation,
            total_bytes,
            expected_digest,
        } => (
            purpose,
            1,
            transfer_generation,
            policy_generation,
            total_bytes,
            0,
            expected_digest,
            &[][..],
        ),
        BackupTransferCommand::Append {
            purpose,
            transfer_generation,
            offset,
            chunk,
        } => (
            purpose,
            2,
            transfer_generation,
            0,
            0,
            offset,
            [0; 32],
            chunk,
        ),
        BackupTransferCommand::Verify {
            purpose,
            transfer_generation,
        } => (purpose, 3, transfer_generation, 0, 0, 0, [0; 32], &[][..]),
        BackupTransferCommand::Restore {
            transfer_generation,
        } => (
            BackupTransferPurpose::Restore,
            4,
            transfer_generation,
            0,
            0,
            0,
            [0; 32],
            &[][..],
        ),
        BackupTransferCommand::Cancel {
            purpose,
            transfer_generation,
        } => (purpose, 5, transfer_generation, 0, 0, 0, [0; 32], &[][..]),
    };
    if transfer == 0
        || chunk.len() > MAX_BACKUP_WIRE_CHUNK
        || total > MAX_BACKUP_BYTES
        || total > u32::MAX as usize
        || offset > u32::MAX as usize
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    if action == 1 && (policy == 0 || total == 0 || digest == [0; 32])
        || action == 2 && chunk.is_empty()
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    let written = BACKUP_TRANSFER_HEADER_BYTES + chunk.len();
    let output = output
        .get_mut(..written)
        .ok_or(BackupTransferError::MalformedCommand)?;
    output.fill(0);
    output[..8].copy_from_slice(TRANSFER_MAGIC);
    output[8] = purpose as u8;
    output[9] = action;
    output[12..20].copy_from_slice(&transfer.to_be_bytes());
    output[20..28].copy_from_slice(&policy.to_be_bytes());
    output[28..32].copy_from_slice(&(total as u32).to_be_bytes());
    output[32..36].copy_from_slice(&(offset as u32).to_be_bytes());
    output[36..68].copy_from_slice(&digest);
    output[68..70].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
    output[72..].copy_from_slice(chunk);
    Ok(written)
}

pub fn decode_backup_transfer_command(
    input: &[u8],
) -> Result<BackupTransferCommand<'_>, BackupTransferError> {
    if input.len() < BACKUP_TRANSFER_HEADER_BYTES
        || input.len() > 4096
        || input.get(..8) != Some(TRANSFER_MAGIC)
        || input[10..12] != [0; 2]
        || input[70..72] != [0; 2]
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    let purpose = match input[8] {
        1 => BackupTransferPurpose::VerifyOnly,
        2 => BackupTransferPurpose::Restore,
        _ => return Err(BackupTransferError::MalformedCommand),
    };
    let action = input[9];
    let transfer_generation = read_u64(input, 12)?;
    let policy_generation = read_u64(input, 20)?;
    let total_bytes = read_u32(input, 28)? as usize;
    let offset = read_u32(input, 32)? as usize;
    let mut digest = [0; 32];
    digest.copy_from_slice(&input[36..68]);
    let chunk_len = usize::from(read_u16(input, 68)?);
    if transfer_generation == 0
        || chunk_len > MAX_BACKUP_WIRE_CHUNK
        || input.len() != BACKUP_TRANSFER_HEADER_BYTES + chunk_len
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    match action {
        1 if policy_generation != 0
            && total_bytes != 0
            && total_bytes <= MAX_BACKUP_BYTES
            && offset == 0
            && digest != [0; 32]
            && chunk_len == 0 =>
        {
            Ok(BackupTransferCommand::Begin {
                purpose,
                transfer_generation,
                policy_generation,
                total_bytes,
                expected_digest: digest,
            })
        }
        2 if policy_generation == 0 && total_bytes == 0 && digest == [0; 32] && chunk_len != 0 => {
            Ok(BackupTransferCommand::Append {
                purpose,
                transfer_generation,
                offset,
                chunk: &input[BACKUP_TRANSFER_HEADER_BYTES..],
            })
        }
        3 if metadata_is_empty(policy_generation, total_bytes, offset, digest, chunk_len) => {
            Ok(BackupTransferCommand::Verify {
                purpose,
                transfer_generation,
            })
        }
        4 if purpose == BackupTransferPurpose::Restore
            && metadata_is_empty(policy_generation, total_bytes, offset, digest, chunk_len) =>
        {
            Ok(BackupTransferCommand::Restore {
                transfer_generation,
            })
        }
        5 if metadata_is_empty(policy_generation, total_bytes, offset, digest, chunk_len) => {
            Ok(BackupTransferCommand::Cancel {
                purpose,
                transfer_generation,
            })
        }
        _ => Err(BackupTransferError::MalformedCommand),
    }
}

fn metadata_is_empty(
    policy: u64,
    total: usize,
    offset: usize,
    digest: [u8; 32],
    chunk: usize,
) -> bool {
    policy == 0 && total == 0 && offset == 0 && digest == [0; 32] && chunk == 0
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, BackupTransferError> {
    let value = input
        .get(offset..offset + 2)
        .ok_or(BackupTransferError::MalformedCommand)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, BackupTransferError> {
    let value = input
        .get(offset..offset + 4)
        .ok_or(BackupTransferError::MalformedCommand)?;
    Ok(u32::from_be_bytes(value.try_into().unwrap()))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, BackupTransferError> {
    let value = input
        .get(offset..offset + 8)
        .ok_or(BackupTransferError::MalformedCommand)?;
    Ok(u64::from_be_bytes(value.try_into().unwrap()))
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
            .begin(
                BackupTransferPurpose::Restore,
                11,
                9,
                encoded.len(),
                descriptor.backup_digest,
            )
            .unwrap();
        for (index, chunk) in encoded.chunks(MAX_BACKUP_TRANSFER_CHUNK).enumerate() {
            session
                .append(
                    BackupTransferPurpose::Restore,
                    11,
                    index * MAX_BACKUP_TRANSFER_CHUNK,
                    chunk,
                )
                .unwrap();
        }
        assert!(
            session
                .verify(BackupTransferPurpose::Restore, 11, &mut Auth)
                .unwrap()
                == descriptor
        );
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
            session.verify(BackupTransferPurpose::Restore, 11, &mut Auth),
            Err(BackupTransferError::StaleTransfer)
        ));
    }

    #[test]
    fn transfer_rejects_replay_reordering_truncation_and_digest_substitution() {
        let (encoded, descriptor) = fixture();
        let mut storage = std::vec![0; MAX_BACKUP_BYTES];
        let mut session = BackupUploadSession::new(&mut storage).unwrap();
        session
            .begin(
                BackupTransferPurpose::VerifyOnly,
                3,
                9,
                encoded.len(),
                descriptor.backup_digest,
            )
            .unwrap();
        assert!(matches!(
            session.append(BackupTransferPurpose::VerifyOnly, 4, 0, &encoded[..16]),
            Err(BackupTransferError::StaleTransfer)
        ));
        assert!(matches!(
            session.append(BackupTransferPurpose::VerifyOnly, 3, 1, &encoded[..16]),
            Err(BackupTransferError::OutOfOrder)
        ));
        assert!(matches!(
            session.append(BackupTransferPurpose::Restore, 3, 0, &encoded[..16]),
            Err(BackupTransferError::PurposeMismatch)
        ));
        session
            .append(BackupTransferPurpose::VerifyOnly, 3, 0, &encoded[..16])
            .unwrap();
        assert!(matches!(
            session.verify(BackupTransferPurpose::VerifyOnly, 3, &mut Auth),
            Err(BackupTransferError::Incomplete)
        ));
        session.clear();
        session
            .begin(
                BackupTransferPurpose::VerifyOnly,
                5,
                9,
                encoded.len(),
                [8; 32],
            )
            .unwrap();
        for (index, chunk) in encoded.chunks(MAX_BACKUP_TRANSFER_CHUNK).enumerate() {
            session
                .append(
                    BackupTransferPurpose::VerifyOnly,
                    5,
                    index * MAX_BACKUP_TRANSFER_CHUNK,
                    chunk,
                )
                .unwrap();
        }
        assert!(matches!(
            session.verify(BackupTransferPurpose::VerifyOnly, 5, &mut Auth),
            Err(BackupTransferError::DigestMismatch)
        ));
    }

    #[test]
    fn wire_commands_round_trip_canonically_and_bind_purpose() {
        let chunk = [0xa5; MAX_BACKUP_WIRE_CHUNK];
        let commands = [
            BackupTransferCommand::Begin {
                purpose: BackupTransferPurpose::Restore,
                transfer_generation: 7,
                policy_generation: 9,
                total_bytes: MAX_BACKUP_BYTES,
                expected_digest: [3; 32],
            },
            BackupTransferCommand::Append {
                purpose: BackupTransferPurpose::Restore,
                transfer_generation: 7,
                offset: 4096,
                chunk: &chunk,
            },
            BackupTransferCommand::Verify {
                purpose: BackupTransferPurpose::Restore,
                transfer_generation: 7,
            },
            BackupTransferCommand::Restore {
                transfer_generation: 7,
            },
            BackupTransferCommand::Cancel {
                purpose: BackupTransferPurpose::Restore,
                transfer_generation: 7,
            },
        ];
        let mut wire = [0u8; 4096];
        for expected in commands {
            let written = encode_backup_transfer_command(expected, &mut wire).unwrap();
            assert_eq!(
                decode_backup_transfer_command(&wire[..written]),
                Ok(expected)
            );
            let mut trailing = std::vec::Vec::from(&wire[..written]);
            trailing.push(0);
            assert_eq!(
                decode_backup_transfer_command(&trailing),
                Err(BackupTransferError::MalformedCommand)
            );
        }
        wire.fill(0);
        assert_eq!(
            decode_backup_transfer_command(&wire[..BACKUP_TRANSFER_HEADER_BYTES]),
            Err(BackupTransferError::MalformedCommand)
        );
    }
}
