use crate::{
    BackupDescriptor, BackupError, BackupRestoreTarget, DurableAuthenticator, MAX_BACKUP_BYTES,
    restore_backup, verify_backup,
};
use mrml_crypto::Sha256;
use mrml_interface_certificate_lifecycle_v1 as abi;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTransferProgress {
    pub purpose: BackupTransferPurpose,
    pub transfer_generation: u64,
    pub policy_generation: u64,
    pub accepted_bytes: usize,
    pub total_bytes: usize,
    pub verified: Option<BackupDescriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupTransferReceiptState {
    Accepted,
    Verified,
    Restored,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTransferReceipt {
    pub state: BackupTransferReceiptState,
    pub purpose: BackupTransferPurpose,
    pub transfer_generation: u64,
    pub policy_generation: u64,
    pub accepted_bytes: u32,
    pub total_bytes: u32,
    pub record_count: u16,
    pub backup_digest: [u8; 32],
}

pub const BACKUP_TRANSFER_RECEIPT_BYTES: usize = 80;
const RECEIPT_MAGIC: &[u8; 8] = b"MRMLBR01";

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

    pub fn progress(&self) -> Option<BackupTransferProgress> {
        self.upload.map(|upload| BackupTransferProgress {
            purpose: upload.purpose,
            transfer_generation: upload.transfer_generation,
            policy_generation: upload.policy_generation,
            accepted_bytes: upload.written,
            total_bytes: upload.total_bytes,
            verified: upload.verified,
        })
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

pub struct BackupTransferLifecycle<'a> {
    session: BackupUploadSession<'a>,
}

impl<'a> BackupTransferLifecycle<'a> {
    pub fn new(storage: &'a mut [u8]) -> Result<Self, BackupTransferError> {
        Ok(Self {
            session: BackupUploadSession::new(storage)?,
        })
    }

    pub fn handle<A: DurableAuthenticator, T: BackupRestoreTarget>(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
        authenticator: &mut A,
        target: &mut T,
    ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
        if policy_generation == 0 {
            return Err(abi::BackupOperationError::StalePolicy);
        }
        let command = decode_backup_transfer_command(request)
            .map_err(|_| abi::BackupOperationError::InvalidRequest)?;
        let (receipt, clear_after) = match command {
            BackupTransferCommand::Begin {
                purpose,
                transfer_generation,
                policy_generation: command_policy,
                total_bytes,
                expected_digest,
            } if operation_matches(operation, purpose) && command_policy == policy_generation => {
                self.session
                    .begin(
                        purpose,
                        transfer_generation,
                        policy_generation,
                        total_bytes,
                        expected_digest,
                    )
                    .map_err(map_transfer_error)?;
                (
                    receipt_from_progress(
                        self.session.progress().unwrap(),
                        BackupTransferReceiptState::Accepted,
                    ),
                    false,
                )
            }
            BackupTransferCommand::Append {
                purpose,
                transfer_generation,
                offset,
                chunk,
            } if operation_matches(operation, purpose) => {
                self.require_binding(purpose, transfer_generation, policy_generation)?;
                self.session
                    .append(purpose, transfer_generation, offset, chunk)
                    .map_err(map_transfer_error)?;
                (
                    receipt_from_progress(
                        self.session.progress().unwrap(),
                        BackupTransferReceiptState::Accepted,
                    ),
                    false,
                )
            }
            BackupTransferCommand::Verify {
                purpose,
                transfer_generation,
            } if operation_matches(operation, purpose) => {
                self.require_binding(purpose, transfer_generation, policy_generation)?;
                let descriptor = self
                    .session
                    .verify(purpose, transfer_generation, authenticator)
                    .map_err(map_transfer_error)?;
                let mut receipt = receipt_from_progress(
                    self.session.progress().unwrap(),
                    BackupTransferReceiptState::Verified,
                );
                receipt.record_count = descriptor.record_count;
                receipt.backup_digest = descriptor.backup_digest;
                (receipt, purpose == BackupTransferPurpose::VerifyOnly)
            }
            BackupTransferCommand::Restore {
                transfer_generation,
            } if operation == abi::RESTORE_COMMIT => {
                self.require_binding(
                    BackupTransferPurpose::Restore,
                    transfer_generation,
                    policy_generation,
                )?;
                let progress = self.session.progress().unwrap();
                let descriptor = self
                    .session
                    .restore(transfer_generation, authenticator, target)
                    .map_err(map_transfer_error)?;
                let mut receipt =
                    receipt_from_progress(progress, BackupTransferReceiptState::Restored);
                receipt.record_count = descriptor.record_count;
                receipt.backup_digest = descriptor.backup_digest;
                (receipt, false)
            }
            BackupTransferCommand::Cancel {
                purpose,
                transfer_generation,
            } if operation_matches(operation, purpose) => {
                self.require_binding(purpose, transfer_generation, policy_generation)?;
                let progress = self.session.progress().unwrap();
                self.session
                    .cancel(purpose, transfer_generation)
                    .map_err(map_transfer_error)?;
                (
                    receipt_from_progress(progress, BackupTransferReceiptState::Cancelled),
                    false,
                )
            }
            _ => return Err(abi::BackupOperationError::InvalidRequest),
        };
        encode_backup_transfer_receipt(receipt, output)
            .map_err(|_| abi::BackupOperationError::OperationFailed)?;
        if clear_after {
            self.session.clear();
        }
        Ok(abi::BackupOperationResponse {
            written: BACKUP_TRANSFER_RECEIPT_BYTES as u64,
            backup_generation: receipt.transfer_generation,
        })
    }

    fn require_binding(
        &self,
        purpose: BackupTransferPurpose,
        transfer_generation: u64,
        policy_generation: u64,
    ) -> Result<(), abi::BackupOperationError> {
        match self.session.progress() {
            Some(progress)
                if progress.purpose == purpose
                    && progress.transfer_generation == transfer_generation
                    && progress.policy_generation == policy_generation =>
            {
                Ok(())
            }
            Some(progress) if progress.policy_generation != policy_generation => {
                Err(abi::BackupOperationError::StalePolicy)
            }
            _ => Err(abi::BackupOperationError::InvalidRequest),
        }
    }
}

fn operation_matches(operation: u32, purpose: BackupTransferPurpose) -> bool {
    matches!(
        (operation, purpose),
        (abi::BACKUP_VERIFY, BackupTransferPurpose::VerifyOnly)
            | (abi::RESTORE_VERIFY_ONLY, BackupTransferPurpose::Restore)
    )
}

fn map_transfer_error(error: BackupTransferError) -> abi::BackupOperationError {
    match error {
        BackupTransferError::MalformedCommand
        | BackupTransferError::InvalidTransfer
        | BackupTransferError::StaleTransfer
        | BackupTransferError::OutOfOrder
        | BackupTransferError::Incomplete
        | BackupTransferError::PurposeMismatch => abi::BackupOperationError::InvalidRequest,
        BackupTransferError::TransferInProgress
        | BackupTransferError::DigestMismatch
        | BackupTransferError::Backup(_) => abi::BackupOperationError::OperationFailed,
    }
}

fn receipt_from_progress(
    progress: BackupTransferProgress,
    state: BackupTransferReceiptState,
) -> BackupTransferReceipt {
    BackupTransferReceipt {
        state,
        purpose: progress.purpose,
        transfer_generation: progress.transfer_generation,
        policy_generation: progress.policy_generation,
        accepted_bytes: progress.accepted_bytes as u32,
        total_bytes: progress.total_bytes as u32,
        record_count: 0,
        backup_digest: [0; 32],
    }
}

pub fn encode_backup_transfer_receipt(
    receipt: BackupTransferReceipt,
    output: &mut [u8],
) -> Result<(), BackupTransferError> {
    if receipt.transfer_generation == 0
        || receipt.policy_generation == 0
        || receipt.total_bytes == 0
        || receipt.accepted_bytes > receipt.total_bytes
        || matches!(
            receipt.state,
            BackupTransferReceiptState::Verified | BackupTransferReceiptState::Restored
        ) && (receipt.record_count == 0 || receipt.backup_digest == [0; 32])
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    let output = output
        .get_mut(..BACKUP_TRANSFER_RECEIPT_BYTES)
        .ok_or(BackupTransferError::MalformedCommand)?;
    output.fill(0);
    output[..8].copy_from_slice(RECEIPT_MAGIC);
    output[8] = match receipt.state {
        BackupTransferReceiptState::Accepted => 1,
        BackupTransferReceiptState::Verified => 2,
        BackupTransferReceiptState::Restored => 3,
        BackupTransferReceiptState::Cancelled => 4,
    };
    output[9] = receipt.purpose as u8;
    output[16..24].copy_from_slice(&receipt.transfer_generation.to_be_bytes());
    output[24..32].copy_from_slice(&receipt.policy_generation.to_be_bytes());
    output[32..36].copy_from_slice(&receipt.accepted_bytes.to_be_bytes());
    output[36..40].copy_from_slice(&receipt.total_bytes.to_be_bytes());
    output[40..42].copy_from_slice(&receipt.record_count.to_be_bytes());
    output[48..80].copy_from_slice(&receipt.backup_digest);
    Ok(())
}

pub fn decode_backup_transfer_receipt(
    input: &[u8],
) -> Result<BackupTransferReceipt, BackupTransferError> {
    if input.len() != BACKUP_TRANSFER_RECEIPT_BYTES
        || input.get(..8) != Some(RECEIPT_MAGIC)
        || input[10..16] != [0; 6]
        || input[42..48] != [0; 6]
    {
        return Err(BackupTransferError::MalformedCommand);
    }
    let state = match input[8] {
        1 => BackupTransferReceiptState::Accepted,
        2 => BackupTransferReceiptState::Verified,
        3 => BackupTransferReceiptState::Restored,
        4 => BackupTransferReceiptState::Cancelled,
        _ => return Err(BackupTransferError::MalformedCommand),
    };
    let purpose = match input[9] {
        1 => BackupTransferPurpose::VerifyOnly,
        2 => BackupTransferPurpose::Restore,
        _ => return Err(BackupTransferError::MalformedCommand),
    };
    let mut backup_digest = [0; 32];
    backup_digest.copy_from_slice(&input[48..80]);
    let receipt = BackupTransferReceipt {
        state,
        purpose,
        transfer_generation: read_u64(input, 16)?,
        policy_generation: read_u64(input, 24)?,
        accepted_bytes: read_u32(input, 32)?,
        total_bytes: read_u32(input, 36)?,
        record_count: read_u16(input, 40)?,
        backup_digest,
    };
    let mut canonical = [0u8; BACKUP_TRANSFER_RECEIPT_BYTES];
    encode_backup_transfer_receipt(receipt, &mut canonical)?;
    if canonical != input {
        return Err(BackupTransferError::MalformedCommand);
    }
    Ok(receipt)
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

    #[test]
    fn lifecycle_handler_binds_policy_purpose_and_atomic_restore() {
        let (encoded, descriptor) = fixture();
        let mut storage = std::vec![0; MAX_BACKUP_BYTES];
        let mut lifecycle = BackupTransferLifecycle::new(&mut storage).unwrap();
        let mut request = [0u8; 4096];
        let mut response = [0u8; BACKUP_TRANSFER_RECEIPT_BYTES];
        let begin = BackupTransferCommand::Begin {
            purpose: BackupTransferPurpose::Restore,
            transfer_generation: 41,
            policy_generation: 9,
            total_bytes: encoded.len(),
            expected_digest: descriptor.backup_digest,
        };
        let written = encode_backup_transfer_command(begin, &mut request).unwrap();
        lifecycle
            .handle(
                abi::RESTORE_VERIFY_ONLY,
                9,
                &request[..written],
                &mut response,
                &mut Auth,
                &mut Target::default(),
            )
            .unwrap();
        for (index, chunk) in encoded.chunks(MAX_BACKUP_WIRE_CHUNK).enumerate() {
            let command = BackupTransferCommand::Append {
                purpose: BackupTransferPurpose::Restore,
                transfer_generation: 41,
                offset: index * MAX_BACKUP_WIRE_CHUNK,
                chunk,
            };
            let written = encode_backup_transfer_command(command, &mut request).unwrap();
            lifecycle
                .handle(
                    abi::RESTORE_VERIFY_ONLY,
                    9,
                    &request[..written],
                    &mut response,
                    &mut Auth,
                    &mut Target::default(),
                )
                .unwrap();
        }
        let verify = BackupTransferCommand::Verify {
            purpose: BackupTransferPurpose::Restore,
            transfer_generation: 41,
        };
        let written = encode_backup_transfer_command(verify, &mut request).unwrap();
        lifecycle
            .handle(
                abi::RESTORE_VERIFY_ONLY,
                9,
                &request[..written],
                &mut response,
                &mut Auth,
                &mut Target::default(),
            )
            .unwrap();
        let receipt = decode_backup_transfer_receipt(&response).unwrap();
        assert_eq!(receipt.state, BackupTransferReceiptState::Verified);
        assert_eq!(receipt.backup_digest, descriptor.backup_digest);
        let restore = BackupTransferCommand::Restore {
            transfer_generation: 41,
        };
        let written = encode_backup_transfer_command(restore, &mut request).unwrap();
        assert_eq!(
            lifecycle.handle(
                abi::RESTORE_COMMIT,
                8,
                &request[..written],
                &mut response,
                &mut Auth,
                &mut Target::default(),
            ),
            Err(abi::BackupOperationError::StalePolicy)
        );
        let mut clean = Target {
            empty: true,
            ..Target::default()
        };
        lifecycle
            .handle(
                abi::RESTORE_COMMIT,
                9,
                &request[..written],
                &mut response,
                &mut Auth,
                &mut clean,
            )
            .unwrap();
        assert_eq!(
            decode_backup_transfer_receipt(&response).unwrap().state,
            BackupTransferReceiptState::Restored
        );
        assert!(clean.committed && clean.imported == 1);
    }
}
