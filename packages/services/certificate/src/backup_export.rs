use crate::{BackupDescriptor, BackupError, MAX_BACKUP_BYTES};
use mrml_crypto::Sha256;

pub const BACKUP_EXPORT_COMMAND_BYTES: usize = 32;
pub const MAX_BACKUP_EXPORT_CHUNK: usize = 8192;
const EXPORT_MAGIC: &[u8; 8] = b"MRMLBE01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupExportError {
    InvalidCommand,
    InvalidGeneration,
    ExportInProgress,
    NoExport,
    StaleExport,
    OutOfOrder,
    OutputTooSmall,
    Source(BackupError),
}

impl From<BackupError> for BackupExportError {
    fn from(value: BackupError) -> Self {
        Self::Source(value)
    }
}

pub trait BackupExportSource {
    /// Creates one authenticated, recoverable backup from the authoritative
    /// catalog. Implementations must include provider-sealed key records and
    /// must never place raw private-key bytes in `output`.
    fn create_recoverable_backup(
        &mut self,
        policy_generation: u64,
        output: &mut [u8],
    ) -> Result<(usize, BackupDescriptor), BackupError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupExportCommand {
    Begin {
        export_generation: u64,
        policy_generation: u64,
    },
    Read {
        export_generation: u64,
        offset: usize,
    },
    Finish {
        export_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupExportReceipt {
    pub export_generation: u64,
    pub policy_generation: u64,
    pub offset: u32,
    pub total_bytes: u32,
    pub record_count: u16,
    pub backup_digest: [u8; 32],
    pub finished: bool,
}

#[derive(Clone, Copy)]
struct ActiveExport {
    export_generation: u64,
    descriptor: BackupDescriptor,
    total_bytes: usize,
    next_offset: usize,
}

pub struct BackupExportSession<'a> {
    bytes: &'a mut [u8],
    active: Option<ActiveExport>,
}

impl<'a> BackupExportSession<'a> {
    pub fn new(storage: &'a mut [u8]) -> Result<Self, BackupExportError> {
        let bytes = storage
            .get_mut(..MAX_BACKUP_BYTES)
            .ok_or(BackupExportError::OutputTooSmall)?;
        bytes.fill(0);
        Ok(Self {
            bytes,
            active: None,
        })
    }

    pub fn begin(
        &mut self,
        export_generation: u64,
        policy_generation: u64,
        source: &mut impl BackupExportSource,
    ) -> Result<BackupExportReceipt, BackupExportError> {
        if export_generation == 0 || policy_generation == 0 {
            return Err(BackupExportError::InvalidGeneration);
        }
        if self.active.is_some() {
            return Err(BackupExportError::ExportInProgress);
        }
        let result = source.create_recoverable_backup(policy_generation, self.bytes);
        let (written, descriptor) = match result {
            Ok(value) => value,
            Err(error) => {
                self.bytes.fill(0);
                return Err(error.into());
            }
        };
        if written == 0
            || written > self.bytes.len()
            || descriptor.policy_generation != policy_generation
            || descriptor.record_count == 0
            || descriptor.backup_digest != Sha256::digest(&self.bytes[..written])
        {
            self.bytes.fill(0);
            return Err(BackupExportError::Source(BackupError::Malformed));
        }
        self.active = Some(ActiveExport {
            export_generation,
            descriptor,
            total_bytes: written,
            next_offset: 0,
        });
        Ok(receipt(self.active.unwrap(), false))
    }

    pub fn read(
        &mut self,
        export_generation: u64,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(usize, BackupExportReceipt), BackupExportError> {
        let active = self.active.as_mut().ok_or(BackupExportError::NoExport)?;
        if active.export_generation != export_generation {
            return Err(BackupExportError::StaleExport);
        }
        if offset != active.next_offset {
            return Err(BackupExportError::OutOfOrder);
        }
        if output.is_empty() {
            return Err(BackupExportError::OutputTooSmall);
        }
        let remaining = active.total_bytes - active.next_offset;
        let written = remaining.min(output.len()).min(MAX_BACKUP_EXPORT_CHUNK);
        output[..written]
            .copy_from_slice(&self.bytes[active.next_offset..active.next_offset + written]);
        active.next_offset += written;
        Ok((written, receipt(*active, false)))
    }

    pub fn finish(
        &mut self,
        export_generation: u64,
    ) -> Result<BackupExportReceipt, BackupExportError> {
        let active = self.active.ok_or(BackupExportError::NoExport)?;
        if active.export_generation != export_generation {
            return Err(BackupExportError::StaleExport);
        }
        if active.next_offset != active.total_bytes {
            return Err(BackupExportError::OutOfOrder);
        }
        let receipt = receipt(active, true);
        self.clear();
        Ok(receipt)
    }

    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.active = None;
    }
}

impl Drop for BackupExportSession<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

fn receipt(active: ActiveExport, finished: bool) -> BackupExportReceipt {
    BackupExportReceipt {
        export_generation: active.export_generation,
        policy_generation: active.descriptor.policy_generation,
        offset: active.next_offset as u32,
        total_bytes: active.total_bytes as u32,
        record_count: active.descriptor.record_count,
        backup_digest: active.descriptor.backup_digest,
        finished,
    }
}

pub fn encode_backup_export_command(
    command: BackupExportCommand,
) -> Result<[u8; BACKUP_EXPORT_COMMAND_BYTES], BackupExportError> {
    let (action, generation, policy, offset) = match command {
        BackupExportCommand::Begin {
            export_generation,
            policy_generation,
        } => (1, export_generation, policy_generation, 0),
        BackupExportCommand::Read {
            export_generation,
            offset,
        } => (2, export_generation, 0, offset),
        BackupExportCommand::Finish { export_generation } => (3, export_generation, 0, 0),
    };
    if generation == 0 || offset > u32::MAX as usize || (action == 1) != (policy != 0) {
        return Err(BackupExportError::InvalidCommand);
    }
    let mut output = [0; BACKUP_EXPORT_COMMAND_BYTES];
    output[..8].copy_from_slice(EXPORT_MAGIC);
    output[8] = action;
    output[12..20].copy_from_slice(&generation.to_be_bytes());
    output[20..28].copy_from_slice(&policy.to_be_bytes());
    output[28..32].copy_from_slice(&(offset as u32).to_be_bytes());
    Ok(output)
}

pub fn decode_backup_export_command(
    input: &[u8],
) -> Result<BackupExportCommand, BackupExportError> {
    if input.len() != BACKUP_EXPORT_COMMAND_BYTES
        || input.get(..8) != Some(EXPORT_MAGIC)
        || input[9..12] != [0; 3]
    {
        return Err(BackupExportError::InvalidCommand);
    }
    let generation = u64::from_be_bytes(input[12..20].try_into().unwrap());
    let policy = u64::from_be_bytes(input[20..28].try_into().unwrap());
    let offset = u32::from_be_bytes(input[28..32].try_into().unwrap()) as usize;
    match input[8] {
        1 if generation != 0 && policy != 0 && offset == 0 => Ok(BackupExportCommand::Begin {
            export_generation: generation,
            policy_generation: policy,
        }),
        2 if generation != 0 && policy == 0 => Ok(BackupExportCommand::Read {
            export_generation: generation,
            offset,
        }),
        3 if generation != 0 && policy == 0 && offset == 0 => Ok(BackupExportCommand::Finish {
            export_generation: generation,
        }),
        _ => Err(BackupExportError::InvalidCommand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::{vec, vec::Vec};

    struct Source(Vec<u8>);
    impl BackupExportSource for Source {
        fn create_recoverable_backup(
            &mut self,
            policy_generation: u64,
            output: &mut [u8],
        ) -> Result<(usize, BackupDescriptor), BackupError> {
            output[..self.0.len()].copy_from_slice(&self.0);
            Ok((
                self.0.len(),
                BackupDescriptor {
                    policy_generation,
                    record_count: 3,
                    backup_digest: Sha256::digest(&self.0),
                },
            ))
        }
    }

    #[test]
    fn export_is_exact_sequential_generation_bound_and_cleared() {
        let expected = vec![0x5a; MAX_BACKUP_EXPORT_CHUNK + 7];
        let mut source = Source(expected.clone());
        let mut storage = vec![0xa5; MAX_BACKUP_BYTES];
        let mut session = BackupExportSession::new(&mut storage).unwrap();
        let opened = session.begin(9, 4, &mut source).unwrap();
        assert_eq!(opened.total_bytes as usize, expected.len());
        let mut output = [0u8; MAX_BACKUP_EXPORT_CHUNK];
        let (first, progress) = session.read(9, 0, &mut output).unwrap();
        assert_eq!(first, output.len());
        assert_eq!(&output, &expected[..first]);
        assert_eq!(progress.offset as usize, first);
        assert_eq!(
            session.read(9, 0, &mut output),
            Err(BackupExportError::OutOfOrder)
        );
        assert_eq!(
            session.read(8, first, &mut output),
            Err(BackupExportError::StaleExport)
        );
        let (last, _) = session.read(9, first, &mut output).unwrap();
        assert_eq!(last, 7);
        assert_eq!(&output[..last], &expected[first..]);
        assert!(session.finish(9).unwrap().finished);
        assert_eq!(
            session.read(9, 0, &mut output),
            Err(BackupExportError::NoExport)
        );
        drop(session);
        assert!(storage.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn commands_are_canonical_and_reject_reserved_or_ambiguous_fields() {
        for command in [
            BackupExportCommand::Begin {
                export_generation: 2,
                policy_generation: 3,
            },
            BackupExportCommand::Read {
                export_generation: 2,
                offset: 17,
            },
            BackupExportCommand::Finish {
                export_generation: 2,
            },
        ] {
            let encoded = encode_backup_export_command(command).unwrap();
            assert_eq!(decode_backup_export_command(&encoded).unwrap(), command);
            let mut malformed = encoded;
            malformed[10] = 1;
            assert_eq!(
                decode_backup_export_command(&malformed),
                Err(BackupExportError::InvalidCommand)
            );
        }
    }

    #[test]
    fn invalid_source_receipt_clears_staged_bytes() {
        let mut source = Source(vec![1, 2, 3]);
        let mut storage = vec![0xa5; MAX_BACKUP_BYTES];
        let mut session = BackupExportSession::new(&mut storage).unwrap();
        source.0.clear();
        assert!(matches!(
            session.begin(1, 1, &mut source),
            Err(BackupExportError::Source(BackupError::Malformed))
        ));
        drop(session);
        assert!(storage.iter().all(|byte| *byte == 0));
    }
}
