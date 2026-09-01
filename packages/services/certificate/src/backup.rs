use crate::{
    DurableAuthenticator, DurableError, DurableNamespace, DurableObjectId, DurableRecord,
    DurableRecordKind, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES, SecretHandle,
};
use mrml_crypto::Sha256;

pub const BACKUP_VERSION: u16 = 1;
pub const MAX_BACKUP_RECORDS: usize = 64;
pub const MAX_BACKUP_BYTES: usize =
    8 + 2 + 8 + 2 + MAX_BACKUP_RECORDS * (4 + MAX_DURABLE_RECORD_BYTES) + 32;
const BACKUP_MAGIC: &[u8; 8] = b"MRMLCBK\0";
const MANIFEST_BYTES: usize = 8 + 2 + 8 + 2 + MAX_BACKUP_RECORDS * 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupError {
    Empty,
    TooManyRecords,
    TooLarge,
    Malformed,
    DuplicateObject,
    AuthenticationFailed,
    Durable(DurableError),
    TargetNotEmpty,
    TargetUnavailable,
    CommitUncertain,
    InvalidSealedKey,
    SealingUnavailable,
    RestoreBindingMismatch,
}

const SEALED_KEY_MAGIC: &[u8; 8] = b"MRMLSEAL";
const SEALED_KEY_VERSION: u16 = 1;
const SEALED_KEY_HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 32 + 2;
pub const MAX_SEALED_KEY_BYTES: usize = MAX_DURABLE_PAYLOAD - SEALED_KEY_HEADER_BYTES;

pub trait SealedKeyProvider {
    /// Produces an opaque provider-specific sealed record. Plain private-key
    /// bytes never cross this interface.
    fn seal_key(
        &mut self,
        handle: SecretHandle,
        recovery_policy_digest: [u8; 32],
        output: &mut [u8],
    ) -> Result<usize, BackupError>;

    /// Imports an authenticated opaque record into a clean provider and
    /// returns a new non-exporting handle.
    fn restore_key(
        &mut self,
        expected_identity: [u8; 32],
        recovery_policy_digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<SecretHandle, BackupError>;
}

pub fn prepare_sealed_key_record(
    namespace: DurableNamespace,
    kind: DurableRecordKind,
    object: DurableObjectId,
    previous_generation: u64,
    handle: SecretHandle,
    recovery_policy_digest: [u8; 32],
    provider: &mut impl SealedKeyProvider,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<DurableRecord, BackupError> {
    if !matches!(
        (namespace, kind),
        (
            DurableNamespace::AccountSecretHandles,
            DurableRecordKind::AccountSealedKey
        ) | (
            DurableNamespace::CertificateSecretHandles,
            DurableRecordKind::CertificateSealedKey
        )
    ) || recovery_policy_digest == [0; 32]
        || handle.identity == [0; 32]
        || handle.provider_generation == 0
    {
        return Err(BackupError::InvalidSealedKey);
    }
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    payload[..8].copy_from_slice(SEALED_KEY_MAGIC);
    payload[8..10].copy_from_slice(&SEALED_KEY_VERSION.to_be_bytes());
    payload[10..42].copy_from_slice(&handle.identity);
    payload[42..50].copy_from_slice(&handle.provider_generation.to_be_bytes());
    payload[50..82].copy_from_slice(&recovery_policy_digest);
    let sealed_len = provider.seal_key(
        handle,
        recovery_policy_digest,
        &mut payload[SEALED_KEY_HEADER_BYTES..],
    )?;
    if sealed_len == 0 || sealed_len > MAX_SEALED_KEY_BYTES {
        payload.fill(0);
        return Err(BackupError::InvalidSealedKey);
    }
    payload[82..84].copy_from_slice(&(sealed_len as u16).to_be_bytes());
    let record = DurableRecord::prepare(
        namespace,
        kind,
        object,
        previous_generation,
        &payload[..SEALED_KEY_HEADER_BYTES + sealed_len],
        authenticator,
    )?;
    payload.fill(0);
    Ok(record)
}

pub fn restore_sealed_key_record(
    record: &DurableRecord,
    expected_recovery_policy_digest: [u8; 32],
    provider: &mut impl SealedKeyProvider,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<SecretHandle, BackupError> {
    record.verify(authenticator)?;
    if !matches!(
        (record.namespace, record.kind),
        (
            DurableNamespace::AccountSecretHandles,
            DurableRecordKind::AccountSealedKey
        ) | (
            DurableNamespace::CertificateSecretHandles,
            DurableRecordKind::CertificateSealedKey
        )
    ) {
        return Err(BackupError::InvalidSealedKey);
    }
    let payload = record.payload();
    if payload.len() < SEALED_KEY_HEADER_BYTES
        || payload.get(..8) != Some(SEALED_KEY_MAGIC)
        || read_u16(payload, 8)? != SEALED_KEY_VERSION
    {
        return Err(BackupError::InvalidSealedKey);
    }
    let mut identity = [0; 32];
    identity.copy_from_slice(&payload[10..42]);
    let provider_generation = read_u64(payload, 42)?;
    let mut recovery_policy_digest = [0; 32];
    recovery_policy_digest.copy_from_slice(&payload[50..82]);
    let sealed_len = usize::from(read_u16(payload, 82)?);
    if identity == [0; 32]
        || provider_generation == 0
        || recovery_policy_digest != expected_recovery_policy_digest
        || sealed_len == 0
        || sealed_len > MAX_SEALED_KEY_BYTES
        || payload.len() != SEALED_KEY_HEADER_BYTES + sealed_len
    {
        return Err(BackupError::RestoreBindingMismatch);
    }
    let restored = provider.restore_key(
        identity,
        recovery_policy_digest,
        &payload[SEALED_KEY_HEADER_BYTES..],
    )?;
    if restored.identity != identity || restored.provider_generation == 0 {
        return Err(BackupError::RestoreBindingMismatch);
    }
    Ok(restored)
}

impl From<DurableError> for BackupError {
    fn from(value: DurableError) -> Self {
        Self::Durable(value)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupDescriptor {
    pub policy_generation: u64,
    pub record_count: u16,
    pub backup_digest: [u8; 32],
}

pub fn create_backup(
    policy_generation: u64,
    records: &[&DurableRecord],
    output: &mut [u8],
    authenticator: &mut impl DurableAuthenticator,
) -> Result<(usize, BackupDescriptor), BackupError> {
    if records.is_empty() {
        return Err(BackupError::Empty);
    }
    if records.len() > MAX_BACKUP_RECORDS {
        return Err(BackupError::TooManyRecords);
    }
    let mut cursor = 0usize;
    write(output, &mut cursor, BACKUP_MAGIC)?;
    write(output, &mut cursor, &BACKUP_VERSION.to_be_bytes())?;
    write(output, &mut cursor, &policy_generation.to_be_bytes())?;
    write(output, &mut cursor, &(records.len() as u16).to_be_bytes())?;
    let mut manifest = [0u8; MANIFEST_BYTES];
    let mut manifest_len = 0usize;
    write(&mut manifest, &mut manifest_len, BACKUP_MAGIC)?;
    write(
        &mut manifest,
        &mut manifest_len,
        &BACKUP_VERSION.to_be_bytes(),
    )?;
    write(
        &mut manifest,
        &mut manifest_len,
        &policy_generation.to_be_bytes(),
    )?;
    write(
        &mut manifest,
        &mut manifest_len,
        &(records.len() as u16).to_be_bytes(),
    )?;
    let mut identities =
        [(DurableNamespace::PublicState, DurableObjectId([0; 16])); MAX_BACKUP_RECORDS];
    for (index, record) in records.iter().enumerate() {
        record.verify(authenticator)?;
        if identities[..index]
            .iter()
            .any(|identity| *identity == (record.namespace, record.object))
        {
            return Err(BackupError::DuplicateObject);
        }
        identities[index] = (record.namespace, record.object);
        let length_offset = cursor;
        write(output, &mut cursor, &[0; 4])?;
        let record_start = cursor;
        let written = record.encode(
            output
                .get_mut(record_start..)
                .ok_or(BackupError::TooLarge)?,
        )?;
        cursor = cursor.checked_add(written).ok_or(BackupError::TooLarge)?;
        output
            .get_mut(length_offset..length_offset + 4)
            .ok_or(BackupError::TooLarge)?
            .copy_from_slice(&(written as u32).to_be_bytes());
        write(
            &mut manifest,
            &mut manifest_len,
            &Sha256::digest(&output[record_start..cursor]),
        )?;
    }
    let tag = authenticator.authenticate(&manifest[..manifest_len])?;
    write(output, &mut cursor, &tag)?;
    let descriptor = BackupDescriptor {
        policy_generation,
        record_count: records.len() as u16,
        backup_digest: Sha256::digest(&output[..cursor]),
    };
    Ok((cursor, descriptor))
}

pub fn create_recoverable_backup(
    policy_generation: u64,
    records: &[&DurableRecord],
    output: &mut [u8],
    authenticator: &mut impl DurableAuthenticator,
) -> Result<(usize, BackupDescriptor), BackupError> {
    for record in records {
        let counterpart = match record.kind {
            DurableRecordKind::AccountKeyHandle => Some(DurableRecordKind::AccountSealedKey),
            DurableRecordKind::CertificateKeyHandle => {
                Some(DurableRecordKind::CertificateSealedKey)
            }
            DurableRecordKind::AccountSealedKey => Some(DurableRecordKind::AccountKeyHandle),
            DurableRecordKind::CertificateSealedKey => {
                Some(DurableRecordKind::CertificateKeyHandle)
            }
            _ => None,
        };
        let Some(counterpart) = counterpart else {
            continue;
        };
        let identity = sealed_or_handle_identity(record)?;
        if !records.iter().any(|candidate| {
            candidate.kind == counterpart
                && candidate.namespace == record.namespace
                && sealed_or_handle_identity(candidate).ok() == Some(identity)
        }) {
            return Err(BackupError::InvalidSealedKey);
        }
    }
    create_backup(policy_generation, records, output, authenticator)
}

fn sealed_or_handle_identity(record: &DurableRecord) -> Result<[u8; 32], BackupError> {
    let payload = record.payload();
    let source = match record.kind {
        DurableRecordKind::AccountKeyHandle | DurableRecordKind::CertificateKeyHandle => {
            payload.get(..32).ok_or(BackupError::InvalidSealedKey)?
        }
        DurableRecordKind::AccountSealedKey | DurableRecordKind::CertificateSealedKey
            if payload.get(..8) == Some(SEALED_KEY_MAGIC) =>
        {
            payload.get(10..42).ok_or(BackupError::InvalidSealedKey)?
        }
        _ => return Err(BackupError::InvalidSealedKey),
    };
    let mut identity = [0; 32];
    identity.copy_from_slice(source);
    if identity == [0; 32] {
        return Err(BackupError::InvalidSealedKey);
    }
    Ok(identity)
}

pub fn verify_backup(
    input: &[u8],
    authenticator: &mut impl DurableAuthenticator,
) -> Result<BackupDescriptor, BackupError> {
    let parsed = parse_backup(input, authenticator, |_, _| Ok(()))?;
    Ok(parsed)
}

pub trait BackupRestoreTarget {
    fn require_empty(&mut self) -> Result<(), BackupError>;
    fn begin(&mut self, descriptor: BackupDescriptor) -> Result<(), BackupError>;
    fn import(&mut self, record: &DurableRecord) -> Result<(), BackupError>;
    fn commit(&mut self, descriptor: BackupDescriptor) -> Result<(), BackupError>;
    fn abort(&mut self);
}

pub fn restore_backup(
    input: &[u8],
    authenticator: &mut impl DurableAuthenticator,
    target: &mut impl BackupRestoreTarget,
) -> Result<BackupDescriptor, BackupError> {
    target.require_empty()?;
    let descriptor = verify_backup(input, authenticator)?;
    target.begin(descriptor)?;
    let result = parse_backup(input, authenticator, |record, _| target.import(record));
    match result {
        Ok(parsed) if parsed == descriptor => match target.commit(descriptor) {
            Ok(()) => Ok(descriptor),
            Err(error) => {
                target.abort();
                Err(error)
            }
        },
        Ok(_) => {
            target.abort();
            Err(BackupError::Malformed)
        }
        Err(error) => {
            target.abort();
            Err(error)
        }
    }
}

fn parse_backup(
    input: &[u8],
    authenticator: &mut impl DurableAuthenticator,
    mut visit: impl FnMut(&DurableRecord, usize) -> Result<(), BackupError>,
) -> Result<BackupDescriptor, BackupError> {
    if input.len() > MAX_BACKUP_BYTES || input.len() < 8 + 2 + 8 + 2 + 4 + 32 {
        return Err(BackupError::Malformed);
    }
    if input.get(..8) != Some(BACKUP_MAGIC) || read_u16(input, 8)? != BACKUP_VERSION {
        return Err(BackupError::Malformed);
    }
    let policy_generation = read_u64(input, 10)?;
    let count = usize::from(read_u16(input, 18)?);
    if count == 0 || count > MAX_BACKUP_RECORDS {
        return Err(BackupError::Malformed);
    }
    let mut manifest = [0u8; MANIFEST_BYTES];
    let mut manifest_len = 0usize;
    write(&mut manifest, &mut manifest_len, &input[..20])?;
    let mut cursor = 20usize;
    let mut identities =
        [(DurableNamespace::PublicState, DurableObjectId([0; 16])); MAX_BACKUP_RECORDS];
    for index in 0..count {
        let length =
            usize::try_from(read_u32(input, cursor)?).map_err(|_| BackupError::Malformed)?;
        cursor = cursor.checked_add(4).ok_or(BackupError::Malformed)?;
        if length == 0 || length > MAX_DURABLE_RECORD_BYTES {
            return Err(BackupError::Malformed);
        }
        let end = cursor.checked_add(length).ok_or(BackupError::Malformed)?;
        let encoded = input.get(cursor..end).ok_or(BackupError::Malformed)?;
        let record = DurableRecord::decode(encoded, authenticator)?;
        if identities[..index]
            .iter()
            .any(|identity| *identity == (record.namespace, record.object))
        {
            return Err(BackupError::DuplicateObject);
        }
        identities[index] = (record.namespace, record.object);
        write(&mut manifest, &mut manifest_len, &Sha256::digest(encoded))?;
        visit(&record, index)?;
        cursor = end;
    }
    if input.len() != cursor + 32 {
        return Err(BackupError::Malformed);
    }
    let mut tag = [0; 32];
    tag.copy_from_slice(&input[cursor..]);
    if !authenticator.verify(&manifest[..manifest_len], &tag)? {
        return Err(BackupError::AuthenticationFailed);
    }
    Ok(BackupDescriptor {
        policy_generation,
        record_count: count as u16,
        backup_digest: Sha256::digest(input),
    })
}

fn write(output: &mut [u8], cursor: &mut usize, value: &[u8]) -> Result<(), BackupError> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(BackupError::TooLarge)?;
    output
        .get_mut(*cursor..end)
        .ok_or(BackupError::TooLarge)?
        .copy_from_slice(value);
    *cursor = end;
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, BackupError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(BackupError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, BackupError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(BackupError::Malformed)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, BackupError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(BackupError::Malformed)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableRecordKind, SecretHandle};
    use mrml_crypto::hmac_sha256;

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, value: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[value]))
        }
        fn verify(&mut self, value: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[value]) == *tag)
        }
    }

    struct Target {
        empty: bool,
        imported: usize,
        committed: bool,
        aborted: bool,
    }

    struct Sealer {
        next_generation: u64,
    }
    impl SealedKeyProvider for Sealer {
        fn seal_key(
            &mut self,
            handle: SecretHandle,
            recovery_policy_digest: [u8; 32],
            output: &mut [u8],
        ) -> Result<usize, BackupError> {
            let value = Sha256::digest(
                &[
                    handle.identity.as_slice(),
                    &handle.provider_generation.to_be_bytes(),
                    &recovery_policy_digest,
                ]
                .concat(),
            );
            output[..32].copy_from_slice(&value);
            Ok(32)
        }
        fn restore_key(
            &mut self,
            expected_identity: [u8; 32],
            _: [u8; 32],
            sealed: &[u8],
        ) -> Result<SecretHandle, BackupError> {
            if sealed.len() != 32 {
                return Err(BackupError::InvalidSealedKey);
            }
            Ok(SecretHandle {
                identity: expected_identity,
                provider_generation: self.next_generation,
            })
        }
    }
    impl BackupRestoreTarget for Target {
        fn require_empty(&mut self) -> Result<(), BackupError> {
            self.empty.then_some(()).ok_or(BackupError::TargetNotEmpty)
        }
        fn begin(&mut self, _: BackupDescriptor) -> Result<(), BackupError> {
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
            self.aborted = true
        }
    }

    #[test]
    fn authenticated_backup_verifies_and_restores_only_to_clean_target() {
        let mut auth = Auth([9; 32]);
        let public = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Account,
            DurableObjectId([1; 16]),
            0,
            b"account",
            &mut auth,
        )
        .unwrap();
        let handle = SecretHandle {
            identity: [7; 32],
            provider_generation: 2,
        };
        let mut handle_payload = [0; 40];
        handle_payload[..32].copy_from_slice(&handle.identity);
        handle_payload[32..].copy_from_slice(&handle.provider_generation.to_be_bytes());
        let secret = DurableRecord::prepare(
            DurableNamespace::AccountSecretHandles,
            DurableRecordKind::AccountKeyHandle,
            DurableObjectId([2; 16]),
            0,
            &handle_payload,
            &mut auth,
        )
        .unwrap();
        let mut encoded = [0; 16 * 1024];
        let (written, descriptor) =
            create_backup(4, &[&public, &secret], &mut encoded, &mut auth).unwrap();
        assert!(verify_backup(&encoded[..written], &mut auth).unwrap() == descriptor);
        let mut target = Target {
            empty: true,
            imported: 0,
            committed: false,
            aborted: false,
        };
        restore_backup(&encoded[..written], &mut auth, &mut target).unwrap();
        assert_eq!(target.imported, 2);
        assert!(target.committed);
        encoded[30] ^= 1;
        assert!(verify_backup(&encoded[..written], &mut auth).is_err());
        let mut nonempty = Target {
            empty: false,
            imported: 0,
            committed: false,
            aborted: false,
        };
        assert!(matches!(
            restore_backup(&encoded[..written], &mut auth, &mut nonempty),
            Err(BackupError::TargetNotEmpty)
        ));
    }

    #[test]
    fn sealed_account_and_certificate_keys_restore_as_new_nonexporting_handles() {
        let mut auth = Auth([9; 32]);
        let policy = Sha256::digest(b"owner recovery policy and destination");
        let original = SecretHandle {
            identity: [7; 32],
            provider_generation: 2,
        };
        let mut source = Sealer { next_generation: 9 };
        let account = prepare_sealed_key_record(
            DurableNamespace::AccountSecretHandles,
            DurableRecordKind::AccountSealedKey,
            DurableObjectId([1; 16]),
            0,
            original,
            policy,
            &mut source,
            &mut auth,
        )
        .unwrap();
        let certificate = prepare_sealed_key_record(
            DurableNamespace::CertificateSecretHandles,
            DurableRecordKind::CertificateSealedKey,
            DurableObjectId([2; 16]),
            0,
            SecretHandle {
                identity: [8; 32],
                provider_generation: 3,
            },
            policy,
            &mut source,
            &mut auth,
        )
        .unwrap();
        let mut account_handle_payload = [0; 40];
        account_handle_payload[..32].copy_from_slice(&original.identity);
        account_handle_payload[32..].copy_from_slice(&original.provider_generation.to_be_bytes());
        let account_handle = DurableRecord::prepare(
            DurableNamespace::AccountSecretHandles,
            DurableRecordKind::AccountKeyHandle,
            DurableObjectId([3; 16]),
            0,
            &account_handle_payload,
            &mut auth,
        )
        .unwrap();
        let mut certificate_handle_payload = [0; 40];
        certificate_handle_payload[..32].copy_from_slice(&[8; 32]);
        certificate_handle_payload[32..].copy_from_slice(&3u64.to_be_bytes());
        let certificate_handle = DurableRecord::prepare(
            DurableNamespace::CertificateSecretHandles,
            DurableRecordKind::CertificateKeyHandle,
            DurableObjectId([4; 16]),
            0,
            &certificate_handle_payload,
            &mut auth,
        )
        .unwrap();
        let mut encoded = [0; 16 * 1024];
        assert!(create_recoverable_backup(4, &[&account_handle], &mut encoded, &mut auth).is_err());
        let (written, _) = create_recoverable_backup(
            4,
            &[&account_handle, &account, &certificate_handle, &certificate],
            &mut encoded,
            &mut auth,
        )
        .unwrap();
        verify_backup(&encoded[..written], &mut auth).unwrap();
        let mut destination = Sealer { next_generation: 9 };
        let restored =
            restore_sealed_key_record(&account, policy, &mut destination, &mut auth).unwrap();
        assert_eq!(restored.identity, original.identity);
        assert_eq!(restored.provider_generation, 9);
        assert!(restore_sealed_key_record(&account, [1; 32], &mut destination, &mut auth).is_err());
        assert!(
            restore_sealed_key_record(&certificate, policy, &mut destination, &mut auth).is_ok()
        );
    }
}
