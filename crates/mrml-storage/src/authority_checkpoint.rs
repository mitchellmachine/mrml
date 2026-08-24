use crate::{
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StoragePrincipal, StorageRights, VolumeId,
};
use core::array;
use mrml_crypto::Sha3_256;

pub const AUTHORITY_CHECKPOINT_HEADER_BYTES: usize = 80;
pub const AUTHORITY_CHECKPOINT_GRANT_BYTES: usize = 48;
const DIGEST_OFFSET: usize = 48;
const DIGEST_BYTES: usize = 32;
const MAGIC: [u8; 4] = *b"MRAC";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRecoveryGrant {
    principal: StoragePrincipal,
    object: StorageObjectId,
    kind: StorageObjectKind,
    rights: StorageRights,
    parent: Option<usize>,
}

impl StorageRecoveryGrant {
    pub const fn root(
        principal: StoragePrincipal,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
    ) -> Self {
        Self {
            principal,
            object,
            kind,
            rights,
            parent: None,
        }
    }

    pub const fn derived(
        principal: StoragePrincipal,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        parent: usize,
    ) -> Self {
        Self {
            principal,
            object,
            kind,
            rights,
            parent: Some(parent),
        }
    }
}

/// Exact authenticated recovery authorization supplied by the boot/recovery
/// policy boundary. Checkpoint bytes and their digest are data, not authority.
/// This proof is consumed by reconstruction and is intentionally not clonable.
pub struct AuthenticatedAuthorityCheckpoint {
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    digest: [u8; DIGEST_BYTES],
}

impl AuthenticatedAuthorityCheckpoint {
    /// Creates a proof only after external trusted recovery has authenticated
    /// the exact checkpoint, owner-approved grant policy, selected volume root,
    /// and monotonic epoch.
    ///
    /// # Safety
    ///
    /// The caller must bind all fields to authenticated recovery evidence and
    /// must not issue more than one proof for the same accepted epoch. A raw
    /// digest, object name, principal number, or checkpoint file is never
    /// sufficient evidence.
    pub const unsafe fn new(
        epoch: u64,
        volume: VolumeId,
        root_generation: u64,
        handle_generation: u32,
        digest: [u8; DIGEST_BYTES],
    ) -> Self {
        Self {
            epoch,
            volume,
            root_generation,
            handle_generation,
            digest,
        }
    }
}

pub struct RecoveredStorageAuthorities<const N: usize> {
    table: StorageAuthorityTable<N>,
    handles: [Option<StorageHandle>; N],
    count: usize,
    epoch: u64,
}

impl<const N: usize> RecoveredStorageAuthorities<N> {
    pub fn into_parts(
        self,
    ) -> (
        StorageAuthorityTable<N>,
        [Option<StorageHandle>; N],
        usize,
        u64,
    ) {
        (self.table, self.handles, self.count, self.epoch)
    }
}

/// Volatile replay guard initialized from authenticated rollback-resistant
/// recovery state. Updating this guard is atomic with successful in-memory
/// reconstruction; persisting it remains the caller's recovery obligation.
pub struct AuthorityRecoveryGuard {
    accepted_epoch: u64,
    accepted_handle_generation: u32,
}

impl AuthorityRecoveryGuard {
    pub const fn new(accepted_epoch: u64, accepted_handle_generation: u32) -> Self {
        Self {
            accepted_epoch,
            accepted_handle_generation,
        }
    }

    pub const fn accepted_epoch(&self) -> u64 {
        self.accepted_epoch
    }

    pub const fn accepted_handle_generation(&self) -> u32 {
        self.accepted_handle_generation
    }

    pub fn recover<const N: usize>(
        &mut self,
        input: &[u8],
        proof: AuthenticatedAuthorityCheckpoint,
    ) -> Result<RecoveredStorageAuthorities<N>, AuthorityCheckpointError> {
        let decoded = decode::<N>(input)?;
        if decoded.epoch == 0
            || decoded.root_generation == 0
            || decoded.epoch <= self.accepted_epoch
            || decoded.handle_generation == 0
            || decoded.handle_generation <= self.accepted_handle_generation
            || decoded.epoch != proof.epoch
            || decoded.volume != proof.volume
            || decoded.root_generation != proof.root_generation
            || decoded.handle_generation != proof.handle_generation
            || decoded.digest != proof.digest
        {
            return Err(AuthorityCheckpointError::AuthenticationMismatch);
        }

        let mut table =
            StorageAuthorityTable::<N>::from_recovery_generation(decoded.handle_generation)?;
        let mut handles = [None; N];
        for index in 0..decoded.count {
            let grant = decoded.grants[index].ok_or(AuthorityCheckpointError::Malformed)?;
            let handle = if let Some(parent) = grant.parent {
                let parent_handle = handles[parent].ok_or(AuthorityCheckpointError::Malformed)?;
                let parent_grant =
                    decoded.grants[parent].ok_or(AuthorityCheckpointError::Malformed)?;
                if parent_grant.object != grant.object || parent_grant.kind != grant.kind {
                    return Err(AuthorityCheckpointError::AuthorityAmplification);
                }
                table.derive(
                    parent_handle,
                    parent_grant.principal,
                    grant.principal,
                    grant.rights,
                )?
            } else {
                table.insert(grant.object, grant.kind, grant.rights, grant.principal)?
            };
            handles[index] = Some(handle);
        }
        self.accepted_epoch = decoded.epoch;
        self.accepted_handle_generation = decoded.handle_generation;
        Ok(RecoveredStorageAuthorities {
            table,
            handles,
            count: decoded.count,
            epoch: decoded.epoch,
        })
    }
}

pub fn encode_authority_checkpoint(
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    grants: &[StorageRecoveryGrant],
    output: &mut [u8],
) -> Result<usize, AuthorityCheckpointError> {
    if epoch == 0
        || root_generation == 0
        || handle_generation == 0
        || grants.len() > u16::MAX as usize
    {
        return Err(AuthorityCheckpointError::Malformed);
    }
    let length = checkpoint_length(grants.len())?;
    if output.len() < length {
        return Err(AuthorityCheckpointError::BufferTooSmall);
    }
    for (index, grant) in grants.iter().enumerate() {
        if grant.object.volume() != volume {
            return Err(AuthorityCheckpointError::Malformed);
        }
        validate_grant(grant, index, grants)?;
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4] = VERSION;
    output[6..8].copy_from_slice(&(AUTHORITY_CHECKPOINT_HEADER_BYTES as u16).to_le_bytes());
    output[8..16].copy_from_slice(&epoch.to_le_bytes());
    output[16..32].copy_from_slice(&volume.bytes());
    output[32..40].copy_from_slice(&root_generation.to_le_bytes());
    output[40..42].copy_from_slice(&(grants.len() as u16).to_le_bytes());
    output[42..46].copy_from_slice(&handle_generation.to_le_bytes());

    for (index, grant) in grants.iter().enumerate() {
        let start = AUTHORITY_CHECKPOINT_HEADER_BYTES + index * AUTHORITY_CHECKPOINT_GRANT_BYTES;
        output[start..start + 8].copy_from_slice(&grant.principal.value().to_le_bytes());
        output[start + 8..start + 16].copy_from_slice(&grant.object.local().to_le_bytes());
        output[start + 16] = grant.kind as u8;
        let parent = match grant.parent {
            Some(parent) => {
                u16::try_from(parent + 1).map_err(|_| AuthorityCheckpointError::Malformed)?
            }
            None => 0,
        };
        output[start + 18..start + 20].copy_from_slice(&parent.to_le_bytes());
        output[start + 20..start + 24].copy_from_slice(&grant.rights.bits().to_le_bytes());
    }
    let digest = checkpoint_digest(&output[..length]);
    output[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    Ok(length)
}

pub fn authority_checkpoint_digest(
    input: &[u8],
) -> Result<[u8; DIGEST_BYTES], AuthorityCheckpointError> {
    if input.len() < AUTHORITY_CHECKPOINT_HEADER_BYTES {
        return Err(AuthorityCheckpointError::Malformed);
    }
    Ok(checkpoint_digest(input))
}

struct Decoded<const N: usize> {
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    digest: [u8; DIGEST_BYTES],
    grants: [Option<StorageRecoveryGrant>; N],
    count: usize,
}

fn decode<const N: usize>(input: &[u8]) -> Result<Decoded<N>, AuthorityCheckpointError> {
    if input.len() < AUTHORITY_CHECKPOINT_HEADER_BYTES
        || input[..4] != MAGIC
        || input[4] != VERSION
        || input[5] != 0
        || u16::from_le_bytes([input[6], input[7]]) as usize != AUTHORITY_CHECKPOINT_HEADER_BYTES
        || input[46..48].iter().any(|byte| *byte != 0)
    {
        return Err(AuthorityCheckpointError::Malformed);
    }
    let count = u16::from_le_bytes([input[40], input[41]]) as usize;
    if count > N || input.len() != checkpoint_length(count)? {
        return Err(AuthorityCheckpointError::CapacityMismatch);
    }
    let digest: [u8; DIGEST_BYTES] = input[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES]
        .try_into()
        .map_err(|_| AuthorityCheckpointError::Malformed)?;
    if checkpoint_digest(input) != digest {
        return Err(AuthorityCheckpointError::DigestMismatch);
    }
    let volume = VolumeId::new(
        input[16..32]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    )?;
    let epoch = u64::from_le_bytes(
        input[8..16]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let root_generation = u64::from_le_bytes(
        input[32..40]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let handle_generation = u32::from_le_bytes(
        input[42..46]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let mut grants: [Option<StorageRecoveryGrant>; N] = array::from_fn(|_| None);
    for index in 0..count {
        let start = AUTHORITY_CHECKPOINT_HEADER_BYTES + index * AUTHORITY_CHECKPOINT_GRANT_BYTES;
        if input[start + 17] != 0 || input[start + 24..start + 48].iter().any(|byte| *byte != 0) {
            return Err(AuthorityCheckpointError::Malformed);
        }
        let principal = StoragePrincipal::new(u64::from_le_bytes(
            input[start..start + 8]
                .try_into()
                .map_err(|_| AuthorityCheckpointError::Malformed)?,
        ))?;
        let object = StorageObjectId::new(
            volume,
            u64::from_le_bytes(
                input[start + 8..start + 16]
                    .try_into()
                    .map_err(|_| AuthorityCheckpointError::Malformed)?,
            ),
        )?;
        let kind = match input[start + 16] {
            1 => StorageObjectKind::Volume,
            2 => StorageObjectKind::Directory,
            3 => StorageObjectKind::File,
            _ => return Err(AuthorityCheckpointError::Malformed),
        };
        let rights = StorageRights::from_bits(
            kind,
            u32::from_le_bytes(
                input[start + 20..start + 24]
                    .try_into()
                    .map_err(|_| AuthorityCheckpointError::Malformed)?,
            ),
        )?;
        let encoded_parent = u16::from_le_bytes([input[start + 18], input[start + 19]]) as usize;
        let parent = if encoded_parent == 0 {
            None
        } else {
            Some(encoded_parent - 1)
        };
        let grant = StorageRecoveryGrant {
            principal,
            object,
            kind,
            rights,
            parent,
        };
        validate_grant(&grant, index, &grants[..index])?;
        grants[index] = Some(grant);
    }
    Ok(Decoded {
        epoch,
        volume,
        root_generation,
        handle_generation,
        digest,
        grants,
        count,
    })
}

fn validate_grant(
    grant: &StorageRecoveryGrant,
    index: usize,
    grants: &[impl GrantEntry],
) -> Result<(), AuthorityCheckpointError> {
    StorageRights::from_bits(grant.kind, grant.rights.bits())?;
    if let Some(parent) = grant.parent {
        if parent >= index {
            return Err(AuthorityCheckpointError::InvalidLineage);
        }
        let parent_grant = grants[parent]
            .grant()
            .ok_or(AuthorityCheckpointError::InvalidLineage)?;
        if parent_grant.object != grant.object
            || parent_grant.kind != grant.kind
            || !parent_grant.rights.contains(StorageRights::DELEGATE)
            || !parent_grant.rights.contains(grant.rights)
        {
            return Err(AuthorityCheckpointError::AuthorityAmplification);
        }
    }
    Ok(())
}

trait GrantEntry {
    fn grant(&self) -> Option<&StorageRecoveryGrant>;
}

impl GrantEntry for StorageRecoveryGrant {
    fn grant(&self) -> Option<&StorageRecoveryGrant> {
        Some(self)
    }
}

impl GrantEntry for Option<StorageRecoveryGrant> {
    fn grant(&self) -> Option<&StorageRecoveryGrant> {
        self.as_ref()
    }
}

fn checkpoint_length(count: usize) -> Result<usize, AuthorityCheckpointError> {
    AUTHORITY_CHECKPOINT_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(AUTHORITY_CHECKPOINT_GRANT_BYTES)
                .ok_or(AuthorityCheckpointError::Malformed)?,
        )
        .ok_or(AuthorityCheckpointError::Malformed)
}

fn checkpoint_digest(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..DIGEST_OFFSET]);
    digest.update(&[0; DIGEST_BYTES]);
    digest.update(&input[DIGEST_OFFSET + DIGEST_BYTES..]);
    digest.finalize()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityCheckpointError {
    BufferTooSmall,
    Malformed,
    CapacityMismatch,
    DigestMismatch,
    AuthenticationMismatch,
    InvalidLineage,
    AuthorityAmplification,
    Authority(StorageAuthorityError),
}

impl From<StorageAuthorityError> for AuthorityCheckpointError {
    fn from(value: StorageAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<crate::StorageIdentityError> for AuthorityCheckpointError {
    fn from(_: crate::StorageIdentityError) -> Self {
        Self::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume() -> VolumeId {
        VolumeId::new([0x41; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn principal(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn proof(
        bytes: &[u8],
        epoch: u64,
        root_generation: u64,
        handle_generation: u32,
    ) -> AuthenticatedAuthorityCheckpoint {
        let digest = authority_checkpoint_digest(bytes).unwrap();
        unsafe {
            AuthenticatedAuthorityCheckpoint::new(
                epoch,
                volume(),
                root_generation,
                handle_generation,
                digest,
            )
        }
    }

    #[test]
    fn authenticated_checkpoint_reconstructs_fresh_attenuated_lineage() {
        let root_rights = StorageRights::READ
            .union(StorageRights::WRITE)
            .union(StorageRights::DELEGATE);
        let grants = [
            StorageRecoveryGrant::root(
                principal(1),
                object(7),
                StorageObjectKind::File,
                root_rights,
            ),
            StorageRecoveryGrant::derived(
                principal(2),
                object(7),
                StorageObjectKind::File,
                StorageRights::READ.union(StorageRights::DELEGATE),
                0,
            ),
            StorageRecoveryGrant::derived(
                principal(3),
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                1,
            ),
        ];
        let mut encoded =
            [0xa5; AUTHORITY_CHECKPOINT_HEADER_BYTES + 3 * AUTHORITY_CHECKPOINT_GRANT_BYTES];
        let length =
            encode_authority_checkpoint(9, volume(), 14, 20, &grants, &mut encoded).unwrap();
        assert_eq!(length, encoded.len());
        let mut guard = AuthorityRecoveryGuard::new(8, 19);
        let recovered = guard
            .recover::<4>(&encoded, proof(&encoded, 9, 14, 20))
            .unwrap();
        let (mut table, handles, count, epoch) = recovered.into_parts();
        assert_eq!((count, epoch, guard.accepted_epoch()), (3, 9, 9));
        assert_eq!(guard.accepted_handle_generation(), 20);
        assert_eq!(
            table.authorize(
                handles[2].unwrap(),
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Ok(object(7))
        );
        assert_eq!(table.revoke(handles[0].unwrap(), principal(1)), Ok(3));
        assert_eq!(table.next_recovery_generation(), Ok(22));
        assert_eq!(
            table.authorize(
                handles[2].unwrap(),
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );

        let stale = handles[2].unwrap();
        encode_authority_checkpoint(10, volume(), 15, 22, &grants, &mut encoded).unwrap();
        let recovered = guard
            .recover::<4>(&encoded, proof(&encoded, 10, 15, 22))
            .unwrap();
        let (next_table, next_handles, _, _) = recovered.into_parts();
        assert_ne!(stale.token(), next_handles[2].unwrap().token());
        assert_eq!(
            next_table.authorize(
                stale,
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
    }

    #[test]
    fn corruption_substitution_and_replay_never_advance_guard() {
        let grants = [StorageRecoveryGrant::root(
            principal(1),
            object(2),
            StorageObjectKind::Directory,
            StorageRights::LOOKUP,
        )];
        let mut encoded = [0; AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES];
        encode_authority_checkpoint(5, volume(), 6, 30, &grants, &mut encoded).unwrap();
        let digest = authority_checkpoint_digest(&encoded).unwrap();
        let mut corrupt = encoded;
        corrupt[AUTHORITY_CHECKPOINT_HEADER_BYTES + 8] ^= 1;
        let mut guard = AuthorityRecoveryGuard::new(4, 29);
        let corrupt_proof =
            unsafe { AuthenticatedAuthorityCheckpoint::new(5, volume(), 6, 30, digest) };
        assert_eq!(
            guard.recover::<2>(&corrupt, corrupt_proof).map(|_| ()),
            Err(AuthorityCheckpointError::DigestMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 4);

        let wrong_root =
            unsafe { AuthenticatedAuthorityCheckpoint::new(5, volume(), 7, 30, digest) };
        assert_eq!(
            guard.recover::<2>(&encoded, wrong_root).map(|_| ()),
            Err(AuthorityCheckpointError::AuthenticationMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 4);
        guard
            .recover::<2>(&encoded, proof(&encoded, 5, 6, 30))
            .unwrap();
        assert_eq!(guard.accepted_epoch(), 5);
        assert_eq!(
            guard
                .recover::<2>(&encoded, proof(&encoded, 5, 6, 30))
                .map(|_| ()),
            Err(AuthorityCheckpointError::AuthenticationMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 5);
    }

    #[test]
    fn codec_rejects_amplification_lineage_hidden_data_and_capacity() {
        let root = StorageRecoveryGrant::root(
            principal(1),
            object(3),
            StorageObjectKind::File,
            StorageRights::READ.union(StorageRights::DELEGATE),
        );
        let amplified = StorageRecoveryGrant::derived(
            principal(2),
            object(3),
            StorageObjectKind::File,
            StorageRights::WRITE,
            0,
        );
        let mut encoded =
            [0xa5; AUTHORITY_CHECKPOINT_HEADER_BYTES + 2 * AUTHORITY_CHECKPOINT_GRANT_BYTES];
        assert_eq!(
            encode_authority_checkpoint(1, volume(), 1, 40, &[root, amplified], &mut encoded),
            Err(AuthorityCheckpointError::AuthorityAmplification)
        );
        assert!(encoded.iter().all(|byte| *byte == 0xa5));
        let forward = StorageRecoveryGrant::derived(
            principal(2),
            object(3),
            StorageObjectKind::File,
            StorageRights::READ,
            1,
        );
        assert_eq!(
            encode_authority_checkpoint(1, volume(), 1, 40, &[root, forward], &mut encoded),
            Err(AuthorityCheckpointError::InvalidLineage)
        );
        assert!(encoded.iter().all(|byte| *byte == 0xa5));

        encode_authority_checkpoint(2, volume(), 2, 40, &[root], &mut encoded[..128]).unwrap();
        let mut canonical =
            [0; AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES];
        canonical.copy_from_slice(
            &encoded[..AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES],
        );
        canonical[AUTHORITY_CHECKPOINT_HEADER_BYTES + 24] = 1;
        let digest = checkpoint_digest(&canonical);
        canonical[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
        let mut guard = AuthorityRecoveryGuard::new(1, 39);
        assert_eq!(
            guard
                .recover::<1>(&canonical, proof(&canonical, 2, 2, 40))
                .map(|_| ()),
            Err(AuthorityCheckpointError::Malformed)
        );
        assert_eq!(guard.accepted_epoch(), 1);
        assert_eq!(
            guard
                .recover::<0>(&encoded[..128], proof(&encoded[..128], 2, 2, 40),)
                .map(|_| ()),
            Err(AuthorityCheckpointError::CapacityMismatch)
        );
    }
}
