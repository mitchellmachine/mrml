//! Crash-durable Linux storage for the exact current trust-policy generation.

use mrml_crypto::Sha3_512;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
    remove_file, rename_file,
};

const FILE_MAGIC: &[u8; 8] = b"MRGTPF01";
const FILE_DIGEST_BYTES: usize = 64;
const MAX_POLICY_FILE_BYTES: usize = 8 + 4 + MAX_ENCODED_TRUST_POLICY_BYTES + FILE_DIGEST_BYTES;

use crate::{
    EmergencyRecoveryAuthority, EmergencyRecoveryAuthorization, EmergencyRecoveryTransition,
    HybridPolicyError, MAX_ENCODED_TRUST_POLICY_BYTES, TrustGeneration, TrustPolicyCandidate,
    TrustPolicyState, encode_trust_policy, parse_trust_policy,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPolicyFileError {
    Resource,
    Io,
    AlreadyExists,
    Integrity,
    StaleLock,
    StaleGeneration,
    Policy(HybridPolicyError),
    Durability,
    UncertainCommit,
}

/// One repository's exact current policy. The directory is an authority-scoped
/// storage location supplied by the caller; its name never grants policy
/// authority.
pub struct LinuxDurableTrustPolicyStore {
    root: Text,
    active: Text,
    temporary: Text,
    lock: Text,
}

impl LinuxDurableTrustPolicyStore {
    pub fn create(path: &str, state: &TrustPolicyState) -> Result<Self, TrustPolicyFileError> {
        create_dir_all(path).map_err(|_| TrustPolicyFileError::Io)?;
        let store = Self::paths(path)?;
        if path_exists(&store.active) {
            return Err(TrustPolicyFileError::AlreadyExists);
        }
        let bytes = encode_file(state)?;
        let mut file =
            File::create_new(&store.temporary).map_err(|_| TrustPolicyFileError::AlreadyExists)?;
        file.write_all(&bytes)
            .map_err(|_| TrustPolicyFileError::Io)?;
        file.sync().map_err(|_| TrustPolicyFileError::Durability)?;
        drop(file);
        rename_file(&store.temporary, &store.active).map_err(|_| TrustPolicyFileError::Io)?;
        sync_policy_directory(&store.root)?;
        if store.load()? != *state {
            return Err(TrustPolicyFileError::Integrity);
        }
        Ok(store)
    }

    pub fn open(path: &str) -> Result<Self, TrustPolicyFileError> {
        let store = Self::paths(path)?;
        store.load()?;
        Ok(store)
    }

    pub fn load(&self) -> Result<TrustPolicyState, TrustPolicyFileError> {
        let mut file =
            File::open_regular(&self.active).map_err(|_| TrustPolicyFileError::Integrity)?;
        let length = usize::try_from(file.len().map_err(|_| TrustPolicyFileError::Integrity)?)
            .map_err(|_| TrustPolicyFileError::Resource)?;
        if length == 0 || length > MAX_POLICY_FILE_BYTES {
            return Err(TrustPolicyFileError::Resource);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| TrustPolicyFileError::Resource)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| TrustPolicyFileError::Integrity)?;
        parse_file(&bytes)
    }

    /// Consumes one authenticated emergency authorization and selects its exact
    /// next policy generation. Replay fails against the reread current digest
    /// and generation before any temporary file is created.
    #[allow(clippy::too_many_arguments)]
    pub fn emergency_transition(
        &self,
        expected_generation: TrustGeneration,
        expected_digest: [u8; 64],
        authority: &EmergencyRecoveryAuthority,
        transition: &EmergencyRecoveryTransition,
        authorization: EmergencyRecoveryAuthorization,
        candidate: TrustPolicyCandidate,
    ) -> Result<TrustPolicyState, TrustPolicyFileError> {
        let lock = File::create_new(&self.lock).map_err(|_| TrustPolicyFileError::StaleLock)?;
        lock.sync().map_err(|_| TrustPolicyFileError::Durability)?;
        drop(lock);
        sync_policy_directory(&self.root)?;

        let result = self.emergency_transition_while_locked(
            expected_generation,
            expected_digest,
            authority,
            transition,
            authorization,
            candidate,
        );
        match result {
            Ok(next) => {
                remove_file(&self.lock).map_err(|_| TrustPolicyFileError::UncertainCommit)?;
                sync_policy_directory(&self.root)
                    .map_err(|_| TrustPolicyFileError::UncertainCommit)?;
                Ok(next)
            }
            Err(error) => {
                if matches!(
                    error,
                    TrustPolicyFileError::StaleGeneration | TrustPolicyFileError::Policy(_)
                ) {
                    let _ = remove_file(&self.lock);
                    let _ = sync_policy_directory(&self.root);
                }
                Err(error)
            }
        }
    }

    fn emergency_transition_while_locked(
        &self,
        expected_generation: TrustGeneration,
        expected_digest: [u8; 64],
        authority: &EmergencyRecoveryAuthority,
        transition: &EmergencyRecoveryTransition,
        authorization: EmergencyRecoveryAuthorization,
        candidate: TrustPolicyCandidate,
    ) -> Result<TrustPolicyState, TrustPolicyFileError> {
        let current = self.load()?;
        if current.generation() != expected_generation || current.digest() != expected_digest {
            return Err(TrustPolicyFileError::StaleGeneration);
        }
        let next = current
            .emergency_transition(authority, transition, authorization, candidate)
            .map_err(TrustPolicyFileError::Policy)?;
        let bytes = encode_file(&next)?;
        let mut temporary =
            File::create_new(&self.temporary).map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        temporary
            .write_all(&bytes)
            .map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        temporary
            .sync()
            .map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        drop(temporary);
        rename_file(&self.temporary, &self.active)
            .map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        sync_policy_directory(&self.root).map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        let reopened = self
            .load()
            .map_err(|_| TrustPolicyFileError::UncertainCommit)?;
        if reopened != next {
            return Err(TrustPolicyFileError::UncertainCommit);
        }
        Ok(next)
    }

    fn paths(path: &str) -> Result<Self, TrustPolicyFileError> {
        let root = canonical_path(path).map_err(|_| TrustPolicyFileError::Io)?;
        if !path_is_directory(&root) {
            return Err(TrustPolicyFileError::Io);
        }
        Ok(Self {
            active: join_path(&root, "trust-policy.current"),
            temporary: join_path(&root, "trust-policy.next"),
            lock: join_path(&root, "trust-policy.lock"),
            root,
        })
    }
}

fn encode_file(state: &TrustPolicyState) -> Result<Vector<u8>, TrustPolicyFileError> {
    let policy = encode_trust_policy(state).map_err(TrustPolicyFileError::Policy)?;
    let length = u32::try_from(policy.len()).map_err(|_| TrustPolicyFileError::Resource)?;
    let mut bytes = Vector::new();
    bytes
        .try_reserve_exact(8 + 4 + policy.len() + FILE_DIGEST_BYTES)
        .map_err(|_| TrustPolicyFileError::Resource)?;
    bytes.extend(FILE_MAGIC.iter().copied());
    bytes.extend(length.to_be_bytes());
    bytes.extend(policy.iter().copied());
    let digest = Sha3_512::digest(&bytes);
    bytes.extend(digest);
    Ok(bytes)
}

fn parse_file(bytes: &[u8]) -> Result<TrustPolicyState, TrustPolicyFileError> {
    if bytes.len() < 8 + 4 + FILE_DIGEST_BYTES || &bytes[..8] != FILE_MAGIC {
        return Err(TrustPolicyFileError::Integrity);
    }
    let mut length = [0; 4];
    length.copy_from_slice(&bytes[8..12]);
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| TrustPolicyFileError::Resource)?;
    let end = 12usize
        .checked_add(length)
        .ok_or(TrustPolicyFileError::Resource)?;
    if length == 0
        || length > MAX_ENCODED_TRUST_POLICY_BYTES
        || end.checked_add(FILE_DIGEST_BYTES) != Some(bytes.len())
    {
        return Err(TrustPolicyFileError::Integrity);
    }
    if Sha3_512::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err(TrustPolicyFileError::Integrity);
    }
    let state = parse_trust_policy(&bytes[12..end]).map_err(|_| TrustPolicyFileError::Integrity)?;
    if &*encode_file(&state)? != bytes {
        return Err(TrustPolicyFileError::Integrity);
    }
    Ok(state)
}

#[cfg(unix)]
fn sync_policy_directory(path: &str) -> Result<(), TrustPolicyFileError> {
    mrml_runtime::sync_directory(path).map_err(|_| TrustPolicyFileError::Durability)
}

#[cfg(not(unix))]
fn sync_policy_directory(_: &str) -> Result<(), TrustPolicyFileError> {
    Err(TrustPolicyFileError::Durability)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        AuthorizedHybridPair, FullRefName, PolicyPairStatus, RepositoryIdentity,
        RevocationGeneration,
    };
    use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ml_dsa_65_keygen};
    use mrml_openpgp::SigningKeyV6;
    use mrml_runtime::{process_id, remove_dir_all, write_new_file};

    fn root(label: &str) -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-trust-policy-{label}-{}", process_id()),
        )
    }

    fn pair() -> AuthorizedHybridPair {
        let openpgp = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let mut public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9; 32], &mut public, &mut secret).unwrap();
        AuthorizedHybridPair::bind(&openpgp.public_key(), &public)
    }

    fn candidate(
        repository: RepositoryIdentity,
        pair: AuthorizedHybridPair,
        generation: u64,
        previous_policy_digest: [u8; 64],
        emergency_policy_digest: [u8; 64],
    ) -> TrustPolicyCandidate {
        TrustPolicyCandidate {
            repository,
            generation: TrustGeneration(generation),
            previous_policy_digest,
            revocation_generation: RevocationGeneration(generation),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: false,
            legacy_checkpoint: None,
            hybrid_cutover: None,
            emergency_policy_digest: Some(emergency_policy_digest),
            active_pairs: [pair].into(),
            pair_statuses: [PolicyPairStatus::new(pair, 1, 1_000, None).unwrap()].into(),
            legacy_v4_statuses: Vector::new(),
            revoked_legacy_v4: Vector::new(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        }
    }

    fn fixture() -> (
        Text,
        LinuxDurableTrustPolicyStore,
        TrustPolicyState,
        EmergencyRecoveryAuthority,
        EmergencyRecoveryAuthority,
        AuthorizedHybridPair,
    ) {
        let root = root("fixture");
        let _ = remove_dir_all(&root);
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let pair = pair();
        let authority = EmergencyRecoveryAuthority::new(
            repository.clone(),
            7,
            1,
            1_000,
            1,
            [pair].into(),
            Vector::new(),
            Vector::new(),
        )
        .unwrap();
        let next_authority = EmergencyRecoveryAuthority::new(
            repository.clone(),
            8,
            1,
            2_000,
            1,
            [pair].into(),
            Vector::new(),
            Vector::new(),
        )
        .unwrap();
        let state = TrustPolicyState::establish(candidate(
            repository,
            pair,
            1,
            [0; 64],
            authority.digest(),
        ))
        .unwrap();
        let store = LinuxDurableTrustPolicyStore::create(&root, &state).unwrap();
        (root, store, state, authority, next_authority, pair)
    }

    #[test]
    fn create_reopen_torn_tamper_and_stale_lock_fail_closed() {
        let (root, store, state, _, _, _) = fixture();
        assert_eq!(store.load().unwrap(), state);
        assert_eq!(
            LinuxDurableTrustPolicyStore::open(&root)
                .unwrap()
                .load()
                .unwrap(),
            state
        );
        assert_eq!(
            LinuxDurableTrustPolicyStore::create(&root, &state).err(),
            Some(TrustPolicyFileError::AlreadyExists)
        );
        write_new_file(&store.lock, b"locked").unwrap();
        let current = store.load().unwrap();
        let result = store.emergency_transition(
            current.generation(),
            current.digest(),
            &EmergencyRecoveryAuthority::new(
                current.repository().clone(),
                1,
                1,
                2,
                1,
                [current.active_pairs()[0]].into(),
                Vector::new(),
                Vector::new(),
            )
            .unwrap(),
            &EmergencyRecoveryTransition::new(
                current.repository().clone(),
                1,
                current.digest(),
                current.generation(),
                current.revocation_generation(),
                [1; 64],
                TrustGeneration(2),
                RevocationGeneration(2),
                [2; 64],
                1,
            )
            .unwrap(),
            EmergencyRecoveryAuthorization::exact_test_authorization(
                &EmergencyRecoveryAuthority::new(
                    current.repository().clone(),
                    1,
                    1,
                    2,
                    1,
                    [current.active_pairs()[0]].into(),
                    Vector::new(),
                    Vector::new(),
                )
                .unwrap(),
                &EmergencyRecoveryTransition::new(
                    current.repository().clone(),
                    1,
                    current.digest(),
                    current.generation(),
                    current.revocation_generation(),
                    [1; 64],
                    TrustGeneration(2),
                    RevocationGeneration(2),
                    [2; 64],
                    1,
                )
                .unwrap(),
            ),
            candidate(
                current.repository().clone(),
                current.active_pairs()[0],
                2,
                current.digest(),
                [2; 64],
            ),
        );
        assert_eq!(result.err(), Some(TrustPolicyFileError::StaleLock));
        remove_file(&store.lock).unwrap();

        let bytes = encode_file(&state).unwrap();
        remove_file(&store.active).unwrap();
        let mut torn = File::create_new(&store.active).unwrap();
        torn.write_all(&bytes[..bytes.len() / 2]).unwrap();
        torn.sync().unwrap();
        assert!(LinuxDurableTrustPolicyStore::open(&root).is_err());
        drop(torn);
        remove_file(&store.active).unwrap();
        let mut corrupted = bytes;
        corrupted[16] ^= 1;
        let mut file = File::create_new(&store.active).unwrap();
        file.write_all(&corrupted).unwrap();
        file.sync().unwrap();
        assert!(LinuxDurableTrustPolicyStore::open(&root).is_err());
        drop(file);
        remove_dir_all(&root).unwrap();
    }

    #[test]
    fn emergency_update_reopens_exact_next_state_and_replay_is_stale() {
        let (root, store, state, authority, next_authority, pair) = fixture();
        let next_policy = TrustPolicyState::from_emergency_candidate_for_test(candidate(
            state.repository().clone(),
            pair,
            2,
            state.digest(),
            next_authority.digest(),
        ));
        let transition = EmergencyRecoveryTransition::new(
            state.repository().clone(),
            authority.generation(),
            state.digest(),
            state.generation(),
            state.revocation_generation(),
            next_policy.digest(),
            next_policy.generation(),
            next_policy.revocation_generation(),
            next_authority.digest(),
            100,
        )
        .unwrap();
        let authorization =
            EmergencyRecoveryAuthorization::exact_test_authorization(&authority, &transition);
        let persisted = store
            .emergency_transition(
                state.generation(),
                state.digest(),
                &authority,
                &transition,
                authorization,
                candidate(
                    state.repository().clone(),
                    pair,
                    2,
                    state.digest(),
                    next_authority.digest(),
                ),
            )
            .unwrap();
        assert_eq!(persisted, next_policy);
        assert_eq!(
            LinuxDurableTrustPolicyStore::open(&root)
                .unwrap()
                .load()
                .unwrap(),
            next_policy
        );
        let replay = store.emergency_transition(
            state.generation(),
            state.digest(),
            &authority,
            &transition,
            EmergencyRecoveryAuthorization::exact_test_authorization(&authority, &transition),
            candidate(
                state.repository().clone(),
                pair,
                2,
                state.digest(),
                next_authority.digest(),
            ),
        );
        assert_eq!(replay.err(), Some(TrustPolicyFileError::StaleGeneration));
        remove_dir_all(&root).unwrap();
    }
}
