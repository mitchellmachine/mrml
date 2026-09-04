use mrml_crypto::erase_secret_bytes;
use mrml_git::{
    AuthorizedHybridPair, DurableDetachedCommitProofDirectory, GitObjectType,
    HybridVerificationRequest, LinuxDurableTrustPolicyStore, ObjectFormat, RepositoryIdentity,
    SignaturePurpose, TrustGeneration, encode_trust_policy, parse_trust_policy,
    verify_hybrid_signature,
};
use mrml_git_authority::{
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, AuthorityCapability,
    AuthorityDispatchError, AuthorityFrame, AuthorityFrameKind, AuthorityListener,
    AuthorityOperation, AuthorityPeer, AuthorityReplayWindow, AuthoritySession,
    LinuxAuthorityCandidateStore, LinuxAuthorityGenerationStore, MAX_AUTHORITY_PAYLOAD_BYTES,
    ProductionAuthority, ProductionAuthorityCatalog, decode_frame, encode_frame,
};
use mrml_openpgp::{
    MAX_OPENPGP_PUBLIC_KEY_BYTES, MAX_OPENPGP_SIGNATURE_BYTES, parse_public_key_v6_ascii,
};
use mrml_runtime::DirectoryCapability;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EX_USAGE: i32 = 64;
const EX_CONFIG: i32 = 78;
const STATUS_OK: u16 = 0;
const STATUS_UNAVAILABLE: u16 = 1;
const MAX_AUTHORITY_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_AUTHORITY_REPOSITORIES: usize = 100_000;
const AUTHORITY_WORKERS: usize = 16;
const AUTHORITY_QUEUE_CAPACITY: usize = 256;

fn main() {
    if run().is_err() {
        eprintln!("mrml-git-authority: operation failed closed");
        std::process::exit(EX_CONFIG);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    if let [
        _,
        command,
        policy_root,
        repository,
        next_openpgp,
        next_ml_dsa,
        next_owner_uid,
        valid_from,
        valid_until,
        previous_output,
        next_output,
        output_owner_uid,
    ] = arguments.as_slice()
        && command == "construct-overlap-policy"
    {
        return construct_overlap_policy(
            policy_root,
            repository,
            next_openpgp,
            next_ml_dsa,
            next_owner_uid.parse().map_err(|_| ())?,
            valid_from.parse().map_err(|_| ())?,
            valid_until.parse().map_err(|_| ())?,
            Path::new(previous_output),
            Path::new(next_output),
            output_owner_uid.parse().map_err(|_| ())?,
        );
    }
    if let [
        _,
        command,
        policy_root,
        repository,
        retiring_openpgp,
        retiring_ml_dsa,
        retiring_owner_uid,
        retired_at,
        previous_output,
        next_output,
        output_owner_uid,
    ] = arguments.as_slice()
        && command == "construct-retirement-policy"
    {
        return construct_retirement_policy(
            policy_root,
            repository,
            retiring_openpgp,
            retiring_ml_dsa,
            retiring_owner_uid.parse().map_err(|_| ())?,
            retired_at.parse().map_err(|_| ())?,
            Path::new(previous_output),
            Path::new(next_output),
            output_owner_uid.parse().map_err(|_| ())?,
        );
    }
    if let [
        _,
        command,
        policy_root,
        repository,
        expected_policy,
        expected_owner_uid,
    ] = arguments.as_slice()
        && command == "verify-selected-policy"
    {
        return verify_selected_policy(
            policy_root,
            repository,
            expected_policy,
            expected_owner_uid.parse().map_err(|_| ())?,
        );
    }
    match arguments.as_slice() {
        [
            _,
            command,
            _socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            generations,
            repository,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
            repository_generation,
        ] if matches!(
            command.as_str(),
            "check-config" | "describe-signer" | "describe-receipt-verifier"
        ) =>
        {
            let _ = parse_peer(peer_uid, peer_gid)?;
            let authority_peer = parse_peer(own_uid, own_gid)?;
            let _capability = read_capability(capability, authority_peer.uid)?;
            let authority = load_authority(
                authority_peer.uid,
                policy,
                proofs,
                generations,
                repository,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
                repository_generation.parse().map_err(|_| ())?,
            )?;
            if command == "describe-signer" {
                print_hex(&authority.signer_identity());
            } else if command == "describe-receipt-verifier" {
                print_hex(&authority.receipt_verification_key());
            } else {
                println!("valid");
            }
            Ok(())
        }
        [
            _,
            command,
            socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            generations,
            repository,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
            repository_generation,
        ] if command == "serve" => serve(
            socket,
            capability,
            parse_peer(peer_uid, peer_gid)?,
            parse_peer(own_uid, own_gid)?,
            policy,
            proofs,
            generations,
            repository,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time.parse().map_err(|_| ())?,
            repository_generation.parse().map_err(|_| ())?,
        ),
        [
            _,
            command,
            socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            generations,
            catalog,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
        ] if command == "serve-catalog" => {
            let authority_peer = parse_peer(own_uid, own_gid)?;
            let authority = load_production_authority_catalog(
                authority_peer.uid,
                policy,
                proofs,
                generations,
                catalog,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
            )?;
            serve_authority_catalog(
                socket,
                capability,
                parse_peer(peer_uid, peer_gid)?,
                authority_peer,
                authority,
            )
        }
        [
            _,
            command,
            _socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            generations,
            catalog,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
        ] if command == "check-catalog" => {
            let _ = parse_peer(peer_uid, peer_gid)?;
            let authority_peer = parse_peer(own_uid, own_gid)?;
            let _ = read_capability(capability, authority_peer.uid)?;
            let _ = load_production_authority_catalog(
                authority_peer.uid,
                policy,
                proofs,
                generations,
                catalog,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
            )?;
            println!("valid");
            Ok(())
        }
        [
            _,
            command,
            socket,
            capability,
            own_uid,
            own_gid,
            authority_uid,
            authority_gid,
        ] if command == "healthcheck" => healthcheck(
            socket,
            capability,
            parse_peer(own_uid, own_gid)?,
            parse_peer(authority_uid, authority_gid)?,
        ),
        [_, command, socket, own_uid, socket_gid] if command == "listener-health" => {
            listener_health(
                Path::new(socket),
                own_uid.parse().map_err(|_| ())?,
                socket_gid.parse().map_err(|_| ())?,
            )
        }
        [
            _,
            command,
            policy_root,
            repository,
            next_policy,
            previous_openpgp,
            previous_ml_dsa,
            previous_openpgp_signature,
            previous_ml_dsa_signature,
            next_openpgp,
            next_ml_dsa,
            next_openpgp_signature,
            next_ml_dsa_signature,
            validation_time,
            expected_generation,
            expected_digest,
            own_uid,
        ] if command == "transition-policy" => transition_policy(
            policy_root,
            repository,
            next_policy,
            previous_openpgp,
            previous_ml_dsa,
            previous_openpgp_signature,
            previous_ml_dsa_signature,
            next_openpgp,
            next_ml_dsa,
            next_openpgp_signature,
            next_ml_dsa_signature,
            validation_time.parse().map_err(|_| ())?,
            expected_generation.parse().map_err(|_| ())?,
            parse_lower_hex_64(expected_digest)?,
            own_uid.parse().map_err(|_| ())?,
        ),
        _ => {
            eprintln!(
                "usage: mrml-git-authority construct-overlap-policy POLICY_ROOT REPOSITORY NEXT_OPENPGP NEXT_ML_DSA NEXT_OWNER_UID VALID_FROM VALID_UNTIL PREVIOUS_OUTPUT NEXT_OUTPUT OUTPUT_OWNER_UID\n       mrml-git-authority construct-retirement-policy POLICY_ROOT REPOSITORY RETIRING_OPENPGP RETIRING_ML_DSA RETIRING_OWNER_UID RETIRED_AT PREVIOUS_OUTPUT NEXT_OUTPUT OUTPUT_OWNER_UID\n       mrml-git-authority verify-selected-policy POLICY_ROOT REPOSITORY EXPECTED_POLICY EXPECTED_OWNER_UID\n       mrml-git-authority serve-catalog SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT CATALOG OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME\n       mrml-git-authority check-catalog SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT CATALOG OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME\n       mrml-git-authority serve SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority check-config SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority describe-signer SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority describe-receipt-verifier SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT GENERATION_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority transition-policy POLICY_ROOT REPOSITORY NEXT_POLICY PREVIOUS_OPENPGP PREVIOUS_ML_DSA PREVIOUS_OPENPGP_SIGNATURE PREVIOUS_ML_DSA_SIGNATURE NEXT_OPENPGP NEXT_ML_DSA NEXT_OPENPGP_SIGNATURE NEXT_ML_DSA_SIGNATURE VALIDATION_TIME CURRENT_GENERATION CURRENT_DIGEST OWN_UID\n       mrml-git-authority listener-health SOCKET OWN_UID SOCKET_GID\n       mrml-git-authority healthcheck SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID"
            );
            std::process::exit(EX_USAGE);
        }
    }
}

fn verify_selected_policy(
    policy_root: &str,
    repository: &str,
    expected_policy_path: &str,
    expected_owner_uid: u32,
) -> Result<(), ()> {
    if expected_owner_uid == 0 {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let store = LinuxDurableTrustPolicyStore::open(
        policy_storage_path(policy_root, &repository)?
            .to_str()
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let selected = store.load().map_err(|_| ())?;
    let selected_bytes = encode_trust_policy(&selected).map_err(|_| ())?;
    let expected = read_regular(
        expected_policy_path,
        1,
        mrml_git::MAX_ENCODED_TRUST_POLICY_BYTES,
        expected_owner_uid,
        false,
    )?;
    if selected.repository() != &repository || selected_bytes[..] != expected[..] {
        return Err(());
    }
    println!(
        "generation={} digest={}",
        selected.generation().0,
        lower_hex(&selected.digest())
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn construct_overlap_policy(
    policy_root: &str,
    repository: &str,
    next_openpgp_path: &str,
    next_ml_dsa_path: &str,
    next_owner_uid: u32,
    valid_from: u64,
    valid_until: u64,
    previous_output: &Path,
    next_output: &Path,
    output_owner_uid: u32,
) -> Result<(), ()> {
    if next_owner_uid == 0 || output_owner_uid == 0 || valid_from >= valid_until {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let store = LinuxDurableTrustPolicyStore::open(
        policy_storage_path(policy_root, &repository)?
            .to_str()
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let current = store.load().map_err(|_| ())?;
    if current.repository() != &repository {
        return Err(());
    }
    let (next_openpgp, next_ml_dsa) =
        read_hybrid_public_pair(next_openpgp_path, next_ml_dsa_path, next_owner_uid)?;
    let next_pair = AuthorizedHybridPair::bind(&next_openpgp, &next_ml_dsa);
    let previous_bytes = encode_trust_policy(&current).map_err(|_| ())?;
    let next_bytes = current
        .encode_overlap_successor(next_pair, valid_from, valid_until)
        .map_err(|_| ())?;
    write_public_output(previous_output, &previous_bytes, output_owner_uid)?;
    write_public_output(next_output, &next_bytes, output_owner_uid)?;
    let next = parse_trust_policy(&next_bytes).map_err(|_| ())?;
    println!(
        "previous_generation={} previous_digest={} generation={} digest={}",
        current.generation().0,
        lower_hex(&current.digest()),
        next.generation().0,
        lower_hex(&next.digest())
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn construct_retirement_policy(
    policy_root: &str,
    repository: &str,
    retiring_openpgp_path: &str,
    retiring_ml_dsa_path: &str,
    retiring_owner_uid: u32,
    retired_at: u64,
    previous_output: &Path,
    next_output: &Path,
    output_owner_uid: u32,
) -> Result<(), ()> {
    if retiring_owner_uid == 0 || output_owner_uid == 0 || retired_at == 0 {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let store = LinuxDurableTrustPolicyStore::open(
        policy_storage_path(policy_root, &repository)?
            .to_str()
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let current = store.load().map_err(|_| ())?;
    if current.repository() != &repository {
        return Err(());
    }
    let (retiring_openpgp, retiring_ml_dsa) = read_hybrid_public_pair(
        retiring_openpgp_path,
        retiring_ml_dsa_path,
        retiring_owner_uid,
    )?;
    let retiring_pair = AuthorizedHybridPair::bind(&retiring_openpgp, &retiring_ml_dsa);
    let previous_bytes = encode_trust_policy(&current).map_err(|_| ())?;
    let next_bytes = current
        .encode_retirement_successor(retiring_pair, retired_at)
        .map_err(|_| ())?;
    write_public_output(previous_output, &previous_bytes, output_owner_uid)?;
    write_public_output(next_output, &next_bytes, output_owner_uid)?;
    let next = parse_trust_policy(&next_bytes).map_err(|_| ())?;
    println!(
        "previous_generation={} previous_digest={} generation={} digest={}",
        current.generation().0,
        lower_hex(&current.digest()),
        next.generation().0,
        lower_hex(&next.digest())
    );
    Ok(())
}

fn write_public_output(path: &Path, bytes: &[u8], expected_owner: u32) -> Result<(), ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let parent_path = path.parent().and_then(Path::to_str).ok_or(())?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or(())?;
    let parent = DirectoryCapability::open_root(parent_path).map_err(|_| ())?;
    let metadata = parent.metadata().map_err(|_| ())?;
    if metadata.uid != expected_owner || metadata.mode & 0o022 != 0 {
        return Err(());
    }
    install_or_verify_public(&parent, name, bytes, &metadata)?;
    parent.sync().map_err(|_| ())
}

fn transition_policy(
    policy_root: &str,
    repository: &str,
    next_policy_path: &str,
    previous_openpgp_path: &str,
    previous_ml_dsa_path: &str,
    previous_openpgp_signature_path: &str,
    previous_ml_dsa_signature_path: &str,
    next_openpgp_path: &str,
    next_ml_dsa_path: &str,
    next_openpgp_signature_path: &str,
    next_ml_dsa_signature_path: &str,
    validation_time: u64,
    expected_generation: u64,
    expected_digest: [u8; 64],
    own_uid: u32,
) -> Result<(), ()> {
    if validation_time == 0 || expected_generation == 0 || own_uid == 0 {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let policy_path = policy_storage_path(policy_root, &repository)?;
    let store = LinuxDurableTrustPolicyStore::open(policy_path.to_str().ok_or(())?)
        .map_err(|_| transition_failure("policy_store"))?;
    let current = store
        .load()
        .map_err(|_| transition_failure("current_policy"))?;
    if current.repository() != &repository {
        return Err(());
    }
    let next_policy_bytes = read_regular(
        next_policy_path,
        1,
        mrml_git::MAX_ENCODED_TRUST_POLICY_BYTES,
        own_uid,
        false,
    )
    .map_err(|_| transition_failure("next_policy_input"))?;
    let next = parse_trust_policy(&next_policy_bytes)
        .map_err(|_| transition_failure("next_policy_parse"))?;
    if next.repository() != &repository {
        return Err(());
    }
    let (previous_openpgp, previous_ml_dsa) =
        read_hybrid_public_pair(previous_openpgp_path, previous_ml_dsa_path, own_uid)
            .map_err(|_| transition_failure("previous_public_pair"))?;
    let (next_openpgp, next_ml_dsa) =
        read_hybrid_public_pair(next_openpgp_path, next_ml_dsa_path, own_uid)
            .map_err(|_| transition_failure("next_public_pair"))?;
    let previous_pair = AuthorizedHybridPair::bind(&previous_openpgp, &previous_ml_dsa);
    let next_pair = AuthorizedHybridPair::bind(&next_openpgp, &next_ml_dsa);
    let previous_policy = current
        .active_verification_policy_at(previous_pair, validation_time, true)
        .map_err(|_| transition_failure("previous_pair_inactive"))?;
    let next_verification_policy = next
        .active_verification_policy_at(next_pair, validation_time, true)
        .map_err(|_| transition_failure("next_pair_inactive"))?;
    let previous_openpgp_signature = read_regular(
        previous_openpgp_signature_path,
        1,
        MAX_OPENPGP_SIGNATURE_BYTES,
        own_uid,
        false,
    )
    .map_err(|_| transition_failure("previous_openpgp_signature_input"))?;
    let previous_ml_dsa_signature = read_regular(
        previous_ml_dsa_signature_path,
        mrml_crypto::ML_DSA_65_SIGNATURE_BYTES,
        mrml_crypto::ML_DSA_65_SIGNATURE_BYTES,
        own_uid,
        false,
    )
    .map_err(|_| transition_failure("previous_ml_dsa_signature_input"))?;
    let next_openpgp_signature = read_regular(
        next_openpgp_signature_path,
        1,
        MAX_OPENPGP_SIGNATURE_BYTES,
        own_uid,
        false,
    )
    .map_err(|_| transition_failure("next_openpgp_signature_input"))?;
    let next_ml_dsa_signature = read_regular(
        next_ml_dsa_signature_path,
        mrml_crypto::ML_DSA_65_SIGNATURE_BYTES,
        mrml_crypto::ML_DSA_65_SIGNATURE_BYTES,
        own_uid,
        false,
    )
    .map_err(|_| transition_failure("next_ml_dsa_signature_input"))?;
    let previous_request = HybridVerificationRequest {
        repository: &repository,
        object_format: ObjectFormat::Sha256,
        object_type: GitObjectType::KeyRotation,
        purpose: SignaturePurpose::KeyRotation,
        trust_generation: current.generation(),
        revocation_generation: current.revocation_generation(),
        payload: &next_policy_bytes,
        openpgp_signature: &previous_openpgp_signature,
        ml_dsa_signature: &previous_ml_dsa_signature,
    };
    let mut scratch = vec![0u8; MAX_OPENPGP_SIGNATURE_BYTES];
    let previous_authorization = verify_hybrid_signature(
        &previous_policy,
        &previous_openpgp,
        &previous_ml_dsa,
        &previous_request,
        &mut scratch,
    )
    .map_err(|_| transition_failure("previous_authorization"))?;
    let next_request = HybridVerificationRequest {
        repository: &repository,
        object_format: ObjectFormat::Sha256,
        object_type: GitObjectType::KeyRotation,
        purpose: SignaturePurpose::KeyRotation,
        trust_generation: next.generation(),
        revocation_generation: next.revocation_generation(),
        payload: &next_policy_bytes,
        openpgp_signature: &next_openpgp_signature,
        ml_dsa_signature: &next_ml_dsa_signature,
    };
    let next_authorization = verify_hybrid_signature(
        &next_verification_policy,
        &next_openpgp,
        &next_ml_dsa,
        &next_request,
        &mut scratch,
    )
    .map_err(|_| transition_failure("next_authorization"))?;
    #[cfg(test)]
    pause_transition_test_boundary(&policy_path, "signature-verification-complete");
    install_transition_verifier(
        &policy_path,
        next.generation(),
        next_openpgp_path,
        next_ml_dsa_path,
        own_uid,
    )
    .map_err(|_| transition_failure("verifier_install"))?;
    #[cfg(test)]
    pause_transition_test_boundary(&policy_path, "trust-snapshot-published");
    let selected = store
        .transition(
            TrustGeneration(expected_generation),
            expected_digest,
            next,
            &previous_authorization,
            &next_authorization,
        )
        .map_err(|_| transition_failure("durable_selection"))?;
    println!(
        "generation={} digest={}",
        selected.generation().0,
        lower_hex(&selected.digest())
    );
    Ok(())
}

#[cfg(test)]
fn pause_transition_test_boundary(policy_path: &Path, boundary: &str) {
    if std::env::var("MRML_AUTHORITY_TRANSITION_TEST_BOUNDARY").as_deref() != Ok(boundary) {
        return;
    }
    let marker = policy_path.join(".transition-test-boundary");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .unwrap();
    std::io::Write::write_all(&mut file, boundary.as_bytes()).unwrap();
    file.sync_all().unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn transition_failure(category: &'static str) {
    eprintln!("component=mrml-git-authority event=trust_transition_failed category={category}");
}

fn install_transition_verifier(
    policy_path: &Path,
    generation: TrustGeneration,
    openpgp_path: &str,
    ml_dsa_path: &str,
    input_owner_uid: u32,
) -> Result<(), ()> {
    let openpgp = read_regular(
        openpgp_path,
        1,
        MAX_OPENPGP_PUBLIC_KEY_BYTES,
        input_owner_uid,
        false,
    )?;
    let ml_dsa = read_regular(
        ml_dsa_path,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        input_owner_uid,
        false,
    )?;
    let policy = DirectoryCapability::open_root(policy_path.to_str().ok_or(())?).map_err(|_| ())?;
    let policy_metadata = policy.metadata().map_err(|_| ())?;
    let keyring = match policy.open_directory("verification-keys") {
        Ok(directory) => directory,
        Err(_) => {
            let directory = policy
                .create_directory("verification-keys", 0o755)
                .map_err(|_| ())?;
            policy.sync().map_err(|_| ())?;
            directory
        }
    };
    let keyring_metadata = keyring.metadata().map_err(|_| ())?;
    if keyring_metadata.uid != policy_metadata.uid
        || keyring_metadata.gid != policy_metadata.gid
        || keyring_metadata.mode & 0o777 != 0o755
    {
        return Err(());
    }
    install_or_verify_public(
        &keyring,
        &format!("trust-{}.openpgp.asc", generation.0),
        &openpgp,
        &keyring_metadata,
    )?;
    install_or_verify_public(
        &keyring,
        &format!("trust-{}.ml-dsa.bin", generation.0),
        &ml_dsa,
        &keyring_metadata,
    )?;
    keyring.sync().map_err(|_| ())
}

fn install_or_verify_public(
    directory: &DirectoryCapability,
    name: &str,
    expected: &[u8],
    directory_metadata: &mrml_runtime::DirectoryMetadata,
) -> Result<(), ()> {
    let mut file = match directory.open_regular(name) {
        Ok(file) => file,
        Err(_) => {
            let mut file = directory.create_new_file(name, 0o444).map_err(|_| ())?;
            file.write_all(expected).map_err(|_| ())?;
            file.sync().map_err(|_| ())?;
            drop(file);
            directory.open_regular(name).map_err(|_| ())?
        }
    };
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.uid != directory_metadata.uid
        || metadata.gid != directory_metadata.gid
        || metadata.mode & 0o777 != 0o444
        || metadata.links != 1
        || file.len().map_err(|_| ())? != expected.len() as u64
    {
        return Err(());
    }
    let mut actual = vec![0; expected.len()];
    file.read_exact(&mut actual).map_err(|_| ())?;
    if actual != expected {
        return Err(());
    }
    Ok(())
}

fn read_hybrid_public_pair(
    openpgp_path: &str,
    ml_dsa_path: &str,
    own_uid: u32,
) -> Result<
    (
        mrml_openpgp::PublicKeyV6,
        [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
    ),
    (),
> {
    let openpgp_bytes = read_regular(
        openpgp_path,
        1,
        MAX_OPENPGP_PUBLIC_KEY_BYTES,
        own_uid,
        false,
    )?;
    let mut scratch = vec![0u8; MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let openpgp = parse_public_key_v6_ascii(&openpgp_bytes, &mut scratch).map_err(|_| ())?;
    let ml_dsa_bytes = read_regular(
        ml_dsa_path,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        own_uid,
        false,
    )?;
    let mut ml_dsa = [0u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES];
    ml_dsa.copy_from_slice(&ml_dsa_bytes);
    Ok((openpgp, ml_dsa))
}

fn parse_lower_hex_64(input: &str) -> Result<[u8; 64], ()> {
    if input.len() != 128
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    let mut output = [0u8; 64];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

fn print_hex(bytes: &[u8]) {
    println!("{}", lower_hex(bytes));
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn listener_health(socket: &Path, own_uid: u32, socket_gid: u32) -> Result<(), ()> {
    if own_uid == 0 || socket_gid == 0 {
        return Err(());
    }
    let metadata = std::fs::symlink_metadata(socket).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != own_uid
        || metadata.gid() != socket_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(());
    }
    println!("ready");
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityRepositoryBootstrap {
    repository: RepositoryIdentity,
    generation: u64,
}

fn parse_authority_repository_catalog(
    input: &[u8],
) -> Result<Vec<AuthorityRepositoryBootstrap>, ()> {
    let text = std::str::from_utf8(input).map_err(|_| ())?;
    if !text.ends_with('\n') {
        return Err(());
    }
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err(());
    }
    let mut repositories = Vec::new();
    for line in lines {
        let (repository, generation) = line.split_once(" generation=").ok_or(())?;
        let repository = repository.strip_prefix("repository=").ok_or(())?;
        let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
        let generation = generation.parse::<u64>().map_err(|_| ())?;
        if generation == 0
            || repositories.len() >= MAX_AUTHORITY_REPOSITORIES
            || repositories
                .last()
                .is_some_and(|previous: &AuthorityRepositoryBootstrap| {
                    previous.repository >= repository
                })
        {
            return Err(());
        }
        repositories.push(AuthorityRepositoryBootstrap {
            repository,
            generation,
        });
    }
    if repositories.is_empty() {
        return Err(());
    }
    Ok(repositories)
}

#[allow(clippy::too_many_arguments)]
fn load_production_authority_catalog(
    authority_uid: u32,
    policy_path: &str,
    proof_path: &str,
    generation_path: &str,
    catalog_path: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
) -> Result<ProductionAuthorityCatalog, ()> {
    let catalog_bytes = read_regular(
        catalog_path,
        1,
        MAX_AUTHORITY_CATALOG_BYTES,
        authority_uid,
        false,
    )?;
    let repositories = parse_authority_repository_catalog(&catalog_bytes)?;
    let mut authorities = mrml_runtime::Vector::new();
    authorities
        .try_reserve_exact(repositories.len())
        .map_err(|_| ())?;
    for entry in repositories {
        let authority = load_authority(
            authority_uid,
            policy_path,
            proof_path,
            generation_path,
            entry.repository.as_str(),
            openpgp_path,
            ml_dsa_path,
            receipt_key_path,
            validation_time,
            entry.generation,
        )?;
        authorities.push((entry.repository, authority));
    }
    ProductionAuthorityCatalog::new(authorities).map_err(|_| ())
}

fn serve(
    socket: &str,
    capability_path: &str,
    expected_gitd: AuthorityPeer,
    authority_peer: AuthorityPeer,
    policy_path: &str,
    proof_path: &str,
    generation_path: &str,
    repository: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<(), ()> {
    let repository_identity = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let authority = load_authority(
        authority_peer.uid,
        policy_path,
        proof_path,
        generation_path,
        repository,
        openpgp_path,
        ml_dsa_path,
        receipt_key_path,
        validation_time,
        repository_generation,
    )?;
    let catalog = ProductionAuthorityCatalog::new([(repository_identity, authority)].into())
        .map_err(|_| ())?;
    serve_authority_catalog(
        socket,
        capability_path,
        expected_gitd,
        authority_peer,
        catalog,
    )
}

fn serve_authority_catalog(
    socket: &str,
    capability_path: &str,
    expected_gitd: AuthorityPeer,
    authority_peer: AuthorityPeer,
    authority: ProductionAuthorityCatalog,
) -> Result<(), ()> {
    let termination_signals = TerminationSignals::block_current()?;
    let capability = Arc::new(read_capability(capability_path, authority_peer.uid)?);
    let authority = Arc::new(authority);
    let listener = AuthorityListener::bind(Path::new(socket), 0o660, expected_gitd)
        .and_then(|listener| listener.allow_health_peer(authority_peer))
        .map_err(|_| ())?;
    let replay = Arc::new(std::sync::Mutex::new(AuthorityReplayWindow::new()));
    let health_replay = Arc::new(std::sync::Mutex::new(AuthorityReplayWindow::new()));
    let terminating = Arc::new(AtomicBool::new(false));
    let signal_terminating = terminating.clone();
    let signal_socket = PathBuf::from(socket);
    let signal_worker = std::thread::spawn(move || {
        if termination_signals.wait().is_ok() {
            signal_terminating.store(true, Ordering::Release);
            let _ = std::os::unix::net::UnixStream::connect(signal_socket);
        }
    });
    let (jobs, receiver) = mrml_runtime::blocking_channel(AUTHORITY_QUEUE_CAPACITY);
    let mut workers = Vec::with_capacity(AUTHORITY_WORKERS);
    for index in 0..AUTHORITY_WORKERS {
        let receiver = receiver.clone();
        let capability = capability.clone();
        let authority = authority.clone();
        let replay = replay.clone();
        let health_replay = health_replay.clone();
        workers.push(
            std::thread::Builder::new()
                .name(format!("mrml-git-authority-{index}"))
                .spawn(move || {
                    while let Ok(session) = receiver.recv() {
                        serve_authority_session(
                            session,
                            expected_gitd,
                            authority_peer,
                            &capability,
                            &authority,
                            &replay,
                            &health_replay,
                        );
                    }
                })
                .map_err(|_| ())?,
        );
    }
    drop(receiver);
    loop {
        if terminating.load(Ordering::Acquire) {
            break;
        }
        let session = match listener.accept() {
            Ok(session) => session,
            Err(_) => continue,
        };
        if terminating.load(Ordering::Acquire) {
            break;
        }
        if jobs.send(session).is_err() {
            break;
        }
    }
    drop(jobs);
    for worker in workers {
        worker.join().map_err(|_| ())?;
    }
    signal_worker.join().map_err(|_| ())?;
    Ok(())
}

fn serve_authority_session(
    mut session: AuthoritySession,
    expected_gitd: AuthorityPeer,
    authority_peer: AuthorityPeer,
    capability: &AuthorityCapability,
    authority: &ProductionAuthorityCatalog,
    replay: &std::sync::Mutex<AuthorityReplayWindow>,
    health_replay: &std::sync::Mutex<AuthorityReplayWindow>,
) {
    let mut encoded = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
    let Ok(length) = session.read_frame(&mut encoded) else {
        return;
    };
    let observed_peer = session.observed_peer();
    let request = {
        let replay = if observed_peer == expected_gitd {
            replay
        } else {
            health_replay
        };
        let Ok(mut replay) = replay.lock() else {
            return;
        };
        match decode_frame(
            &encoded[..length],
            AuthorityFrameKind::Request,
            observed_peer,
            observed_peer,
            capability,
            &mut replay,
        ) {
            Ok(request) => request,
            Err(_) => return,
        }
    };
    if observed_peer != expected_gitd && request.operation != AuthorityOperation::Health {
        return;
    }
    let result = mrml_runtime::unix_time_seconds()
        .ok_or(AuthorityDispatchError::Unavailable)
        .and_then(|now| authority.dispatch(request.operation, request.payload, now));
    let (status, payload) = match &result {
        Ok(payload) => (STATUS_OK, &payload[..]),
        Err(AuthorityDispatchError::Malformed) => (2, &[][..]),
        Err(AuthorityDispatchError::Unauthorized) => (3, &[][..]),
        Err(AuthorityDispatchError::Unavailable) => (STATUS_UNAVAILABLE, &[][..]),
        Err(AuthorityDispatchError::Resource) => (4, &[][..]),
    };
    let response = AuthorityFrame {
        kind: AuthorityFrameKind::Response,
        operation: request.operation,
        request_id: request.request_id,
        status,
        peer: authority_peer,
        payload,
    };
    let Ok(response_length) = encode_frame(response, capability, &mut encoded) else {
        return;
    };
    let _ = session.write_frame(&encoded[..response_length]);
}

fn load_authority(
    authority_uid: u32,
    policy_path: &str,
    proof_path: &str,
    generation_path: &str,
    repository: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<ProductionAuthority, ()> {
    let repository_identity = RepositoryIdentity::parse(repository)
        .map_err(|_| authority_startup_failure("repository"))?;
    let policy_root = DirectoryCapability::open_root(policy_path)
        .map_err(|_| authority_startup_failure("policy_root"))?;
    let policy_directory = policy_root
        .open_directory(repository_identity.as_str())
        .map_err(|_| authority_startup_failure("policy_directory"))?;
    let policy = LinuxDurableTrustPolicyStore::open_capability(
        policy_directory.try_clone().map_err(|_| ())?,
    )
    .map_err(|_| authority_startup_failure("policy_store"))?;
    let proof_directory = open_or_create_authority_repository_directory(
        proof_path,
        &repository_identity,
        authority_uid,
    )
    .map_err(|_| authority_startup_failure("proof_directory"))?;
    let proofs = DurableDetachedCommitProofDirectory::open_capability(proof_directory)
        .map_err(|_| authority_startup_failure("proof_store"))?;
    let bootstrap = read_hybrid_public_pair(openpgp_path, ml_dsa_path, authority_uid)
        .map_err(|_| authority_startup_failure("bootstrap_verifier"))?;
    let current_policy = policy
        .load()
        .map_err(|_| authority_startup_failure("selected_policy"))?;
    let (openpgp_key, ml_dsa_key) = select_authority_verifier(
        &current_policy,
        &policy_directory,
        validation_time,
        bootstrap,
    )
    .map_err(|_| authority_startup_failure("selected_verifier"))?;
    let mut receipt_bytes = read_regular(receipt_key_path, 32, 32, authority_uid, true)
        .map_err(|_| authority_startup_failure("receipt_key"))?;
    let mut receipt_key = [0u8; 32];
    receipt_key.copy_from_slice(&receipt_bytes);
    erase_secret_bytes(&mut receipt_bytes);
    let (generation_directory, candidate_directory) =
        open_authority_state_directories(generation_path, authority_uid)
            .map_err(|_| authority_startup_failure("state_directories"))?;
    let generations = LinuxAuthorityGenerationStore::open_capability(
        generation_directory,
        authority_uid,
        &repository_identity,
        mrml_git::RepositoryGeneration(repository_generation),
    )
    .map_err(|_| authority_startup_failure("generation_store"))?;
    let candidates =
        LinuxAuthorityCandidateStore::open_capability(candidate_directory, authority_uid)
            .map_err(|_| authority_startup_failure("candidate_store"))?;
    let authority = ProductionAuthority::new_with_stores(
        policy,
        proofs,
        openpgp_key,
        ml_dsa_key,
        receipt_key,
        validation_time,
        Box::new(generations),
        Some(candidates),
    )
    .map_err(|_| authority_startup_failure("authority_state"))?;
    erase_secret_bytes(&mut receipt_key);
    Ok(authority)
}

fn authority_startup_failure(category: &'static str) {
    eprintln!("component=mrml-git-authority event=startup_failed category={category}");
}

fn select_authority_verifier(
    policy: &mrml_git::TrustPolicyState,
    policy_directory: &DirectoryCapability,
    validation_time: u64,
    bootstrap: (
        mrml_openpgp::PublicKeyV6,
        [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
    ),
) -> Result<
    (
        mrml_openpgp::PublicKeyV6,
        [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
    ),
    (),
> {
    let bootstrap_pair = AuthorizedHybridPair::bind(&bootstrap.0, &bootstrap.1);
    if policy
        .active_verification_policy_at(bootstrap_pair, validation_time, true)
        .is_ok()
    {
        return Ok(bootstrap);
    }
    let selected = read_transition_verifier(policy_directory, policy.generation())?;
    let selected_pair = AuthorizedHybridPair::bind(&selected.0, &selected.1);
    policy
        .active_verification_policy_at(selected_pair, validation_time, true)
        .map_err(|_| ())?;
    Ok(selected)
}

fn read_transition_verifier(
    policy_directory: &DirectoryCapability,
    generation: TrustGeneration,
) -> Result<
    (
        mrml_openpgp::PublicKeyV6,
        [u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
    ),
    (),
> {
    let policy_metadata = policy_directory.metadata().map_err(|_| ())?;
    let keyring = policy_directory
        .open_directory("verification-keys")
        .map_err(|_| ())?;
    let keyring_metadata = keyring.metadata().map_err(|_| ())?;
    if keyring_metadata.uid != policy_metadata.uid
        || keyring_metadata.gid != policy_metadata.gid
        || keyring_metadata.mode & 0o777 != 0o755
    {
        return Err(());
    }
    let openpgp = read_capability_public(
        &keyring,
        &format!("trust-{}.openpgp.asc", generation.0),
        1,
        MAX_OPENPGP_PUBLIC_KEY_BYTES,
        &keyring_metadata,
    )?;
    let ml_dsa = read_capability_public(
        &keyring,
        &format!("trust-{}.ml-dsa.bin", generation.0),
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        &keyring_metadata,
    )?;
    let mut scratch = vec![0; MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let openpgp = parse_public_key_v6_ascii(&openpgp, &mut scratch).map_err(|_| ())?;
    let mut ml_dsa_key = [0; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES];
    ml_dsa_key.copy_from_slice(&ml_dsa);
    Ok((openpgp, ml_dsa_key))
}

fn read_capability_public(
    directory: &DirectoryCapability,
    name: &str,
    minimum: usize,
    maximum: usize,
    directory_metadata: &mrml_runtime::DirectoryMetadata,
) -> Result<Vec<u8>, ()> {
    let mut file = directory.open_regular(name).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let length = usize::try_from(file.len().map_err(|_| ())?).map_err(|_| ())?;
    if metadata.uid != directory_metadata.uid
        || metadata.gid != directory_metadata.gid
        || metadata.mode & 0o777 != 0o444
        || metadata.links != 1
        || length < minimum
        || length > maximum
    {
        return Err(());
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn open_authority_state_directories(
    generation_path: &str,
    authority_uid: u32,
) -> Result<(DirectoryCapability, DirectoryCapability), ()> {
    let generation_path = Path::new(generation_path);
    if !generation_path.is_absolute() {
        return Err(());
    }
    let parent_path = generation_path.parent().ok_or(())?;
    let generation_name = generation_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(())?;
    let parent = DirectoryCapability::open_root(parent_path.to_str().ok_or(())?).map_err(|_| ())?;
    let parent_metadata = parent.metadata().map_err(|_| ())?;
    if parent_metadata.uid != authority_uid || parent_metadata.mode & 0o777 != 0o700 {
        return Err(());
    }
    let open_or_create = |name: &str| match parent.open_directory(name) {
        Ok(directory) => Ok(directory),
        Err(_) => parent.create_directory(name, 0o700).map_err(|_| ()),
    };
    let generations = open_or_create(generation_name)?;
    let candidates = open_or_create("candidates")?;
    for directory in [&generations, &candidates] {
        let metadata = directory.metadata().map_err(|_| ())?;
        if metadata.uid != parent_metadata.uid
            || metadata.gid != parent_metadata.gid
            || metadata.mode & 0o777 != 0o700
        {
            return Err(());
        }
    }
    parent.sync().map_err(|_| ())?;
    Ok((generations, candidates))
}

fn open_or_create_authority_repository_directory(
    root: &str,
    repository: &RepositoryIdentity,
    authority_uid: u32,
) -> Result<DirectoryCapability, ()> {
    let root = DirectoryCapability::open_root(root).map_err(|_| ())?;
    let root_metadata = root.metadata().map_err(|_| ())?;
    if root_metadata.uid != authority_uid || root_metadata.mode & 0o777 != 0o700 {
        return Err(());
    }
    let (owner, name) = repository.as_str().split_once('/').ok_or(())?;
    let owner = match root.open_directory(owner) {
        Ok(directory) => directory,
        Err(_) => root.create_directory(owner, 0o700).map_err(|_| ())?,
    };
    let directory = match owner.open_directory(name) {
        Ok(directory) => directory,
        Err(_) => owner.create_directory(name, 0o700).map_err(|_| ())?,
    };
    for candidate in [&owner, &directory] {
        let metadata = candidate.metadata().map_err(|_| ())?;
        if metadata.uid != root_metadata.uid
            || metadata.gid != root_metadata.gid
            || metadata.mode & 0o777 != 0o700
        {
            return Err(());
        }
    }
    owner.sync().map_err(|_| ())?;
    root.sync().map_err(|_| ())?;
    Ok(directory)
}

#[cfg_attr(not(test), allow(dead_code))]
fn authority_storage_paths(
    policy_root: &str,
    proof_root: &str,
    repository: &str,
) -> Result<(PathBuf, PathBuf), ()> {
    let policy_root = Path::new(policy_root);
    let proof_root = Path::new(proof_root);
    if !policy_root.is_absolute() || !proof_root.is_absolute() {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    Ok((
        policy_storage_path(policy_root.to_str().ok_or(())?, &repository)?,
        proof_root.join(repository.as_str()),
    ))
}

fn policy_storage_path(policy_root: &str, repository: &RepositoryIdentity) -> Result<PathBuf, ()> {
    let policy_root = Path::new(policy_root);
    if !policy_root.is_absolute() {
        return Err(());
    }
    Ok(policy_root.join(repository.as_str()))
}

fn healthcheck(
    socket: &str,
    capability_path: &str,
    own_peer: AuthorityPeer,
    authority_peer: AuthorityPeer,
) -> Result<(), ()> {
    let capability = read_healthcheck_capability(capability_path, own_peer)?;
    let mut session = AuthoritySession::connect(Path::new(socket)).map_err(|_| ())?;
    let request_id = mrml_runtime::unix_time_seconds().ok_or(())?;
    let request = AuthorityFrame {
        kind: AuthorityFrameKind::Request,
        operation: AuthorityOperation::Health,
        request_id,
        status: 0,
        peer: own_peer,
        payload: &[],
    };
    let mut encoded = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
    let length = encode_frame(request, &capability, &mut encoded).map_err(|_| ())?;
    session.write_frame(&encoded[..length]).map_err(|_| ())?;
    let length = session.read_frame(&mut encoded).map_err(|_| ())?;
    let response = decode_frame(
        &encoded[..length],
        AuthorityFrameKind::Response,
        session.observed_peer(),
        authority_peer,
        &capability,
        &mut AuthorityReplayWindow::new(),
    )
    .map_err(|_| ())?;
    if response.operation != AuthorityOperation::Health
        || response.request_id != request.request_id
        || response.status != STATUS_OK
        || response.payload != b"ready-v1"
    {
        return Err(());
    }
    println!("ready");
    Ok(())
}

fn read_healthcheck_capability(
    capability_path: &str,
    own_peer: AuthorityPeer,
) -> Result<AuthorityCapability, ()> {
    read_capability(capability_path, own_peer.uid)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSignalSet {
    bits: [u64; 16],
}

struct TerminationSignals {
    set: NativeSignalSet,
}

impl TerminationSignals {
    fn block_current() -> Result<Self, ()> {
        const SIG_BLOCK: i32 = 0;
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        let mut set = NativeSignalSet { bits: [0; 16] };
        if unsafe { sigemptyset(&mut set) } != 0
            || unsafe { sigaddset(&mut set, SIGINT) } != 0
            || unsafe { sigaddset(&mut set, SIGTERM) } != 0
            || unsafe { pthread_sigmask(SIG_BLOCK, &set, core::ptr::null_mut()) } != 0
        {
            return Err(());
        }
        Ok(Self { set })
    }

    fn wait(self) -> Result<i32, ()> {
        let mut signal = 0;
        if unsafe { sigwait(&self.set, &mut signal) } == 0 && matches!(signal, 2 | 15) {
            Ok(signal)
        } else {
            Err(())
        }
    }
}

unsafe extern "C" {
    fn sigemptyset(set: *mut NativeSignalSet) -> i32;
    fn sigaddset(set: *mut NativeSignalSet, signal: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const NativeSignalSet, old: *mut NativeSignalSet) -> i32;
    fn sigwait(set: *const NativeSignalSet, signal: *mut i32) -> i32;
}

fn parse_peer(uid: &str, gid: &str) -> Result<AuthorityPeer, ()> {
    let peer = AuthorityPeer {
        uid: uid.parse().map_err(|_| ())?,
        gid: gid.parse().map_err(|_| ())?,
    };
    if peer.uid == 0 || peer.gid == 0 {
        return Err(());
    }
    Ok(peer)
}

fn read_capability(path: &str, expected_owner: u32) -> Result<AuthorityCapability, ()> {
    let mut bytes = read_regular(
        path,
        AUTHORITY_CAPABILITY_BYTES,
        AUTHORITY_CAPABILITY_BYTES,
        expected_owner,
        true,
    )?;
    let mut key = [0u8; AUTHORITY_CAPABILITY_BYTES];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    let result = AuthorityCapability::new(key);
    erase_secret_bytes(&mut key);
    result.map_err(|_| ())
}

fn read_regular(
    path: &str,
    minimum: usize,
    maximum: usize,
    expected_owner: u32,
    secret: bool,
) -> Result<Vec<u8>, ()> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or(())?;
    let directory = DirectoryCapability::open_root(parent.to_str().ok_or(())?).map_err(|_| ())?;
    read_regular_from(&directory, name, minimum, maximum, expected_owner, secret)
}

fn read_regular_from(
    directory: &DirectoryCapability,
    name: &str,
    minimum: usize,
    maximum: usize,
    expected_owner: u32,
    secret: bool,
) -> Result<Vec<u8>, ()> {
    let mut file = directory.open_regular(name).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let length = file.len().map_err(|_| ())?;
    let mode = metadata.mode & 0o777;
    if metadata.links != 1
        || metadata.uid != expected_owner
        || (secret && !matches!(mode, 0o400 | 0o440 | 0o600))
        || (!secret && mode & 0o022 != 0)
        || length < minimum as u64
        || length > maximum as u64
    {
        return Err(());
    }
    let mut bytes = vec![0u8; length as usize];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{
        ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
        ml_dsa_65_keygen, ml_dsa_65_sign,
    };
    use mrml_git::{
        FullRefName, PolicyPairStatus, RevocationGeneration, TrustPolicyCandidate,
        TrustPolicyState, canonical_hybrid_transcript,
    };
    use mrml_openpgp::{DigestAlgorithm, SigningKeyV6, sign_detached_v6_ascii_with_salt};
    use mrml_runtime::Vector;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn repository_catalog_is_exact_ordered_and_bounded() {
        let parsed = parse_authority_repository_catalog(
            b"version=1\nrepository=owner/first generation=3\nrepository=owner/second generation=9\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].repository.as_str(), "owner/first");
        assert_eq!(parsed[0].generation, 3);
        assert_eq!(parsed[1].repository.as_str(), "owner/second");
        assert_eq!(parsed[1].generation, 9);
        for invalid in [
            &b"version=1\n"[..],
            &b"version=2\nrepository=owner/first generation=3\n"[..],
            &b"version=1\nrepository=owner/first generation=0\n"[..],
            &b"version=1\nrepository=owner/second generation=3\nrepository=owner/first generation=4\n"[..],
            &b"version=1\nrepository=owner/first generation=3"[..],
            &b"version=1\nrepository=../escape generation=3\n"[..],
        ] {
            assert!(parse_authority_repository_catalog(invalid).is_err());
        }
    }

    #[test]
    fn bootstrap_read_remains_bound_to_retained_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-bootstrap-retained-{}",
            std::process::id()
        ));
        let displaced = root.with_extension("displaced");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&displaced);
        std::fs::create_dir(&root).unwrap();
        let key = root.join("receipt.key");
        std::fs::write(&key, [0x31; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&key).unwrap());
        let retained = DirectoryCapability::open_root(root.to_str().unwrap()).unwrap();
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("receipt.key"), [0x41; 32]).unwrap();

        assert_eq!(
            read_regular_from(&retained, "receipt.key", 32, 32, uid, true),
            Ok(vec![0x31; 32])
        );

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn healthcheck_reads_the_client_owned_capability_copy() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-health-capability-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let capability = root.join("authority-channel");
        std::fs::write(&capability, [0x51; AUTHORITY_CAPABILITY_BYTES]).unwrap();
        std::fs::set_permissions(&capability, std::fs::Permissions::from_mode(0o400)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&capability).unwrap());
        let own_peer = AuthorityPeer { uid, gid: uid };

        assert!(read_healthcheck_capability(capability.to_str().unwrap(), own_peer).is_ok());
        assert!(
            read_healthcheck_capability(
                capability.to_str().unwrap(),
                AuthorityPeer {
                    uid: uid.saturating_add(1),
                    gid: uid,
                },
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn listener_health_requires_exact_socket_identity_and_mode() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-listener-health-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert!(listener_health(&socket, metadata.uid(), metadata.gid()).is_ok());
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(listener_health(&socket, metadata.uid(), metadata.gid()).is_err());
        drop(listener);
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn authority_paths_require_absolute_roots_and_canonical_repository_identity() {
        assert_eq!(
            authority_storage_paths("/policy", "/proof", "owner/project").unwrap(),
            (
                PathBuf::from("/policy/owner/project"),
                PathBuf::from("/proof/owner/project")
            )
        );
        for repository in [
            "../policy",
            "owner/../policy",
            "/owner/project",
            "owner//repo",
        ] {
            assert!(authority_storage_paths("/policy", "/proof", repository).is_err());
        }
        assert!(authority_storage_paths("policy", "/proof", "owner/project").is_err());
        assert!(authority_storage_paths("/policy", "proof", "owner/project").is_err());
    }

    #[test]
    fn authority_state_directories_share_one_retained_parent() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-state-retained-{}",
            std::process::id()
        ));
        let displaced = root.with_extension("displaced");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&displaced);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&root).unwrap());
        let generation_path = root.join("generations");
        let (generations, candidates) =
            open_authority_state_directories(generation_path.to_str().unwrap(), uid).unwrap();
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        generations
            .create_new_file("retained-generation", 0o600)
            .unwrap();
        candidates
            .create_new_file("retained-candidate", 0o600)
            .unwrap();
        assert!(displaced.join("generations/retained-generation").is_file());
        assert!(displaced.join("candidates/retained-candidate").is_file());
        assert!(!root.join("generations").exists());
        assert!(!root.join("candidates").exists());

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn signer_identity_encoding_is_exact_lowercase_hex() {
        assert_eq!(lower_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(parse_lower_hex_64(&"ab".repeat(64)), Ok([0xab; 64]));
        assert!(parse_lower_hex_64(&"AB".repeat(64)).is_err());
        assert!(parse_lower_hex_64(&"a".repeat(127)).is_err());
        assert!(parse_lower_hex_64(&"gg".repeat(64)).is_err());
    }

    #[test]
    #[ignore = "child fixture invoked by the transition process-kill matrix"]
    fn normal_transition_verifies_both_real_signatures_and_reopens_exact_policy() {
        let resume = std::env::var_os("MRML_AUTHORITY_TRANSITION_TEST_RESUME").is_some();
        let root = std::env::var_os("MRML_AUTHORITY_TRANSITION_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "mrml-authority-normal-transition-{}",
                    std::process::id()
                ))
            });
        if !resume {
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir(&root).unwrap();
        }
        let uid = std::fs::metadata(&root).unwrap().uid();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old_openpgp = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let next_openpgp = SigningKeyV6::from_seed([8; 32], 1_700_000_000).unwrap();
        let mut old_ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut old_ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9; 32], &mut old_ml_public, &mut old_ml_secret).unwrap();
        let mut next_ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut next_ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[10; 32], &mut next_ml_public, &mut next_ml_secret).unwrap();
        let old_pair = AuthorizedHybridPair::bind(&old_openpgp.public_key(), &old_ml_public);
        let next_pair = AuthorizedHybridPair::bind(&next_openpgp.public_key(), &next_ml_public);
        assert_ne!(old_pair, next_pair);
        let initial = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(1),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(1),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: false,
            legacy_checkpoint: None,
            hybrid_cutover: None,
            emergency_policy_digest: Some([11; 64]),
            active_pairs: [old_pair].into(),
            pair_statuses: [
                PolicyPairStatus::new(old_pair, 1_700_000_000, 1_800_000_000, None).unwrap(),
            ]
            .into(),
            legacy_v4_statuses: Vector::new(),
            revoked_legacy_v4: Vector::new(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        let next_policy = initial
            .encode_overlap_successor(next_pair, 1_700_000_000, 1_800_000_000)
            .unwrap();
        let expected_next = parse_trust_policy(&next_policy).unwrap();
        let policy_root = root.join("policies");
        let policy_directory = policy_root.join(repository.as_str());
        if resume {
            assert_eq!(
                LinuxDurableTrustPolicyStore::open(policy_directory.to_str().unwrap())
                    .unwrap()
                    .load()
                    .unwrap(),
                initial
            );
        } else {
            LinuxDurableTrustPolicyStore::create(policy_directory.to_str().unwrap(), &initial)
                .unwrap();
        }

        let old_transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::KeyRotation,
            SignaturePurpose::KeyRotation,
            TrustGeneration(1),
            old_pair,
            &next_policy,
        )
        .unwrap();
        let next_transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::KeyRotation,
            SignaturePurpose::KeyRotation,
            TrustGeneration(2),
            next_pair,
            &next_policy,
        )
        .unwrap();
        let mut old_openpgp_signature = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let old_openpgp_length = sign_detached_v6_ascii_with_salt(
            &old_openpgp,
            &old_transcript,
            DigestAlgorithm::Sha512,
            1_700_000_010,
            &[12; 32],
            &mut old_openpgp_signature,
        )
        .unwrap();
        let mut next_openpgp_signature = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let next_openpgp_length = sign_detached_v6_ascii_with_salt(
            &next_openpgp,
            &next_transcript,
            DigestAlgorithm::Sha512,
            1_700_000_010,
            &[13; 32],
            &mut next_openpgp_signature,
        )
        .unwrap();
        let mut old_ml_signature = [0; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &old_ml_secret,
            b"mrml.git.hybrid.v1",
            &old_transcript,
            &[14; 32],
            &mut old_ml_signature,
        )
        .unwrap();
        let mut next_ml_signature = [0; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &next_ml_secret,
            b"mrml.git.hybrid.v1",
            &next_transcript,
            &[15; 32],
            &mut next_ml_signature,
        )
        .unwrap();

        let next_policy_path = root.join("next-policy.bin");
        let old_openpgp_path = root.join("old-openpgp.asc");
        let old_ml_path = root.join("old-ml.bin");
        let old_openpgp_signature_path = root.join("old-openpgp.sig");
        let old_ml_signature_path = root.join("old-ml.sig");
        let next_openpgp_path = root.join("next-openpgp.asc");
        let next_ml_path = root.join("next-ml.bin");
        let next_openpgp_signature_path = root.join("next-openpgp.sig");
        let next_ml_signature_path = root.join("next-ml.sig");
        write_public(&next_policy_path, &next_policy);
        write_openpgp_public(&old_openpgp_path, &old_openpgp);
        write_public(&old_ml_path, &old_ml_public);
        write_public(
            &old_openpgp_signature_path,
            &old_openpgp_signature[..old_openpgp_length],
        );
        write_public(&old_ml_signature_path, &old_ml_signature);
        write_openpgp_public(&next_openpgp_path, &next_openpgp);
        write_public(&next_ml_path, &next_ml_public);
        write_public(
            &next_openpgp_signature_path,
            &next_openpgp_signature[..next_openpgp_length],
        );
        write_public(&next_ml_signature_path, &next_ml_signature);

        assert!(
            transition_policy(
                path(&policy_root),
                repository.as_str(),
                path(&next_policy_path),
                path(&old_openpgp_path),
                path(&old_ml_path),
                path(&old_openpgp_signature_path),
                path(&old_ml_signature_path),
                path(&next_openpgp_path),
                path(&next_ml_path),
                path(&next_openpgp_signature_path),
                path(&next_ml_signature_path),
                1_700_000_020,
                1,
                initial.digest(),
                uid,
            )
            .is_ok()
        );
        assert_eq!(
            LinuxDurableTrustPolicyStore::open(path(&policy_directory))
                .unwrap()
                .load()
                .unwrap(),
            expected_next
        );
        assert!(
            verify_selected_policy(
                path(&policy_root),
                repository.as_str(),
                path(&next_policy_path),
                uid,
            )
            .is_ok()
        );
        let substituted_policy_path = root.join("substituted-policy.bin");
        let mut substituted_policy = next_policy.clone();
        substituted_policy[0] ^= 1;
        write_public(&substituted_policy_path, &substituted_policy);
        assert!(
            verify_selected_policy(
                path(&policy_root),
                repository.as_str(),
                path(&substituted_policy_path),
                uid,
            )
            .is_err()
        );
        let keyring = policy_directory.join("verification-keys");
        let retained_openpgp = keyring.join("trust-2.openpgp.asc");
        let retained_ml_dsa = keyring.join("trust-2.ml-dsa.bin");
        assert_eq!(
            std::fs::read(&retained_openpgp).unwrap(),
            std::fs::read(&next_openpgp_path).unwrap()
        );
        assert_eq!(
            std::fs::read(&retained_ml_dsa).unwrap(),
            std::fs::read(&next_ml_path).unwrap()
        );
        for retained in [retained_openpgp, retained_ml_dsa] {
            let metadata = std::fs::metadata(retained).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o444);
            assert_eq!(metadata.uid(), uid);
            assert_eq!(metadata.nlink(), 1);
        }

        let retirement_time = 1_700_000_030;
        let retirement_policy = expected_next
            .encode_retirement_successor(old_pair, retirement_time)
            .unwrap();
        let old_retirement_transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::KeyRotation,
            SignaturePurpose::KeyRotation,
            TrustGeneration(2),
            old_pair,
            &retirement_policy,
        )
        .unwrap();
        let next_retirement_transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::KeyRotation,
            SignaturePurpose::KeyRotation,
            TrustGeneration(3),
            next_pair,
            &retirement_policy,
        )
        .unwrap();
        let old_openpgp_length = sign_detached_v6_ascii_with_salt(
            &old_openpgp,
            &old_retirement_transcript,
            DigestAlgorithm::Sha512,
            1_700_000_035,
            &[16; 32],
            &mut old_openpgp_signature,
        )
        .unwrap();
        let next_openpgp_length = sign_detached_v6_ascii_with_salt(
            &next_openpgp,
            &next_retirement_transcript,
            DigestAlgorithm::Sha512,
            1_700_000_035,
            &[17; 32],
            &mut next_openpgp_signature,
        )
        .unwrap();
        ml_dsa_65_sign(
            &old_ml_secret,
            b"mrml.git.hybrid.v1",
            &old_retirement_transcript,
            &[18; 32],
            &mut old_ml_signature,
        )
        .unwrap();
        ml_dsa_65_sign(
            &next_ml_secret,
            b"mrml.git.hybrid.v1",
            &next_retirement_transcript,
            &[19; 32],
            &mut next_ml_signature,
        )
        .unwrap();
        write_public(&next_policy_path, &retirement_policy);
        write_public(
            &old_openpgp_signature_path,
            &old_openpgp_signature[..old_openpgp_length],
        );
        write_public(&old_ml_signature_path, &old_ml_signature);
        write_public(
            &next_openpgp_signature_path,
            &next_openpgp_signature[..next_openpgp_length],
        );
        write_public(&next_ml_signature_path, &next_ml_signature);
        assert!(
            transition_policy(
                path(&policy_root),
                repository.as_str(),
                path(&next_policy_path),
                path(&old_openpgp_path),
                path(&old_ml_path),
                path(&old_openpgp_signature_path),
                path(&old_ml_signature_path),
                path(&next_openpgp_path),
                path(&next_ml_path),
                path(&next_openpgp_signature_path),
                path(&next_ml_signature_path),
                1_700_000_040,
                2,
                expected_next.digest(),
                uid,
            )
            .is_ok()
        );
        let retired = LinuxDurableTrustPolicyStore::open(path(&policy_directory))
            .unwrap()
            .load()
            .unwrap();
        assert_eq!(retired.generation(), TrustGeneration(3));
        assert!(
            retired
                .active_verification_policy_at(old_pair, 1_700_000_040, true)
                .is_err()
        );
        let selected = select_authority_verifier(
            &retired,
            &DirectoryCapability::open_root(path(&policy_directory)).unwrap(),
            1_700_000_040,
            (old_openpgp.public_key(), old_ml_public),
        )
        .unwrap();
        assert_eq!(
            AuthorizedHybridPair::bind(&selected.0, &selected.1),
            next_pair
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transition_process_kills_reopen_exact_signature_and_snapshot_boundaries() {
        for boundary in [
            "signature-verification-complete",
            "trust-snapshot-published",
        ] {
            let root = std::env::temp_dir().join(format!(
                "mrml-authority-transition-kill-{}-{boundary}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let executable = std::env::current_exe().unwrap();
            let mut child = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "tests::normal_transition_verifies_both_real_signatures_and_reopens_exact_policy",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MRML_AUTHORITY_TRANSITION_TEST_ROOT", &root)
                .env("MRML_AUTHORITY_TRANSITION_TEST_BOUNDARY", boundary)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let policy_directory = root.join("policies/owner/repository");
            let marker = policy_directory.join(".transition-test-boundary");
            for _ in 0..500 {
                if marker.is_file() {
                    break;
                }
                assert!(child.try_wait().unwrap().is_none());
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), boundary);
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());

            let selected = LinuxDurableTrustPolicyStore::open(path(&policy_directory))
                .unwrap()
                .load()
                .unwrap();
            assert_eq!(selected.generation(), TrustGeneration(1));
            let keyring = policy_directory.join("verification-keys");
            if boundary == "signature-verification-complete" {
                assert!(!keyring.exists());
            } else {
                assert!(keyring.join("trust-2.openpgp.asc").is_file());
                assert!(keyring.join("trust-2.ml-dsa.bin").is_file());
            }

            let resumed = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "tests::normal_transition_verifies_both_real_signatures_and_reopens_exact_policy",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MRML_AUTHORITY_TRANSITION_TEST_ROOT", &root)
                .env("MRML_AUTHORITY_TRANSITION_TEST_RESUME", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(resumed.success());
            assert!(!root.exists());
        }
    }

    #[test]
    fn transition_verifier_is_immutable_within_one_generation() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-transition-verifier-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let policy = root.join("policy");
        std::fs::create_dir(&policy).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o755)).unwrap();
        let openpgp = root.join("next-openpgp.asc");
        let ml_dsa = root.join("next-ml-dsa.bin");
        write_public(&openpgp, b"first-public-key");
        write_public(&ml_dsa, &[7; ML_DSA_65_PUBLIC_KEY_BYTES]);
        let uid = std::fs::metadata(&openpgp).unwrap().uid();

        install_transition_verifier(
            &policy,
            TrustGeneration(2),
            path(&openpgp),
            path(&ml_dsa),
            uid,
        )
        .unwrap();
        let retained = policy.join("verification-keys/trust-2.openpgp.asc");
        assert_eq!(std::fs::read(&retained).unwrap(), b"first-public-key");

        write_public(&openpgp, b"substituted-key");
        assert!(
            install_transition_verifier(
                &policy,
                TrustGeneration(2),
                path(&openpgp),
                path(&ml_dsa),
                uid,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&retained).unwrap(), b"first-public-key");
        std::fs::remove_dir_all(root).unwrap();
    }

    fn write_public(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_openpgp_public(path: &Path, key: &SigningKeyV6) {
        let mut encoded = vec![0; MAX_OPENPGP_PUBLIC_KEY_BYTES];
        let length = key.public_key().encode_ascii(&mut encoded).unwrap();
        write_public(path, &encoded[..length]);
    }

    fn path(value: &Path) -> &str {
        value.to_str().unwrap()
    }
}
