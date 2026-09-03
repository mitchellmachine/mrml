#![feature(peer_credentials_unix_socket)]

use mrml_crypto::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    Sha256, Sha3_512, erase_secret_bytes, ml_dsa_65_sign, ml_dsa_65_verify,
};
use mrml_git::{
    AuthorizedHybridPair, GitObjectType, HybridCommitSignatures, ObjectFormat,
    ProtectedSignerCapability, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    SignaturePurpose, TrustGeneration, UnixProtectedSignerError, canonical_hybrid_transcript,
    OP_ADVANCE_GENERATION, decode_advance_request, decode_protected_signer_request,
    encode_advance_response, encode_loose_object_with_format, encode_protected_signer_hello,
    encode_protected_signer_response, parse_trust_policy, protected_signer_operation,
    verify_signer_generation_advancement, ProtectedSignerSession, MAX_ENCODED_TRUST_POLICY_BYTES,
};
use mrml_openpgp::{
    DigestAlgorithm, MAX_OPENPGP_SIGNATURE_BYTES, SigningKeyV6, sign_detached_v6_ascii_with_salt,
};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const O_NOFOLLOW: i32 = 0x20_000;
const MAX_REQUEST_FRAME: usize = 17 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_LIFETIME_SECONDS: u64 = 5;
const MAXIMUM_SESSION_SEQUENCE: u64 = 1;

struct Configuration {
    socket: PathBuf,
    capability_file: PathBuf,
    client_uid: u32,
    client_gid: u32,
    owner_uid: u32,
    socket_gid: u32,
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    state_file: PathBuf,
    authority_receipt_public_file: PathBuf,
    openpgp_seed_file: PathBuf,
    openpgp_created_at: u32,
    ml_dsa_public_file: PathBuf,
    ml_dsa_secret_file: PathBuf,
}

struct SecretBuffer(Vec<u8>);

impl Deref for SecretBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.0);
    }
}

fn main() {
    if run().is_err() {
        eprintln!("mrml-git-protected-signer: operation failed closed");
        std::process::exit(78);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    if let [
        _,
        command,
        socket,
        capability_file,
        capability_owner_uid,
        signer_uid,
        signer_gid,
    ] = arguments.as_slice()
        && command == "socket-health"
    {
        return socket_health(
            Path::new(socket),
            Path::new(capability_file),
            capability_owner_uid.parse().map_err(|_| ())?,
            signer_uid.parse().map_err(|_| ())?,
            signer_gid.parse().map_err(|_| ())?,
        );
    }
    if let [
        _,
        command,
        owner_uid,
        repository,
        trust_generation,
        openpgp_seed,
        openpgp_created_at,
        ml_dsa_public,
        ml_dsa_secret,
        next_policy,
        openpgp_public_output,
        openpgp_signature_output,
        ml_dsa_signature_output,
    ] = arguments.as_slice()
        && command == "sign-key-rotation"
    {
        return sign_key_rotation(
            owner_uid.parse().map_err(|_| ())?,
            repository,
            trust_generation.parse().map_err(|_| ())?,
            Path::new(openpgp_seed),
            openpgp_created_at.parse().map_err(|_| ())?,
            Path::new(ml_dsa_public),
            Path::new(ml_dsa_secret),
            Path::new(next_policy),
            Path::new(openpgp_public_output),
            Path::new(openpgp_signature_output),
            Path::new(ml_dsa_signature_output),
        );
    }
    let config = parse_arguments(&arguments)?;
    let mut capability_bytes = read_secret(&config.capability_file, 32, config.owner_uid)?;
    let mut capability_array = [0; 32];
    capability_array.copy_from_slice(&capability_bytes);
    erase_secret_bytes(&mut capability_bytes);
    let capability = ProtectedSignerCapability::new(capability_array).map_err(|_| ())?;
    erase_secret_bytes(&mut capability_array);
    let mut seed_bytes = read_secret(&config.openpgp_seed_file, 32, config.owner_uid)?;
    let mut seed = [0; 32];
    seed.copy_from_slice(&seed_bytes);
    erase_secret_bytes(&mut seed_bytes);
    let openpgp = SigningKeyV6::from_seed(seed, config.openpgp_created_at).map_err(|_| ())?;
    erase_secret_bytes(&mut seed);
    let ml_dsa = read_secret(
        &config.ml_dsa_secret_file,
        ML_DSA_65_SECRET_KEY_BYTES,
        config.owner_uid,
    )?;
    let ml_dsa_public = read_public(
        &config.ml_dsa_public_file,
        ML_DSA_65_PUBLIC_KEY_BYTES,
        config.owner_uid,
    )?;
    validate_ml_dsa_pair(&ml_dsa_public, &ml_dsa)?;
    let authority_receipt_public = read_public(
        &config.authority_receipt_public_file,
        32,
        config.owner_uid,
    )?;
    let authority_receipt_public: [u8; 32] = authority_receipt_public.try_into().map_err(|_| ())?;
    let mut state = SignerState::open(&config)?;

    let signals = TerminationSignals::block_current()?;
    let terminating = Arc::new(AtomicBool::new(false));
    let waiter_terminating = terminating.clone();
    let wake_socket = config.socket.clone();
    std::thread::spawn(move || {
        if signals.wait().is_ok() {
            waiter_terminating.store(true, Ordering::Release);
            let _ = UnixStream::connect(wake_socket);
        }
    });
    serve(
        &config,
        &capability,
        &openpgp,
        &ml_dsa_public,
        &ml_dsa,
        &authority_receipt_public,
        &mut state,
        &terminating,
    )
}

fn socket_health(
    path: &Path,
    capability_file: &Path,
    capability_owner_uid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), ()> {
    if capability_owner_uid == 0 || signer_uid == 0 || signer_gid == 0 {
        return Err(());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    let path = path.to_str().ok_or(())?;
    if !path.starts_with('/') || path.len() > 107 || path.as_bytes().contains(&0) {
        return Err(());
    }
    let mut capability_bytes = read_secret(capability_file, 32, capability_owner_uid)?;
    let mut capability_array = [0; 32];
    capability_array.copy_from_slice(&capability_bytes);
    erase_secret_bytes(&mut capability_bytes);
    let capability = ProtectedSignerCapability::new(capability_array).map_err(|_| ())?;
    erase_secret_bytes(&mut capability_array);
    let mut stream = UnixStream::connect(path).map_err(|_| ())?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let peer = stream.peer_cred().map_err(|_| ())?;
    if peer.uid != signer_uid || peer.gid != signer_gid {
        return Err(());
    }
    let hello = read_frame(&mut stream)?;
    let session = mrml_git::decode_protected_signer_hello(&hello, &capability).map_err(|_| ())?;
    let now = mrml_runtime::unix_time_seconds().ok_or(())?;
    if session.expires_at < now || session.maximum_sequence == 0 {
        return Err(());
    }
    println!("ready");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_key_rotation(
    owner_uid: u32,
    repository: &str,
    trust_generation: u64,
    openpgp_seed_path: &Path,
    openpgp_created_at: u32,
    ml_dsa_public_path: &Path,
    ml_dsa_secret_path: &Path,
    next_policy_path: &Path,
    openpgp_public_output: &Path,
    openpgp_signature_output: &Path,
    ml_dsa_signature_output: &Path,
) -> Result<(), ()> {
    if owner_uid == 0 || trust_generation == 0 || openpgp_created_at == 0 {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    let next_policy_bytes = read_public_bounded(
        next_policy_path,
        1,
        MAX_ENCODED_TRUST_POLICY_BYTES,
        owner_uid,
    )?;
    let next_policy = parse_trust_policy(&next_policy_bytes).map_err(|_| ())?;
    if next_policy.repository() != &repository {
        return Err(());
    }
    validate_new_public_output(openpgp_public_output, owner_uid)?;
    validate_new_public_output(openpgp_signature_output, owner_uid)?;
    validate_new_public_output(ml_dsa_signature_output, owner_uid)?;
    let mut seed_bytes = read_secret(openpgp_seed_path, 32, owner_uid)?;
    let mut seed = [0; 32];
    seed.copy_from_slice(&seed_bytes);
    erase_secret_bytes(&mut seed_bytes);
    let openpgp = SigningKeyV6::from_seed(seed, openpgp_created_at).map_err(|_| ())?;
    erase_secret_bytes(&mut seed);
    let ml_dsa_public = read_public(
        ml_dsa_public_path,
        ML_DSA_65_PUBLIC_KEY_BYTES,
        owner_uid,
    )?;
    let mut ml_dsa_secret = read_secret(
        ml_dsa_secret_path,
        ML_DSA_65_SECRET_KEY_BYTES,
        owner_uid,
    )?;
    validate_ml_dsa_pair(&ml_dsa_public, &ml_dsa_secret)?;
    let public_ml_dsa: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
        ml_dsa_public.as_slice().try_into().map_err(|_| ())?;
    let pair = AuthorizedHybridPair::bind(&openpgp.public_key(), public_ml_dsa);
    let transcript = canonical_hybrid_transcript(
        &repository,
        ObjectFormat::Sha256,
        GitObjectType::KeyRotation,
        SignaturePurpose::KeyRotation,
        TrustGeneration(trust_generation),
        pair,
        &next_policy_bytes,
    )
    .map_err(|_| ())?;
    let mut salt = [0; 32];
    let mut randomizer = [0; 32];
    mrml_runtime::fill_random(&mut salt).map_err(|_| ())?;
    mrml_runtime::fill_random(&mut randomizer).map_err(|_| ())?;
    let mut openpgp_signature = [0; MAX_OPENPGP_SIGNATURE_BYTES];
    let openpgp_length = sign_detached_v6_ascii_with_salt(
        &openpgp,
        &transcript,
        DigestAlgorithm::Sha512,
        mrml_runtime::unix_time_seconds().ok_or(())?,
        &salt,
        &mut openpgp_signature,
    )
    .map_err(|_| ())?;
    let mut ml_dsa_signature = [0; ML_DSA_65_SIGNATURE_BYTES];
    let signing_result = ml_dsa_65_sign(
        &ml_dsa_secret,
        b"mrml.git.hybrid.v1",
        &transcript,
        &randomizer,
        &mut ml_dsa_signature,
    );
    erase_secret_bytes(&mut ml_dsa_secret);
    erase_secret_bytes(&mut salt);
    erase_secret_bytes(&mut randomizer);
    signing_result.map_err(|_| ())?;
    let mut openpgp_public = [0; mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let openpgp_public_length = openpgp
        .public_key()
        .encode_ascii(&mut openpgp_public)
        .map_err(|_| ())?;
    write_new_public(
        openpgp_public_output,
        &openpgp_public[..openpgp_public_length],
        owner_uid,
    )?;
    write_new_public(
        openpgp_signature_output,
        &openpgp_signature[..openpgp_length],
        owner_uid,
    )?;
    write_new_public(ml_dsa_signature_output, &ml_dsa_signature, owner_uid)?;
    erase_secret_bytes(&mut ml_dsa_signature);
    println!("key-rotation authorization written");
    Ok(())
}

fn validate_ml_dsa_pair(public: &[u8], secret: &[u8]) -> Result<(), ()> {
    let mut randomizer = [0; 32];
    mrml_runtime::fill_random(&mut randomizer).map_err(|_| ())?;
    let mut signature = [0; ML_DSA_65_SIGNATURE_BYTES];
    let result = ml_dsa_65_sign(
        secret,
        b"mrml.git.signer.key-check.v1",
        b"startup key agreement",
        &randomizer,
        &mut signature,
    )
    .and_then(|_| {
        ml_dsa_65_verify(
            public,
            b"mrml.git.signer.key-check.v1",
            b"startup key agreement",
            &signature,
        )
    });
    erase_secret_bytes(&mut randomizer);
    erase_secret_bytes(&mut signature);
    result.map_err(|_| ())
}

const SIGNER_STATE_MAGIC: &[u8; 8] = b"MRGSTA01";
const SIGNER_STATE_BYTES: usize = 8 + 8 + 8 + 8 + 32;

struct SignerState {
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
}

impl SignerState {
    fn open(config: &Configuration) -> Result<Self, ()> {
        if !config.state_file.is_absolute() {
            return Err(());
        }
        if !config.state_file.exists() {
            let initial = Self {
                repository_generation: config.repository_generation,
                trust_generation: config.trust_generation,
                revocation_generation: config.revocation_generation,
            };
            initial.persist_new(&config.state_file, config)?;
        }
        let bytes = read_public(&config.state_file, SIGNER_STATE_BYTES, config.owner_uid)?;
        let state = Self::decode(&bytes, &config.repository)?;
        if state.trust_generation != config.trust_generation
            || state.revocation_generation != config.revocation_generation
        {
            return Err(());
        }
        Ok(state)
    }

    fn advance(
        &mut self,
        config: &Configuration,
        authority_public: &[u8; 32],
        encoded_receipt: &[u8],
    ) -> Result<(), ()> {
        let mut identity = Sha3_512::new();
        identity.update(b"MRML git receipt signer identity v1");
        identity.update(authority_public);
        let identity = identity.finalize();
        let next = verify_signer_generation_advancement(
            encoded_receipt,
            authority_public,
            &identity,
            &config.repository,
            self.repository_generation,
            self.trust_generation,
            self.revocation_generation,
        )
        .map_err(|_| ())?;
        let candidate = Self {
            repository_generation: next,
            trust_generation: self.trust_generation,
            revocation_generation: self.revocation_generation,
        };
        let temporary = config.state_file.with_extension("state.next");
        candidate.persist_new(&temporary, config)?;
        fs::rename(&temporary, &config.state_file).map_err(|_| ())?;
        sync_parent(&config.state_file)?;
        let reopened = Self::decode(
            &read_public(&config.state_file, SIGNER_STATE_BYTES, config.owner_uid)?,
            &config.repository,
        )?;
        if reopened.repository_generation != next
            || reopened.trust_generation != self.trust_generation
            || reopened.revocation_generation != self.revocation_generation
        {
            return Err(());
        }
        *self = reopened;
        Ok(())
    }

    fn persist_new(&self, path: &Path, config: &Configuration) -> Result<(), ()> {
        validate_new_public_output(path, config.owner_uid)?;
        let bytes = self.encode(&config.repository);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(|_| ())?;
        output.write_all(&bytes).map_err(|_| ())?;
        output.sync_all().map_err(|_| ())?;
        drop(output);
        sync_parent(path)
    }

    fn encode(&self, repository: &RepositoryIdentity) -> [u8; SIGNER_STATE_BYTES] {
        let mut output = [0u8; SIGNER_STATE_BYTES];
        output[..8].copy_from_slice(SIGNER_STATE_MAGIC);
        output[8..16].copy_from_slice(&self.repository_generation.0.to_be_bytes());
        output[16..24].copy_from_slice(&self.trust_generation.0.to_be_bytes());
        output[24..32].copy_from_slice(&self.revocation_generation.0.to_be_bytes());
        let checksum = signer_state_checksum(repository, &output[..32]);
        output[32..].copy_from_slice(&checksum);
        output
    }

    fn decode(bytes: &[u8], repository: &RepositoryIdentity) -> Result<Self, ()> {
        if bytes.len() != SIGNER_STATE_BYTES || &bytes[..8] != SIGNER_STATE_MAGIC {
            return Err(());
        }
        let expected = signer_state_checksum(repository, &bytes[..32]);
        if bytes[32..] != expected {
            return Err(());
        }
        let read = |range: core::ops::Range<usize>| {
            u64::from_be_bytes(bytes[range].try_into().map_err(|_| ())?)
                .checked_sub(0)
                .filter(|value| *value != 0)
                .ok_or(())
        };
        Ok(Self {
            repository_generation: RepositoryGeneration(read(8..16)?),
            trust_generation: TrustGeneration(read(16..24)?),
            revocation_generation: RevocationGeneration(read(24..32)?),
        })
    }
}

fn signer_state_checksum(repository: &RepositoryIdentity, state: &[u8]) -> [u8; 32] {
    let mut checksum = Sha256::new();
    checksum.update(b"MRML protected signer generation state v1\0");
    checksum.update(repository.as_str().as_bytes());
    checksum.update(state);
    checksum.finalize()
}

fn sync_parent(path: &Path) -> Result<(), ()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path.parent().ok_or(())?)
        .map_err(|_| ())?;
    directory.sync_all().map_err(|_| ())
}

fn serve(
    config: &Configuration,
    capability: &ProtectedSignerCapability,
    openpgp: &SigningKeyV6,
    ml_dsa_public: &[u8],
    ml_dsa: &[u8],
    authority_receipt_public: &[u8; 32],
    state: &mut SignerState,
    terminating: &AtomicBool,
) -> Result<(), ()> {
    validate_socket_path(&config.socket, config.owner_uid, config.socket_gid)?;
    if fs::symlink_metadata(&config.socket).is_ok() {
        return Err(());
    }
    let listener = UnixListener::bind(&config.socket).map_err(|_| ())?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660)).map_err(|_| ())?;
    let socket_metadata = fs::symlink_metadata(&config.socket).map_err(|_| ())?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.file_type().is_symlink()
        || socket_metadata.uid() != config.owner_uid
        || socket_metadata.gid() != config.socket_gid
        || socket_metadata.mode() & 0o777 != 0o660
    {
        return Err(());
    }
    let socket_guard = SocketGuard {
        path: config.socket.clone(),
        device: socket_metadata.dev(),
        inode: socket_metadata.ino(),
    };
    println!("ready");
    while !terminating.load(Ordering::Acquire) {
        let (mut stream, _) = listener.accept().map_err(|_| ())?;
        if terminating.load(Ordering::Acquire) {
            break;
        }
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
        let peer = stream.peer_cred().map_err(|_| ())?;
        if peer.uid != config.client_uid || peer.gid != config.client_gid {
            eprintln!("component=mrml-git-protected-signer event=request_failed category=peer");
            continue;
        }
        let mut session_id = [0; 32];
        if mrml_runtime::fill_random(&mut session_id).is_err() || session_id == [0; 32] {
            eprintln!("component=mrml-git-protected-signer event=request_failed category=random");
            continue;
        }
        let session = match mrml_runtime::unix_time_seconds()
            .and_then(|now| now.checked_add(SESSION_LIFETIME_SECONDS))
            .map(|expires_at| ProtectedSignerSession {
                id: session_id,
                expires_at,
                maximum_sequence: MAXIMUM_SESSION_SEQUENCE,
            })
            .and_then(|session| {
                encode_protected_signer_hello(session, capability)
                    .ok()
                    .map(|hello| (session, hello))
            }) {
            Some(session) => session,
            None => {
                eprintln!("component=mrml-git-protected-signer event=request_failed category=random");
                continue;
            }
        };
        if write_frame(&mut stream, &session.1).is_err() {
            eprintln!("component=mrml-git-protected-signer event=request_failed category=write");
            continue;
        }
        match serve_one(
            &mut stream,
            config,
            capability,
            openpgp,
            ml_dsa_public,
            ml_dsa,
            authority_receipt_public,
            state,
            session.0,
        ) {
            Ok(()) => eprintln!(
                "component=mrml-git-protected-signer event=request_complete category=sign"
            ),
            Err(error) => eprintln!(
                "component=mrml-git-protected-signer event=request_failed category={}",
                error.category()
            ),
        }
    }
    drop(socket_guard);
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && !metadata.file_type().is_symlink()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
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
        let mut set = NativeSignalSet { bits: [0; 16] };
        if unsafe { sigemptyset(&mut set) } != 0
            || unsafe { sigaddset(&mut set, 2) } != 0
            || unsafe { sigaddset(&mut set, 15) } != 0
            || unsafe { pthread_sigmask(0, &set, core::ptr::null_mut()) } != 0
        {
            return Err(());
        }
        Ok(Self { set })
    }

    fn wait(self) -> Result<(), ()> {
        let mut signal = 0;
        (unsafe { sigwait(&self.set, &mut signal) } == 0 && matches!(signal, 2 | 15))
            .then_some(())
            .ok_or(())
    }
}

unsafe extern "C" {
    fn sigemptyset(set: *mut NativeSignalSet) -> i32;
    fn sigaddset(set: *mut NativeSignalSet, signal: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const NativeSignalSet, old: *mut NativeSignalSet) -> i32;
    fn sigwait(set: *const NativeSignalSet, signal: *mut i32) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServeError {
    Read,
    Authenticate,
    SignContext,
    SignCommit,
    SignTranscript,
    SignRandom,
    SignOpenPgp,
    SignMlDsa,
    SignOutput,
    Encode,
    Write,
}

impl ServeError {
    const fn category(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Authenticate => "authenticate",
            Self::SignContext => "sign-context",
            Self::SignCommit => "sign-commit",
            Self::SignTranscript => "sign-transcript",
            Self::SignRandom => "sign-random",
            Self::SignOpenPgp => "sign-openpgp",
            Self::SignMlDsa => "sign-ml-dsa",
            Self::SignOutput => "sign-output",
            Self::Encode => "encode",
            Self::Write => "write",
        }
    }
}

fn serve_one(
    stream: &mut UnixStream,
    config: &Configuration,
    capability: &ProtectedSignerCapability,
    openpgp: &SigningKeyV6,
    ml_dsa_public: &[u8],
    ml_dsa: &[u8],
    authority_receipt_public: &[u8; 32],
    state: &mut SignerState,
    session: ProtectedSignerSession,
) -> Result<(), ServeError> {
    let frame = read_frame(stream).map_err(|_| ServeError::Read)?;
    if protected_signer_operation(&frame).map_err(|_| ServeError::Authenticate)?
        == OP_ADVANCE_GENERATION
    {
        let request = decode_advance_request(&frame, capability)
            .map_err(|_| ServeError::Authenticate)?;
        let now = mrml_runtime::unix_time_seconds().ok_or(ServeError::Authenticate)?;
        validate_session_fields(
            session,
            request.session_id,
            request.session_expires_at,
            request.sequence,
            now,
        )
        .map_err(|_| ServeError::Authenticate)?;
        let result = state.advance(
            config,
            authority_receipt_public,
            &request.authenticated_receipt,
        );
        let response = encode_advance_response(
            request.request_id,
            session,
            request.sequence,
            result.is_ok(),
            capability,
        )
        .map_err(|_| ServeError::Encode)?;
        write_frame(stream, &response).map_err(|_| ServeError::Write)?;
        return result.map_err(|_| ServeError::SignContext);
    }
    let request = decode_protected_signer_request(&frame, capability)
        .map_err(|_| ServeError::Authenticate)?;
    let now = mrml_runtime::unix_time_seconds().ok_or(ServeError::Authenticate)?;
    validate_session_request(session, &request, now).map_err(|_| ServeError::Authenticate)?;
    let request_id = request.request_id;
    let sequence = request.sequence;
    let result = sign_request(config, state, openpgp, ml_dsa_public, ml_dsa, request);
    let response = encode_protected_signer_response(
        request_id,
        session,
        sequence,
        result
            .as_ref()
            .map_err(|_| UnixProtectedSignerError::Rejected),
        capability,
    )
    .map_err(|_| ServeError::Encode)?;
    write_frame(stream, &response).map_err(|_| ServeError::Write)?;
    result.map(|_| ()).map_err(|error| match error {
        SignError::Context => ServeError::SignContext,
        SignError::Commit => ServeError::SignCommit,
        SignError::Transcript => ServeError::SignTranscript,
        SignError::Random => ServeError::SignRandom,
        SignError::OpenPgp => ServeError::SignOpenPgp,
        SignError::MlDsa => ServeError::SignMlDsa,
        SignError::Output => ServeError::SignOutput,
    })
}

fn validate_session_request(
    session: ProtectedSignerSession,
    request: &mrml_git::ProtectedSignerRequest,
    now: u64,
) -> Result<(), ()> {
    validate_session_fields(
        session,
        request.session_id,
        request.session_expires_at,
        request.sequence,
        now,
    )
}

fn validate_session_fields(
    session: ProtectedSignerSession,
    session_id: [u8; 32],
    session_expires_at: u64,
    sequence: u64,
    now: u64,
) -> Result<(), ()> {
    if session_id != session.id
        || session_expires_at != session.expires_at
        || sequence != 1
        || sequence > session.maximum_sequence
        || now > session.expires_at
    {
        return Err(());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignError {
    Context,
    Commit,
    Transcript,
    Random,
    OpenPgp,
    MlDsa,
    Output,
}

fn sign_request(
    config: &Configuration,
    state: &SignerState,
    openpgp: &SigningKeyV6,
    ml_dsa_public: &[u8],
    ml_dsa: &[u8],
    request: mrml_git::ProtectedSignerRequest,
) -> Result<HybridCommitSignatures, SignError> {
    if request.repository != config.repository
        || request.repository_generation != state.repository_generation
        || request.trust_generation != state.trust_generation
        || request.revocation_generation != state.revocation_generation
    {
        return Err(SignError::Context);
    }
    let (computed, _) = encode_loose_object_with_format(
        ObjectFormat::Sha256,
        mrml_git::ObjectKind::Commit,
        &request.exact_contents,
    );
    if computed != request.commit {
        return Err(SignError::Commit);
    }
    let public = openpgp.public_key();
    let public_ml_dsa: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
        ml_dsa_public.try_into().map_err(|_| SignError::Context)?;
    let pair = AuthorizedHybridPair::bind(&public, public_ml_dsa);
    let transcript = canonical_hybrid_transcript(
        &request.repository,
        ObjectFormat::Sha256,
        GitObjectType::Commit,
        SignaturePurpose::GitCommit,
        request.trust_generation,
        pair,
        &request.exact_contents,
    )
    .map_err(|_| SignError::Transcript)?;
    let mut salt = [0; 32];
    let mut randomizer = [0; 32];
    mrml_runtime::fill_random(&mut salt).map_err(|_| SignError::Random)?;
    mrml_runtime::fill_random(&mut randomizer).map_err(|_| SignError::Random)?;
    let mut openpgp_signature = [0; MAX_OPENPGP_SIGNATURE_BYTES];
    let openpgp_length = sign_detached_v6_ascii_with_salt(
        openpgp,
        &transcript,
        DigestAlgorithm::Sha512,
        mrml_runtime::unix_time_seconds().ok_or(SignError::OpenPgp)?,
        &salt,
        &mut openpgp_signature,
    )
    .map_err(|_| SignError::OpenPgp)?;
    let mut ml_dsa_signature = [0; ML_DSA_65_SIGNATURE_BYTES];
    ml_dsa_65_sign(
        ml_dsa,
        b"mrml.git.hybrid.v1",
        &transcript,
        &randomizer,
        &mut ml_dsa_signature,
    )
    .map_err(|_| SignError::MlDsa)?;
    erase_secret_bytes(&mut salt);
    erase_secret_bytes(&mut randomizer);
    HybridCommitSignatures::new(&openpgp_signature[..openpgp_length], &ml_dsa_signature)
        .map_err(|_| SignError::Output)
}

fn parse_arguments(arguments: &[String]) -> Result<Configuration, ()> {
    let [
        _,
        command,
        socket,
        capability,
        client_uid,
        client_gid,
        owner_uid,
        socket_gid,
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        state_file,
        authority_receipt_public,
        openpgp_seed,
        openpgp_created_at,
        ml_dsa_public,
        ml_dsa_secret,
    ] = arguments
    else {
        return Err(());
    };
    if command != "serve" {
        return Err(());
    }
    let nonzero = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(())
    };
    Ok(Configuration {
        socket: socket.into(),
        capability_file: capability.into(),
        client_uid: u32::try_from(nonzero(client_uid)?).map_err(|_| ())?,
        client_gid: u32::try_from(nonzero(client_gid)?).map_err(|_| ())?,
        owner_uid: u32::try_from(nonzero(owner_uid)?).map_err(|_| ())?,
        socket_gid: u32::try_from(nonzero(socket_gid)?).map_err(|_| ())?,
        repository: RepositoryIdentity::parse(repository).map_err(|_| ())?,
        repository_generation: RepositoryGeneration(nonzero(repository_generation)?),
        trust_generation: TrustGeneration(nonzero(trust_generation)?),
        revocation_generation: RevocationGeneration(nonzero(revocation_generation)?),
        state_file: state_file.into(),
        authority_receipt_public_file: authority_receipt_public.into(),
        openpgp_seed_file: openpgp_seed.into(),
        openpgp_created_at: u32::try_from(nonzero(openpgp_created_at)?).map_err(|_| ())?,
        ml_dsa_public_file: ml_dsa_public.into(),
        ml_dsa_secret_file: ml_dsa_secret.into(),
    })
}

fn read_public(path: &Path, exact: usize, expected_owner: u32) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.len() != exact as u64
    {
        return Err(());
    }
    let mut bytes = vec![0; exact];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn read_public_bounded(
    path: &Path,
    minimum: usize,
    maximum: usize,
    expected_owner: u32,
) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.len() < minimum as u64
        || metadata.len() > maximum as u64
    {
        return Err(());
    }
    let mut bytes = vec![0; metadata.len() as usize];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn validate_new_public_output(path: &Path, expected_owner: u32) -> Result<(), ()> {
    if !path.is_absolute() || fs::symlink_metadata(path).is_ok() {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
    {
        return Err(());
    }
    Ok(())
}

fn write_new_public(path: &Path, bytes: &[u8], expected_owner: u32) -> Result<(), ()> {
    validate_new_public_output(path, expected_owner)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    output.write_all(bytes).map_err(|_| ())?;
    output.sync_all().map_err(|_| ())?;
    drop(output);
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != bytes.len() as u64
    {
        return Err(());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path.parent().ok_or(())?)
        .map_err(|_| ())?;
    directory.sync_all().map_err(|_| ())
}

fn read_secret(path: &Path, exact: usize, expected_owner: u32) -> Result<SecretBuffer, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || !matches!(metadata.mode() & 0o777, 0o400 | 0o600)
        || metadata.len() != exact as u64
    {
        return Err(());
    }
    let mut bytes = SecretBuffer(vec![0; exact]);
    if file.read_exact(&mut bytes).is_err() {
        return Err(());
    }
    Ok(bytes)
}

fn validate_socket_path(path: &Path, expected_owner: u32, expected_group: u32) -> Result<(), ()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 107
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let canonical = fs::canonicalize(parent).map_err(|_| ())?;
    if canonical != parent {
        return Err(());
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.gid() != expected_group
        || metadata.mode() & 0o7777 != 0o2770
    {
        return Err(());
    }
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).map_err(|_| ())?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_REQUEST_FRAME {
        return Err(());
    }
    let mut frame = vec![0; length];
    stream.read_exact(&mut frame).map_err(|_| ())?;
    Ok(frame)
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), ()> {
    let length = u32::try_from(frame.len()).map_err(|_| ())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(frame))
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_git::{
        AuditReceipt, FullRefName, HybridVerificationRequest, ObjectId, PolicyPairStatus,
        QuarantineTransactionId, TrustPolicyCandidate, TrustPolicyState,
        authenticated_audit_receipt_transcript, encode_audit_receipt, encode_trust_policy,
        verify_hybrid_signature,
    };
    use mrml_runtime::Vector;

    #[test]
    fn ml_dsa_startup_check_rejects_a_substituted_public_key() {
        let mut public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        mrml_crypto::ml_dsa_65_keygen(&[7; 32], &mut public, &mut secret).unwrap();
        validate_ml_dsa_pair(&public, &secret).unwrap();
        public[0] ^= 1;
        assert!(validate_ml_dsa_pair(&public, &secret).is_err());
        erase_secret_bytes(&mut secret);
    }

    #[test]
    fn signer_operation_produces_hybrid_commit_signatures() {
        let values = [
            "signer",
            "serve",
            "/run/user/1/s.sock",
            "/run/user/1/cap",
            "1",
            "1",
            "1",
            "1",
            "owner/repo",
            "2",
            "3",
            "4",
            "/state/generation.state",
            "/keys/authority-receipt-public.bin",
            "/keys/pgp",
            "1700000000",
            "/keys/ml.pub",
            "/keys/ml.secret",
        ]
        .map(String::from);
        let config = parse_arguments(&values).unwrap();
        let openpgp = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        mrml_crypto::ml_dsa_65_keygen(&[9; 32], &mut ml_public, &mut ml_secret).unwrap();
        let contents =
            b"tree 1111111111111111111111111111111111111111111111111111111111111111\n\na\n";
        let (commit, _) = encode_loose_object_with_format(
            ObjectFormat::Sha256,
            mrml_git::ObjectKind::Commit,
            contents,
        );
        let request = mrml_git::ProtectedSignerRequest {
            session_id: [5; 32],
            session_expires_at: u64::MAX,
            sequence: 1,
            request_id: 1,
            repository: RepositoryIdentity::parse("owner/repo").unwrap(),
            repository_generation: RepositoryGeneration(2),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            commit,
            exact_contents: (*contents).into(),
        };
        let state = SignerState {
            repository_generation: RepositoryGeneration(2),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
        };
        let signatures =
            sign_request(&config, &state, &openpgp, &ml_public, &ml_secret, request).unwrap();
        assert!(!signatures.openpgp().is_empty());
        assert_eq!(signatures.ml_dsa().len(), ML_DSA_65_SIGNATURE_BYTES);
        erase_secret_bytes(&mut ml_secret);
    }

    #[test]
    fn signer_session_rejects_replay_wrong_sequence_and_expiry() {
        let session = ProtectedSignerSession {
            id: [7; 32],
            expires_at: 20,
            maximum_sequence: 1,
        };
        let mut request = mrml_git::ProtectedSignerRequest {
            session_id: session.id,
            session_expires_at: session.expires_at,
            sequence: 1,
            request_id: 1,
            repository: RepositoryIdentity::parse("owner/repo").unwrap(),
            repository_generation: RepositoryGeneration(2),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            commit: ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap(),
            exact_contents: Vector::from(*b"commit bytes"),
        };
        assert!(validate_session_request(session, &request, 20).is_ok());
        request.session_id[0] ^= 1;
        assert!(validate_session_request(session, &request, 20).is_err());
        request.session_id = session.id;
        request.sequence = 2;
        assert!(validate_session_request(session, &request, 20).is_err());
        request.sequence = 1;
        assert!(validate_session_request(session, &request, 21).is_err());
    }

    #[test]
    fn signer_state_advances_once_and_survives_restart() {
        let root = std::env::temp_dir().join(format!(
            "mrml-protected-signer-state-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = fs::metadata(&root).unwrap().uid();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let config = Configuration {
            socket: root.join("signer.sock"),
            capability_file: root.join("capability"),
            client_uid: owner_uid.saturating_add(1),
            client_gid: owner_uid.saturating_add(1),
            owner_uid,
            socket_gid: owner_uid,
            repository: repository.clone(),
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(11),
            revocation_generation: RevocationGeneration(13),
            state_file: root.join("generation.state"),
            authority_receipt_public_file: root.join("authority.pub"),
            openpgp_seed_file: root.join("openpgp.seed"),
            openpgp_created_at: 1,
            ml_dsa_public_file: root.join("ml.pub"),
            ml_dsa_secret_file: root.join("ml.secret"),
        };
        let mut state = SignerState::open(&config).unwrap();
        let seed = [0x42; 32];
        let public = mrml_crypto::ed25519_public(&seed);
        let receipt = AuditReceipt {
            transaction: QuarantineTransactionId([3; 16]),
            repository,
            repository_generation: RepositoryGeneration(7),
            activated_repository_generation: RepositoryGeneration(8),
            trust_generation: TrustGeneration(11),
            revocation_generation: RevocationGeneration(13),
            updates: [(
                FullRefName::parse("refs/heads/main").unwrap(),
                ObjectId::Sha256([1; 32]),
                ObjectId::Sha256([2; 32]),
            )]
            .into(),
        };
        let canonical = encode_audit_receipt(&receipt).unwrap();
        let transcript = authenticated_audit_receipt_transcript(&canonical).unwrap();
        let signature = mrml_crypto::ed25519_sign(&seed, &transcript);
        let mut signer_identity = Sha3_512::new();
        signer_identity.update(b"MRML git receipt signer identity v1");
        signer_identity.update(&public);
        let signer_identity = signer_identity.finalize();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"MRARCP01");
        encoded.extend_from_slice(&signer_identity);
        encoded.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&canonical);
        encoded.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&signature);
        let checksum = Sha256::digest(&encoded);
        encoded.extend_from_slice(&checksum);
        state.advance(&config, &public, &encoded).unwrap();
        assert_eq!(state.repository_generation, RepositoryGeneration(8));
        let reopened = SignerState::open(&config).unwrap();
        assert_eq!(reopened.repository_generation, RepositoryGeneration(8));
        assert!(state.advance(&config, &public, &encoded).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_shot_key_rotation_outputs_are_exact_and_independently_verified() {
        let root = std::env::temp_dir().join(format!(
            "mrml-key-rotation-signer-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = fs::metadata(&root).unwrap().uid();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let openpgp_seed = [0x21; 32];
        let openpgp = SigningKeyV6::from_seed(openpgp_seed, 1_700_000_000).unwrap();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        mrml_crypto::ml_dsa_65_keygen(&[0x22; 32], &mut ml_public, &mut ml_secret).unwrap();
        let pair = AuthorizedHybridPair::bind(&openpgp.public_key(), &ml_public);
        let policy = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(2),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(2),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: false,
            legacy_checkpoint: None,
            hybrid_cutover: None,
            emergency_policy_digest: None,
            active_pairs: [pair].into(),
            pair_statuses: [PolicyPairStatus::new(pair, 1, u64::MAX, None).unwrap()].into(),
            legacy_v4_statuses: Vector::new(),
            revoked_legacy_v4: Vector::new(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        let policy_bytes = encode_trust_policy(&policy).unwrap();
        let seed_path = root.join("openpgp.seed");
        let ml_public_path = root.join("ml.pub");
        let ml_secret_path = root.join("ml.secret");
        let policy_path = root.join("next-policy.bin");
        write_test_input(&seed_path, &openpgp_seed, 0o600);
        write_test_input(&ml_public_path, &ml_public, 0o600);
        write_test_input(&ml_secret_path, &ml_secret, 0o600);
        write_test_input(&policy_path, &policy_bytes, 0o600);
        erase_secret_bytes(&mut ml_secret);
        let openpgp_public_output = root.join("openpgp.asc");
        let openpgp_signature_output = root.join("openpgp.sig");
        let ml_signature_output = root.join("ml.sig");
        sign_key_rotation(
            owner_uid,
            repository.as_str(),
            2,
            &seed_path,
            1_700_000_000,
            &ml_public_path,
            &ml_secret_path,
            &policy_path,
            &openpgp_public_output,
            &openpgp_signature_output,
            &ml_signature_output,
        )
        .unwrap();
        assert!(
            sign_key_rotation(
                owner_uid,
                repository.as_str(),
                2,
                &seed_path,
                1_700_000_000,
                &ml_public_path,
                &ml_secret_path,
                &policy_path,
                &openpgp_public_output,
                &openpgp_signature_output,
                &ml_signature_output,
            )
            .is_err()
        );
        let openpgp_public_bytes = fs::read(&openpgp_public_output).unwrap();
        let mut public_scratch = vec![0; mrml_openpgp::MAX_OPENPGP_PUBLIC_KEY_BYTES];
        let exported_openpgp = mrml_openpgp::parse_public_key_v6_ascii(
            &openpgp_public_bytes,
            &mut public_scratch,
        )
        .unwrap();
        assert_eq!(exported_openpgp, openpgp.public_key());
        let openpgp_signature = fs::read(&openpgp_signature_output).unwrap();
        let ml_signature = fs::read(&ml_signature_output).unwrap();
        let now = mrml_runtime::unix_time_seconds().unwrap();
        let verification_policy = policy
            .active_verification_policy_at(pair, now, true)
            .unwrap();
        let request = HybridVerificationRequest {
            repository: &repository,
            object_format: ObjectFormat::Sha256,
            object_type: GitObjectType::KeyRotation,
            purpose: SignaturePurpose::KeyRotation,
            trust_generation: TrustGeneration(2),
            revocation_generation: RevocationGeneration(2),
            payload: &policy_bytes,
            openpgp_signature: &openpgp_signature,
            ml_dsa_signature: &ml_signature,
        };
        let mut signature_scratch = vec![0; MAX_OPENPGP_SIGNATURE_BYTES];
        verify_hybrid_signature(
            &verification_policy,
            &exported_openpgp,
            &ml_public,
            &request,
            &mut signature_scratch,
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    fn write_test_input(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn arguments_reject_zero_generations_and_wrong_arity() {
        let values = [
            "signer",
            "serve",
            "/run/user/1/s.sock",
            "/run/user/1/cap",
            "1",
            "1",
            "1",
            "1",
            "owner/repo",
            "1",
            "2",
            "3",
            "/state/generation.state",
            "/keys/authority-receipt-public.bin",
            "/keys/pgp",
            "1700000000",
            "/keys/ml.pub",
            "/keys/ml.secret",
        ]
        .map(String::from);
        assert!(parse_arguments(&values).is_ok());
        let mut zero = values;
        zero[10] = "0".into();
        assert!(parse_arguments(&zero).is_err());
        assert!(parse_arguments(&zero[..10]).is_err());
    }

    #[test]
    fn socket_directory_requires_exact_owner_group_and_setgid_mode() {
        let root = std::env::temp_dir().join(format!(
            "mrml-protected-signer-socket-policy-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o2770)).unwrap();
        let metadata = fs::symlink_metadata(&root).unwrap();
        let socket = root.join("signer.sock");
        assert!(validate_socket_path(&socket, metadata.uid(), metadata.gid()).is_ok());
        assert!(
            validate_socket_path(&socket, metadata.uid(), metadata.gid().wrapping_add(1)).is_err()
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_socket_path(&socket, metadata.uid(), metadata.gid()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
