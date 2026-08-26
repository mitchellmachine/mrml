use crate::{PeError, PeImage};
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512, lamport_verify};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    Kernel = 1,
    VmImage = 2,
    ServiceImage = 3,
    CudaKernelBundle = 4,
    LaunchPolicy = 5,
    ApplicationImage = 6,
}

pub const MAX_KERNEL_IMAGE_BYTES: u32 = 64 * 1024 * 1024;
pub const MAX_SERVICE_IMAGE_BYTES: u32 = 128 * 1024 * 1024;
pub const MAX_VM_IMAGE_BYTES: u32 = 512 * 1024 * 1024;
pub const MAX_CUDA_KERNEL_BUNDLE_BYTES: u32 = 64 * 1024 * 1024;
pub const MAX_LAUNCH_POLICY_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_APPLICATION_IMAGE_BYTES: u32 = 128 * 1024 * 1024;

pub const fn executable_image_limit(kind: ArtifactKind) -> Option<u32> {
    match kind {
        ArtifactKind::Kernel => Some(MAX_KERNEL_IMAGE_BYTES),
        ArtifactKind::ServiceImage => Some(MAX_SERVICE_IMAGE_BYTES),
        ArtifactKind::VmImage => Some(MAX_VM_IMAGE_BYTES),
        ArtifactKind::ApplicationImage => Some(MAX_APPLICATION_IMAGE_BYTES),
        ArtifactKind::CudaKernelBundle | ArtifactKind::LaunchPolicy => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    InvalidPublicKey,
    UntrustedPublicKey,
    InvalidSignature,
    RollbackDetected,
    EmptyArtifact,
    MalformedManifest,
    MissingTrustRoot,
    ReusedTrustRoot,
    VersionExhausted,
    MalformedBootstrapState,
    UnauthenticatedBootstrapState,
    StateConflict,
    StateStorageFailure,
    MalformedContainer,
    WrongArtifactKind,
    ReleaseMismatch,
    IncompleteReleaseAdmission,
}

pub const SIGNED_ARTIFACT_HEADER_BYTES: usize = 112;
pub const SIGNED_ARTIFACT_OVERHEAD_BYTES: usize =
    SIGNED_ARTIFACT_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES + LAMPORT_SIGNATURE_BYTES;
const SIGNED_ARTIFACT_MAGIC: &[u8; 16] = b"MRML-SIGNED-v1\0\0";

/// Allocation-free view of the canonical signed-artifact wire format.
///
/// The public key and signature have fixed lengths, and the payload consumes
/// the exact remainder of the input. This prevents trailing-data and offset
/// confusion between the build signer, firmware, and kernel.
pub struct SignedArtifact<'a> {
    kind: ArtifactKind,
    version: u64,
    payload: &'a [u8],
    public_key: &'a [u8],
    signature: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableArtifactError {
    Signature(ArtifactError),
    Format(PeError),
    NonExecutableKind,
}

pub struct VerifiedExecutable<'a> {
    artifact: VerifiedArtifact,
    image: PeImage<'a>,
}

impl<'a> VerifiedExecutable<'a> {
    pub const fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }
    pub const fn image(&self) -> &PeImage<'a> {
        &self.image
    }
}

impl<'a> SignedArtifact<'a> {
    pub fn decode(encoded: &'a [u8]) -> Result<Self, ArtifactError> {
        let fixed = SIGNED_ARTIFACT_HEADER_BYTES
            .checked_add(LAMPORT_PUBLIC_KEY_BYTES)
            .and_then(|length| length.checked_add(LAMPORT_SIGNATURE_BYTES))
            .ok_or(ArtifactError::MalformedContainer)?;
        if encoded.len() < fixed || &encoded[..16] != SIGNED_ARTIFACT_MAGIC {
            return Err(ArtifactError::MalformedContainer);
        }
        let kind = match encoded[16] {
            1 => ArtifactKind::Kernel,
            2 => ArtifactKind::VmImage,
            3 => ArtifactKind::ServiceImage,
            4 => ArtifactKind::CudaKernelBundle,
            5 => ArtifactKind::LaunchPolicy,
            6 => ArtifactKind::ApplicationImage,
            _ => return Err(ArtifactError::MalformedContainer),
        };
        if encoded[17..24].iter().any(|byte| *byte != 0) {
            return Err(ArtifactError::MalformedContainer);
        }
        let version = u64::from_le_bytes(
            encoded[24..32]
                .try_into()
                .map_err(|_| ArtifactError::MalformedContainer)?,
        );
        let payload_length = u64::from_le_bytes(
            encoded[32..40]
                .try_into()
                .map_err(|_| ArtifactError::MalformedContainer)?,
        );
        let payload_length =
            usize::try_from(payload_length).map_err(|_| ArtifactError::MalformedContainer)?;
        let expected = fixed
            .checked_add(payload_length)
            .ok_or(ArtifactError::MalformedContainer)?;
        if version == 0 || payload_length == 0 || encoded.len() != expected {
            return Err(ArtifactError::MalformedContainer);
        }
        let declared_digest = &encoded[40..104];
        if encoded[104..112].iter().any(|byte| *byte != 0) {
            return Err(ArtifactError::MalformedContainer);
        }
        let key_start = SIGNED_ARTIFACT_HEADER_BYTES;
        let signature_start = key_start + LAMPORT_PUBLIC_KEY_BYTES;
        let payload_start = signature_start + LAMPORT_SIGNATURE_BYTES;
        let payload = &encoded[payload_start..];
        let digest = Sha3_512::digest(payload);
        if declared_digest != digest {
            return Err(ArtifactError::MalformedContainer);
        }
        Ok(Self {
            kind,
            version,
            public_key: &encoded[key_start..signature_start],
            signature: &encoded[signature_start..payload_start],
            payload,
        })
    }

    /// Confirms that this exact canonical container carries the payload from
    /// an already authenticated executable. This is a transport binding only:
    /// callers must first verify the signature through a `TrustRoot`.
    pub fn matches_verified_executable(&self, executable: &VerifiedExecutable<'_>) -> bool {
        self.kind == executable.artifact().kind()
            && self.version == executable.artifact().version()
            && Sha3_512::digest(self.payload) == *executable.artifact().digest()
    }

    pub fn verify(
        &self,
        root: &TrustRoot,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedArtifact, ArtifactError> {
        if self.kind != expected_kind || root.kind != expected_kind {
            return Err(ArtifactError::WrongArtifactKind);
        }
        root.verify(self.version, self.payload, self.public_key, self.signature)
    }

    /// Authenticates an OS executable before interpreting any PE-controlled
    /// offsets. CUDA bundles and launch policies are data, never executables.
    pub fn verify_executable(
        &self,
        root: &TrustRoot,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedExecutable<'a>, ExecutableArtifactError> {
        let maximum = executable_image_limit(expected_kind)
            .ok_or(ExecutableArtifactError::NonExecutableKind)?;
        let artifact = self
            .verify(root, expected_kind)
            .map_err(ExecutableArtifactError::Signature)?;
        let image = PeImage::parse_with_limit(self.payload, maximum)
            .map_err(ExecutableArtifactError::Format)?;
        Ok(VerifiedExecutable { artifact, image })
    }

    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }
}

pub struct TrustRoot {
    kind: ArtifactKind,
    public_key_digest: [u8; 64],
    minimum_version: u64,
}

impl TrustRoot {
    pub const fn new(
        kind: ArtifactKind,
        public_key_digest: [u8; 64],
        minimum_version: u64,
    ) -> Self {
        Self {
            kind,
            public_key_digest,
            minimum_version,
        }
    }

    pub fn verify(
        &self,
        version: u64,
        artifact: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedArtifact, ArtifactError> {
        if artifact.is_empty() {
            return Err(ArtifactError::EmptyArtifact);
        }
        if version < self.minimum_version {
            return Err(ArtifactError::RollbackDetected);
        }
        if public_key.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(ArtifactError::InvalidPublicKey);
        }
        let candidate = Sha3_512::digest(public_key);
        let mut difference = 0u8;
        for (candidate_byte, trusted_byte) in candidate.iter().zip(&self.public_key_digest) {
            difference |= *candidate_byte ^ *trusted_byte;
        }
        if difference != 0 {
            return Err(ArtifactError::UntrustedPublicKey);
        }
        if signature.len() != LAMPORT_SIGNATURE_BYTES {
            return Err(ArtifactError::InvalidSignature);
        }
        let digest = Sha3_512::digest(artifact);
        let statement = artifact_statement(self.kind, version, artifact.len() as u64, digest);
        lamport_verify(public_key, &statement, signature)
            .map_err(|_| ArtifactError::InvalidSignature)?;
        Ok(VerifiedArtifact {
            kind: self.kind,
            version,
            digest,
        })
    }
}

pub struct VerifiedArtifact {
    kind: ArtifactKind,
    version: u64,
    digest: [u8; 64],
}

impl VerifiedArtifact {
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

pub fn artifact_statement(
    kind: ArtifactKind,
    version: u64,
    length: u64,
    digest: [u8; 64],
) -> [u8; 104] {
    let mut statement = [0u8; 104];
    statement[..17].copy_from_slice(b"MRML-ARTIFACT-v1\0");
    statement[17] = kind as u8;
    statement[24..32].copy_from_slice(&version.to_le_bytes());
    statement[32..40].copy_from_slice(&length.to_le_bytes());
    statement[40..].copy_from_slice(&digest);
    statement
}

pub const RELEASE_MANIFEST_BYTES: usize = 408;

#[derive(Clone, Copy)]
pub struct ReleaseManifest {
    release: u64,
    next_root_digest: [u8; 64],
    artifact_roots: [[u8; 64]; 5],
}

impl ReleaseManifest {
    pub fn new(
        release: u64,
        next_root_digest: [u8; 64],
        artifact_roots: [[u8; 64]; 5],
    ) -> Result<Self, ArtifactError> {
        if release == 0
            || next_root_digest.iter().all(|byte| *byte == 0)
            || artifact_roots
                .iter()
                .any(|root| root.iter().all(|byte| *byte == 0))
        {
            return Err(ArtifactError::MissingTrustRoot);
        }
        for (index, root) in artifact_roots.iter().enumerate() {
            if constant_time_equal(root, &next_root_digest)
                || artifact_roots[index + 1..]
                    .iter()
                    .any(|other| constant_time_equal(root, other))
            {
                return Err(ArtifactError::ReusedTrustRoot);
            }
        }
        Ok(Self {
            release,
            next_root_digest,
            artifact_roots,
        })
    }

    pub fn encode(self) -> [u8; RELEASE_MANIFEST_BYTES] {
        let mut output = [0u8; RELEASE_MANIFEST_BYTES];
        output[..16].copy_from_slice(b"MRML-RELEASE-v1\0");
        output[16..24].copy_from_slice(&self.release.to_le_bytes());
        output[24..88].copy_from_slice(&self.next_root_digest);
        for (index, root) in self.artifact_roots.iter().enumerate() {
            output[88 + index * 64..152 + index * 64].copy_from_slice(root);
        }
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ArtifactError> {
        if input.len() != RELEASE_MANIFEST_BYTES || &input[..16] != b"MRML-RELEASE-v1\0" {
            return Err(ArtifactError::MalformedManifest);
        }
        let release = u64::from_le_bytes(input[16..24].try_into().unwrap());
        let next_root_digest = input[24..88].try_into().unwrap();
        let artifact_roots = core::array::from_fn(|index| {
            input[88 + index * 64..152 + index * 64].try_into().unwrap()
        });
        Self::new(release, next_root_digest, artifact_roots)
    }
}

pub struct BootstrapState {
    current_root_digest: [u8; 64],
    minimum_release: u64,
    installed_manifest_digest: [u8; 64],
}

pub const BOOTSTRAP_STATE_BYTES: usize = 152;

/// Backend contract for TPM NV or an equivalently authenticated monotonic
/// store. Implementations must authenticate reads and make compare-and-store
/// atomic across power loss; ordinary files do not satisfy this contract.
pub trait MonotonicStateStore {
    fn load_authenticated(
        &self,
        output: &mut [u8; BOOTSTRAP_STATE_BYTES],
    ) -> Result<(), ArtifactError>;

    fn compare_and_store(
        &mut self,
        expected: &[u8; BOOTSTRAP_STATE_BYTES],
        replacement: &[u8; BOOTSTRAP_STATE_BYTES],
    ) -> Result<(), ArtifactError>;
}

impl BootstrapState {
    pub fn genesis(
        current_root_digest: [u8; 64],
        minimum_release: u64,
    ) -> Result<Self, ArtifactError> {
        if current_root_digest.iter().all(|byte| *byte == 0) || minimum_release == 0 {
            return Err(ArtifactError::MalformedBootstrapState);
        }
        Ok(Self {
            current_root_digest,
            minimum_release,
            installed_manifest_digest: [0; 64],
        })
    }

    pub fn verify_release(
        &self,
        encoded: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(VerifiedRelease, Self), ArtifactError> {
        let manifest = ReleaseManifest::decode(encoded)?;
        TrustRoot::new(
            ArtifactKind::LaunchPolicy,
            self.current_root_digest,
            self.minimum_release,
        )
        .verify(manifest.release, encoded, public_key, signature)?;
        if constant_time_equal(&manifest.next_root_digest, &self.current_root_digest)
            || manifest
                .artifact_roots
                .iter()
                .any(|root| constant_time_equal(root, &self.current_root_digest))
        {
            return Err(ArtifactError::ReusedTrustRoot);
        }
        let minimum_release = manifest
            .release
            .checked_add(1)
            .ok_or(ArtifactError::VersionExhausted)?;
        Ok((
            VerifiedRelease { manifest },
            Self {
                current_root_digest: manifest.next_root_digest,
                minimum_release,
                installed_manifest_digest: Sha3_512::digest(encoded),
            },
        ))
    }

    /// Reconstructs exact artifact authority for the already committed release
    /// without replaying its one-time manifest-key transition.
    pub fn admit_installed_release(
        &self,
        encoded: &[u8],
    ) -> Result<VerifiedRelease, ArtifactError> {
        if self.installed_manifest_digest.iter().all(|byte| *byte == 0)
            || !constant_time_equal(&self.installed_manifest_digest, &Sha3_512::digest(encoded))
        {
            return Err(ArtifactError::UnauthenticatedBootstrapState);
        }
        let manifest = ReleaseManifest::decode(encoded)?;
        if manifest.release.checked_add(1) != Some(self.minimum_release) {
            return Err(ArtifactError::ReleaseMismatch);
        }
        Ok(VerifiedRelease { manifest })
    }

    pub const fn minimum_release(&self) -> u64 {
        self.minimum_release
    }

    pub const fn current_root_digest(&self) -> [u8; 64] {
        self.current_root_digest
    }

    pub fn installed_manifest_digest(&self) -> Option<[u8; 64]> {
        if self.installed_manifest_digest == [0; 64] {
            None
        } else {
            Some(self.installed_manifest_digest)
        }
    }

    pub fn encode(self) -> [u8; BOOTSTRAP_STATE_BYTES] {
        let mut output = [0u8; BOOTSTRAP_STATE_BYTES];
        output[..16].copy_from_slice(b"MRML-BOOTSTATE1\0");
        output[16..24].copy_from_slice(&self.minimum_release.to_le_bytes());
        output[24..88].copy_from_slice(&self.current_root_digest);
        output[88..152].copy_from_slice(&self.installed_manifest_digest);
        output
    }

    /// Parses the canonical state bytes without asserting anything about their
    /// storage or provenance. The returned value is data, not boot authority.
    pub fn decode_canonical(input: &[u8]) -> Result<Self, ArtifactError> {
        if input.len() != BOOTSTRAP_STATE_BYTES
            || &input[..16] != b"MRML-BOOTSTATE1\0"
            || input[24..88].iter().all(|byte| *byte == 0)
        {
            return Err(ArtifactError::MalformedBootstrapState);
        }
        let minimum_release = u64::from_le_bytes(input[16..24].try_into().unwrap());
        if minimum_release == 0 {
            return Err(ArtifactError::MalformedBootstrapState);
        }
        Ok(Self {
            current_root_digest: input[24..88].try_into().unwrap(),
            minimum_release,
            installed_manifest_digest: input[88..152].try_into().unwrap(),
        })
    }

    /// Decodes bytes supplied by an independently authenticated monotonic
    /// store. Calling this function does not itself authenticate ordinary data.
    pub fn decode_authenticated(input: &[u8]) -> Result<Self, ArtifactError> {
        Self::decode_canonical(input)
    }

    pub fn verify_and_commit<S: MonotonicStateStore>(
        store: &mut S,
        encoded_manifest: &[u8],
        root_public_key: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedRelease, ArtifactError> {
        let mut encoded_state = [0u8; BOOTSTRAP_STATE_BYTES];
        store.load_authenticated(&mut encoded_state)?;
        let current = Self::decode_authenticated(&encoded_state)?;
        let (release, next) =
            current.verify_release(encoded_manifest, root_public_key, signature)?;
        store.compare_and_store(&encoded_state, &next.encode())?;
        Ok(release)
    }
}

pub struct VerifiedRelease {
    manifest: ReleaseManifest,
}

const BOOT_KERNEL_ADMITTED: u8 = 1;
const BOOT_SERVICE_ADMITTED: u8 = 1 << 1;
const BOOT_VM_ADMITTED: u8 = 1 << 2;
const BOOT_CUDA_ADMITTED: u8 = 1 << 3;
const BOOT_POLICY_ADMITTED: u8 = 1 << 4;
const REQUIRED_BOOT_ADMISSIONS: u8 = BOOT_KERNEL_ADMITTED
    | BOOT_SERVICE_ADMITTED
    | BOOT_VM_ADMITTED
    | BOOT_CUDA_ADMITTED
    | BOOT_POLICY_ADMITTED;

/// Typed release transaction that cannot publish a new manifest transition
/// until all five exact manifest artifacts have been admitted.
pub struct PendingBootRelease {
    release: VerifiedRelease,
    expected: [u8; BOOTSTRAP_STATE_BYTES],
    replacement: [u8; BOOTSTRAP_STATE_BYTES],
    manifest_digest: [u8; 64],
    admitted: u8,
    needs_publication: bool,
}

impl PendingBootRelease {
    pub fn installed(
        authenticated_state: [u8; BOOTSTRAP_STATE_BYTES],
        encoded_manifest: &[u8],
    ) -> Result<Self, ArtifactError> {
        let current = BootstrapState::decode_authenticated(&authenticated_state)?;
        let release = current.admit_installed_release(encoded_manifest)?;
        Ok(Self {
            release,
            expected: authenticated_state,
            replacement: authenticated_state,
            manifest_digest: Sha3_512::digest(encoded_manifest),
            admitted: 0,
            needs_publication: false,
        })
    }

    pub fn transition(
        authenticated_state: [u8; BOOTSTRAP_STATE_BYTES],
        encoded_manifest: &[u8],
        root_public_key: &[u8],
        signature: &[u8],
    ) -> Result<Self, ArtifactError> {
        let current = BootstrapState::decode_authenticated(&authenticated_state)?;
        let (release, next) =
            current.verify_release(encoded_manifest, root_public_key, signature)?;
        Ok(Self {
            release,
            expected: authenticated_state,
            replacement: next.encode(),
            manifest_digest: Sha3_512::digest(encoded_manifest),
            admitted: 0,
            needs_publication: true,
        })
    }

    pub fn verify_artifact(
        &mut self,
        artifact: &SignedArtifact<'_>,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedArtifact, ArtifactError> {
        let verified = self.release.verify_artifact(artifact, expected_kind)?;
        self.record_boot_kind(expected_kind);
        Ok(verified)
    }

    pub fn verify_executable<'a>(
        &mut self,
        artifact: &SignedArtifact<'a>,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedExecutable<'a>, ExecutableArtifactError> {
        let verified = self.release.verify_executable(artifact, expected_kind)?;
        self.record_boot_kind(expected_kind);
        Ok(verified)
    }

    pub fn publish<S: MonotonicStateStore>(&mut self, store: &mut S) -> Result<(), ArtifactError> {
        if self.admitted & REQUIRED_BOOT_ADMISSIONS != REQUIRED_BOOT_ADMISSIONS {
            return Err(ArtifactError::IncompleteReleaseAdmission);
        }
        if self.needs_publication {
            store.compare_and_store(&self.expected, &self.replacement)?;
            self.needs_publication = false;
        }
        self.expected.fill(0);
        self.replacement.fill(0);
        Ok(())
    }

    pub const fn release(&self) -> u64 {
        self.release.release()
    }

    pub const fn manifest_digest(&self) -> [u8; 64] {
        self.manifest_digest
    }

    pub const fn needs_publication(&self) -> bool {
        self.needs_publication
    }

    fn record_boot_kind(&mut self, kind: ArtifactKind) {
        self.admitted |= match kind {
            ArtifactKind::Kernel => BOOT_KERNEL_ADMITTED,
            ArtifactKind::ServiceImage => BOOT_SERVICE_ADMITTED,
            ArtifactKind::VmImage => BOOT_VM_ADMITTED,
            ArtifactKind::CudaKernelBundle => BOOT_CUDA_ADMITTED,
            ArtifactKind::LaunchPolicy => BOOT_POLICY_ADMITTED,
            ArtifactKind::ApplicationImage => 0,
        };
    }
}

impl Drop for PendingBootRelease {
    fn drop(&mut self) {
        self.expected.fill(0);
        self.replacement.fill(0);
    }
}

impl VerifiedRelease {
    fn trust_root(&self, kind: ArtifactKind) -> Result<TrustRoot, ArtifactError> {
        let digest = self
            .manifest
            .artifact_roots
            .get(kind as usize - 1)
            .copied()
            .ok_or(ArtifactError::MissingTrustRoot)?;
        Ok(TrustRoot::new(kind, digest, self.manifest.release))
    }

    /// Authenticates one artifact only when its signed version is exactly this
    /// release. A per-kind minimum-version root is never exposed to callers.
    pub fn verify_artifact(
        &self,
        artifact: &SignedArtifact<'_>,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedArtifact, ArtifactError> {
        if artifact.kind() != expected_kind {
            return Err(ArtifactError::WrongArtifactKind);
        }
        if artifact.version() != self.manifest.release {
            return Err(ArtifactError::ReleaseMismatch);
        }
        artifact.verify(&self.trust_root(expected_kind)?, expected_kind)
    }

    /// Applies exact-release authentication before interpreting executable
    /// payload bytes as PE metadata.
    pub fn verify_executable<'a>(
        &self,
        artifact: &SignedArtifact<'a>,
        expected_kind: ArtifactKind,
    ) -> Result<VerifiedExecutable<'a>, ExecutableArtifactError> {
        let maximum = executable_image_limit(expected_kind)
            .ok_or(ExecutableArtifactError::NonExecutableKind)?;
        let verified = self
            .verify_artifact(artifact, expected_kind)
            .map_err(ExecutableArtifactError::Signature)?;
        let image = PeImage::parse_with_limit(artifact.payload(), maximum)
            .map_err(ExecutableArtifactError::Format)?;
        Ok(VerifiedExecutable {
            artifact: verified,
            image,
        })
    }

    pub const fn release(&self) -> u64 {
        self.manifest.release
    }
}

fn constant_time_equal(left: &[u8; 64], right: &[u8; 64]) -> bool {
    let mut difference = 0;
    for index in 0..64 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{LAMPORT_PRIVATE_KEY_BYTES, lamport_public_key, lamport_sign};

    struct TestStateStore {
        state: [u8; BOOTSTRAP_STATE_BYTES],
        force_conflict: bool,
    }

    impl MonotonicStateStore for TestStateStore {
        fn load_authenticated(
            &self,
            output: &mut [u8; BOOTSTRAP_STATE_BYTES],
        ) -> Result<(), ArtifactError> {
            output.copy_from_slice(&self.state);
            Ok(())
        }

        fn compare_and_store(
            &mut self,
            expected: &[u8; BOOTSTRAP_STATE_BYTES],
            replacement: &[u8; BOOTSTRAP_STATE_BYTES],
        ) -> Result<(), ArtifactError> {
            if self.force_conflict || self.state != *expected {
                return Err(ArtifactError::StateConflict);
            }
            self.state.copy_from_slice(replacement);
            Ok(())
        }
    }

    fn signed_test_parts(
        kind: ArtifactKind,
        version: u64,
        payload: &[u8],
        seed: u8,
    ) -> (
        [u8; LAMPORT_PUBLIC_KEY_BYTES],
        [u8; LAMPORT_SIGNATURE_BYTES],
    ) {
        let private = [seed; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = [0; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        lamport_sign(
            &private,
            &artifact_statement(
                kind,
                version,
                payload.len() as u64,
                Sha3_512::digest(payload),
            ),
            &mut signature,
        )
        .unwrap();
        (public, signature)
    }

    #[test]
    fn trust_root_binds_kind_version_length_key_and_content() {
        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(73).wrapping_add(9) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let artifact = b"measured CUDA PTX bundle";
        let statement = artifact_statement(
            ArtifactKind::CudaKernelBundle,
            4,
            artifact.len() as u64,
            Sha3_512::digest(artifact),
        );
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let root = TrustRoot::new(ArtifactKind::CudaKernelBundle, Sha3_512::digest(&public), 4);
        assert!(root.verify(4, artifact, &public, &signature).is_ok());
        assert_eq!(
            root.verify(3, artifact, &public, &signature).err(),
            Some(ArtifactError::RollbackDetected)
        );
        assert_eq!(
            root.verify(4, b"changed", &public, &signature).err(),
            Some(ArtifactError::InvalidSignature)
        );
        let wrong_kind = TrustRoot::new(ArtifactKind::VmImage, Sha3_512::digest(&public), 4);
        assert_eq!(
            wrong_kind.verify(4, artifact, &public, &signature).err(),
            Some(ArtifactError::InvalidSignature)
        );
        public[0] ^= 1;
        assert_eq!(
            root.verify(4, artifact, &public, &signature).err(),
            Some(ArtifactError::UntrustedPublicKey)
        );
    }

    #[test]
    fn signed_release_rotates_root_and_rejects_replay() {
        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(29).wrapping_add(3) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let manifest =
            ReleaseManifest::new(7, [9; 64], [[1; 64], [2; 64], [3; 64], [4; 64], [5; 64]])
                .unwrap()
                .encode();
        let statement = artifact_statement(
            ArtifactKind::LaunchPolicy,
            7,
            manifest.len() as u64,
            Sha3_512::digest(&manifest),
        );
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let state = BootstrapState::genesis(Sha3_512::digest(&public), 7).unwrap();
        let (release, next) = state
            .verify_release(&manifest, &public, &signature)
            .unwrap();
        assert_eq!(release.release(), 7);
        assert_eq!(next.minimum_release(), 8);
        assert_eq!(
            next.installed_manifest_digest(),
            Some(Sha3_512::digest(&manifest))
        );
        assert_eq!(
            next.admit_installed_release(&manifest).unwrap().release(),
            7
        );
        let mut substituted_manifest = manifest;
        substituted_manifest[24] ^= 1;
        assert_eq!(
            next.admit_installed_release(&substituted_manifest).err(),
            Some(ArtifactError::UnauthenticatedBootstrapState)
        );
        assert_eq!(
            state.admit_installed_release(&manifest).err(),
            Some(ArtifactError::UnauthenticatedBootstrapState)
        );
        assert_eq!(
            next.verify_release(&manifest, &public, &signature).err(),
            Some(ArtifactError::RollbackDetected)
        );

        let mut store = TestStateStore {
            state: BootstrapState::genesis(Sha3_512::digest(&public), 7)
                .unwrap()
                .encode(),
            force_conflict: false,
        };
        let committed =
            BootstrapState::verify_and_commit(&mut store, &manifest, &public, &signature).unwrap();
        assert_eq!(committed.release(), 7);
        assert_eq!(
            BootstrapState::decode_authenticated(&store.state)
                .unwrap()
                .admit_installed_release(&manifest)
                .unwrap()
                .release(),
            7
        );
        assert_eq!(
            BootstrapState::decode_authenticated(&store.state)
                .unwrap()
                .minimum_release(),
            8
        );
        assert_eq!(
            BootstrapState::verify_and_commit(&mut store, &manifest, &public, &signature).err(),
            Some(ArtifactError::RollbackDetected)
        );
    }

    #[test]
    fn pending_boot_release_requires_complete_artifact_set_and_repeats_without_republication() {
        let mut transition_private = [0x19; LAMPORT_PRIVATE_KEY_BYTES];
        let mut transition_public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&transition_private, &mut transition_public).unwrap();

        let kernel_payload = b"kernel";
        let mut kernel_private = [0x2a; LAMPORT_PRIVATE_KEY_BYTES];
        let mut kernel_public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        let mut kernel_signature = [0; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&kernel_private, &mut kernel_public).unwrap();
        lamport_sign(
            &kernel_private,
            &artifact_statement(
                ArtifactKind::Kernel,
                7,
                kernel_payload.len() as u64,
                Sha3_512::digest(kernel_payload),
            ),
            &mut kernel_signature,
        )
        .unwrap();

        let vm_payload = b"vm";
        let (vm_public, vm_signature) =
            signed_test_parts(ArtifactKind::VmImage, 7, vm_payload, 0x4c);
        let cuda_payload = b"cuda";
        let (cuda_public, cuda_signature) =
            signed_test_parts(ArtifactKind::CudaKernelBundle, 7, cuda_payload, 0x5d);
        let policy_payload = b"policy";
        let (policy_public, policy_signature) =
            signed_test_parts(ArtifactKind::LaunchPolicy, 7, policy_payload, 0x6e);

        let service_payload = b"service";
        let mut service_private = [0x3b; LAMPORT_PRIVATE_KEY_BYTES];
        let mut service_public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        let mut service_signature = [0; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&service_private, &mut service_public).unwrap();
        lamport_sign(
            &service_private,
            &artifact_statement(
                ArtifactKind::ServiceImage,
                7,
                service_payload.len() as u64,
                Sha3_512::digest(service_payload),
            ),
            &mut service_signature,
        )
        .unwrap();

        let manifest = ReleaseManifest::new(
            7,
            [0x91; 64],
            [
                Sha3_512::digest(&kernel_public),
                Sha3_512::digest(&vm_public),
                Sha3_512::digest(&service_public),
                Sha3_512::digest(&cuda_public),
                Sha3_512::digest(&policy_public),
            ],
        )
        .unwrap()
        .encode();
        let mut transition_signature = [0; LAMPORT_SIGNATURE_BYTES];
        lamport_sign(
            &transition_private,
            &artifact_statement(
                ArtifactKind::LaunchPolicy,
                7,
                manifest.len() as u64,
                Sha3_512::digest(&manifest),
            ),
            &mut transition_signature,
        )
        .unwrap();
        transition_private.fill(0);
        kernel_private.fill(0);
        service_private.fill(0);

        let initial = BootstrapState::genesis(Sha3_512::digest(&transition_public), 7)
            .unwrap()
            .encode();
        let mut store = TestStateStore {
            state: initial,
            force_conflict: false,
        };
        let mut pending = PendingBootRelease::transition(
            initial,
            &manifest,
            &transition_public,
            &transition_signature,
        )
        .unwrap();
        assert_eq!(
            pending.publish(&mut store),
            Err(ArtifactError::IncompleteReleaseAdmission)
        );
        let kernel = SignedArtifact {
            kind: ArtifactKind::Kernel,
            version: 7,
            payload: kernel_payload,
            public_key: &kernel_public,
            signature: &kernel_signature,
        };
        pending
            .verify_artifact(&kernel, ArtifactKind::Kernel)
            .unwrap();
        assert_eq!(
            pending.publish(&mut store),
            Err(ArtifactError::IncompleteReleaseAdmission)
        );
        let service = SignedArtifact {
            kind: ArtifactKind::ServiceImage,
            version: 7,
            payload: service_payload,
            public_key: &service_public,
            signature: &service_signature,
        };
        pending
            .verify_artifact(&service, ArtifactKind::ServiceImage)
            .unwrap();
        assert_eq!(
            pending.publish(&mut store),
            Err(ArtifactError::IncompleteReleaseAdmission)
        );
        let vm = SignedArtifact {
            kind: ArtifactKind::VmImage,
            version: 7,
            payload: vm_payload,
            public_key: &vm_public,
            signature: &vm_signature,
        };
        let cuda = SignedArtifact {
            kind: ArtifactKind::CudaKernelBundle,
            version: 7,
            payload: cuda_payload,
            public_key: &cuda_public,
            signature: &cuda_signature,
        };
        let policy = SignedArtifact {
            kind: ArtifactKind::LaunchPolicy,
            version: 7,
            payload: policy_payload,
            public_key: &policy_public,
            signature: &policy_signature,
        };
        assert_eq!(
            pending
                .verify_artifact(&vm, ArtifactKind::CudaKernelBundle)
                .err(),
            Some(ArtifactError::WrongArtifactKind)
        );
        pending.verify_artifact(&vm, ArtifactKind::VmImage).unwrap();
        pending
            .verify_artifact(&cuda, ArtifactKind::CudaKernelBundle)
            .unwrap();
        assert_eq!(
            pending.publish(&mut store),
            Err(ArtifactError::IncompleteReleaseAdmission)
        );
        pending
            .verify_artifact(&policy, ArtifactKind::LaunchPolicy)
            .unwrap();
        store.force_conflict = true;
        assert_eq!(
            pending.publish(&mut store),
            Err(ArtifactError::StateConflict)
        );
        assert!(pending.needs_publication());
        store.force_conflict = false;
        pending.publish(&mut store).unwrap();
        assert!(!pending.needs_publication());

        let mut repeat = PendingBootRelease::installed(store.state, &manifest).unwrap();
        repeat
            .verify_artifact(&kernel, ArtifactKind::Kernel)
            .unwrap();
        repeat
            .verify_artifact(&service, ArtifactKind::ServiceImage)
            .unwrap();
        repeat.verify_artifact(&vm, ArtifactKind::VmImage).unwrap();
        repeat
            .verify_artifact(&cuda, ArtifactKind::CudaKernelBundle)
            .unwrap();
        repeat
            .verify_artifact(&policy, ArtifactKind::LaunchPolicy)
            .unwrap();
        store.force_conflict = true;
        repeat.publish(&mut store).unwrap();
    }

    #[test]
    fn release_manifest_rejects_every_one_time_root_collision() {
        let roots = [[1; 64], [2; 64], [3; 64], [4; 64], [5; 64]];
        assert_eq!(
            ReleaseManifest::new(7, roots[0], roots).err(),
            Some(ArtifactError::ReusedTrustRoot)
        );
        let mut duplicate = roots;
        duplicate[4] = duplicate[1];
        assert_eq!(
            ReleaseManifest::new(7, [9; 64], duplicate).err(),
            Some(ArtifactError::ReusedTrustRoot)
        );

        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(53).wrapping_add(11) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let current_root = Sha3_512::digest(&public);
        let manifest = ReleaseManifest::new(
            7,
            [9; 64],
            [current_root, [2; 64], [3; 64], [4; 64], [5; 64]],
        )
        .unwrap()
        .encode();
        let statement = artifact_statement(
            ArtifactKind::LaunchPolicy,
            7,
            manifest.len() as u64,
            Sha3_512::digest(&manifest),
        );
        lamport_sign(&private, &statement, &mut signature).unwrap();

        assert_eq!(
            BootstrapState::genesis(current_root, 7)
                .unwrap()
                .verify_release(&manifest, &public, &signature)
                .err(),
            Some(ArtifactError::ReusedTrustRoot)
        );
    }

    #[test]
    fn bootstrap_state_rejects_corruption_and_atomic_conflicts() {
        let root = [7; 64];
        let encoded = BootstrapState::genesis(root, 3).unwrap().encode();
        let decoded = BootstrapState::decode_authenticated(&encoded).unwrap();
        assert_eq!(decoded.minimum_release(), 3);
        assert_eq!(decoded.current_root_digest(), root);
        assert_eq!(decoded.installed_manifest_digest(), None);
        assert_eq!(
            BootstrapState::genesis([0; 64], 3).err(),
            Some(ArtifactError::MalformedBootstrapState)
        );
        assert_eq!(
            BootstrapState::genesis(root, 0).err(),
            Some(ArtifactError::MalformedBootstrapState)
        );

        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        assert_eq!(
            BootstrapState::decode_authenticated(&corrupt).err(),
            Some(ArtifactError::MalformedBootstrapState)
        );
        let mut zero_version = encoded;
        zero_version[16..24].fill(0);
        assert_eq!(
            BootstrapState::decode_authenticated(&zero_version).err(),
            Some(ArtifactError::MalformedBootstrapState)
        );

        let mut store = TestStateStore {
            state: encoded,
            force_conflict: true,
        };
        assert_eq!(
            store.compare_and_store(
                &encoded,
                &BootstrapState::genesis([8; 64], 4).unwrap().encode(),
            ),
            Err(ArtifactError::StateConflict)
        );
        assert_eq!(store.state, encoded);
        store.force_conflict = false;
        let substituted_root = BootstrapState::genesis([6; 64], 3).unwrap().encode();
        assert_eq!(
            store.compare_and_store(
                &substituted_root,
                &BootstrapState::genesis([8; 64], 4).unwrap().encode(),
            ),
            Err(ArtifactError::StateConflict)
        );
        assert_eq!(store.state, encoded);
    }

    #[test]
    fn signed_container_is_canonical_and_fail_closed() {
        const PAYLOAD: &[u8] = b"position-independent kernel image";
        const TOTAL: usize = SIGNED_ARTIFACT_HEADER_BYTES
            + LAMPORT_PUBLIC_KEY_BYTES
            + LAMPORT_SIGNATURE_BYTES
            + PAYLOAD.len();
        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(41).wrapping_add(17) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let digest = Sha3_512::digest(PAYLOAD);
        let statement = artifact_statement(ArtifactKind::Kernel, 9, PAYLOAD.len() as u64, digest);
        lamport_sign(&private, &statement, &mut signature).unwrap();

        let mut encoded = [0u8; TOTAL];
        encoded[..16].copy_from_slice(SIGNED_ARTIFACT_MAGIC);
        encoded[16] = ArtifactKind::Kernel as u8;
        encoded[24..32].copy_from_slice(&9u64.to_le_bytes());
        encoded[32..40].copy_from_slice(&(PAYLOAD.len() as u64).to_le_bytes());
        encoded[40..104].copy_from_slice(&digest);
        let key_end = SIGNED_ARTIFACT_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES;
        let signature_end = key_end + LAMPORT_SIGNATURE_BYTES;
        encoded[SIGNED_ARTIFACT_HEADER_BYTES..key_end].copy_from_slice(&public);
        encoded[key_end..signature_end].copy_from_slice(&signature);
        encoded[signature_end..].copy_from_slice(PAYLOAD);

        let root = TrustRoot::new(ArtifactKind::Kernel, Sha3_512::digest(&public), 9);
        let container = SignedArtifact::decode(&encoded).unwrap();
        assert_eq!(container.payload(), PAYLOAD);
        assert!(container.verify(&root, ArtifactKind::Kernel).is_ok());
        assert_eq!(
            container.verify(&root, ArtifactKind::VmImage).err(),
            Some(ArtifactError::WrongArtifactKind)
        );

        let artifact_roots = [
            Sha3_512::digest(&public),
            [2; 64],
            [3; 64],
            [4; 64],
            [5; 64],
        ];
        let exact_release = VerifiedRelease {
            manifest: ReleaseManifest::new(9, [0xa5; 64], artifact_roots).unwrap(),
        };
        let admitted = exact_release
            .verify_artifact(&container, ArtifactKind::Kernel)
            .unwrap();
        assert_eq!(admitted.kind(), ArtifactKind::Kernel);
        assert_eq!(admitted.version(), 9);
        for release in [8, 10] {
            let other_release = VerifiedRelease {
                manifest: ReleaseManifest::new(release, [0xa5; 64], artifact_roots).unwrap(),
            };
            assert_eq!(
                other_release
                    .verify_artifact(&container, ArtifactKind::Kernel)
                    .err(),
                Some(ArtifactError::ReleaseMismatch)
            );
            assert_eq!(
                other_release
                    .verify_executable(&container, ArtifactKind::Kernel)
                    .err(),
                Some(ExecutableArtifactError::Signature(
                    ArtifactError::ReleaseMismatch
                ))
            );
        }
        assert_eq!(
            exact_release
                .verify_artifact(&container, ArtifactKind::ServiceImage)
                .err(),
            Some(ArtifactError::WrongArtifactKind)
        );
        assert!(matches!(
            exact_release.verify_executable(&container, ArtifactKind::Kernel),
            Err(ExecutableArtifactError::Format(_))
        ));

        let mut trailing = [0u8; TOTAL + 1];
        trailing[..TOTAL].copy_from_slice(&encoded);
        assert_eq!(
            SignedArtifact::decode(&trailing).err(),
            Some(ArtifactError::MalformedContainer)
        );
        encoded[signature_end] ^= 1;
        assert_eq!(
            SignedArtifact::decode(&encoded).err(),
            Some(ArtifactError::MalformedContainer)
        );
    }

    #[test]
    fn application_image_has_independent_executable_kind_and_no_core_release_root() {
        let payload = b"application-image";
        let (public, signature) =
            signed_test_parts(ArtifactKind::ApplicationImage, 9, payload, 0x7f);
        let application = SignedArtifact {
            kind: ArtifactKind::ApplicationImage,
            version: 9,
            payload,
            public_key: &public,
            signature: &signature,
        };
        let root = TrustRoot::new(ArtifactKind::ApplicationImage, Sha3_512::digest(&public), 9);
        assert!(
            application
                .verify(&root, ArtifactKind::ApplicationImage)
                .is_ok()
        );
        assert_eq!(
            executable_image_limit(ArtifactKind::ApplicationImage),
            Some(MAX_APPLICATION_IMAGE_BYTES)
        );
        let release = VerifiedRelease {
            manifest: ReleaseManifest::new(
                9,
                [0xa5; 64],
                [[1; 64], [2; 64], [3; 64], [4; 64], [5; 64]],
            )
            .unwrap(),
        };
        assert_eq!(
            release
                .verify_artifact(&application, ArtifactKind::ApplicationImage)
                .err(),
            Some(ArtifactError::MissingTrustRoot)
        );
    }
}
