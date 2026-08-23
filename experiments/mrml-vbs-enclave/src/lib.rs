#![no_std]

#[cfg(target_os = "windows")]
use core::cell::UnsafeCell;
use core::ffi::c_void;
#[cfg(any(target_os = "windows", test))]
use mrml_crypto::hmac_sha256;
#[cfg(any(target_os = "windows", test))]
use mrml_kernel::{
    AUTHORITY_RECEIPT_BYTES, AuthorityReceipt, LAUNCH_REQUEST_BYTES, LaunchRequest,
    ProtectionBackend, ProtectionClaims, ProtectionPolicy, ProtectionReport, ProtectionSession,
    VBS_ATTESTATION_DATA_BYTES, VBS_RECEIPT_VERIFICATION_INPUT_BYTES, VBS_WORKLOAD_CHALLENGE_BYTES,
    VBS_WORKLOAD_RESULT_BYTES, VbsAttestationData,
};
#[cfg(target_os = "windows")]
use mrml_kernel::{
    UnverifiedVbsAttestationReport, VBS_ATTESTATION_CHALLENGE_BYTES,
    VBS_ATTESTATION_ENVELOPE_BYTES, VBS_ATTESTATION_REPORT_MAX_BYTES, VBS_AUTHORITY_CONTEXT_BYTES,
    VBS_SEALED_KEY_BLOB_MAX_BYTES, VBS_SEALED_KEY_CONFIRMATION_BYTES,
    VBS_SEALED_KEY_ENVELOPE_BYTES, VBS_WORKLOAD_SECRET_REQUEST_BYTES, VbsAttestationEnvelope,
    VbsAttestationExpectation, VbsAuthorityContext, VbsAuthorityOperation, VbsSealedKeyEnvelope,
};

#[cfg(test)]
const AUTHORITY_KEY: [u8; 32] = [0x39; 32];
#[cfg(any(target_os = "windows", test))]
const AUTHORITY_MEASUREMENT: [u8; 64] = [0x51; 64];
#[cfg(any(target_os = "windows", test))]
const AUTHORITY_SECURITY_VERSION: u64 = 1;

#[cfg(any(target_os = "windows", test))]
fn authority_policy() -> ProtectionPolicy {
    ProtectionPolicy::new(
        ProtectionBackend::VbsEnclave,
        ProtectionClaims::VTL0_ISOLATION
            .union(ProtectionClaims::MEASURED)
            .union(ProtectionClaims::SEALED_KEYS),
        false,
        AUTHORITY_SECURITY_VERSION,
        AUTHORITY_MEASUREMENT,
    )
}

#[cfg(any(target_os = "windows", test))]
fn erase_secret(secret: &mut [u8]) {
    for byte in secret {
        // SAFETY: `byte` is an exclusively borrowed valid byte. Volatile writes
        // make erasure observable to the abstract machine and resist removal.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(target_os = "windows")]
#[link(name = "vertdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn EnclaveCopyIntoEnclave(
        enclave_address: *mut c_void,
        untrusted_address: *const c_void,
        bytes: usize,
    ) -> i32;
    fn EnclaveCopyOutOfEnclave(
        untrusted_address: *mut c_void,
        enclave_address: *const c_void,
        bytes: usize,
    ) -> i32;
    fn EnclaveUsesAttestedKeys() -> u8;
    fn EnclaveGetAttestationReport(
        enclave_data: *const u8,
        report: *mut c_void,
        buffer_size: u32,
        output_size: *mut u32,
    ) -> i32;
    fn EnclaveGetEnclaveInformation(
        information_size: u32,
        enclave_information: *mut EnclaveInformation,
    ) -> i32;
    fn EnclaveVerifyAttestationReport(
        enclave_type: u32,
        report: *const c_void,
        report_size: u32,
    ) -> i32;
    fn EnclaveSealData(
        data: *const c_void,
        data_size: u32,
        identity_policy: u32,
        runtime_policy: u32,
        protected_blob: *mut c_void,
        buffer_size: u32,
        protected_blob_size: *mut u32,
    ) -> i32;
    fn EnclaveUnsealData(
        protected_blob: *const c_void,
        protected_blob_size: u32,
        decrypted_data: *mut c_void,
        buffer_size: u32,
        decrypted_data_size: *mut u32,
        sealing_identity: *mut c_void,
        unsealing_flags: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "bcrypt", kind = "raw-dylib")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, bytes: u32, flags: u32) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "vertdll", kind = "raw-dylib")]
#[allow(dead_code)]
unsafe extern "C" {
    #[link_name = "memcpy"]
    fn vertdll_memcpy(destination: *mut c_void, source: *const c_void, bytes: usize)
    -> *mut c_void;
    #[link_name = "memset"]
    fn vertdll_memset(destination: *mut c_void, value: i32, bytes: usize) -> *mut c_void;
    #[link_name = "memcmp"]
    fn vertdll_memcmp(left: *const c_void, right: *const c_void, bytes: usize) -> i32;
}

#[cfg(target_os = "windows")]
core::arch::global_asm!(
    r#"
    .section .rdata$mrmlcfg,"dr"
    .p2align 2
    .globl mrml_guard_function_table
mrml_guard_function_table:
    .rva DllMain
    .rva mrml_authority_probe
    .rva mrml_launch_authority
"#
);

#[cfg(target_os = "windows")]
unsafe extern "C" {
    static mrml_guard_function_table: u32;
}

const ENCLAVE_BYTES: u64 = 2 * 1024 * 1024;
const IMAGE_ENCLAVE_POLICY_STRICT_MEMORY: u32 = 2;
const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 1;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ImageEnclaveConfig64 {
    size: u32,
    minimum_required_config_size: u32,
    policy_flags: u32,
    number_of_imports: u32,
    import_list: u32,
    import_entry_size: u32,
    family_id: [u8; 16],
    image_id: [u8; 16],
    image_version: u32,
    security_version: u32,
    enclave_size: u64,
    number_of_threads: u32,
    enclave_flags: u32,
}

const _: () = assert!(core::mem::size_of::<ImageEnclaveConfig64>() == 80);

#[derive(Clone, Copy)]
#[repr(C)]
struct EnclaveInformation {
    enclave_type: u32,
    reserved: u32,
    base_address: *mut c_void,
    size: usize,
    identity: [u8; 152],
}

const _: () = assert!(core::mem::size_of::<EnclaveInformation>() == 176);
const _: () = assert!(core::mem::offset_of!(EnclaveInformation, identity) == 24);
#[cfg(target_os = "windows")]
const ENCLAVE_TYPE_VBS: u32 = 0x10;
#[cfg(target_os = "windows")]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
#[cfg(target_os = "windows")]
const ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE: u32 = 1;

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy)]
struct ChallengeState {
    binding: [u8; VBS_ATTESTATION_DATA_BYTES],
    pending: bool,
}

#[cfg(any(target_os = "windows", test))]
impl ChallengeState {
    const fn new() -> Self {
        Self {
            binding: [0; VBS_ATTESTATION_DATA_BYTES],
            pending: false,
        }
    }

    fn store(&mut self, binding: VbsAttestationData) -> Result<(), ()> {
        if self.pending {
            return Err(());
        }
        self.binding = binding.encode();
        self.pending = true;
        Ok(())
    }

    fn take(&mut self) -> Result<VbsAttestationData, ()> {
        if !self.pending {
            return Err(());
        }
        let binding = VbsAttestationData::decode(&self.binding).map_err(|_| ())?;
        self.binding.fill(0);
        self.pending = false;
        Ok(binding)
    }
}

#[cfg(target_os = "windows")]
struct ChallengeCell(UnsafeCell<ChallengeState>);

// SAFETY: the enclave configuration creates exactly one execution thread, so
// exported calls cannot concurrently access this cell. The state is never
// exposed outside VTL1 and every successful verification consumes it once.
#[cfg(target_os = "windows")]
unsafe impl Sync for ChallengeCell {}

#[cfg(target_os = "windows")]
static CHALLENGE_STATE: ChallengeCell = ChallengeCell(UnsafeCell::new(ChallengeState::new()));

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy)]
struct AuthorityKeyState {
    key: [u8; 32],
    loaded: bool,
}

#[cfg(any(target_os = "windows", test))]
impl AuthorityKeyState {
    const fn new() -> Self {
        Self {
            key: [0; 32],
            loaded: false,
        }
    }

    fn install(&mut self, key: [u8; 32]) -> Result<(), ()> {
        if self.loaded || key == [0; 32] {
            return Err(());
        }
        self.key = key;
        self.loaded = true;
        Ok(())
    }

    fn get(&self) -> Result<[u8; 32], ()> {
        self.loaded.then_some(self.key).ok_or(())
    }
}

#[cfg(target_os = "windows")]
struct AuthorityKeyCell(UnsafeCell<AuthorityKeyState>);

// SAFETY: the signed enclave configuration permits one execution thread.
#[cfg(target_os = "windows")]
unsafe impl Sync for AuthorityKeyCell {}

#[cfg(target_os = "windows")]
static AUTHORITY_KEY_STATE: AuthorityKeyCell =
    AuthorityKeyCell(UnsafeCell::new(AuthorityKeyState::new()));

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy)]
struct SecretReleaseState {
    receipt_binding: [u8; VBS_ATTESTATION_DATA_BYTES],
    attestation_binding: [u8; VBS_ATTESTATION_DATA_BYTES],
    receipt_verified: bool,
    attestation_verified: bool,
}

#[cfg(any(target_os = "windows", test))]
impl SecretReleaseState {
    const fn new() -> Self {
        Self {
            receipt_binding: [0; VBS_ATTESTATION_DATA_BYTES],
            attestation_binding: [0; VBS_ATTESTATION_DATA_BYTES],
            receipt_verified: false,
            attestation_verified: false,
        }
    }

    fn record_receipt(&mut self, binding: VbsAttestationData) -> Result<(), ()> {
        if self.receipt_verified {
            return Err(());
        }
        self.receipt_binding = binding.encode();
        self.receipt_verified = true;
        Ok(())
    }

    fn record_attestation(&mut self, binding: VbsAttestationData) -> Result<(), ()> {
        if self.attestation_verified {
            return Err(());
        }
        self.attestation_binding = binding.encode();
        self.attestation_verified = true;
        Ok(())
    }

    fn consume(&mut self, expected: VbsAttestationData) -> Result<(), ()> {
        if !self.receipt_verified
            || !self.attestation_verified
            || self.receipt_binding != expected.encode()
            || self.attestation_binding != expected.encode()
        {
            return Err(());
        }
        self.receipt_binding.fill(0);
        self.attestation_binding.fill(0);
        self.receipt_verified = false;
        self.attestation_verified = false;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
struct SecretReleaseCell(UnsafeCell<SecretReleaseState>);

#[cfg(target_os = "windows")]
unsafe impl Sync for SecretReleaseCell {}

#[cfg(target_os = "windows")]
static SECRET_RELEASE_STATE: SecretReleaseCell =
    SecretReleaseCell(UnsafeCell::new(SecretReleaseState::new()));

#[unsafe(no_mangle)]
pub static __enclave_config: ImageEnclaveConfig64 = ImageEnclaveConfig64 {
    size: 80,
    minimum_required_config_size: 80,
    policy_flags: IMAGE_ENCLAVE_POLICY_STRICT_MEMORY,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: *b"MRML-VBS-FAMILY!",
    image_id: *b"MRML-AUTHORITY!!",
    image_version: 1,
    security_version: 1,
    enclave_size: ENCLAVE_BYTES,
    number_of_threads: 1,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

#[derive(Clone, Copy)]
#[repr(C)]
struct ImageLoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalog_offset: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ImageLoadConfigDirectory64 {
    size: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_timeout: u32,
    decommit_free_block_threshold: u64,
    decommit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check: u64,
    guard_cf_dispatch: u64,
    guard_cf_function_table: *const u32,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_table: u64,
    guard_address_taken_iat_count: u64,
    guard_long_jump_table: u64,
    guard_long_jump_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: *const ImageEnclaveConfig64,
}

unsafe impl Sync for ImageLoadConfigDirectory64 {}

const _: () = assert!(core::mem::size_of::<ImageLoadConfigDirectory64>() == 256);
const _: () = assert!(
    core::mem::offset_of!(ImageLoadConfigDirectory64, enclave_configuration_pointer) == 248
);

#[used]
#[unsafe(no_mangle)]
static _load_config_used: ImageLoadConfigDirectory64 = ImageLoadConfigDirectory64 {
    size: 256,
    timestamp: 0,
    major_version: 0,
    minor_version: 0,
    global_flags_clear: 0,
    global_flags_set: 0,
    critical_section_timeout: 0,
    decommit_free_block_threshold: 0,
    decommit_total_free_threshold: 0,
    lock_prefix_table: 0,
    maximum_allocation_size: 0,
    virtual_memory_threshold: 0,
    process_affinity_mask: 0,
    process_heap_flags: 0,
    csd_version: 0,
    dependent_load_flags: 0,
    edit_list: 0,
    security_cookie: 0,
    se_handler_table: 0,
    se_handler_count: 0,
    guard_cf_check: 0,
    guard_cf_dispatch: 0,
    #[cfg(target_os = "windows")]
    guard_cf_function_table: core::ptr::addr_of!(mrml_guard_function_table),
    #[cfg(not(target_os = "windows"))]
    guard_cf_function_table: core::ptr::null(),
    guard_cf_function_count: 3,
    // The image publishes a sorted valid-call-target table and deliberately
    // does not claim compiler CFG instrumentation while the dispatch/check
    // pointers above remain absent.
    guard_flags: 0x0000_0400 | 0x0000_0800,
    code_integrity: ImageLoadConfigCodeIntegrity {
        flags: 0,
        catalog: 0,
        catalog_offset: 0,
        reserved: 0,
    },
    guard_address_taken_iat_table: 0,
    guard_address_taken_iat_count: 0,
    guard_long_jump_table: 0,
    guard_long_jump_count: 0,
    dynamic_value_reloc_table: 0,
    chpe_metadata: 0,
    guard_rf_failure_routine: 0,
    guard_rf_failure_routine_pointer: 0,
    dynamic_value_reloc_table_offset: 0,
    dynamic_value_reloc_table_section: 0,
    reserved2: 0,
    guard_rf_verify_stack_pointer: 0,
    hot_patch_table_offset: 0,
    reserved3: 0,
    enclave_configuration_pointer: core::ptr::from_ref(&__enclave_config),
};

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: *mut c_void, _: u32, _: *mut c_void) -> i32 {
    1
}

/// Minimal call-boundary proof. It never dereferences host memory; strict-memory
/// authority messages will use explicit enclave copy APIs in the next stage.
#[unsafe(no_mangle)]
pub extern "system" fn mrml_authority_probe(context: *mut c_void) -> *mut c_void {
    ((context as usize) ^ 0x4d52_4d4c) as *mut c_void
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
#[cfg(target_os = "windows")]
enum AuthorityStatus {
    Success = 0,
    ContextCopyFailed = 1,
    InvalidContext = 2,
    RequestCopyFailed = 3,
    RequestRejected = 4,
    ReceiptCopyFailed = 5,
    UnsafeKeyPlatform = 6,
    AttestationFailed = 7,
    AttestationCopyFailed = 8,
    EnclaveInformationFailed = 9,
    PointerAliasesEnclave = 10,
    ChallengeGenerationFailed = 11,
    ChallengePending = 12,
    ChallengeMissing = 13,
    AttestationVerificationFailed = 14,
    AttestationIdentityRejected = 15,
    KeySealFailed = 16,
    KeyLoadFailed = 17,
    KeyAlreadyLoaded = 18,
    SecretReleaseDenied = 19,
    SecretConsumeFailed = 20,
}

#[cfg(target_os = "windows")]
fn current_enclave_range() -> Result<(usize, usize), AuthorityStatus> {
    let mut information = EnclaveInformation {
        enclave_type: 0,
        reserved: 0,
        base_address: core::ptr::null_mut(),
        size: 0,
        identity: [0; 152],
    };
    // SAFETY: the output structure is enclave-local, correctly sized, aligned,
    // exclusively borrowed, and fully initialized before the platform writes it.
    if unsafe {
        EnclaveGetEnclaveInformation(
            core::mem::size_of::<EnclaveInformation>() as u32,
            &mut information,
        )
    } != 0
        || information.enclave_type != ENCLAVE_TYPE_VBS
        || information.reserved != 0
        || information.base_address.is_null()
        || information.size == 0
    {
        return Err(AuthorityStatus::EnclaveInformationFailed);
    }
    let start = information.base_address as usize;
    let end = start
        .checked_add(information.size)
        .ok_or(AuthorityStatus::EnclaveInformationFailed)?;
    Ok((start, end))
}

#[cfg(target_os = "windows")]
fn current_identity_expectation() -> Result<VbsAttestationExpectation, AuthorityStatus> {
    let mut information = EnclaveInformation {
        enclave_type: 0,
        reserved: 0,
        base_address: core::ptr::null_mut(),
        size: 0,
        identity: [0; 152],
    };
    // SAFETY: the destination is enclave-local and has the exact documented ABI.
    if unsafe {
        EnclaveGetEnclaveInformation(
            core::mem::size_of::<EnclaveInformation>() as u32,
            &mut information,
        )
    } != 0
        || information.enclave_type != ENCLAVE_TYPE_VBS
        || information.reserved != 0
    {
        return Err(AuthorityStatus::EnclaveInformationFailed);
    }
    let identity = &information.identity;
    let owner_id = identity[..32]
        .try_into()
        .map_err(|_| AuthorityStatus::EnclaveInformationFailed)?;
    let unique_id = identity[32..64]
        .try_into()
        .map_err(|_| AuthorityStatus::EnclaveInformationFailed)?;
    let author_id = identity[64..96]
        .try_into()
        .map_err(|_| AuthorityStatus::EnclaveInformationFailed)?;
    let family_id = identity[96..112]
        .try_into()
        .map_err(|_| AuthorityStatus::EnclaveInformationFailed)?;
    let image_id = identity[112..128]
        .try_into()
        .map_err(|_| AuthorityStatus::EnclaveInformationFailed)?;
    let read_version = |offset: usize| {
        u32::from_le_bytes(identity[offset..offset + 4].try_into().unwrap_or([0; 4]))
    };
    VbsAttestationExpectation::new(
        owner_id,
        unique_id,
        author_id,
        family_id,
        image_id,
        read_version(128),
        read_version(132),
        read_version(136),
    )
    .map_err(|_| AuthorityStatus::EnclaveInformationFailed)
}

#[cfg(target_os = "windows")]
fn generate_challenge(
    seed: LaunchRequest,
) -> Result<[u8; VBS_ATTESTATION_CHALLENGE_BYTES], AuthorityStatus> {
    let mut nonce = [0; VBS_ATTESTATION_CHALLENGE_BYTES];
    // SAFETY: the buffer is enclave-local, exact-sized, and exclusively borrowed.
    if unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
        || nonce == [0; VBS_ATTESTATION_CHALLENGE_BYTES]
    {
        return Err(AuthorityStatus::ChallengeGenerationFailed);
    }
    let request = LaunchRequest::new(
        seed.sequence(),
        nonce,
        seed.image_measurement(),
        authority_policy().commitment(),
    )
    .map_err(|_| AuthorityStatus::ChallengeGenerationFailed)?;
    let binding = VbsAttestationData::for_launch_request(nonce, request, authority_policy())
        .map_err(|_| AuthorityStatus::ChallengeGenerationFailed)?;
    // SAFETY: the image declares one enclave thread, preventing concurrent access.
    unsafe { &mut *CHALLENGE_STATE.0.get() }
        .store(binding)
        .map_err(|_| AuthorityStatus::ChallengePending)?;
    Ok(nonce)
}

#[cfg(target_os = "windows")]
fn take_challenge() -> Result<VbsAttestationData, AuthorityStatus> {
    // SAFETY: the image declares one enclave thread, preventing concurrent access.
    unsafe { &mut *CHALLENGE_STATE.0.get() }
        .take()
        .map_err(|_| AuthorityStatus::ChallengeMissing)
}

#[cfg(any(target_os = "windows", test))]
fn range_is_outside_enclave(
    address: usize,
    bytes: usize,
    enclave_start: usize,
    enclave_end: usize,
) -> bool {
    bytes != 0
        && enclave_start < enclave_end
        && address
            .checked_add(bytes)
            .is_some_and(|end| end <= enclave_start || address >= enclave_end)
}

#[cfg(any(target_os = "windows", test))]
fn approved_request(encoded_request: &[u8; LAUNCH_REQUEST_BYTES]) -> Result<LaunchRequest, ()> {
    let request = LaunchRequest::decode(encoded_request).map_err(|_| ())?;
    if request.image_measurement() != AUTHORITY_MEASUREMENT
        || request.policy_measurement() != authority_policy().commitment()
    {
        return Err(());
    }
    Ok(request)
}

#[cfg(any(target_os = "windows", test))]
fn process_authority_request(
    encoded_request: &[u8; LAUNCH_REQUEST_BYTES],
    uses_attested_keys: bool,
    authority_key: &[u8; 32],
) -> Result<[u8; AUTHORITY_RECEIPT_BYTES], ()> {
    if !uses_attested_keys {
        return Err(());
    }
    let request = approved_request(encoded_request)?;
    let claims = ProtectionClaims::VTL0_ISOLATION
        .union(ProtectionClaims::MEASURED)
        .union(ProtectionClaims::SEALED_KEYS);
    let report = ProtectionReport::new(
        ProtectionBackend::VbsEnclave,
        claims,
        false,
        AUTHORITY_SECURITY_VERSION,
        request.sequence(),
        request.image_measurement(),
        request.nonce(),
    )
    .map_err(|_| ())?;
    AuthorityReceipt::seal(authority_key, request, report).map_err(|_| ())
}

#[cfg(any(target_os = "windows", test))]
fn verify_authority_receipt(
    input: &[u8; VBS_RECEIPT_VERIFICATION_INPUT_BYTES],
    authority_key: &[u8; 32],
) -> Result<(), ()> {
    let request = LaunchRequest::decode(&input[..LAUNCH_REQUEST_BYTES]).map_err(|_| ())?;
    approved_request(&request.encode())?;
    let mut session = ProtectionSession::new(request.nonce()).map_err(|_| ())?;
    AuthorityReceipt::verify_and_admit(
        authority_key,
        request,
        &input[LAUNCH_REQUEST_BYTES..],
        authority_policy().commitment(),
        &mut session,
        authority_policy(),
    )
    .map(|_| ())
    .map_err(|_| ())
}

#[cfg(any(target_os = "windows", test))]
fn consume_workload_secret(
    secret: &mut [u8; 32],
    request: LaunchRequest,
    challenge: &[u8; VBS_WORKLOAD_CHALLENGE_BYTES],
) -> Result<[u8; VBS_WORKLOAD_RESULT_BYTES], ()> {
    if *secret == [0; 32] || *challenge == [0; VBS_WORKLOAD_CHALLENGE_BYTES] {
        erase_secret(secret);
        return Err(());
    }
    let request_bytes = request.encode();
    let result = hmac_sha256(
        secret,
        &[
            b"MRML-VBS-WORKLOAD-SECRET-CONSUME-v1\0",
            &request_bytes,
            challenge,
        ],
    );
    erase_secret(secret);
    Ok(result)
}

#[cfg(target_os = "windows")]
fn generate_sealed_secret()
-> Result<([u8; 32], [u8; VBS_SEALED_KEY_ENVELOPE_BYTES]), AuthorityStatus> {
    let mut secret = [0; 32];
    if unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            secret.as_mut_ptr(),
            secret.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
        || secret == [0; 32]
    {
        return Err(AuthorityStatus::KeySealFailed);
    }
    let mut envelope = [0; VBS_SEALED_KEY_ENVELOPE_BYTES];
    let mut blob_bytes = 0u32;
    // Exact-code sealing plus runtime policy zero forbids debug unsealing.
    if unsafe {
        EnclaveSealData(
            secret.as_ptr().cast(),
            secret.len() as u32,
            ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE,
            0,
            envelope[8..].as_mut_ptr().cast(),
            VBS_SEALED_KEY_BLOB_MAX_BYTES as u32,
            &mut blob_bytes,
        )
    } != 0
        || blob_bytes == 0
        || blob_bytes as usize > VBS_SEALED_KEY_BLOB_MAX_BYTES
    {
        erase_secret(&mut secret);
        return Err(AuthorityStatus::KeySealFailed);
    }
    envelope[..8].copy_from_slice(&(blob_bytes as u64).to_le_bytes());
    Ok((secret, envelope))
}

/// Strict-memory VTL1 authority entry. The host context and its buffers are
/// never dereferenced directly; Vertdll performs both boundary copies.
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub extern "system" fn mrml_launch_authority(context: *mut c_void) -> *mut c_void {
    let enclave_range = match current_enclave_range() {
        Ok(range) => range,
        Err(status) => return status as usize as *mut c_void,
    };
    if !range_is_outside_enclave(
        context as usize,
        VBS_AUTHORITY_CONTEXT_BYTES,
        enclave_range.0,
        enclave_range.1,
    ) {
        return AuthorityStatus::PointerAliasesEnclave as usize as *mut c_void;
    }
    let mut encoded_context = [0; VBS_AUTHORITY_CONTEXT_BYTES];
    // SAFETY: `encoded_context` is enclave-local writable memory. Vertdll validates and
    // copies from the untrusted pointer without direct enclave dereference.
    if unsafe {
        EnclaveCopyIntoEnclave(
            encoded_context.as_mut_ptr().cast(),
            context.cast_const(),
            encoded_context.len(),
        )
    } != 0
    {
        return AuthorityStatus::ContextCopyFailed as usize as *mut c_void;
    }
    let Ok(call) = VbsAuthorityContext::decode(&encoded_context) else {
        return AuthorityStatus::InvalidContext as usize as *mut c_void;
    };
    match call.operation() {
        VbsAuthorityOperation::IssueReceipt
            if call.input_bytes() == LAUNCH_REQUEST_BYTES as u64
                && call.output_bytes() == AUTHORITY_RECEIPT_BYTES as u64 => {}
        VbsAuthorityOperation::IssueAttestationReport
            if call.input_bytes() == LAUNCH_REQUEST_BYTES as u64
                && call.output_bytes() == VBS_ATTESTATION_ENVELOPE_BYTES as u64 => {}
        VbsAuthorityOperation::GenerateAttestationChallenge
            if call.input_bytes() == LAUNCH_REQUEST_BYTES as u64
                && call.output_bytes() == VBS_ATTESTATION_CHALLENGE_BYTES as u64 => {}
        VbsAuthorityOperation::VerifyAttestationReport
            if call.input_bytes() == VBS_ATTESTATION_ENVELOPE_BYTES as u64
                && call.output_bytes() == VBS_ATTESTATION_DATA_BYTES as u64 => {}
        VbsAuthorityOperation::GenerateSealedKey
            if call.input_bytes() == LAUNCH_REQUEST_BYTES as u64
                && call.output_bytes() == VBS_SEALED_KEY_ENVELOPE_BYTES as u64 => {}
        VbsAuthorityOperation::LoadSealedKey
            if call.input_bytes() == VBS_SEALED_KEY_ENVELOPE_BYTES as u64
                && call.output_bytes() == VBS_SEALED_KEY_CONFIRMATION_BYTES as u64 => {}
        VbsAuthorityOperation::VerifyReceipt
            if call.input_bytes() == VBS_RECEIPT_VERIFICATION_INPUT_BYTES as u64
                && call.output_bytes() == VBS_SEALED_KEY_CONFIRMATION_BYTES as u64 => {}
        VbsAuthorityOperation::GenerateWorkloadSecret
            if call.input_bytes() == LAUNCH_REQUEST_BYTES as u64
                && call.output_bytes() == VBS_SEALED_KEY_ENVELOPE_BYTES as u64 => {}
        VbsAuthorityOperation::ConsumeWorkloadSecret
            if call.input_bytes() == VBS_WORKLOAD_SECRET_REQUEST_BYTES as u64
                && call.output_bytes() == VBS_WORKLOAD_RESULT_BYTES as u64 => {}
        _ => return AuthorityStatus::InvalidContext as usize as *mut c_void,
    }
    let (Ok(request_address), Ok(receipt_address)) = (
        usize::try_from(call.input_address()),
        usize::try_from(call.output_address()),
    ) else {
        return AuthorityStatus::InvalidContext as usize as *mut c_void;
    };
    if !range_is_outside_enclave(
        request_address,
        call.input_bytes() as usize,
        enclave_range.0,
        enclave_range.1,
    ) || !range_is_outside_enclave(
        receipt_address,
        call.output_bytes() as usize,
        enclave_range.0,
        enclave_range.1,
    ) {
        return AuthorityStatus::PointerAliasesEnclave as usize as *mut c_void;
    }
    // SAFETY: this zero-argument Vertdll query is available only inside a VBS
    // enclave and returns a Windows BOOLEAN. False means all protected operations
    // fail closed because debugger or TPM key-provisioning guarantees are absent.
    if unsafe { EnclaveUsesAttestedKeys() } == 0 {
        return AuthorityStatus::UnsafeKeyPlatform as usize as *mut c_void;
    }
    if call.operation() == VbsAuthorityOperation::VerifyAttestationReport {
        let mut encoded_envelope = [0; VBS_ATTESTATION_ENVELOPE_BYTES];
        // SAFETY: destination is enclave-local and exact-sized; source was proven
        // wholly outside this enclave and is copied only through Vertdll.
        if unsafe {
            EnclaveCopyIntoEnclave(
                encoded_envelope.as_mut_ptr().cast(),
                (request_address as *const u8).cast(),
                encoded_envelope.len(),
            )
        } != 0
        {
            return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
        }
        let envelope = match VbsAttestationEnvelope::decode(&encoded_envelope) {
            Ok(envelope) => envelope,
            Err(_) => {
                return AuthorityStatus::AttestationVerificationFailed as usize as *mut c_void;
            }
        };
        let expected_binding = match take_challenge() {
            Ok(binding) => binding,
            Err(status) => return status as usize as *mut c_void,
        };
        // SAFETY: the report is an immutable enclave-local copy with a bounded u32
        // length. Windows verifies that it was generated on this VBS system.
        if unsafe {
            EnclaveVerifyAttestationReport(
                ENCLAVE_TYPE_VBS,
                envelope.report().as_ptr().cast(),
                envelope.report().len() as u32,
            )
        } != 0
        {
            return AuthorityStatus::AttestationVerificationFailed as usize as *mut c_void;
        }
        let expected_identity = match current_identity_expectation() {
            Ok(identity) => identity,
            Err(status) => return status as usize as *mut c_void,
        };
        let parsed = match UnverifiedVbsAttestationReport::parse(envelope.report()) {
            Ok(parsed) => parsed,
            Err(_) => return AuthorityStatus::AttestationIdentityRejected as usize as *mut c_void,
        };
        if parsed
            .matches_expectation(expected_binding, expected_identity)
            .is_err()
        {
            return AuthorityStatus::AttestationIdentityRejected as usize as *mut c_void;
        }
        // SAFETY: the signed image declares exactly one enclave thread.
        if unsafe { &mut *SECRET_RELEASE_STATE.0.get() }
            .record_attestation(expected_binding)
            .is_err()
        {
            return AuthorityStatus::SecretReleaseDenied as usize as *mut c_void;
        }
        let verified_binding = expected_binding.encode();
        // SAFETY: source is enclave-local and destination was proven entirely outside.
        if unsafe {
            EnclaveCopyOutOfEnclave(
                (receipt_address as *mut u8).cast(),
                verified_binding.as_ptr().cast(),
                verified_binding.len(),
            )
        } != 0
        {
            return AuthorityStatus::AttestationCopyFailed as usize as *mut c_void;
        }
        return AuthorityStatus::Success as usize as *mut c_void;
    }

    if call.operation() == VbsAuthorityOperation::LoadSealedKey {
        let mut encoded = [0; VBS_SEALED_KEY_ENVELOPE_BYTES];
        // SAFETY: destination is enclave-local and exact-sized; source is outside.
        if unsafe {
            EnclaveCopyIntoEnclave(
                encoded.as_mut_ptr().cast(),
                (request_address as *const u8).cast(),
                encoded.len(),
            )
        } != 0
        {
            return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
        }
        let envelope = match VbsSealedKeyEnvelope::decode(&encoded) {
            Ok(envelope) => envelope,
            Err(_) => return AuthorityStatus::KeyLoadFailed as usize as *mut c_void,
        };
        let mut key = [0; 32];
        let mut key_bytes = 0u32;
        let mut flags = 0u32;
        // SAFETY: the opaque blob and all outputs are enclave-local and bounded.
        if unsafe {
            EnclaveUnsealData(
                envelope.blob().as_ptr().cast(),
                envelope.blob().len() as u32,
                key.as_mut_ptr().cast(),
                key.len() as u32,
                &mut key_bytes,
                core::ptr::null_mut(),
                &mut flags,
            )
        } != 0
            || key_bytes != key.len() as u32
            || flags != 0
        {
            erase_secret(&mut key);
            return AuthorityStatus::KeyLoadFailed as usize as *mut c_void;
        }
        // SAFETY: the signed image declares exactly one enclave thread.
        if unsafe { &mut *AUTHORITY_KEY_STATE.0.get() }
            .install(key)
            .is_err()
        {
            erase_secret(&mut key);
            return AuthorityStatus::KeyAlreadyLoaded as usize as *mut c_void;
        }
        erase_secret(&mut key);
        let confirmation = [0xa5; VBS_SEALED_KEY_CONFIRMATION_BYTES];
        // The marker is diagnostic only; successful status plus VTL1-held state
        // carries the security meaning, never these host-visible bytes.
        if unsafe {
            EnclaveCopyOutOfEnclave(
                (receipt_address as *mut u8).cast(),
                confirmation.as_ptr().cast(),
                confirmation.len(),
            )
        } != 0
        {
            return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
        }
        return AuthorityStatus::Success as usize as *mut c_void;
    }

    if call.operation() == VbsAuthorityOperation::VerifyReceipt {
        let mut input = [0; VBS_RECEIPT_VERIFICATION_INPUT_BYTES];
        // SAFETY: destination is enclave-local and source was proven outside.
        if unsafe {
            EnclaveCopyIntoEnclave(
                input.as_mut_ptr().cast(),
                (request_address as *const u8).cast(),
                input.len(),
            )
        } != 0
        {
            return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
        }
        // SAFETY: the signed image declares exactly one enclave thread.
        let mut key = match unsafe { &*AUTHORITY_KEY_STATE.0.get() }.get() {
            Ok(key) => key,
            Err(()) => return AuthorityStatus::KeyLoadFailed as usize as *mut c_void,
        };
        let verified = verify_authority_receipt(&input, &key);
        erase_secret(&mut key);
        if verified.is_err() {
            return AuthorityStatus::RequestRejected as usize as *mut c_void;
        }
        let request = match LaunchRequest::decode(&input[..LAUNCH_REQUEST_BYTES]) {
            Ok(request) => request,
            Err(_) => return AuthorityStatus::RequestRejected as usize as *mut c_void,
        };
        let binding = match VbsAttestationData::for_launch_request(
            request.nonce(),
            request,
            authority_policy(),
        ) {
            Ok(binding) => binding,
            Err(_) => return AuthorityStatus::RequestRejected as usize as *mut c_void,
        };
        // SAFETY: the signed image declares exactly one enclave thread.
        if unsafe { &mut *SECRET_RELEASE_STATE.0.get() }
            .record_receipt(binding)
            .is_err()
        {
            return AuthorityStatus::SecretReleaseDenied as usize as *mut c_void;
        }
        let confirmation = [0x5a; VBS_SEALED_KEY_CONFIRMATION_BYTES];
        if unsafe {
            EnclaveCopyOutOfEnclave(
                (receipt_address as *mut u8).cast(),
                confirmation.as_ptr().cast(),
                confirmation.len(),
            )
        } != 0
        {
            return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
        }
        return AuthorityStatus::Success as usize as *mut c_void;
    }

    if call.operation() == VbsAuthorityOperation::ConsumeWorkloadSecret {
        let mut input = [0; VBS_WORKLOAD_SECRET_REQUEST_BYTES];
        // SAFETY: destination is enclave-local and source was proven outside.
        if unsafe {
            EnclaveCopyIntoEnclave(
                input.as_mut_ptr().cast(),
                (request_address as *const u8).cast(),
                input.len(),
            )
        } != 0
        {
            return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
        }
        let request = match LaunchRequest::decode(&input[..LAUNCH_REQUEST_BYTES]) {
            Ok(request) => request,
            Err(_) => return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void,
        };
        if approved_request(&request.encode()).is_err() {
            return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void;
        }
        let envelope_end = LAUNCH_REQUEST_BYTES + VBS_SEALED_KEY_ENVELOPE_BYTES;
        let envelope =
            match VbsSealedKeyEnvelope::decode(&input[LAUNCH_REQUEST_BYTES..envelope_end]) {
                Ok(envelope) => envelope,
                Err(_) => return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void,
            };
        let Ok(challenge): Result<&[u8; VBS_WORKLOAD_CHALLENGE_BYTES], _> =
            input[envelope_end..].try_into()
        else {
            return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void;
        };
        if *challenge == [0; VBS_WORKLOAD_CHALLENGE_BYTES] {
            return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void;
        }
        let binding = match VbsAttestationData::for_launch_request(
            request.nonce(),
            request,
            authority_policy(),
        ) {
            Ok(binding) => binding,
            Err(_) => return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void,
        };
        let mut secret = [0; 32];
        let mut secret_bytes = 0u32;
        let mut flags = 0u32;
        if unsafe {
            EnclaveUnsealData(
                envelope.blob().as_ptr().cast(),
                envelope.blob().len() as u32,
                secret.as_mut_ptr().cast(),
                secret.len() as u32,
                &mut secret_bytes,
                core::ptr::null_mut(),
                &mut flags,
            )
        } != 0
            || secret_bytes != secret.len() as u32
            || flags != 0
            || secret == [0; 32]
        {
            erase_secret(&mut secret);
            return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void;
        }
        // Consume both independently established authorizations exactly once.
        if unsafe { &mut *SECRET_RELEASE_STATE.0.get() }
            .consume(binding)
            .is_err()
        {
            erase_secret(&mut secret);
            return AuthorityStatus::SecretReleaseDenied as usize as *mut c_void;
        }
        let result = match consume_workload_secret(&mut secret, request, challenge) {
            Ok(result) => result,
            Err(()) => return AuthorityStatus::SecretConsumeFailed as usize as *mut c_void,
        };
        if unsafe {
            EnclaveCopyOutOfEnclave(
                (receipt_address as *mut u8).cast(),
                result.as_ptr().cast(),
                result.len(),
            )
        } != 0
        {
            return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
        }
        return AuthorityStatus::Success as usize as *mut c_void;
    }

    let mut request = [0; LAUNCH_REQUEST_BYTES];
    // SAFETY: destination is enclave-local and exact-sized; source remains an
    // untrusted address handled exclusively by the Vertdll copy primitive.
    if unsafe {
        EnclaveCopyIntoEnclave(
            request.as_mut_ptr().cast(),
            (request_address as *const u8).cast(),
            request.len(),
        )
    } != 0
    {
        return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
    }
    match call.operation() {
        VbsAuthorityOperation::IssueReceipt => {
            // SAFETY: the signed image declares exactly one enclave thread.
            let mut key = match unsafe { &*AUTHORITY_KEY_STATE.0.get() }.get() {
                Ok(key) => key,
                Err(()) => return AuthorityStatus::UnsafeKeyPlatform as usize as *mut c_void,
            };
            let receipt = match process_authority_request(&request, true, &key) {
                Ok(receipt) => receipt,
                Err(()) => {
                    erase_secret(&mut key);
                    return AuthorityStatus::RequestRejected as usize as *mut c_void;
                }
            };
            erase_secret(&mut key);
            // SAFETY: source is enclave-local and exact-sized; destination remains an
            // untrusted address handled exclusively by the Vertdll copy primitive.
            if unsafe {
                EnclaveCopyOutOfEnclave(
                    (receipt_address as *mut u8).cast(),
                    receipt.as_ptr().cast(),
                    receipt.len(),
                )
            } != 0
            {
                return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
            }
        }
        VbsAuthorityOperation::GenerateSealedKey => {
            if approved_request(&request).is_err() {
                return AuthorityStatus::RequestRejected as usize as *mut c_void;
            }
            // SAFETY: the signed image declares exactly one enclave thread.
            if unsafe { &*AUTHORITY_KEY_STATE.0.get() }.get().is_ok() {
                return AuthorityStatus::KeyAlreadyLoaded as usize as *mut c_void;
            }
            let (mut key, envelope) = match generate_sealed_secret() {
                Ok(generated) => generated,
                Err(status) => return status as usize as *mut c_void,
            };
            if unsafe {
                EnclaveCopyOutOfEnclave(
                    (receipt_address as *mut u8).cast(),
                    envelope.as_ptr().cast(),
                    envelope.len(),
                )
            } != 0
            {
                erase_secret(&mut key);
                return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
            }
            // SAFETY: the signed image declares exactly one enclave thread.
            if unsafe { &mut *AUTHORITY_KEY_STATE.0.get() }
                .install(key)
                .is_err()
            {
                erase_secret(&mut key);
                return AuthorityStatus::KeyAlreadyLoaded as usize as *mut c_void;
            }
            erase_secret(&mut key);
        }
        VbsAuthorityOperation::GenerateWorkloadSecret => {
            if approved_request(&request).is_err() {
                return AuthorityStatus::RequestRejected as usize as *mut c_void;
            }
            let (mut secret, envelope) = match generate_sealed_secret() {
                Ok(generated) => generated,
                Err(status) => return status as usize as *mut c_void,
            };
            erase_secret(&mut secret);
            if unsafe {
                EnclaveCopyOutOfEnclave(
                    (receipt_address as *mut u8).cast(),
                    envelope.as_ptr().cast(),
                    envelope.len(),
                )
            } != 0
            {
                return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
            }
        }
        VbsAuthorityOperation::IssueAttestationReport => {
            let Ok(launch) = approved_request(&request) else {
                return AuthorityStatus::RequestRejected as usize as *mut c_void;
            };
            let Ok(binding) =
                VbsAttestationData::for_launch_request(launch.nonce(), launch, authority_policy())
            else {
                return AuthorityStatus::RequestRejected as usize as *mut c_void;
            };
            let encoded_binding = binding.encode();
            let mut report = [0; VBS_ATTESTATION_REPORT_MAX_BYTES];
            let mut report_bytes = 0u32;
            // SAFETY: binding, report, and output-size pointers are enclave-local and
            // bounded. Vertdll produces the VBS-signed report into the fixed buffer.
            if unsafe {
                EnclaveGetAttestationReport(
                    encoded_binding.as_ptr(),
                    report.as_mut_ptr().cast(),
                    report.len() as u32,
                    &mut report_bytes,
                )
            } != 0
                || report_bytes == 0
                || report_bytes as usize > report.len()
            {
                return AuthorityStatus::AttestationFailed as usize as *mut c_void;
            }
            let Some(report_address) = receipt_address.checked_add(8) else {
                return AuthorityStatus::InvalidContext as usize as *mut c_void;
            };
            if receipt_address
                .checked_add(VBS_ATTESTATION_ENVELOPE_BYTES)
                .is_none()
            {
                return AuthorityStatus::InvalidContext as usize as *mut c_void;
            }
            let encoded_size = u64::from(report_bytes).to_le_bytes();
            // SAFETY: both sources are enclave-local and bounded; both destinations
            // are untrusted addresses handled only by the explicit copy primitive.
            if unsafe {
                EnclaveCopyOutOfEnclave(
                    (receipt_address as *mut u8).cast(),
                    encoded_size.as_ptr().cast(),
                    encoded_size.len(),
                )
            } != 0
                || unsafe {
                    EnclaveCopyOutOfEnclave(
                        (report_address as *mut u8).cast(),
                        report.as_ptr().cast(),
                        report_bytes as usize,
                    )
                } != 0
            {
                return AuthorityStatus::AttestationCopyFailed as usize as *mut c_void;
            }
        }
        VbsAuthorityOperation::GenerateAttestationChallenge => {
            let Ok(seed) = approved_request(&request) else {
                return AuthorityStatus::RequestRejected as usize as *mut c_void;
            };
            let challenge = match generate_challenge(seed) {
                Ok(challenge) => challenge,
                Err(status) => return status as usize as *mut c_void,
            };
            // SAFETY: source is enclave-local and destination was proven outside VTL1.
            if unsafe {
                EnclaveCopyOutOfEnclave(
                    (receipt_address as *mut u8).cast(),
                    challenge.as_ptr().cast(),
                    challenge.len(),
                )
            } != 0
            {
                return AuthorityStatus::AttestationCopyFailed as usize as *mut c_void;
            }
        }
        _ => return AuthorityStatus::InvalidContext as usize as *mut c_void,
    }
    AuthorityStatus::Success as usize as *mut c_void
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_configuration_is_strict_primary_and_non_debug() {
        assert_eq!(core::mem::size_of::<ImageEnclaveConfig64>(), 80);
        assert_eq!(
            __enclave_config.policy_flags,
            IMAGE_ENCLAVE_POLICY_STRICT_MEMORY
        );
        assert_eq!(
            __enclave_config.enclave_flags,
            IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
        );
        assert_eq!(__enclave_config.enclave_size, ENCLAVE_BYTES);
        assert_eq!(__enclave_config.number_of_threads, 1);
        assert_eq!(core::mem::size_of::<ImageLoadConfigDirectory64>(), 256);
        assert_eq!(
            _load_config_used.enclave_configuration_pointer,
            core::ptr::from_ref(&__enclave_config)
        );
    }

    #[test]
    fn call_probe_never_dereferences_untrusted_context() {
        let context = 0x1234usize as *mut c_void;
        assert_eq!(
            mrml_authority_probe(context) as usize,
            0x1234usize ^ 0x4d52_4d4c
        );
    }

    #[test]
    fn authority_emits_bound_non_debug_vbs_receipt() {
        let request = LaunchRequest::new(
            9,
            [0xa2; 32],
            AUTHORITY_MEASUREMENT,
            authority_policy().commitment(),
        )
        .unwrap();
        let receipt = process_authority_request(&request.encode(), true, &AUTHORITY_KEY).unwrap();
        let verified = AuthorityReceipt::verify(&AUTHORITY_KEY, request, &receipt).unwrap();
        assert_eq!(verified.report().backend(), ProtectionBackend::VbsEnclave);
        assert_eq!(
            verified.report().claims(),
            ProtectionClaims::VTL0_ISOLATION
                .union(ProtectionClaims::MEASURED)
                .union(ProtectionClaims::SEALED_KEYS)
        );
    }

    #[test]
    fn independent_vtl1_receipt_verifier_rejects_host_mutation() {
        let request = LaunchRequest::new(
            9,
            [0xa2; 32],
            AUTHORITY_MEASUREMENT,
            authority_policy().commitment(),
        )
        .unwrap();
        let receipt = process_authority_request(&request.encode(), true, &AUTHORITY_KEY).unwrap();
        let mut input = [0; VBS_RECEIPT_VERIFICATION_INPUT_BYTES];
        input[..LAUNCH_REQUEST_BYTES].copy_from_slice(&request.encode());
        input[LAUNCH_REQUEST_BYTES..].copy_from_slice(&receipt);
        assert_eq!(verify_authority_receipt(&input, &AUTHORITY_KEY), Ok(()));
        input[LAUNCH_REQUEST_BYTES + AUTHORITY_RECEIPT_BYTES - 1] ^= 1;
        assert_eq!(verify_authority_receipt(&input, &AUTHORITY_KEY), Err(()));
        assert_eq!(verify_authority_receipt(&input, &[0x72; 32]), Err(()));
    }

    #[test]
    fn authority_rejects_unapproved_measurement_and_malformed_request() {
        let wrong =
            LaunchRequest::new(9, [0xa2; 32], [0x52; 64], authority_policy().commitment()).unwrap();
        assert_eq!(
            process_authority_request(&wrong.encode(), true, &AUTHORITY_KEY),
            Err(())
        );
        let wrong_policy =
            LaunchRequest::new(9, [0xa2; 32], AUTHORITY_MEASUREMENT, [0x73; 64]).unwrap();
        assert_eq!(
            process_authority_request(&wrong_policy.encode(), true, &AUTHORITY_KEY),
            Err(())
        );
        let mut malformed = wrong.encode();
        malformed[0] ^= 1;
        assert_eq!(
            process_authority_request(&malformed, true, &AUTHORITY_KEY),
            Err(())
        );
    }

    #[test]
    fn authority_refuses_receipts_without_safe_attested_keys() {
        let request = LaunchRequest::new(
            9,
            [0xa2; 32],
            AUTHORITY_MEASUREMENT,
            authority_policy().commitment(),
        )
        .unwrap();
        assert_eq!(
            process_authority_request(&request.encode(), false, &AUTHORITY_KEY),
            Err(())
        );
    }

    #[test]
    fn untrusted_ranges_must_be_wholly_outside_enclave() {
        let enclave_start = 0x20_0000;
        let enclave_end = 0x40_0000;
        assert!(range_is_outside_enclave(
            0x10_0000,
            4096,
            enclave_start,
            enclave_end
        ));
        assert!(range_is_outside_enclave(
            enclave_end,
            4096,
            enclave_start,
            enclave_end
        ));
        for (address, bytes) in [
            (enclave_start - 1, 2),
            (enclave_start, 1),
            (enclave_end - 1, 2),
            (usize::MAX, 2),
            (0x10_0000, 0),
        ] {
            assert!(!range_is_outside_enclave(
                address,
                bytes,
                enclave_start,
                enclave_end
            ));
        }
    }

    #[test]
    fn verifier_challenge_is_single_pending_and_single_use() {
        let mut state = ChallengeState::new();
        let policy = authority_policy();
        let request =
            LaunchRequest::new(1, [0x91; 32], AUTHORITY_MEASUREMENT, policy.commitment()).unwrap();
        let binding = VbsAttestationData::for_launch_request([0x91; 32], request, policy).unwrap();
        let other_request =
            LaunchRequest::new(1, [0x92; 32], AUTHORITY_MEASUREMENT, policy.commitment()).unwrap();
        let other_binding =
            VbsAttestationData::for_launch_request([0x92; 32], other_request, policy).unwrap();
        assert_eq!(state.take(), Err(()));
        assert_eq!(state.store(binding), Ok(()));
        assert_eq!(state.store(other_binding), Err(()));
        assert_eq!(state.take(), Ok(binding));
        assert_eq!(state.take(), Err(()));
        assert_eq!(state.binding, [0; VBS_ATTESTATION_DATA_BYTES]);
    }

    #[test]
    fn authority_key_state_is_nonzero_install_once_and_never_encoded() {
        let mut state = AuthorityKeyState::new();
        assert_eq!(state.get(), Err(()));
        assert_eq!(state.install([0; 32]), Err(()));
        assert_eq!(state.install([0x73; 32]), Ok(()));
        assert_eq!(state.get(), Ok([0x73; 32]));
        assert_eq!(state.install([0x74; 32]), Err(()));
        let mut working_copy = state.get().unwrap();
        erase_secret(&mut working_copy);
        assert_eq!(working_copy, [0; 32]);
    }

    #[test]
    fn secret_release_requires_matching_dual_gates_and_is_single_use() {
        let policy = authority_policy();
        let request =
            LaunchRequest::new(3, [0x81; 32], AUTHORITY_MEASUREMENT, policy.commitment()).unwrap();
        let binding =
            VbsAttestationData::for_launch_request(request.nonce(), request, policy).unwrap();
        let other_request =
            LaunchRequest::new(4, [0x82; 32], AUTHORITY_MEASUREMENT, policy.commitment()).unwrap();
        let other =
            VbsAttestationData::for_launch_request(other_request.nonce(), other_request, policy)
                .unwrap();
        let mut state = SecretReleaseState::new();
        assert_eq!(state.consume(binding), Err(()));
        assert_eq!(state.record_receipt(binding), Ok(()));
        assert_eq!(state.consume(binding), Err(()));
        assert_eq!(state.record_attestation(other), Ok(()));
        assert_eq!(state.consume(binding), Err(()));

        let mut state = SecretReleaseState::new();
        assert_eq!(state.record_attestation(binding), Ok(()));
        assert_eq!(state.record_receipt(binding), Ok(()));
        assert_eq!(state.record_receipt(binding), Err(()));
        assert_eq!(state.consume(binding), Ok(()));
        assert_eq!(state.consume(binding), Err(()));
        assert_eq!(state.receipt_binding, [0; VBS_ATTESTATION_DATA_BYTES]);
        assert_eq!(state.attestation_binding, [0; VBS_ATTESTATION_DATA_BYTES]);
    }

    #[test]
    fn workload_secret_consumer_binds_request_and_challenge_then_erases() {
        let policy = authority_policy();
        let request =
            LaunchRequest::new(3, [0x81; 32], AUTHORITY_MEASUREMENT, policy.commitment()).unwrap();
        let mut first_secret = [0x61; 32];
        let first = consume_workload_secret(&mut first_secret, request, &[0x71; 32]).unwrap();
        assert_eq!(first_secret, [0; 32]);

        let mut second_secret = [0x61; 32];
        let second = consume_workload_secret(&mut second_secret, request, &[0x72; 32]).unwrap();
        assert_ne!(first, second);
        assert_eq!(second_secret, [0; 32]);

        let mut zero_secret = [0; 32];
        assert_eq!(
            consume_workload_secret(&mut zero_secret, request, &[0x71; 32]),
            Err(())
        );
        let mut secret = [0x61; 32];
        assert_eq!(
            consume_workload_secret(&mut secret, request, &[0; 32]),
            Err(())
        );
        assert_eq!(secret, [0; 32]);
    }
}
