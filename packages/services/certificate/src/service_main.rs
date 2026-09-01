#![no_std]
#![no_main]
use core::arch::{asm, global_asm};
use mrml_certificate::*;
use mrml_crypto::Sha256;
use mrml_interface_certificate_challenge_v1 as challenge_abi;
use mrml_interface_certificate_identity_v1 as identity_abi;
use mrml_interface_certificate_lifecycle_v1 as lifecycle_abi;
use mrml_interface_certificate_signing_v1 as signing_abi;

static mut LOOP: CertificateNativeServiceLoop = CertificateNativeServiceLoop::new();
global_asm!(
    r#"
        .section .text$a,"xr"
        .global efi_main
    efi_main:
        and rsp, -16
        sub rsp, 16
        mov [rsp], rbp
        mov rdi, r13
        mov rsi, r14
        mov rdx, r11
        mov rcx, r12
        mov r8, r15
        mov r9, rbx
        call mrml_certd_probe
        ud2

        .org efi_main + 512, 0xcc
        .global mrml_certd_probe_sender_entry
    mrml_certd_probe_sender_entry:
        and rsp, -16
        mov rdi, r13
        mov rsi, r14
        mov rdx, r12
        mov rcx, r15
        mov r8, r11
        call mrml_certd_probe_sender
        ud2
    "#
);
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}
struct Interrupt80;
unsafe impl CertificateRawSyscall for Interrupt80 {
    unsafe fn invoke(&mut self, f: &mut CertificateSyscallFrame) {
        unsafe {
            asm!("int 0x80",inlateout("rax")f.rax,inlateout("rdi")f.rdi,inlateout("rsi")f.rsi,inlateout("rdx")f.rdx,inlateout("r10")f.r10,inlateout("r8")f.r8,inlateout("r9")f.r9,options(nostack))
        }
    }
}
struct Auth;
impl DurableAuthenticator for Auth {
    fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError> {
        let mut h = Sha256::new();
        h.update(b"mrml-certd-native-probe-only");
        h.update(record);
        Ok(h.finalize())
    }
    fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
        Ok(self.authenticate(record)? == *tag)
    }
}
struct ProbeStorage {
    bytes: [u8; MAX_DURABLE_RECORD_BYTES],
    length: usize,
    prepared: Option<PreparedStoreReceipt>,
    committed: Option<CommittedStoreReceipt>,
}
impl ProbeStorage {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_DURABLE_RECORD_BYTES],
            length: 0,
            prepared: None,
            committed: None,
        }
    }
}
impl CertificateDurableStorageCapability for ProbeStorage {
    type Error = ();
    fn prepare_record(
        &mut self,
        record: &[u8],
        expected: PreparedStoreReceipt,
    ) -> Result<PreparedStoreReceipt, Self::Error> {
        if record.is_empty() || record.len() > self.bytes.len() || self.prepared.is_some() {
            return Err(());
        }
        self.bytes[..record.len()].copy_from_slice(record);
        self.length = record.len();
        self.prepared = Some(expected);
        Ok(expected)
    }
    fn commit_record(
        &mut self,
        prepared: PreparedStoreReceipt,
    ) -> Result<CommittedStoreReceipt, Self::Error> {
        if self.prepared != Some(prepared) {
            return Err(());
        }
        let receipt = CommittedStoreReceipt {
            namespace: prepared.namespace,
            object: prepared.object,
            generation: prepared.generation,
            payload_digest: prepared.payload_digest,
            store_generation: prepared.store_generation,
        };
        self.committed = Some(receipt);
        Ok(receipt)
    }
    fn authoritative_receipt(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<CommittedStoreReceipt>, Self::Error> {
        Ok(self
            .committed
            .filter(|receipt| receipt.namespace == namespace && receipt.object == object))
    }
    fn read_authoritative_record(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
        output: &mut [u8],
    ) -> Result<Option<(CommittedStoreReceipt, usize)>, Self::Error> {
        let Some(receipt) = self
            .committed
            .filter(|receipt| receipt.namespace == namespace && receipt.object == object)
        else {
            return Ok(None);
        };
        if output.len() < self.length {
            return Err(());
        }
        output[..self.length].copy_from_slice(&self.bytes[..self.length]);
        Ok(Some((receipt, self.length)))
    }
}
struct Providers {
    generation: u64,
}
impl CertificateIdentityProvider for Providers {
    fn describe(
        &mut self,
        identity: &[u8],
        _: u64,
        o: &mut [u8],
    ) -> Result<identity_abi::DescribeResponse, identity_abi::DescribeError> {
        if identity != b"probe.identity" {
            return Err(identity_abi::DescribeError::IdentityUnavailable);
        }
        let value = b"MRMLCERTPROBE1";
        if o.len() < value.len() {
            return Err(identity_abi::DescribeError::OutputTooSmall);
        }
        o[..value.len()].copy_from_slice(value);
        Ok(identity_abi::DescribeResponse {
            written: value.len() as u64,
            current_generation: self.generation,
        })
    }
    fn read_chain(
        &mut self,
        _: &[u8],
        _: u64,
        _: u32,
        _: &mut [u8],
    ) -> Result<identity_abi::ReadChainResponse, identity_abi::ReadChainError> {
        Err(identity_abi::ReadChainError::PermissionDenied)
    }
    fn request_signing_route(
        &mut self,
        _: &[u8],
        _: u64,
        _: &[u8; 32],
        _: &mut [u8],
    ) -> Result<identity_abi::RequestSigningRouteResponse, identity_abi::RequestSigningRouteError>
    {
        Err(identity_abi::RequestSigningRouteError::PermissionDenied)
    }
    fn poll_generation(
        &mut self,
        identity: &[u8],
        _: u64,
    ) -> Result<identity_abi::PollGenerationResponse, identity_abi::PollGenerationError> {
        if identity != b"probe.identity" {
            Err(identity_abi::PollGenerationError::IdentityUnavailable)
        } else {
            Ok(identity_abi::PollGenerationResponse {
                current_generation: self.generation,
                health: identity_abi::HEALTH_HEALTHY,
            })
        }
    }
}
impl CertificateSigningProvider for Providers {
    fn describe_public_key(
        &mut self,
        _: &[u8],
        _: u64,
        _: &[u8; 32],
        _: u64,
        _: &mut [u8],
    ) -> Result<signing_abi::DescribePublicKeyResponse, signing_abi::DescribePublicKeyError> {
        Err(signing_abi::DescribePublicKeyError::PermissionDenied)
    }
    fn sign_approved_digest(
        &mut self,
        _: u32,
        _: &[u8],
        _: u64,
        _: &[u8; 32],
        _: u64,
        _: &[u8; 32],
        _: &mut [u8],
    ) -> Result<signing_abi::SignResponse, signing_abi::SignError> {
        Err(signing_abi::SignError::PermissionDenied)
    }
}
impl CertificateChallengeProvider for Providers {
    fn prepare(
        &mut self,
        _: PreparedChallenge<'_>,
        _: &mut [u8],
    ) -> Result<challenge_abi::PrepareResponse, challenge_abi::PrepareError> {
        Err(challenge_abi::PrepareError::PermissionDenied)
    }
    fn activate(&mut self, _: &[u8]) -> Result<u64, challenge_abi::ActivateError> {
        Err(challenge_abi::ActivateError::PermissionDenied)
    }
    fn prepare_removal(&mut self, _: &[u8]) -> Result<u64, challenge_abi::PrepareRemovalError> {
        Err(challenge_abi::PrepareRemovalError::PermissionDenied)
    }
    fn commit_removal(&mut self, _: &[u8]) -> Result<u64, challenge_abi::CommitRemovalError> {
        Err(challenge_abi::CommitRemovalError::PermissionDenied)
    }
    fn authoritative_state(
        &mut self,
        _: &[u8],
    ) -> Result<challenge_abi::AuthoritativeStateResponse, challenge_abi::AuthoritativeStateError>
    {
        Err(challenge_abi::AuthoritativeStateError::PermissionDenied)
    }
}
impl CertificateLifecycleAuthorizer for Providers {
    fn authorize_status(&self, scope: u32, object: &[u8]) -> bool {
        scope == lifecycle_abi::SCOPE_IDENTITY && object == b"probe.identity"
    }
    fn authorize_account(&self, _: u32, _: u64, _: &[u8]) -> bool {
        false
    }
    fn authorize_identity(&self, _: u32, _: &[u8], _: u64, _: &[u8]) -> bool {
        false
    }
    fn authorize_backup(&self, _: u32, _: u64, _: &[u8]) -> bool {
        false
    }
}
impl CertificateLifecycleProvider for Providers {
    fn status(
        &mut self,
        _: u32,
        _: &[u8],
        o: &mut [u8],
    ) -> Result<lifecycle_abi::StatusResponse, lifecycle_abi::StatusError> {
        let value = b"restored-active";
        if o.len() < value.len() {
            return Err(lifecycle_abi::StatusError::OutputTooSmall);
        }
        o[..value.len()].copy_from_slice(value);
        Ok(lifecycle_abi::StatusResponse {
            written: value.len() as u64,
            state_generation: self.generation,
        })
    }
    fn account_operation(
        &mut self,
        _: u32,
        _: u64,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<lifecycle_abi::AccountOperationResponse, lifecycle_abi::AccountOperationError> {
        Err(lifecycle_abi::AccountOperationError::PermissionDenied)
    }
    fn identity_operation(
        &mut self,
        _: u32,
        _: &[u8],
        _: u64,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<lifecycle_abi::IdentityOperationResponse, lifecycle_abi::IdentityOperationError>
    {
        Err(lifecycle_abi::IdentityOperationError::PermissionDenied)
    }
    fn backup_operation(
        &mut self,
        _: u32,
        _: u64,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<lifecycle_abi::BackupOperationResponse, lifecycle_abi::BackupOperationError> {
        Err(lifecycle_abi::BackupOperationError::PermissionDenied)
    }
}
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_certd_probe(
    endpoint: u64,
    caller: u64,
    shared_read: u64,
    shared_write: u64,
    shared_len: u64,
    route: u64,
    provider_generation: u64,
) -> ! {
    let shared_len = usize::try_from(shared_len).unwrap_or_else(|_| halt());
    let mut auth = Auth;
    let record = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Deployment,
        DurableObjectId(*b"probe.identity!!"),
        provider_generation.checked_sub(1).unwrap_or_else(|| halt()),
        b"restored-active",
        &mut auth,
    )
    .unwrap_or_else(|_| halt());
    let mut store = CapabilityDurableStateStore::new(ProbeStorage::new());
    let mut transaction =
        DurableTransaction::prepare(&record, &mut store).unwrap_or_else(|_| halt());
    transaction.commit(&mut store).unwrap_or_else(|_| halt());
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let (_, len) = store
        .load_authoritative(DurableNamespace::PublicState, record.object, &mut encoded)
        .unwrap_or_else(|_| halt())
        .unwrap_or_else(|| halt());
    let restored = DurableRecord::decode(&encoded[..len], &mut auth).unwrap_or_else(|_| halt());
    if restored.payload() != b"restored-active" || restored.generation != provider_generation {
        halt()
    }
    encoded.fill(0);
    let mut syscalls = CertificateUserspaceSyscalls::new(
        Interrupt80,
        endpoint,
        caller,
        shared_read,
        shared_write,
        shared_len,
        route,
        provider_generation,
    )
    .unwrap_or_else(|_| halt());
    let authorizer = Providers {
        generation: restored.generation,
    };
    let mut signing = Providers {
        generation: restored.generation,
    };
    let mut identity = Providers {
        generation: restored.generation,
    };
    let mut challenge = Providers {
        generation: restored.generation,
    };
    let mut lifecycle = Providers {
        generation: restored.generation,
    };
    let loop_state = unsafe { &mut *core::ptr::addr_of_mut!(LOOP) };
    loop_state
        .serve_once(
            &mut syscalls,
            &authorizer,
            &mut signing,
            &mut identity,
            &mut challenge,
            &mut lifecycle,
        )
        .unwrap_or_else(|_| halt());
    loop_state.erase();
    terminate()
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_certd_probe_sender(
    endpoint: u64,
    receiver: u64,
    provider_generation: u64,
    shared_write: u64,
    shared_read: u64,
) -> ! {
    const IDENTITY_OFFSET: usize = 0;
    const OUTPUT_OFFSET: usize = 32;
    const OUTPUT_LENGTH: usize = 64;
    write_shared(shared_write, IDENTITY_OFFSET, b"probe.identity");
    let identity = identity_abi::BorrowedReadView::within(IDENTITY_OFFSET as u64, 14, 4096)
        .unwrap_or_else(|| halt());
    let output =
        identity_abi::BorrowedWriteView::within(OUTPUT_OFFSET as u64, OUTPUT_LENGTH as u64, 4096)
            .unwrap_or_else(|| halt());
    let request = identity_abi::encode_describe_request(identity_abi::DescribeRequest {
        identity,
        observed_generation: 0,
        output,
    })
    .unwrap_or_else(|_| halt());
    send_call(endpoint, receiver, &request);
    let mut response = [0u8; identity_abi::RESPONSE_BYTES];
    receive_exact(&mut response);
    let receipt = identity_abi::decode_describe_response(&response, OUTPUT_LENGTH as u64)
        .unwrap_or_else(|_| halt())
        .unwrap_or_else(|_| halt());
    if receipt.written != 14 || receipt.current_generation != provider_generation {
        halt()
    }
    let mut described = [0u8; 14];
    read_shared(shared_read, OUTPUT_OFFSET, &mut described);
    if described != *b"MRMLCERTPROBE1" {
        halt()
    }
    terminate()
}

fn write_shared(capability: u64, offset: usize, input: &[u8]) {
    let mut status = 8u64;
    unsafe {
        asm!("int 0x80",inlateout("rax")status,in("rdi")capability,in("rsi")offset as u64,inlateout("rdx")input.as_ptr() as u64=>_,in("r10")input.len() as u64,in("r8")0u64,in("r9")0u64,options(nostack))
    }
    if status != 0 {
        halt()
    }
}

fn read_shared(capability: u64, offset: usize, output: &mut [u8]) {
    let mut status = 7u64;
    unsafe {
        asm!("int 0x80",inlateout("rax")status,in("rdi")capability,in("rsi")offset as u64,inlateout("rdx")output.as_mut_ptr() as u64=>_,in("r10")output.len() as u64,in("r8")0u64,in("r9")0u64,options(nostack))
    }
    if status != 0 {
        halt()
    }
}

fn send_call(endpoint: u64, receiver: u64, request: &[u8]) {
    let mut status = 4u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") endpoint,
            in("rsi") receiver,
            inlateout("rdx") request.as_ptr() as u64 => _,
            in("r10") request.len() as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    }
    if status != 0 {
        halt()
    }
}

fn receive_exact(response: &mut [u8]) {
    let mut status = 5u64;
    let length: u64;
    let capability_count: u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") response.as_mut_ptr() as u64,
            in("rsi") response.len() as u64,
            inlateout("rdx") 0u64 => length,
            inlateout("r10") 0u64 => capability_count,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            options(nostack)
        )
    }
    if status != 0 || length != response.len() as u64 || capability_count != 0 {
        halt()
    }
}

fn terminate() -> ! {
    unsafe {
        asm!("int 0x80",in("rax")3u64,in("rdi")0u64,in("rsi")0u64,in("rdx")0u64,in("r10")0u64,in("r8")0u64,in("r9")0u64,options(noreturn,nostack))
    }
}
fn halt() -> ! {
    unsafe {
        asm!(
            "cli",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        )
    }
}
