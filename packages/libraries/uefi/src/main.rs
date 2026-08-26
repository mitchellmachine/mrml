#![no_std]
#![no_main]

use core::arch::global_asm;
use core::cell::UnsafeCell;
#[cfg(feature = "package-boot")]
use mrml_crypto::Sha3_512;
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES};
use mrml_kernel::{
    ArtifactKind, BOOTSTRAP_STATE_BYTES, BootIsolationOverride, BuildReceipt, FramebufferInfo,
    InstalledRecoveryBootIdentity, InstalledRecoverySataRoute, MAX_CUDA_KERNEL_BUNDLE_BYTES,
    MAX_HANDOFF_BYTES, MAX_HANDOFF_MADT_BYTES, MAX_KERNEL_IMAGE_BYTES, MAX_LAUNCH_POLICY_BYTES,
    MAX_SERVICE_IMAGE_BYTES, MAX_VM_IMAGE_BYTES, MemoryKind, MemoryRegion, MonotonicStateStore,
    PeImage, PendingBootRelease, PhysAddr, PixelFormat, RELEASE_MANIFEST_BYTES,
    RecoveryStateMetadata, SIGNED_ARTIFACT_OVERHEAD_BYTES, ServiceLaunch, SignedArtifact,
    TrustRoot,
    arch::x86_64::{
        AcpiMemory, MAX_X86_64_CPUS, PRIVILEGE_STACK_ARENA_PAGES, PagePermissions,
        PageTableBuildError, PageTableBuilder, PageTableStore, PerCpuPrivilegeStacks, VirtAddr,
        copy_madt,
    },
    encode_handoff_with_smp_service_recovery_isolation_installed_and_sata_route,
};
#[cfg(feature = "package-boot")]
use mrml_package_format::{
    BootPackageRecord, BootPackageRole, MAX_BOOT_PACKAGE_BYTES, MAX_BOOT_RELEASE_BYTES,
    parse as parse_package, parse_release,
};
use mrml_storage::{
    AUTHORITY_RECOVERY_STATE_BYTES, AuthorityRecoveryStateStore, VolumeId,
    decode_canonical_authority_recovery_state,
};
use mrml_uefi::tpm::{
    NvCounterError, PcrReleaseStateJournal, RecoveryJournalConfiguration,
    ReleaseStateJournalConfiguration, TpmNonceSource, TpmTransport, enforce_version,
    open_recovery_journal, open_release_state_journal, verify_distinct_journal_layouts,
};
use mrml_uefi::*;

const MAP_BYTES: usize = 64 * 1024;

struct FirmwareBuffer(UnsafeCell<[u8; MAP_BYTES]>);
unsafe impl Sync for FirmwareBuffer {}
static MEMORY_MAP: FirmwareBuffer = FirmwareBuffer(UnsafeCell::new([0; MAP_BYTES]));
struct RegionBuffer(UnsafeCell<[NormalizedRegion; MAX_NORMALIZED_REGIONS]>);
unsafe impl Sync for RegionBuffer {}
static REGIONS: RegionBuffer = RegionBuffer(UnsafeCell::new(
    [NormalizedRegion::EMPTY; MAX_NORMALIZED_REGIONS],
));
const FILE_INFO_BYTES: usize = 1024;
struct FileInfoBuffer(UnsafeCell<[u8; FILE_INFO_BYTES]>);
unsafe impl Sync for FileInfoBuffer {}
static FILE_INFO: FileInfoBuffer = FileInfoBuffer(UnsafeCell::new([0; FILE_INFO_BYTES]));
const HANDOFF_BYTES: usize = MAX_HANDOFF_BYTES;
const PAGE_BYTES: usize = 4096;
const HANDOFF_PAGES: usize = HANDOFF_BYTES.div_ceil(PAGE_BYTES);
const HANDOFF_ALLOCATION_BYTES: usize = HANDOFF_PAGES * PAGE_BYTES;
#[repr(C, align(4096))]
struct HandoffBuffer(UnsafeCell<[u8; HANDOFF_ALLOCATION_BYTES]>);
unsafe impl Sync for HandoffBuffer {}
static HANDOFF: HandoffBuffer = HandoffBuffer(UnsafeCell::new([0; HANDOFF_ALLOCATION_BYTES]));
const _: () = assert!(core::mem::align_of::<HandoffBuffer>() == PAGE_BYTES);
const _: () = assert!(core::mem::size_of::<HandoffBuffer>() == HANDOFF_ALLOCATION_BYTES);
struct MadtBuffer(UnsafeCell<[u8; MAX_HANDOFF_MADT_BYTES]>);
unsafe impl Sync for MadtBuffer {}
static MADT: MadtBuffer = MadtBuffer(UnsafeCell::new([0; MAX_HANDOFF_MADT_BYTES]));
const INSTALLED_RECOVERY_HANDLES: usize = 32;
const INSTALLED_RECOVERY_ALLOCATIONS: usize = 256;
const INSTALLED_RECOVERY_DIRECTORIES: usize = 64;
const INSTALLED_RECOVERY_EXTENTS: usize = 64;
const INSTALLED_RECOVERY_OBJECTS: usize = 64;
const INSTALLED_RECOVERY_METADATA_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct InstalledRecoveryHandoff {
    identity: InstalledRecoveryBootIdentity,
    sata_route: Option<InstalledRecoverySataRoute>,
}
struct RecoveryPathBuffer(UnsafeCell<[u8; MAX_UEFI_DEVICE_PATH_BYTES]>);
unsafe impl Sync for RecoveryPathBuffer {}
static RECOVERY_DEVICE_PATH: RecoveryPathBuffer =
    RecoveryPathBuffer(UnsafeCell::new([0; MAX_UEFI_DEVICE_PATH_BYTES]));
struct RecoveryFirmwareBlock(UnsafeCell<UefiRecoveryBlock>);
unsafe impl Sync for RecoveryFirmwareBlock {}
static RECOVERY_PROBE: RecoveryFirmwareBlock =
    RecoveryFirmwareBlock(UnsafeCell::new(UefiRecoveryBlock::new()));
struct RecoveryNativeBlock(UnsafeCell<[u8; UEFI_RECOVERY_BLOCK_BYTES]>);
unsafe impl Sync for RecoveryNativeBlock {}
static RECOVERY_VOLUME_SCRATCH: RecoveryNativeBlock =
    RecoveryNativeBlock(UnsafeCell::new([0; UEFI_RECOVERY_BLOCK_BYTES]));
static RECOVERY_PRIMARY: RecoveryNativeBlock =
    RecoveryNativeBlock(UnsafeCell::new([0; UEFI_RECOVERY_BLOCK_BYTES]));
static RECOVERY_SECONDARY: RecoveryNativeBlock =
    RecoveryNativeBlock(UnsafeCell::new([0; UEFI_RECOVERY_BLOCK_BYTES]));
struct RecoveryMetadataBuffer(UnsafeCell<[u8; INSTALLED_RECOVERY_METADATA_BYTES]>);
unsafe impl Sync for RecoveryMetadataBuffer {}
static RECOVERY_METADATA: RecoveryMetadataBuffer =
    RecoveryMetadataBuffer(UnsafeCell::new([0; INSTALLED_RECOVERY_METADATA_BYTES]));
const KERNEL_STACK_GUARD_PAGES: usize = 1;
const KERNEL_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 75, 69, 82, 78, 69, 76, 46, 83, 73, 71, 78, 69, 68, 0,
];
#[cfg(feature = "package-boot")]
const KERNEL_PACKAGE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 75, 69, 82, 78, 69, 76, 46, 80, 65, 67, 75, 65, 71, 69,
    0,
];
#[cfg(feature = "package-boot")]
const SYSTEM_RELEASE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 83, 89, 83, 84, 69, 77, 46, 82, 69, 76, 69, 65, 83, 69,
    0,
];
#[cfg(feature = "package-boot")]
const BOOTLOADER_PACKAGE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 66, 79, 79, 84, 76, 79, 65, 68, 69, 82, 46, 80, 65, 67,
    75, 65, 71, 69, 0,
];
#[cfg(feature = "package-boot")]
const CONFIGURATION_PACKAGE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 67, 79, 78, 70, 73, 71, 85, 82, 65, 84, 73, 79, 78, 46,
    80, 65, 67, 75, 65, 71, 69, 0,
];
const SERVICE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 83, 69, 82, 86, 73, 67, 69, 46, 83, 73, 71, 78, 69, 68,
    0,
];
const VM_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 86, 77, 46, 83, 73, 71, 78, 69, 68, 0,
];
const CUDA_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 67, 85, 68, 65, 46, 83, 73, 71, 78, 69, 68, 0,
];
const POLICY_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 80, 79, 76, 73, 67, 89, 46, 83, 73, 71, 78, 69, 68, 0,
];
const RELEASE_MANIFEST_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 82, 69, 76, 69, 65, 83, 69, 46, 77, 65, 78, 73, 70, 69,
    83, 84, 0,
];
const RELEASE_PUBLIC_KEY_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 82, 69, 76, 69, 65, 83, 69, 46, 80, 85, 66, 76, 73, 67,
    0,
];
const RELEASE_SIGNATURE_PATH: &[u16] = &[
    92, 69, 70, 73, 92, 77, 82, 77, 76, 92, 82, 69, 76, 69, 65, 83, 69, 46, 83, 73, 71, 0,
];
const SERVICE_STACK_PAGES: usize = 16;
const SERVICE_TABLE_PAGES: usize = 64;

#[derive(Clone, Copy)]
struct Framebuffer {
    base: u64,
    size: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
}

#[derive(Clone, Copy)]
struct Transition {
    root: u64,
    stack_top: u64,
    entry_stack_top: u64,
    double_fault_stack_top: u64,
    ap_trampoline: u64,
    ap_stack_arena: u64,
}

#[derive(Clone, Copy)]
struct PreparedService {
    launch: ServiceLaunch,
}

struct FirmwarePageTables {
    services: *const BootServices,
    frames: [u64; 256],
    count: usize,
}

struct FirmwareTpm {
    protocol: *mut Tcg2Protocol,
}

struct FirmwareRng {
    protocol: *mut RngProtocol,
}

struct PreparedRelease {
    journal: PcrReleaseStateJournal<FirmwareTpm, FirmwareRng>,
    admission: PendingBootRelease,
}

const MAX_TPM_COMMAND_BYTES: usize = 256;
const _: () = assert!(MAX_TPM_COMMAND_BYTES >= 35 + mrml_storage::RELEASE_STATE_JOURNAL_SLOT_BYTES);

impl TpmNonceSource for FirmwareRng {
    fn fill_nonce(&mut self, output: &mut [u8; 32]) -> Result<(), NvCounterError> {
        let protocol = unsafe { self.protocol.as_mut() }.ok_or(NvCounterError::Transport)?;
        check(unsafe {
            (protocol.get_rng)(
                protocol,
                core::ptr::null(),
                output.len(),
                output.as_mut_ptr(),
            )
        })
        .map_err(|_| NvCounterError::Transport)
    }
}

impl TpmTransport for FirmwareTpm {
    fn submit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, NvCounterError> {
        if command.len() > MAX_TPM_COMMAND_BYTES || response.len() < 10 {
            return Err(NvCounterError::Transport);
        }
        let protocol = unsafe { self.protocol.as_mut() }.ok_or(NvCounterError::Transport)?;
        let mut input = [0u8; MAX_TPM_COMMAND_BYTES];
        input[..command.len()].copy_from_slice(command);
        check(unsafe {
            (protocol.submit_command)(
                protocol,
                command.len() as u32,
                input.as_mut_ptr(),
                response.len() as u32,
                response.as_mut_ptr(),
            )
        })
        .map_err(|_| NvCounterError::Transport)?;
        let declared = u32::from_be_bytes(
            response[2..6]
                .try_into()
                .map_err(|_| NvCounterError::MalformedResponse)?,
        ) as usize;
        if !(10..=response.len()).contains(&declared) {
            return Err(NvCounterError::MalformedResponse);
        }
        Ok(declared)
    }
}

impl PageTableStore for FirmwarePageTables {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
        let services = unsafe { self.services.as_ref() }.ok_or(PageTableBuildError::Storage)?;
        if self.count == self.frames.len() {
            return Err(PageTableBuildError::Storage);
        }
        // AP real-mode startup can load only a 32-bit CR3, so every frame in
        // the shared hierarchy is deliberately allocated below 4 GiB.
        let mut address = u64::from(u32::MAX) & !(PAGE_BYTES as u64 - 1);
        check(unsafe { (services.allocate_pages)(1, 2, 1, &mut address) })
            .map_err(|_| PageTableBuildError::Storage)?;
        let frame = PhysAddr::new(address).map_err(|_| PageTableBuildError::Storage)?;
        unsafe { core::ptr::write_bytes(address as *mut u8, 0, 4096) };
        self.frames[self.count] = address;
        self.count += 1;
        Ok(frame)
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        if index >= 512 {
            return Err(PageTableBuildError::Storage);
        }
        Ok(unsafe { *((table.get() as *const u64).add(index)) })
    }

    fn write(
        &mut self,
        table: PhysAddr,
        index: usize,
        value: u64,
    ) -> Result<(), PageTableBuildError> {
        if index >= 512 {
            return Err(PageTableBuildError::Storage);
        }
        unsafe { *((table.get() as *mut u64).add(index)) = value };
        Ok(())
    }
}

global_asm!(
    r#"
    .section .text
    .p2align 12
    .global mrml_activate_address_space
mrml_activate_address_space:
    cli
    mov r11, rcx
    mov r12, rdx
    mov r10, qword ptr [rsp + 40]
    mov r13, qword ptr [rsp + 48]
    mov r14, qword ptr [rsp + 56]
    mov r15, r8
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x800
    wrmsr
    mov rax, cr0
    or rax, 0x10000
    mov cr0, rax
    mov cr3, r11
    mov rsp, r12
    mov rcx, r9
    mov rdx, r10
    mov r8, r13
    mov r9, r14
    jmp r15
    .global mrml_activate_address_space_end
mrml_activate_address_space_end:
    "#
);

unsafe extern "efiapi" {
    fn mrml_activate_address_space(
        root: u64,
        stack_top: u64,
        entry: u64,
        handoff: *const u8,
        handoff_length: usize,
        entry_stack_top: u64,
        double_fault_stack_top: u64,
    ) -> !;
    static mrml_activate_address_space_end: u8;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

#[unsafe(export_name = "efi_main")]
/// UEFI entry invoked by firmware with the loaded-image handle and live system
/// table.
///
/// # Safety
///
/// `table` must be the valid system table supplied for `image`; its boot
/// services and protocols must remain live until the successful one-way
/// `ExitBootServices` transition.
pub unsafe extern "efiapi" fn efi_main(image: Handle, table: *mut SystemTable) -> Status {
    // SAFETY: UEFI invokes this entry point with a live system table. Every
    // pointer obtained below is checked for null before it is dereferenced and
    // is used only while boot services remain active.
    match unsafe { boot(image, table) } {
        Ok(()) => SUCCESS,
        Err(status) => status,
    }
}

unsafe fn boot(image: Handle, table: *mut SystemTable) -> Result<(), Status> {
    let system = unsafe { table.as_mut() }.ok_or(LOAD_ERROR)?;
    let services = unsafe { system.boot_services.as_mut() }.ok_or(LOAD_ERROR)?;
    let isolation_selection = unsafe { loaded_boot_isolation_selection(image, services) }?;
    let secure_boot = detect_secure_boot(system.runtime_services)?;
    if require_secure_boot() && !secure_boot {
        return Err(LOAD_ERROR);
    }

    let mut gop_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.locate_protocol)(&GOP_GUID, core::ptr::null_mut(), &mut gop_pointer)
    })?;
    let gop = unsafe { (gop_pointer as *mut GraphicsOutputProtocol).as_mut() }.ok_or(LOAD_ERROR)?;
    let mode = unsafe { gop.mode.as_mut() }.ok_or(LOAD_ERROR)?;
    let info = unsafe { mode.info.as_ref() }.ok_or(LOAD_ERROR)?;
    if !matches!(info.pixel_format, 0 | 1)
        || info.horizontal_resolution == 0
        || info.vertical_resolution == 0
        || info.pixels_per_scan_line < info.horizontal_resolution
        || mode.framebuffer_base == 0
        || mode.framebuffer_size == 0
    {
        return Err(LOAD_ERROR);
    }
    let framebuffer = Framebuffer {
        base: mode.framebuffer_base,
        size: mode.framebuffer_size,
        width: info.horizontal_resolution,
        height: info.vertical_resolution,
        stride: info.pixels_per_scan_line,
        format: info.pixel_format,
    };
    let pixel_format = if framebuffer.format == 0 {
        PixelFormat::RedGreenBlueReserved
    } else {
        PixelFormat::BlueGreenRedReserved
    };
    FramebufferInfo::new(
        framebuffer.base,
        framebuffer.size as u64,
        framebuffer.width,
        framebuffer.height,
        framebuffer.stride,
        pixel_format,
    )
    .map_err(|_| LOAD_ERROR)?;
    paint(framebuffer, [0x80, 0x00, 0x00]);

    let mut rng_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.locate_protocol)(&RNG_GUID, core::ptr::null_mut(), &mut rng_pointer)
    })?;
    let rng = unsafe { (rng_pointer as *mut RngProtocol).as_mut() }.ok_or(LOAD_ERROR)?;
    let mut entropy = [0u8; 32];
    check(unsafe { (rng.get_rng)(rng, core::ptr::null(), entropy.len(), entropy.as_mut_ptr()) })?;
    if entropy.iter().all(|byte| *byte == 0) {
        return Err(LOAD_ERROR);
    }
    paint(framebuffer, [0x80, 0x40, 0x00]);

    let recovery_configuration = configured_recovery_journal()?;
    let mut prepared_release = unsafe {
        prepare_configured_release(
            image,
            services,
            framebuffer,
            rng_pointer.cast(),
            recovery_configuration,
        )
    }?;

    #[cfg(not(feature = "package-boot"))]
    let kernel_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            KERNEL_PATH,
            MAX_KERNEL_IMAGE_BYTES as usize + SIGNED_ARTIFACT_OVERHEAD_BYTES,
        )
    }?;
    #[cfg(feature = "package-boot")]
    let kernel_file = unsafe { load_kernel_package(image, services, framebuffer) }?;
    if kernel_file
        .address
        .checked_add(kernel_file.length as u64)
        .is_none()
    {
        return Err(LOAD_ERROR);
    }
    let kernel_bytes = unsafe {
        core::slice::from_raw_parts(kernel_file.address as *const u8, kernel_file.length)
    };
    let signed = SignedArtifact::decode(kernel_bytes).map_err(|_| LOAD_ERROR)?;
    let verified = if let Some(release) = prepared_release.as_mut() {
        release
            .admission
            .verify_executable(&signed, ArtifactKind::Kernel)
            .map_err(|_| LOAD_ERROR)?
    } else {
        signed
            .verify_executable(
                &TrustRoot::new(
                    ArtifactKind::Kernel,
                    embedded_kernel_root().ok_or(LOAD_ERROR)?,
                    embedded_minimum_version().ok_or(LOAD_ERROR)?,
                ),
                ArtifactKind::Kernel,
            )
            .map_err(|_| LOAD_ERROR)?
    };
    loader_trace(0xa1);
    if verified.image().image_size() == 0 {
        return Err(LOAD_ERROR);
    }
    paint(framebuffer, [0x20, 0x40, 0x80]);
    let image_size = verified.image().image_size() as usize;
    let image_pages = image_size
        .checked_add(4095)
        .map(|value| value / 4096)
        .ok_or(LOAD_ERROR)?;
    let image_allocation_bytes = image_pages.checked_mul(4096).ok_or(LOAD_ERROR)?;
    let mut image_address = 0u64;
    check(unsafe { (services.allocate_pages)(0, 1, image_pages, &mut image_address) })?;
    if image_address == 0 || !image_address.is_multiple_of(4096) {
        return Err(LOAD_ERROR);
    }
    let image_allocation = unsafe {
        core::slice::from_raw_parts_mut(image_address as *mut u8, image_allocation_bytes)
    };
    image_allocation.fill(0);
    let image_destination = &mut image_allocation[..image_size];
    let kernel_entry = verified
        .image()
        .materialize_at(image_destination, image_address)
        .map_err(|_| LOAD_ERROR)?;
    loader_trace(0xa2);
    let service_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            SERVICE_PATH,
            MAX_SERVICE_IMAGE_BYTES as usize + SIGNED_ARTIFACT_OVERHEAD_BYTES,
        )
    }?;
    loader_trace(0xa3);
    let service_bytes = unsafe {
        core::slice::from_raw_parts(service_file.address as *const u8, service_file.length)
    };
    let service_signed = SignedArtifact::decode(service_bytes).map_err(|_| LOAD_ERROR)?;
    let service_verified = if let Some(release) = prepared_release.as_mut() {
        release
            .admission
            .verify_executable(&service_signed, ArtifactKind::ServiceImage)
            .map_err(|_| LOAD_ERROR)?
    } else {
        service_signed
            .verify_executable(
                &TrustRoot::new(
                    ArtifactKind::ServiceImage,
                    embedded_service_root().ok_or(LOAD_ERROR)?,
                    embedded_service_minimum_version().ok_or(LOAD_ERROR)?,
                ),
                ArtifactKind::ServiceImage,
            )
            .map_err(|_| LOAD_ERROR)?
    };
    loader_trace(0xa4);
    let additional_release_artifacts = if let Some(release) = prepared_release.as_mut() {
        Some([
            unsafe {
                load_and_admit_release_artifact(
                    image,
                    services,
                    framebuffer,
                    &mut release.admission,
                    VM_PATH,
                    MAX_VM_IMAGE_BYTES as usize,
                    ArtifactKind::VmImage,
                )
            }?,
            unsafe {
                load_and_admit_release_artifact(
                    image,
                    services,
                    framebuffer,
                    &mut release.admission,
                    CUDA_PATH,
                    MAX_CUDA_KERNEL_BUNDLE_BYTES as usize,
                    ArtifactKind::CudaKernelBundle,
                )
            }?,
            unsafe {
                load_and_admit_release_artifact(
                    image,
                    services,
                    framebuffer,
                    &mut release.admission,
                    POLICY_PATH,
                    MAX_LAUNCH_POLICY_BYTES as usize,
                    ArtifactKind::LaunchPolicy,
                )
            }?,
        ])
    } else {
        None
    };
    if let Some(artifacts) = &additional_release_artifacts {
        verify_release_build_receipt(
            &artifacts[2],
            signed.payload().len() as u64,
            *verified.artifact().digest(),
            service_signed.payload().len() as u64,
            *service_verified.artifact().digest(),
        )?;
    }
    if let Some(release) = prepared_release.as_mut() {
        release
            .admission
            .publish(&mut release.journal)
            .map_err(|_| LOAD_ERROR)?;
    }
    let kernel_measured =
        measure_artifact(services, signed.payload(), b"MRML authenticated kernel PE")?;
    if require_tpm_measurement() && !kernel_measured {
        return Err(LOAD_ERROR);
    }
    let service_measured = measure_artifact(
        services,
        service_signed.payload(),
        b"MRML authenticated service PE",
    )?;
    let additional_release_measured = if let Some(artifacts) = &additional_release_artifacts {
        let descriptions: [&[u8]; 3] = [
            b"MRML authenticated VM image",
            b"MRML authenticated CUDA bundle",
            b"MRML authenticated policy",
        ];
        let mut measured = true;
        for (artifact, description) in artifacts.iter().zip(descriptions) {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    artifact.file.address as *const u8,
                    artifact.file.length,
                )
            };
            let signed = SignedArtifact::decode(bytes).map_err(|_| LOAD_ERROR)?;
            measured &= measure_artifact(services, signed.payload(), description)?;
        }
        measured
    } else {
        true
    };
    let artifact_set_measured = if let Some(release) = prepared_release.as_ref() {
        let artifacts = additional_release_artifacts.as_ref().ok_or(LOAD_ERROR)?;
        let artifact_set = encode_selected_release_artifact_set(
            release.admission.release(),
            release.admission.manifest_digest(),
            [
                *verified.artifact().digest(),
                artifacts[0].digest,
                *service_verified.artifact().digest(),
                artifacts[1].digest,
                artifacts[2].digest,
            ],
        )
        .map_err(|_| LOAD_ERROR)?;
        measure_artifact(services, &artifact_set, b"MRML selected release set")?
    } else {
        let artifact_set = encode_selected_boot_artifact_set(
            verified.artifact().version(),
            *verified.artifact().digest(),
            service_verified.artifact().version(),
            *service_verified.artifact().digest(),
        )
        .map_err(|_| LOAD_ERROR)?;
        measure_artifact(services, &artifact_set, b"MRML selected artifact set")?
    };
    if let Some(artifacts) = additional_release_artifacts {
        for artifact in artifacts {
            unsafe { release_loaded_file(services, artifact.file) }?;
        }
    }
    let measured_boot =
        kernel_measured && service_measured && additional_release_measured && artifact_set_measured;
    if require_tpm_measurement() && !measured_boot {
        return Err(LOAD_ERROR);
    }
    let service_image_size = service_verified.image().image_size() as usize;
    let service_image_pages = service_image_size.div_ceil(PAGE_BYTES);
    let service_allocation_bytes = service_image_pages
        .checked_mul(PAGE_BYTES)
        .ok_or(LOAD_ERROR)?;
    let mut service_image_physical = 0u64;
    check(unsafe {
        (services.allocate_pages)(0, 2, service_image_pages, &mut service_image_physical)
    })?;
    let service_image = unsafe {
        core::slice::from_raw_parts_mut(service_image_physical as *mut u8, service_allocation_bytes)
    };
    service_image.fill(0);
    let service_entry = service_verified
        .image()
        .materialize(&mut service_image[..service_image_size])
        .map_err(|_| LOAD_ERROR)?;
    loader_trace(0xa5);
    let mut service_stack_physical = 0u64;
    check(unsafe {
        (services.allocate_pages)(0, 2, SERVICE_STACK_PAGES, &mut service_stack_physical)
    })?;
    let mut service_table_physical = 0u64;
    check(unsafe {
        (services.allocate_pages)(0, 2, SERVICE_TABLE_PAGES, &mut service_table_physical)
    })?;
    if [
        service_image_physical,
        service_stack_physical,
        service_table_physical,
    ]
    .into_iter()
    .any(|address| address == 0 || !address.is_multiple_of(PAGE_BYTES as u64))
    {
        return Err(LOAD_ERROR);
    }
    unsafe {
        core::ptr::write_bytes(
            service_stack_physical as *mut u8,
            0,
            SERVICE_STACK_PAGES * PAGE_BYTES,
        );
        core::ptr::write_bytes(
            service_table_physical as *mut u8,
            0,
            SERVICE_TABLE_PAGES * PAGE_BYTES,
        );
    }
    let service_stack_top = 0x0000_0002_0000_0000u64;
    let prepared_service = PreparedService {
        launch: ServiceLaunch::new(
            PhysAddr::new(service_file.address).map_err(|_| LOAD_ERROR)?,
            service_file.length as u64,
            PhysAddr::new(service_image_physical).map_err(|_| LOAD_ERROR)?,
            service_image_pages as u64,
            service_verified.image().image_base(),
            service_entry,
            PhysAddr::new(service_stack_physical).map_err(|_| LOAD_ERROR)?,
            SERVICE_STACK_PAGES as u64,
            service_stack_top,
            PhysAddr::new(service_table_physical).map_err(|_| LOAD_ERROR)?,
            SERVICE_TABLE_PAGES as u64,
            service_verified.artifact().version(),
            *service_verified.artifact().digest(),
        )
        .map_err(|_| LOAD_ERROR)?,
    };
    loader_trace(0xa6);
    let transition = prepare_transition(
        services,
        verified.image(),
        image_address,
        framebuffer,
        prepared_service,
    )?;
    loader_trace(0xa7);
    let kernel_version = verified.artifact().version();
    let kernel_measurement = *verified.artifact().digest();
    paint(framebuffer, [0x00, 0x60, 0x20]);

    paint(framebuffer, [0x14, 0x21, 0x35]);

    let acpi_root = unsafe { find_acpi_root(system) }.map_err(|_| LOAD_ERROR)?;
    if acpi_root == 0 {
        return Err(LOAD_ERROR);
    }
    let legacy_rollback_protected = enforce_rollback_counter(services, kernel_version)?;
    let rollback_protected = prepared_release.is_some() || legacy_rollback_protected;
    if require_rollback_counter() && !rollback_protected {
        return Err(LOAD_ERROR);
    }
    let recovery_state =
        admit_configured_recovery_journal(services, rng_pointer.cast(), recovery_configuration)?;
    let installed_recovery =
        validate_configured_installed_recovery(services, image, recovery_state)?;
    let coherent_release = prepared_release.is_some();

    loader_trace(0xa8);
    let (map_size, descriptor_size) = unsafe { exit_boot_services(image, services) }?;
    unsafe {
        launch_after_exit(
            map_size,
            descriptor_size,
            transition,
            kernel_entry,
            kernel_version,
            kernel_measurement,
            measured_boot,
            secure_boot,
            rollback_protected,
            coherent_release,
            entropy,
            acpi_root,
            framebuffer,
            prepared_service,
            recovery_state,
            installed_recovery,
            isolation_selection,
        )
    }
}

/// Completes the one-way transition after UEFI boot services have terminated.
/// Every validation failure beyond this boundary fail-stops because returning
/// to firmware after a successful `ExitBootServices` call is invalid.
///
/// # Safety
///
/// The caller must have successfully exited boot services with the memory-map
/// snapshot stored in `MEMORY_MAP`, and `map_size` must describe initialized
/// bytes in that buffer using the supplied nonzero `descriptor_size`.
#[allow(clippy::too_many_arguments)]
unsafe fn launch_after_exit(
    map_size: usize,
    descriptor_size: usize,
    transition: Transition,
    kernel_entry: u64,
    kernel_version: u64,
    kernel_measurement: [u8; 64],
    measured_boot: bool,
    secure_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    entropy: [u8; 32],
    acpi_root: u64,
    framebuffer: Framebuffer,
    service: PreparedService,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryHandoff>,
    isolation_selection: BootIsolationSelection,
) -> ! {
    let map_bytes = unsafe { core::slice::from_raw_parts(MEMORY_MAP.0.get().cast(), map_size) };
    let regions = unsafe { &mut *REGIONS.0.get() };
    let region_count = match normalize_memory_map(
        map_bytes,
        descriptor_size,
        framebuffer.base,
        framebuffer.size as u64,
        regions,
    ) {
        Ok(count) => count,
        Err(_) => halt(),
    };
    if region_count == 0 {
        halt();
    }
    loader_trace(0xb1);
    let mut acpi_memory = FirmwareAcpiMemory {
        regions: &regions[..region_count],
    };
    let madt_storage = unsafe { &mut *MADT.0.get() };
    let madt_length = match copy_madt(&mut acpi_memory, acpi_root, madt_storage) {
        Ok(length) => length,
        Err(_) => halt(),
    };
    loader_trace(0xb2);
    if enter_kernel(
        transition,
        kernel_entry,
        kernel_version,
        kernel_measurement,
        measured_boot,
        secure_boot,
        rollback_protected,
        coherent_release,
        entropy,
        acpi_root,
        framebuffer,
        &regions[..region_count],
        &madt_storage[..madt_length],
        service,
        recovery_state,
        installed_recovery,
        isolation_selection,
    )
    .is_err()
    {
        halt();
    }
    halt()
}

struct FirmwareAcpiMemory<'a> {
    regions: &'a [NormalizedRegion],
}

impl AcpiMemory for FirmwareAcpiMemory<'_> {
    fn read_exact(&mut self, physical: u64, output: &mut [u8]) -> bool {
        let Some(end) = physical.checked_add(output.len() as u64) else {
            return false;
        };
        let admitted = self.regions.iter().any(|region| {
            region.kind == NormalizedMemoryKind::Acpi
                && region.start <= physical
                && region
                    .pages
                    .checked_mul(PAGE_BYTES as u64)
                    .and_then(|bytes| region.start.checked_add(bytes))
                    .is_some_and(|region_end| end <= region_end)
        });
        if !admitted {
            return false;
        }
        // SAFETY: the post-ExitBootServices memory map proves the complete
        // source range is ACPI memory, and the destination is loader-owned.
        unsafe {
            core::ptr::copy_nonoverlapping(
                physical as *const u8,
                output.as_mut_ptr(),
                output.len(),
            );
        }
        true
    }
}

fn embedded_kernel_root() -> Option<[u8; 64]> {
    parse_root_digest(option_env!("MRML_KERNEL_ROOT_DIGEST_HEX")?.as_bytes())
}

#[cfg(feature = "package-boot")]
fn embedded_kernel_package_root() -> Option<[u8; 64]> {
    parse_root_digest(option_env!("MRML_KERNEL_PACKAGE_ROOT_DIGEST_HEX")?.as_bytes())
}

#[cfg(feature = "package-boot")]
fn embedded_system_release_root() -> Option<[u8; 64]> {
    parse_root_digest(option_env!("MRML_SYSTEM_RELEASE_ROOT_DIGEST_HEX")?.as_bytes())
}

fn embedded_minimum_version() -> Option<u64> {
    parse_nonzero_version(option_env!("MRML_KERNEL_MIN_VERSION")?.as_bytes())
}

fn embedded_service_root() -> Option<[u8; 64]> {
    parse_root_digest(option_env!("MRML_SERVICE_ROOT_DIGEST_HEX")?.as_bytes())
}

fn embedded_service_minimum_version() -> Option<u64> {
    parse_nonzero_version(option_env!("MRML_SERVICE_MIN_VERSION")?.as_bytes())
}

fn require_tpm_measurement() -> bool {
    matches!(option_env!("MRML_REQUIRE_TPM"), Some("1"))
}

fn require_secure_boot() -> bool {
    matches!(option_env!("MRML_REQUIRE_SECURE_BOOT"), Some("1"))
}

fn require_rollback_counter() -> bool {
    matches!(option_env!("MRML_REQUIRE_ROLLBACK"), Some("1"))
}

fn configured_nv_index() -> Result<Option<u32>, Status> {
    let Some(encoded) = option_env!("MRML_TPM_NV_INDEX_HEX") else {
        return Ok(None);
    };
    let bytes = encoded.as_bytes();
    if bytes.len() != 8 {
        return Err(LOAD_ERROR);
    }
    let mut value = 0u32;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(LOAD_ERROR),
        };
        value = value.checked_mul(16).ok_or(LOAD_ERROR)? | u32::from(digit);
    }
    Ok(Some(value))
}

fn enforce_rollback_counter(services: &BootServices, version: u64) -> Result<bool, Status> {
    let Some(index) = configured_nv_index()? else {
        return Ok(false);
    };
    let mut protocol_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.locate_protocol)(
            &TCG2_PROTOCOL_GUID,
            core::ptr::null_mut(),
            &mut protocol_pointer,
        )
    })?;
    let mut transport = FirmwareTpm {
        protocol: protocol_pointer.cast(),
    };
    enforce_version(&mut transport, index, version, 1024).map_err(|_| LOAD_ERROR)?;
    Ok(true)
}

fn configured_recovery_journal() -> Result<Option<RecoveryJournalConfiguration>, Status> {
    RecoveryJournalConfiguration::parse_optional([
        option_env!("MRML_RECOVERY_COUNTER_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RECOVERY_SLOT0_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RECOVERY_SLOT1_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RECOVERY_POLICY_DIGEST_HEX").map(str::as_bytes),
        option_env!("MRML_RECOVERY_PCR_DIGEST_HEX").map(str::as_bytes),
        option_env!("MRML_RECOVERY_PCR_SELECT_HEX").map(str::as_bytes),
    ])
    .map_err(|_| LOAD_ERROR)
}

fn configured_release_state_journal() -> Result<Option<ReleaseStateJournalConfiguration>, Status> {
    ReleaseStateJournalConfiguration::parse_optional([
        option_env!("MRML_RELEASE_COUNTER_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RELEASE_SLOT0_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RELEASE_SLOT1_NV_INDEX_HEX").map(str::as_bytes),
        option_env!("MRML_RELEASE_POLICY_DIGEST_HEX").map(str::as_bytes),
        option_env!("MRML_RELEASE_PCR_DIGEST_HEX").map(str::as_bytes),
        option_env!("MRML_RELEASE_PCR_SELECT_HEX").map(str::as_bytes),
    ])
    .map_err(|_| LOAD_ERROR)
}

fn require_release_manifest() -> bool {
    matches!(option_env!("MRML_REQUIRE_RELEASE_MANIFEST"), Some("1"))
}

unsafe fn prepare_configured_release(
    image: Handle,
    services: &BootServices,
    framebuffer: Framebuffer,
    rng: *mut RngProtocol,
    recovery: Option<RecoveryJournalConfiguration>,
) -> Result<Option<PreparedRelease>, Status> {
    let Some(configuration) = configured_release_state_journal()? else {
        return if require_release_manifest() {
            Err(LOAD_ERROR)
        } else {
            Ok(None)
        };
    };
    if rng.is_null() {
        return Err(LOAD_ERROR);
    }
    let (layout, policy) = configuration.into_parts();
    if let Some(recovery) = recovery {
        let (recovery_layout, _) = recovery.into_parts();
        verify_distinct_journal_layouts(recovery_layout, layout).map_err(|_| LOAD_ERROR)?;
    }
    let manifest_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            RELEASE_MANIFEST_PATH,
            RELEASE_MANIFEST_BYTES,
        )
    }?;
    if manifest_file.length != RELEASE_MANIFEST_BYTES {
        return Err(LOAD_ERROR);
    }
    let manifest = unsafe {
        core::slice::from_raw_parts(manifest_file.address as *const u8, manifest_file.length)
    };

    let mut protocol_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.locate_protocol)(
            &TCG2_PROTOCOL_GUID,
            core::ptr::null_mut(),
            &mut protocol_pointer,
        )
    })?;
    let transport = FirmwareTpm {
        protocol: protocol_pointer.cast(),
    };
    let nonce_source = FirmwareRng { protocol: rng };
    let journal = open_release_state_journal(transport, nonce_source, layout, policy)
        .map_err(|_| LOAD_ERROR)?;
    let mut expected = [0; BOOTSTRAP_STATE_BYTES];
    journal
        .load_authenticated(&mut expected)
        .map_err(|_| LOAD_ERROR)?;
    if let Ok(admission) = PendingBootRelease::installed(expected, manifest) {
        return Ok(Some(PreparedRelease { journal, admission }));
    }

    let public_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            RELEASE_PUBLIC_KEY_PATH,
            LAMPORT_PUBLIC_KEY_BYTES,
        )
    }?;
    let signature_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            RELEASE_SIGNATURE_PATH,
            LAMPORT_SIGNATURE_BYTES,
        )
    }?;
    if public_file.length != LAMPORT_PUBLIC_KEY_BYTES
        || signature_file.length != LAMPORT_SIGNATURE_BYTES
    {
        return Err(LOAD_ERROR);
    }
    let public = unsafe {
        core::slice::from_raw_parts(public_file.address as *const u8, public_file.length)
    };
    let signature = unsafe {
        core::slice::from_raw_parts(signature_file.address as *const u8, signature_file.length)
    };
    let admission = PendingBootRelease::transition(expected, manifest, public, signature)
        .map_err(|_| LOAD_ERROR)?;
    Ok(Some(PreparedRelease { journal, admission }))
}

fn admit_configured_recovery_journal(
    services: &BootServices,
    rng: *mut RngProtocol,
    configuration: Option<RecoveryJournalConfiguration>,
) -> Result<Option<RecoveryStateMetadata>, Status> {
    let Some(configuration) = configuration else {
        return Ok(None);
    };
    if rng.is_null() {
        return Err(LOAD_ERROR);
    }
    let mut protocol_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.locate_protocol)(
            &TCG2_PROTOCOL_GUID,
            core::ptr::null_mut(),
            &mut protocol_pointer,
        )
    })?;
    let (layout, policy) = configuration.into_parts();
    let transport = FirmwareTpm {
        protocol: protocol_pointer.cast(),
    };
    let nonce_source = FirmwareRng { protocol: rng };
    let journal =
        open_recovery_journal(transport, nonce_source, layout, policy).map_err(|_| LOAD_ERROR)?;
    let mut state = [0; AUTHORITY_RECOVERY_STATE_BYTES];
    let result = journal
        .load_authenticated(&mut state)
        .map_err(|_| LOAD_ERROR)
        .and_then(|()| {
            let decoded =
                decode_canonical_authority_recovery_state(&state).map_err(|_| LOAD_ERROR)?;
            RecoveryStateMetadata::new(
                decoded.accepted_epoch(),
                decoded.accepted_handle_generation(),
                decoded.accepted_volume().map(|volume| volume.bytes()),
                decoded.accepted_root_generation(),
            )
            .map(Some)
            .map_err(|_| LOAD_ERROR)
        });
    state.fill(0);
    result
}

/// Requires an authenticated journal volume/root selection to exist as one
/// exact, completely reachable installed graph before firmware services exit.
/// The retained identity is evidence only; UEFI protocol authority is closed
/// inside the recovery operation and never crosses the kernel handoff.
fn validate_configured_installed_recovery(
    services: &BootServices,
    image: Handle,
    recovery: Option<RecoveryStateMetadata>,
) -> Result<Option<InstalledRecoveryHandoff>, Status> {
    let Some(recovery) = recovery else {
        return Ok(None);
    };
    let Some(expected_volume) = recovery.accepted_volume() else {
        return Ok(None);
    };
    let expected_volume = VolumeId::new(expected_volume).map_err(|_| LOAD_ERROR)?;
    let handles = unsafe { locate_block_io_handles::<INSTALLED_RECOVERY_HANDLES>(services) }
        .map_err(|_| LOAD_ERROR)?;
    let path = unsafe { &mut *RECOVERY_DEVICE_PATH.0.get() };
    let probe = unsafe { &mut *RECOVERY_PROBE.0.get() };
    let selected = unsafe {
        select_uefi_recovery_volume(services, image, &handles, expected_volume, path, probe)
    }
    .map_err(|_| LOAD_ERROR)?;
    let recovered = unsafe {
        recover_selected_uefi_reachable_state::<
            INSTALLED_RECOVERY_ALLOCATIONS,
            INSTALLED_RECOVERY_DIRECTORIES,
            INSTALLED_RECOVERY_EXTENTS,
            INSTALLED_RECOVERY_OBJECTS,
        >(
            services,
            image,
            selected,
            path,
            &mut *RECOVERY_VOLUME_SCRATCH.0.get(),
            &mut *RECOVERY_PRIMARY.0.get(),
            &mut *RECOVERY_SECONDARY.0.get(),
            &mut *RECOVERY_METADATA.0.get(),
        )
    }
    .map_err(|_| LOAD_ERROR)?;
    let identity = bind_recovered_uefi_installed_identity(
        selected,
        &recovered,
        expected_volume,
        recovery.accepted_root_generation(),
    )
    .map_err(|_| LOAD_ERROR)?;
    let sata_route = identity.sata_handoff_route().map_err(|_| LOAD_ERROR)?;
    let identity = identity.boot_identity().map_err(|_| LOAD_ERROR)?;
    Ok(Some(InstalledRecoveryHandoff {
        identity,
        sata_route,
    }))
}

fn detect_secure_boot(runtime: *mut RuntimeServices) -> Result<bool, Status> {
    const SECURE_BOOT: &[u16] = &[83, 101, 99, 117, 114, 101, 66, 111, 111, 116, 0];
    const SETUP_MODE: &[u16] = &[83, 101, 116, 117, 112, 77, 111, 100, 101, 0];
    let runtime = unsafe { runtime.as_ref() }.ok_or(LOAD_ERROR)?;
    Ok(read_boolean_variable(runtime, SECURE_BOOT)? == Some(true)
        && read_boolean_variable(runtime, SETUP_MODE)? == Some(false))
}

fn read_boolean_variable(runtime: &RuntimeServices, name: &[u16]) -> Result<Option<bool>, Status> {
    if name.last().copied() != Some(0) {
        return Err(LOAD_ERROR);
    }
    let mut attributes = 0u32;
    let mut size = 1usize;
    let mut value = 0u8;
    let status = unsafe {
        (runtime.get_variable)(
            name.as_ptr(),
            &GLOBAL_VARIABLE_GUID,
            &mut attributes,
            &mut size,
            (&mut value as *mut u8).cast(),
        )
    };
    if status == NOT_FOUND {
        return Ok(None);
    }
    check(status)?;
    if size != 1 || value > 1 {
        return Err(LOAD_ERROR);
    }
    Ok(Some(value == 1))
}

fn measure_artifact(
    services: &BootServices,
    payload: &[u8],
    description: &[u8],
) -> Result<bool, Status> {
    if payload.is_empty() || description.is_empty() || description.len() > 32 {
        return Err(LOAD_ERROR);
    }
    let mut protocol_pointer = core::ptr::null_mut();
    let status = unsafe {
        (services.locate_protocol)(
            &TCG2_PROTOCOL_GUID,
            core::ptr::null_mut(),
            &mut protocol_pointer,
        )
    };
    if status == NOT_FOUND {
        return Ok(false);
    }
    check(status)?;
    let protocol = unsafe { (protocol_pointer as *mut Tcg2Protocol).as_mut() }.ok_or(LOAD_ERROR)?;
    let mut event = Tcg2Event {
        size: (core::mem::size_of::<u32>()
            + core::mem::size_of::<Tcg2EventHeader>()
            + description.len()) as u32,
        header: Tcg2EventHeader {
            header_size: core::mem::size_of::<Tcg2EventHeader>() as u32,
            header_version: 1,
            pcr_index: 11,
            event_type: 0x0000_000d,
        },
        event: [0; 32],
    };
    event.event[..description.len()].copy_from_slice(description);
    check(unsafe {
        (protocol.hash_log_extend_event)(
            protocol,
            0,
            payload.as_ptr() as u64,
            payload.len() as u64,
            &mut event,
        )
    })?;
    Ok(true)
}

struct LoadedFile {
    address: u64,
    length: usize,
}

struct AdmittedReleaseArtifact {
    file: LoadedFile,
    digest: [u8; 64],
}

fn verify_release_build_receipt(
    policy: &AdmittedReleaseArtifact,
    kernel_length: u64,
    kernel_digest: [u8; 64],
    service_length: u64,
    service_digest: [u8; 64],
) -> Result<(), Status> {
    let bytes = unsafe {
        core::slice::from_raw_parts(policy.file.address as *const u8, policy.file.length)
    };
    let signed = SignedArtifact::decode(bytes).map_err(|_| LOAD_ERROR)?;
    let receipt = BuildReceipt::decode(signed.payload()).map_err(|_| LOAD_ERROR)?;
    receipt
        .validate_uefi_release(kernel_length, kernel_digest, service_length, service_digest)
        .map_err(|_| LOAD_ERROR)
}

unsafe fn release_loaded_file(services: &BootServices, file: LoadedFile) -> Result<(), Status> {
    let pages = file.length.div_ceil(PAGE_BYTES);
    let allocation_bytes = pages.checked_mul(PAGE_BYTES).ok_or(LOAD_ERROR)?;
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(file.address as *mut u8, allocation_bytes) };
    bytes.fill(0);
    check(unsafe { (services.free_pages)(file.address, pages) })
}

unsafe fn load_and_admit_release_artifact(
    image: Handle,
    services: &BootServices,
    framebuffer: Framebuffer,
    admission: &mut PendingBootRelease,
    path: &[u16],
    maximum_payload: usize,
    kind: ArtifactKind,
) -> Result<AdmittedReleaseArtifact, Status> {
    let maximum = maximum_payload
        .checked_add(SIGNED_ARTIFACT_OVERHEAD_BYTES)
        .ok_or(LOAD_ERROR)?;
    let file = unsafe { load_file(image, services, framebuffer, path, maximum) }?;
    if file.address.checked_add(file.length as u64).is_none() {
        return Err(LOAD_ERROR);
    }
    let bytes = unsafe { core::slice::from_raw_parts(file.address as *const u8, file.length) };
    let signed = SignedArtifact::decode(bytes).map_err(|_| LOAD_ERROR)?;
    let verified = admission
        .verify_artifact(&signed, kind)
        .map_err(|_| LOAD_ERROR)?;
    Ok(AdmittedReleaseArtifact {
        file,
        digest: *verified.digest(),
    })
}

#[cfg(feature = "package-boot")]
unsafe fn load_kernel_package(
    image: Handle,
    services: &BootServices,
    framebuffer: Framebuffer,
) -> Result<LoadedFile, Status> {
    let release_file = unsafe {
        load_file(
            image,
            services,
            framebuffer,
            SYSTEM_RELEASE_PATH,
            MAX_BOOT_RELEASE_BYTES,
        )
    }?;
    let release_bytes = unsafe {
        core::slice::from_raw_parts(release_file.address as *const u8, release_file.length)
    };
    let release = parse_release(release_bytes, true).map_err(|_| LOAD_ERROR)?;
    if release.key_id != embedded_system_release_root().ok_or(LOAD_ERROR)? {
        return Err(LOAD_ERROR);
    }
    loader_trace(0xc8);
    let _bootloader = unsafe {
        load_release_package(
            image,
            services,
            framebuffer,
            BOOTLOADER_PACKAGE_PATH,
            release.package(BootPackageRole::Bootloader),
            "org.mrml.library.uefi",
            "bootloader",
            "uefi-loader",
            16 * 1024 * 1024,
            None,
        )
    }?;
    let _configuration = unsafe {
        load_release_package(
            image,
            services,
            framebuffer,
            CONFIGURATION_PACKAGE_PATH,
            release.package(BootPackageRole::Configuration),
            "org.mrml.service.config",
            "configuration",
            "configuration",
            1024 * 1024,
            None,
        )
    }?;
    loader_trace(0xc9);
    let kernel = unsafe {
        load_release_package(
            image,
            services,
            framebuffer,
            KERNEL_PACKAGE_PATH,
            release.package(BootPackageRole::Kernel),
            "org.mrml.system.kernel",
            "kernel",
            "kernel",
            MAX_KERNEL_IMAGE_BYTES as usize + SIGNED_ARTIFACT_OVERHEAD_BYTES,
            Some(embedded_kernel_package_root().ok_or(LOAD_ERROR)?),
        )
    }?;
    let kernel_bytes =
        unsafe { core::slice::from_raw_parts(kernel.address as *const u8, kernel.length) };
    let signed = SignedArtifact::decode(kernel_bytes).map_err(|_| LOAD_ERROR)?;
    if signed.kind() != ArtifactKind::Kernel
        || signed.version() != release.package(BootPackageRole::Kernel).version
    {
        return Err(LOAD_ERROR);
    }
    loader_trace(0xb2);
    Ok(kernel)
}

#[cfg(feature = "package-boot")]
unsafe fn load_release_package(
    image: Handle,
    services: &BootServices,
    framebuffer: Framebuffer,
    path: &[u16],
    record: BootPackageRecord,
    expected_id: &str,
    expected_class: &str,
    purpose: &str,
    maximum_raw: usize,
    expected_key: Option<[u8; 64]>,
) -> Result<LoadedFile, Status> {
    let package_file =
        unsafe { load_file(image, services, framebuffer, path, MAX_BOOT_PACKAGE_BYTES) }?;
    let package_bytes = unsafe {
        core::slice::from_raw_parts(package_file.address as *const u8, package_file.length)
    };
    if Sha3_512::digest(package_bytes) != record.package_digest {
        return Err(LOAD_ERROR);
    }
    let package = parse_package(package_bytes, true, true).map_err(|_| LOAD_ERROR)?;
    if package.id != expected_id
        || package.class != expected_class
        || package.version != record.version
        || expected_key.is_some_and(|key| package.key_id != key)
    {
        return Err(LOAD_ERROR);
    }
    let payload = package.select(purpose, "x86_64").map_err(|_| LOAD_ERROR)?;
    if payload.raw_len == 0 || payload.raw_len > maximum_raw {
        return Err(LOAD_ERROR);
    }
    loader_trace(0xb0);
    let pages = payload.raw_len.checked_add(4095).ok_or(LOAD_ERROR)? / 4096;
    let allocation_bytes = pages.checked_mul(4096).ok_or(LOAD_ERROR)?;
    let mut address = 0_u64;
    check(unsafe { (services.allocate_pages)(0, 1, pages, &mut address) })?;
    if address == 0 || !address.is_multiple_of(4096) {
        return Err(LOAD_ERROR);
    }
    let allocation =
        unsafe { core::slice::from_raw_parts_mut(address as *mut u8, allocation_bytes) };
    allocation.fill(0);
    payload
        .decode(&mut allocation[..payload.raw_len])
        .map_err(|_| LOAD_ERROR)?;
    loader_trace(0xb2);
    Ok(LoadedFile {
        address,
        length: payload.raw_len,
    })
}

unsafe fn load_file(
    image: Handle,
    services: &BootServices,
    framebuffer: Framebuffer,
    path: &[u16],
    maximum: usize,
) -> Result<LoadedFile, Status> {
    if path.last().copied() != Some(0) || maximum == 0 {
        return Err(LOAD_ERROR);
    }
    let mut loaded_pointer = core::ptr::null_mut();
    check(unsafe { (services.handle_protocol)(image, &LOADED_IMAGE_GUID, &mut loaded_pointer) })?;
    let loaded =
        unsafe { (loaded_pointer as *mut LoadedImageProtocol).as_ref() }.ok_or(LOAD_ERROR)?;
    paint(framebuffer, [0x80, 0x80, 0x00]);
    if loaded.device_handle.is_null() {
        return Err(LOAD_ERROR);
    }
    paint(framebuffer, [0x40, 0x80, 0x00]);
    let mut filesystem_pointer = core::ptr::null_mut();
    check(unsafe {
        (services.handle_protocol)(
            loaded.device_handle,
            &SIMPLE_FILE_SYSTEM_GUID,
            &mut filesystem_pointer,
        )
    })?;
    let filesystem = unsafe { (filesystem_pointer as *mut SimpleFileSystemProtocol).as_mut() }
        .ok_or(LOAD_ERROR)?;
    paint(framebuffer, [0x80, 0x00, 0x80]);
    let mut root = core::ptr::null_mut();
    check(unsafe { (filesystem.open_volume)(filesystem, &mut root) })?;
    let root = unsafe { root.as_mut() }.ok_or(LOAD_ERROR)?;
    paint(framebuffer, [0x00, 0x80, 0x80]);
    let mut file_pointer = core::ptr::null_mut();
    let open_status = unsafe { (root.open)(root, &mut file_pointer, path.as_ptr(), 1, 0) };
    let _ = unsafe { (root.close)(root) };
    check(open_status)?;
    paint(framebuffer, [0x00, 0x00, 0x80]);
    let file = unsafe { file_pointer.as_mut() }.ok_or(LOAD_ERROR)?;
    let result = unsafe { read_file_pages(file, services, maximum) };
    let close_status = unsafe { (file.close)(file) };
    let loaded = result?;
    check(close_status)?;
    Ok(loaded)
}

/// Reads the current image's bounded UEFI LoadOptions before any boot-service
/// exit. Firmware supplies the buffer, so size, nullness, alignment, and the
/// complete UTF-16 token stream are validated before the shared parser runs.
unsafe fn loaded_boot_isolation_selection(
    image: Handle,
    services: &BootServices,
) -> Result<BootIsolationSelection, Status> {
    let mut loaded_pointer = core::ptr::null_mut();
    check(unsafe { (services.handle_protocol)(image, &LOADED_IMAGE_GUID, &mut loaded_pointer) })?;
    let loaded =
        unsafe { (loaded_pointer as *const LoadedImageProtocol).as_ref() }.ok_or(LOAD_ERROR)?;
    unsafe { parse_loaded_image_boot_isolation(loaded) }.map_err(|_| LOAD_ERROR)
}

unsafe fn read_file_pages(
    file: &mut FileProtocol,
    services: &BootServices,
    maximum: usize,
) -> Result<LoadedFile, Status> {
    let mut info_size = 0usize;
    let status =
        unsafe { (file.get_info)(file, &FILE_INFO_GUID, &mut info_size, core::ptr::null_mut()) };
    if status != BUFFER_TOO_SMALL || !(80..=FILE_INFO_BYTES).contains(&info_size) {
        return Err(LOAD_ERROR);
    }
    let info = unsafe { &mut *FILE_INFO.0.get() };
    check(unsafe {
        (file.get_info)(
            file,
            &FILE_INFO_GUID,
            &mut info_size,
            info.as_mut_ptr().cast(),
        )
    })?;
    if info_size < 80 {
        return Err(LOAD_ERROR);
    }
    let file_length_u64 = u64::from_le_bytes(info[8..16].try_into().map_err(|_| LOAD_ERROR)?);
    let file_length = usize::try_from(file_length_u64).map_err(|_| LOAD_ERROR)?;
    if file_length == 0 || file_length > maximum {
        return Err(LOAD_ERROR);
    }
    let pages = file_length
        .checked_add(4095)
        .map(|bytes| bytes / 4096)
        .ok_or(LOAD_ERROR)?;
    let mut address = 0u64;
    check(unsafe { (services.allocate_pages)(0, 2, pages, &mut address) })?;
    if address == 0 || !address.is_multiple_of(4096) {
        return Err(LOAD_ERROR);
    }
    let mut total = 0usize;
    while total < file_length {
        let mut amount = file_length - total;
        check(unsafe { (file.read)(file, &mut amount, (address as *mut u8).add(total).cast()) })?;
        if amount == 0 || amount > file_length - total {
            return Err(LOAD_ERROR);
        }
        total += amount;
    }
    let mut extra = 0u8;
    let mut extra_size = 1usize;
    check(unsafe { (file.read)(file, &mut extra_size, (&mut extra as *mut u8).cast()) })?;
    if extra_size != 0 {
        return Err(LOAD_ERROR);
    }
    Ok(LoadedFile {
        address,
        length: file_length,
    })
}

#[allow(clippy::too_many_arguments)]
fn enter_kernel(
    transition: Transition,
    kernel_entry: u64,
    kernel_version: u64,
    kernel_measurement: [u8; 64],
    measured_boot: bool,
    secure_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    entropy: [u8; 32],
    acpi_root: u64,
    framebuffer: Framebuffer,
    regions: &[NormalizedRegion],
    madt: &[u8],
    service: PreparedService,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryHandoff>,
    isolation_selection: BootIsolationSelection,
) -> Result<(), Status> {
    let placeholder = MemoryRegion::new(
        PhysAddr::new(0).map_err(|_| LOAD_ERROR)?,
        1,
        MemoryKind::Reserved,
    )
    .map_err(|_| LOAD_ERROR)?;
    let mut kernel_regions = [placeholder; MAX_NORMALIZED_REGIONS];
    for (destination, source) in kernel_regions.iter_mut().zip(regions) {
        let kind = match source.kind {
            NormalizedMemoryKind::Free => MemoryKind::Free,
            NormalizedMemoryKind::Kernel => MemoryKind::Kernel,
            NormalizedMemoryKind::Firmware => MemoryKind::Firmware,
            NormalizedMemoryKind::Mmio => MemoryKind::Mmio,
            NormalizedMemoryKind::Acpi => MemoryKind::Acpi,
            NormalizedMemoryKind::Reserved => MemoryKind::Reserved,
        };
        *destination = MemoryRegion::new(
            PhysAddr::new(source.start).map_err(|_| LOAD_ERROR)?,
            source.pages,
            kind,
        )
        .map_err(|_| LOAD_ERROR)?;
    }
    let pixel_format = if framebuffer.format == 0 {
        PixelFormat::RedGreenBlueReserved
    } else {
        PixelFormat::BlueGreenRedReserved
    };
    let framebuffer_info = FramebufferInfo::new(
        framebuffer.base,
        framebuffer.size as u64,
        framebuffer.width,
        framebuffer.height,
        framebuffer.stride,
        pixel_format,
    )
    .map_err(|_| LOAD_ERROR)?;
    let handoff_page = unsafe { &mut *HANDOFF.0.get() };
    handoff_page.fill(0);
    let handoff = &mut handoff_page[..HANDOFF_BYTES];
    let isolation_override = match isolation_selection {
        BootIsolationSelection::ConfiguredDefault => None,
        BootIsolationSelection::TotalMicrovmOnce => Some(BootIsolationOverride::TotalMicrovmOnce),
    };
    let installed_recovery_identity = installed_recovery.map(|installed| installed.identity);
    let installed_recovery_sata_route =
        installed_recovery.and_then(|installed| installed.sata_route);
    let handoff_length =
        encode_handoff_with_smp_service_recovery_isolation_installed_and_sata_route(
            kernel_version,
            entropy,
            kernel_measurement,
            secure_boot,
            measured_boot,
            rollback_protected,
            coherent_release,
            acpi_root,
            framebuffer_info,
            &kernel_regions[..regions.len()],
            transition.ap_trampoline,
            transition.ap_stack_arena,
            service.launch,
            recovery_state,
            installed_recovery_identity,
            installed_recovery_sata_route,
            isolation_override,
            madt,
            handoff,
        )
        .map_err(|_| LOAD_ERROR)?;
    loader_trace(0xb3);
    if kernel_entry == 0 {
        return Err(LOAD_ERROR);
    }
    // SAFETY: the authenticated PE parser proved the entry lies in an
    // executable section, materialization completed before boot-services exit,
    // and the canonical handoff remains in static loader memory.
    unsafe {
        mrml_activate_address_space(
            transition.root,
            transition.stack_top,
            kernel_entry,
            handoff.as_ptr(),
            handoff_length,
            transition.entry_stack_top,
            transition.double_fault_stack_top,
        )
    }
}

fn prepare_transition(
    services: &BootServices,
    image: &PeImage<'_>,
    image_address: u64,
    framebuffer: Framebuffer,
    service: PreparedService,
) -> Result<Transition, Status> {
    let stack_allocation_pages = MAX_X86_64_CPUS
        .checked_mul(PRIVILEGE_STACK_ARENA_PAGES as usize)
        .and_then(|pages| pages.checked_add(KERNEL_STACK_GUARD_PAGES))
        .ok_or(LOAD_ERROR)?;
    let mut stack_allocation_base = 0u64;
    check(unsafe {
        (services.allocate_pages)(0, 2, stack_allocation_pages, &mut stack_allocation_base)
    })?;
    let stack_base = stack_allocation_base
        .checked_add((KERNEL_STACK_GUARD_PAGES as u64) * 4096)
        .ok_or(LOAD_ERROR)?;
    let stack_set = PerCpuPrivilegeStacks::<MAX_X86_64_CPUS>::new(
        stack_base,
        stack_base,
        PRIVILEGE_STACK_ARENA_PAGES,
    )
    .map_err(|_| LOAD_ERROR)?;
    let stack_layout = stack_set
        .cpu(0)
        .map(|cpu| cpu.virtual_layout())
        .map_err(|_| LOAD_ERROR)?;
    let stack_top = stack_layout.early_top().map_err(|_| LOAD_ERROR)?;
    if stack_allocation_base == 0
        || !stack_allocation_base.is_multiple_of(4096)
        || !stack_base.is_multiple_of(4096)
        || !stack_top.wrapping_add(8).is_multiple_of(16)
    {
        return Err(LOAD_ERROR);
    }
    let stack_allocation_bytes = stack_allocation_pages.checked_mul(4096).ok_or(LOAD_ERROR)?;
    unsafe { core::ptr::write_bytes(stack_allocation_base as *mut u8, 0, stack_allocation_bytes) };
    unsafe { *(stack_top as *mut u64) = 0 };

    let store = FirmwarePageTables {
        services: services as *const BootServices,
        frames: [0; 256],
        count: 0,
    };
    let mut ap_trampoline = 0x000f_f000u64;
    check(unsafe { (services.allocate_pages)(1, 2, 1, &mut ap_trampoline) })?;
    if !(PAGE_BYTES as u64..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(PAGE_BYTES as u64)
    {
        return Err(LOAD_ERROR);
    }
    unsafe { core::ptr::write_bytes(ap_trampoline as *mut u8, 0, PAGE_BYTES) };
    let mut tables = PageTableBuilder::new(store).map_err(|_| LOAD_ERROR)?;
    for index in 0..image.load_region_count() {
        let region = image.load_region(index).map_err(|_| LOAD_ERROR)?;
        let start = image_address
            .checked_add(region.virtual_address() as u64)
            .ok_or(LOAD_ERROR)?;
        let permissions = match (region.writable(), region.executable()) {
            (true, false) => PagePermissions::KERNEL_READ_WRITE,
            (false, true) => PagePermissions::KERNEL_READ_EXECUTE,
            (false, false) => PagePermissions::KERNEL_READ,
            (true, true) => return Err(LOAD_ERROR),
        };
        map_identity(&mut tables, start, region.pages() as u64, permissions)?;
    }
    for cpu in 0..MAX_X86_64_CPUS {
        let layout = stack_set
            .cpu(cpu)
            .map(|stacks| stacks.virtual_layout())
            .map_err(|_| LOAD_ERROR)?;
        for (base, pages) in [
            (layout.early_base(), layout.early_pages()),
            (
                layout.entry_base().map_err(|_| LOAD_ERROR)?,
                layout.entry_pages(),
            ),
            (
                layout.double_fault_base().map_err(|_| LOAD_ERROR)?,
                layout.double_fault_pages(),
            ),
        ] {
            map_identity(&mut tables, base, pages, PagePermissions::KERNEL_READ_WRITE)?;
        }
    }
    let handoff_address = HANDOFF.0.get() as u64;
    if !handoff_address.is_multiple_of(PAGE_BYTES as u64) {
        return Err(LOAD_ERROR);
    }
    map_identity(
        &mut tables,
        handoff_address,
        HANDOFF_PAGES as u64,
        PagePermissions::KERNEL_READ,
    )?;
    map_containing_identity(
        &mut tables,
        framebuffer.base,
        framebuffer.size as u64,
        PagePermissions::KERNEL_READ_WRITE,
    )?;
    map_identity(
        &mut tables,
        0xfee0_0000,
        1,
        PagePermissions::KERNEL_MMIO_READ_WRITE,
    )?;
    let trampoline_start = mrml_activate_address_space as *const () as usize as u64;
    let trampoline_end = core::ptr::addr_of!(mrml_activate_address_space_end) as u64;
    if !trampoline_start.is_multiple_of(PAGE_BYTES as u64)
        || trampoline_end <= trampoline_start
        || trampoline_end
            > trampoline_start
                .checked_add(PAGE_BYTES as u64)
                .ok_or(LOAD_ERROR)?
    {
        return Err(LOAD_ERROR);
    }
    map_identity(
        &mut tables,
        trampoline_start,
        1,
        PagePermissions::KERNEL_READ_EXECUTE,
    )?;
    map_identity(
        &mut tables,
        ap_trampoline,
        1,
        PagePermissions::KERNEL_MMIO_READ_WRITE,
    )?;
    map_identity(
        &mut tables,
        service.launch.artifact_physical().get(),
        service.launch.artifact_length().div_ceil(PAGE_BYTES as u64),
        PagePermissions::KERNEL_READ,
    )?;
    map_identity(
        &mut tables,
        service.launch.image_physical().get(),
        service.launch.image_pages(),
        PagePermissions::KERNEL_READ,
    )?;
    map_identity(
        &mut tables,
        service.launch.stack_physical().get(),
        service.launch.stack_pages(),
        PagePermissions::KERNEL_READ_WRITE,
    )?;
    map_identity(
        &mut tables,
        service.launch.table_physical().get(),
        service.launch.table_pages(),
        PagePermissions::KERNEL_READ_WRITE,
    )?;
    let mut frame_index = 0usize;
    while frame_index < tables.store().count {
        let frame = tables.store().frames[frame_index];
        map_identity(
            &mut tables,
            frame,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )?;
        frame_index += 1;
    }
    Ok(Transition {
        root: tables.root().get(),
        stack_top,
        entry_stack_top: stack_layout.entry_top().map_err(|_| LOAD_ERROR)?,
        double_fault_stack_top: stack_layout.double_fault_top().map_err(|_| LOAD_ERROR)?,
        ap_trampoline,
        ap_stack_arena: stack_base,
    })
}

fn map_containing_identity(
    tables: &mut PageTableBuilder<FirmwarePageTables>,
    address: u64,
    length: u64,
    permissions: PagePermissions,
) -> Result<(), Status> {
    if length == 0 {
        return Err(LOAD_ERROR);
    }
    let start = address & !4095;
    let end = address.checked_add(length).ok_or(LOAD_ERROR)?;
    let rounded_end = end.checked_add(4095).ok_or(LOAD_ERROR)? & !4095;
    map_identity(tables, start, (rounded_end - start) / 4096, permissions)
}

fn map_identity(
    tables: &mut PageTableBuilder<FirmwarePageTables>,
    start: u64,
    pages: u64,
    permissions: PagePermissions,
) -> Result<(), Status> {
    if !start.is_multiple_of(4096) || pages == 0 {
        return Err(LOAD_ERROR);
    }
    for page in 0..pages {
        let address = start
            .checked_add(page.checked_mul(4096).ok_or(LOAD_ERROR)?)
            .ok_or(LOAD_ERROR)?;
        tables
            .map_page(
                VirtAddr::new(address).map_err(|_| LOAD_ERROR)?,
                PhysAddr::new(address).map_err(|_| LOAD_ERROR)?,
                permissions,
            )
            .map_err(|_| LOAD_ERROR)?;
    }
    Ok(())
}

unsafe fn exit_boot_services(
    image: Handle,
    services: &BootServices,
) -> Result<(usize, usize), Status> {
    let map = MEMORY_MAP.0.get().cast::<MemoryDescriptor>();
    let mut last_status = LOAD_ERROR;
    for _ in 0..3 {
        let mut map_size = MAP_BYTES;
        let mut map_key = 0usize;
        let mut descriptor_size = 0usize;
        let mut descriptor_version = 0u32;
        check(unsafe {
            (services.get_memory_map)(
                &mut map_size,
                map,
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        })?;
        if descriptor_size < core::mem::size_of::<MemoryDescriptor>()
            || map_size == 0
            || map_size > MAP_BYTES
            || !map_size.is_multiple_of(descriptor_size)
        {
            return Err(LOAD_ERROR);
        }
        last_status = unsafe { (services.exit_boot_services)(image, map_key) };
        if !status_is_error(last_status) {
            return Ok((map_size, descriptor_size));
        }
    }
    Err(last_status)
}

fn check(status: Status) -> Result<(), Status> {
    if status_is_error(status) {
        Err(status)
    } else {
        Ok(())
    }
}

fn paint(framebuffer: Framebuffer, rgb: [u8; 3]) {
    let pixels = framebuffer
        .stride
        .checked_mul(framebuffer.height)
        .unwrap_or(0) as usize;
    let bytes = pixels.checked_mul(4).unwrap_or(0).min(framebuffer.size);
    if bytes == 0 {
        return;
    }
    let encoded = if framebuffer.format == 0 {
        [rgb[0], rgb[1], rgb[2], 0]
    } else {
        [rgb[2], rgb[1], rgb[0], 0]
    };
    // SAFETY: GOP guarantees the framebuffer allocation described by the
    // active mode. Length is capped to both calculated geometry and the
    // firmware-reported allocation.
    let framebuffer =
        unsafe { core::slice::from_raw_parts_mut(framebuffer.base as *mut u8, bytes) };
    for pixel in framebuffer.as_chunks_mut::<4>().0 {
        pixel.copy_from_slice(&encoded);
    }
}

fn loader_trace(stage: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack))
    };
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
