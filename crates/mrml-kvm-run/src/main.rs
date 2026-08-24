#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(target_os = "linux")]
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};
use mrml_error::{Result, anyhow};
#[cfg(target_os = "linux")]
use mrml_kernel::arch::x86_64::{Mapping, PRIVILEGE_STACK_ARENA_PAGES, PagePermissions, VirtAddr};
#[cfg(target_os = "linux")]
use mrml_kernel::{
    ArtifactKind, CapabilitySpace, GPU_DOORBELL_PORT, GPU_QUEUE_MESSAGE_BYTES, GpuCommandRing,
    GpuQueueIdentity, GpuQueueReceiver, GpuResourceResponse, GpuResourceResponseSender,
    GpuSharedQueueLayout, GpuVmmQueueBridge, GuestMemory, HypercallRouter, InterruptPolicy,
    IoDirection, IoPortPolicy, IoPortRule, ObjectId, ResourceCommand, Rights,
    SIGNED_ARTIFACT_OVERHEAD_BYTES, SignedArtifact, TrustRoot, VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
    VIRTUAL_BLOCK_DOORBELL_PORT, VerifiedExecutable, VerifiedGpuKernelBundle, VirtualBlockBackend,
    VirtualBlockConfigurationPage, VirtualBlockDevice, VirtualBlockMutationError,
    VirtualBlockProcessOutcome, VirtualBlockQueueBridge, VirtualBlockQueueLayout,
    VirtualBlockResumePage, VmBackend, VmExit, VmTable, run_virtual_block_completion_ack_once,
    run_virtual_block_doorbell_once, verify_gpu_kernel_bundle,
};
#[cfg(any(test, target_os = "linux"))]
use mrml_kernel::{
    FramebufferInfo, MemoryKind, MemoryRegion, PhysAddr, PixelFormat, encode_handoff,
    encode_handoff_with_smp,
};
#[cfg(target_os = "linux")]
use mrml_kvm::{KvmLaunchLayout, KvmSystem, PreparedKvmGuest};
#[cfg(target_os = "linux")]
use mrml_runtime::Instant;
#[cfg(target_os = "linux")]
use mrml_runtime::mrml_println as println;

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
const MAX_KERNEL_BUNDLE: usize = SIGNED_ARTIFACT_OVERHEAD_BYTES + 16 * 1024 * 1024;
#[cfg(any(test, target_os = "linux"))]
const FRAMEBUFFER: u64 = 0x00a0_0000;
#[cfg(target_os = "linux")]
const EXCEPTION_PROBE_PORT: u16 = 0x4d53;
#[cfg(target_os = "linux")]
const TIMER_READY_PORT: u16 = 0x4d54;
#[cfg(target_os = "linux")]
const TIMER_TICK_PORT: u16 = 0x4d55;
#[cfg(target_os = "linux")]
const PREEMPTION_PROBE_PORT: u16 = 0x4d5b;
#[cfg(target_os = "linux")]
const USER_PROBE_PORT: u16 = 0x4d56;
#[cfg(target_os = "linux")]
const USER_CALL_PROBE_PORT: u16 = 0x4d57;
#[cfg(target_os = "linux")]
const SERVICE_PROBE_PORT: u16 = 0x4d58;
#[cfg(target_os = "linux")]
const SERVICE_FRAME_PORT: u16 = 0x4d59;
#[cfg(target_os = "linux")]
const SERVICE_CALL_PORT: u16 = 0x4d5a;
#[cfg(target_os = "linux")]
const SMP_PROBE_PORT: u16 = 0x4d5c;
#[cfg(target_os = "linux")]
const SERVICE_PHYSICAL: u64 = 0x0060_0000;
#[cfg(target_os = "linux")]
const SERVICE_VIRTUAL: u64 = 0x0000_0001_4000_0000;
#[cfg(target_os = "linux")]
const SERVICE_STACK_PHYSICAL: u64 = 0x0080_0000;
#[cfg(target_os = "linux")]
const SERVICE_STACK_VIRTUAL: u64 = 0x0070_0000;
#[cfg(target_os = "linux")]
const SERVICE_TABLE_PHYSICAL: u64 = 0x00c0_0000;
#[cfg(target_os = "linux")]
const SERVICE_B_PHYSICAL: u64 = 0x0090_0000;
#[cfg(target_os = "linux")]
const SERVICE_B_STACK_PHYSICAL: u64 = 0x00e0_0000;
#[cfg(target_os = "linux")]
const SERVICE_B_TABLE_PHYSICAL: u64 = 0x00d0_0000;
#[cfg(target_os = "linux")]
const SERVICE_C_PHYSICAL: u64 = 0x0130_0000;
#[cfg(target_os = "linux")]
const SERVICE_C_TABLE_PHYSICAL: u64 = 0x0140_0000;
#[cfg(target_os = "linux")]
const SERVICE_C_STACK_PHYSICAL: u64 = 0x0150_0000;
#[cfg(target_os = "linux")]
const SERVICE_SHARED_PHYSICAL: u64 = 0x00f0_0000;
#[cfg(target_os = "linux")]
const SERVICE_SHARED_VIRTUAL: u64 = 0x006f_e000;
#[cfg(target_os = "linux")]
const SERVICE_RESOURCE_PHYSICAL: u64 = 0x00f0_1000;
#[cfg(target_os = "linux")]
const SERVICE_RESOURCE_VIRTUAL: u64 = 0x006f_f000;
#[cfg(target_os = "linux")]
const BLOCK_PROOF_PORT: u16 = 0x4d65;
#[cfg(target_os = "linux")]
const BLOCK_PROBE_CYCLES: usize = 8;
#[cfg(target_os = "linux")]
const BLOCK_PROBE_OPERATIONS: u32 = (BLOCK_PROBE_CYCLES * 4) as u32;
#[cfg(target_os = "linux")]
const BLOCK_QUIESCE_WINDOW: usize = BLOCK_PROBE_CYCLES - 2;
#[cfg(target_os = "linux")]
const BLOCK_QUIESCE_REQUESTS: u32 = (BLOCK_QUIESCE_WINDOW * 2 + 2) as u32;
#[cfg(target_os = "linux")]
const BLOCK_QUIESCE_RETIRED: u32 = BLOCK_QUIESCE_REQUESTS - 2;
#[cfg(target_os = "linux")]
const BLOCK_PROBE_POLICY_EXITS: u64 = (BLOCK_PROBE_CYCLES * 8) as u64;
#[cfg(target_os = "linux")]
const BLOCK_CONFIGURATION_BASE: u64 = 0x0060_4000;
#[cfg(target_os = "linux")]
const BLOCK_RESUME_BASE: u64 = 0x0060_5000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
enum LaunchMode {
    Boot,
    FaultProbe,
    TimerProbe,
    PreemptionProbe,
    UserProbe,
    ServiceProbe,
    BlockServiceProbe,
    BlockGuestDriverProbe,
    ServiceRestartRequestProbe,
    ServicePreemptionProbe,
    GpuBenchmark,
    SmpProbe,
    SmpSchedulerProbe,
    SmpIpiProbe,
    SmpServiceMigrationProbe,
    SmpPeriodicBalanceProbe,
}

#[cfg(any(test, target_os = "linux"))]
impl LaunchMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "boot" => Ok(Self::Boot),
            "fault-probe" => Ok(Self::FaultProbe),
            "timer-probe" => Ok(Self::TimerProbe),
            "preemption-probe" => Ok(Self::PreemptionProbe),
            "user-probe" => Ok(Self::UserProbe),
            "service-probe" => Ok(Self::ServiceProbe),
            "block-service-probe" => Ok(Self::BlockServiceProbe),
            "block-guest-driver-probe" => Ok(Self::BlockGuestDriverProbe),
            "service-restart-request-probe" => Ok(Self::ServiceRestartRequestProbe),
            "service-preemption-probe" => Ok(Self::ServicePreemptionProbe),
            "gpu-benchmark" => Ok(Self::GpuBenchmark),
            "smp-probe" => Ok(Self::SmpProbe),
            "smp-scheduler-probe" => Ok(Self::SmpSchedulerProbe),
            "smp-ipi-probe" => Ok(Self::SmpIpiProbe),
            "smp-service-migration-probe" => Ok(Self::SmpServiceMigrationProbe),
            "smp-periodic-balance-probe" => Ok(Self::SmpPeriodicBalanceProbe),
            _ => Err(anyhow!(
                "mode must be boot, fault-probe, timer-probe, preemption-probe, user-probe, service-probe, block-service-probe, block-guest-driver-probe, service-restart-request-probe, service-preemption-probe, gpu-benchmark, smp-probe, smp-scheduler-probe, smp-ipi-probe, smp-service-migration-probe, or smp-periodic-balance-probe"
            )),
        }
    }
}

#[cfg(target_os = "linux")]
struct DriverProbeBlock([u8; 8192]);

#[cfg(target_os = "linux")]
unsafe impl VirtualBlockBackend for DriverProbeBlock {
    type Error = ();

    fn read_blocks(
        &mut self,
        block: u64,
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        let start = usize::try_from(block)
            .ok()
            .and_then(|block| block.checked_mul(4096))
            .ok_or(())?;
        let end = start.checked_add(output.len()).ok_or(())?;
        let source = self.0.get(start..end).ok_or(())?;
        if output.len() != 4096 {
            return Err(());
        }
        output.copy_from_slice(source);
        Ok(())
    }

    fn write_blocks(
        &mut self,
        block: u64,
        input: &[u8],
    ) -> core::result::Result<(), VirtualBlockMutationError<Self::Error>> {
        let start = usize::try_from(block)
            .ok()
            .and_then(|block| block.checked_mul(4096))
            .ok_or(VirtualBlockMutationError::Rejected(()))?;
        let end = start
            .checked_add(input.len())
            .ok_or(VirtualBlockMutationError::Rejected(()))?;
        if input.len() != 4096 {
            return Err(VirtualBlockMutationError::Rejected(()));
        }
        let destination = self
            .0
            .get_mut(start..end)
            .ok_or(VirtualBlockMutationError::Rejected(()))?;
        destination.copy_from_slice(input);
        Ok(())
    }

    fn flush(&mut self) -> core::result::Result<(), VirtualBlockMutationError<Self::Error>> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn block_configuration(
    layout: VirtualBlockQueueLayout,
) -> Result<mrml_kernel::VirtualBlockConfiguration> {
    let mut device = VirtualBlockDevice::<2>::new(4096, 2, 0)
        .map_err(|_| anyhow!("invalid block probe geometry"))?;
    device
        .negotiate(0)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("invalid block probe configuration"))?;
    device
        .configuration()
        .map_err(|_| anyhow!("block probe configuration is unavailable"))
}

#[cfg(target_os = "linux")]
fn run_block_guest_driver_probe(
    mut guest: PreparedKvmGuest<16>,
    system: &KvmSystem,
    executable: &VerifiedExecutable<'_>,
    handoff: &[u8],
    launch_layout: KvmLaunchLayout,
    layout: VirtualBlockQueueLayout,
) -> Result<()> {
    let interrupt_object = ObjectId(0x301);
    let mut capabilities = CapabilitySpace::<1>::new();
    let interrupt_capability = capabilities
        .insert(interrupt_object, Rights::SIGNAL)
        .map_err(|_| anyhow!("failed to create block interrupt capability"))?;
    let mut interrupt_policy = InterruptPolicy::deny_all();
    interrupt_policy
        .allow(48)
        .map_err(|_| anyhow!("failed to allow block interrupt vector"))?;
    let mut io_policy = IoPortPolicy::<2>::deny_all();
    io_policy
        .allow(
            IoPortRule::new(VIRTUAL_BLOCK_DOORBELL_PORT, 4, IoDirection::Write)
                .map_err(|_| anyhow!("invalid block doorbell policy"))?,
        )
        .and_then(|()| {
            IoPortRule::new(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, IoDirection::Write)
                .and_then(|rule| io_policy.allow(rule))
        })
        .map_err(|_| anyhow!("failed to install block I/O policy"))?;
    let mut vms = VmTable::<1>::new();
    let vm = vms
        .create(BLOCK_PROBE_POLICY_EXITS)
        .map_err(|_| anyhow!("failed to create block VM state"))?;
    vms.mark_loaded(vm)
        .and_then(|()| vms.start(vm))
        .map_err(|_| anyhow!("failed to start block VM policy state"))?;
    let mut router = HypercallRouter::new(ObjectId(0x302), ObjectId(0x303), ObjectId(0x304));
    let guest_memory = GuestMemory::<0>::new();
    let mut device =
        VirtualBlockDevice::<2>::new(4096, 2, 0).map_err(|_| anyhow!("invalid block device"))?;
    device
        .negotiate(0)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("failed to activate block device"))?;
    let mut bridge = VirtualBlockQueueBridge::<2>::new(layout)
        .map_err(|_| anyhow!("failed to bind block queue bridge"))?;
    let mut storage = DriverProbeBlock([0; 8192]);
    let mut scratch = [0; 4096];

    for window in 0..(BLOCK_PROBE_CYCLES * 2) {
        for offset in 0..2 {
            let operation = window * 2 + offset;
            let outcome = match run_virtual_block_doorbell_once(
                &mut guest,
                &mut storage,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io_policy,
                &interrupt_policy,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let state = guest.snapshot().map_err(|snapshot| {
                        anyhow!(
                            "block doorbell {} failed: {:?}; snapshot failed: {:?}",
                            operation + 1,
                            error,
                            snapshot
                        )
                    })?;
                    return Err(anyhow!(
                        "block doorbell {} failed: {:?}; rip={:#x} rsp={:#x} cr2={:#x} cr3={:#x}",
                        operation + 1,
                        error,
                        state.instruction_pointer(),
                        state.stack_pointer(),
                        state.fault_address(),
                        state.page_table_root()
                    ));
                }
            };
            if !matches!(outcome, VirtualBlockProcessOutcome::Completed(_)) {
                return Err(anyhow!(
                    "block operation {} was not completed",
                    operation + 1
                ));
            }
        }
        if window == BLOCK_QUIESCE_WINDOW {
            let configuration = device
                .configuration()
                .map_err(|_| anyhow!("block configuration unavailable at quiescence"))?;
            let configuration_page =
                VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, configuration)
                    .map_err(|_| anyhow!("invalid block configuration at quiescence"))?;
            let resume_page = VirtualBlockResumePage::fresh(BLOCK_RESUME_BASE, configuration_page)
                .map_err(|_| anyhow!("invalid block resume page at quiescence"))?;
            device
                .suspend()
                .map_err(|_| anyhow!("block device did not quiesce exactly"))?;
            let published = bridge
                .publish_resume_page(&mut guest, &device, resume_page)
                .map_err(|error| anyhow!("block resume publication failed: {:?}", error))?;
            let state = published.state();
            if state.request_producer() != u64::from(BLOCK_QUIESCE_REQUESTS)
                || state.request_consumed() != u64::from(BLOCK_QUIESCE_REQUESTS)
                || state.completion_published() != u64::from(BLOCK_QUIESCE_REQUESTS)
                || state.completion_consumer() != u64::from(BLOCK_QUIESCE_RETIRED)
                || state.last_admitted_request_id() != u64::from(BLOCK_QUIESCE_REQUESTS)
                || state.last_published_request_id() != u64::from(BLOCK_QUIESCE_REQUESTS)
            {
                return Err(anyhow!("block quiescence state mismatch"));
            }
            let restart_image = bridge
                .capture_restart_image(&guest, &device, published)
                .map_err(|error| anyhow!("block restart snapshot failed: {:?}", error))?;
            drop(guest);
            // SAFETY: `guest` owned the exact captured native VM and has been
            // consumed and destroyed. No native execution can resume or seed
            // another replacement; the same device and bridge stay suspended.
            let lost_execution = unsafe { restart_image.confirm_execution_loss() };
            let configuration_page =
                VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, configuration)
                    .map_err(|_| anyhow!("invalid replacement block configuration page"))?;
            let mut replacement = system
                .prepare_kernel_block_guest::<16>(
                    0,
                    executable,
                    handoff,
                    launch_layout,
                    layout,
                    configuration_page,
                    VirtualBlockResumePage::fresh(BLOCK_RESUME_BASE, configuration_page)
                        .map_err(|_| anyhow!("invalid replacement block resume page"))?,
                )
                .map_err(|error| anyhow!("replacement block VM preparation failed: {:?}", error))?;
            let mut fresh_payload_pages = [0; 8192];
            VmBackend::read_guest(&replacement, FRAMEBUFFER, &mut fresh_payload_pages)
                .map_err(|_| anyhow!("replacement block payload validation failed"))?;
            if fresh_payload_pages.iter().any(|byte| *byte != 0) {
                return Err(anyhow!("replacement block payload was not fresh"));
            }
            bridge
                .restore_restart_image(&mut replacement, &device, lost_execution)
                .map_err(|error| {
                    anyhow!("replacement block VM state restoration failed: {:?}", error)
                })?;
            guest = replacement;
            device
                .resume()
                .map_err(|_| anyhow!("block device did not resume exactly"))?;
        }
        for offset in 0..2 {
            let operation = window * 2 + offset;
            let acknowledgement = match run_virtual_block_completion_ack_once(
                &mut guest,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io_policy,
                &mut device,
                &mut bridge,
            ) {
                Ok(acknowledgement) => acknowledgement,
                Err(error) => {
                    let state = guest.snapshot().map_err(|snapshot| {
                        anyhow!(
                            "block acknowledgement {} failed: {:?}; snapshot failed: {:?}",
                            operation + 1,
                            error,
                            snapshot
                        )
                    })?;
                    return Err(anyhow!(
                        "block acknowledgement {} failed: {:?}; rip={:#x} rsp={:#x} cr2={:#x} cr3={:#x}",
                        operation + 1,
                        error,
                        state.instruction_pointer(),
                        state.stack_pointer(),
                        state.fault_address(),
                        state.page_table_root()
                    ));
                }
            };
            if acknowledgement != (operation + 1) as u64 {
                return Err(anyhow!("block acknowledgement position mismatch"));
            }
        }
    }
    let final_cycle = (BLOCK_PROBE_CYCLES - 1) as u8;
    if storage.0[..4096] != [0x40 + final_cycle; 4096]
        || storage.0[4096..] != [0x90 + final_cycle; 4096]
    {
        return Err(anyhow!("block backend payload mismatch"));
    }
    let proof = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("block proof execution failed: {:?}", error))?;
    if proof
        != (VmExit::Io {
            port: BLOCK_PROOF_PORT,
            size: 4,
            write: true,
            value: BLOCK_PROBE_OPERATIONS,
        })
    {
        return Err(anyhow!("block common-driver proof mismatch: {:?}", proof));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
fn application_main() -> Result<()> {
    let total_started = Instant::now();
    let arguments = mrml_runtime::command_arguments();
    if arguments.len() == 3 && arguments[1] == "--export-cuda-bundle" {
        mrml_runtime::write_file(&arguments[2], mrml_tensor::cuda::embedded_cuda_bundle())?;
        println!("wrote exact embedded CUDA PTX bundle to {}", arguments[2]);
        return Ok(());
    }
    if arguments.len() != 5 && arguments.len() != 8 {
        return Err(anyhow!(
            "usage: mrml-kvm-run KERNEL.signed RELEASE.public MINIMUM_VERSION MODE [CUDA.signed CUDA.public CUDA_MINIMUM_VERSION]\n       mrml-kvm-run --export-cuda-bundle OUTPUT.ptx"
        ));
    }
    let minimum_version = arguments[3]
        .parse::<u64>()
        .ok()
        .filter(|version| *version != 0)
        .ok_or_else(|| anyhow!("minimum version must be a nonzero integer"))?;
    let mode = LaunchMode::parse(&arguments[4])?;
    if matches!(
        mode,
        LaunchMode::GpuBenchmark
            | LaunchMode::ServiceProbe
            | LaunchMode::BlockServiceProbe
            | LaunchMode::ServiceRestartRequestProbe
            | LaunchMode::ServicePreemptionProbe
            | LaunchMode::SmpServiceMigrationProbe
    ) != (arguments.len() == 8)
    {
        return Err(anyhow!(
            "gpu-benchmark and service modes require exactly one matching signed artifact, public key, and minimum version"
        ));
    }
    let bundle = mrml_runtime::read_file_bounded(&arguments[1], MAX_KERNEL_BUNDLE)?;
    let public = mrml_runtime::read_file_bounded(&arguments[2], LAMPORT_PUBLIC_KEY_BYTES)?;
    if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
        return Err(anyhow!("invalid release public-key length"));
    }
    let verification_started = Instant::now();
    let root = TrustRoot::new(
        ArtifactKind::Kernel,
        Sha3_512::digest(&public),
        minimum_version,
    );
    let signed = SignedArtifact::decode(&bundle).map_err(|_| anyhow!("invalid signed bundle"))?;
    let executable = signed
        .verify_executable(&root, ArtifactKind::Kernel)
        .map_err(|_| anyhow!("kernel signature or PE policy rejected"))?;
    let service_mode = matches!(
        mode,
        LaunchMode::ServiceProbe
            | LaunchMode::BlockServiceProbe
            | LaunchMode::ServiceRestartRequestProbe
            | LaunchMode::ServicePreemptionProbe
            | LaunchMode::SmpServiceMigrationProbe
    );
    let service_bundle = if service_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[5],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + mrml_kernel::MAX_SERVICE_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let service_public = if service_mode {
        let public = mrml_runtime::read_file_bounded(&arguments[6], LAMPORT_PUBLIC_KEY_BYTES)?;
        if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(anyhow!("invalid service public-key length"));
        }
        Some(public)
    } else {
        None
    };
    let service_executable = match (&service_bundle, &service_public) {
        (Some(bundle), Some(public)) => {
            let minimum = arguments[7]
                .parse::<u64>()
                .ok()
                .filter(|version| *version != 0)
                .ok_or_else(|| anyhow!("service minimum version must be nonzero"))?;
            let root = TrustRoot::new(
                ArtifactKind::ServiceImage,
                Sha3_512::digest(public),
                minimum,
            );
            let signed = SignedArtifact::decode(bundle)
                .map_err(|_| anyhow!("invalid signed service bundle"))?;
            Some(
                signed
                    .verify_executable(&root, ArtifactKind::ServiceImage)
                    .map_err(|_| anyhow!("service signature or PE policy rejected"))?,
            )
        }
        (None, None) => None,
        _ => return Err(anyhow!("incomplete service verification inputs")),
    };
    let cuda_bundle = if mode == LaunchMode::GpuBenchmark {
        Some(verify_cuda_bundle(
            &arguments[5],
            &arguments[6],
            &arguments[7],
        )?)
    } else {
        None
    };
    let verification_micros = verification_started.elapsed().as_micros();
    let mut entropy = [0u8; 32];
    mrml_runtime::fill_random(&mut entropy)
        .map_err(|_| anyhow!("operating-system boot entropy failed"))?;
    let smp_mode = matches!(
        mode,
        LaunchMode::SmpProbe
            | LaunchMode::SmpSchedulerProbe
            | LaunchMode::SmpIpiProbe
            | LaunchMode::SmpServiceMigrationProbe
            | LaunchMode::SmpPeriodicBalanceProbe
    );
    let handoff = if smp_mode {
        smp_boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
        )?
    } else {
        boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
            u64::from(mode == LaunchMode::BlockGuestDriverProbe) + 1,
        )?
    };
    let user_probe = matches!(mode, LaunchMode::UserProbe | LaunchMode::PreemptionProbe);
    let (image_virtual, handoff_virtual, stack_virtual) = if smp_mode {
        (0xffff_8001_4000_0000, 0xffff_8001_5000_0000, 0x100_0000)
    } else if user_probe {
        (0x0040_0000, 0x0200_0000, 0xffff_8001_6000_0000)
    } else {
        (
            0xffff_8001_4000_0000,
            0xffff_8001_5000_0000,
            0xffff_8001_6000_0000,
        )
    };
    let table_pages = if matches!(
        mode,
        LaunchMode::SmpIpiProbe
            | LaunchMode::SmpServiceMigrationProbe
            | LaunchMode::SmpPeriodicBalanceProbe
    ) {
        64
    } else {
        32
    };
    let layout = KvmLaunchLayout::new(
        0x10_0000,
        table_pages,
        0x20_0000,
        image_virtual,
        0x50_0000,
        handoff_virtual,
        0x100_0000,
        stack_virtual,
        PRIVILEGE_STACK_ARENA_PAGES,
        user_probe,
    )
    .map_err(|_| anyhow!("invalid fixed kernel launch layout"))?;
    let system = KvmSystem::open()
        .map_err(|error| anyhow!("KVM is unavailable or incompatible: {:?}", error))?;
    let preparation_started = Instant::now();
    let queue_layout = GpuSharedQueueLayout::new(0x00b0_0000, 0x00b0_1000, 1)
        .map_err(|_| anyhow!("invalid fixed GPU queue layout"))?;
    let block_layout = VirtualBlockQueueLayout::new(0x0060_0000, 0x0060_2000, 2)
        .map_err(|_| anyhow!("invalid fixed block queue layout"))?;
    let block_configuration = block_configuration(block_layout)?;
    let mut guest = match mode {
        LaunchMode::GpuBenchmark => system.prepare_kernel_gpu_guest::<16>(
            0,
            &executable,
            handoff.as_slice(),
            layout,
            queue_layout,
        ),
        LaunchMode::BlockGuestDriverProbe => system.prepare_kernel_block_guest::<16>(
            0,
            &executable,
            handoff.as_slice(),
            layout,
            block_layout,
            VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, block_configuration)
                .map_err(|_| anyhow!("invalid block configuration page"))?,
            VirtualBlockResumePage::fresh(
                BLOCK_RESUME_BASE,
                VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, block_configuration)
                    .map_err(|_| anyhow!("invalid block configuration page"))?,
            )
            .map_err(|_| anyhow!("invalid block resume page"))?,
        ),
        LaunchMode::TimerProbe
        | LaunchMode::PreemptionProbe
        | LaunchMode::ServicePreemptionProbe => {
            system.prepare_timer_kernel_guest::<16>(0, &executable, handoff.as_slice(), layout)
        }
        LaunchMode::SmpProbe
        | LaunchMode::SmpSchedulerProbe
        | LaunchMode::SmpIpiProbe
        | LaunchMode::SmpServiceMigrationProbe
        | LaunchMode::SmpPeriodicBalanceProbe => {
            system.prepare_smp_kernel_guest::<16>(&executable, handoff.as_slice(), layout)
        }
        LaunchMode::ServiceProbe
        | LaunchMode::BlockServiceProbe
        | LaunchMode::ServiceRestartRequestProbe => system
            .prepare_isolated_service_kernel_guest::<16>(
                0,
                &executable,
                handoff.as_slice(),
                layout,
            ),
        _ => system.prepare_kernel_guest::<16>(0, &executable, handoff.as_slice(), layout),
    }
    .map_err(|error| anyhow!("verified kernel launch preparation failed: {:?}", error))?;
    if service_mode {
        let local_apic = matches!(
            mode,
            LaunchMode::ServicePreemptionProbe | LaunchMode::SmpServiceMigrationProbe
        );
        guest = guest
            .attach_isolated_service_at(
                0,
                &executable,
                layout,
                service_executable
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing verified service executable"))?,
                SERVICE_PHYSICAL,
                SERVICE_VIRTUAL,
                SERVICE_STACK_PHYSICAL,
                SERVICE_STACK_VIRTUAL,
                8,
                SERVICE_TABLE_PHYSICAL,
                32,
                local_apic,
            )
            .map_err(|error| anyhow!("isolated service preparation failed: {:?}", error))?;
        guest = guest
            .attach_isolated_service_at(
                1,
                &executable,
                layout,
                service_executable
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing verified service executable"))?,
                SERVICE_B_PHYSICAL,
                SERVICE_VIRTUAL,
                SERVICE_B_STACK_PHYSICAL,
                SERVICE_STACK_VIRTUAL,
                8,
                SERVICE_B_TABLE_PHYSICAL,
                32,
                local_apic,
            )
            .map_err(|error| anyhow!("second isolated service preparation failed: {:?}", error))?;
        if matches!(
            mode,
            LaunchMode::ServiceProbe | LaunchMode::ServiceRestartRequestProbe
        ) {
            guest = guest
                .attach_isolated_service_at(
                    2,
                    &executable,
                    layout,
                    service_executable
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing verified service executable"))?,
                    SERVICE_C_PHYSICAL,
                    SERVICE_VIRTUAL,
                    SERVICE_C_STACK_PHYSICAL,
                    SERVICE_STACK_VIRTUAL,
                    8,
                    SERVICE_C_TABLE_PHYSICAL,
                    32,
                    local_apic,
                )
                .map_err(|error| {
                    anyhow!("third isolated service preparation failed: {:?}", error)
                })?;
        }
        let shared = Mapping::new(
            VirtAddr::new(SERVICE_SHARED_VIRTUAL)
                .map_err(|_| anyhow!("invalid service shared virtual address"))?,
            PhysAddr::new(SERVICE_SHARED_PHYSICAL)
                .map_err(|_| anyhow!("invalid service shared physical address"))?,
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .map_err(|_| anyhow!("invalid service shared-page mapping"))?;
        guest = guest
            .attach_service_shared_page(shared)
            .map_err(|error| anyhow!("service shared-page attachment failed: {:?}", error))?;
        let resource = Mapping::new(
            VirtAddr::new(SERVICE_RESOURCE_VIRTUAL)
                .map_err(|_| anyhow!("invalid service resource virtual address"))?,
            PhysAddr::new(SERVICE_RESOURCE_PHYSICAL)
                .map_err(|_| anyhow!("invalid service resource physical address"))?,
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .map_err(|_| anyhow!("invalid service resource-page mapping"))?;
        guest = guest
            .attach_service_resource_page(0, resource)
            .map_err(|error| anyhow!("service resource-page attachment failed: {:?}", error))?;
        let service_entry = guest
            .service_entry()
            .ok_or_else(|| anyhow!("missing KVM service entry"))?;
        if guest.service_page_table_root() != PhysAddr::new(SERVICE_TABLE_PHYSICAL).ok()
            || guest.service_entry_at(1) != Some(service_entry)
            || guest.service_page_table_root_at(1) != PhysAddr::new(SERVICE_B_TABLE_PHYSICAL).ok()
            || (matches!(
                mode,
                LaunchMode::ServiceProbe | LaunchMode::ServiceRestartRequestProbe
            ) && (guest.service_entry_at(2) != Some(service_entry)
                || guest.service_page_table_root_at(2)
                    != PhysAddr::new(SERVICE_C_TABLE_PHYSICAL).ok()))
        {
            return Err(anyhow!(
                "isolated service layout did not match the signed probe ABI"
            ));
        }
        VmBackend::write_guest(
            &mut guest,
            SERVICE_SHARED_PHYSICAL + 8,
            &service_entry.to_le_bytes(),
        )
        .map_err(|_| anyhow!("failed to publish KVM service entry"))?;
    }
    let preparation_micros = preparation_started.elapsed().as_micros();
    let execution_started = Instant::now();
    if mode == LaunchMode::BlockGuestDriverProbe {
        run_block_guest_driver_probe(
            guest,
            &system,
            &executable,
            handoff.as_slice(),
            layout,
            block_layout,
        )?;
        println!(
            "verified signed compiled eight-cycle two-slot common block guest driver under KVM: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    let mut exit = if smp_mode {
        let (bootstrap, application) = guest
            .run_smp()
            .map_err(|error| anyhow!("KVM SMP execution failed: {:?}", error))?;
        let scheduler_probe = mode == LaunchMode::SmpSchedulerProbe;
        let ipi_probe = mode == LaunchMode::SmpIpiProbe;
        let service_migration_probe = mode == LaunchMode::SmpServiceMigrationProbe;
        let expected_bootstrap = VmExit::Io {
            port: if mode == LaunchMode::SmpPeriodicBalanceProbe {
                0x4d64
            } else if scheduler_probe {
                0x4d5e
            } else if ipi_probe || service_migration_probe {
                0x4d60
            } else {
                SMP_PROBE_PORT
            },
            size: 4,
            write: true,
            value: 2,
        };
        let expected_application = VmExit::Io {
            port: if mode == LaunchMode::SmpPeriodicBalanceProbe {
                0x4d63
            } else if scheduler_probe {
                0x4d5f
            } else if ipi_probe {
                0x4d61
            } else if service_migration_probe {
                0x4d62
            } else {
                SMP_PROBE_PORT
            },
            size: 4,
            write: true,
            value: if mode == LaunchMode::SmpPeriodicBalanceProbe {
                0x0001_0002
            } else {
                0x0001_0001
            },
        };
        if bootstrap != expected_bootstrap || application != expected_application {
            return Err(anyhow!(
                "SMP proof mismatch: bootstrap={:?} application={:?}",
                bootstrap,
                application
            ));
        }
        VmExit::Halted
    } else {
        VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution failed: {:?}", error))?
    };
    if mode == LaunchMode::GpuBenchmark {
        service_gpu_benchmark(
            &mut guest,
            queue_layout,
            handoff_entropy(handoff.as_slice())?,
            cuda_bundle
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified CUDA bundle"))?,
            exit,
        )?;
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after GPU completion failed: {:?}", error))?;
    } else if mode == LaunchMode::FaultProbe {
        if exit
            != (VmExit::Io {
                port: EXCEPTION_PROBE_PORT,
                size: 4,
                write: true,
                value: 6,
            })
        {
            return Err(anyhow!(
                "fault probe did not reach the checked invalid-opcode dispatcher: {:?}",
                exit
            ));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after exception probe failed: {:?}", error))?;
    } else if mode == LaunchMode::ServicePreemptionProbe {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "service preemption probe did not initialize: {:?}",
                exit
            ));
        }
        for stage in [0x2320u32, 1, 2, 3, 4, 5, 6] {
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM service preemption failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: PREEMPTION_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "service preemption stage {:#x} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
        }
        exit = VmExit::Halted;
    } else if mode == LaunchMode::PreemptionProbe {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!("preemption probe did not enter CPL3: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM timer frame capture failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: PREEMPTION_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x2320,
            })
        {
            return Err(anyhow!("timer frame was not vector 32 at CPL3: {:?}", exit));
        }
        println!("validated CPL3 timer frame");
        for stage in 1u32..=6 {
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM preemption stage {} failed: {:?}", stage, error))?;
            if exit
                != (VmExit::Io {
                    port: PREEMPTION_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                let state = guest
                    .snapshot()
                    .map_err(|error| anyhow!("preemption failure snapshot failed: {:?}", error))?;
                return Err(anyhow!(
                    "timer preemption stage {} mismatch: {:?}, rip={:#x} rsp={:#x} cr2={:#x} cr3={:#x}",
                    stage,
                    exit,
                    state.instruction_pointer(),
                    state.stack_pointer(),
                    state.fault_address(),
                    state.page_table_root()
                ));
            }
            println!("validated preemption stage {}", stage);
        }
        exit = VmExit::Halted;
    } else if mode == LaunchMode::TimerProbe {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "timer probe did not reach its interruptible wait: {:?}",
                exit
            ));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "KVM execution waiting for local counter failed: {:?}",
                error
            )
        })?;
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 2,
            })
        {
            return Err(anyhow!("local APIC counter did not elapse: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution delivering local timer failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: TIMER_TICK_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "timer probe did not execute one scheduler tick: {:?}",
                exit
            ));
        }
        // The authenticated timer output is the terminal proof. A KVM guest
        // with an in-kernel interrupt controller can remain blocked in HLT,
        // so do not require a subsequent host-visible halt exit.
        exit = VmExit::Halted;
    } else if mode == LaunchMode::UserProbe {
        if exit
            != (VmExit::Io {
                port: USER_CALL_PROBE_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "user probe did not complete capability IPC through vector 0x80: {:?}",
                exit
            ));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after user call failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: USER_PROBE_PORT,
                size: 4,
                write: true,
                value: 3,
            })
        {
            return Err(anyhow!(
                "user probe did not return through the checked ring-three fault path: {:?}",
                exit
            ));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after user proof failed: {:?}", error))?;
    } else if mode == LaunchMode::BlockServiceProbe {
        let cleanup_stages = [0x21, 0x31, 0x20, 0x30];
        let mut cleanup_stage = 0;
        for _ in 0..32 {
            if let VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value,
            } = exit
            {
                if cleanup_stages.get(cleanup_stage).copied() != Some(value) {
                    return Err(anyhow!(
                        "KVM block-service cleanup stage mismatch: {:?}",
                        exit
                    ));
                }
                cleanup_stage += 1;
                if value == 0x30 {
                    println!(
                        "verified independently signed CPL3 block-service loop and lifecycle cleanup under KVM: verify={}us prepare={}us execute={}us total={}us",
                        verification_micros,
                        preparation_micros,
                        execution_started.elapsed().as_micros(),
                        total_started.elapsed().as_micros()
                    );
                    return Ok(());
                }
            }
            if !matches!(
                exit,
                VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 1..=3,
                }
            ) && !matches!(
                exit,
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    ..
                }
            ) {
                return Err(anyhow!("KVM block-service stage mismatch: {:?}", exit));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM block-service execution failed: {:?}", error))?;
        }
        return Err(anyhow!("KVM block-service probe exceeded its stage bound"));
    } else if matches!(
        mode,
        LaunchMode::ServiceProbe | LaunchMode::ServiceRestartRequestProbe
    ) {
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!("isolated receiver did not block: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution during service send failed: {:?}", error))?;
        if mode == LaunchMode::ServiceRestartRequestProbe {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 1,
                })
            {
                return Err(anyhow!(
                    "isolated restart manager did not block: {:?}",
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("KVM execution after manager block failed: {:?}", error)
            })?;
        }
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: 2,
            })
        {
            return Err(anyhow!("isolated service send failed: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!("KVM execution entering sender cleanup failed: {:?}", error)
        })?;
        let configuration_stages: &[u32] = &[1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3];
        for &stage in configuration_stages {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "KVM configuration response stage {} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("KVM configuration response execution failed: {:?}", error)
            })?;
        }
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x21,
            })
        {
            return Err(anyhow!("KVM sender cleanup request mismatch: {:?}", exit));
        }
        complete_kvm_service_cleanup(
            &mut guest,
            1,
            SERVICE_B_STACK_PHYSICAL,
            SERVICE_B_TABLE_PHYSICAL,
            &executable,
            service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified service executable"))?,
        )?;
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after sender cleanup failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x22,
            })
        {
            return Err(anyhow!("KVM typed peer-death proof mismatch: {:?}", exit));
        }
        if mode == LaunchMode::ServiceRestartRequestProbe {
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM restart request execution failed: {:?}", error))?;
            for stage in [3u32, 2, 1, 2, 1] {
                if exit
                    != (VmExit::Io {
                        port: SERVICE_CALL_PORT,
                        size: 4,
                        write: true,
                        value: stage,
                    })
                {
                    return Err(anyhow!(
                        "KVM restart IPC stage {} mismatch: {:?}",
                        stage,
                        exit
                    ));
                }
                exit = VmBackend::run(&mut guest, 0)
                    .map_err(|error| anyhow!("KVM restart IPC execution failed: {:?}", error))?;
            }
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x24,
                })
            {
                return Err(anyhow!(
                    "KVM trusted restart-plan stage mismatch: {:?}",
                    exit
                ));
            }
            guest
                .restore_service_shared_page(1)
                .map_err(|error| anyhow!("failed to re-arm KVM sender page: {:?}", error))?;
            for stage in [2u32, 3] {
                exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                    anyhow!("KVM restart completion execution failed: {:?}", error)
                })?;
                if exit
                    != (VmExit::Io {
                        port: SERVICE_CALL_PORT,
                        size: 4,
                        write: true,
                        value: stage,
                    })
                {
                    return Err(anyhow!(
                        "KVM restart completion stage {} mismatch: {:?}",
                        stage,
                        exit
                    ));
                }
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM manager completion fault failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_FRAME_PORT,
                    size: 4,
                    write: true,
                    value: 0x001b_2303,
                })
            {
                return Err(anyhow!("KVM manager frame mismatch: {:?}", exit));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM restart proof completion failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x25,
                })
            {
                return Err(anyhow!("KVM restart proof mismatch: {:?}", exit));
            }
            println!(
                "verified authorized CPL3 restart request under KVM: verify={}us prepare={}us execute={}us total={}us",
                verification_micros,
                preparation_micros,
                execution_started.elapsed().as_micros(),
                total_started.elapsed().as_micros()
            );
            return Ok(());
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after typed peer death failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: 3,
            })
        {
            return Err(anyhow!("isolated service receive failed: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after service IPC failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_FRAME_PORT,
                size: 4,
                write: true,
                value: 0x001b_2303,
            })
        {
            return Err(anyhow!(
                "isolated service produced a malformed privilege frame: {:?}",
                exit
            ));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "KVM execution entering receiver cleanup failed: {:?}",
                error
            )
        })?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x20,
            })
        {
            return Err(anyhow!("KVM receiver cleanup request mismatch: {:?}", exit));
        }
        complete_kvm_service_cleanup(
            &mut guest,
            0,
            SERVICE_STACK_PHYSICAL,
            SERVICE_TABLE_PHYSICAL,
            &executable,
            service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified service executable"))?,
        )?;
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution after receiver cleanup failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 3,
            })
        {
            let state = guest
                .snapshot()
                .map_err(|error| anyhow!("service failure snapshot failed: {:?}", error))?;
            return Err(anyhow!(
                "isolated signed service did not return through its CPL3 breakpoint: {:?}, rip={:#x} cs={:#x} rsp={:#x} cr2={:#x} cr3={:#x}",
                exit,
                state.instruction_pointer(),
                state.code_selector(),
                state.stack_pointer(),
                state.fault_address(),
                state.page_table_root()
            ));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "KVM execution starting restarted service failed: {:?}",
                error
            )
        })?;
        for stage in [0x31u32, 0x32, 0x34, 0x35, 0x36, 0x37, 0x33] {
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!("KVM restart stage {:#x} failed: {:?}", stage, exit));
            }
            if stage == 0x31 {
                VmBackend::write_guest(&mut guest, SERVICE_SHARED_PHYSICAL, &[0; 8])
                    .map_err(|error| anyhow!("failed to reset KVM shared page: {:?}", error))?;
                guest
                    .restore_service_shared_page(0)
                    .and_then(|_| guest.restore_service_shared_page(1))
                    .map_err(|error| anyhow!("failed to re-arm KVM shared page: {:?}", error))?;
                guest
                    .restore_service_resource_page(0)
                    .map_err(|error| anyhow!("failed to re-arm KVM resource page: {:?}", error))?;
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("KVM execution during service restart failed: {:?}", error)
            })?;
        }
        for stage in [1u32, 2] {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "restarted KVM service IPC stage {} failed: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "KVM execution during restarted service IPC failed: {:?}",
                    error
                )
            })?;
        }
        for stage in [1u32, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3, 1] {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "restarted KVM configuration response stage {} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "KVM execution during restarted configuration response failed: {:?}",
                    error
                )
            })?;
        }
        if exit
            != (VmExit::Io {
                port: SERVICE_FRAME_PORT,
                size: 4,
                write: true,
                value: 0x001b_2303,
            })
        {
            return Err(anyhow!("restarted KVM service frame mismatch: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "KVM execution entering final receiver cleanup failed: {:?}",
                error
            )
        })?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x20,
            })
        {
            return Err(anyhow!(
                "final KVM receiver cleanup request mismatch: {:?}",
                exit
            ));
        }
        complete_kvm_service_cleanup(
            &mut guest,
            0,
            SERVICE_STACK_PHYSICAL,
            SERVICE_TABLE_PHYSICAL,
            &executable,
            service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified service executable"))?,
        )?;
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "KVM execution after final receiver cleanup failed: {:?}",
                error
            )
        })?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x23,
            })
        {
            return Err(anyhow!("KVM typed fault-death proof mismatch: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!("KVM execution after typed fault death failed: {:?}", error)
        })?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 4,
            })
        {
            return Err(anyhow!("restarted KVM service proof mismatch: {:?}", exit));
        }
        // The authenticated value-four marker is terminal proof that the
        // rebuilt generation executed and was retired. Do not resume the
        // deliberate CLI/HLT fail-stop loop merely to obtain another exit.
        exit = VmExit::Halted;
    }
    let execution_micros = execution_started.elapsed().as_micros();
    if exit != VmExit::Halted {
        let state = guest.snapshot().map_err(|error| {
            anyhow!("kernel exit {:?}; state capture failed: {:?}", exit, error)
        })?;
        let walk = guest.page_walk(state.fault_address()).map_err(|error| {
            anyhow!(
                "kernel exit {:?}; page walk for {:#x} failed: {:?}",
                exit,
                state.fault_address(),
                error
            )
        })?;
        let physical = walk
            .physical_address(state.fault_address())
            .ok_or_else(|| anyhow!("fault address has no 4 KiB physical translation"))?;
        let mut fault_bytes = [0u8; 8];
        VmBackend::read_guest(&guest, physical, &mut fault_bytes)
            .map_err(|_| anyhow!("translated fault bytes are unreadable"))?;
        let invalid_opcode_gate = state
            .idt_base()
            .checked_add(6 * 16)
            .ok_or_else(|| anyhow!("invalid-opcode gate address overflow"))?;
        let gate_walk = guest
            .page_walk(invalid_opcode_gate)
            .map_err(|_| anyhow!("invalid-opcode gate page walk failed"))?;
        let gate_physical = gate_walk
            .physical_address(invalid_opcode_gate)
            .ok_or_else(|| anyhow!("invalid-opcode gate is not mapped"))?;
        let mut gate = [0u8; 16];
        VmBackend::read_guest(&guest, gate_physical, &mut gate)
            .map_err(|_| anyhow!("invalid-opcode gate bytes are unreadable"))?;
        return Err(anyhow!(
            "kernel exit {:?}: rip={:#x} rsp={:#x} rflags={:#x} cr2={:#x}->{:#x} bytes={:02x?} cr3={:#x} cs={:#x} gdt={:#x}/{:#x} idt={:#x}/{:#x} ud_gate={:02x?} walk={:x?}",
            exit,
            state.instruction_pointer(),
            state.stack_pointer(),
            state.flags(),
            state.fault_address(),
            physical,
            fault_bytes,
            state.page_table_root(),
            state.code_selector(),
            state.gdt_base(),
            state.gdt_limit(),
            state.idt_base(),
            state.idt_limit(),
            gate,
            walk.entries()
        ));
    }
    let mut marker = [0u8; 4];
    VmBackend::read_guest(&guest, FRAMEBUFFER, &mut marker)
        .map_err(|_| anyhow!("kernel framebuffer is unreadable"))?;
    match mode {
        LaunchMode::Boot if marker != [0x57, 0xc8, 0xff, 0] => {
            return Err(anyhow!(
                "kernel did not paint its authenticated boot marker"
            ));
        }
        LaunchMode::FaultProbe if marker != [0; 4] => {
            return Err(anyhow!("fault probe unexpectedly modified the framebuffer"));
        }
        LaunchMode::TimerProbe if marker != [0; 4] => {
            return Err(anyhow!("timer probe unexpectedly modified the framebuffer"));
        }
        LaunchMode::UserProbe if marker != [0; 4] => {
            return Err(anyhow!("user probe unexpectedly modified the framebuffer"));
        }
        LaunchMode::ServiceProbe if marker != [0; 4] => {
            return Err(anyhow!(
                "service probe unexpectedly modified the framebuffer"
            ));
        }
        LaunchMode::GpuBenchmark if marker != [0x78, 0xe0, 0x46, 0] => {
            return Err(anyhow!(
                "kernel did not authenticate the GPU benchmark completion"
            ));
        }
        _ => {}
    }
    println!(
        "verified {:?} kernel reached its expected halt under KVM: verify={}us prepare={}us execute={}us total={}us",
        mode,
        verification_micros,
        preparation_micros,
        execution_micros,
        total_started.elapsed().as_micros()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_cuda_bundle(
    bundle_path: &str,
    public_path: &str,
    minimum_version: &str,
) -> Result<VerifiedGpuKernelBundle> {
    let minimum_version = minimum_version
        .parse::<u64>()
        .ok()
        .filter(|version| *version != 0)
        .ok_or_else(|| anyhow!("CUDA minimum version must be a nonzero integer"))?;
    let bundle = mrml_runtime::read_file_bounded(bundle_path, MAX_KERNEL_BUNDLE)?;
    let public = mrml_runtime::read_file_bounded(public_path, LAMPORT_PUBLIC_KEY_BYTES)?;
    verify_gpu_kernel_bundle(
        &bundle,
        &public,
        minimum_version,
        mrml_tensor::cuda::embedded_cuda_bundle(),
    )
    .map_err(|_| anyhow!("CUDA bundle signature, kind, version, or embedded PTX rejected"))
}

#[cfg(target_os = "linux")]
fn handoff_entropy(handoff: &[u8]) -> Result<[u8; 32]> {
    let decoded = mrml_kernel::BootHandoff::decode(handoff, |_| {})
        .map_err(|_| anyhow!("invalid benchmark handoff"))?;
    Ok(*decoded.evidence().entropy())
}

#[cfg(target_os = "linux")]
fn complete_kvm_service_cleanup<const N: usize>(
    guest: &mut mrml_kvm::PreparedKvmGuest<N>,
    slot: usize,
    stack: u64,
    expected_root: u64,
    wrong: &VerifiedExecutable<'_>,
    service: &VerifiedExecutable<'_>,
) -> Result<()> {
    if slot == 0 {
        guest
            .observe_service_resource_page_revoked(slot)
            .map_err(|error| {
                anyhow!(
                    "KVM resource-page revocation observation failed: {:?}",
                    error
                )
            })?;
    }
    guest
        .revoke_service_shared_page(slot)
        .map_err(|error| anyhow!("KVM shared-page revocation failed: {:?}", error))?;
    if guest.reprovision_isolated_service_at(slot, wrong).is_ok() {
        return Err(anyhow!(
            "KVM service cleanup accepted a different signed executable"
        ));
    }
    VmBackend::write_guest(guest, stack, &[0xa5; 32]).map_err(|error| {
        anyhow!(
            "failed to contaminate stopped KVM service state: {:?}",
            error
        )
    })?;
    let (entry, root) = guest
        .reprovision_isolated_service_at(slot, service)
        .map_err(|error| anyhow!("KVM service cleanup failed: {:?}", error))?;
    let mut erased = [0xff; 32];
    VmBackend::read_guest(guest, stack, &mut erased)
        .map_err(|error| anyhow!("failed to inspect KVM service cleanup: {:?}", error))?;
    if erased != [0; 32]
        || entry != SERVICE_VIRTUAL + u64::from(service.image().entry_rva())
        || root
            != PhysAddr::new(expected_root)
                .map_err(|_| anyhow!("invalid fixed KVM service root"))?
    {
        return Err(anyhow!("KVM service cleanup did not publish clean state"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_gpu_benchmark<const N: usize>(
    guest: &mut mrml_kvm::PreparedKvmGuest<N>,
    layout: GpuSharedQueueLayout,
    entropy: [u8; 32],
    cuda_bundle: &VerifiedGpuKernelBundle,
    exit: VmExit,
) -> Result<()> {
    if exit
        != (VmExit::Io {
            port: GPU_DOORBELL_PORT,
            size: 4,
            write: true,
            value: 1,
        })
    {
        return Err(anyhow!(
            "GPU benchmark guest did not issue the canonical doorbell: {:?}",
            exit
        ));
    }
    let identity = GpuQueueIdentity::from_boot_entropy(&entropy)
        .map_err(|_| anyhow!("GPU queue identity derivation failed"))?;
    let mut bridge = GpuVmmQueueBridge::<1>::new(layout)
        .map_err(|_| anyhow!("GPU queue bridge initialization failed"))?;
    let mut owned = GpuCommandRing::<1>::new()
        .map_err(|_| anyhow!("GPU command queue initialization failed"))?;
    bridge
        .consume_command(guest, &mut owned)
        .map_err(|error| anyhow!("GPU command transfer failed: {:?}", error))?;
    let mut wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
    owned
        .dequeue(&mut wire)
        .map_err(|_| anyhow!("GPU command queue unexpectedly empty"))?;
    let mut receiver = GpuQueueReceiver::new(identity.session(), identity.key())
        .map_err(|_| anyhow!("GPU command receiver initialization failed"))?;
    let (request_id, command) = receiver
        .decode(&wire)
        .map_err(|_| anyhow!("GPU benchmark command authentication failed"))?;
    let ResourceCommand::BenchmarkAdd {
        elements,
        iterations,
    } = command
    else {
        return Err(anyhow!("GPU doorbell carried a non-benchmark command"));
    };
    let elapsed_ns = execute_cuda_add_benchmark(cuda_bundle, elements, iterations)?;
    let mut response = [0u8; GPU_QUEUE_MESSAGE_BYTES];
    GpuResourceResponseSender::new(identity.session(), identity.key())
        .and_then(|mut sender| {
            sender.encode(
                GpuResourceResponse::BenchmarkComplete {
                    request_id,
                    elapsed_ns,
                },
                &mut response,
            )
        })
        .map_err(|_| anyhow!("GPU benchmark response encoding failed"))?;
    bridge
        .publish_completion(guest, &response)
        .map_err(|error| anyhow!("GPU completion publication failed: {:?}", error))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn execute_cuda_add_benchmark(
    _: &VerifiedGpuKernelBundle,
    elements: u32,
    iterations: u32,
) -> Result<u64> {
    use mrml_runtime::Vector;
    use mrml_tensor::cuda::{CudaBuffer, CudaDevice};

    let elements = usize::try_from(elements).map_err(|_| anyhow!("element count overflow"))?;
    let mut a = Vector::new();
    let mut b = Vector::new();
    let mut output = Vector::new();
    a.resize(elements, 1.25f32);
    b.resize(elements, 2.5f32);
    output.resize(elements, 0.0f32);
    let device = CudaDevice::new(0).map_err(|_| anyhow!("CUDA device initialization failed"))?;
    let d_a = CudaBuffer::from_host(&a).map_err(|_| anyhow!("CUDA input A upload failed"))?;
    let d_b = CudaBuffer::from_host(&b).map_err(|_| anyhow!("CUDA input B upload failed"))?;
    let mut d_output =
        CudaBuffer::alloc(elements).map_err(|_| anyhow!("CUDA output allocation failed"))?;
    for _ in 0..20 {
        device.add(&d_a, &d_b, &mut d_output);
    }
    device
        .sync()
        .map_err(|_| anyhow!("CUDA warmup synchronization failed"))?;
    let started = Instant::now();
    for _ in 0..iterations {
        device.add(&d_a, &d_b, &mut d_output);
    }
    device
        .sync()
        .map_err(|_| anyhow!("CUDA benchmark synchronization failed"))?;
    let elapsed = started.elapsed().as_nanos();
    let elapsed_ns = u64::try_from(elapsed)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("GPU benchmark duration is invalid"))?;
    d_output
        .copy_to_host(&mut output)
        .map_err(|_| anyhow!("CUDA benchmark result download failed"))?;
    if output
        .iter()
        .any(|value| (*value - 3.75).abs() >= f32::EPSILON)
    {
        return Err(anyhow!("GPU benchmark produced an incorrect result"));
    }
    let seconds = elapsed_ns as f64 / 1e9;
    println!(
        "MRML_IN_VM_GPU_BENCH elements={} iterations={} total_ns={} kernel_us={:.3} bandwidth_gbps={:.2}",
        elements,
        iterations,
        elapsed_ns,
        elapsed_ns as f64 / 1e3 / iterations as f64,
        elements as f64 * 12.0 * iterations as f64 / seconds / 1e9
    );
    Ok(elapsed_ns)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn application_main() -> Result<()> {
    Err(anyhow!("mrml-kvm-run is available only on Linux hosts"))
}

#[cfg(any(test, target_os = "linux"))]
struct EncodedHandoff {
    bytes: [u8; 316],
    length: usize,
}

#[cfg(any(test, target_os = "linux"))]
impl EncodedHandoff {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[cfg(any(test, target_os = "linux"))]
fn boot_handoff(
    version: u64,
    entropy: [u8; 32],
    measurement: [u8; 64],
    framebuffer_pages: u64,
) -> Result<EncodedHandoff> {
    let framebuffer_bytes = framebuffer_pages
        .checked_mul(4096)
        .filter(|bytes| matches!(*bytes, 4096 | 8192))
        .ok_or_else(|| anyhow!("invalid framebuffer page count"))?;
    let framebuffer = FramebufferInfo::new(
        FRAMEBUFFER,
        framebuffer_bytes,
        16,
        16,
        16,
        PixelFormat::BlueGreenRedReserved,
    )
    .map_err(|_| anyhow!("invalid fixed framebuffer description"))?;
    let region = |address, pages, kind| {
        let address = PhysAddr::new(address).map_err(|_| anyhow!("unaligned launch region"))?;
        MemoryRegion::new(address, pages, kind).map_err(|_| anyhow!("invalid launch region"))
    };
    let regions = [
        region(0x1000, 2, MemoryKind::Free)?,
        region(0x3000, 1, MemoryKind::Kernel)?,
        region(FRAMEBUFFER, framebuffer_pages, MemoryKind::Mmio)?,
    ];
    let mut encoded = [0u8; 316];
    let length = encode_handoff(
        version,
        entropy,
        measurement,
        true,
        false,
        false,
        0x9000,
        framebuffer,
        &regions,
        &mut encoded,
    )
    .map_err(|_| anyhow!("canonical boot handoff construction failed"))?;
    if length != 240 {
        return Err(anyhow!("unexpected canonical boot handoff length"));
    }
    Ok(EncodedHandoff {
        bytes: encoded,
        length,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn smp_boot_handoff(
    version: u64,
    entropy: [u8; 32],
    measurement: [u8; 64],
) -> Result<EncodedHandoff> {
    let framebuffer = FramebufferInfo::new(
        FRAMEBUFFER,
        0x1000,
        16,
        16,
        16,
        PixelFormat::BlueGreenRedReserved,
    )
    .map_err(|_| anyhow!("invalid fixed framebuffer description"))?;
    let region = |address, pages, kind| {
        let address = PhysAddr::new(address).map_err(|_| anyhow!("unaligned launch region"))?;
        MemoryRegion::new(address, pages, kind).map_err(|_| anyhow!("invalid launch region"))
    };
    let regions = [
        region(0x1000, 2, MemoryKind::Free)?,
        region(0x3000, 1, MemoryKind::Kernel)?,
        region(FRAMEBUFFER, 1, MemoryKind::Mmio)?,
    ];
    let mut madt = [0u8; 60];
    madt[..4].copy_from_slice(b"APIC");
    madt[4..8].copy_from_slice(&60u32.to_le_bytes());
    madt[8] = 5;
    madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
    madt[44..52].copy_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]);
    madt[52..60].copy_from_slice(&[0, 8, 1, 1, 1, 0, 0, 0]);
    let checksum = madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    madt[9] = madt[9].wrapping_sub(checksum);
    let mut encoded = [0u8; 316];
    let length = encode_handoff_with_smp(
        version,
        entropy,
        measurement,
        true,
        false,
        false,
        0x9000,
        framebuffer,
        &regions,
        0x8000,
        0x100_0000,
        &madt,
        &mut encoded,
    )
    .map_err(|_| anyhow!("canonical SMP handoff construction failed"))?;
    if length != encoded.len() {
        return Err(anyhow!("unexpected canonical SMP handoff length"));
    }
    Ok(EncodedHandoff {
        bytes: encoded,
        length,
    })
}

mrml_runtime::mrml_entrypoint!(application_main);

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::BootHandoff;

    #[test]
    fn handoff_binds_verified_version_entropy_and_measurement() {
        let entropy = [0x35; 32];
        let measurement = [0xa7; 64];
        let encoded = boot_handoff(19, entropy, measurement, 1).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.evidence().image_version(), 19);
        assert_eq!(decoded.evidence().entropy(), &entropy);
        assert_eq!(decoded.evidence().image_measurement(), &measurement);
        assert!(decoded.evidence().secure_boot());
        assert!(!decoded.evidence().measured_boot());
        assert!(!decoded.evidence().rollback_protected());
    }

    #[test]
    fn block_handoff_binds_two_disjoint_payload_pages() {
        let encoded = boot_handoff(20, [0x36; 32], [0xa8; 64], 2).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.framebuffer().base().get(), FRAMEBUFFER);
        assert_eq!(decoded.framebuffer().byte_length(), 8192);
        assert!(boot_handoff(20, [0x36; 32], [0xa8; 64], 3).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn block_probe_backend_rejects_every_out_of_range_access() {
        let mut backend = DriverProbeBlock([0; 8192]);
        let mut block = [0; 4096];
        assert!(backend.read_blocks(2, &mut block).is_err());
        assert!(backend.read_blocks(u64::MAX, &mut block).is_err());
        assert!(backend.read_blocks(0, &mut block[..4095]).is_err());
        assert!(backend.write_blocks(2, &block).is_err());
        assert!(backend.write_blocks(u64::MAX, &block).is_err());
        assert!(backend.write_blocks(0, &block[..4095]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn block_probe_exit_budget_is_exact_and_fail_closed() {
        assert_eq!(BLOCK_PROBE_OPERATIONS, 32);
        assert_eq!(BLOCK_PROBE_POLICY_EXITS, 64);
        let mut vms = VmTable::<1>::new();
        let vm = vms.create(BLOCK_PROBE_POLICY_EXITS).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();
        for _ in 0..BLOCK_PROBE_POLICY_EXITS {
            assert!(vms.account_exit(vm).is_ok());
        }
        assert_eq!(
            vms.account_exit(vm),
            Err(mrml_kernel::VmError::ExitBudgetExceeded)
        );
    }

    #[test]
    fn launch_mode_is_explicit_and_fail_closed() {
        assert_eq!(LaunchMode::parse("boot").unwrap(), LaunchMode::Boot);
        assert_eq!(
            LaunchMode::parse("fault-probe").unwrap(),
            LaunchMode::FaultProbe
        );
        assert_eq!(
            LaunchMode::parse("timer-probe").unwrap(),
            LaunchMode::TimerProbe
        );
        assert_eq!(
            LaunchMode::parse("user-probe").unwrap(),
            LaunchMode::UserProbe
        );
        assert_eq!(
            LaunchMode::parse("service-probe").unwrap(),
            LaunchMode::ServiceProbe
        );
        assert_eq!(
            LaunchMode::parse("block-service-probe").unwrap(),
            LaunchMode::BlockServiceProbe
        );
        assert_eq!(
            LaunchMode::parse("block-guest-driver-probe").unwrap(),
            LaunchMode::BlockGuestDriverProbe
        );
        assert_eq!(
            LaunchMode::parse("service-restart-request-probe").unwrap(),
            LaunchMode::ServiceRestartRequestProbe
        );
        assert!(LaunchMode::parse("diagnostic").is_err());
        assert_eq!(
            LaunchMode::parse("gpu-benchmark").unwrap(),
            LaunchMode::GpuBenchmark
        );
        assert_eq!(
            LaunchMode::parse("smp-probe").unwrap(),
            LaunchMode::SmpProbe
        );
        assert_eq!(
            LaunchMode::parse("smp-scheduler-probe").unwrap(),
            LaunchMode::SmpSchedulerProbe
        );
        assert_eq!(
            LaunchMode::parse("smp-ipi-probe").unwrap(),
            LaunchMode::SmpIpiProbe
        );
    }

    #[test]
    fn smp_handoff_binds_two_cpus_and_launch_resources() {
        let encoded = smp_boot_handoff(7, [0x51; 32], [0xa3; 64]).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.ap_trampoline(), Some(0x8000));
        assert_eq!(decoded.ap_stack_arena(), Some(0x100_0000));
        let topology = mrml_kernel::arch::x86_64::X86CpuTopology::parse_madt(
            decoded.madt(encoded.as_slice()).unwrap(),
        )
        .unwrap();
        assert_eq!(topology.len(), 2);
        assert_eq!(topology.cpu(0).unwrap().apic_id(), 0);
        assert_eq!(topology.cpu(1).unwrap().apic_id(), 1);
    }
}
