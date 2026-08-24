#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

#[cfg(target_os = "windows")]
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};
use mrml_error::{Result, anyhow};
#[cfg(target_os = "windows")]
use mrml_kernel::arch::x86_64::{Mapping, PRIVILEGE_STACK_ARENA_PAGES, PagePermissions, VirtAddr};
#[cfg(all(target_os = "windows", feature = "cuda"))]
use mrml_kernel::verify_gpu_kernel_bundle;
#[cfg(target_os = "windows")]
use mrml_kernel::{
    ArtifactKind, CapabilitySpace, GPU_DOORBELL_PORT, GPU_QUEUE_MESSAGE_BYTES, GpuCommandRing,
    GpuQueueIdentity, GpuQueueReceiver, GpuResourceResponse, GpuResourceResponseSender,
    GpuSharedQueueLayout, GpuVmmQueueBridge, GuestMemory, HypercallRouter, InterruptPolicy,
    ObjectId, ResourceCommand, Rights, SIGNED_ARTIFACT_OVERHEAD_BYTES, SignedArtifact, TrustRoot,
    VIRTUAL_BLOCK_FEATURE_FLUSH, VerifiedExecutable, VerifiedGpuKernelBundle, VirtualBlockBackend,
    VirtualBlockBackendAuthority, VirtualBlockConfigurationPage, VirtualBlockDevice,
    VirtualBlockDeviceState, VirtualBlockMutationError, VirtualBlockPciAttachment,
    VirtualBlockPciAttachmentState, VirtualBlockPciCleanupMode, VirtualBlockPciCleanupRecord,
    VirtualBlockPciFunctionRevoker, VirtualBlockPciMemoryMapper, VirtualBlockPciResourceRevoker,
    VirtualBlockPciWindowBackend, VirtualBlockProcessOutcome, VirtualBlockQueueBridge,
    VirtualBlockQueueLayout, VirtualBlockResumePage, VirtualBlockTransactionOutcome,
    VirtualBlockTransport, VirtualPciAttachedResources, VirtualPciConfigurationMechanismOne,
    VirtualPciConfigurationRouter, VirtualPciIdentity, VirtualPciIoOutcome, VirtualPciLocation,
    VirtualPciMemoryBar, VirtualPciMmioWindow, VirtualPciNativeResourceError,
    VirtualPciType0Function, VmBackend, VmExit, VmTable, run_pci_configuration_once,
    run_pci_configuration_once_with_mapper, run_virtual_block_mmio_transaction_once,
    run_virtual_block_transaction_once,
};
#[cfg(any(test, target_os = "windows"))]
use mrml_kernel::{
    FramebufferInfo, MemoryKind, MemoryRegion, PhysAddr, PixelFormat, RecoveryStateMetadata,
    encode_handoff, encode_handoff_with_recovery, encode_handoff_with_smp,
};
#[cfg(all(target_os = "windows", feature = "cuda"))]
use mrml_runtime::Vector;
#[cfg(target_os = "windows")]
use mrml_runtime::{Instant, mrml_println as println};
#[cfg(target_os = "windows")]
use mrml_whp::{PreparedWhpGuest, WhpLaunchLayout, WhpSystem};

#[cfg(target_os = "windows")]
const MAX_KERNEL_BUNDLE: usize = SIGNED_ARTIFACT_OVERHEAD_BYTES + 16 * 1024 * 1024;
#[cfg(any(test, target_os = "windows"))]
const FRAMEBUFFER: u64 = 0x00a0_0000;
#[cfg(target_os = "windows")]
const COMMAND_BASE: u64 = 0x00b0_0000;
#[cfg(target_os = "windows")]
const COMPLETION_BASE: u64 = 0x00b0_1000;
#[cfg(target_os = "windows")]
const SERVICE_FRAME_PORT: u16 = 0x4d59;
#[cfg(target_os = "windows")]
const SERVICE_PROBE_PORT: u16 = 0x4d58;
#[cfg(target_os = "windows")]
const SERVICE_CALL_PORT: u16 = 0x4d5a;
#[cfg(target_os = "windows")]
const TIMER_READY_PORT: u16 = 0x4d54;
#[cfg(target_os = "windows")]
const TIMER_TICK_PORT: u16 = 0x4d55;
#[cfg(target_os = "windows")]
const PREEMPTION_PROBE_PORT: u16 = 0x4d5b;
#[cfg(target_os = "windows")]
const SMP_PROBE_PORT: u16 = 0x4d5c;
#[cfg(target_os = "windows")]
const SERVICE_PHYSICAL: u64 = 0x0060_0000;
#[cfg(target_os = "windows")]
const SERVICE_VIRTUAL: u64 = 0x0000_0001_4000_0000;
#[cfg(target_os = "windows")]
const SERVICE_STACK_PHYSICAL: u64 = 0x0080_0000;
#[cfg(target_os = "windows")]
const SERVICE_STACK_VIRTUAL: u64 = 0x0070_0000;
#[cfg(target_os = "windows")]
const SERVICE_TABLE_PHYSICAL: u64 = 0x00c0_0000;
#[cfg(target_os = "windows")]
const SERVICE_B_PHYSICAL: u64 = 0x0090_0000;
#[cfg(target_os = "windows")]
const SERVICE_B_STACK_PHYSICAL: u64 = 0x00e0_0000;
#[cfg(target_os = "windows")]
const SERVICE_B_TABLE_PHYSICAL: u64 = 0x00d0_0000;
#[cfg(target_os = "windows")]
const SERVICE_C_PHYSICAL: u64 = 0x0130_0000;
#[cfg(target_os = "windows")]
const SERVICE_C_TABLE_PHYSICAL: u64 = 0x0140_0000;
#[cfg(target_os = "windows")]
const SERVICE_C_STACK_PHYSICAL: u64 = 0x0150_0000;
#[cfg(target_os = "windows")]
const SERVICE_SHARED_PHYSICAL: u64 = 0x00f0_0000;
#[cfg(target_os = "windows")]
const SERVICE_SHARED_VIRTUAL: u64 = 0x006f_e000;
#[cfg(target_os = "windows")]
const SERVICE_RESOURCE_PHYSICAL: u64 = 0x00f0_1000;
#[cfg(target_os = "windows")]
const SERVICE_RESOURCE_VIRTUAL: u64 = 0x006f_f000;
#[cfg(target_os = "windows")]
const BLOCK_PROOF_PORT: u16 = 0x4d65;
#[cfg(target_os = "windows")]
const BLOCK_PROBE_CYCLES: usize = 8;
#[cfg(target_os = "windows")]
const BLOCK_PROBE_OPERATIONS: u32 = (BLOCK_PROBE_CYCLES * 4) as u32;
#[cfg(target_os = "windows")]
const BLOCK_QUIESCE_WINDOW: usize = BLOCK_PROBE_CYCLES - 2;
#[cfg(target_os = "windows")]
const BLOCK_QUIESCE_REQUESTS: u32 = (BLOCK_QUIESCE_WINDOW * 2 + 2) as u32;
#[cfg(target_os = "windows")]
const BLOCK_QUIESCE_RETIRED: u32 = BLOCK_QUIESCE_REQUESTS - 2;
#[cfg(target_os = "windows")]
const BLOCK_PROBE_POLICY_EXITS: u64 = (BLOCK_PROBE_CYCLES * 8) as u64;
#[cfg(target_os = "windows")]
const BLOCK_CONFIGURATION_BASE: u64 = 0x0060_4000;
#[cfg(target_os = "windows")]
const BLOCK_RESUME_BASE: u64 = 0x0060_5000;
#[cfg(target_os = "windows")]
const PCI_PROOF_PORT: u16 = 0x4d66;
#[cfg(target_os = "windows")]
const PCI_TEST_SELECTOR: u32 = 0x8000_2000;
#[cfg(target_os = "windows")]
const PCI_TEST_CLASS_SELECTOR: u32 = PCI_TEST_SELECTOR + 8;
#[cfg(target_os = "windows")]
const PCI_TEST_VENDOR_DEVICE: u32 = 0x5678_1234;
#[cfg(target_os = "windows")]
const PCI_TEST_CLASS: u32 = 0x0180_0001;
#[cfg(target_os = "windows")]
const PCI_TEST_BAR_SELECTOR: u32 = PCI_TEST_SELECTOR + 16;
#[cfg(target_os = "windows")]
const PCI_TEST_COMMAND_SELECTOR: u32 = PCI_TEST_SELECTOR + 4;
#[cfg(target_os = "windows")]
const PCI_TEST_MMIO_BASE: u64 = 0x00c0_0000;
#[cfg(target_os = "windows")]
const PCI_BLOCK_PROBE_OPERATIONS: u32 = 5;
#[cfg(target_os = "windows")]
const PCI_PROBE_POLICY_EXITS: u64 = 19;

#[cfg(target_os = "windows")]
struct DriverProbeBlock([u8; 8192], usize);

#[cfg(target_os = "windows")]
struct PreinstalledPciMmioWindow {
    mapped: bool,
}

#[cfg(target_os = "windows")]
struct DestroyedPciBlockResources<'a> {
    capabilities: &'a mut CapabilitySpace<2>,
    block_capability: mrml_kernel::Capability,
    interrupt_capability: mrml_kernel::Capability,
    expected_pci: VirtualPciAttachedResources,
    expected_block_generation: u32,
    expected_queue: VirtualBlockQueueLayout,
    expected_backend: VirtualBlockBackendAuthority,
    expected_window: VirtualPciMmioWindow,
    execution_destroyed: bool,
    revoked: bool,
}

#[cfg(target_os = "windows")]
unsafe impl VirtualBlockPciResourceRevoker for DestroyedPciBlockResources<'_> {
    type Error = ();

    fn revoke_block_resources(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> core::result::Result<(), Self::Error> {
        if !self.execution_destroyed
            || self.revoked
            || record.pci() != self.expected_pci
            || record.block_generation() != self.expected_block_generation
            || record.queue() != self.expected_queue
            || record.interrupt_vector() != 48
            || record.backend() != self.expected_backend
            || record.mapped_window() != Some(self.expected_window)
        {
            return Err(());
        }
        let backend = record.backend();
        if self.capabilities.authorize_exact(
            self.block_capability,
            Rights::READ.union(Rights::WRITE).union(Rights::FLUSH),
        ) != Ok(backend.object())
            || self
                .capabilities
                .authorize_exact(self.interrupt_capability, Rights::SIGNAL)
                != Ok(ObjectId(0x315))
        {
            return Err(());
        }
        self.capabilities
            .revoke(self.block_capability)
            .map_err(|_| ())?;
        self.capabilities
            .revoke(self.interrupt_capability)
            .map_err(|_| ())?;
        self.revoked = true;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
unsafe impl VirtualBlockPciWindowBackend for PreinstalledPciMmioWindow {
    fn map_block_window(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> core::result::Result<(), VirtualPciNativeResourceError> {
        let window = record
            .pci()
            .mmio_window()
            .ok_or(VirtualPciNativeResourceError::Rejected)?;
        if self.mapped
            || record.mapped_window().is_some()
            || u64::from(window.address()) != PCI_TEST_MMIO_BASE
            || u64::from(window.size()) != mrml_kernel::PAGE_SIZE
        {
            return Err(VirtualPciNativeResourceError::Rejected);
        }
        self.mapped = true;
        Ok(())
    }

    fn unmap_block_window(
        &mut self,
        record: VirtualBlockPciCleanupRecord,
    ) -> core::result::Result<(), VirtualPciNativeResourceError> {
        if !self.mapped || record.mapped_window() != record.pci().mmio_window() {
            return Err(VirtualPciNativeResourceError::Rejected);
        }
        // This controlled probe can validate its preinstalled trap window, but
        // cannot remove the first-level leaf after launch.  Never report a
        // successful revocation that the backend did not actually perform.
        Err(VirtualPciNativeResourceError::Uncertain)
    }
}

#[cfg(target_os = "windows")]
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
        self.1 = self
            .1
            .checked_add(1)
            .ok_or(VirtualBlockMutationError::Rejected(()))?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn block_configuration(
    layout: VirtualBlockQueueLayout,
    transport: VirtualBlockTransport,
) -> Result<mrml_kernel::VirtualBlockConfiguration> {
    let features = if transport == VirtualBlockTransport::MrmlSpecificPciMmio {
        VIRTUAL_BLOCK_FEATURE_FLUSH
    } else {
        0
    };
    let mut device = VirtualBlockDevice::<2>::new_with_transport(4096, 2, features, transport)
        .map_err(|_| anyhow!("invalid block probe geometry"))?;
    device
        .negotiate(features)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("invalid block probe configuration"))?;
    device
        .configuration()
        .map_err(|_| anyhow!("block probe configuration is unavailable"))
}

#[cfg(target_os = "windows")]
fn run_block_guest_driver_probe<'system>(
    mut guest: PreparedWhpGuest<'system>,
    system: &'system WhpSystem,
    executable: &VerifiedExecutable<'_>,
    handoff: &[u8],
    launch_layout: WhpLaunchLayout,
    layout: VirtualBlockQueueLayout,
) -> Result<()> {
    let block_object = ObjectId(0x300);
    let interrupt_object = ObjectId(0x301);
    let mut capabilities = CapabilitySpace::<2>::new();
    let block_capability = capabilities
        .insert(
            block_object,
            Rights::READ.union(Rights::WRITE).union(Rights::FLUSH),
        )
        .map_err(|_| anyhow!("failed to create block backend capability"))?;
    let interrupt_capability = capabilities
        .insert(interrupt_object, Rights::SIGNAL)
        .map_err(|_| anyhow!("failed to create block interrupt capability"))?;
    let mut interrupt_policy = InterruptPolicy::deny_all();
    interrupt_policy
        .allow(48)
        .map_err(|_| anyhow!("failed to allow block interrupt vector"))?;
    let transport = VirtualBlockTransport::MrmlSpecificScalarIo;
    let io_policy = transport
        .io_policy()
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
    let mut device = VirtualBlockDevice::<2>::new_with_transport(4096, 2, 0, transport)
        .map_err(|_| anyhow!("invalid block device"))?;
    device
        .negotiate(0)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("failed to activate block device"))?;
    let mut bridge = VirtualBlockQueueBridge::<2>::new(layout)
        .map_err(|_| anyhow!("failed to bind block queue bridge"))?;
    let mut storage = DriverProbeBlock([0; 8192], 0);
    let mut scratch = [0; 4096];

    for window in 0..(BLOCK_PROBE_CYCLES * 2) {
        for offset in 0..2 {
            let operation = window * 2 + offset;
            let outcome = run_virtual_block_transaction_once(
                &mut guest,
                &mut storage,
                mrml_kernel::VirtualBlockBackendAuthority::new(
                    block_capability,
                    block_object,
                    0,
                    2,
                )
                .map_err(|_| anyhow!("invalid block backend authority"))?,
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
            )
            .map_err(|error| anyhow!("block doorbell {} failed: {:?}", operation + 1, error))?;
            let outcome = match outcome {
                VirtualBlockTransactionOutcome::Doorbell(outcome) => outcome,
                VirtualBlockTransactionOutcome::CompletionAcknowledged(_) => {
                    return Err(anyhow!(
                        "block operation {} produced an unexpected acknowledgement",
                        operation + 1
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
            // SAFETY: `guest` owned the exact captured native partition and
            // has been consumed and destroyed. No native execution can resume
            // or seed another replacement; the same device and bridge stay
            // suspended.
            let lost_execution = unsafe { restart_image.confirm_execution_loss() };
            let configuration_page =
                VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, configuration)
                    .map_err(|_| anyhow!("invalid replacement block configuration page"))?;
            let mut replacement = system
                .prepare_kernel_block_guest(
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
            let acknowledgement = run_virtual_block_transaction_once(
                &mut guest,
                &mut storage,
                mrml_kernel::VirtualBlockBackendAuthority::new(
                    block_capability,
                    block_object,
                    0,
                    2,
                )
                .map_err(|_| anyhow!("invalid block backend authority"))?,
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
            )
            .map_err(|error| {
                anyhow!(
                    "block acknowledgement {} failed: {:?}",
                    operation + 1,
                    error
                )
            })?;
            let acknowledgement = match acknowledgement {
                VirtualBlockTransactionOutcome::CompletionAcknowledged(acknowledgement) => {
                    acknowledgement
                }
                VirtualBlockTransactionOutcome::Doorbell(_) => {
                    return Err(anyhow!(
                        "block acknowledgement {} produced an unexpected doorbell",
                        operation + 1
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

#[cfg(target_os = "windows")]
fn run_pci_configuration_probe<'system>(
    mut guest: PreparedWhpGuest<'system>,
    system: &'system WhpSystem,
    executable: &VerifiedExecutable<'_>,
    handoff: &[u8],
    launch_layout: WhpLaunchLayout,
) -> Result<()> {
    let mut vms = VmTable::<1>::new();
    let vm = vms
        .create(PCI_PROBE_POLICY_EXITS)
        .map_err(|_| anyhow!("failed to create PCI probe VM state"))?;
    vms.mark_loaded(vm)
        .and_then(|()| vms.start(vm))
        .map_err(|_| anyhow!("failed to start PCI probe VM state"))?;
    let mut hypercalls = HypercallRouter::new(ObjectId(0x311), ObjectId(0x312), ObjectId(0x313));
    let mut capabilities = CapabilitySpace::<2>::new();
    let memory = GuestMemory::<0>::new();
    let mut transport = VirtualPciConfigurationMechanismOne::new();
    let mut router = VirtualPciConfigurationRouter::new();
    let location = VirtualPciLocation::new(0, 0, 4, 0)
        .map_err(|_| anyhow!("invalid test-only PCI location"))?;
    let identity = VirtualPciIdentity::new(0x1234, 0x5678, 1, 0, 0x80, 1, 0x1234, 0x5678)
        .map_err(|_| anyhow!("invalid test-only PCI identity"))?;
    let pci = router
        .attach(
            location,
            VirtualPciType0Function::new(
                identity,
                VirtualPciMemoryBar::new(4096).map_err(|_| anyhow!("invalid test-only PCI BAR"))?,
            ),
        )
        .map_err(|_| anyhow!("failed to attach test-only PCI function"))?;
    let layout = VirtualBlockQueueLayout::new(0x0060_0000, 0x0060_2000, 2)
        .map_err(|_| anyhow!("invalid PCI block queue layout"))?;
    let mut device = VirtualBlockDevice::<2>::new_with_transport(
        4096,
        2,
        VIRTUAL_BLOCK_FEATURE_FLUSH,
        VirtualBlockTransport::MrmlSpecificPciMmio,
    )
    .map_err(|_| anyhow!("invalid PCI block device"))?;
    device
        .negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("failed to activate PCI block device"))?;
    let mut bridge = VirtualBlockQueueBridge::<2>::new(layout)
        .map_err(|_| anyhow!("failed to bind PCI block queue"))?;
    let block_object = ObjectId(0x314);
    let block_capability = capabilities
        .insert(
            block_object,
            Rights::READ.union(Rights::WRITE).union(Rights::FLUSH),
        )
        .map_err(|_| anyhow!("failed to create PCI block backend capability"))?;
    let interrupt_object = ObjectId(0x315);
    let interrupt_capability = capabilities
        .insert(interrupt_object, Rights::SIGNAL)
        .map_err(|_| anyhow!("failed to create PCI block interrupt capability"))?;
    let authority = VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 2)
        .map_err(|_| anyhow!("invalid PCI block backend authority"))?;
    let mut attachment = VirtualBlockPciAttachment::new(
        router
            .describe_attachment(pci)
            .map_err(|_| anyhow!("failed to describe test-only PCI function"))?,
        &device,
        &bridge,
        authority,
    )
    .map_err(|_| anyhow!("failed to bind test-only PCI block function"))?;

    let selector = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI selector transaction failed: {:?}", error))?;
    if selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_SELECTOR) {
        return Err(anyhow!("WHP PCI selector outcome mismatch: {:?}", selector));
    }
    let read = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI identity-read transaction failed: {:?}", error))?;
    if read != VirtualPciIoOutcome::Read(PCI_TEST_VENDOR_DEVICE) {
        return Err(anyhow!(
            "WHP PCI identity-read outcome mismatch: {:?}",
            read
        ));
    }
    let class_selector = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI class selector transaction failed: {:?}", error))?;
    if class_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_CLASS_SELECTOR) {
        return Err(anyhow!(
            "WHP PCI class selector mismatch: {:?}",
            class_selector
        ));
    }
    let class = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI class-read transaction failed: {:?}", error))?;
    if class != VirtualPciIoOutcome::Read(PCI_TEST_CLASS) {
        return Err(anyhow!("WHP PCI class-read outcome mismatch: {:?}", class));
    }
    let bar_selector = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI BAR selector failed: {:?}", error))?;
    if bar_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_BAR_SELECTOR) {
        return Err(anyhow!("WHP PCI BAR selector mismatch: {:?}", bar_selector));
    }
    let bar = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI BAR assignment failed: {:?}", error))?;
    if bar
        != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::BarAddress(
            PCI_TEST_MMIO_BASE as u32,
        ))
    {
        return Err(anyhow!("WHP PCI BAR assignment mismatch: {:?}", bar));
    }
    let command_selector = run_pci_configuration_once(
        &mut guest,
        0,
        &mut vms,
        vm,
        &mut hypercalls,
        &capabilities,
        &memory,
        &mut transport,
        &mut router,
    )
    .map_err(|error| anyhow!("WHP PCI command selector failed: {:?}", error))?;
    if command_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_COMMAND_SELECTOR) {
        return Err(anyhow!(
            "WHP PCI command selector mismatch: {:?}",
            command_selector
        ));
    }
    let mut window_backend = PreinstalledPciMmioWindow { mapped: false };
    let command = {
        let mut mapper =
            VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
        run_pci_configuration_once_with_mapper(
            &mut guest,
            0,
            &mut vms,
            vm,
            &mut hypercalls,
            &capabilities,
            &memory,
            &mut transport,
            &mut router,
            &mut mapper,
        )
    }
    .map_err(|error| anyhow!("WHP PCI memory enable failed: {:?}", error))?;
    if command
        != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::Command(
            mrml_kernel::PCI_COMMAND_MEMORY_SPACE | mrml_kernel::PCI_COMMAND_INTERRUPT_DISABLE,
        ))
        || !window_backend.mapped
    {
        return Err(anyhow!("WHP PCI memory enable mismatch: {:?}", command));
    }
    let io = VirtualBlockTransport::MrmlSpecificPciMmio
        .io_policy()
        .map_err(|_| anyhow!("failed to construct deny-all MMIO I/O policy"))?;
    let mut interrupt_policy = InterruptPolicy::deny_all();
    interrupt_policy
        .allow(48)
        .map_err(|_| anyhow!("failed to allow PCI block interrupt"))?;
    let mut backend = DriverProbeBlock([0; 8192], 0);
    let mut scratch = [0u8; 4096];
    for transaction in 0..10usize {
        let mmio = run_virtual_block_mmio_transaction_once(
            &mut guest,
            &mut backend,
            authority,
            0,
            &mut vms,
            vm,
            &mut hypercalls,
            &capabilities,
            &memory,
            &io,
            &interrupt_policy,
            interrupt_capability,
            interrupt_object,
            &router,
            &attachment,
            &mut device,
            &mut bridge,
            &mut scratch,
        )
        .map_err(|error| {
            anyhow!(
                "WHP PCI-MMIO block transaction {} failed: {:?}",
                transaction + 1,
                error
            )
        })?;
        let expected_doorbell = matches!(transaction, 0 | 1 | 4 | 5 | 8);
        if (expected_doorbell
            && !matches!(
                mmio,
                VirtualBlockTransactionOutcome::Doorbell(VirtualBlockProcessOutcome::Completed(_))
            ))
            || (!expected_doorbell
                && !matches!(
                    mmio,
                    VirtualBlockTransactionOutcome::CompletionAcknowledged(_)
                ))
        {
            return Err(anyhow!(
                "WHP PCI-MMIO transaction {} outcome mismatch: {:?}",
                transaction + 1,
                mmio
            ));
        }
        if transaction == 0 {
            if device.pending_interrupt_vector() != Some(48) {
                return Err(anyhow!("masked PCI completion was not retained exactly"));
            }
            let unmask = {
                let mut mapper =
                    VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
                run_pci_configuration_once_with_mapper(
                    &mut guest,
                    0,
                    &mut vms,
                    vm,
                    &mut hypercalls,
                    &capabilities,
                    &memory,
                    &mut transport,
                    &mut router,
                    &mut mapper,
                )
            }
            .map_err(|error| anyhow!("WHP PCI interrupt unmask failed: {:?}", error))?;
            if unmask
                != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::Command(
                    mrml_kernel::PCI_COMMAND_MEMORY_SPACE,
                ))
            {
                return Err(anyhow!("WHP PCI interrupt unmask mismatch: {:?}", unmask));
            }
        }
    }
    if backend.0[..4096] != [0x5a; 4096] || backend.0[4096..] != [0xa5; 4096] {
        return Err(anyhow!("WHP PCI-MMIO block backend payload mismatch"));
    }
    if backend.1 != 1 {
        return Err(anyhow!("WHP PCI-MMIO block flush count mismatch"));
    }
    let configuration = device
        .configuration()
        .map_err(|_| anyhow!("PCI block configuration unavailable at replacement"))?;
    let configuration_page =
        VirtualBlockConfigurationPage::new(BLOCK_CONFIGURATION_BASE, configuration)
            .map_err(|_| anyhow!("invalid PCI block replacement configuration page"))?;
    let resume_page = VirtualBlockResumePage::fresh(BLOCK_RESUME_BASE, configuration_page)
        .map_err(|_| anyhow!("invalid PCI block replacement resume page"))?;
    device
        .suspend()
        .map_err(|_| anyhow!("PCI block device did not suspend exactly"))?;
    let published = bridge
        .publish_resume_page(&mut guest, &device, resume_page)
        .map_err(|error| anyhow!("PCI block resume publication failed: {:?}", error))?;
    let state = published.state();
    let completed = u64::from(PCI_BLOCK_PROBE_OPERATIONS);
    if state.request_producer() != completed
        || state.request_consumed() != completed
        || state.completion_published() != completed
        || state.completion_consumer() != completed
        || state.last_admitted_request_id() != completed
        || state.last_published_request_id() != completed
    {
        return Err(anyhow!("PCI block replacement state mismatch"));
    }
    let restart_image = bridge
        .capture_restart_image(&guest, &device, published)
        .map_err(|error| anyhow!("PCI block restart snapshot failed: {:?}", error))?;
    drop(guest);
    // SAFETY: the exact captured partition has been consumed and destroyed;
    // the retained device, bridge, router, attachment, and backend stay live
    // and suspended until restoration completes.
    let lost_execution = unsafe { restart_image.confirm_execution_loss() };
    let mut replacement = system
        .prepare_kernel_block_mmio_guest(
            executable,
            handoff,
            launch_layout,
            layout,
            configuration_page,
            VirtualBlockResumePage::fresh(BLOCK_RESUME_BASE, configuration_page)
                .map_err(|_| anyhow!("invalid fresh PCI block replacement resume page"))?,
            PCI_TEST_MMIO_BASE,
        )
        .map_err(|error| anyhow!("replacement PCI block VM preparation failed: {:?}", error))?;
    bridge
        .restore_restart_image(&mut replacement, &device, lost_execution)
        .map_err(|error| anyhow!("replacement PCI block restoration failed: {:?}", error))?;
    guest = replacement;
    device
        .resume()
        .map_err(|_| anyhow!("PCI block device did not resume exactly"))?;
    let proof = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("WHP PCI proof execution failed: {:?}", error))?;
    if proof
        != (VmExit::Io {
            port: PCI_PROOF_PORT,
            size: 4,
            write: true,
            value: PCI_BLOCK_PROBE_OPERATIONS,
        })
    {
        return Err(anyhow!("WHP PCI proof mismatch: {:?}", proof));
    }
    let expected_pci = router
        .describe_attachment(pci)
        .map_err(|_| anyhow!("PCI cleanup attachment disappeared"))?
        .resources();
    let expected_window = expected_pci
        .mmio_window()
        .ok_or_else(|| anyhow!("PCI cleanup window disappeared"))?;
    let expected_block_generation = device.generation();
    drop(guest);
    let mut destroyed = DestroyedPciBlockResources {
        capabilities: &mut capabilities,
        block_capability,
        interrupt_capability,
        expected_pci,
        expected_block_generation,
        expected_queue: layout,
        expected_backend: authority,
        expected_window,
        execution_destroyed: true,
        revoked: false,
    };
    let next_generation = {
        let mut revoker = VirtualBlockPciFunctionRevoker::new(
            &mut attachment,
            &mut device,
            &mut destroyed,
            VirtualBlockPciCleanupMode::Reset,
        );
        router
            .reset_with_revoker(pci, &mut revoker)
            .map_err(|error| anyhow!("destroyed WHP PCI cleanup failed: {:?}", error))?
    };
    let reset_pci = router
        .describe_attachment(pci)
        .map_err(|_| anyhow!("reset PCI attachment disappeared"))?
        .resources();
    if next_generation != 2
        || !destroyed.revoked
        || attachment.state() != VirtualBlockPciAttachmentState::Reset
        || device.state() != VirtualBlockDeviceState::Created
        || reset_pci.function_generation() != 2
        || reset_pci.command() != 0
        || reset_pci.mmio_window().is_some()
        || destroyed
            .capabilities
            .authorize(block_capability, Rights::READ)
            .is_ok()
        || destroyed
            .capabilities
            .authorize(interrupt_capability, Rights::SIGNAL)
            .is_ok()
    {
        return Err(anyhow!("destroyed WHP PCI cleanup state mismatch"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn application_main() -> Result<()> {
    let total_started = Instant::now();
    let arguments = mrml_runtime::command_arguments();
    if arguments.len() == 3 && arguments[1] == "--export-cuda-bundle" {
        #[cfg(feature = "cuda")]
        {
            mrml_runtime::write_file(&arguments[2], mrml_tensor::cuda::embedded_cuda_bundle())?;
            println!("wrote exact embedded CUDA PTX bundle to {}", arguments[2]);
            return Ok(());
        }
        #[cfg(not(feature = "cuda"))]
        return Err(anyhow!(
            "CUDA support was excluded from this launcher build"
        ));
    }
    let service_mode = arguments.len() == 8 && arguments[4] == "service-probe";
    let block_service_mode = arguments.len() == 8 && arguments[4] == "block-service-probe";
    let service_restart_request_mode =
        arguments.len() == 8 && arguments[4] == "service-restart-request-probe";
    let service_preemption_mode =
        arguments.len() == 8 && arguments[4] == "service-preemption-probe";
    let smp_service_migration_mode =
        arguments.len() == 8 && arguments[4] == "smp-service-migration-probe";
    let service_artifact_mode = service_mode
        || block_service_mode
        || service_restart_request_mode
        || service_preemption_mode
        || smp_service_migration_mode;
    let timer_mode = arguments.len() == 5 && arguments[4] == "timer-probe";
    let block_guest_driver_mode =
        arguments.len() == 5 && arguments[4] == "block-guest-driver-probe";
    let pci_configuration_mode = arguments.len() == 5 && arguments[4] == "pci-configuration-probe";
    let preemption_mode = arguments.len() == 5 && arguments[4] == "preemption-probe";
    let vmx_root_mode = arguments.len() == 5 && arguments[4] == "vmx-root-probe";
    let smp_mode = arguments.len() == 5 && arguments[4] == "smp-probe";
    let smp_scheduler_mode = arguments.len() == 5 && arguments[4] == "smp-scheduler-probe";
    let smp_ipi_mode = arguments.len() == 5 && arguments[4] == "smp-ipi-probe";
    let smp_periodic_balance_mode =
        arguments.len() == 5 && arguments[4] == "smp-periodic-balance-probe";
    if arguments.len() != 7
        && !service_artifact_mode
        && !timer_mode
        && !block_guest_driver_mode
        && !pci_configuration_mode
        && !preemption_mode
        && !vmx_root_mode
        && !smp_mode
        && !smp_scheduler_mode
        && !smp_ipi_mode
        && !smp_periodic_balance_mode
    {
        return Err(anyhow!(
            "usage: mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION CUDA.signed CUDA.public CUDA_MINIMUM_VERSION\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION vmx-root-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION timer-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION block-guest-driver-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION pci-configuration-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION preemption-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION smp-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION smp-scheduler-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION smp-ipi-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION smp-periodic-balance-probe\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION service-probe SERVICE.signed SERVICE.public SERVICE_MINIMUM_VERSION\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION block-service-probe SERVICE.signed SERVICE.public SERVICE_MINIMUM_VERSION\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION service-restart-request-probe SERVICE.signed SERVICE.public SERVICE_MINIMUM_VERSION\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION service-preemption-probe SERVICE.signed SERVICE.public SERVICE_MINIMUM_VERSION\n       mrml-whp-run KERNEL.signed RELEASE.public MINIMUM_VERSION smp-service-migration-probe SERVICE.signed SERVICE.public SERVICE_MINIMUM_VERSION\n       mrml-whp-run --export-cuda-bundle OUTPUT.ptx"
        ));
    }
    let minimum_version = arguments[3]
        .parse::<u64>()
        .ok()
        .filter(|version| *version != 0)
        .ok_or_else(|| anyhow!("minimum version must be a nonzero integer"))?;
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
    let service_bundle = if service_artifact_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[5],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + mrml_kernel::MAX_SERVICE_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let service_public = if service_artifact_mode {
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
    let cuda_bundle = if service_artifact_mode
        || timer_mode
        || block_guest_driver_mode
        || pci_configuration_mode
        || preemption_mode
        || vmx_root_mode
        || smp_mode
        || smp_scheduler_mode
        || smp_ipi_mode
        || smp_periodic_balance_mode
    {
        None
    } else {
        Some(verify_cuda_bundle(
            &arguments[4],
            &arguments[5],
            &arguments[6],
        )?)
    };
    let verification_micros = verification_started.elapsed().as_micros();
    let mut entropy = [0u8; 32];
    mrml_runtime::fill_random(&mut entropy)
        .map_err(|_| anyhow!("operating-system boot entropy failed"))?;
    let hosted_smp = smp_mode
        || smp_scheduler_mode
        || smp_ipi_mode
        || smp_service_migration_mode
        || smp_periodic_balance_mode;
    let handoff = if hosted_smp {
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
            u64::from(block_guest_driver_mode || pci_configuration_mode) + 1,
            block_service_mode.then(|| {
                RecoveryStateMetadata::new(8, 2, Some([0x44; 16]), 17)
                    .expect("fixed recovery metadata")
            }),
        )?
    };
    let (image_virtual, handoff_virtual, stack_virtual) = if hosted_smp {
        (0xffff_8001_4000_0000, 0xffff_8001_5000_0000, 0x100_0000)
    } else if preemption_mode {
        (0x0040_0000, 0x0200_0000, 0xffff_8001_6000_0000)
    } else {
        (
            0xffff_8001_4000_0000,
            0xffff_8001_5000_0000,
            0xffff_8001_6000_0000,
        )
    };
    let table_pages = if smp_ipi_mode || smp_service_migration_mode || smp_periodic_balance_mode {
        64
    } else {
        32
    };
    let layout = WhpLaunchLayout::new(
        0x10_0000,
        table_pages,
        0x20_0000,
        image_virtual,
        0x50_0000,
        handoff_virtual,
        0x100_0000,
        stack_virtual,
        PRIVILEGE_STACK_ARENA_PAGES,
        preemption_mode,
    )
    .map_err(|_| anyhow!("invalid fixed WHP launch layout"))?;
    let queue = GpuSharedQueueLayout::new(COMMAND_BASE, COMPLETION_BASE, 1)
        .map_err(|_| anyhow!("invalid fixed GPU queue layout"))?;
    let block_layout = VirtualBlockQueueLayout::new(0x0060_0000, 0x0060_2000, 2)
        .map_err(|_| anyhow!("invalid fixed block queue layout"))?;
    let block_transport = if pci_configuration_mode {
        VirtualBlockTransport::MrmlSpecificPciMmio
    } else {
        VirtualBlockTransport::MrmlSpecificScalarIo
    };
    let block_configuration = block_configuration(block_layout, block_transport)?;
    let system = WhpSystem::open()
        .map_err(|error| anyhow!("Windows Hypervisor Platform is unavailable: {:?}", error))?;
    let preparation_started = Instant::now();
    let mut guest = if pci_configuration_mode {
        system.prepare_kernel_block_mmio_guest(
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
            PCI_TEST_MMIO_BASE,
        )
    } else if block_guest_driver_mode {
        system.prepare_kernel_block_guest(
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
        )
    } else if service_mode || block_service_mode || service_restart_request_mode {
        system.prepare_isolated_service_kernel(&executable, handoff.as_slice(), layout)
    } else if service_preemption_mode {
        system.prepare_preemption_kernel(&executable, handoff.as_slice(), layout)
    } else if timer_mode {
        system.prepare_timer_kernel(&executable, handoff.as_slice(), layout)
    } else if preemption_mode {
        system.prepare_preemption_kernel(&executable, handoff.as_slice(), layout)
    } else if hosted_smp {
        system.prepare_smp_kernel(&executable, handoff.as_slice(), layout)
    } else {
        system.prepare_kernel_gpu_guest(&executable, handoff.as_slice(), layout, queue)
    }
    .map_err(|error| anyhow!("verified WHP kernel preparation failed: {:?}", error))?;
    if service_artifact_mode {
        let local_apic = service_preemption_mode || smp_service_migration_mode;
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
            .map_err(|error| anyhow!("isolated WHP service preparation failed: {:?}", error))?;
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
            .map_err(|error| {
                anyhow!(
                    "second isolated WHP service preparation failed: {:?}",
                    error
                )
            })?;
        if service_mode || service_restart_request_mode {
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
                    anyhow!("third isolated WHP service preparation failed: {:?}", error)
                })?;
        }
        let shared = Mapping::new(
            VirtAddr::new(SERVICE_SHARED_VIRTUAL)
                .map_err(|_| anyhow!("invalid WHP service shared virtual address"))?,
            PhysAddr::new(SERVICE_SHARED_PHYSICAL)
                .map_err(|_| anyhow!("invalid WHP service shared physical address"))?,
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .map_err(|_| anyhow!("invalid WHP service shared-page mapping"))?;
        guest = guest
            .attach_service_shared_page(shared)
            .map_err(|error| anyhow!("WHP service shared-page attachment failed: {:?}", error))?;
        let resource = Mapping::new(
            VirtAddr::new(SERVICE_RESOURCE_VIRTUAL)
                .map_err(|_| anyhow!("invalid WHP service resource virtual address"))?,
            PhysAddr::new(SERVICE_RESOURCE_PHYSICAL)
                .map_err(|_| anyhow!("invalid WHP service resource physical address"))?,
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .map_err(|_| anyhow!("invalid WHP service resource-page mapping"))?;
        guest = guest
            .attach_service_resource_page(0, resource)
            .map_err(|error| anyhow!("WHP service resource-page attachment failed: {:?}", error))?;
        let service_entry = guest
            .service_entry()
            .ok_or_else(|| anyhow!("missing WHP service entry"))?;
        if guest.service_page_table_root() != PhysAddr::new(SERVICE_TABLE_PHYSICAL).ok()
            || guest.service_entry_at(1) != Some(service_entry)
            || guest.service_page_table_root_at(1) != PhysAddr::new(SERVICE_B_TABLE_PHYSICAL).ok()
            || ((service_mode || service_restart_request_mode)
                && (guest.service_entry_at(2) != Some(service_entry)
                    || guest.service_page_table_root_at(2)
                        != PhysAddr::new(SERVICE_C_TABLE_PHYSICAL).ok()))
        {
            return Err(anyhow!("isolated WHP service layout mismatch"));
        }
        VmBackend::write_guest(
            &mut guest,
            SERVICE_SHARED_PHYSICAL + 8,
            &service_entry.to_le_bytes(),
        )
        .map_err(|_| anyhow!("failed to publish WHP service entry"))?;
    }
    let preparation_micros = preparation_started.elapsed().as_micros();
    let execution_started = Instant::now();
    if pci_configuration_mode {
        run_pci_configuration_probe(guest, &system, &executable, handoff.as_slice(), layout)?;
        println!(
            "verified signed test-only attached MRML block PCI-MMIO write/read/flush, orderly VM replacement, and destroyed-VM cleanup under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if block_guest_driver_mode {
        run_block_guest_driver_probe(
            guest,
            &system,
            &executable,
            handoff.as_slice(),
            layout,
            block_layout,
        )?;
        println!(
            "verified signed compiled eight-cycle two-slot common block guest driver under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    let exit = if hosted_smp {
        let (bootstrap, application) = guest
            .run_smp()
            .map_err(|error| anyhow!("WHP SMP execution failed: {:?}", error))?;
        let expected_bootstrap = VmExit::Io {
            port: if smp_periodic_balance_mode {
                0x4d64
            } else if smp_scheduler_mode {
                0x4d5e
            } else if smp_ipi_mode || smp_service_migration_mode {
                0x4d60
            } else {
                SMP_PROBE_PORT
            },
            size: 4,
            write: true,
            value: 2,
        };
        let expected_application = VmExit::Io {
            port: if smp_periodic_balance_mode {
                0x4d63
            } else if smp_scheduler_mode {
                0x4d5f
            } else if smp_ipi_mode {
                0x4d61
            } else if smp_service_migration_mode {
                0x4d62
            } else {
                SMP_PROBE_PORT
            },
            size: 4,
            write: true,
            value: if smp_periodic_balance_mode {
                0x0001_0002
            } else {
                0x0001_0001
            },
        };
        if bootstrap != expected_bootstrap || application != expected_application {
            return Err(anyhow!(
                "WHP SMP proof mismatch: bootstrap={:?} application={:?}",
                bootstrap,
                application
            ));
        }
        println!(
            "verified signed two-vCPU kernel startup under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    } else {
        match VmBackend::run(&mut guest, 0) {
            Ok(exit) => exit,
            Err(error) => {
                let mut marker = [0u8; 4];
                let _ = VmBackend::read_guest(&guest, FRAMEBUFFER, &mut marker);
                return Err(anyhow!(
                    "WHP execution failed: {:?}; framebuffer marker={:02x?}",
                    error,
                    marker
                ));
            }
        }
    };
    if let VmExit::GuestMemoryFault { guest_address, .. } = exit {
        let walk = guest
            .page_walk(guest_address)
            .map_err(|_| anyhow!("failed to inspect WHP guest execute fault"))?;
        let physical = walk.physical_address(guest_address);
        let mut instruction = [0u8; 8];
        if let Some(address) = physical {
            let _ = VmBackend::read_guest(&guest, address, &mut instruction);
        }
        return Err(anyhow!(
            "WHP guest memory fault at {:#x}: page_entries={:x?} physical={:x?} bytes={:02x?}",
            guest_address,
            walk.entries(),
            physical,
            instruction
        ));
    }
    if vmx_root_mode {
        let expected = [0xd0u32, 0xd1, 0xd2, 0xd3, 0xd4, 0xdf];
        let mut actual = exit;
        for (index, stage) in expected.into_iter().enumerate() {
            let wanted = VmExit::Io {
                port: 0xe9,
                size: 1,
                write: true,
                value: stage,
            };
            if actual != wanted {
                return Err(anyhow!(
                    "WHP nested-VMX stage {:#x} mismatch: {:?}",
                    stage,
                    actual
                ));
            }
            if index + 1 != expected.len() {
                actual = VmBackend::run(&mut guest, 0)
                    .map_err(|error| anyhow!("WHP nested-VMX execution failed: {:?}", error))?;
            }
        }
        println!(
            "verified controlled nested-VMX EPT violation and teardown under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if service_preemption_mode {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "WHP service preemption did not initialize: {:?}",
                exit
            ));
        }
        for stage in [0x2320u32, 1, 2, 3, 4, 5, 6] {
            let exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP service preemption failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: PREEMPTION_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "WHP service preemption stage {:#x} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
        }
        println!(
            "verified cross-root CPL3 timer preemption under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if timer_mode {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!("WHP timer did not initialize: {:?}", exit));
        }
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP local APIC counter wait failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 2,
            })
        {
            return Err(anyhow!("WHP local APIC counter did not elapse: {:?}", exit));
        }
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP local APIC delivery failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: TIMER_TICK_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!("WHP scheduler timer tick mismatch: {:?}", exit));
        }
        println!(
            "verified local-APIC scheduler tick under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if preemption_mode {
        if exit
            != (VmExit::Io {
                port: TIMER_READY_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "WHP preemption probe did not initialize: {:?}",
                exit
            ));
        }
        let expected = [0x2320u32, 1, 2, 3, 4, 5, 6];
        for stage in expected {
            let exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP preemption stage failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: PREEMPTION_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "WHP preemption stage {:#x} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
        }
        println!(
            "verified CPL3 timer preemption under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if block_service_mode {
        let mut exit = exit;
        let cleanup_stages = [0x21, 0x31, 0x20, 0x30];
        let mut cleanup_stage = 0;
        for _ in 0..256 {
            if let VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value,
            } = exit
            {
                if cleanup_stages.get(cleanup_stage).copied() != Some(value) {
                    return Err(anyhow!(
                        "WHP block-service cleanup stage mismatch: {:?}",
                        exit
                    ));
                }
                cleanup_stage += 1;
                if value == 0x30 {
                    println!(
                        "verified independently signed CPL3 block-service stable-policy publication/recovery and lifecycle cleanup under WHP: verify={}us prepare={}us execute={}us total={}us",
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
                return Err(anyhow!("WHP block-service stage mismatch: {:?}", exit));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP block-service execution failed: {:?}", error))?;
        }
        return Err(anyhow!("WHP block-service probe exceeded its stage bound"));
    }
    if service_mode || service_restart_request_mode {
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!("isolated WHP receiver did not block: {:?}", exit));
        }
        let mut exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP execution during service send failed: {:?}", error))?;
        if service_restart_request_mode {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 1,
                })
            {
                return Err(anyhow!(
                    "isolated WHP restart manager did not block: {:?}",
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("WHP execution after manager block failed: {:?}", error)
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
            return Err(anyhow!("isolated WHP service send mismatch: {:?}", exit));
        }
        let mut exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!("WHP execution entering sender cleanup failed: {:?}", error)
        })?;
        let configuration_stages: &[u32] = &[1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3];
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
                    "WHP configuration response stage {} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("WHP configuration response execution failed: {:?}", error)
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
            return Err(anyhow!("WHP sender cleanup request mismatch: {:?}", exit));
        }
        complete_whp_service_cleanup(
            &mut guest,
            1,
            SERVICE_B_STACK_PHYSICAL,
            SERVICE_B_TABLE_PHYSICAL,
            &executable,
            service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified service executable"))?,
        )?;
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP execution after sender cleanup failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0x22,
            })
        {
            return Err(anyhow!("WHP typed peer-death proof mismatch: {:?}", exit));
        }
        if service_restart_request_mode {
            let mut exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP restart request execution failed: {:?}", error))?;
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
                        "WHP restart IPC stage {} mismatch: {:?}",
                        stage,
                        exit
                    ));
                }
                exit = VmBackend::run(&mut guest, 0)
                    .map_err(|error| anyhow!("WHP restart IPC execution failed: {:?}", error))?;
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
                    "WHP trusted restart-plan stage mismatch: {:?}",
                    exit
                ));
            }
            guest
                .restore_service_shared_page(1)
                .map_err(|error| anyhow!("failed to re-arm WHP sender page: {:?}", error))?;
            for stage in [2u32, 3] {
                let exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                    anyhow!("WHP restart completion execution failed: {:?}", error)
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
                        "WHP restart completion stage {} mismatch: {:?}",
                        stage,
                        exit
                    ));
                }
            }
            let exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP manager completion fault failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_FRAME_PORT,
                    size: 4,
                    write: true,
                    value: 0x001b_2303,
                })
            {
                return Err(anyhow!("WHP manager frame mismatch: {:?}", exit));
            }
            let exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP restart proof completion failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x25,
                })
            {
                return Err(anyhow!("WHP restart proof mismatch: {:?}", exit));
            }
            println!(
                "verified authorized CPL3 restart request under WHP: verify={}us prepare={}us execute={}us total={}us",
                verification_micros,
                preparation_micros,
                execution_started.elapsed().as_micros(),
                total_started.elapsed().as_micros()
            );
            return Ok(());
        }
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP execution after typed peer death failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: 3,
            })
        {
            return Err(anyhow!("isolated WHP receive mismatch: {:?}", exit));
        }
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP execution after service IPC failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_FRAME_PORT,
                size: 4,
                write: true,
                value: 0x001b_2303,
            })
        {
            return Err(anyhow!("isolated WHP service frame mismatch: {:?}", exit));
        }
        let exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "WHP execution entering receiver cleanup failed: {:?}",
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
            return Err(anyhow!("WHP receiver cleanup request mismatch: {:?}", exit));
        }
        complete_whp_service_cleanup(
            &mut guest,
            0,
            SERVICE_STACK_PHYSICAL,
            SERVICE_TABLE_PHYSICAL,
            &executable,
            service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified service executable"))?,
        )?;
        let exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("WHP execution after receiver cleanup failed: {:?}", error))?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 3,
            })
        {
            return Err(anyhow!("isolated WHP service proof mismatch: {:?}", exit));
        }
        let mut exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "WHP execution starting restarted service failed: {:?}",
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
                return Err(anyhow!(
                    "WHP restart stage {:#x} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            if stage == 0x31 {
                VmBackend::write_guest(&mut guest, SERVICE_SHARED_PHYSICAL, &[0; 8])
                    .map_err(|error| anyhow!("failed to reset WHP shared page: {:?}", error))?;
                guest
                    .restore_service_shared_page(0)
                    .and_then(|_| guest.restore_service_shared_page(1))
                    .map_err(|error| anyhow!("failed to re-arm WHP shared page: {:?}", error))?;
                guest
                    .restore_service_resource_page(0)
                    .map_err(|error| anyhow!("failed to re-arm WHP resource page: {:?}", error))?;
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("WHP execution during service restart failed: {:?}", error)
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
                    "restarted WHP service IPC stage {} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "WHP execution during restarted service IPC failed: {:?}",
                    error
                )
            })?;
        }
        for stage in [1u32, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3, 1] {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: stage,
                })
            {
                return Err(anyhow!(
                    "restarted WHP configuration response stage {} mismatch: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "WHP execution during restarted configuration response failed: {:?}",
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
            return Err(anyhow!("restarted WHP service frame mismatch: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!(
                "WHP execution entering final receiver cleanup failed: {:?}",
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
                "final WHP receiver cleanup request mismatch: {:?}",
                exit
            ));
        }
        complete_whp_service_cleanup(
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
                "WHP execution after final receiver cleanup failed: {:?}",
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
            return Err(anyhow!("WHP typed fault-death proof mismatch: {:?}", exit));
        }
        exit = VmBackend::run(&mut guest, 0).map_err(|error| {
            anyhow!("WHP execution after typed fault death failed: {:?}", error)
        })?;
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 4,
            })
        {
            return Err(anyhow!("restarted WHP service proof mismatch: {:?}", exit));
        }
        // The authenticated value-four marker is terminal proof that the
        // rebuilt generation executed and was retired. The kernel deliberately
        // enters its CLI/HLT fail-stop loop immediately afterward.
        println!(
            "verified independently signed service restart and re-entry under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    service_gpu_benchmark(
        &mut guest,
        queue,
        entropy,
        cuda_bundle
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified CUDA bundle"))?,
        exit,
    )?;
    let exit = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("WHP execution after GPU completion failed: {:?}", error))?;
    if exit
        != (VmExit::Io {
            port: GPU_DOORBELL_PORT,
            size: 4,
            write: true,
            value: 2,
        })
    {
        return Err(anyhow!(
            "GPU benchmark kernel exited unexpectedly: {:?}",
            exit
        ));
    }
    let mut marker = [0u8; 4];
    VmBackend::read_guest(&guest, FRAMEBUFFER, &mut marker)
        .map_err(|_| anyhow!("kernel framebuffer is unreadable"))?;
    if marker != [0x78, 0xe0, 0x46, 0] {
        return Err(anyhow!(
            "kernel did not authenticate the GPU benchmark completion"
        ));
    }
    println!(
        "verified GPU benchmark kernel completed under WHP: verify={}us prepare={}us execute={}us total={}us",
        verification_micros,
        preparation_micros,
        execution_started.elapsed().as_micros(),
        total_started.elapsed().as_micros()
    );
    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "cuda")]
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

#[cfg(all(target_os = "windows", not(feature = "cuda")))]
fn verify_cuda_bundle(_: &str, _: &str, _: &str) -> Result<VerifiedGpuKernelBundle> {
    Err(anyhow!(
        "CUDA support was excluded from this launcher build"
    ))
}

#[cfg(target_os = "windows")]
fn complete_whp_service_cleanup(
    guest: &mut PreparedWhpGuest<'_>,
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
                    "WHP resource-page revocation observation failed: {:?}",
                    error
                )
            })?;
    }
    guest
        .revoke_service_shared_page(slot)
        .map_err(|error| anyhow!("WHP shared-page revocation failed: {:?}", error))?;
    if guest.reprovision_isolated_service_at(slot, wrong).is_ok() {
        return Err(anyhow!(
            "WHP service cleanup accepted a different signed executable"
        ));
    }
    VmBackend::write_guest(guest, stack, &[0xa5; 32]).map_err(|error| {
        anyhow!(
            "failed to contaminate stopped WHP service state: {:?}",
            error
        )
    })?;
    let (entry, root) = guest
        .reprovision_isolated_service_at(slot, service)
        .map_err(|error| anyhow!("WHP service cleanup failed: {:?}", error))?;
    let mut erased = [0xff; 32];
    VmBackend::read_guest(guest, stack, &mut erased)
        .map_err(|error| anyhow!("failed to inspect WHP service cleanup: {:?}", error))?;
    if erased != [0; 32]
        || entry != SERVICE_VIRTUAL + u64::from(service.image().entry_rva())
        || root
            != PhysAddr::new(expected_root)
                .map_err(|_| anyhow!("invalid fixed WHP service root"))?
    {
        return Err(anyhow!("WHP service cleanup did not publish clean state"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_gpu_benchmark(
    guest: &mut PreparedWhpGuest<'_>,
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
            "guest issued a noncanonical GPU doorbell: {:?}",
            exit
        ));
    }
    let identity = GpuQueueIdentity::from_boot_entropy(&entropy)
        .map_err(|_| anyhow!("GPU queue identity derivation failed"))?;
    let mut bridge = GpuVmmQueueBridge::<1>::new(layout)
        .map_err(|_| anyhow!("GPU bridge initialization failed"))?;
    let mut commands = GpuCommandRing::<1>::new()
        .map_err(|_| anyhow!("GPU command queue initialization failed"))?;
    bridge
        .consume_command(guest, &mut commands)
        .map_err(|error| anyhow!("GPU command transfer failed: {:?}", error))?;
    let mut wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
    commands
        .dequeue(&mut wire)
        .map_err(|_| anyhow!("GPU command queue unexpectedly empty"))?;
    let mut receiver = GpuQueueReceiver::new(identity.session(), identity.key())
        .map_err(|_| anyhow!("GPU receiver initialization failed"))?;
    let (request_id, command) = receiver
        .decode(&wire)
        .map_err(|_| anyhow!("GPU command authentication failed"))?;
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
        .map_err(|_| anyhow!("GPU response encoding failed"))?;
    bridge
        .publish_completion(guest, &response)
        .map_err(|error| anyhow!("GPU completion publication failed: {:?}", error))?;
    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "cuda")]
fn execute_cuda_add_benchmark(
    _: &VerifiedGpuKernelBundle,
    elements: u32,
    iterations: u32,
) -> Result<u64> {
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
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos())
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("GPU benchmark duration is invalid"))?;
    d_output
        .copy_to_host(&mut output)
        .map_err(|_| anyhow!("CUDA result download failed"))?;
    if output
        .iter()
        .any(|value| (*value - 3.75).abs() >= f32::EPSILON)
    {
        return Err(anyhow!("GPU benchmark produced an incorrect result"));
    }
    let seconds = elapsed_ns as f64 / 1e9;
    println!(
        "MRML_IN_VM_GPU_BENCH backend=whp elements={} iterations={} total_ns={} kernel_us={:.3} bandwidth_gbps={:.2}",
        elements,
        iterations,
        elapsed_ns,
        elapsed_ns as f64 / 1e3 / iterations as f64,
        elements as f64 * 12.0 * iterations as f64 / seconds / 1e9
    );
    Ok(elapsed_ns)
}

#[cfg(all(target_os = "windows", not(feature = "cuda")))]
fn execute_cuda_add_benchmark(_: &VerifiedGpuKernelBundle, _: u32, _: u32) -> Result<u64> {
    Err(anyhow!(
        "CUDA support was excluded from this launcher build"
    ))
}

#[cfg(not(target_os = "windows"))]
fn application_main() -> Result<()> {
    Err(anyhow!("mrml-whp-run is available only on Windows hosts"))
}

#[cfg(any(test, target_os = "windows"))]
struct EncodedHandoff {
    bytes: [u8; 316],
    length: usize,
}

#[cfg(any(test, target_os = "windows"))]
impl EncodedHandoff {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[cfg(any(test, target_os = "windows"))]
fn boot_handoff(
    version: u64,
    entropy: [u8; 32],
    measurement: [u8; 64],
    framebuffer_pages: u64,
    recovery_state: Option<RecoveryStateMetadata>,
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
    .map_err(|_| anyhow!("invalid framebuffer description"))?;
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
    let length = match recovery_state {
        Some(recovery_state) => encode_handoff_with_recovery(
            version,
            entropy,
            measurement,
            true,
            false,
            false,
            0x9000,
            framebuffer,
            &regions,
            recovery_state,
            &mut encoded,
        ),
        None => encode_handoff(
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
        ),
    }
    .map_err(|_| anyhow!("handoff construction failed"))?;
    if length != 240 + usize::from(recovery_state.is_some()) * 40 {
        return Err(anyhow!("unexpected handoff length"));
    }
    Ok(EncodedHandoff {
        bytes: encoded,
        length,
    })
}

#[cfg(any(test, target_os = "windows"))]
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
    .map_err(|_| anyhow!("invalid framebuffer description"))?;
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
    .map_err(|_| anyhow!("SMP handoff construction failed"))?;
    if length != encoded.len() {
        return Err(anyhow!("unexpected SMP handoff length"));
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
    fn handoff_binds_entropy_and_measurement() {
        let encoded = boot_handoff(9, [0x35; 32], [0xa7; 64], 1, None).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.evidence().image_version(), 9);
        assert_eq!(decoded.evidence().entropy(), &[0x35; 32]);
        assert_eq!(decoded.evidence().image_measurement(), &[0xa7; 64]);
    }

    #[test]
    fn block_handoff_binds_two_disjoint_payload_pages() {
        let encoded = boot_handoff(11, [0x37; 32], [0xa9; 64], 2, None).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.framebuffer().base().get(), FRAMEBUFFER);
        assert_eq!(decoded.framebuffer().byte_length(), 8192);
        assert!(boot_handoff(11, [0x37; 32], [0xa9; 64], 0, None).is_err());
    }

    #[test]
    fn recovery_handoff_binds_fixed_probe_metadata() {
        let recovery = RecoveryStateMetadata::new(8, 2, Some([0x44; 16]), 17).unwrap();
        let encoded = boot_handoff(12, [0x38; 32], [0xaa; 64], 1, Some(recovery)).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.recovery_state(), Some(recovery));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn block_probe_backend_rejects_every_out_of_range_access() {
        let mut backend = DriverProbeBlock([0; 8192], 0);
        let mut block = [0; 4096];
        assert!(backend.read_blocks(2, &mut block).is_err());
        assert!(backend.read_blocks(u64::MAX, &mut block).is_err());
        assert!(backend.read_blocks(0, &mut block[..4095]).is_err());
        assert!(backend.write_blocks(2, &block).is_err());
        assert!(backend.write_blocks(u64::MAX, &block).is_err());
        assert!(backend.write_blocks(0, &block[..4095]).is_err());
    }

    #[cfg(target_os = "windows")]
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

    #[cfg(target_os = "windows")]
    #[test]
    fn pci_block_probe_budget_covers_configuration_and_exact_queue_transactions() {
        assert_eq!(PCI_BLOCK_PROBE_OPERATIONS, 5);
        assert_eq!(
            PCI_PROBE_POLICY_EXITS,
            9 + 2 * u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        );
        let layout = VirtualBlockQueueLayout::new(0x0060_0000, 0x0060_2000, 2).unwrap();
        let pci = block_configuration(layout, VirtualBlockTransport::MrmlSpecificPciMmio).unwrap();
        let scalar =
            block_configuration(layout, VirtualBlockTransport::MrmlSpecificScalarIo).unwrap();
        assert_eq!(pci.negotiated_features(), VIRTUAL_BLOCK_FEATURE_FLUSH);
        assert_eq!(scalar.negotiated_features(), 0);
    }

    #[test]
    fn smp_handoff_binds_two_cpus_and_launch_resources() {
        let encoded = smp_boot_handoff(10, [0x36; 32], [0xa8; 64]).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        let topology = decoded
            .madt(encoded.as_slice())
            .and_then(|madt| mrml_kernel::arch::x86_64::X86CpuTopology::parse_madt(madt).ok())
            .unwrap();
        assert_eq!(topology.len(), 2);
        assert_eq!(decoded.ap_trampoline(), Some(0x8000));
        assert_eq!(decoded.ap_stack_arena(), Some(0x100_0000));
    }
}
