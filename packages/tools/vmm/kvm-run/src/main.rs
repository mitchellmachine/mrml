#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(target_os = "linux")]
use mrml_config::{
    AdmittedConfigurationGuestFactory, ConfigTransaction, ConfigurationMicrovmEndpoint,
    ConfigurationService, EffectiveBootIsolationPolicy, IsolationPolicyApplicationPlan,
    IsolationPolicySetting, IsolationServiceBounds, IsolationServiceIdentity,
    MicrovmConfigurationServiceLauncher, OwnerIsolationSelection,
    PreparedMicrovmConfigurationLauncher, PreparedTotalServiceSet,
    RecoveredDeploymentTotalControlPlane, RecoveredDeploymentTotalRuntime, SettingId,
    TotalServicePreparationBinding,
    hosted_recovery_probe::{HOSTED_TOTAL_COMPONENT_DOMAIN, recover_total_control_plane},
};
#[cfg(target_os = "linux")]
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};
#[cfg(target_os = "linux")]
use mrml_deployment::{
    DeploymentService, GenerationCandidate, encode_deployment_release_checkpoint,
};
use mrml_error::{Result, anyhow};
#[cfg(target_os = "linux")]
use mrml_kernel::arch::x86_64::{Mapping, PRIVILEGE_STACK_ARENA_PAGES, PagePermissions, VirtAddr};
#[cfg(target_os = "linux")]
use mrml_kernel::{
    ActiveMicrovmProjectionPlan, AdmittedApplicationGuestFactory, AffinityDeadlineVmBackend,
    ApplicationLaunch, ApplicationMicrovmEndpoint, ArtifactKind, BootIsolationOverride, Capability,
    CapabilitySpace, CpuBudgetId, CpuBudgetSpec, CpuBudgetTable, CpuRuntimeSlice,
    DeadlineVmBackend, GPU_DOORBELL_PORT, GPU_QUEUE_MESSAGE_BYTES, GpuCommandRing,
    GpuQueueIdentity, GpuQueueReceiver, GpuResourceResponse, GpuResourceResponseSender,
    GpuSharedQueueLayout, GpuVmmQueueBridge, GuestMemory, HypercallRouter, InterruptPolicy,
    IsolationAdmissionTable, IsolationApplicationBackend, IsolationApplicationSpec, IsolationMode,
    IsolationPlacement, IsolationUnavailableReason, MAX_APPLICATION_IMAGE_BYTES,
    MAX_COMPONENT_IMAGE_REGIONS, MemoryPoolTable, MicrovmPageProjectionKind,
    MicrovmProjectionDescriptor, MicrovmProjectionKind, MicrovmProjectionPlan,
    MicrovmProjectionRequirements, ObjectId, PAGE_SIZE, PreparedMicrovmApplicationBackend,
    ResourceCommand, Rights, SIGNED_ARTIFACT_OVERHEAD_BYTES, ScheduledDeadlineVmBackend,
    ScheduledSmpVmBackend, SignedArtifact, TotalMicrovmClass, TrustRoot,
    VIRTUAL_BLOCK_FEATURE_FLUSH, VcpuReservationId, VerifiedExecutable, VerifiedGpuKernelBundle,
    VirtualBlockBackend, VirtualBlockBackendAuthority, VirtualBlockCompletionStatus,
    VirtualBlockConfigurationPage, VirtualBlockDevice, VirtualBlockDeviceState, VirtualBlockError,
    VirtualBlockMutationError, VirtualBlockPciAttachment, VirtualBlockPciAttachmentState,
    VirtualBlockPciCleanupMode, VirtualBlockPciCleanupRecord, VirtualBlockPciFunctionRevoker,
    VirtualBlockPciGuestMemoryMapper, VirtualBlockPciGuestWindowBackend,
    VirtualBlockPciResourceRevoker, VirtualBlockProcessOutcome, VirtualBlockQueueBridge,
    VirtualBlockQueueLayout, VirtualBlockRequest, VirtualBlockResumePage,
    VirtualBlockTransactionOutcome, VirtualBlockTransport, VirtualBlockVmmMemory,
    VirtualPciAttachedResources, VirtualPciConfigurationMechanismOne,
    VirtualPciConfigurationRouter, VirtualPciIdentity, VirtualPciIoOutcome, VirtualPciLocation,
    VirtualPciMemoryBar, VirtualPciMmioWindow, VirtualPciNativeResourceError,
    VirtualPciType0Function, VmBackend, VmDeadlineOutcome, VmExit, VmTable,
    admit_microvm_projection, bind_component_service_handoff, bind_verified_application_image,
    component_image_page_plan, prepare_isolation_service_route, prepare_microvm_guest_ram,
    release_component_image, release_microvm_guest_ram, reserve_component_image,
    reserve_isolation_vcpus, reserve_microvm_guest_ram, reserve_microvm_page_projection,
    route_isolation_application, run_pci_configuration_once,
    run_pci_configuration_once_with_backend_mapper, run_virtual_block_mmio_transaction_once,
    run_virtual_block_transaction_once, verify_gpu_kernel_bundle,
};
#[cfg(any(test, target_os = "linux"))]
use mrml_kernel::{
    BootHandoff, FramebufferInfo, InstalledRecoveryBootIdentity, InstalledRecoverySource,
    MemoryKind, MemoryRegion, PhysAddr, PixelFormat, RecoveryStateMetadata, encode_handoff,
    encode_handoff_with_application, encode_handoff_with_recovery,
    encode_handoff_with_recovery_and_isolation,
    encode_handoff_with_recovery_isolation_and_installed, encode_handoff_with_smp,
    encode_handoff_with_smp_recovery_isolation_and_installed,
};
#[cfg(target_os = "linux")]
use mrml_kvm::{KvmLaunchLayout, KvmSystem, PreparedKvmGuest};
#[cfg(target_os = "linux")]
use mrml_package_format::{
    ComponentServicePlacement, InterfaceCatalogView, MAX_BOOT_PACKAGE_BYTES,
    MAX_BOOT_RELEASE_BYTES, MAX_SYSTEM_RELEASE_BYTES, ManifestInterfaceDeclaration,
    RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
    SystemGenerationDigestRecord, SystemGenerationView, admit_kernel_payload,
    decode_canonical_manifest_interface, encode_interface_catalog, encode_runtime_inventory,
    encode_system_generation, resolve_activated_interface_catalog,
};
#[cfg(target_os = "linux")]
use mrml_runtime::Instant;
#[cfg(target_os = "linux")]
use mrml_runtime::Vector;
#[cfg(target_os = "linux")]
use mrml_runtime::mrml_println as println;

#[cfg(target_os = "linux")]
type KvmConfigurationLauncher =
    PreparedMicrovmConfigurationLauncher<AdmittedConfigurationGuestFactory<PreparedKvmGuest<16>>>;

#[cfg(target_os = "linux")]
type KvmApplicationLauncher =
    PreparedMicrovmApplicationBackend<AdmittedApplicationGuestFactory<PreparedKvmGuest<16>>>;

#[cfg(target_os = "linux")]
struct ConfiguredTotalServicePolicy {
    effective: Option<EffectiveBootIsolationPolicy>,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
}

#[cfg(target_os = "linux")]
enum KvmTotalAdmission {
    Standalone(IsolationAdmissionTable<2>),
    Recovered(RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>),
}

#[cfg(target_os = "linux")]
impl core::ops::Deref for KvmTotalAdmission {
    type Target = IsolationAdmissionTable<2>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Standalone(admission) => admission,
            Self::Recovered(total) => total.admission(),
        }
    }
}

#[cfg(target_os = "linux")]
impl core::ops::DerefMut for KvmTotalAdmission {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Standalone(admission) => admission,
            Self::Recovered(total) => total.admission_mut(),
        }
    }
}

#[cfg(target_os = "linux")]
const APPLICATION_MEMORY_NAMESPACE: u16 = 0x3a50;
#[cfg(target_os = "linux")]
const APPLICATION_CPU_NAMESPACE: u16 = 0x3a51;

#[cfg(target_os = "linux")]
struct KvmApplicationProjection {
    prepared: Option<MicrovmProjectionPlan<1>>,
    active: Option<ActiveMicrovmProjectionPlan<1>>,
    memory: MemoryPoolTable<1, 1>,
    cpu: CpuBudgetTable<1, 1>,
    capabilities: CapabilitySpace<4>,
    ram_capability: Capability,
    cpu_capability: Capability,
}

#[cfg(target_os = "linux")]
impl KvmApplicationProjection {
    fn prepare(spec: IsolationApplicationSpec, guest_pages: u64) -> Result<Self> {
        let mut capabilities = CapabilitySpace::<4>::new();
        let mut memory = MemoryPoolTable::<1, 1>::new(APPLICATION_MEMORY_NAMESPACE)
            .map_err(|error| anyhow!("application RAM table failed: {:?}", error))?;
        let (pool, pool_capability) = memory
            .create_root(
                guest_pages,
                1,
                0,
                Rights::ALLOCATE
                    .union(Rights::CONTROL)
                    .union(Rights::INSPECT),
                &mut capabilities,
            )
            .map_err(|error| anyhow!("application RAM pool failed: {:?}", error))?;
        let (ram, ram_capability) = reserve_microvm_guest_ram(
            &mut memory,
            pool,
            pool_capability,
            guest_pages,
            &mut capabilities,
        )
        .map_err(|error| anyhow!("application RAM reservation failed: {:?}", error))?;
        let mut cpu = CpuBudgetTable::<1, 1>::new(APPLICATION_CPU_NAMESPACE)
            .map_err(|error| anyhow!("application CPU table failed: {:?}", error))?;
        let budget_spec = CpuBudgetSpec::new(1, 100_000, 100_000, 0, 1)
            .map_err(|error| anyhow!("application CPU budget failed: {:?}", error))?;
        let (budget, cpu_capability) = cpu
            .create_root(budget_spec, &mut capabilities)
            .map_err(|error| anyhow!("application CPU root failed: {:?}", error))?;
        let vcpus = cpu
            .reserve_vcpus(budget, cpu_capability, spec.domain(), 1, &capabilities)
            .map_err(|error| anyhow!("application vCPU reservation failed: {:?}", error))?;
        let interface_object = ObjectId(0x4150_505f_4950_4301);
        let interface_capability = capabilities
            .insert(interface_object, Rights::SIGNAL)
            .map_err(|error| anyhow!("application interface authority failed: {:?}", error))?;
        let interface = MicrovmProjectionDescriptor::new(
            MicrovmProjectionKind::InterfaceTransport,
            interface_object,
            1,
            interface_capability,
            Rights::SIGNAL,
        )
        .map_err(|error| anyhow!("application interface projection failed: {:?}", error))?;
        let requirements = MicrovmProjectionRequirements::for_application(
            spec,
            guest_pages,
            1,
            &[MicrovmProjectionKind::InterfaceTransport],
        )
        .map_err(|error| anyhow!("application projection requirements failed: {:?}", error))?;
        let prepared = admit_microvm_projection(
            requirements,
            ram,
            ram_capability,
            &memory,
            vcpus,
            cpu_capability,
            &cpu,
            [Some(interface)],
            &capabilities,
        )
        .map_err(|failure| anyhow!("application projection admission failed: {:?}", failure))?;
        Ok(Self {
            prepared: Some(prepared),
            active: None,
            memory,
            cpu,
            capabilities,
            ram_capability,
            cpu_capability,
        })
    }

    fn activate(&mut self) -> Result<()> {
        let active = self
            .prepared
            .take()
            .ok_or_else(|| anyhow!("application projection was already consumed"))?
            .activate_data_plane()
            .map_err(|error| anyhow!("application RAM activation failed: {:?}", error))?;
        self.active = Some(active);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let active = self
            .active
            .take()
            .ok_or_else(|| anyhow!("application projection was not active"))?;
        let (ram, vcpus, descriptors) = unsafe { active.retire() };
        for descriptor in descriptors.into_iter().flatten() {
            self.capabilities
                .revoke(descriptor.capability())
                .map_err(|error| anyhow!("application projection revoke failed: {:?}", error))?;
        }
        unsafe {
            release_microvm_guest_ram(
                &mut self.memory,
                ram,
                self.ram_capability,
                &mut self.capabilities,
            )
        }
        .map_err(|error| anyhow!("application RAM release failed: {:?}", error))?;
        self.cpu
            .release_vcpus(vcpus, self.cpu_capability, &self.capabilities)
            .map_err(|error| anyhow!("application vCPU release failed: {:?}", error))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn total_application_spec(
    package_id: &'static str,
    executable: &VerifiedExecutable<'_>,
) -> Result<IsolationApplicationSpec> {
    let record = SystemGenerationDigestRecord {
        package_id,
        version: executable.artifact().version(),
        artifact_digest: executable.artifact().digest(),
    };
    let mut generation_bytes = [0u8; 256];
    let generation_length = encode_system_generation(1, &[record], &mut generation_bytes)
        .map_err(|error| anyhow!("application SystemGeneration encoding failed: {:?}", error))?;
    let generation = SystemGenerationView::decode(&generation_bytes[..generation_length])
        .map_err(|error| anyhow!("application SystemGeneration decoding failed: {:?}", error))?;
    let bound = bind_verified_application_image(package_id, generation, executable.artifact())
        .map_err(|error| anyhow!("application generation binding failed: {:?}", error))?;
    bound
        .route_spec(
            ObjectId(0x4150_505f_444f_4d),
            ObjectId(0x4150_505f_5052_4f42),
            1,
            IsolationPlacement::Microvm,
        )
        .map_err(|error| anyhow!("application route specification failed: {:?}", error))
}

#[cfg(target_os = "linux")]
fn application_guest_pages(
    table_pages: u64,
    kernel: &VerifiedExecutable<'_>,
    handoff_bytes: usize,
    application: ApplicationLaunch,
    application_bundle_bytes: usize,
) -> Result<u64> {
    table_pages
        .checked_add(accounted_pages(u64::from(kernel.image().image_size()))?)
        .and_then(|pages| pages.checked_add(accounted_pages(handoff_bytes as u64).ok()?))
        .and_then(|pages| pages.checked_add(PRIVILEGE_STACK_ARENA_PAGES))
        .and_then(|pages| pages.checked_add(accounted_pages(application_bundle_bytes as u64).ok()?))
        .and_then(|pages| pages.checked_add(application.image_pages()))
        .and_then(|pages| pages.checked_add(application.stack_pages()))
        .and_then(|pages| pages.checked_add(application.table_pages()))
        .ok_or_else(|| anyhow!("application guest RAM commitment overflow"))
}

#[cfg(target_os = "linux")]
const COMPONENT_MEMORY_OBJECTS: usize = 4 + 2 * (MAX_COMPONENT_IMAGE_REGIONS + 1);
#[cfg(target_os = "linux")]
const COMPONENT_MEMORY_MAPPINGS: usize = 2 + 2 * MAX_COMPONENT_IMAGE_REGIONS;
#[cfg(target_os = "linux")]
const COMPONENT_MEMORY_CAPABILITIES: usize = 7 + 2 * (MAX_COMPONENT_IMAGE_REGIONS + 1);

#[cfg(target_os = "linux")]
type ComponentCpuAuthority = (
    CpuBudgetTable<1, 1>,
    CapabilitySpace<1>,
    CpuBudgetId,
    Capability,
    VcpuReservationId,
    [u64; 2],
);

#[cfg(target_os = "linux")]
fn run_component_vcpu<T>(
    cpu: &mut Option<ComponentCpuAuthority>,
    run: impl FnOnce(CpuRuntimeSlice) -> Result<T>,
) -> Result<T> {
    let (budgets, capabilities, budget, capability, reservation, next_start) = cpu
        .as_mut()
        .ok_or_else(|| anyhow!("missing component vCPU runtime authority"))?;
    let usage = budgets
        .usage(*budget, *capability, capabilities)
        .map_err(|error| anyhow!("component vCPU usage failed: {:?}", error))?;
    let remaining_runtime = usage
        .spec()
        .runtime_micros()
        .checked_sub(usage.consumed_runtime_micros())
        .ok_or_else(|| anyhow!("component vCPU runtime accounting underflow"))?;
    let period_start = usage
        .runtime_period_start_micros()
        .ok_or_else(|| anyhow!("component vCPU period was not started"))?;
    let period_end = period_start
        .checked_add(u64::from(usage.spec().period_micros()))
        .ok_or_else(|| anyhow!("component vCPU period overflow"))?;
    let remaining_period =
        u32::try_from(period_end.saturating_sub(next_start[0])).unwrap_or(u32::MAX);
    let maximum = remaining_runtime.min(remaining_period);
    let slice: CpuRuntimeSlice = budgets
        .authorize_runtime_slice(
            *reservation,
            *capability,
            0,
            0,
            0,
            next_start[0],
            maximum,
            capabilities,
        )
        .map_err(|error| anyhow!("component vCPU runtime charge failed: {:?}", error))?;
    let started = Instant::now();
    let result = run(slice);
    let elapsed = u64::try_from(started.elapsed().as_micros())
        .map_err(|_| anyhow!("component vCPU elapsed time overflow"))?;
    let end = next_start[0]
        .checked_add(elapsed)
        .ok_or_else(|| anyhow!("component vCPU runtime cursor overflow"))?;
    budgets
        .reconcile_runtime_slice(slice, *capability, end, capabilities)
        .map_err(|error| anyhow!("component vCPU runtime reconciliation failed: {:?}", error))?;
    next_start[0] = end;
    result
}

#[cfg(target_os = "linux")]
fn run_component_smp<B>(
    cpu: &mut Option<ComponentCpuAuthority>,
    backend: &mut B,
) -> Result<([VmExit; 2], [u64; 2])>
where
    B: ScheduledSmpVmBackend,
    B::Error: core::fmt::Debug,
{
    let (budgets, capabilities, _budget, capability, reservation, next_start) = cpu
        .as_mut()
        .ok_or_else(|| anyhow!("missing component SMP runtime authority"))?;
    let usage = budgets
        .usage(*_budget, *capability, capabilities)
        .map_err(|error| anyhow!("component SMP usage failed: {:?}", error))?;
    if usage.spec().maximum_parallelism() != 2 {
        return Err(anyhow!("component SMP authority is not exactly two-vCPU"));
    }
    let maximum = usage.spec().runtime_micros() / 2;
    let bootstrap = budgets
        .authorize_runtime_slice(
            *reservation,
            *capability,
            0,
            0,
            0,
            next_start[0],
            maximum,
            capabilities,
        )
        .map_err(|error| anyhow!("component bootstrap vCPU charge failed: {:?}", error))?;
    let application = match budgets.authorize_runtime_slice(
        *reservation,
        *capability,
        1,
        1,
        0,
        next_start[1],
        maximum,
        capabilities,
    ) {
        Ok(slice) => slice,
        Err(error) => {
            let _ = budgets.reconcile_runtime_slice(
                bootstrap,
                *capability,
                next_start[0],
                capabilities,
            );
            return Err(anyhow!(
                "component application vCPU charge failed: {:?}",
                error
            ));
        }
    };
    let run = ScheduledSmpVmBackend::run_smp_with_scheduling_deadlines(
        backend,
        [bootstrap.logical_cpu(), application.logical_cpu()],
        [bootstrap.priority(), application.priority()],
        [bootstrap.charged_micros(), application.charged_micros()],
    );
    let (elapsed, outcomes) = match run {
        Ok(outcomes) => (
            [outcomes[0].elapsed_micros(), outcomes[1].elapsed_micros()],
            Ok(outcomes),
        ),
        Err(error) => (
            [u64::from(maximum); 2],
            Err(anyhow!(
                "scheduled component SMP execution failed: {:?}",
                error
            )),
        ),
    };
    for (index, (slice, elapsed)) in [bootstrap, application]
        .into_iter()
        .zip(elapsed)
        .enumerate()
    {
        let end = next_start[index]
            .checked_add(elapsed)
            .ok_or_else(|| anyhow!("component SMP runtime cursor overflow"))?;
        budgets
            .reconcile_runtime_slice(slice, *capability, end, capabilities)
            .map_err(|error| {
                anyhow!(
                    "component vCPU {} reconciliation failed: {:?}",
                    index,
                    error
                )
            })?;
        next_start[index] = end;
    }
    let outcomes = outcomes?;
    let [bootstrap, application] = outcomes;
    let bootstrap = match bootstrap.outcome() {
        VmDeadlineOutcome::Exit(exit) => exit,
        VmDeadlineOutcome::Expired => {
            return Err(anyhow!("component bootstrap vCPU deadline expired"));
        }
    };
    let application = match application.outcome() {
        VmDeadlineOutcome::Exit(exit) => exit,
        VmDeadlineOutcome::Expired => {
            return Err(anyhow!("component application vCPU deadline expired"));
        }
    };
    Ok(([bootstrap, application], elapsed))
}

#[cfg(target_os = "linux")]
fn run_scheduled_smp<B>(backend: &mut B) -> Result<([VmExit; 2], [u64; 2])>
where
    B: ScheduledSmpVmBackend,
    B::Error: core::fmt::Debug,
{
    const SLICE_MICROS: u32 = 100_000;
    let mut capabilities = CapabilitySpace::<1>::new();
    let mut budgets = CpuBudgetTable::<1, 1>::new(0x1a54)
        .map_err(|error| anyhow!("SMP CPU table failed: {:?}", error))?;
    let spec = CpuBudgetSpec::new(2, 2 * SLICE_MICROS, 2 * SLICE_MICROS, 0, 0b11)
        .map_err(|error| anyhow!("SMP CPU budget failed: {:?}", error))?;
    let (budget, capability) = budgets
        .create_root(spec, &mut capabilities)
        .map_err(|error| anyhow!("SMP CPU root failed: {:?}", error))?;
    let reservation = budgets
        .reserve_vcpus(
            budget,
            capability,
            ObjectId(0x534d_505f_5052_4f42),
            2,
            &capabilities,
        )
        .map_err(|error| anyhow!("SMP vCPU reservation failed: {:?}", error))?;
    budgets
        .start_runtime_period(reservation, capability, 0, &capabilities)
        .map_err(|error| anyhow!("SMP CPU runtime start failed: {:?}", error))?;
    let bootstrap = budgets
        .authorize_runtime_slice(
            reservation,
            capability,
            0,
            0,
            0,
            0,
            SLICE_MICROS,
            &capabilities,
        )
        .map_err(|error| anyhow!("bootstrap SMP runtime charge failed: {:?}", error))?;
    let application = match budgets.authorize_runtime_slice(
        reservation,
        capability,
        1,
        1,
        0,
        0,
        SLICE_MICROS,
        &capabilities,
    ) {
        Ok(slice) => slice,
        Err(error) => {
            let _ = budgets.reconcile_runtime_slice(bootstrap, capability, 0, &capabilities);
            let _ = budgets.release_vcpus(reservation, capability, &capabilities);
            let _ = budgets.retire_root(budget, capability, &mut capabilities);
            return Err(anyhow!(
                "application SMP runtime charge failed: {:?}",
                error
            ));
        }
    };
    let run = ScheduledSmpVmBackend::run_smp_with_scheduling_deadlines(
        backend,
        [bootstrap.logical_cpu(), application.logical_cpu()],
        [bootstrap.priority(), application.priority()],
        [bootstrap.charged_micros(), application.charged_micros()],
    );
    let (ends, outcomes) = match run {
        Ok(outcomes) => (
            [outcomes[0].elapsed_micros(), outcomes[1].elapsed_micros()],
            Ok(outcomes),
        ),
        Err(error) => (
            [u64::from(SLICE_MICROS); 2],
            Err(anyhow!("scheduled KVM SMP execution failed: {:?}", error)),
        ),
    };
    let bootstrap_reconciliation =
        budgets.reconcile_runtime_slice(bootstrap, capability, ends[0], &capabilities);
    let application_reconciliation =
        budgets.reconcile_runtime_slice(application, capability, ends[1], &capabilities);
    let released = budgets
        .release_vcpus(reservation, capability, &capabilities)
        .map_err(|error| anyhow!("SMP vCPU release failed: {:?}", error));
    let retired = budgets
        .retire_root(budget, capability, &mut capabilities)
        .map_err(|error| anyhow!("SMP CPU root retirement failed: {:?}", error));
    bootstrap_reconciliation.map_err(|error| {
        anyhow!(
            "bootstrap SMP runtime reconciliation failed at {}us: {:?}",
            ends[0],
            error
        )
    })?;
    application_reconciliation.map_err(|error| {
        anyhow!(
            "application SMP runtime reconciliation failed at {}us: {:?}",
            ends[1],
            error
        )
    })?;
    released?;
    retired?;
    let outcomes = outcomes?;
    let bootstrap_exit = match outcomes[0].outcome() {
        VmDeadlineOutcome::Exit(exit) => exit,
        VmDeadlineOutcome::Expired => return Err(anyhow!("KVM bootstrap vCPU deadline expired")),
    };
    let application_exit = match outcomes[1].outcome() {
        VmDeadlineOutcome::Exit(exit) => exit,
        VmDeadlineOutcome::Expired => return Err(anyhow!("KVM application vCPU deadline expired")),
    };
    Ok(([bootstrap_exit, application_exit], ends))
}

#[cfg(target_os = "linux")]
fn recover_hosted_component_owner<'out>(
    handoff: &BootHandoff,
    release: &[u8],
    release_key: &[u8; 64],
    output: &mut [u8],
    installed: Option<(
        [mrml_config::hosted_recovery_probe::HostedInstalledService<'_, 'out>; 2],
        mrml_config::hosted_recovery_probe::HostedRecoveryDisk<'_>,
    )>,
) -> core::result::Result<
    (
        RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>,
        Option<[VerifiedExecutable<'out>; 2]>,
    ),
    mrml_config::hosted_recovery_probe::HostedRecoveryProbeBuildError<()>,
> {
    // SAFETY: both modes build only controlled hosted fixtures. Their synthesized
    // approval is not production recovery or physical evidence.
    unsafe {
        if let Some((services, image)) = installed {
            mrml_config::hosted_recovery_probe::recover_distinct_total_control_plane_with_installed_services(
                handoff, release, release_key, output, services, image,
            ).map(|(owner, executables)| (owner, Some(executables)))
        } else {
            recover_total_control_plane::<2>(handoff, release, release_key, output)
                .map(|owner| (owner, None))
        }
    }
}

#[cfg(target_os = "linux")]
fn configured_total_service_policy(
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
    handoff: &BootHandoff,
) -> Result<ConfiguredTotalServicePolicy> {
    let service =
        configured_isolation_service(domain, interface, interface_generation, provider_generation)?;
    let root_object = ObjectId(0x4953_4f4c_4154_494f);
    let component_object = ObjectId(0x434f_4e46_504f_4c59);
    let system_object = ObjectId(0x5359_5354_504f_4c59);
    let component = IsolationPolicySetting::component(
        SettingId::new(1).map_err(|error| anyhow!("KVM component setting failed: {:?}", error))?,
        component_object,
        IsolationPlacement::NativeService,
    )
    .map_err(|error| anyhow!("KVM component policy failed: {:?}", error))?;
    let system = IsolationPolicySetting::system(
        SettingId::new(2).map_err(|error| anyhow!("KVM system setting failed: {:?}", error))?,
        system_object,
    )
    .map_err(|error| anyhow!("KVM system policy failed: {:?}", error))?;
    let mut configuration = ConfigurationService::<2, 4>::new(
        root_object,
        &[
            component
                .schema()
                .map_err(|error| anyhow!("KVM component schema failed: {:?}", error))?,
            system
                .schema()
                .map_err(|error| anyhow!("KVM system schema failed: {:?}", error))?,
        ],
    )
    .map_err(|error| anyhow!("KVM policy configuration failed: {:?}", error))?;
    let mut capabilities = CapabilitySpace::<5>::new();
    let root = capabilities
        .insert(root_object, Rights::CONTROL)
        .map_err(|error| anyhow!("KVM policy root capability failed: {:?}", error))?;
    let component_write = capabilities
        .insert(component_object, Rights::WRITE)
        .map_err(|error| anyhow!("KVM component write capability failed: {:?}", error))?;
    let component_read = capabilities
        .insert(component_object, Rights::READ)
        .map_err(|error| anyhow!("KVM component read capability failed: {:?}", error))?;
    let system_write = capabilities
        .insert(system_object, Rights::WRITE)
        .map_err(|error| anyhow!("KVM system write capability failed: {:?}", error))?;
    let system_read = capabilities
        .insert(system_object, Rights::READ)
        .map_err(|error| anyhow!("KVM system read capability failed: {:?}", error))?;
    let mut transaction = ConfigTransaction::<2>::new(0);
    component
        .stage(
            &mut transaction,
            component_write,
            OwnerIsolationSelection::Microvm,
        )
        .map_err(|error| anyhow!("KVM component policy staging failed: {:?}", error))?;
    system
        .stage(
            &mut transaction,
            system_write,
            OwnerIsolationSelection::TotalMicrovm,
        )
        .map_err(|error| anyhow!("KVM system policy staging failed: {:?}", error))?;
    configuration
        .commit(&capabilities, root, &transaction)
        .map_err(|error| anyhow!("KVM policy commit failed: {:?}", error))?;
    let plan = IsolationPolicyApplicationPlan::load(
        &configuration,
        &capabilities,
        system,
        system_read,
        component,
        component_read,
    )
    .map_err(|error| anyhow!("KVM policy load failed: {:?}", error))?;
    let recovery = handoff
        .recovery_state()
        .ok_or_else(|| anyhow!("KVM Total policy requires decoded recovery metadata"))?;
    let effective = plan
        .apply(&configuration, &capabilities)
        .map_err(|error| anyhow!("KVM configured isolation application failed: {:?}", error))?
        .compose_boot_override(handoff.isolation_override());
    if effective.mode() != IsolationMode::TotalMicrovm
        || effective.boot_override() != Some(BootIsolationOverride::TotalMicrovmOnce)
    {
        return Err(anyhow!(
            "KVM canonical boot handoff did not request strict Total MicroVM isolation"
        ));
    }
    println!(
        "isolation-boot-policy|status=PASS|backend=kvm|configured=total-microvm|component=microvm|handoff=decoded|accepted_epoch={}|override=total-microvm-once|effective=total-microvm|policy_generation={}",
        recovery.accepted_epoch(),
        effective.policy_generation()
    );
    Ok(ConfiguredTotalServicePolicy {
        effective: Some(effective),
        bounds: service.bounds,
        identity: service.identity,
    })
}

#[cfg(target_os = "linux")]
fn configured_isolation_service(
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
) -> Result<ConfiguredTotalServicePolicy> {
    let bounds = IsolationServiceBounds::new(
        IsolationPlacement::NativeService,
        IsolationPlacement::NativeService,
        IsolationPlacement::Microvm,
        true,
        true,
    )
    .map_err(|error| anyhow!("KVM package isolation bounds failed: {:?}", error))?;
    let identity = IsolationServiceIdentity::new(
        domain,
        interface,
        interface_generation,
        provider_generation,
        TotalMicrovmClass::MicrovmEligible,
    )
    .map_err(|error| anyhow!("KVM service identity failed: {:?}", error))?;
    Ok(ConfiguredTotalServicePolicy {
        effective: None,
        bounds,
        identity,
    })
}

#[cfg(target_os = "linux")]
enum KvmGuestOwner {
    Direct(PreparedKvmGuest<16>),
    Application {
        launcher: KvmApplicationLauncher,
        endpoint: ApplicationMicrovmEndpoint,
        projection: KvmApplicationProjection,
    },
    Configuration {
        launcher: KvmConfigurationLauncher,
        endpoint: ConfigurationMicrovmEndpoint,
    },
}

#[cfg(target_os = "linux")]
impl KvmGuestOwner {
    fn guest(&self) -> &PreparedKvmGuest<16> {
        match self {
            Self::Direct(guest) => guest,
            Self::Application {
                launcher, endpoint, ..
            } => launcher
                .active_guest(*endpoint)
                .expect("stored application endpoint must select its retained guest"),
            Self::Configuration { launcher, endpoint } => launcher
                .active_guest(*endpoint)
                .expect("stored configuration endpoint must select its retained guest"),
        }
    }

    fn guest_mut(&mut self) -> &mut PreparedKvmGuest<16> {
        match self {
            Self::Direct(guest) => guest,
            Self::Application {
                launcher, endpoint, ..
            } => launcher
                .active_guest_mut(*endpoint)
                .expect("stored application endpoint must select its retained guest"),
            Self::Configuration { launcher, endpoint } => launcher
                .active_guest_mut(*endpoint)
                .expect("stored configuration endpoint must select its retained guest"),
        }
    }

    fn into_direct(self) -> Result<PreparedKvmGuest<16>> {
        match self {
            Self::Direct(guest) => Ok(guest),
            Self::Application { .. } | Self::Configuration { .. } => Err(anyhow!(
                "retained application/configuration microVM cannot enter an unrelated launch path"
            )),
        }
    }

    fn finish(mut self) -> Result<()> {
        match &mut self {
            Self::Application {
                launcher,
                endpoint,
                projection,
            } => {
                launcher
                    .revoke(endpoint)
                    .map_err(|error| anyhow!("KVM application teardown failed: {:?}", error))?;
                projection.finish()?;
            }
            Self::Configuration { launcher, endpoint } => launcher
                .revoke_microvm(endpoint)
                .map_err(|error| anyhow!("KVM configuration teardown failed: {:?}", error))?,
            Self::Direct(_) => {}
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl core::ops::Deref for KvmGuestOwner {
    type Target = PreparedKvmGuest<16>;

    fn deref(&self) -> &Self::Target {
        self.guest()
    }
}

#[cfg(target_os = "linux")]
impl core::ops::DerefMut for KvmGuestOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guest_mut()
    }
}

#[cfg(target_os = "linux")]
impl VmBackend for KvmGuestOwner {
    type Error = <PreparedKvmGuest<16> as VmBackend>::Error;

    fn run(&mut self, vcpu: u32) -> core::result::Result<VmExit, Self::Error> {
        VmBackend::run(self.guest_mut(), vcpu)
    }

    fn read_guest(
        &self,
        guest_address: u64,
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        VmBackend::read_guest(self.guest(), guest_address, output)
    }

    fn write_guest(
        &mut self,
        guest_address: u64,
        input: &[u8],
    ) -> core::result::Result<(), Self::Error> {
        VmBackend::write_guest(self.guest_mut(), guest_address, input)
    }

    fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> core::result::Result<(), Self::Error> {
        VmBackend::inject_interrupt(self.guest_mut(), vcpu, vector)
    }
}

#[cfg(target_os = "linux")]
impl DeadlineVmBackend for KvmGuestOwner {
    fn run_with_deadline(
        &mut self,
        vcpu: u32,
        maximum_micros: u32,
    ) -> core::result::Result<VmDeadlineOutcome, Self::Error> {
        DeadlineVmBackend::run_with_deadline(self.guest_mut(), vcpu, maximum_micros)
    }
}

#[cfg(target_os = "linux")]
impl AffinityDeadlineVmBackend for KvmGuestOwner {
    fn run_with_affinity_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        maximum_micros: u32,
    ) -> core::result::Result<VmDeadlineOutcome, Self::Error> {
        AffinityDeadlineVmBackend::run_with_affinity_deadline(
            self.guest_mut(),
            vcpu,
            logical_cpu,
            maximum_micros,
        )
    }
}

#[cfg(target_os = "linux")]
impl ScheduledDeadlineVmBackend for KvmGuestOwner {
    fn run_with_scheduling_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        priority: u8,
        maximum_micros: u32,
    ) -> core::result::Result<VmDeadlineOutcome, Self::Error> {
        ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
            self.guest_mut(),
            vcpu,
            logical_cpu,
            priority,
            maximum_micros,
        )
    }
}

#[cfg(target_os = "linux")]
impl ScheduledSmpVmBackend for KvmGuestOwner {
    fn run_smp_with_scheduling_deadlines(
        &mut self,
        logical_cpus: [u8; 2],
        priorities: [u8; 2],
        maximum_micros: [u32; 2],
    ) -> core::result::Result<[mrml_kernel::ScheduledVcpuOutcome; 2], Self::Error> {
        ScheduledSmpVmBackend::run_smp_with_scheduling_deadlines(
            self.guest_mut(),
            logical_cpus,
            priorities,
            maximum_micros,
        )
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
const MAX_KERNEL_BUNDLE: usize = SIGNED_ARTIFACT_OVERHEAD_BYTES + 16 * 1024 * 1024;
#[cfg(any(test, target_os = "linux"))]
const FRAMEBUFFER: u64 = 0x00a0_0000;
#[cfg(target_os = "linux")]
const APPLICATION_PROBE_PORT: u16 = 0x4d66;
#[cfg(target_os = "linux")]
const APPLICATION_ARTIFACT_PHYSICAL: u64 = 0x00a0_1000;
#[cfg(target_os = "linux")]
const APPLICATION_IMAGE_PHYSICAL: u64 = 0x00a2_0000;
#[cfg(target_os = "linux")]
const APPLICATION_STACK_PHYSICAL: u64 = 0x00a2_8000;
#[cfg(target_os = "linux")]
const APPLICATION_STACK_TOP: u64 = 0x0090_0000;
#[cfg(target_os = "linux")]
const APPLICATION_TABLE_PHYSICAL: u64 = 0x00a3_0000;
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
fn accounted_pages(bytes: u64) -> Result<u64> {
    bytes
        .checked_add(mrml_kernel::PAGE_SIZE - 1)
        .map(|rounded| rounded / mrml_kernel::PAGE_SIZE)
        .filter(|pages| *pages != 0)
        .ok_or_else(|| anyhow!("invalid guest RAM extent"))
}
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
#[cfg(target_os = "linux")]
const PCI_PROOF_PORT: u16 = 0x4d66;
#[cfg(target_os = "linux")]
const PCI_WITHDRAW_PROOF_PORT: u16 = 0x4d67;
#[cfg(target_os = "linux")]
const PCI_TEST_SELECTOR: u32 = 0x8000_2000;
#[cfg(target_os = "linux")]
const PCI_TEST_CLASS_SELECTOR: u32 = PCI_TEST_SELECTOR + 8;
#[cfg(target_os = "linux")]
const PCI_TEST_VENDOR_DEVICE: u32 = 0x5678_1234;
#[cfg(target_os = "linux")]
const PCI_TEST_CLASS: u32 = 0x0180_0001;
#[cfg(target_os = "linux")]
const PCI_TEST_BAR_SELECTOR: u32 = PCI_TEST_SELECTOR + 16;
#[cfg(target_os = "linux")]
const PCI_TEST_COMMAND_SELECTOR: u32 = PCI_TEST_SELECTOR + 4;
#[cfg(target_os = "linux")]
const PCI_TEST_MMIO_BASE: u64 = 0x00c0_0000;
#[cfg(target_os = "linux")]
const PCI_BLOCK_PROBE_OPERATIONS: u32 = 5;
#[cfg(target_os = "linux")]
const PCI_PROBE_POLICY_EXITS: u64 = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
enum LaunchMode {
    Boot,
    ApplicationProbe,
    GuiApplicationProbe,
    FaultProbe,
    TimerProbe,
    PreemptionProbe,
    UserProbe,
    ServiceProbe,
    CertificateServiceProbe,
    DeadlineReceiveProbe,
    DeadlineReceiveMessageProbe,
    DeadlineReceiveCancelProbe,
    DeadlineReceiveCancelDeniedProbe,
    DeadlineReceiveCancelReplayProbe,
    InvalidReturnProbe,
    BufferDriftProbe,
    ComponentServiceProbe,
    ComponentServiceSmpProbe,
    ComponentReleaseInputs,
    BlockServiceProbe,
    BlockGuestDriverProbe,
    PciConfigurationProbe,
    ServiceRestartRequestProbe,
    ScanoutServiceProbe,
    ScanoutServiceDeniedProbe,
    Fat32ReadyProbe,
    Fat32DataProbe,
    Fat32RestartProbe,
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
            "application-probe" => Ok(Self::ApplicationProbe),
            "gui-application-probe" => Ok(Self::GuiApplicationProbe),
            "fault-probe" => Ok(Self::FaultProbe),
            "timer-probe" => Ok(Self::TimerProbe),
            "preemption-probe" => Ok(Self::PreemptionProbe),
            "user-probe" => Ok(Self::UserProbe),
            "service-probe" => Ok(Self::ServiceProbe),
            "certificate-service-probe" => Ok(Self::CertificateServiceProbe),
            "deadline-receive-probe" => Ok(Self::DeadlineReceiveProbe),
            "deadline-receive-message-probe" => Ok(Self::DeadlineReceiveMessageProbe),
            "deadline-receive-cancel-probe" => Ok(Self::DeadlineReceiveCancelProbe),
            "deadline-receive-cancel-denied-probe" => Ok(Self::DeadlineReceiveCancelDeniedProbe),
            "deadline-receive-cancel-replay-probe" => Ok(Self::DeadlineReceiveCancelReplayProbe),
            "invalid-return-probe" => Ok(Self::InvalidReturnProbe),
            "buffer-drift-probe" => Ok(Self::BufferDriftProbe),
            "component-service-probe" => Ok(Self::ComponentServiceProbe),
            "component-service-smp-probe" => Ok(Self::ComponentServiceSmpProbe),
            "component-release-inputs" => Ok(Self::ComponentReleaseInputs),
            "block-service-probe" => Ok(Self::BlockServiceProbe),
            "block-guest-driver-probe" => Ok(Self::BlockGuestDriverProbe),
            "pci-configuration-probe" => Ok(Self::PciConfigurationProbe),
            "service-restart-request-probe" => Ok(Self::ServiceRestartRequestProbe),
            "scanout-service-probe" => Ok(Self::ScanoutServiceProbe),
            "scanout-service-denied-probe" => Ok(Self::ScanoutServiceDeniedProbe),
            "fat32-ready-probe" => Ok(Self::Fat32ReadyProbe),
            "fat32-data-probe" => Ok(Self::Fat32DataProbe),
            "fat32-restart-probe" => Ok(Self::Fat32RestartProbe),
            "service-preemption-probe" => Ok(Self::ServicePreemptionProbe),
            "gpu-benchmark" => Ok(Self::GpuBenchmark),
            "smp-probe" => Ok(Self::SmpProbe),
            "smp-scheduler-probe" => Ok(Self::SmpSchedulerProbe),
            "smp-ipi-probe" => Ok(Self::SmpIpiProbe),
            "smp-service-migration-probe" => Ok(Self::SmpServiceMigrationProbe),
            "smp-periodic-balance-probe" => Ok(Self::SmpPeriodicBalanceProbe),
            _ => Err(anyhow!(
                "mode must be boot, application-probe, gui-application-probe, fault-probe, timer-probe, preemption-probe, user-probe, service-probe, certificate-service-probe, deadline-receive-probe, deadline-receive-message-probe, deadline-receive-cancel-probe, deadline-receive-cancel-denied-probe, deadline-receive-cancel-replay-probe, invalid-return-probe, buffer-drift-probe, component-service-probe, component-release-inputs, block-service-probe, block-guest-driver-probe, pci-configuration-probe, service-restart-request-probe, fat32-ready-probe, fat32-data-probe, fat32-restart-probe, service-preemption-probe, gpu-benchmark, smp-probe, smp-scheduler-probe, smp-ipi-probe, smp-service-migration-probe, smp-periodic-balance-probe, scanout-service-probe, or scanout-service-denied-probe"
            )),
        }
    }

    const fn application_package_id(self) -> Option<&'static str> {
        match self {
            Self::ApplicationProbe => Some("org.mrml.app.isolation-probe"),
            Self::GuiApplicationProbe => Some("org.mrml.app.gui-probe"),
            _ => None,
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn require_invalid_return_stage(exit: VmExit, expected: u32) -> Result<()> {
    if !matches!(expected, 0x26 | 0x27) {
        return Err(anyhow!("invalid-return expected stage is not canonical"));
    }
    if exit
        != (VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value: expected,
        })
    {
        return Err(anyhow!(
            "invalid-return stage {:#x} mismatch: {:?}",
            expected,
            exit
        ));
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn require_buffer_drift_stage(exit: VmExit, expected: u32) -> Result<()> {
    if !matches!(expected, 0x28 | 0x29) {
        return Err(anyhow!("buffer-drift expected stage is not canonical"));
    }
    if exit
        != (VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value: expected,
        })
    {
        return Err(anyhow!(
            "buffer-drift stage {:#x} mismatch: {:?}",
            expected,
            exit
        ));
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn require_deadline_receive_proof(exit: VmExit, expected: u32) -> Result<()> {
    if !matches!(expected, 0x2a | 0x2b | 0x2c | 0x2d | 0x2e) {
        return Err(anyhow!("deadline-receive proof is not canonical"));
    }
    if exit
        != (VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value: expected,
        })
    {
        return Err(anyhow!("deadline-receive proof mismatch: {:?}", exit));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct DriverProbeBlock([u8; 8192], usize);

#[cfg(target_os = "linux")]
struct NativePciMmioWindow {
    mapped: bool,
}

#[cfg(target_os = "linux")]
struct DestroyedPciBlockResources<'a> {
    capabilities: &'a mut CapabilitySpace<2>,
    block_capability: mrml_kernel::Capability,
    interrupt_capability: mrml_kernel::Capability,
    expected_pci: VirtualPciAttachedResources,
    expected_block_generation: u32,
    expected_queue: VirtualBlockQueueLayout,
    expected_backend: VirtualBlockBackendAuthority,
    expected_window: VirtualPciMmioWindow,
    expected_mapped_window: Option<VirtualPciMmioWindow>,
    execution_destroyed: bool,
    revoked: bool,
}

#[cfg(target_os = "linux")]
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
            || record.pci().mmio_window() != Some(self.expected_window)
            || record.mapped_window() != self.expected_mapped_window
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

#[cfg(target_os = "linux")]
unsafe impl VirtualBlockPciGuestWindowBackend<PreparedKvmGuest<16>> for NativePciMmioWindow {
    fn map_block_window(
        &mut self,
        guest: &mut PreparedKvmGuest<16>,
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
        guest
            .install_trapped_mmio(PCI_TEST_MMIO_BASE)
            .map_err(|_| VirtualPciNativeResourceError::Uncertain)?;
        self.mapped = true;
        Ok(())
    }

    fn unmap_block_window(
        &mut self,
        guest: &mut PreparedKvmGuest<16>,
        record: VirtualBlockPciCleanupRecord,
    ) -> core::result::Result<(), VirtualPciNativeResourceError> {
        if !self.mapped || record.mapped_window() != record.pci().mmio_window() {
            return Err(VirtualPciNativeResourceError::Rejected);
        }
        guest
            .withdraw_trapped_mmio(PCI_TEST_MMIO_BASE)
            .map_err(|_| VirtualPciNativeResourceError::Uncertain)?;
        self.mapped = false;
        Ok(())
    }
}

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
        self.1 = self
            .1
            .checked_add(1)
            .ok_or(VirtualBlockMutationError::Rejected(()))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn run_block_guest_driver_probe(
    mut guest: PreparedKvmGuest<16>,
    system: &KvmSystem,
    executable: &VerifiedExecutable<'_>,
    handoff: &[u8],
    launch_layout: KvmLaunchLayout,
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
            let outcome = match run_virtual_block_transaction_once(
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
            ) {
                Ok(VirtualBlockTransactionOutcome::Doorbell(outcome)) => outcome,
                Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(_)) => {
                    return Err(anyhow!(
                        "block operation {} produced an unexpected acknowledgement",
                        operation + 1
                    ));
                }
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
            let acknowledgement = match run_virtual_block_transaction_once(
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
            ) {
                Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(acknowledgement)) => {
                    acknowledgement
                }
                Ok(VirtualBlockTransactionOutcome::Doorbell(_)) => {
                    return Err(anyhow!(
                        "block acknowledgement {} produced an unexpected doorbell",
                        operation + 1
                    ));
                }
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
fn run_pci_configuration_probe(
    mut guest: PreparedKvmGuest<16>,
    system: &KvmSystem,
    executable: &VerifiedExecutable<'_>,
    handoff: &[u8],
    launch_layout: KvmLaunchLayout,
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
    .map_err(|error| anyhow!("KVM PCI selector transaction failed: {:?}", error))?;
    if selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_SELECTOR) {
        return Err(anyhow!("KVM PCI selector outcome mismatch: {:?}", selector));
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
    .map_err(|error| anyhow!("KVM PCI identity-read transaction failed: {:?}", error))?;
    if read != VirtualPciIoOutcome::Read(PCI_TEST_VENDOR_DEVICE) {
        return Err(anyhow!(
            "KVM PCI identity-read outcome mismatch: {:?}",
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
    .map_err(|error| anyhow!("KVM PCI class selector transaction failed: {:?}", error))?;
    if class_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_CLASS_SELECTOR) {
        return Err(anyhow!(
            "KVM PCI class selector mismatch: {:?}",
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
    .map_err(|error| anyhow!("KVM PCI class-read transaction failed: {:?}", error))?;
    if class != VirtualPciIoOutcome::Read(PCI_TEST_CLASS) {
        return Err(anyhow!("KVM PCI class-read outcome mismatch: {:?}", class));
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
    .map_err(|error| anyhow!("KVM PCI BAR selector failed: {:?}", error))?;
    if bar_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_BAR_SELECTOR) {
        return Err(anyhow!("KVM PCI BAR selector mismatch: {:?}", bar_selector));
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
    .map_err(|error| anyhow!("KVM PCI BAR assignment failed: {:?}", error))?;
    if bar
        != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::BarAddress(
            PCI_TEST_MMIO_BASE as u32,
        ))
    {
        return Err(anyhow!("KVM PCI BAR assignment mismatch: {:?}", bar));
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
    .map_err(|error| anyhow!("KVM PCI command selector failed: {:?}", error))?;
    if command_selector != VirtualPciIoOutcome::AddressRegister(PCI_TEST_COMMAND_SELECTOR) {
        return Err(anyhow!(
            "KVM PCI command selector mismatch: {:?}",
            command_selector
        ));
    }
    let mut window_backend = NativePciMmioWindow { mapped: false };
    if guest
        .install_trapped_mmio(PCI_TEST_MMIO_BASE + mrml_kernel::PAGE_SIZE)
        .is_ok()
    {
        return Err(anyhow!("KVM PCI MMIO install accepted a wrong leaf"));
    }
    let command = {
        let mut mapper =
            VirtualBlockPciGuestMemoryMapper::new(&mut attachment, &device, &mut window_backend);
        run_pci_configuration_once_with_backend_mapper(
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
    .map_err(|error| anyhow!("KVM PCI memory enable failed: {:?}", error))?;
    if command
        != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::Command(
            mrml_kernel::PCI_COMMAND_MEMORY_SPACE | mrml_kernel::PCI_COMMAND_INTERRUPT_DISABLE,
        ))
        || !window_backend.mapped
    {
        return Err(anyhow!("KVM PCI memory enable mismatch: {:?}", command));
    }
    if guest.install_trapped_mmio(PCI_TEST_MMIO_BASE).is_ok() {
        return Err(anyhow!("KVM PCI MMIO install accepted replay"));
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
                "KVM PCI-MMIO block transaction {} failed: {:?}",
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
                "KVM PCI-MMIO transaction {} outcome mismatch: {:?}",
                transaction + 1,
                mmio
            ));
        }
        if transaction == 0 {
            if device.pending_interrupt_vector() != Some(48) {
                return Err(anyhow!("masked PCI completion was not retained exactly"));
            }
            let unmask = {
                let mut mapper = VirtualBlockPciGuestMemoryMapper::new(
                    &mut attachment,
                    &device,
                    &mut window_backend,
                );
                run_pci_configuration_once_with_backend_mapper(
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
            .map_err(|error| anyhow!("KVM PCI interrupt unmask failed: {:?}", error))?;
            if unmask
                != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::Command(
                    mrml_kernel::PCI_COMMAND_MEMORY_SPACE,
                ))
            {
                return Err(anyhow!("KVM PCI interrupt unmask mismatch: {:?}", unmask));
            }
        }
    }
    if backend.0[..4096] != [0x5a; 4096] || backend.0[4096..] != [0xa5; 4096] {
        return Err(anyhow!("KVM PCI-MMIO block backend payload mismatch"));
    }
    if backend.1 != 1 {
        return Err(anyhow!("KVM PCI-MMIO block flush count mismatch"));
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
    // SAFETY: the exact captured native VM has been consumed and destroyed;
    // the retained device, bridge, router, attachment, and backend stay live
    // and suspended until restoration completes.
    let lost_execution = unsafe { restart_image.confirm_execution_loss() };
    let mut replacement = system
        .prepare_kernel_block_dynamic_mmio_guest::<16>(
            0,
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
    replacement
        .install_trapped_mmio(PCI_TEST_MMIO_BASE)
        .map_err(|error| anyhow!("replacement PCI BAR restoration failed: {:?}", error))?;
    bridge
        .restore_restart_image(&mut replacement, &device, lost_execution)
        .map_err(|error| anyhow!("replacement PCI block restoration failed: {:?}", error))?;
    guest = replacement;
    device
        .resume()
        .map_err(|_| anyhow!("PCI block device did not resume exactly"))?;
    let proof = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("KVM PCI proof execution failed: {:?}", error))?;
    if proof
        != (VmExit::Io {
            port: PCI_PROOF_PORT,
            size: 4,
            write: true,
            value: PCI_BLOCK_PROBE_OPERATIONS,
        })
    {
        return Err(anyhow!("KVM PCI proof mismatch: {:?}", proof));
    }
    // Leave both reset-sensitive ownership classes in the destroyed native
    // guest: request 6 has a published completion that was never acknowledged,
    // while request 7 remains admitted but unissued. These records are test
    // data only; the exact attachment, capabilities, and generations below
    // remain the authority for cleanup and successor admission.
    let old_generation = device.generation();
    let published_request = VirtualBlockRequest::write(
        old_generation,
        u64::from(PCI_BLOCK_PROBE_OPERATIONS) + 1,
        0,
        1,
        FRAMEBUFFER,
        4096,
    );
    let mut encoded_request = [0; mrml_kernel::VIRTUAL_BLOCK_REQUEST_BYTES];
    published_request.encode(&mut encoded_request);
    VirtualBlockVmmMemory::write_virtual_block(
        &mut guest,
        layout.request_base() + 192,
        &encoded_request,
    )
    .and_then(|()| {
        VirtualBlockVmmMemory::write_virtual_block(
            &mut guest,
            layout.request_base(),
            &6u64.to_le_bytes(),
        )
    })
    .map_err(|_| anyhow!("failed to stage published reset request"))?;
    let mut consumed = [0; mrml_kernel::VIRTUAL_BLOCK_REQUEST_BYTES];
    bridge
        .consume_request(&mut guest, &mut consumed)
        .map_err(|error| anyhow!("failed to consume published reset request: {:?}", error))?;
    let admitted = device
        .admit(&consumed)
        .map_err(|error| anyhow!("failed to admit published reset request: {:?}", error))?;
    let completion = device
        .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
        .map_err(|error| anyhow!("failed to complete published reset request: {:?}", error))?;
    bridge
        .publish_completion(&mut guest, completion)
        .map_err(|error| anyhow!("failed to publish reset completion: {:?}", error))?;
    let inflight_request = VirtualBlockRequest::read(
        old_generation,
        u64::from(PCI_BLOCK_PROBE_OPERATIONS) + 2,
        1,
        1,
        FRAMEBUFFER + 4096,
        4096,
    );
    inflight_request.encode(&mut encoded_request);
    VirtualBlockVmmMemory::write_virtual_block(
        &mut guest,
        layout.request_base() + 128,
        &encoded_request,
    )
    .and_then(|()| {
        VirtualBlockVmmMemory::write_virtual_block(
            &mut guest,
            layout.request_base(),
            &7u64.to_le_bytes(),
        )
    })
    .map_err(|_| anyhow!("failed to stage in-flight reset request"))?;
    bridge
        .consume_request(&mut guest, &mut consumed)
        .map_err(|error| anyhow!("failed to consume in-flight reset request: {:?}", error))?;
    let stale_ticket = device
        .admit(&consumed)
        .map_err(|error| anyhow!("failed to admit in-flight reset request: {:?}", error))?
        .ticket();
    if guest
        .withdraw_trapped_mmio(PCI_TEST_MMIO_BASE + mrml_kernel::PAGE_SIZE)
        .is_ok()
    {
        return Err(anyhow!("KVM PCI MMIO withdrawal accepted a wrong leaf"));
    }
    let disable = {
        let mut mapper =
            VirtualBlockPciGuestMemoryMapper::new(&mut attachment, &device, &mut window_backend);
        router
            .write_with_backend_mapper(location, 4, 2, 0, &mut guest, &mut mapper)
            .map_err(|_| anyhow!("failed to disable retired KVM PCI MMIO window"))?
    };
    if disable != mrml_kernel::VirtualPciWriteOutcome::Command(0)
        || window_backend.mapped
        || attachment.mapped_window().is_some()
    {
        return Err(anyhow!("KVM PCI MMIO withdrawal cleanup was incomplete"));
    }
    println!("KVM_PCI_WITHDRAW coherent=1");
    if guest.withdraw_trapped_mmio(PCI_TEST_MMIO_BASE).is_ok() {
        return Err(anyhow!("KVM PCI MMIO withdrawal accepted replay"));
    }
    let continued = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("KVM post-withdrawal execution failed: {:?}", error))?;
    if continued
        != (VmExit::Io {
            port: PCI_WITHDRAW_PROOF_PORT,
            size: 4,
            write: true,
            value: PCI_BLOCK_PROBE_OPERATIONS,
        })
    {
        return Err(anyhow!(
            "KVM post-withdrawal proof mismatch: {:?}",
            continued
        ));
    }
    println!("KVM_PCI_WITHDRAW continued=1");
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
        expected_mapped_window: None,
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
            .map_err(|error| anyhow!("destroyed KVM PCI cleanup failed: {:?}", error))?
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
        return Err(anyhow!("destroyed KVM PCI cleanup state mismatch"));
    }
    device
        .negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("failed to activate successor PCI block device"))?;
    if device.complete(stale_ticket, VirtualBlockCompletionStatus::Ok, 4096)
        != Err(VirtualBlockError::StaleTicket)
        || device.admit(&encoded_request) != Err(VirtualBlockError::StaleGeneration)
    {
        return Err(anyhow!(
            "destroyed KVM PCI cleanup retained stale block ownership"
        ));
    }
    let successor_bridge = VirtualBlockQueueBridge::<2>::new(layout)
        .map_err(|_| anyhow!("failed to construct successor PCI block queue"))?;
    let successor_block_capability = destroyed
        .capabilities
        .insert(
            block_object,
            Rights::READ.union(Rights::WRITE).union(Rights::FLUSH),
        )
        .map_err(|_| anyhow!("failed to authorize successor block backend"))?;
    let successor_interrupt_capability = destroyed
        .capabilities
        .insert(interrupt_object, Rights::SIGNAL)
        .map_err(|_| anyhow!("failed to authorize successor block interrupt"))?;
    let successor_authority =
        VirtualBlockBackendAuthority::new(successor_block_capability, block_object, 0, 2)
            .map_err(|_| anyhow!("invalid successor block authority"))?;
    let successor_attachment = VirtualBlockPciAttachment::new(
        router
            .describe_attachment(pci)
            .map_err(|_| anyhow!("successor PCI attachment disappeared"))?,
        &device,
        &successor_bridge,
        successor_authority,
    )
    .map_err(|_| anyhow!("failed to bind successor PCI block attachment"))?;
    let fresh_request = VirtualBlockRequest::read(2, 1, 0, 1, FRAMEBUFFER, 4096);
    let mut fresh_encoded = [0; mrml_kernel::VIRTUAL_BLOCK_REQUEST_BYTES];
    fresh_request.encode(&mut fresh_encoded);
    if successor_attachment.block_generation() != 2
        || successor_attachment.pci().function_generation() != 2
        || device.admit(&fresh_encoded).is_err()
        || destroyed
            .capabilities
            .authorize(successor_interrupt_capability, Rights::SIGNAL)
            .is_err()
    {
        return Err(anyhow!(
            "KVM PCI successor generation was not independently admissible"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
fn read_kernel_package(
    path: &str,
    public_path: &str,
    minimum: u64,
    release_binding: Option<(&str, &str)>,
) -> Result<Vector<u8>> {
    let bytes = mrml_runtime::read_file_bounded(path, MAX_BOOT_PACKAGE_BYTES)?;
    let public = mrml_runtime::read_file_bounded(public_path, LAMPORT_PUBLIC_KEY_BYTES)?;
    let release = if let Some((release_path, release_public_path)) = release_binding {
        let release_bytes = mrml_runtime::read_file_bounded(release_path, MAX_BOOT_RELEASE_BYTES)?;
        let release_public =
            mrml_runtime::read_file_bounded(release_public_path, LAMPORT_PUBLIC_KEY_BYTES)?;
        Some((release_bytes, release_public))
    } else {
        None
    };
    let payload = match admit_kernel_payload(
        &bytes,
        &public,
        minimum,
        MAX_KERNEL_BUNDLE,
        release
            .as_ref()
            .map(|(release, public)| (release.as_ref(), public.as_ref())),
    ) {
        Ok(payload) => payload,
        Err(error) => {
            println!("boot-artifacts|status=FAIL|backend=kvm|detail={error:?}");
            return Err(anyhow!("kernel package admission rejected"));
        }
    };
    let mut output = Vector::with_capacity(payload.raw_len)
        .map_err(|_| anyhow!("kernel package allocation failed"))?;
    output.resize(payload.raw_len, 0);
    payload
        .decode(&mut output)
        .map_err(|_| anyhow!("kernel package decompression rejected"))?;
    Ok(output)
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
    if arguments.len() == 7 && arguments[1] == "--verify-boot-artifacts" {
        let minimum = arguments[4]
            .parse::<u64>()
            .ok()
            .filter(|version| *version != 0)
            .ok_or_else(|| anyhow!("minimum version must be a nonzero integer"))?;
        let payload = read_kernel_package(
            &arguments[2],
            &arguments[3],
            minimum,
            Some((&arguments[5], &arguments[6])),
        )?;
        println!(
            "boot-artifacts|status=PASS|backend=kvm|raw_kernel_bytes={}",
            payload.len()
        );
        return Ok(());
    }
    if arguments.len() != 6
        && arguments.len() != 8
        && arguments.len() != 9
        && arguments.len() != 14
        && arguments.len() != 15
    {
        return Err(anyhow!(
            "usage: mrml-kvm-run KERNEL.mrp PACKAGE.public KERNEL.public MINIMUM_VERSION MODE [SYSTEM.mrs SYSTEM_RELEASE.public | ARTIFACT.signed ARTIFACT.public ARTIFACT_MINIMUM_VERSION | CONSUMER.signed CONSUMER.public CONSUMER_MINIMUM PROVIDER.signed PROVIDER.public PROVIDER_MINIMUM GENERAL_SYSTEM.mrs GENERAL_SYSTEM.public]\n       MODE component-release-inputs writes GENERATION.bin CATALOG.bin RUNTIME.bin in the final three positions after verifying the same component inputs\n       mrml-kvm-run --verify-boot-artifacts KERNEL.mrp PACKAGE.public MINIMUM_VERSION SYSTEM.mrs SYSTEM_RELEASE.public\n       mrml-kvm-run --export-cuda-bundle OUTPUT.ptx"
        ));
    }
    let minimum_version = arguments[4]
        .parse::<u64>()
        .ok()
        .filter(|version| *version != 0)
        .ok_or_else(|| anyhow!("minimum version must be a nonzero integer"))?;
    let mode = LaunchMode::parse(&arguments[5])?;
    if arguments.len() == 8 && mode != LaunchMode::Boot {
        return Err(anyhow!(
            "SystemRelease binding is accepted only for boot mode"
        ));
    }
    let component_release_input_mode = mode == LaunchMode::ComponentReleaseInputs;
    let component_smp_mode = mode == LaunchMode::ComponentServiceSmpProbe;
    let component_service_mode = component_release_input_mode
        || mode == LaunchMode::ComponentServiceProbe
        || component_smp_mode;
    let scanout_mode = matches!(mode, LaunchMode::ScanoutServiceProbe | LaunchMode::ScanoutServiceDeniedProbe);
    let block_service_mode = mode == LaunchMode::BlockServiceProbe;
    let total_service_mode = block_service_mode || matches!(
        mode,
        LaunchMode::ScanoutServiceProbe
            | LaunchMode::ScanoutServiceDeniedProbe
            | LaunchMode::ServiceProbe
            | LaunchMode::CertificateServiceProbe
            | LaunchMode::DeadlineReceiveProbe
            | LaunchMode::DeadlineReceiveMessageProbe
            | LaunchMode::DeadlineReceiveCancelProbe
            | LaunchMode::DeadlineReceiveCancelDeniedProbe
            | LaunchMode::DeadlineReceiveCancelReplayProbe
            | LaunchMode::InvalidReturnProbe
            | LaunchMode::BufferDriftProbe
            | LaunchMode::ComponentServiceProbe
            | LaunchMode::ComponentServiceSmpProbe
    );
    let component_argument_count = if component_release_input_mode { 15 } else { 14 };
    if component_service_mode != (arguments.len() == component_argument_count) {
        return Err(anyhow!(
            "component service modes require exact consumer/provider signed artifacts plus one signed general SystemRelease and explicit public roots; component-release-inputs additionally requires three output paths"
        ));
    }
    if matches!(
        mode,
        LaunchMode::ApplicationProbe
            | LaunchMode::GuiApplicationProbe
            | LaunchMode::GpuBenchmark
            | LaunchMode::ServiceProbe
            | LaunchMode::CertificateServiceProbe
            | LaunchMode::DeadlineReceiveProbe
            | LaunchMode::DeadlineReceiveMessageProbe
            | LaunchMode::DeadlineReceiveCancelProbe
            | LaunchMode::DeadlineReceiveCancelDeniedProbe
            | LaunchMode::DeadlineReceiveCancelReplayProbe
            | LaunchMode::InvalidReturnProbe
            | LaunchMode::BufferDriftProbe
            | LaunchMode::BlockServiceProbe
            | LaunchMode::ServiceRestartRequestProbe
            | LaunchMode::ScanoutServiceProbe
            | LaunchMode::ScanoutServiceDeniedProbe
            | LaunchMode::Fat32ReadyProbe
            | LaunchMode::Fat32DataProbe
            | LaunchMode::Fat32RestartProbe
            | LaunchMode::ServicePreemptionProbe
            | LaunchMode::SmpServiceMigrationProbe
    ) != (arguments.len() == 9)
    {
        return Err(anyhow!(
            "application, gpu-benchmark, and service modes require exactly one matching signed artifact, public key, and minimum version"
        ));
    }
    let release_binding =
        (arguments.len() == 8).then(|| (arguments[6].as_str(), arguments[7].as_str()));
    let bundle = read_kernel_package(
        &arguments[1],
        &arguments[2],
        minimum_version,
        release_binding,
    )?;
    let public = mrml_runtime::read_file_bounded(&arguments[3], LAMPORT_PUBLIC_KEY_BYTES)?;
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
            | LaunchMode::CertificateServiceProbe
            | LaunchMode::DeadlineReceiveProbe
            | LaunchMode::DeadlineReceiveMessageProbe
            | LaunchMode::DeadlineReceiveCancelProbe
            | LaunchMode::DeadlineReceiveCancelDeniedProbe
            | LaunchMode::DeadlineReceiveCancelReplayProbe
            | LaunchMode::InvalidReturnProbe
            | LaunchMode::BufferDriftProbe
            | LaunchMode::ComponentServiceProbe
            | LaunchMode::ComponentServiceSmpProbe
            | LaunchMode::ComponentReleaseInputs
            | LaunchMode::BlockServiceProbe
            | LaunchMode::ServiceRestartRequestProbe
            | LaunchMode::ScanoutServiceProbe
            | LaunchMode::ScanoutServiceDeniedProbe
            | LaunchMode::Fat32ReadyProbe
            | LaunchMode::Fat32DataProbe
            | LaunchMode::Fat32RestartProbe
            | LaunchMode::ServicePreemptionProbe
            | LaunchMode::SmpServiceMigrationProbe
    );
    let service_bundle = if service_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[6],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + mrml_kernel::MAX_SERVICE_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let service_public = if service_mode {
        let public = mrml_runtime::read_file_bounded(&arguments[7], LAMPORT_PUBLIC_KEY_BYTES)?;
        if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(anyhow!("invalid service public-key length"));
        }
        Some(public)
    } else {
        None
    };
    let service_executable = match (&service_bundle, &service_public) {
        (Some(bundle), Some(public)) => {
            let minimum = arguments[8]
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
    if mode == LaunchMode::Fat32RestartProbe {
        let image = service_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing FAT32 service image"))?
            .image();
        if image.image_base() != SERVICE_VIRTUAL || image.image_size() > 2 * 1024 * 1024 {
            return Err(anyhow!(
                "FAT32 service image exceeds its restart erasure arena"
            ));
        }
    }
    let application_bundle = if mode.application_package_id().is_some() {
        Some(mrml_runtime::read_file_bounded(
            &arguments[6],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + MAX_APPLICATION_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let application_public = if mode.application_package_id().is_some() {
        let public = mrml_runtime::read_file_bounded(&arguments[7], LAMPORT_PUBLIC_KEY_BYTES)?;
        if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(anyhow!("invalid application public-key length"));
        }
        Some(public)
    } else {
        None
    };
    let application_executable = match (&application_bundle, &application_public) {
        (Some(bundle), Some(public)) => {
            let minimum = arguments[8]
                .parse::<u64>()
                .ok()
                .filter(|version| *version != 0)
                .ok_or_else(|| anyhow!("application minimum version must be nonzero"))?;
            let root = TrustRoot::new(
                ArtifactKind::ApplicationImage,
                Sha3_512::digest(public),
                minimum,
            );
            let signed = SignedArtifact::decode(bundle)
                .map_err(|_| anyhow!("invalid signed application bundle"))?;
            Some(
                signed
                    .verify_executable(&root, ArtifactKind::ApplicationImage)
                    .map_err(|_| anyhow!("application signature or PE policy rejected"))?,
            )
        }
        (None, None) => None,
        _ => return Err(anyhow!("incomplete application verification inputs")),
    };
    let provider_bundle = if component_service_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[9],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + mrml_kernel::MAX_SERVICE_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let provider_public = if component_service_mode {
        let public = mrml_runtime::read_file_bounded(&arguments[10], LAMPORT_PUBLIC_KEY_BYTES)?;
        if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(anyhow!("invalid provider public-key length"));
        }
        Some(public)
    } else {
        None
    };
    let provider_executable = match (&provider_bundle, &provider_public) {
        (Some(bundle), Some(public)) => {
            let minimum = arguments[11]
                .parse::<u64>()
                .ok()
                .filter(|version| *version != 0)
                .ok_or_else(|| anyhow!("provider minimum version must be nonzero"))?;
            let root = TrustRoot::new(
                ArtifactKind::ServiceImage,
                Sha3_512::digest(public),
                minimum,
            );
            let signed = SignedArtifact::decode(bundle)
                .map_err(|_| anyhow!("invalid signed provider bundle"))?;
            Some(
                signed
                    .verify_executable(&root, ArtifactKind::ServiceImage)
                    .map_err(|_| anyhow!("provider signature or PE policy rejected"))?,
            )
        }
        (None, None) => None,
        _ => return Err(anyhow!("incomplete provider verification inputs")),
    };
    let cuda_bundle = if mode == LaunchMode::GpuBenchmark {
        Some(verify_cuda_bundle(
            &arguments[6],
            &arguments[7],
            &arguments[8],
        )?)
    } else {
        None
    };
    let verification_micros = verification_started.elapsed().as_micros();
    let mut entropy = [0u8; 32];
    mrml_runtime::fill_random(&mut entropy)
        .map_err(|_| anyhow!("operating-system boot entropy failed"))?;
    let application_launch = if let (Some(bundle), Some(application)) =
        (application_bundle.as_ref(), application_executable.as_ref())
    {
        let image_pages = u64::from(application.image().image_size())
            .checked_add(PAGE_SIZE - 1)
            .ok_or_else(|| anyhow!("application image-page rounding overflow"))?
            / PAGE_SIZE;
        let image_virtual = application.image().image_base();
        Some(
            ApplicationLaunch::new(
                PhysAddr::new(APPLICATION_ARTIFACT_PHYSICAL)
                    .map_err(|_| anyhow!("invalid application artifact address"))?,
                bundle.len() as u64,
                PhysAddr::new(APPLICATION_IMAGE_PHYSICAL)
                    .map_err(|_| anyhow!("invalid application image address"))?,
                image_pages,
                image_virtual,
                image_virtual
                    .checked_add(u64::from(application.image().entry_rva()))
                    .ok_or_else(|| anyhow!("application entry overflow"))?,
                PhysAddr::new(APPLICATION_STACK_PHYSICAL)
                    .map_err(|_| anyhow!("invalid application stack address"))?,
                8,
                APPLICATION_STACK_TOP,
                PhysAddr::new(APPLICATION_TABLE_PHYSICAL)
                    .map_err(|_| anyhow!("invalid application table address"))?,
                32,
                application.artifact().version(),
                *application.artifact().digest(),
            )
            .map_err(|error| anyhow!("invalid typed application launch: {:?}", error))?,
        )
    } else {
        None
    };
    let smp_mode = matches!(
        mode,
        LaunchMode::SmpProbe
            | LaunchMode::SmpSchedulerProbe
            | LaunchMode::SmpIpiProbe
            | LaunchMode::SmpServiceMigrationProbe
            | LaunchMode::SmpPeriodicBalanceProbe
    );
    let total_recovery = total_service_mode.then(|| {
        if block_service_mode {
            RecoveryStateMetadata::new(8, 2, Some([0x51; 16]), 1)
                .expect("fixed block-service recovery metadata")
        } else {
            RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14)
                .expect("fixed Total recovery metadata")
        }
    });
    let total_override = total_service_mode.then_some(BootIsolationOverride::TotalMicrovmOnce);
    let handoff = if let Some(application) = application_launch {
        application_boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
            application,
        )?
    } else if smp_mode || component_smp_mode {
        smp_boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
            total_recovery,
            total_override,
            false,
        )?
    } else {
        boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
            u64::from(matches!(
                mode,
                LaunchMode::BlockGuestDriverProbe | LaunchMode::PciConfigurationProbe
            )) + 1,
            total_recovery,
            total_override,
            false,
        )?
    };
    let decoded_boot_handoff = BootHandoff::decode(handoff.as_slice(), |_| {})
        .map_err(|error| anyhow!("KVM canonical boot handoff decode failed: {:?}", error))?;
    let user_probe = matches!(mode, LaunchMode::UserProbe | LaunchMode::PreemptionProbe);
    let (image_virtual, handoff_virtual, stack_virtual) = if smp_mode || component_smp_mode {
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
    let table_pages = if mode.application_package_id().is_some() {
        40
    } else if component_smp_mode
        || matches!(
            mode,
            LaunchMode::SmpIpiProbe
                | LaunchMode::SmpServiceMigrationProbe
                | LaunchMode::SmpPeriodicBalanceProbe
        )
    {
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
    let mut component_ram = if component_service_mode {
        let consumer = service_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified ZIM consumer"))?;
        let provider = provider_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified Zstd provider"))?;
        let kernel_image_pages = accounted_pages(executable.image().image_size() as u64)?;
        let handoff_pages = accounted_pages(handoff.as_slice().len() as u64)?;
        let consumer_plan = component_image_page_plan(consumer.image())
            .map_err(|error| anyhow!("consumer image accounting failed: {:?}", error))?;
        let provider_plan = component_image_page_plan(provider.image())
            .map_err(|error| anyhow!("provider image accounting failed: {:?}", error))?;
        let consumer_pages = consumer_plan
            .total_pages()
            .ok_or_else(|| anyhow!("consumer image page count overflow"))?;
        let provider_pages = provider_plan
            .total_pages()
            .ok_or_else(|| anyhow!("provider image page count overflow"))?;
        let base_pages = table_pages
            .checked_add(kernel_image_pages)
            .and_then(|pages| pages.checked_add(handoff_pages))
            .and_then(|pages| pages.checked_add(PRIVILEGE_STACK_ARENA_PAGES))
            .and_then(|pages| pages.checked_add(1))
            .ok_or_else(|| anyhow!("component base guest RAM overflow"))?;
        let service_pages = (8 + 32) + (8 + 32);
        let guest_pages = base_pages
            .checked_add(service_pages)
            .ok_or_else(|| anyhow!("component guest RAM overflow"))?;
        let control_pages = accounted_pages(core::mem::size_of::<PreparedKvmGuest<16>>() as u64)?;
        let total_pages = guest_pages
            .checked_add(control_pages)
            .and_then(|pages| pages.checked_add(2))
            .and_then(|pages| pages.checked_add(consumer_pages))
            .and_then(|pages| pages.checked_add(provider_pages))
            .ok_or_else(|| anyhow!("component memory commitment overflow"))?;
        let mapping_limit = u32::from(consumer_plan.regions())
            .checked_add(u32::from(provider_plan.regions()))
            .and_then(|mappings| mappings.checked_add(2))
            .ok_or_else(|| anyhow!("component mapping commitment overflow"))?;
        let mut authorities = CapabilitySpace::<COMPONENT_MEMORY_CAPABILITIES>::new();
        let mut memory =
            MemoryPoolTable::<1, COMPONENT_MEMORY_OBJECTS, COMPONENT_MEMORY_MAPPINGS>::new(0x5a52)
                .map_err(|error| anyhow!("component RAM table failed: {:?}", error))?;
        let (pool, pool_capability) = memory
            .create_root(
                total_pages,
                mapping_limit,
                0,
                Rights::ALLOCATE
                    .union(Rights::CONTROL)
                    .union(Rights::INSPECT),
                &mut authorities,
            )
            .map_err(|error| anyhow!("component RAM pool failed: {:?}", error))?;
        let (reservation, ram_capability) = reserve_microvm_guest_ram(
            &mut memory,
            pool,
            pool_capability,
            guest_pages,
            &mut authorities,
        )
        .map_err(|error| anyhow!("component RAM reservation failed: {:?}", error))?;
        let mut prepared =
            prepare_microvm_guest_ram(&memory, reservation, ram_capability, &authorities)
                .map_err(|error| anyhow!("component RAM preparation failed: {:?}", error))?;
        prepared
            .consume_phase(base_pages)
            .map_err(|error| anyhow!("component base RAM phase failed: {:?}", error))?;
        let (control, control_capability) = mrml_kernel::reserve_microvm_control_memory(
            &mut memory,
            pool,
            pool_capability,
            control_pages,
            &mut authorities,
        )
        .map_err(|error| anyhow!("component control-memory reservation failed: {:?}", error))?;
        let projection_target = authorities
            .insert(
                ObjectId(0x434f_4d50_5f56_4d00),
                Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL),
            )
            .map_err(|error| anyhow!("component projection target failed: {:?}", error))?;
        let provider_projection_target = authorities
            .insert(
                ObjectId(0x434f_4d50_5f56_4d01),
                Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL),
            )
            .map_err(|error| anyhow!("provider projection target failed: {:?}", error))?;
        let (shared_projection, shared_capability) = reserve_microvm_page_projection(
            &mut memory,
            pool,
            pool_capability,
            projection_target,
            MicrovmPageProjectionKind::SharedData,
            SERVICE_SHARED_VIRTUAL / PAGE_SIZE,
            &mut authorities,
        )
        .map_err(|error| anyhow!("component shared projection failed: {:?}", error))?;
        let (resource_projection, resource_capability) = reserve_microvm_page_projection(
            &mut memory,
            pool,
            pool_capability,
            projection_target,
            MicrovmPageProjectionKind::Resource,
            SERVICE_RESOURCE_VIRTUAL / PAGE_SIZE,
            &mut authorities,
        )
        .map_err(|error| anyhow!("component resource projection failed: {:?}", error))?;
        let consumer_image = reserve_component_image(
            &mut memory,
            pool,
            pool_capability,
            projection_target,
            consumer.image(),
            SERVICE_VIRTUAL / PAGE_SIZE,
            &mut authorities,
        )
        .map_err(|error| anyhow!("consumer image reservation failed: {:?}", error))?;
        let provider_image = reserve_component_image(
            &mut memory,
            pool,
            pool_capability,
            provider_projection_target,
            provider.image(),
            SERVICE_VIRTUAL / PAGE_SIZE,
            &mut authorities,
        )
        .map_err(|error| anyhow!("provider image reservation failed: {:?}", error))?;
        Some((
            memory,
            authorities,
            pool,
            pool_capability,
            ram_capability,
            prepared,
            service_pages,
            control,
            control_capability,
            projection_target,
            provider_projection_target,
            shared_projection,
            shared_capability,
            resource_projection,
            resource_capability,
            consumer_image,
            provider_image,
        ))
    } else {
        None
    };
    let mut active_component_ram = None;
    let preparation_started = Instant::now();
    let component_generation = if component_service_mode {
        let consumer = service_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified ZIM consumer"))?;
        let provider = provider_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified Zstd provider"))?;
        let records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: consumer.artifact().version(),
                artifact_digest: consumer.artifact().digest(),
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: provider.artifact().version(),
                artifact_digest: provider.artifact().digest(),
            },
        ];
        let mut bytes = [0u8; 256];
        let length = encode_system_generation(1, &records, &mut bytes)
            .map_err(|error| anyhow!("KVM SystemGeneration encoding failed: {:?}", error))?;
        let digest = SystemGenerationView::decode(&bytes[..length])
            .map_err(|error| anyhow!("KVM SystemGeneration decoding failed: {:?}", error))?
            .digest();
        let requirement = match decode_canonical_manifest_interface(include_bytes!(
            "../../../../libraries/zim/mrml.toml"
        ))
        .map_err(|error| anyhow!("KVM ZIM interface manifest failed: {:?}", error))?
        {
            ManifestInterfaceDeclaration::Requirement(requirement) => requirement,
            ManifestInterfaceDeclaration::Provider(_) => {
                return Err(anyhow!("KVM ZIM manifest declared a provider"));
            }
        };
        let provider = match decode_canonical_manifest_interface(include_bytes!(
            "../../../../libraries/zstd/mrml.toml"
        ))
        .map_err(|error| anyhow!("KVM Zstd interface manifest failed: {:?}", error))?
        {
            ManifestInterfaceDeclaration::Provider(provider) => provider,
            ManifestInterfaceDeclaration::Requirement(_) => {
                return Err(anyhow!("KVM Zstd manifest declared a requirement"));
            }
        };
        let mut catalog = [0u8; 256];
        let catalog_length = encode_interface_catalog(1, &[requirement], &[provider], &mut catalog)
            .map_err(|error| anyhow!("KVM interface catalog failed: {:?}", error))?;
        let catalog_digest = InterfaceCatalogView::decode(&catalog[..catalog_length])
            .map_err(|error| anyhow!("KVM interface catalog decoding failed: {:?}", error))?
            .digest();
        let runtime_records = [
            RuntimeInventoryRecord {
                package_id: "org.mrml.zim",
                version: consumer.artifact().version(),
                artifact_digest: consumer.artifact().digest(),
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: true,
                preferred: RuntimeIsolationPlacement::InProcess,
                minimum: RuntimeIsolationPlacement::InProcess,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::InProcess.bit()
                    | RuntimeIsolationPlacement::NativeService.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
            RuntimeInventoryRecord {
                package_id: "org.mrml.zstd",
                version: records[1].version,
                artifact_digest: records[1].artifact_digest,
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: true,
                preferred: RuntimeIsolationPlacement::NativeService,
                minimum: RuntimeIsolationPlacement::NativeService,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::NativeService.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
        ];
        let mut runtime = [0u8; 512];
        let runtime_length = encode_runtime_inventory(1, &runtime_records, &mut runtime)
            .map_err(|error| anyhow!("KVM runtime inventory failed: {:?}", error))?;
        Some((
            bytes,
            length,
            digest,
            catalog,
            catalog_length,
            catalog_digest,
            runtime,
            runtime_length,
        ))
    } else {
        None
    };
    let mut component_release_authority = None;
    let active_component_generation = if let Some((
        bytes,
        length,
        _,
        catalog,
        catalog_length,
        _,
        runtime,
        runtime_length,
    )) = component_generation.as_ref()
    {
        if component_release_input_mode {
            mrml_runtime::write_file(&arguments[12], &bytes[..*length])?;
            mrml_runtime::write_file(&arguments[13], &catalog[..*catalog_length])?;
            mrml_runtime::write_file(&arguments[14], &runtime[..*runtime_length])?;
            println!(
                "component-release-inputs|status=PASS|backend=kvm|generation_bytes={}|catalog_bytes={}|runtime_bytes={}",
                length, catalog_length, runtime_length
            );
            return Ok(());
        }
        let release_bytes =
            mrml_runtime::read_file_bounded(&arguments[12], MAX_SYSTEM_RELEASE_BYTES)?;
        let release_public =
            mrml_runtime::read_file_bounded(&arguments[13], LAMPORT_PUBLIC_KEY_BYTES)?;
        if release_public.len() != LAMPORT_PUBLIC_KEY_BYTES {
            return Err(anyhow!(
                "invalid KVM general SystemRelease public-key length"
            ));
        }
        let expected_release_key = Sha3_512::digest(&release_public);
        let deployment_root = ObjectId(0x4445_504c_4f59);
        let mut capabilities = CapabilitySpace::<2>::new();
        let control = capabilities
            .insert(deployment_root, Rights::CONTROL)
            .map_err(|error| anyhow!("KVM deployment authority failed: {:?}", error))?;
        let inspect = capabilities
            .insert(deployment_root, Rights::READ)
            .map_err(|error| anyhow!("KVM deployment inspection failed: {:?}", error))?;
        let mut deployment = DeploymentService::<1>::new(deployment_root)
            .map_err(|error| anyhow!("KVM DeploymentService failed: {:?}", error))?;
        let candidate = deployment
            .stage(
                &capabilities,
                control,
                GenerationCandidate::from_system_release(
                    &release_bytes,
                    &expected_release_key,
                    0x5359_5347_454e,
                    1,
                )
                .map_err(|error| anyhow!("KVM generation candidate failed: {:?}", error))?,
            )
            .map_err(|error| anyhow!("KVM candidate staging failed: {:?}", error))?;
        let prepared = deployment
            .prepare_activation(&capabilities, control, candidate, None)
            .map_err(|error| anyhow!("KVM generation preparation failed: {:?}", error))?;
        let active = deployment
            .commit_activation(&capabilities, control, prepared)
            .map_err(|error| anyhow!("KVM generation activation failed: {:?}", error))?;
        if *active.generation_digest()
            != SystemGenerationView::decode(&bytes[..*length])
                .map_err(|error| anyhow!("KVM local generation decode failed: {:?}", error))?
                .digest()
            || *active.interface_catalog_digest()
                != InterfaceCatalogView::decode(&catalog[..*catalog_length])
                    .map_err(|error| anyhow!("KVM local catalog decode failed: {:?}", error))?
                    .digest()
        {
            return Err(anyhow!(
                "KVM SystemRelease did not bind the verified component artifacts"
            ));
        }
        let active_release = deployment
            .active_release(&capabilities, inspect)
            .map_err(|error| anyhow!("KVM active release read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("KVM activation lost SystemRelease identity"))?;
        let checkpoint = encode_deployment_release_checkpoint(deployment_root, active_release)
            .map_err(|error| anyhow!("KVM generation checkpoint failed: {:?}", error))?;
        let recovered = DeploymentService::<1>::recover(deployment_root, &checkpoint)
            .map_err(|error| anyhow!("KVM generation recovery failed: {:?}", error))?;
        let recovered_active = recovered
            .active(&capabilities, inspect)
            .map_err(|error| anyhow!("KVM active generation read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("KVM recovered no active SystemGeneration"))?;
        let recovered_release = recovered
            .active_release(&capabilities, inspect)
            .map_err(|error| anyhow!("KVM recovered release read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("KVM recovered no active SystemRelease identity"))?;
        if recovered_release.generation() != recovered_active {
            return Err(anyhow!("KVM recovered release/generation mismatch"));
        }
        component_release_authority = Some((release_bytes, expected_release_key));
        Some(recovered_release)
    } else {
        None
    };
    let configured_total_policy = if total_service_mode {
        let (domain, interface, interface_generation, provider_generation) =
            if component_service_mode {
                (
                    HOSTED_TOTAL_COMPONENT_DOMAIN,
                    ObjectId(0x5a53_5444_0000_0003),
                    3,
                    provider_executable
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing verified Zstd provider"))?
                        .artifact()
                        .version(),
                )
            } else if block_service_mode {
                // This identity labels the signed RAM-backed test service, not
                // readiness of the required installed storage coordinator.
                (
                    ObjectId(0x424c_4f43_4b),
                    ObjectId(0x424c_4f43_4b00_0001),
                    1,
                    service_executable
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing verified block-service fixture"))?
                        .artifact()
                        .version(),
                )
            } else if scanout_mode {
                (
                    ObjectId(0x5343_414e_4f55_54),
                    ObjectId(0x5343_414e_0000_0001),
                    1,
                    service_executable.as_ref()
                        .ok_or_else(|| anyhow!("missing verified scanout provider"))?
                        .artifact().version(),
                )
            } else {
                (
                    ObjectId(0x434f_4e46_4947),
                    ObjectId(0x434f_4e46_4947_0001),
                    1,
                    service_executable
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing verified configuration provider"))?
                        .artifact()
                        .version(),
                )
            };
        Some(if component_service_mode {
            configured_isolation_service(
                domain,
                interface,
                interface_generation,
                provider_generation,
            )?
        } else {
            configured_total_service_policy(
                domain,
                interface,
                interface_generation,
                provider_generation,
                &decoded_boot_handoff,
            )?
        })
    } else {
        None
    };
    // Strict Total classification is authenticated and bound to the exact
    // control-plane domain before CPU, RAM, or KVM guest construction begins.
    // The immutable inventory is retained across construction and finalized
    // only after the same domain has been committed as a running microVM.
    let mut isolation_admission = if component_service_mode {
        configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing configured KVM component policy"))?;
        let (release_bytes, expected_release_key) = component_release_authority
            .as_ref()
            .ok_or_else(|| anyhow!("missing authenticated KVM component release"))?;
        let mut release_output = Vector::with_capacity(MAX_SYSTEM_RELEASE_BYTES)
            .map_err(|_| anyhow!("KVM release recovery scratch allocation failed"))?;
        release_output
            .try_resize(MAX_SYSTEM_RELEASE_BYTES, 0)
            .map_err(|_| anyhow!("KVM release recovery scratch initialization failed"))?;
        let (total, _) = recover_hosted_component_owner(
            &decoded_boot_handoff,
            release_bytes,
            expected_release_key,
            &mut release_output,
            None,
        )
        .map_err(|error| anyhow!("KVM recovered boot Total admission failed: {:?}", error))?;
        println!(
            "isolation-recovery|status=PASS|backend=kvm|authority_epoch={}|boot_accepted_epoch={}|recovery_root_generation={}|configuration_revision={}",
            total.policy().authority_epoch(),
            total.policy().boot_accepted_epoch(),
            total.policy().recovery_root_generation(),
            total.policy().configuration_revision(),
        );
        Some(KvmTotalAdmission::Recovered(total))
    } else if total_service_mode {
        let configured = configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing configured KVM service policy"))?;
        Some(KvmTotalAdmission::Standalone(
            configured
                .effective
                .ok_or_else(|| anyhow!("missing transient KVM service policy"))?
                .admission_table(1)
                .map_err(|error| anyhow!("KVM isolation admission failed: {:?}", error))?,
        ))
    } else {
        None
    };
    let mut complete_isolation_preparation: Option<PreparedTotalServiceSet<2>> = None;
    let mut isolation_preparation = match (
        isolation_admission.as_mut(),
        configured_total_policy.as_ref(),
    ) {
        (Some(KvmTotalAdmission::Recovered(total)), Some(configured)) => {
            let mut prepared = total
                .prepare_complete_service_set(&[TotalServicePreparationBinding::new(
                    configured.bounds,
                    configured.identity,
                )])
                .map_err(|error| {
                    anyhow!("KVM recovered complete preparation failed: {:?}", error)
                })?;
            let domain = configured.identity.domain();
            let spec = prepared.spec(domain).ok_or_else(|| {
                anyhow!("KVM complete preparation omitted the recovered component domain")
            })?;
            let verified = provider_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified KVM Zstd provider"))?;
            let consumer = service_executable
                .as_ref()
                .ok_or_else(|| anyhow!("missing verified KVM ZIM consumer"))?;
            let release = total.installed_admission().release();
            if !release.matches_service_executable(spec, "org.mrml.zstd", verified)
                || !release.matches_service_executable_set([
                    (spec, "org.mrml.zim", consumer),
                    (spec, "org.mrml.zstd", verified),
                ])
            {
                prepared.cancel_all(total.admission_mut()).map_err(|error| {
                    anyhow!("KVM recovered executable set cancellation failed: {:?}", error)
                })?;
                return Err(anyhow!("KVM service executable set not bound to recovered release"));
            }
            let route = prepared.take(domain).ok_or_else(|| {
                anyhow!("KVM complete preparation omitted the recovered component route")
            })?;
            complete_isolation_preparation = Some(prepared);
            Some(route)
        }
        (Some(KvmTotalAdmission::Standalone(admission)), Some(configured)) => {
            let admitted = configured
                .effective
                .ok_or_else(|| anyhow!("missing transient KVM service policy"))?
                .admit_service(configured.bounds)
                .map_err(|error| anyhow!("KVM configured admission failed: {:?}", error))?;
            let spec = admitted
                .service_spec(
                    admission.system_generation(),
                    configured.identity.domain(),
                    configured.identity.interface(),
                    configured.identity.interface_generation(),
                    configured.identity.provider_generation(),
                    configured.identity.class(),
                )
                .map_err(|error| anyhow!("KVM configured service spec failed: {:?}", error))?;
            Some(
                prepare_isolation_service_route(admission, spec)
                    .map_err(|error| anyhow!("KVM isolation preparation failed: {:?}", error))?,
            )
        }
        (None, None) => None,
        _ => return Err(anyhow!("KVM Total policy/admission ownership mismatch")),
    };
    let mut installed_total_runtime: Option<RecoveredDeploymentTotalRuntime<1, 4, 2, 1, 2>> = None;
    let mut component_cpu = if component_service_mode {
        let mut capabilities = CapabilitySpace::<1>::new();
        let mut budgets = CpuBudgetTable::<1, 1>::new(0x1a53)
            .map_err(|error| anyhow!("component CPU table failed: {:?}", error))?;
        let parallelism = if component_smp_mode { 2 } else { 1 };
        let runtime = 100_000u32
            .checked_mul(u32::from(parallelism))
            .ok_or_else(|| anyhow!("component CPU runtime overflow"))?;
        let affinity = if component_smp_mode { 0b11 } else { 1 };
        let spec = CpuBudgetSpec::new(parallelism, runtime, runtime, 0, affinity)
            .map_err(|error| anyhow!("component CPU budget failed: {:?}", error))?;
        let (budget, capability) = budgets
            .create_root(spec, &mut capabilities)
            .map_err(|error| anyhow!("component CPU root failed: {:?}", error))?;
        let route = isolation_preparation
            .take()
            .ok_or_else(|| anyhow!("missing component isolation route for CPU reservation"))?;
        let reserved = reserve_isolation_vcpus(
            route,
            isolation_admission
                .as_mut()
                .ok_or_else(|| anyhow!("missing component isolation admission"))?,
            &mut budgets,
            budget,
            capability,
            parallelism,
            &capabilities,
        )
        .map_err(|error| anyhow!("component vCPU reservation failed: {:?}", error))?;
        let (route, reservation) = reserved.into_parts();
        isolation_preparation = Some(route);
        budgets
            .start_runtime_period(reservation, capability, 0, &capabilities)
            .map_err(|error| anyhow!("component CPU runtime start failed: {:?}", error))?;
        Some((
            budgets,
            capabilities,
            budget,
            capability,
            reservation,
            [0; 2],
        ))
    } else {
        None
    };
    let application_spec = match (
        mode.application_package_id(),
        application_executable.as_ref(),
    ) {
        (Some(package_id), Some(application)) => {
            Some(total_application_spec(package_id, application)?)
        }
        (None, None) => None,
        _ => return Err(anyhow!("incomplete KVM application identity")),
    };
    let mut application_projection = match (
        application_spec,
        application_launch,
        application_bundle.as_ref(),
        application_executable.as_ref(),
    ) {
        (Some(spec), Some(application), Some(bundle), Some(_)) => {
            let pages = application_guest_pages(
                table_pages,
                &executable,
                handoff.as_slice().len(),
                application,
                bundle.len(),
            )?;
            Some(KvmApplicationProjection::prepare(spec, pages)?)
        }
        (None, None, None, None) => None,
        _ => return Err(anyhow!("incomplete KVM application projection inputs")),
    };
    let queue_layout = GpuSharedQueueLayout::new(0x00b0_0000, 0x00b0_1000, 1)
        .map_err(|_| anyhow!("invalid fixed GPU queue layout"))?;
    let block_layout = VirtualBlockQueueLayout::new(0x0060_0000, 0x0060_2000, 2)
        .map_err(|_| anyhow!("invalid fixed block queue layout"))?;
    let block_transport = if mode == LaunchMode::PciConfigurationProbe {
        VirtualBlockTransport::MrmlSpecificPciMmio
    } else {
        VirtualBlockTransport::MrmlSpecificScalarIo
    };
    let block_configuration = block_configuration(block_layout, block_transport)?;
    let guest_preparation = match mode {
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
        LaunchMode::PciConfigurationProbe => system.prepare_kernel_block_dynamic_mmio_guest::<16>(
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
            PCI_TEST_MMIO_BASE,
        ),
        LaunchMode::TimerProbe
        | LaunchMode::PreemptionProbe
        | LaunchMode::DeadlineReceiveProbe
        | LaunchMode::DeadlineReceiveMessageProbe
        | LaunchMode::DeadlineReceiveCancelProbe
        | LaunchMode::DeadlineReceiveCancelDeniedProbe
        | LaunchMode::DeadlineReceiveCancelReplayProbe
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
        | LaunchMode::CertificateServiceProbe
        | LaunchMode::InvalidReturnProbe
        | LaunchMode::BufferDriftProbe
        | LaunchMode::ComponentServiceProbe
        | LaunchMode::BlockServiceProbe
        | LaunchMode::ServiceRestartRequestProbe
        | LaunchMode::ScanoutServiceProbe
        | LaunchMode::ScanoutServiceDeniedProbe
        | LaunchMode::Fat32ReadyProbe
        | LaunchMode::Fat32DataProbe
        | LaunchMode::Fat32RestartProbe => system
            .prepare_isolated_service_kernel_guest::<16>(
                0,
                &executable,
                handoff.as_slice(),
                layout,
            ),
        LaunchMode::ComponentServiceSmpProbe => system
            .prepare_isolated_service_smp_kernel_guest::<16>(
                &executable,
                handoff.as_slice(),
                layout,
            ),
        _ => system.prepare_kernel_guest::<16>(0, &executable, handoff.as_slice(), layout),
    };
    let mut guest = match guest_preparation {
        Ok(guest) => guest,
        Err(error) => {
            if component_service_mode {
                isolation_preparation
                    .take()
                    .ok_or_else(|| anyhow!("missing prepared component isolation route"))?
                    .unavailable(
                        isolation_admission
                            .as_mut()
                            .ok_or_else(|| anyhow!("missing component isolation admission"))?,
                        IsolationUnavailableReason::VmmResource,
                    )
                    .map_err(|failure| {
                        anyhow!("component unavailability publication failed: {:?}", failure)
                    })?;
            }
            return Err(anyhow!(
                "verified kernel launch preparation failed: {:?}",
                error
            ));
        }
    };
    if let (Some(application), Some(bundle), Some(application_executable)) = (
        application_launch,
        application_bundle.as_ref(),
        application_executable.as_ref(),
    ) {
        guest = guest
            .attach_application_boot_resources(application, bundle, application_executable)
            .map_err(|error| anyhow!("application boot-resource attachment failed: {:?}", error))?;
        application_projection
            .as_mut()
            .ok_or_else(|| anyhow!("missing admitted KVM application projection"))?
            .activate()?;
    }
    let mut component_launch = if component_service_mode {
        let prepared = isolation_preparation
            .take()
            .ok_or_else(|| anyhow!("missing prepared component isolation route"))?;
        let (generation_bytes, generation_length, _, catalog_bytes, catalog_length, _, _, _) =
            component_generation
                .as_ref()
                .ok_or_else(|| anyhow!("missing canonical component SystemGeneration"))?;
        let handoff = resolve_activated_interface_catalog(
            active_component_generation
                .as_ref()
                .ok_or_else(|| anyhow!("missing active component SystemGeneration"))?
                .generation(),
            &generation_bytes[..*generation_length],
            &catalog_bytes[..*catalog_length],
            "org.mrml.zim",
            "org.mrml.interface.compression.zstd",
            1,
            0x5a49_4d5f_5a53_5444,
            0x5a53_5444_0000_0003,
            ComponentServicePlacement::Microvm,
        )
        .map_err(|error| anyhow!("component interface resolution failed: {:?}", error))?;
        Some(match bind_component_service_handoff(prepared, handoff) {
            Ok(launch) => launch,
            Err((route, error)) => {
                route
                    .unavailable(
                        isolation_admission
                            .as_mut()
                            .ok_or_else(|| anyhow!("missing component isolation admission"))?,
                        IsolationUnavailableReason::VmmResource,
                    )
                    .map_err(|failure| {
                        anyhow!("component unavailability publication failed: {:?}", failure)
                    })?;
                return Err(anyhow!("component launch binding failed: {:?}", error));
            }
        })
    } else {
        None
    };
    if service_mode {
        let isolated_stack_pages = match mode {
            LaunchMode::BlockServiceProbe => 256,
            LaunchMode::CertificateServiceProbe => 64,
            // The pinned FAT32 PE entry probes a 0x35378-byte frame.
            LaunchMode::Fat32ReadyProbe | LaunchMode::Fat32DataProbe | LaunchMode::Fat32RestartProbe => 64,
            _ => 8,
        };
        let local_apic = component_smp_mode
            || matches!(
                mode,
                LaunchMode::DeadlineReceiveProbe
                    | LaunchMode::DeadlineReceiveMessageProbe
                    | LaunchMode::DeadlineReceiveCancelProbe
                    | LaunchMode::DeadlineReceiveCancelDeniedProbe
                    | LaunchMode::DeadlineReceiveCancelReplayProbe
                    | LaunchMode::ServicePreemptionProbe
                    | LaunchMode::SmpServiceMigrationProbe
            );
        guest = if let Some(launch) = component_launch.as_ref() {
            let ram = component_ram
                .as_mut()
                .ok_or_else(|| anyhow!("missing component RAM construction authority"))?;
            ram.5
                .consume_phase(ram.6)
                .map_err(|error| anyhow!("component service RAM phase failed: {:?}", error))?;
            match guest.attach_component_service_pair(
                launch,
                &executable,
                layout,
                service_executable
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing verified ZIM consumer"))?,
                SERVICE_PHYSICAL,
                SERVICE_VIRTUAL,
                SERVICE_STACK_PHYSICAL,
                SERVICE_STACK_VIRTUAL,
                8,
                SERVICE_TABLE_PHYSICAL,
                32,
                provider_executable
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing verified Zstd provider"))?,
                SERVICE_B_PHYSICAL,
                SERVICE_VIRTUAL,
                SERVICE_B_STACK_PHYSICAL,
                SERVICE_STACK_VIRTUAL,
                8,
                SERVICE_B_TABLE_PHYSICAL,
                32,
                local_apic,
            ) {
                Ok(guest) => guest,
                Err(error) => {
                    component_launch
                        .take()
                        .ok_or_else(|| anyhow!("missing prepared component launch"))?
                        .unavailable(
                            isolation_admission
                                .as_mut()
                                .ok_or_else(|| anyhow!("missing component isolation admission"))?,
                            IsolationUnavailableReason::VmmResource,
                        )
                        .map_err(|failure| {
                            anyhow!("component unavailability publication failed: {:?}", failure)
                        })?;
                    return Err(anyhow!(
                        "component service pair preparation failed: {:?}",
                        error
                    ));
                }
            }
        } else {
            let guest = guest
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
                    isolated_stack_pages,
                    SERVICE_TABLE_PHYSICAL,
                    32,
                    local_apic,
                )
                .map_err(|error| anyhow!("isolated service preparation failed: {:?}", error))?;
            guest
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
                    isolated_stack_pages,
                    SERVICE_B_TABLE_PHYSICAL,
                    32,
                    local_apic,
                )
                .map_err(|error| {
                    anyhow!("second isolated service preparation failed: {:?}", error)
                })?
        };
        if matches!(
            mode,
            LaunchMode::ServiceProbe
                | LaunchMode::DeadlineReceiveProbe
                | LaunchMode::DeadlineReceiveMessageProbe
                | LaunchMode::DeadlineReceiveCancelProbe
                | LaunchMode::DeadlineReceiveCancelDeniedProbe
                | LaunchMode::DeadlineReceiveCancelReplayProbe
                | LaunchMode::ServiceRestartRequestProbe
                | LaunchMode::Fat32ReadyProbe
                | LaunchMode::Fat32DataProbe
                | LaunchMode::Fat32RestartProbe
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
        if !scanout_mode {
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
        }
        if component_service_mode {
            let (
                memory,
                authorities,
                pool,
                pool_capability,
                ram_capability,
                prepared,
                _,
                control,
                control_capability,
                projection_target,
                provider_projection_target,
                shared_projection,
                shared_capability,
                resource_projection,
                resource_capability,
                consumer_image,
                provider_image,
            ) = component_ram
                .take()
                .ok_or_else(|| anyhow!("missing completed component RAM construction"))?;
            let active = prepared
                .complete()
                .map_err(|error| anyhow!("component RAM publication failed: {:?}", error))?;
            active_component_ram = Some((
                memory,
                authorities,
                pool,
                pool_capability,
                ram_capability,
                active,
                control,
                control_capability,
                projection_target,
                provider_projection_target,
                shared_projection,
                shared_capability,
                resource_projection,
                resource_capability,
                consumer_image,
                provider_image,
            ));
        }
        let service_entry = guest
            .service_entry()
            .ok_or_else(|| anyhow!("missing KVM service entry"))?;
        let provider_entry = guest
            .service_entry_at(1)
            .ok_or_else(|| anyhow!("missing KVM provider entry"))?;
        if guest.service_page_table_root() != PhysAddr::new(SERVICE_TABLE_PHYSICAL).ok()
            || guest.service_page_table_root_at(1) != PhysAddr::new(SERVICE_B_TABLE_PHYSICAL).ok()
            || (!component_service_mode && provider_entry != service_entry)
            || (matches!(
                mode,
                LaunchMode::ServiceProbe
                    | LaunchMode::DeadlineReceiveProbe
                    | LaunchMode::DeadlineReceiveMessageProbe
                    | LaunchMode::DeadlineReceiveCancelProbe
                    | LaunchMode::DeadlineReceiveCancelDeniedProbe
                    | LaunchMode::DeadlineReceiveCancelReplayProbe
                    | LaunchMode::ServiceRestartRequestProbe
                    | LaunchMode::Fat32ReadyProbe
                    | LaunchMode::Fat32DataProbe
                    | LaunchMode::Fat32RestartProbe
            ) && (guest.service_entry_at(2) != Some(service_entry)
                || guest.service_page_table_root_at(2)
                    != PhysAddr::new(SERVICE_C_TABLE_PHYSICAL).ok()))
        {
            return Err(anyhow!(
                "isolated service layout did not match the signed probe ABI"
            ));
        }
        if scanout_mode {
            let grant = if mode == LaunchMode::ScanoutServiceDeniedProbe { 2 } else { 1 };
            guest = guest.attach_scanout_bootstrap(grant)
                .map_err(|error| anyhow!("failed to prepare supervisor-only KVM scanout bootstrap: {:?}", error))?;
        } else {
            VmBackend::write_guest(
                &mut guest,
                SERVICE_SHARED_PHYSICAL + 8,
                &service_entry.to_le_bytes(),
            )
            .map_err(|_| anyhow!("failed to publish KVM service entry"))?;
        }
        if component_service_mode {
            VmBackend::write_guest(
                &mut guest,
                SERVICE_SHARED_PHYSICAL + 16,
                &provider_entry.to_le_bytes(),
            )
            .map_err(|_| anyhow!("failed to publish KVM provider entry"))?;
        }
    }
    if let Some(launch) = component_launch.take() {
        let consumer_artifact = *service_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified KVM component consumer"))?
            .artifact()
            .digest();
        let provider_artifact = *provider_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified KVM component provider"))?
            .artifact()
            .digest();
        let route = launch
            .verify(
                ArtifactKind::ServiceImage,
                &consumer_artifact,
                ArtifactKind::ServiceImage,
                &provider_artifact,
            )
            .map_err(|(_, error)| anyhow!("KVM component artifact seal failed: {:?}", error))?
            .into_route();
        if let Some(prepared) = complete_isolation_preparation.as_mut() {
            prepared.restore(route).map_err(|(error, _)| {
                anyhow!("KVM transformed complete route restore failed: {:?}", error)
            })?;
        } else {
            isolation_preparation = Some(route);
        }
    }
    let mut guest = if application_executable.is_some() {
        let spec = application_spec
            .ok_or_else(|| anyhow!("missing KVM application route specification"))?;
        let mut admission = IsolationAdmissionTable::<1>::new(
            IsolationMode::TotalMicrovm,
            spec.system_generation(),
            1,
        )
        .map_err(|error| anyhow!("application Total admission failed: {:?}", error))?;
        let mut launcher = PreparedMicrovmApplicationBackend::new(
            AdmittedApplicationGuestFactory::new(spec, guest),
        );
        let routed = route_isolation_application(&mut admission, &mut launcher, spec)
            .map_err(|error| anyhow!("application Total route failed: {:?}", error))?;
        let endpoint = routed.into_endpoint();
        if endpoint.spec() != spec || !admission.total_microvm_report().satisfied() {
            return Err(anyhow!(
                "application Total MicroVM admission was not satisfied"
            ));
        }
        let report = admission.total_microvm_report();
        println!(
            "application-isolation|status=PASS|scope=single-application|backend=kvm|system_generation={}|policy_generation={}|eligible={}|microvm={}|native_fallback={}",
            spec.system_generation(),
            spec.policy_generation(),
            report.running_microvm_eligible,
            report.running_in_microvm,
            report.native_fallback,
        );
        KvmGuestOwner::Application {
            launcher,
            endpoint,
            projection: application_projection
                .take()
                .ok_or_else(|| anyhow!("missing active KVM application projection"))?,
        }
    } else if component_service_mode {
        let configured = configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing KVM recovered component policy"))?;
        let total = match isolation_admission.take() {
            Some(KvmTotalAdmission::Recovered(total)) => total,
            _ => {
                return Err(anyhow!(
                    "KVM complete component set lost recovered admission"
                ));
            }
        };
        let prepared = complete_isolation_preparation
            .take()
            .ok_or_else(|| anyhow!("missing KVM complete component preparation"))?;
        if prepared.len() != 1 {
            return Err(anyhow!("KVM runner expects one recovered component domain"));
        }
        let spec = prepared
            .spec(configured.identity.domain())
            .ok_or_else(|| anyhow!("KVM complete component preparation lost its route"))?;
        let mut provisional_guest = Some(guest);
        let (runtime, mut routed) = total.start_prepared_services(
            prepared,
            |route_spec| {
                if route_spec != spec {
                    return Err(anyhow!("prepared KVM component identity changed"));
                }
                let guest = provisional_guest.take()
                    .ok_or_else(|| anyhow!("KVM component endpoint was already constructed"))?;
                let mut launcher = PreparedMicrovmConfigurationLauncher::new(
                    AdmittedConfigurationGuestFactory::new(spec, guest),
                );
                let endpoint = launcher.launch_microvm(spec)
                    .map_err(|(_, error)| anyhow!("KVM configuration lifecycle failed: {:?}", error))?;
                Ok((launcher, endpoint))
            },
            |_, (mut launcher, endpoint)| {
                if launcher.revoke_microvm(&endpoint).is_ok() {
                    Ok(())
                } else {
                    Err((launcher, endpoint))
                }
            },
        ).map_err(|failure| anyhow!(
            "KVM complete component startup failed: {:?}; unconfirmed endpoints={}",
            failure.error(), failure.pending_count(),
        ))?;
        let (launcher, endpoint) = routed.take(configured.identity.domain())
            .ok_or_else(|| anyhow!("KVM complete publication omitted component endpoint"))?
            .into_endpoint();
        debug_assert!(routed.is_empty());
        let proof = runtime.proof();
        println!(
            "component-total-inventory|status=PASS|backend=kvm|classified={}|eligible={}|microvm={}|native_fallback={}",
            proof.classified_domains(),
            proof.running_microvm_eligible(),
            proof.running_in_microvm(),
            runtime.admission().total_microvm_report().native_fallback
        );
        installed_total_runtime = Some(runtime);
        KvmGuestOwner::Configuration { launcher, endpoint }
    } else if let (Some(admission), Some(prepared)) =
        (isolation_admission.as_mut(), isolation_preparation)
    {
        let spec = prepared.spec();
        let routed = prepared
            .commit(admission, guest)
            .map_err(|(_, error, _)| anyhow!("KVM isolation commit failed: {:?}", error))?;
        if routed.system_generation() != admission.system_generation() {
            return Err(anyhow!("KVM active SystemGeneration changed during launch"));
        }
        let admitted_guest = routed.into_endpoint();
        if !admission.total_microvm_report().satisfied() {
            return Err(anyhow!("KVM Total MicroVM admission was not satisfied"));
        }
        let mut launcher = PreparedMicrovmConfigurationLauncher::new(
            AdmittedConfigurationGuestFactory::new(spec, admitted_guest),
        );
        let endpoint = launcher
            .launch_microvm(spec)
            .map_err(|(_, error)| anyhow!("KVM configuration lifecycle failed: {:?}", error))?;
        KvmGuestOwner::Configuration { launcher, endpoint }
    } else {
        KvmGuestOwner::Direct(guest)
    };
    let preparation_micros = preparation_started.elapsed().as_micros();
    let execution_started = Instant::now();
    if mode == LaunchMode::PciConfigurationProbe {
        run_pci_configuration_probe(
            guest.into_direct()?,
            &system,
            &executable,
            handoff.as_slice(),
            layout,
        )?;
        println!(
            "verified signed test-only attached MRML block PCI-MMIO write/read/flush, decode-coupled native BAR install/withdraw with checked CR3 reload and continuation, orderly VM replacement, and pending-I/O reset isolation under KVM: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if mode == LaunchMode::BlockGuestDriverProbe {
        run_block_guest_driver_probe(
            guest.into_direct()?,
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
        let (exits, elapsed) = run_scheduled_smp(&mut guest)?;
        let [bootstrap, application] = exits;
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
        println!(
            "verified signed scheduled two-vCPU kernel startup under KVM: bootstrap={}us application={}us",
            elapsed[0], elapsed[1]
        );
        VmExit::Halted
    } else if component_smp_mode {
        let (exits, elapsed) = run_component_smp(&mut component_cpu, &mut guest)?;
        let [bootstrap, application] = exits;
        let expected_bootstrap = VmExit::Io {
            port: SMP_PROBE_PORT,
            size: 4,
            write: true,
            value: 2,
        };
        let expected_application = VmExit::Io {
            port: SMP_PROBE_PORT,
            size: 4,
            write: true,
            value: 0x0001_0001,
        };
        if bootstrap != expected_bootstrap || application != expected_application {
            return Err(anyhow!(
                "component SMP proof mismatch: bootstrap={:?} application={:?}",
                bootstrap,
                application
            ));
        }
        println!(
            "verified Total-mode component two-vCPU startup under KVM: bootstrap={}us application={}us",
            elapsed[0], elapsed[1]
        );
        run_component_vcpu(&mut component_cpu, |slice| {
            match ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
                &mut guest,
                0,
                slice.logical_cpu(),
                slice.priority(),
                slice.charged_micros(),
            ) {
                Ok(VmDeadlineOutcome::Exit(exit)) => Ok(exit),
                Ok(VmDeadlineOutcome::Expired) => {
                    Err(anyhow!("KVM component vCPU deadline expired"))
                }
                Err(error) => Err(anyhow!("KVM component execution failed: {:?}", error)),
            }
        })?
    } else if component_service_mode {
        run_component_vcpu(&mut component_cpu, |slice| {
            match ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
                &mut guest,
                0,
                slice.logical_cpu(),
                slice.priority(),
                slice.charged_micros(),
            ) {
                Ok(VmDeadlineOutcome::Exit(exit)) => Ok(exit),
                Ok(VmDeadlineOutcome::Expired) => {
                    Err(anyhow!("KVM component vCPU deadline expired"))
                }
                Err(error) => Err(anyhow!("KVM component execution failed: {:?}", error)),
            }
        })?
    } else {
        VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM execution failed: {:?}", error))?
    };
    if mode.application_package_id().is_some() {
        for stage in 1..=6u32 {
            let expected = VmExit::Io {
                port: APPLICATION_PROBE_PORT,
                size: 4,
                write: true,
                value: 0xa000 | stage,
            };
            if exit != expected {
                return Err(anyhow!(
                    "Total-mode application stopped before signed-kernel stage {}: {:?}",
                    stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM application continuation failed: {:?}", error))?;
        }
        if exit
            != (VmExit::Io {
                port: APPLICATION_PROBE_PORT,
                size: 4,
                write: true,
                value: 1,
            })
        {
            return Err(anyhow!(
                "Total-mode application did not exit through the authenticated CPL3 path: {:?}",
                exit
            ));
        }
        println!(
            "verified ordered signed-kernel stages and authenticated CPL3 application exit under KVM"
        );
        exit = VmExit::Halted;
    } else if mode == LaunchMode::GpuBenchmark {
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
    } else if matches!(
        mode,
        LaunchMode::ComponentServiceProbe | LaunchMode::ComponentServiceSmpProbe
    ) {
        let cleanup_stages = [0x21, 0x20, 0x40];
        let mut cleanup_stage = 0;
        for accepted_exits in 0..64 {
            match exit {
                VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 1..=2,
                } => {}
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value,
                } => {
                    if cleanup_stages.get(cleanup_stage).copied() != Some(value) {
                        return Err(anyhow!("KVM component cleanup stage mismatch: {:?}", exit));
                    }
                    cleanup_stage += 1;
                    if value == 0x40 {
                        exit = VmExit::Halted;
                        break;
                    }
                }
                _ => {
                    let state = guest.snapshot().map_err(|error| {
                        anyhow!(
                            "KVM component service stage mismatch ({:?}) and state capture failed: {:?}",
                            exit,
                            error
                        )
                    })?;
                    return Err(anyhow!(
                        "KVM component service stage mismatch after {} accepted exits: {:?}; rip={:#x} rsp={:#x} cr3={:#x} cr2={:#x}",
                        accepted_exits,
                        exit,
                        state.instruction_pointer(),
                        state.stack_pointer(),
                        state.page_table_root(),
                        state.fault_address()
                    ));
                }
            }
            exit = run_component_vcpu(&mut component_cpu, |slice| {
                match ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
                    &mut guest,
                    0,
                    slice.logical_cpu(),
                    slice.priority(),
                    slice.charged_micros(),
                ) {
                    Ok(VmDeadlineOutcome::Exit(exit)) => Ok(exit),
                    Ok(VmDeadlineOutcome::Expired) => {
                        Err(anyhow!("KVM component service vCPU deadline expired"))
                    }
                    Err(error) => Err(anyhow!(
                        "KVM component service execution failed: {:?}",
                        error
                    )),
                }
            })?;
        }
        if exit != VmExit::Halted {
            return Err(anyhow!(
                "KVM component service probe exceeded its stage bound"
            ));
        }
    } else if mode == LaunchMode::BlockServiceProbe {
        let cleanup_stages = [0x21, 0x31, 0x20, 0x30];
        let mut cleanup_stage = 0;
        for observed_stage in 0..1024 {
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
                    let report = isolation_admission
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing KVM block-service admission"))?
                        .total_microvm_report();
                    if !report.satisfied() || report.running_in_microvm != 1 || report.native_fallback != 0 {
                        return Err(anyhow!("KVM block-service fixture lost its admitted microVM"));
                    }
                    guest.finish()?;
                    println!("storage-block-probe|status=PASS|backend=kvm|scope=ram-backed-fixture|microvm=1|native_fallback=0");
                    println!(
                        "verified independently signed CPL3 block-service stable-policy publication/recovery and lifecycle cleanup under KVM: verify={}us prepare={}us execute={}us total={}us",
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
                return Err(anyhow!(
                    "KVM block-service stage mismatch after {} accepted exits: {:?}",
                    observed_stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM block-service execution failed: {:?}", error))?;
        }
        return Err(anyhow!("KVM block-service probe exceeded its stage bound"));
    } else if matches!(
        mode,
        LaunchMode::DeadlineReceiveProbe
            | LaunchMode::DeadlineReceiveMessageProbe
            | LaunchMode::DeadlineReceiveCancelProbe
            | LaunchMode::DeadlineReceiveCancelDeniedProbe
            | LaunchMode::DeadlineReceiveCancelReplayProbe
    ) {
        let expected = match mode {
            LaunchMode::DeadlineReceiveProbe => 0x2a,
            LaunchMode::DeadlineReceiveMessageProbe => 0x2b,
            LaunchMode::DeadlineReceiveCancelProbe => 0x2c,
            LaunchMode::DeadlineReceiveCancelDeniedProbe => 0x2d,
            LaunchMode::DeadlineReceiveCancelReplayProbe => 0x2e,
            _ => unreachable!(),
        };
        require_deadline_receive_proof(exit, expected)?;
        println!(
            "verified exact deadline receive completion under KVM: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        exit = VmExit::Halted;
    } else if mode == LaunchMode::InvalidReturnProbe {
        require_invalid_return_stage(exit, 0x26)?;
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM invalid-return peer execution failed: {:?}", error))?;
        require_invalid_return_stage(exit, 0x27)?;
        exit = VmExit::Halted;
    } else if scanout_mode {
        let probe = |value| VmExit::Io { port: SERVICE_PROBE_PORT, size: 4, write: true, value };
        if mode == LaunchMode::ScanoutServiceDeniedProbe {
            if exit != probe(0x5c02) {
                let state = guest.snapshot().map_err(|error| anyhow!("scanout denial snapshot: {:?}", error))?;
                return Err(anyhow!("KVM scanout denial mismatch: {:?}; rip={:#x} cr2={:#x}", exit, state.instruction_pointer(), state.fault_address()));
            }
            println!("scanout-probe|status=PASS|backend=kvm|scope=single-service-fixture|write_grant=denied|bytes=0|native_fallback=0");
        } else {
            if exit != probe(0x5c01) {
                let state = guest.snapshot().map_err(|error| anyhow!("scanout snapshot: {:?}", error))?;
                return Err(anyhow!("KVM scanout completion mismatch: {:?}; rip={:#x} cr2={:#x}", exit, state.instruction_pointer(), state.fault_address()));
            }
            let mut hash = 0xcbf2_9ce4_8422_2325u64;
            let mut white = 0;
            for _ in 0..4096 {
                let word = match VmBackend::run(&mut guest, 0)
                    .map_err(|error| anyhow!("KVM scanout capture failed: {:?}", error))?
                {
                    VmExit::Io { port: SERVICE_FRAME_PORT, size: 4, write: true, value } if matches!(value, 0x000b_3b5a | 0x00ff_ffff) => value,
                    other => return Err(anyhow!("unexpected scanout pixel exit: {:?}", other)),
                };
                white += usize::from(word == 0x00ff_ffff);
                for byte in word.to_le_bytes() {
                    hash = (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
                }
            }
            if hash != 0xbc3e_34ff_2bb4_77d0 || white != 243
                || VmBackend::run(&mut guest, 0)
                    .map_err(|error| anyhow!("missing KVM scanout terminal: {:?}", error))? != probe(0x5c03)
            {
                return Err(anyhow!("KVM scanout pixels or terminal proof mismatch: pixels={white} hash={hash:#x}"));
            }
            println!("scanout-probe|status=PASS|backend=kvm|scope=single-service-fixture|write_grant=released|bytes=16384|white_pixels={white}|native_fallback=0");
        }
        exit = VmExit::Halted;
    } else if matches!(mode, LaunchMode::Fat32ReadyProbe | LaunchMode::Fat32DataProbe | LaunchMode::Fat32RestartProbe) {
        let data = mode == LaunchMode::Fat32DataProbe;
        let restart = mode == LaunchMode::Fat32RestartProbe;
        if exit != (VmExit::Io { port: SERVICE_PROBE_PORT, size: 4, write: true, value: if restart { 0xf322 } else if data { 0xf321 } else { 0xf320 } }) {
            let state = guest.snapshot()
                .map_err(|error| anyhow!("FAT32 readiness failed ({:?}): {:?}", exit, error))?;
            return Err(anyhow!("FAT32 readiness mismatch: {:?}; rip={:#x} rsp={:#x} cr2={:#x}", exit, state.instruction_pointer(), state.stack_pointer(), state.fault_address()));
        }
        if restart {
            println!("verified signed FAT32 supervised restart and stale-handle denial under KVM");
        } else if data {
            println!("verified signed FAT32 PROBE.TXT read under KVM");
        } else {
            println!("verified authenticated native FAT32 readiness under KVM");
        }
        exit = VmExit::Halted;
    } else if mode == LaunchMode::BufferDriftProbe {
        require_buffer_drift_stage(exit, 0x28)?;
        exit = VmBackend::run(&mut guest, 0)
            .map_err(|error| anyhow!("KVM buffer-drift peer execution failed: {:?}", error))?;
        require_buffer_drift_stage(exit, 0x29)?;
        exit = VmExit::Halted;
    } else if matches!(
        mode,
        LaunchMode::ServiceProbe
            | LaunchMode::CertificateServiceProbe
            | LaunchMode::ServiceRestartRequestProbe
    ) {
        let initial_call = 1;
        if exit
            != (VmExit::Io {
                port: SERVICE_CALL_PORT,
                size: 4,
                write: true,
                value: initial_call,
            })
        {
            let state = guest.snapshot().map_err(|error| {
                anyhow!(
                    "isolated receiver did not block ({:?}) and state capture failed: {:?}",
                    exit,
                    error
                )
            })?;
            return Err(anyhow!(
                "isolated service initial IPC stage mismatch: {:?}; rip={:#x} rsp={:#x} cr3={:#x} cr2={:#x}",
                exit,
                state.instruction_pointer(),
                state.stack_pointer(),
                state.page_table_root(),
                state.fault_address()
            ));
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
        if mode == LaunchMode::CertificateServiceProbe {
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 1,
                })
            {
                return Err(anyhow!(
                    "certificate probe response receive mismatch: {:?}",
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM certificate service response failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 2,
                })
            {
                return Err(anyhow!("certificate probe response mismatch: {:?}", exit));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("KVM certificate service completion failed: {:?}", error)
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
                    "certificate service cleanup request mismatch: {:?}",
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
                    .ok_or_else(|| anyhow!("missing verified certificate service executable"))?,
            )?;
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!("KVM certificate probe peer completion failed: {:?}", error)
            })?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x22,
                })
            {
                return Err(anyhow!(
                    "certificate probe peer-death stage mismatch: {:?}",
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "KVM certificate probe peer finalization failed: {:?}",
                    error
                )
            })?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 3,
                })
            {
                return Err(anyhow!(
                    "certificate probe response completion mismatch: {:?}",
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("KVM certificate probe exit failed: {:?}", error))?;
            if exit
                != (VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x21,
                })
            {
                return Err(anyhow!("certificate peer cleanup mismatch: {:?}", exit));
            }
            complete_kvm_service_cleanup(
                &mut guest,
                1,
                SERVICE_B_STACK_PHYSICAL,
                SERVICE_B_TABLE_PHYSICAL,
                &executable,
                service_executable
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing verified certificate service executable"))?,
            )?;
            println!(
                "verified signed CPL3 certificate persistence and exact identity IPC under KVM: verify={}us prepare={}us execute={}us total={}us",
                verification_micros,
                preparation_micros,
                execution_started.elapsed().as_micros(),
                total_started.elapsed().as_micros()
            );
            return Ok(());
        }
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
                let state = guest.snapshot().map_err(|error| {
                    anyhow!(
                        "KVM configuration response stage {} mismatch ({:?}) and state capture failed: {:?}",
                        stage,
                        exit,
                        error
                    )
                })?;
                return Err(anyhow!(
                    "KVM configuration response stage {} mismatch: {:?}; rip={:#x} rsp={:#x} cr3={:#x} cr2={:#x}",
                    stage,
                    exit,
                    state.instruction_pointer(),
                    state.stack_pointer(),
                    state.page_table_root(),
                    state.fault_address()
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
            let state = guest.snapshot().map_err(|error| {
                anyhow!(
                    "KVM receiver cleanup request mismatch ({:?}) and state capture failed: {:?}",
                    exit,
                    error
                )
            })?;
            return Err(anyhow!(
                "KVM receiver cleanup request mismatch: {:?}; rip={:#x} rsp={:#x} cr3={:#x} cr2={:#x}",
                exit,
                state.instruction_pointer(),
                state.stack_pointer(),
                state.page_table_root(),
                state.fault_address()
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
                let state = guest.snapshot().map_err(|error| {
                    anyhow!(
                        "restarted KVM service IPC stage {} failed ({:?}) and state capture failed: {:?}",
                        stage,
                        exit,
                        error
                    )
                })?;
                return Err(anyhow!(
                    "restarted KVM service IPC stage {} failed: {:?}; rip={:#x} rsp={:#x} cr3={:#x} cr2={:#x}",
                    stage,
                    exit,
                    state.instruction_pointer(),
                    state.stack_pointer(),
                    state.page_table_root(),
                    state.fault_address()
                ));
            }
            exit = VmBackend::run(&mut guest, 0).map_err(|error| {
                anyhow!(
                    "KVM execution during restarted service IPC failed: {:?}",
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
        LaunchMode::ApplicationProbe | LaunchMode::GuiApplicationProbe if marker != [0; 4] => {
            return Err(anyhow!(
                "application probe unexpectedly modified the framebuffer"
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
        LaunchMode::ServiceProbe
        | LaunchMode::CertificateServiceProbe
        | LaunchMode::DeadlineReceiveProbe
        | LaunchMode::DeadlineReceiveMessageProbe
        | LaunchMode::DeadlineReceiveCancelProbe
        | LaunchMode::DeadlineReceiveCancelDeniedProbe
        | LaunchMode::DeadlineReceiveCancelReplayProbe
        | LaunchMode::InvalidReturnProbe
        | LaunchMode::BufferDriftProbe
            if marker != [0; 4] =>
        {
            return Err(anyhow!(
                "service probe unexpectedly modified the framebuffer"
            ));
        }
        LaunchMode::ComponentServiceProbe | LaunchMode::ComponentServiceSmpProbe
            if marker != [0; 4] =>
        {
            return Err(anyhow!(
                "component service probe unexpectedly modified the framebuffer"
            ));
        }
        LaunchMode::GpuBenchmark if marker != [0x78, 0xe0, 0x46, 0] => {
            return Err(anyhow!(
                "kernel did not authenticate the GPU benchmark completion"
            ));
        }
        _ => {}
    }
    let retired_recovered_domains = if component_service_mode {
        Some(
            installed_total_runtime
                .take()
                .ok_or_else(|| anyhow!("missing recovered KVM runtime owner"))?
                .withdraw_for_shutdown()
                .map_err(|error| anyhow!("KVM recovered runtime withdrawal failed: {:?}", error))?,
        )
    } else {
        None
    };
    guest.finish()?;
    if let Some((
        mut memory,
        mut authorities,
        pool,
        pool_capability,
        ram_capability,
        active,
        control,
        control_capability,
        projection_target,
        provider_projection_target,
        shared_projection,
        shared_capability,
        resource_projection,
        resource_capability,
        consumer_image,
        provider_image,
    )) = active_component_ram.take()
    {
        let expected_pages = active.pages();
        let reservation = unsafe { active.retire() };
        let released = unsafe {
            release_microvm_guest_ram(&mut memory, reservation, ram_capability, &mut authorities)
        }
        .map_err(|error| anyhow!("component RAM release failed: {:?}", error))?;
        let usage = memory
            .usage(pool, pool_capability, &authorities)
            .map_err(|error| anyhow!("component RAM inspection failed: {:?}", error))?;
        let expected_control_pages = control.pages();
        let consumer_plan = consumer_image.plan();
        let provider_plan = provider_image.plan();
        let expected_image_pages = consumer_plan
            .total_pages()
            .and_then(|pages| provider_plan.total_pages()?.checked_add(pages))
            .ok_or_else(|| anyhow!("component image release expectation overflow"))?;
        let expected_image_mappings = u32::from(consumer_plan.regions())
            .checked_add(u32::from(provider_plan.regions()))
            .ok_or_else(|| anyhow!("component image mapping expectation overflow"))?;
        if released != expected_pages
            || usage.object_pages() != expected_control_pages + 2 + expected_image_pages
            || usage.active_mappings() != 2 + expected_image_mappings
        {
            return Err(anyhow!("component RAM release state was invalid"));
        }
        unsafe {
            memory
                .release_mapping(shared_projection.mapping(), projection_target, &authorities)
                .map_err(|error| {
                    anyhow!("component shared projection release failed: {:?}", error)
                })?;
            memory
                .release_mapping(
                    resource_projection.mapping(),
                    projection_target,
                    &authorities,
                )
                .map_err(|error| {
                    anyhow!("component resource projection release failed: {:?}", error)
                })?;
        }
        let released_shared = memory
            .release_object(
                shared_projection.object(),
                shared_capability,
                &mut authorities,
            )
            .map_err(|error| anyhow!("component shared page release failed: {:?}", error))?;
        let released_resource = memory
            .release_object(
                resource_projection.object(),
                resource_capability,
                &mut authorities,
            )
            .map_err(|error| anyhow!("component resource page release failed: {:?}", error))?;
        let usage = memory
            .usage(pool, pool_capability, &authorities)
            .map_err(|error| anyhow!("component projection inspection failed: {:?}", error))?;
        if released_shared != 1
            || released_resource != 1
            || usage.object_pages() != expected_control_pages + expected_image_pages
            || usage.active_mappings() != expected_image_mappings
        {
            return Err(anyhow!(
                "component projections were not completely reclaimed"
            ));
        }
        let released_consumer = unsafe {
            release_component_image(
                &mut memory,
                consumer_image,
                projection_target,
                &mut authorities,
            )
        }
        .map_err(|error| anyhow!("consumer image release failed: {:?}", error))?;
        let released_provider = unsafe {
            release_component_image(
                &mut memory,
                provider_image,
                provider_projection_target,
                &mut authorities,
            )
        }
        .map_err(|error| anyhow!("provider image release failed: {:?}", error))?;
        let usage = memory
            .usage(pool, pool_capability, &authorities)
            .map_err(|error| anyhow!("component image inspection failed: {:?}", error))?;
        if released_consumer.pages != consumer_plan.total_pages().unwrap_or(0)
            || released_consumer.regions != consumer_plan.regions()
            || released_provider.pages != provider_plan.total_pages().unwrap_or(0)
            || released_provider.regions != provider_plan.regions()
            || usage.object_pages() != expected_control_pages
            || usage.active_mappings() != 0
        {
            return Err(anyhow!("component images were not completely reclaimed"));
        }
        let released_control = unsafe {
            mrml_kernel::release_microvm_control_memory(
                &mut memory,
                control,
                control_capability,
                &mut authorities,
            )
        }
        .map_err(|error| anyhow!("component control-memory release failed: {:?}", error))?;
        let usage = memory
            .usage(pool, pool_capability, &authorities)
            .map_err(|error| anyhow!("component memory inspection failed: {:?}", error))?;
        if released_control != expected_control_pages
            || usage.object_pages() != 0
            || usage.active_mappings() != 0
        {
            return Err(anyhow!("component memory was not completely reclaimed"));
        }
    }
    if let Some((
        mut budgets,
        mut capabilities,
        budget,
        capability,
        reservation,
        cpu_runtime_micros,
    )) = component_cpu.take()
    {
        let cpu_runtime_total = cpu_runtime_micros[0]
            .checked_add(cpu_runtime_micros[1])
            .ok_or_else(|| anyhow!("component CPU runtime total overflow"))?;
        let expected_vcpus = if cpu_runtime_micros[1] == 0 { 1 } else { 2 };
        if budgets
            .release_vcpus(reservation, capability, &capabilities)
            .map_err(|error| anyhow!("component vCPU release failed: {:?}", error))?
            != expected_vcpus
        {
            return Err(anyhow!("component vCPU release count mismatch"));
        }
        let usage = budgets
            .usage(budget, capability, &capabilities)
            .map_err(|error| anyhow!("component CPU inspection failed: {:?}", error))?;
        if usage.reserved_parallelism() != 0
            || usage.active_reservations() != 0
            || usage.consumed_runtime_micros()
                != u32::try_from(cpu_runtime_total).unwrap_or(u32::MAX)
            || cpu_runtime_total == 0
        {
            return Err(anyhow!("component vCPU authority was not reclaimed"));
        }
        budgets
            .retire_root(budget, capability, &mut capabilities)
            .map_err(|error| anyhow!("component CPU root retirement failed: {:?}", error))?;
        println!(
            "cpu|component_runtime={}us|accounting=elapsed-reconciled|logical_cpu=0|affinity=host-enforced|priority=host-normal|backend=kvm",
            cpu_runtime_total
        );
    }
    if let Some(retired) = retired_recovered_domains {
        println!(
            "isolation-shutdown|status=PASS|backend=kvm|runtime=withdrawn|retired_domains={}",
            retired
        );
    } else if let Some(admission) = isolation_admission.as_ref().map(|value| &**value) {
        let report = admission.total_microvm_report();
        println!(
            "isolation|requested=total-microvm|status=satisfied|backend=kvm|policy_generation={}|eligible={}|microvm={}|native_fallback={}",
            admission.policy_generation(),
            report.running_microvm_eligible,
            report.running_in_microvm,
            report.native_fallback
        );
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
    bytes: [u8; 512],
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
    recovery_state: Option<RecoveryStateMetadata>,
    isolation_override: Option<BootIsolationOverride>,
    coherent_release: bool,
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
    let mut encoded = [0u8; 512];
    let installed_recovery = recovery_state
        .and_then(|state| state.accepted_volume().map(|volume| (state, volume)))
        .map(|(state, volume)| {
            InstalledRecoveryBootIdentity::new(
                InstalledRecoverySource::Hosted,
                [0x42; 32],
                1,
                1,
                4096,
                mrml_config::hosted_recovery_probe::HOSTED_RECOVERY_BLOCK_COUNT,
                volume,
                1,
                state.accepted_root_generation(),
            )
            .map_err(|_| anyhow!("invalid installed recovery identity"))
        })
        .transpose()?;
    let length = match (recovery_state, isolation_override, installed_recovery) {
        (Some(recovery_state), isolation_override, Some(installed_recovery)) => {
            encode_handoff_with_recovery_isolation_and_installed(
                version,
                entropy,
                measurement,
                true,
                false,
                false,
                coherent_release,
                0x9000,
                framebuffer,
                &regions,
                recovery_state,
                installed_recovery,
                isolation_override,
                &mut encoded,
            )
        }
        (Some(recovery_state), Some(isolation_override), None) => {
            encode_handoff_with_recovery_and_isolation(
                version,
                entropy,
                measurement,
                true,
                false,
                false,
                coherent_release,
                0x9000,
                framebuffer,
                &regions,
                recovery_state,
                Some(isolation_override),
                &mut encoded,
            )
        }
        (Some(recovery_state), None, None) => encode_handoff_with_recovery(
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
        (None, None, None) => encode_handoff(
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
        (None, Some(_), None) => {
            return Err(anyhow!("isolation override requires recovery metadata"));
        }
        (None, _, Some(_)) => unreachable!("installed recovery derives from recovery metadata"),
    }
    .map_err(|_| anyhow!("canonical boot handoff construction failed"))?;
    if length
        != 240
            + usize::from(recovery_state.is_some()) * 40
            + usize::from(installed_recovery.is_some()) * 104
    {
        return Err(anyhow!("unexpected canonical boot handoff length"));
    }
    Ok(EncodedHandoff {
        bytes: encoded,
        length,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn application_boot_handoff(
    version: u64,
    entropy: [u8; 32],
    measurement: [u8; 64],
    application: ApplicationLaunch,
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
        region(APPLICATION_ARTIFACT_PHYSICAL, 0xff, MemoryKind::Reserved)?,
    ];
    let mut encoded = [0u8; 512];
    let length = encode_handoff_with_application(
        version,
        entropy,
        measurement,
        true,
        false,
        false,
        0x9000,
        framebuffer,
        &regions,
        application,
        &mut encoded,
    )
    .map_err(|_| anyhow!("canonical application handoff construction failed"))?;
    if length != 424 {
        return Err(anyhow!("unexpected canonical application handoff length"));
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
    recovery_state: Option<RecoveryStateMetadata>,
    isolation_override: Option<BootIsolationOverride>,
    coherent_release: bool,
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
    let mut encoded = [0u8; 512];
    let length = if let Some(recovery_state) = recovery_state {
        let installed = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Hosted,
            [0x42; 32],
            1,
            1,
            4096,
            mrml_config::hosted_recovery_probe::HOSTED_RECOVERY_BLOCK_COUNT,
            recovery_state
                .accepted_volume()
                .ok_or_else(|| anyhow!("SMP Total recovery requires an installed volume"))?,
            1,
            recovery_state.accepted_root_generation(),
        )
        .map_err(|_| anyhow!("invalid hosted installed recovery identity"))?;
        encode_handoff_with_smp_recovery_isolation_and_installed(
            version,
            entropy,
            measurement,
            true,
            false,
            false,
            coherent_release,
            0x9000,
            framebuffer,
            &regions,
            0x8000,
            0x100_0000,
            recovery_state,
            installed,
            isolation_override,
            &madt,
            &mut encoded,
        )
    } else if isolation_override.is_none() {
        encode_handoff_with_smp(
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
    } else {
        return Err(anyhow!("SMP isolation override requires recovery metadata"));
    }
    .map_err(|_| anyhow!("canonical SMP handoff construction failed"))?;
    if length != 316 + usize::from(recovery_state.is_some()) * (40 + 104) {
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
    extern crate std;

    use super::*;
    use mrml_kernel::BootHandoff;

    #[cfg(target_os = "linux")]
    fn signed_recovery_service_fixture(marker: u8) -> (std::vec::Vec<u8>, TrustRoot) {
        use mrml_crypto::{
            LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, lamport_public_key, lamport_sign,
        };
        use mrml_kernel::{SIGNED_ARTIFACT_HEADER_BYTES, artifact_statement};

        let mut image = [0u8; 1024];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x96..0x98].copy_from_slice(&2u16.to_le_bytes());
        let optional = 0x98;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 24..optional + 32]
            .copy_from_slice(&RECOVERY_SERVICE_IMAGE_BASE.to_le_bytes());
        image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 70..optional + 72].copy_from_slice(&0x100u16.to_le_bytes());
        let section = optional + 240;
        image[section..section + 5].copy_from_slice(b".text");
        image[section + 8..section + 12].copy_from_slice(&9u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        // Two inert marker writes to the hosted test adapter, then halt.
        image[0x200..0x209].copy_from_slice(&[
            0xb0,
            marker,
            0xe6,
            0xe9,
            0xb0,
            marker + 2,
            0xe6,
            0xe9,
            0xf4,
        ]);

        let private = std::vec![marker; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = std::vec![0; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = std::vec![0; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let root = TrustRoot::new(ArtifactKind::ServiceImage, Sha3_512::digest(&public), 1);
        let digest = Sha3_512::digest(&image);
        let statement =
            artifact_statement(ArtifactKind::ServiceImage, 1, image.len() as u64, digest);
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let mut signed = std::vec![0; SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len()];
        signed[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        signed[16] = ArtifactKind::ServiceImage as u8;
        signed[24..32].copy_from_slice(&1u64.to_le_bytes());
        signed[32..40].copy_from_slice(&(image.len() as u64).to_le_bytes());
        signed[40..104].copy_from_slice(&digest);
        let signature_at = SIGNED_ARTIFACT_HEADER_BYTES + public.len();
        signed[SIGNED_ARTIFACT_HEADER_BYTES..signature_at].copy_from_slice(&public);
        signed[signature_at..SIGNED_ARTIFACT_OVERHEAD_BYTES].copy_from_slice(&signature);
        signed[SIGNED_ARTIFACT_OVERHEAD_BYTES..].copy_from_slice(&image);
        (signed, root)
    }

    #[cfg(target_os = "linux")]
    const RECOVERY_SERVICE_IMAGE_BASE: u64 = 0xffff_8001_4000_0000;

    // The signed inventory exercises the real admission transaction; the
    // two diagnostic executables are recovered from the same persisted disk image.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a usable /dev/kvm; execute explicitly on a KVM host"]
    fn live_kvm_total_startup_rollback_and_same_spec_restart() {
        use mrml_config::{
            CompleteTotalServiceConstructionError, CompleteTotalServiceStartError,
            ConfigurationMicrovmDeviceLease, PreparedMicrovmConfigurationAccessError,
            PreparedMicrovmConfigurationError,
        };
        use mrml_crypto::{LAMPORT_PRIVATE_KEY_BYTES, lamport_public_key};
        use mrml_kernel::IsolationServiceSpec;
        use mrml_package_format::{
            ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
            encode_system_release_with_runtime_inventory,
        };

        use mrml_config::hosted_recovery_probe::{
            HOSTED_TOTAL_SECONDARY_DOMAIN, HostedInstalledService, HostedRecoveryDisk,
            HostedRecoveryImageFile, HostedRecoveryProbeBuildError, HostedRecoveryProbeError,
        };
        const DOMAINS: [ObjectId; 2] =
            [HOSTED_TOTAL_COMPONENT_DOMAIN, HOSTED_TOTAL_SECONDARY_DOMAIN];
        const IDS: [&str; 2] = ["org.mrml.test.first", "org.mrml.test.second"];
        const INTERFACES: [&str; 2] = ["org.mrml.interface.first", "org.mrml.interface.second"];
        const GEN: u64 = 33;
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let handoff_bytes = boot_handoff(
            21,
            [0x38; 32],
            [0xaa; 64],
            1,
            Some(recovery),
            Some(BootIsolationOverride::TotalMicrovmOnce),
            true,
        )
        .unwrap();
        let handoff = BootHandoff::decode(handoff_bytes.as_slice(), |_| {}).unwrap();
        let signed = [
            signed_recovery_service_fixture(0x51),
            signed_recovery_service_fixture(0x52),
        ];
        let manifest_inputs = [0, 1].map(|i| {
            let container = SignedArtifact::decode(&signed[i].0).unwrap();
            assert!(
                container
                    .verify_executable(&signed[1 - i].1, ArtifactKind::ServiceImage)
                    .is_err()
            );
            container
                .verify_executable(&signed[i].1, ArtifactKind::ServiceImage)
                .unwrap()
        });
        let versions = [0, 1].map(|i| SystemGenerationDigestRecord {
            package_id: IDS[i],
            version: 1,
            artifact_digest: manifest_inputs[i].artifact().digest(),
        });
        let providers = [0, 1].map(|i| {
            ComponentInterfaceProvider::exact(
                IDS[i],
                INTERFACES[i],
                1,
                [0x52 + i as u8; 32],
                ComponentProviderForms::MICROVM,
            )
            .unwrap()
        });
        let requirements = [0, 1].map(|i| {
            ComponentInterfaceRequirement::exact(IDS[i], INTERFACES[i], 1, [0x52 + i as u8; 32])
                .unwrap()
        });
        let classifications = [0, 1].map(|i| RuntimeInventoryRecord {
            package_id: IDS[i],
            version: 1,
            artifact_digest: manifest_inputs[i].artifact().digest(),
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::Microvm,
            minimum: RuntimeIsolationPlacement::Microvm,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        });
        let mut generation = [0; 320];
        let mut catalog = [0; 512];
        let mut inventory = [0; 512];
        let generation_bytes = encode_system_generation(GEN, &versions, &mut generation).unwrap();
        let catalog_bytes =
            encode_interface_catalog(GEN, &requirements, &providers, &mut catalog).unwrap();
        let inventory_bytes =
            encode_runtime_inventory(GEN, &classifications, &mut inventory).unwrap();
        let private = std::vec![0x6du8; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = std::vec![0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let mut release = std::vec![0; MAX_SYSTEM_RELEASE_BYTES];
        let bytes = encode_system_release_with_runtime_inventory(
            &generation[..generation_bytes],
            &catalog[..catalog_bytes],
            &inventory[..inventory_bytes],
            &private,
            &mut release,
        )
        .unwrap();
        let release = &release[..bytes];
        let key = Sha3_512::digest(&public);
        fn recover<'out>(
            handoff: &BootHandoff,
            release: &[u8],
            release_key: &[u8; 64],
            signed: &[(std::vec::Vec<u8>, TrustRoot); 2],
            roots: [&TrustRoot; 2],
            outputs: [&'out mut [u8]; 2],
            image: HostedRecoveryDisk<'_>,
        ) -> Result<
            (
                RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>,
                [VerifiedExecutable<'out>; 2],
            ),
            HostedRecoveryProbeBuildError<()>,
        > {
            let mut output = std::vec![0; MAX_SYSTEM_RELEASE_BYTES];
            let [first, second] = outputs;
            let services = [
                HostedInstalledService {
                    signed_bytes: &signed[0].0,
                    root: roots[0],
                    output: first,
                },
                HostedInstalledService {
                    signed_bytes: &signed[1].0,
                    root: roots[1],
                    output: second,
                },
            ];
            let (owner, executables) = recover_hosted_component_owner(
                handoff,
                release,
                release_key,
                &mut output,
                Some((services, image)),
            )?;
            Ok((
                owner,
                executables.expect("storage fixture must return both executables"),
            ))
        }
        use std::io::{Read, Seek, SeekFrom, Write};
        struct ProbeBlockFile(std::fs::File);
        impl HostedRecoveryImageFile for ProbeBlockFile {
            fn regular_file_len(&self) -> core::result::Result<u64, ()> {
                let metadata = self.0.metadata().map_err(|_| ())?;
                metadata.is_file().then_some(metadata.len()).ok_or(())
            }

            fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> core::result::Result<(), ()> {
                self.0.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
                self.0.read_exact(bytes).map_err(|_| ())
            }

            fn write_at(&mut self, offset: u64, bytes: &[u8]) -> core::result::Result<(), ()> {
                self.0.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
                self.0.write_all(bytes).map_err(|_| ())
            }

            fn sync_all(&self) -> core::result::Result<(), ()> {
                self.0.sync_all().map_err(|_| ())
            }
        }
        // This guard only removes a file we created exclusively. Later
        // launches open the completed image read-only, without repopulating it.
        struct ProbeFile(std::path::PathBuf);
        impl Drop for ProbeFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let (mut image, guard) = (0..100)
            .find_map(|serial| {
                let path = std::env::temp_dir().join(std::format!(
                    "mrml-recovery-{}-{serial}.img",
                    std::process::id()
                ));
                match std::fs::File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(image) => Some((ProbeBlockFile(image), ProbeFile(path))),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("could not create the recovery image: {error}"),
                }
            })
            .expect("no unused disk image path");
        let reopen = || ProbeBlockFile(std::fs::File::open(&guard.0).unwrap());
        let roots = [&signed[0].1, &signed[1].1];
        let mut first_buffer = std::vec![0; signed[0].0.len()];
        let mut second_buffer = std::vec![0; signed[1].0.len()];
        let rejected = recover(
            &handoff,
            release,
            &key,
            &signed,
            [roots[0], roots[0]],
            [&mut first_buffer, &mut second_buffer],
            HostedRecoveryDisk::WriteFixture(&mut image),
        )
        .err()
        .expect("an incorrectly pinned service signer must not recover");
        assert_eq!(
            rejected,
            HostedRecoveryProbeBuildError::Probe(HostedRecoveryProbeError::ServiceExecutable)
        );

        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            false,
            true,
        )
        .unwrap();
        let bindings = [0, 1].map(|i| {
            TotalServicePreparationBinding::new(
                bounds,
                IsolationServiceIdentity::new(
                    DOMAINS[i],
                    ObjectId(0x301 + i as u64),
                    1,
                    1,
                    TotalMicrovmClass::MicrovmEligible,
                )
                .unwrap(),
            )
        });

        let kvm = KvmSystem::open().expect("this explicit live test requires usable KVM");
        let marker_for = |i| if i == 0 { 0x51u8 } else { 0x52u8 };
        let layout = KvmLaunchLayout::new(
            0x10_0000,
            32,
            0x20_0000,
            RECOVERY_SERVICE_IMAGE_BASE,
            0x50_0000,
            0xffff_8000_0050_0000,
            0x100_0000,
            0xffff_8000_0100_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap();
        // Real KVM guest, modeled device withdrawal. This does not map any
        // physical USB resource or stand in for an IOMMU implementation.
        #[derive(Debug)]
        struct ProbeDeviceLease {
            endpoint: ConfigurationMicrovmEndpoint,
            pending: bool,
        }
        impl ConfigurationMicrovmDeviceLease for ProbeDeviceLease {
            type Error = ();
            fn endpoint(&self) -> ConfigurationMicrovmEndpoint { self.endpoint }
            fn withdraw(&mut self) -> core::result::Result<(), Self::Error> {
                if core::mem::take(&mut self.pending) { Err(()) } else { Ok(()) }
            }
        }
        type TestLauncher = PreparedMicrovmConfigurationLauncher<
            AdmittedConfigurationGuestFactory<PreparedKvmGuest<16>>, ProbeDeviceLease,
        >;
        let launch = |spec: IsolationServiceSpec, executables: &[VerifiedExecutable<'_>; 2]| {
            let i = DOMAINS
                .iter()
                .position(|domain| *domain == spec.domain())
                .unwrap();
            let marker = marker_for(i);
            let mut guest = kvm
                .prepare_guest::<16>(0, &executables[i], handoff_bytes.as_slice(), layout)
                .unwrap();
            assert_eq!(
                VmBackend::run(&mut guest, 0).unwrap(),
                VmExit::Io {
                    port: 0xe9,
                    size: 1,
                    write: true,
                    value: u32::from(marker),
                }
            );
            let mut launcher =
                TestLauncher::with_device_leases(AdmittedConfigurationGuestFactory::new(spec, guest));
            let endpoint = launcher.launch_microvm(spec).unwrap();
            (launcher, endpoint)
        };
        let prepare = |owner: &mut RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>,
                       executables: &[VerifiedExecutable<'_>; 2]| {
            let prepared = owner.prepare_complete_service_set(&bindings).unwrap();
            let release = owner.installed_admission().release();
            let entries =
                [0, 1].map(|i| (prepared.spec(DOMAINS[i]).unwrap(), IDS[i], &executables[i]));
            assert!(release.matches_service_executable_set(entries));
            assert!(release.matches_service_executable_set(entries.into_iter().rev()));
            assert!(!release.matches_service_executable_set([entries[0]]));
            assert!(!release.matches_service_executable_set([entries[0], entries[0]]));
            assert!(!release.matches_service_executable_set([entries[0], entries[1], entries[1],]));
            for i in 0..2 {
                let (spec, _, _) = entries[i];
                assert!(!release.matches_service_executable_set([
                    entries[1 - i],
                    (spec, IDS[i], &executables[1 - i]),
                ]));
                assert!(!release.matches_service_executable_set([
                    entries[1 - i],
                    (spec, IDS[1 - i], &executables[1 - i]),
                ]));
            }
            prepared
        };
        let stale = core::cell::Cell::new(None);
        let (mut owner, executables) = recover(
            &handoff,
            release,
            &key,
            &signed,
            roots,
            [&mut first_buffer, &mut second_buffer],
            HostedRecoveryDisk::Existing(&mut reopen()),
        )
        .expect("recover the exact two-domain release and its service executables");
        assert_eq!(owner.admission().running().count(), 0);
        let prepared = prepare(&mut owner, &executables);
        let stops = core::cell::Cell::new(0);
        let mut stop =
            |domain, (mut launcher, endpoint): (TestLauncher, ConfigurationMicrovmEndpoint)| {
                assert_eq!(domain, DOMAINS[0]);
                assert_eq!(Some(endpoint), stale.get());
                stops.set(stops.get() + 1);
                if stops.get() == 1 {
                    assert!(launcher.active_guest(endpoint).is_ok());
                    assert_eq!(
                        launcher.revoke_microvm(&endpoint),
                        Err(PreparedMicrovmConfigurationError::DeviceLease(()))
                    );
                    assert!(matches!(
                        launcher.active_guest(endpoint),
                        Err(PreparedMicrovmConfigurationAccessError::Retiring)
                    ));
                    assert_eq!(launcher.active(), Some(endpoint));
                    return Err((launcher, endpoint));
                }
                launcher.revoke_microvm(&endpoint).unwrap();
                assert!(launcher.active_guest(endpoint).is_err());
                Ok(())
            };
        let mut failed = owner
            .start_prepared_services(
                prepared,
                |spec| {
                    if spec.domain() == DOMAINS[1] {
                        return Err("second service intentionally not ready");
                    }
                    let mut launched = launch(spec, &executables);
                    launched.0.attach_device_lease(ProbeDeviceLease {
                        endpoint: launched.1, pending: true,
                    }).unwrap();
                    stale.set(Some(launched.1));
                    Ok(launched)
                },
                &mut stop,
            )
            .err()
            .expect("partial recovered startup must not publish");
        assert_eq!(
            failed.error(),
            &CompleteTotalServiceStartError::Construction(
                CompleteTotalServiceConstructionError::Construction(
                    "second service intentionally not ready",
                ),
            )
        );
        assert_eq!(failed.pending_count(), 1);
        assert_eq!(stops.get(), 1);
        assert_eq!(failed.retry_teardown(&mut stop), 0);
        assert_eq!(failed.retry_teardown(&mut stop), 0);
        assert_eq!(stops.get(), 2);

        let (mut owner, executables) = recover(
            &handoff,
            release,
            &key,
            &signed,
            roots,
            [&mut first_buffer, &mut second_buffer],
            HostedRecoveryDisk::Existing(&mut reopen()),
        )
        .expect("recover the exact two-domain release and its service executables");
        let prepared = prepare(&mut owner, &executables);
        let (runtime, mut routed) = owner
            .start_prepared_services(
                prepared,
                |spec| Ok::<_, ()>(launch(spec, &executables)),
                |_, mut started: (TestLauncher, ConfigurationMicrovmEndpoint)| {
                    started.0.revoke_microvm(&started.1).unwrap();
                    Ok(())
                },
            )
            .ok()
            .expect("both KVM guests are ready");
        let proof = runtime.proof();
        assert_eq!(proof.classified_domains(), 2);
        assert_eq!(proof.running_in_microvm(), 2);
        assert_eq!(
            runtime.admission().total_microvm_report().native_fallback,
            0
        );

        let (mut first, live) = routed.take(DOMAINS[0]).unwrap().into_endpoint();
        let (mut second, other) = routed.take(DOMAINS[1]).unwrap().into_endpoint();
        // Both guests use the same guest-physical stack address, but the
        // hosted adapter observes independent backing before either retires.
        const STACK_SAMPLE: u64 = 0x100_0040;
        let mut sample = [0xff; 4];
        VmBackend::write_guest(first.active_guest_mut(live).unwrap(), STACK_SAMPLE, b"MRML")
            .unwrap();
        VmBackend::read_guest(first.active_guest(live).unwrap(), STACK_SAMPLE, &mut sample)
            .unwrap();
        assert_eq!(&sample, b"MRML");
        VmBackend::read_guest(
            second.active_guest(other).unwrap(),
            STACK_SAMPLE,
            &mut sample,
        )
        .unwrap();
        assert_eq!(sample, [0; 4]);

        let stale = stale.get().unwrap();
        assert_eq!(stale.spec(), live.spec());
        assert!(matches!(
            first.active_guest_mut(stale),
            Err(PreparedMicrovmConfigurationAccessError::WrongEndpoint)
        ));
        assert_eq!(
            first.revoke_microvm(&stale),
            Err(PreparedMicrovmConfigurationError::WrongEndpoint)
        );
        assert_eq!(
            VmBackend::run(first.active_guest_mut(live).unwrap(), 0).unwrap(),
            VmExit::Io {
                port: 0xe9,
                size: 1,
                write: true,
                value: 0x53,
            }
        );
        assert_eq!(runtime.withdraw_for_shutdown().unwrap(), 2);
        first.revoke_microvm(&live).unwrap();
        // The other real VM continues independently after retirement.
        assert_eq!(
            VmBackend::run(second.active_guest_mut(other).unwrap(), 0).unwrap(),
            VmExit::Io {
                port: 0xe9,
                size: 1,
                write: true,
                value: 0x54,
            }
        );
        second.revoke_microvm(&other).unwrap();
        assert!(second.active_guest(other).is_err());
    }

    #[test]
    fn application_projection_namespaces_are_admissible() {
        assert!(MemoryPoolTable::<1, 1>::new(APPLICATION_MEMORY_NAMESPACE).is_ok());
        assert!(CpuBudgetTable::<1, 1>::new(APPLICATION_CPU_NAMESPACE).is_ok());
    }

    #[test]
    fn handoff_binds_verified_version_entropy_and_measurement() {
        let entropy = [0x35; 32];
        let measurement = [0xa7; 64];
        let encoded = boot_handoff(19, entropy, measurement, 1, None, None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.evidence().image_version(), 19);
        assert_eq!(decoded.evidence().entropy(), &entropy);
        assert_eq!(decoded.evidence().image_measurement(), &measurement);
        assert!(decoded.evidence().secure_boot());
        assert!(!decoded.evidence().measured_boot());
        assert!(!decoded.evidence().rollback_protected());
    }

    #[test]
    fn application_handoff_is_typed_and_does_not_invent_smp_state() {
        let application = ApplicationLaunch::new(
            PhysAddr::new(APPLICATION_ARTIFACT_PHYSICAL).unwrap(),
            100_000,
            PhysAddr::new(APPLICATION_IMAGE_PHYSICAL).unwrap(),
            5,
            0x1_4000_0000,
            0x1_4000_0080,
            PhysAddr::new(APPLICATION_STACK_PHYSICAL).unwrap(),
            8,
            APPLICATION_STACK_TOP,
            PhysAddr::new(APPLICATION_TABLE_PHYSICAL).unwrap(),
            32,
            7,
            [0x71; 64],
        )
        .unwrap();
        let encoded = application_boot_handoff(19, [0x35; 32], [0xa7; 64], application).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.application(), Some(application));
        assert_eq!(decoded.service(), None);
        assert_eq!(decoded.ap_trampoline(), None);
        assert_eq!(decoded.madt(encoded.as_slice()), None);
    }

    #[test]
    fn block_handoff_binds_two_disjoint_payload_pages() {
        let encoded = boot_handoff(20, [0x36; 32], [0xa8; 64], 2, None, None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.framebuffer().base().get(), FRAMEBUFFER);
        assert_eq!(decoded.framebuffer().byte_length(), 8192);
        assert!(boot_handoff(20, [0x36; 32], [0xa8; 64], 3, None, None, false).is_err());
    }

    #[test]
    fn recovery_handoff_binds_fixed_probe_metadata() {
        let recovery = RecoveryStateMetadata::new(8, 2, Some([0x51; 16]), 1).unwrap();
        let encoded =
            boot_handoff(21, [0x38; 32], [0xaa; 64], 1, Some(recovery), None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.recovery_state(), Some(recovery));
        let installed = decoded.installed_recovery().unwrap();
        assert_eq!(installed.source(), InstalledRecoverySource::Hosted);
        assert_eq!(installed.volume(), [0x51; 16]);
        assert_eq!(installed.root_generation(), 1);
    }

    #[test]
    fn total_override_is_consumed_from_the_decoded_recovery_handoff() {
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let encoded = boot_handoff(
            21,
            [0x38; 32],
            [0xaa; 64],
            1,
            Some(recovery),
            Some(BootIsolationOverride::TotalMicrovmOnce),
            true,
        )
        .unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.recovery_state(), Some(recovery));
        assert_eq!(
            decoded.isolation_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
        assert!(decoded.evidence().coherent_release());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn total_policy_rejects_a_decoded_handoff_without_the_override() {
        let recovered_component =
            configured_isolation_service(ObjectId(1), ObjectId(2), 1, 1).unwrap();
        assert!(recovered_component.effective.is_none());
        let recovery = RecoveryStateMetadata::new(8, 1, None, 0).unwrap();
        let encoded =
            boot_handoff(21, [0x38; 32], [0xaa; 64], 1, Some(recovery), None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert!(configured_total_service_policy(ObjectId(1), ObjectId(2), 1, 1, &decoded).is_err());
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
    fn launch_mode_is_explicit_and_fail_closed() {
        assert_eq!(LaunchMode::parse("boot").unwrap(), LaunchMode::Boot);
        assert_eq!(
            LaunchMode::parse("application-probe").unwrap(),
            LaunchMode::ApplicationProbe
        );
        assert_eq!(
            LaunchMode::parse("gui-application-probe").unwrap(),
            LaunchMode::GuiApplicationProbe
        );
        assert_eq!(
            LaunchMode::GuiApplicationProbe.application_package_id(),
            Some("org.mrml.app.gui-probe")
        );
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
            LaunchMode::parse("deadline-receive-probe").unwrap(),
            LaunchMode::DeadlineReceiveProbe
        );
        assert_eq!(
            LaunchMode::parse("deadline-receive-message-probe").unwrap(),
            LaunchMode::DeadlineReceiveMessageProbe
        );
        assert_eq!(
            LaunchMode::parse("deadline-receive-cancel-probe").unwrap(),
            LaunchMode::DeadlineReceiveCancelProbe
        );
        assert_eq!(
            LaunchMode::parse("deadline-receive-cancel-denied-probe").unwrap(),
            LaunchMode::DeadlineReceiveCancelDeniedProbe
        );
        assert_eq!(
            LaunchMode::parse("deadline-receive-cancel-replay-probe").unwrap(),
            LaunchMode::DeadlineReceiveCancelReplayProbe
        );
        assert_eq!(
            LaunchMode::parse("invalid-return-probe").unwrap(),
            LaunchMode::InvalidReturnProbe
        );
        assert_eq!(
            LaunchMode::parse("buffer-drift-probe").unwrap(),
            LaunchMode::BufferDriftProbe
        );
        assert_eq!(
            LaunchMode::parse("component-service-probe").unwrap(),
            LaunchMode::ComponentServiceProbe
        );
        assert_eq!(
            LaunchMode::parse("component-service-smp-probe").unwrap(),
            LaunchMode::ComponentServiceSmpProbe
        );
        assert_eq!(
            LaunchMode::parse("component-release-inputs").unwrap(),
            LaunchMode::ComponentReleaseInputs
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
            LaunchMode::parse("pci-configuration-probe").unwrap(),
            LaunchMode::PciConfigurationProbe
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
    fn invalid_return_stage_validation_is_exact_and_order_bounded() {
        let stage = |value| VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value,
        };
        assert!(require_invalid_return_stage(stage(0x26), 0x26).is_ok());
        assert!(require_invalid_return_stage(stage(0x27), 0x27).is_ok());
        assert!(require_invalid_return_stage(stage(0x27), 0x26).is_err());
        assert!(require_invalid_return_stage(stage(0x26), 0x27).is_err());
        assert!(require_invalid_return_stage(stage(0x26), 0x25).is_err());
        assert!(require_invalid_return_stage(VmExit::Halted, 0x26).is_err());
    }

    #[test]
    fn buffer_drift_stage_validation_is_exact_and_order_bounded() {
        let stage = |value| VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value,
        };
        assert!(require_buffer_drift_stage(stage(0x28), 0x28).is_ok());
        assert!(require_buffer_drift_stage(stage(0x29), 0x29).is_ok());
        assert!(require_buffer_drift_stage(stage(0x29), 0x28).is_err());
        assert!(require_buffer_drift_stage(stage(0x28), 0x29).is_err());
        assert!(require_buffer_drift_stage(stage(0x28), 0x27).is_err());
        assert!(require_buffer_drift_stage(VmExit::Halted, 0x28).is_err());
    }

    #[test]
    fn deadline_receive_proof_is_exact_and_mode_bound() {
        let proof = VmExit::Io {
            port: SERVICE_PROBE_PORT,
            size: 4,
            write: true,
            value: 0x2a,
        };
        assert!(require_deadline_receive_proof(proof, 0x2a).is_ok());
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x2b,
                },
                0x2b,
            )
            .is_ok()
        );
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x2c,
                },
                0x2c,
            )
            .is_ok()
        );
        assert!(require_deadline_receive_proof(proof, 0x2b).is_err());
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x2b,
                },
                0x2a,
            )
            .is_err()
        );
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x29,
                },
                0x2a,
            )
            .is_err()
        );
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_CALL_PORT,
                    size: 4,
                    write: true,
                    value: 0x2a,
                },
                0x2a,
            )
            .is_err()
        );
        assert!(require_deadline_receive_proof(VmExit::Halted, 0x2a).is_err());
        assert!(require_deadline_receive_proof(proof, 0x2c).is_err());
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x2d,
                },
                0x2d,
            )
            .is_ok()
        );
        assert!(require_deadline_receive_proof(proof, 0x2d).is_err());
        assert!(
            require_deadline_receive_proof(
                VmExit::Io {
                    port: SERVICE_PROBE_PORT,
                    size: 4,
                    write: true,
                    value: 0x2e,
                },
                0x2e,
            )
            .is_ok()
        );
        assert!(require_deadline_receive_proof(proof, 0x2e).is_err());
        assert!(require_deadline_receive_proof(proof, 0x2f).is_err());
    }

    #[test]
    fn smp_handoff_binds_two_cpus_and_launch_resources() {
        let encoded = smp_boot_handoff(7, [0x51; 32], [0xa3; 64], None, None, false).unwrap();
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

    #[test]
    fn smp_total_handoff_retains_installed_recovery_identity() {
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let encoded = smp_boot_handoff(
            7,
            [0x51; 32],
            [0xa3; 64],
            Some(recovery),
            Some(BootIsolationOverride::TotalMicrovmOnce),
            true,
        )
        .unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        let installed = decoded.installed_recovery().unwrap();
        assert_eq!(installed.source(), InstalledRecoverySource::Hosted);
        assert_eq!(installed.volume(), [0x51; 16]);
        assert_eq!(installed.root_generation(), 14);
        assert_eq!(decoded.recovery_state(), Some(recovery));
        assert_eq!(
            decoded.isolation_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
    }
}
