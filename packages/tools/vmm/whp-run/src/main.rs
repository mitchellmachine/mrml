#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

#[cfg(target_os = "windows")]
use mrml_config::{
    AdmittedConfigurationGuestFactory, ConfigTransaction, ConfigurationMicrovmEndpoint,
    ConfigurationService, EffectiveBootIsolationPolicy, IsolationPolicyApplicationPlan,
    IsolationPolicySetting, IsolationServiceBounds, IsolationServiceIdentity,
    MicrovmConfigurationServiceLauncher, OwnerIsolationSelection,
    PreparedMicrovmConfigurationLauncher, PreparedTotalServiceSet,
    RecoveredDeploymentTotalControlPlane,
    RecoveredDeploymentTotalRuntime, SettingId, TotalServicePreparationBinding,
    hosted_recovery_probe::{HOSTED_TOTAL_COMPONENT_DOMAIN, recover_total_control_plane},
};
#[cfg(target_os = "windows")]
use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};
#[cfg(target_os = "windows")]
use mrml_deployment::{
    DeploymentService, GenerationCandidate, encode_deployment_release_checkpoint,
};
use mrml_error::{Result, anyhow};
#[cfg(target_os = "windows")]
use mrml_kernel::arch::x86_64::{Mapping, PRIVILEGE_STACK_ARENA_PAGES, PagePermissions, VirtAddr};
#[cfg(all(target_os = "windows", feature = "cuda"))]
use mrml_kernel::verify_gpu_kernel_bundle;
#[cfg(target_os = "windows")]
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
    run_virtual_block_transaction_once,
};
#[cfg(any(test, target_os = "windows"))]
use mrml_kernel::{
    BootHandoff, FramebufferInfo, InstalledRecoveryBootIdentity, InstalledRecoverySource,
    MemoryKind, MemoryRegion, PhysAddr, PixelFormat, RecoveryStateMetadata, encode_handoff,
    encode_handoff_with_application, encode_handoff_with_recovery,
    encode_handoff_with_recovery_and_isolation,
    encode_handoff_with_recovery_isolation_and_installed, encode_handoff_with_smp,
    encode_handoff_with_smp_recovery_isolation_and_installed,
};
#[cfg(target_os = "windows")]
use mrml_package_format::{
    ComponentServicePlacement, InterfaceCatalogView, MAX_BOOT_PACKAGE_BYTES,
    MAX_BOOT_RELEASE_BYTES, MAX_SYSTEM_RELEASE_BYTES, ManifestInterfaceDeclaration,
    RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
    SystemGenerationDigestRecord, SystemGenerationView, admit_kernel_payload,
    decode_canonical_manifest_interface, encode_interface_catalog, encode_runtime_inventory,
    encode_system_generation, resolve_activated_interface_catalog,
};
#[cfg(target_os = "windows")]
use mrml_runtime::{Instant, Vector, mrml_println as println};
#[cfg(target_os = "windows")]
use mrml_whp::{PreparedWhpGuest, WhpLaunchLayout, WhpSystem};

#[cfg(target_os = "windows")]
type WhpConfigurationLauncher<'system> = PreparedMicrovmConfigurationLauncher<
    AdmittedConfigurationGuestFactory<PreparedWhpGuest<'system>>,
>;

#[cfg(target_os = "windows")]
type WhpApplicationLauncher<'system> =
    PreparedMicrovmApplicationBackend<AdmittedApplicationGuestFactory<PreparedWhpGuest<'system>>>;

#[cfg(target_os = "windows")]
struct ConfiguredTotalServicePolicy {
    effective: Option<EffectiveBootIsolationPolicy>,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
}

#[cfg(target_os = "windows")]
enum WhpTotalAdmission {
    Standalone(IsolationAdmissionTable<2>),
    Recovered(RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>),
}

#[cfg(target_os = "windows")]
impl core::ops::Deref for WhpTotalAdmission {
    type Target = IsolationAdmissionTable<2>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Standalone(admission) => admission,
            Self::Recovered(total) => total.admission(),
        }
    }
}

#[cfg(target_os = "windows")]
impl core::ops::DerefMut for WhpTotalAdmission {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Standalone(admission) => admission,
            Self::Recovered(total) => total.admission_mut(),
        }
    }
}

#[cfg(target_os = "windows")]
const APPLICATION_MEMORY_NAMESPACE: u16 = 0x3a50;
#[cfg(target_os = "windows")]
const APPLICATION_CPU_NAMESPACE: u16 = 0x3a51;

#[cfg(target_os = "windows")]
struct WhpApplicationProjection {
    prepared: Option<MicrovmProjectionPlan<1>>,
    active: Option<ActiveMicrovmProjectionPlan<1>>,
    memory: MemoryPoolTable<1, 1>,
    cpu: CpuBudgetTable<1, 1>,
    capabilities: CapabilitySpace<4>,
    ram_capability: Capability,
    cpu_capability: Capability,
}

#[cfg(target_os = "windows")]
impl WhpApplicationProjection {
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
const COMPONENT_MEMORY_OBJECTS: usize = 4 + 2 * (MAX_COMPONENT_IMAGE_REGIONS + 1);
#[cfg(target_os = "windows")]
const COMPONENT_MEMORY_MAPPINGS: usize = 2 + 2 * MAX_COMPONENT_IMAGE_REGIONS;
#[cfg(target_os = "windows")]
const COMPONENT_MEMORY_CAPABILITIES: usize = 7 + 2 * (MAX_COMPONENT_IMAGE_REGIONS + 1);

#[cfg(target_os = "windows")]
type ComponentCpuAuthority = (
    CpuBudgetTable<1, 1>,
    CapabilitySpace<1>,
    CpuBudgetId,
    Capability,
    VcpuReservationId,
    [u64; 2],
);

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn run_component_smp<B>(
    cpu: &mut Option<ComponentCpuAuthority>,
    backend: &mut B,
) -> Result<([VmExit; 2], [u64; 2])>
where
    B: ScheduledSmpVmBackend,
    B::Error: core::fmt::Debug,
{
    let (budgets, capabilities, budget, capability, reservation, next_start) = cpu
        .as_mut()
        .ok_or_else(|| anyhow!("missing component SMP runtime authority"))?;
    let usage = budgets
        .usage(*budget, *capability, capabilities)
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

#[cfg(target_os = "windows")]
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
            Err(anyhow!("scheduled WHP SMP execution failed: {:?}", error)),
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
        VmDeadlineOutcome::Expired => return Err(anyhow!("WHP bootstrap vCPU deadline expired")),
    };
    let application_exit = match outcomes[1].outcome() {
        VmDeadlineOutcome::Exit(exit) => exit,
        VmDeadlineOutcome::Expired => return Err(anyhow!("WHP application vCPU deadline expired")),
    };
    Ok(([bootstrap_exit, application_exit], ends))
}

#[cfg(target_os = "windows")]
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
        SettingId::new(1).map_err(|error| anyhow!("WHP component setting failed: {:?}", error))?,
        component_object,
        IsolationPlacement::NativeService,
    )
    .map_err(|error| anyhow!("WHP component policy failed: {:?}", error))?;
    let system = IsolationPolicySetting::system(
        SettingId::new(2).map_err(|error| anyhow!("WHP system setting failed: {:?}", error))?,
        system_object,
    )
    .map_err(|error| anyhow!("WHP system policy failed: {:?}", error))?;
    let mut configuration = ConfigurationService::<2, 4>::new(
        root_object,
        &[
            component
                .schema()
                .map_err(|error| anyhow!("WHP component schema failed: {:?}", error))?,
            system
                .schema()
                .map_err(|error| anyhow!("WHP system schema failed: {:?}", error))?,
        ],
    )
    .map_err(|error| anyhow!("WHP policy configuration failed: {:?}", error))?;
    let mut capabilities = CapabilitySpace::<5>::new();
    let root = capabilities
        .insert(root_object, Rights::CONTROL)
        .map_err(|error| anyhow!("WHP policy root capability failed: {:?}", error))?;
    let component_write = capabilities
        .insert(component_object, Rights::WRITE)
        .map_err(|error| anyhow!("WHP component write capability failed: {:?}", error))?;
    let component_read = capabilities
        .insert(component_object, Rights::READ)
        .map_err(|error| anyhow!("WHP component read capability failed: {:?}", error))?;
    let system_write = capabilities
        .insert(system_object, Rights::WRITE)
        .map_err(|error| anyhow!("WHP system write capability failed: {:?}", error))?;
    let system_read = capabilities
        .insert(system_object, Rights::READ)
        .map_err(|error| anyhow!("WHP system read capability failed: {:?}", error))?;
    let mut transaction = ConfigTransaction::<2>::new(0);
    component
        .stage(
            &mut transaction,
            component_write,
            OwnerIsolationSelection::Native,
        )
        .map_err(|error| anyhow!("WHP component policy staging failed: {:?}", error))?;
    system
        .stage(
            &mut transaction,
            system_write,
            OwnerIsolationSelection::Balanced,
        )
        .map_err(|error| anyhow!("WHP system policy staging failed: {:?}", error))?;
    configuration
        .commit(&capabilities, root, &transaction)
        .map_err(|error| anyhow!("WHP policy commit failed: {:?}", error))?;
    let plan = IsolationPolicyApplicationPlan::load(
        &configuration,
        &capabilities,
        system,
        system_read,
        component,
        component_read,
    )
    .map_err(|error| anyhow!("WHP policy load failed: {:?}", error))?;
    let recovery = handoff
        .recovery_state()
        .ok_or_else(|| anyhow!("WHP Total policy requires decoded recovery metadata"))?;
    let effective = plan
        .apply(&configuration, &capabilities)
        .map_err(|error| anyhow!("WHP configured isolation application failed: {:?}", error))?
        .compose_boot_override(handoff.isolation_override());
    if effective.mode() != IsolationMode::TotalMicrovm
        || effective.boot_override() != Some(BootIsolationOverride::TotalMicrovmOnce)
    {
        return Err(anyhow!(
            "WHP canonical boot handoff did not request strict Total MicroVM isolation"
        ));
    }
    println!(
        "isolation-boot-policy|status=PASS|backend=whp|configured=balanced|component=native-service|handoff=decoded|accepted_epoch={}|override=total-microvm-once|effective=total-microvm|policy_generation={}",
        recovery.accepted_epoch(),
        effective.policy_generation()
    );
    Ok(ConfiguredTotalServicePolicy {
        effective: Some(effective),
        bounds: service.bounds,
        identity: service.identity,
    })
}

#[cfg(target_os = "windows")]
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
    .map_err(|error| anyhow!("WHP package isolation bounds failed: {:?}", error))?;
    let identity = IsolationServiceIdentity::new(
        domain,
        interface,
        interface_generation,
        provider_generation,
        TotalMicrovmClass::MicrovmEligible,
    )
    .map_err(|error| anyhow!("WHP service identity failed: {:?}", error))?;
    Ok(ConfiguredTotalServicePolicy {
        effective: None,
        bounds,
        identity,
    })
}

#[cfg(target_os = "windows")]
enum WhpGuestOwner<'system> {
    Direct(PreparedWhpGuest<'system>),
    Application {
        launcher: WhpApplicationLauncher<'system>,
        endpoint: ApplicationMicrovmEndpoint,
        projection: WhpApplicationProjection,
    },
    Configuration {
        launcher: WhpConfigurationLauncher<'system>,
        endpoint: ConfigurationMicrovmEndpoint,
    },
}

#[cfg(target_os = "windows")]
impl<'system> WhpGuestOwner<'system> {
    fn guest(&self) -> &PreparedWhpGuest<'system> {
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

    fn guest_mut(&mut self) -> &mut PreparedWhpGuest<'system> {
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

    fn into_direct(self) -> Result<PreparedWhpGuest<'system>> {
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
                    .map_err(|error| anyhow!("WHP application teardown failed: {:?}", error))?;
                projection.finish()?;
            }
            Self::Configuration { launcher, endpoint } => launcher
                .revoke_microvm(endpoint)
                .map_err(|error| anyhow!("WHP configuration teardown failed: {:?}", error))?,
            Self::Direct(_) => {}
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl<'system> core::ops::Deref for WhpGuestOwner<'system> {
    type Target = PreparedWhpGuest<'system>;

    fn deref(&self) -> &Self::Target {
        self.guest()
    }
}

#[cfg(target_os = "windows")]
impl core::ops::DerefMut for WhpGuestOwner<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guest_mut()
    }
}

#[cfg(target_os = "windows")]
impl VmBackend for WhpGuestOwner<'_> {
    type Error = <PreparedWhpGuest<'static> as VmBackend>::Error;

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

#[cfg(target_os = "windows")]
impl DeadlineVmBackend for WhpGuestOwner<'_> {
    fn run_with_deadline(
        &mut self,
        vcpu: u32,
        maximum_micros: u32,
    ) -> core::result::Result<VmDeadlineOutcome, Self::Error> {
        DeadlineVmBackend::run_with_deadline(self.guest_mut(), vcpu, maximum_micros)
    }
}

#[cfg(target_os = "windows")]
impl AffinityDeadlineVmBackend for WhpGuestOwner<'_> {
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

#[cfg(target_os = "windows")]
impl ScheduledDeadlineVmBackend for WhpGuestOwner<'_> {
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

#[cfg(target_os = "windows")]
impl ScheduledSmpVmBackend for WhpGuestOwner<'_> {
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

#[cfg(target_os = "windows")]
const MAX_KERNEL_BUNDLE: usize = SIGNED_ARTIFACT_OVERHEAD_BYTES + 16 * 1024 * 1024;
#[cfg(any(test, target_os = "windows"))]
const FRAMEBUFFER: u64 = 0x00a0_0000;
#[cfg(target_os = "windows")]
const APPLICATION_PROBE_PORT: u16 = 0x4d66;
#[cfg(target_os = "windows")]
const APPLICATION_ARTIFACT_PHYSICAL: u64 = 0x00a0_1000;
#[cfg(target_os = "windows")]
const APPLICATION_IMAGE_PHYSICAL: u64 = 0x00a2_0000;
#[cfg(target_os = "windows")]
const APPLICATION_STACK_PHYSICAL: u64 = 0x00a2_8000;
#[cfg(target_os = "windows")]
const APPLICATION_STACK_TOP: u64 = 0x0090_0000;
#[cfg(target_os = "windows")]
const APPLICATION_TABLE_PHYSICAL: u64 = 0x00a3_0000;
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
fn accounted_pages(bytes: u64) -> Result<u64> {
    bytes
        .checked_add(mrml_kernel::PAGE_SIZE - 1)
        .map(|rounded| rounded / mrml_kernel::PAGE_SIZE)
        .filter(|pages| *pages != 0)
        .ok_or_else(|| anyhow!("invalid guest RAM extent"))
}
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
const PCI_WITHDRAW_PROOF_PORT: u16 = 0x4d67;
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
struct NativePciMmioWindow {
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
    expected_mapped_window: Option<VirtualPciMmioWindow>,
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

#[cfg(target_os = "windows")]
unsafe impl VirtualBlockPciGuestWindowBackend<PreparedWhpGuest<'_>> for NativePciMmioWindow {
    fn map_block_window(
        &mut self,
        guest: &mut PreparedWhpGuest<'_>,
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
        guest: &mut PreparedWhpGuest<'_>,
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
    let mut window_backend = NativePciMmioWindow { mapped: false };
    if guest
        .install_trapped_mmio(PCI_TEST_MMIO_BASE + mrml_kernel::PAGE_SIZE)
        .is_ok()
    {
        return Err(anyhow!("WHP PCI MMIO install accepted a wrong leaf"));
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
    .map_err(|error| anyhow!("WHP PCI memory enable failed: {:?}", error))?;
    if command
        != VirtualPciIoOutcome::Write(mrml_kernel::VirtualPciWriteOutcome::Command(
            mrml_kernel::PCI_COMMAND_MEMORY_SPACE | mrml_kernel::PCI_COMMAND_INTERRUPT_DISABLE,
        ))
        || !window_backend.mapped
    {
        return Err(anyhow!("WHP PCI memory enable mismatch: {:?}", command));
    }
    if guest.install_trapped_mmio(PCI_TEST_MMIO_BASE).is_ok() {
        return Err(anyhow!("WHP PCI MMIO install accepted replay"));
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
        .prepare_kernel_block_dynamic_mmio_guest(
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
        return Err(anyhow!("WHP PCI MMIO withdrawal accepted a wrong leaf"));
    }
    let disable = {
        let mut mapper =
            VirtualBlockPciGuestMemoryMapper::new(&mut attachment, &device, &mut window_backend);
        router
            .write_with_backend_mapper(location, 4, 2, 0, &mut guest, &mut mapper)
            .map_err(|_| anyhow!("failed to disable retired WHP PCI MMIO window"))?
    };
    if disable != mrml_kernel::VirtualPciWriteOutcome::Command(0)
        || window_backend.mapped
        || attachment.mapped_window().is_some()
    {
        return Err(anyhow!("WHP PCI MMIO withdrawal cleanup was incomplete"));
    }
    println!("WHP_PCI_WITHDRAW coherent=1");
    if guest.withdraw_trapped_mmio(PCI_TEST_MMIO_BASE).is_ok() {
        return Err(anyhow!("WHP PCI MMIO withdrawal accepted replay"));
    }
    let continued = VmBackend::run(&mut guest, 0)
        .map_err(|error| anyhow!("WHP post-withdrawal execution failed: {:?}", error))?;
    if continued
        != (VmExit::Io {
            port: PCI_WITHDRAW_PROOF_PORT,
            size: 4,
            write: true,
            value: PCI_BLOCK_PROBE_OPERATIONS,
        })
    {
        return Err(anyhow!(
            "WHP post-withdrawal proof mismatch: {:?}",
            continued
        ));
    }
    println!("WHP_PCI_WITHDRAW continued=1");
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
    device
        .negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH)
        .and_then(|_| device.activate(layout, 48))
        .map_err(|_| anyhow!("failed to activate successor PCI block device"))?;
    if device.complete(stale_ticket, VirtualBlockCompletionStatus::Ok, 4096)
        != Err(VirtualBlockError::StaleTicket)
        || device.admit(&encoded_request) != Err(VirtualBlockError::StaleGeneration)
    {
        return Err(anyhow!(
            "destroyed WHP PCI cleanup retained stale block ownership"
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
            "WHP PCI successor generation was not independently admissible"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
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
            println!("boot-artifacts|status=FAIL|backend=whp|detail={error:?}");
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
            "boot-artifacts|status=PASS|backend=whp|raw_kernel_bytes={}",
            payload.len()
        );
        return Ok(());
    }
    let application_package_id = if arguments.len() == 9 {
        match arguments[5].as_str() {
            "application-probe" => Some("org.mrml.app.isolation-probe"),
            "gui-application-probe" => Some("org.mrml.app.gui-probe"),
            _ => None,
        }
    } else {
        None
    };
    let application_mode = application_package_id.is_some();
    let deadline_receive_message_mode =
        arguments.len() == 9 && arguments[5] == "deadline-receive-message-probe";
    let deadline_receive_cancel_mode =
        arguments.len() == 9 && arguments[5] == "deadline-receive-cancel-probe";
    let deadline_receive_cancel_denied_mode =
        arguments.len() == 9 && arguments[5] == "deadline-receive-cancel-denied-probe";
    let deadline_receive_cancel_replay_mode =
        arguments.len() == 9 && arguments[5] == "deadline-receive-cancel-replay-probe";
    let deadline_receive_mode = arguments.len() == 9
        && matches!(
            arguments[5].as_str(),
            "deadline-receive-probe"
                | "deadline-receive-message-probe"
                | "deadline-receive-cancel-probe"
                | "deadline-receive-cancel-denied-probe"
                | "deadline-receive-cancel-replay-probe"
        );
    let service_mode = arguments.len() == 9
        && matches!(
            arguments[5].as_str(),
            "service-probe"
                | "deadline-receive-probe"
                | "deadline-receive-message-probe"
                | "deadline-receive-cancel-probe"
                | "deadline-receive-cancel-denied-probe"
                | "deadline-receive-cancel-replay-probe"
        );
    let component_release_input_mode =
        arguments.len() == 15 && arguments[5] == "component-release-inputs";
    let component_smp_mode = arguments.len() == 14 && arguments[5] == "component-service-smp-probe";
    let component_service_mode = component_release_input_mode
        || component_smp_mode
        || (arguments.len() == 14 && arguments[5] == "component-service-probe");
    let total_service_mode = service_mode || component_service_mode;
    let block_service_mode = arguments.len() == 9 && arguments[5] == "block-service-probe";
    let service_restart_request_mode =
        arguments.len() == 9 && arguments[5] == "service-restart-request-probe";
    let fat32_ready_mode = arguments.len() == 9 && arguments[5] == "fat32-ready-probe";
    let service_preemption_mode =
        arguments.len() == 9 && arguments[5] == "service-preemption-probe";
    let smp_service_migration_mode =
        arguments.len() == 9 && arguments[5] == "smp-service-migration-probe";
    let service_artifact_mode = service_mode
        || component_service_mode
        || block_service_mode
        || service_restart_request_mode
        || fat32_ready_mode
        || service_preemption_mode
        || smp_service_migration_mode;
    let boot_mode = matches!(arguments.len(), 6 | 8) && arguments[5] == "boot";
    let release_boot_mode = arguments.len() == 8 && boot_mode;
    let timer_mode = arguments.len() == 6 && arguments[5] == "timer-probe";
    let block_guest_driver_mode =
        arguments.len() == 6 && arguments[5] == "block-guest-driver-probe";
    let pci_configuration_mode = arguments.len() == 6 && arguments[5] == "pci-configuration-probe";
    let preemption_mode = arguments.len() == 6 && arguments[5] == "preemption-probe";
    let vmx_root_mode = arguments.len() == 6 && arguments[5] == "vmx-root-probe";
    let smp_mode = arguments.len() == 6 && arguments[5] == "smp-probe";
    let smp_scheduler_mode = arguments.len() == 6 && arguments[5] == "smp-scheduler-probe";
    let smp_ipi_mode = arguments.len() == 6 && arguments[5] == "smp-ipi-probe";
    let smp_periodic_balance_mode =
        arguments.len() == 6 && arguments[5] == "smp-periodic-balance-probe";
    if arguments.len() == 8 && !release_boot_mode {
        return Err(anyhow!(
            "SystemRelease binding is accepted only for boot mode"
        ));
    }
    if arguments.len() != 8
        && !service_artifact_mode
        && !application_mode
        && !boot_mode
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
            "usage: mrml-whp-run KERNEL.mrp PACKAGE.public KERNEL.public MINIMUM_VERSION MODE [SYSTEM.mrs SYSTEM_RELEASE.public | ARTIFACT.signed ARTIFACT.public ARTIFACT_MINIMUM_VERSION | CONSUMER.signed CONSUMER.public CONSUMER_MINIMUM PROVIDER.signed PROVIDER.public PROVIDER_MINIMUM GENERAL_SYSTEM.mrs GENERAL_SYSTEM.public]\n       MODE component-release-inputs writes GENERATION.bin CATALOG.bin RUNTIME.bin in the final three positions after verifying the same component inputs\n       mrml-whp-run --verify-boot-artifacts KERNEL.mrp PACKAGE.public MINIMUM_VERSION SYSTEM.mrs SYSTEM_RELEASE.public\n       mrml-whp-run --export-cuda-bundle OUTPUT.ptx"
        ));
    }
    let minimum_version = arguments[4]
        .parse::<u64>()
        .ok()
        .filter(|version| *version != 0)
        .ok_or_else(|| anyhow!("minimum version must be a nonzero integer"))?;
    let release_binding = release_boot_mode.then(|| (arguments[6].as_str(), arguments[7].as_str()));
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
    let service_bundle = if service_artifact_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[6],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + mrml_kernel::MAX_SERVICE_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let service_public = if service_artifact_mode {
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
    let application_bundle = if application_mode {
        Some(mrml_runtime::read_file_bounded(
            &arguments[6],
            SIGNED_ARTIFACT_OVERHEAD_BYTES + MAX_APPLICATION_IMAGE_BYTES as usize,
        )?)
    } else {
        None
    };
    let application_public = if application_mode {
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
    let cuda_bundle = if application_mode
        || service_artifact_mode
        || boot_mode
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
            &arguments[5],
            &arguments[6],
            &arguments[7],
        )?)
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
    let hosted_smp = smp_mode
        || smp_scheduler_mode
        || smp_ipi_mode
        || smp_service_migration_mode
        || smp_periodic_balance_mode;
    let total_recovery = total_service_mode.then(|| {
        RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14)
            .expect("fixed Total recovery metadata")
    });
    let total_override = total_service_mode.then_some(BootIsolationOverride::TotalMicrovmOnce);
    let handoff = if let Some(application) = application_launch {
        application_boot_handoff(
            executable.artifact().version(),
            entropy,
            *executable.artifact().digest(),
            application,
        )?
    } else if hosted_smp || component_smp_mode {
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
            u64::from(block_guest_driver_mode || pci_configuration_mode) + 1,
            total_recovery.or_else(|| {
                block_service_mode.then(|| {
                    RecoveryStateMetadata::new(8, 2, Some([0x51; 16]), 1)
                        .expect("fixed recovery metadata")
                })
            }),
            total_override,
            false,
        )?
    };
    let decoded_boot_handoff = BootHandoff::decode(handoff.as_slice(), |_| {})
        .map_err(|error| anyhow!("WHP canonical boot handoff decode failed: {:?}", error))?;
    let (image_virtual, handoff_virtual, stack_virtual) = if hosted_smp || component_smp_mode {
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
    let table_pages = if application_mode {
        40
    } else if component_smp_mode
        || smp_ipi_mode
        || smp_service_migration_mode
        || smp_periodic_balance_mode
    {
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
            .ok_or_else(|| anyhow!("component base guest RAM overflow"))?;
        let service_pages = (8 + 32) + (8 + 32);
        let guest_pages = base_pages
            .checked_add(service_pages)
            .ok_or_else(|| anyhow!("component guest RAM overflow"))?;
        let control_pages =
            accounted_pages(core::mem::size_of::<PreparedWhpGuest<'static>>() as u64)?;
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
            .map_err(|error| anyhow!("WHP SystemGeneration encoding failed: {:?}", error))?;
        let digest = SystemGenerationView::decode(&bytes[..length])
            .map_err(|error| anyhow!("WHP SystemGeneration decoding failed: {:?}", error))?
            .digest();
        let requirement = match decode_canonical_manifest_interface(include_bytes!(
            "../../../../libraries/zim/mrml.toml"
        ))
        .map_err(|error| anyhow!("WHP ZIM interface manifest failed: {:?}", error))?
        {
            ManifestInterfaceDeclaration::Requirement(requirement) => requirement,
            ManifestInterfaceDeclaration::Provider(_) => {
                return Err(anyhow!("WHP ZIM manifest declared a provider"));
            }
        };
        let provider = match decode_canonical_manifest_interface(include_bytes!(
            "../../../../libraries/zstd/mrml.toml"
        ))
        .map_err(|error| anyhow!("WHP Zstd interface manifest failed: {:?}", error))?
        {
            ManifestInterfaceDeclaration::Provider(provider) => provider,
            ManifestInterfaceDeclaration::Requirement(_) => {
                return Err(anyhow!("WHP Zstd manifest declared a requirement"));
            }
        };
        let mut catalog = [0u8; 256];
        let catalog_length = encode_interface_catalog(1, &[requirement], &[provider], &mut catalog)
            .map_err(|error| anyhow!("WHP interface catalog failed: {:?}", error))?;
        let catalog_digest = InterfaceCatalogView::decode(&catalog[..catalog_length])
            .map_err(|error| anyhow!("WHP interface catalog decoding failed: {:?}", error))?
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
            .map_err(|error| anyhow!("WHP runtime inventory failed: {:?}", error))?;
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
                "component-release-inputs|status=PASS|backend=whp|generation_bytes={}|catalog_bytes={}|runtime_bytes={}",
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
                "invalid WHP general SystemRelease public-key length"
            ));
        }
        let expected_release_key = Sha3_512::digest(&release_public);
        let deployment_root = ObjectId(0x4445_504c_4f59);
        let mut capabilities = CapabilitySpace::<2>::new();
        let control = capabilities
            .insert(deployment_root, Rights::CONTROL)
            .map_err(|error| anyhow!("WHP deployment authority failed: {:?}", error))?;
        let inspect = capabilities
            .insert(deployment_root, Rights::READ)
            .map_err(|error| anyhow!("WHP deployment inspection failed: {:?}", error))?;
        let mut deployment = DeploymentService::<1>::new(deployment_root)
            .map_err(|error| anyhow!("WHP DeploymentService failed: {:?}", error))?;
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
                .map_err(|error| anyhow!("WHP generation candidate failed: {:?}", error))?,
            )
            .map_err(|error| anyhow!("WHP candidate staging failed: {:?}", error))?;
        let prepared = deployment
            .prepare_activation(&capabilities, control, candidate, None)
            .map_err(|error| anyhow!("WHP generation preparation failed: {:?}", error))?;
        let active = deployment
            .commit_activation(&capabilities, control, prepared)
            .map_err(|error| anyhow!("WHP generation activation failed: {:?}", error))?;
        if *active.generation_digest()
            != SystemGenerationView::decode(&bytes[..*length])
                .map_err(|error| anyhow!("WHP local generation decode failed: {:?}", error))?
                .digest()
            || *active.interface_catalog_digest()
                != InterfaceCatalogView::decode(&catalog[..*catalog_length])
                    .map_err(|error| anyhow!("WHP local catalog decode failed: {:?}", error))?
                    .digest()
        {
            return Err(anyhow!(
                "WHP SystemRelease did not bind the verified component artifacts"
            ));
        }
        let active_release = deployment
            .active_release(&capabilities, inspect)
            .map_err(|error| anyhow!("WHP active release read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("WHP activation lost SystemRelease identity"))?;
        let checkpoint = encode_deployment_release_checkpoint(deployment_root, active_release)
            .map_err(|error| anyhow!("WHP generation checkpoint failed: {:?}", error))?;
        let recovered = DeploymentService::<1>::recover(deployment_root, &checkpoint)
            .map_err(|error| anyhow!("WHP generation recovery failed: {:?}", error))?;
        let recovered_active = recovered
            .active(&capabilities, inspect)
            .map_err(|error| anyhow!("WHP active generation read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("WHP recovered no active SystemGeneration"))?;
        let recovered_release = recovered
            .active_release(&capabilities, inspect)
            .map_err(|error| anyhow!("WHP recovered release read failed: {:?}", error))?
            .ok_or_else(|| anyhow!("WHP recovered no active SystemRelease identity"))?;
        if recovered_release.generation() != recovered_active {
            return Err(anyhow!("WHP recovered release/generation mismatch"));
        }
        component_release_authority = Some((release_bytes, expected_release_key));
        Some(recovered_release)
    } else {
        None
    };
    let configured_total_policy = if service_mode || component_service_mode {
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
    // control-plane domain before CPU, RAM, or WHP guest construction begins.
    // The immutable inventory is retained across construction and finalized
    // only after the same domain has been committed as a running microVM.
    let mut isolation_admission = if component_service_mode {
        configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing configured WHP component policy"))?;
        let (release_bytes, expected_release_key) = component_release_authority
            .as_ref()
            .ok_or_else(|| anyhow!("missing authenticated WHP component release"))?;
        // SAFETY: this executable mode is a hosted controlled probe. The
        // helper's synthesized owner approval is never production recovery or
        // physical rollback evidence.
        let mut release_output = Vector::with_capacity(MAX_SYSTEM_RELEASE_BYTES)
            .map_err(|_| anyhow!("WHP release recovery scratch allocation failed"))?;
        release_output
            .try_resize(MAX_SYSTEM_RELEASE_BYTES, 0)
            .map_err(|_| anyhow!("WHP release recovery scratch initialization failed"))?;
        let total = unsafe {
            recover_total_control_plane::<2>(
                &decoded_boot_handoff,
                release_bytes,
                expected_release_key,
                &mut release_output,
            )
        }
        .map_err(|error| anyhow!("WHP recovered boot Total admission failed: {:?}", error))?;
        println!(
            "isolation-recovery|status=PASS|backend=whp|authority_epoch={}|boot_accepted_epoch={}|recovery_root_generation={}|configuration_revision={}",
            total.policy().authority_epoch(),
            total.policy().boot_accepted_epoch(),
            total.policy().recovery_root_generation(),
            total.policy().configuration_revision(),
        );
        Some(WhpTotalAdmission::Recovered(total))
    } else if service_mode {
        let configured = configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing configured WHP service policy"))?;
        Some(WhpTotalAdmission::Standalone(
            configured
                .effective
                .ok_or_else(|| anyhow!("missing transient WHP service policy"))?
                .admission_table(1)
                .map_err(|error| anyhow!("WHP isolation admission failed: {:?}", error))?,
        ))
    } else {
        None
    };
    let mut complete_isolation_preparation: Option<PreparedTotalServiceSet<2>> = None;
    let mut isolation_preparation = match (
        isolation_admission.as_mut(),
        configured_total_policy.as_ref(),
    ) {
        (Some(WhpTotalAdmission::Recovered(total)), Some(configured)) => {
            let mut prepared = total
                .prepare_complete_service_set(&[TotalServicePreparationBinding::new(
                    configured.bounds,
                    configured.identity,
                )])
                .map_err(|error| {
                    anyhow!("WHP recovered complete preparation failed: {:?}", error)
                })?;
            let route = prepared.take(configured.identity.domain()).ok_or_else(|| {
                anyhow!("WHP complete preparation omitted the recovered component domain")
            })?;
            complete_isolation_preparation = Some(prepared);
            Some(route)
        }
        (Some(WhpTotalAdmission::Standalone(admission)), Some(configured)) => {
            let admitted = configured
                .effective
                .ok_or_else(|| anyhow!("missing transient WHP service policy"))?
                .admit_service(configured.bounds)
                .map_err(|error| anyhow!("WHP configured admission failed: {:?}", error))?;
            let spec = admitted
                .service_spec(
                    admission.system_generation(),
                    configured.identity.domain(),
                    configured.identity.interface(),
                    configured.identity.interface_generation(),
                    configured.identity.provider_generation(),
                    configured.identity.class(),
                )
                .map_err(|error| anyhow!("WHP configured service spec failed: {:?}", error))?;
            Some(
                prepare_isolation_service_route(admission, spec)
                    .map_err(|error| anyhow!("WHP isolation preparation failed: {:?}", error))?,
            )
        }
        (None, None) => None,
        _ => return Err(anyhow!("WHP Total policy/admission ownership mismatch")),
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
    let application_spec = match (application_package_id, application_executable.as_ref()) {
        (Some(package_id), Some(application)) => {
            Some(total_application_spec(package_id, application)?)
        }
        (None, None) => None,
        _ => return Err(anyhow!("incomplete WHP application identity")),
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
            Some(WhpApplicationProjection::prepare(spec, pages)?)
        }
        (None, None, None, None) => None,
        _ => return Err(anyhow!("incomplete WHP application projection inputs")),
    };
    let guest_preparation = if boot_mode || application_mode {
        system.prepare_boot_kernel(&executable, handoff.as_slice(), layout)
    } else if pci_configuration_mode {
        system.prepare_kernel_block_dynamic_mmio_guest(
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
    } else if component_smp_mode {
        system.prepare_isolated_service_smp_kernel(&executable, handoff.as_slice(), layout)
    } else if deadline_receive_mode {
        system.prepare_timer_kernel(&executable, handoff.as_slice(), layout)
    } else if service_mode
        || component_service_mode
        || block_service_mode
        || service_restart_request_mode
        || fat32_ready_mode
    {
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
                "verified WHP kernel preparation failed: {:?}",
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
            .ok_or_else(|| anyhow!("missing admitted WHP application projection"))?
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
    if service_artifact_mode {
        let local_apic = deadline_receive_mode
            || service_preemption_mode
            || smp_service_migration_mode
            || component_smp_mode;
        let isolated_stack_pages = if block_service_mode {
            256
        } else if fat32_ready_mode {
            // Match KVM's guarded stack for the FAT32 PE entry.
            64
        } else {
            8
        };
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
                .map_err(|error| anyhow!("isolated WHP service preparation failed: {:?}", error))?;
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
                    anyhow!(
                        "second isolated WHP service preparation failed: {:?}",
                        error
                    )
                })?
        };
        if service_mode || service_restart_request_mode || fat32_ready_mode {
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
            .ok_or_else(|| anyhow!("missing WHP service entry"))?;
        let provider_entry = guest
            .service_entry_at(1)
            .ok_or_else(|| anyhow!("missing WHP provider entry"))?;
        if guest.service_page_table_root() != PhysAddr::new(SERVICE_TABLE_PHYSICAL).ok()
            || guest.service_page_table_root_at(1) != PhysAddr::new(SERVICE_B_TABLE_PHYSICAL).ok()
            || (!component_service_mode && provider_entry != service_entry)
            || ((service_mode || service_restart_request_mode || fat32_ready_mode)
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
        if component_service_mode {
            VmBackend::write_guest(
                &mut guest,
                SERVICE_SHARED_PHYSICAL + 16,
                &provider_entry.to_le_bytes(),
            )
            .map_err(|_| anyhow!("failed to publish WHP provider entry"))?;
        }
    }
    if let Some(launch) = component_launch.take() {
        let consumer_artifact = *service_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified WHP component consumer"))?
            .artifact()
            .digest();
        let provider_artifact = *provider_executable
            .as_ref()
            .ok_or_else(|| anyhow!("missing verified WHP component provider"))?
            .artifact()
            .digest();
        let route = launch
            .verify(
                ArtifactKind::ServiceImage,
                &consumer_artifact,
                ArtifactKind::ServiceImage,
                &provider_artifact,
            )
            .map_err(|(_, error)| anyhow!("WHP component artifact seal failed: {:?}", error))?
            .into_route();
        if let Some(prepared) = complete_isolation_preparation.as_mut() {
            prepared.restore(route).map_err(|(error, _)| {
                anyhow!("WHP transformed complete route restore failed: {:?}", error)
            })?;
        } else {
            isolation_preparation = Some(route);
        }
    }
    let mut guest = if application_executable.is_some() {
        let spec = application_spec
            .ok_or_else(|| anyhow!("missing WHP application route specification"))?;
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
            "application-isolation|status=PASS|scope=single-application|backend=whp|system_generation={}|policy_generation={}|eligible={}|microvm={}|native_fallback={}",
            spec.system_generation(),
            spec.policy_generation(),
            report.running_microvm_eligible,
            report.running_in_microvm,
            report.native_fallback,
        );
        WhpGuestOwner::Application {
            launcher,
            endpoint,
            projection: application_projection
                .take()
                .ok_or_else(|| anyhow!("missing active WHP application projection"))?,
        }
    } else if component_service_mode && complete_isolation_preparation.is_some() {
        let configured = configured_total_policy
            .as_ref()
            .ok_or_else(|| anyhow!("missing WHP recovered component policy"))?;
        let total = match isolation_admission.as_mut() {
            Some(WhpTotalAdmission::Recovered(total)) => total,
            _ => {
                return Err(anyhow!(
                    "WHP complete component set lost recovered admission"
                ));
            }
        };
        let prepared = complete_isolation_preparation
            .take()
            .ok_or_else(|| anyhow!("missing WHP complete component preparation"))?;
        let spec = prepared
            .spec(configured.identity.domain())
            .ok_or_else(|| anyhow!("WHP complete component preparation lost its route"))?;
        let mut provisional_guest = Some(guest);
        let (prepared, endpoints) = prepared
            .construct_complete_endpoints(total.admission_mut(), |route_spec| {
                if route_spec != spec {
                    return Err("prepared WHP component identity changed");
                }
                provisional_guest
                    .take()
                    .ok_or("WHP component endpoint was constructed more than once")
            })
            .map_err(|failure| {
                anyhow!("WHP complete component construction failed: {:?}", failure.error())
            })?;
        let routed = prepared
            .commit_complete(total.admission_mut(), endpoints)
            .map_err(|failure| {
                anyhow!("WHP complete component publication failed: {:?}", failure.error())
            })?;
        let mut endpoints = routed.into_endpoints().into_iter().flatten();
        let admitted_guest = endpoints
            .next()
            .filter(|binding| binding.domain() == configured.identity.domain())
            .ok_or_else(|| anyhow!("WHP complete publication omitted component endpoint"))?
            .into_endpoint();
        if endpoints.next().is_some() {
            return Err(anyhow!("WHP complete publication returned an excess endpoint"));
        }
        let runtime = match isolation_admission.take() {
            Some(WhpTotalAdmission::Recovered(total)) => {
                total.authorize_runtime().map_err(|error| {
                    anyhow!("WHP recovered runtime authorization failed: {:?}", error)
                })?
            }
            _ => return Err(anyhow!("WHP component route lost installed Total owner")),
        };
        let proof = runtime.proof();
        println!(
            "component-total-inventory|status=PASS|backend=whp|classified={}|eligible={}|microvm={}|native_fallback={}",
            proof.classified_domains(),
            proof.running_microvm_eligible(),
            proof.running_in_microvm(),
            runtime.admission().total_microvm_report().native_fallback
        );
        installed_total_runtime = Some(runtime);
        let mut launcher = PreparedMicrovmConfigurationLauncher::new(
            AdmittedConfigurationGuestFactory::new(spec, admitted_guest),
        );
        let endpoint = launcher
            .launch_microvm(spec)
            .map_err(|(_, error)| anyhow!("WHP configuration lifecycle failed: {:?}", error))?;
        WhpGuestOwner::Configuration { launcher, endpoint }
    } else if let (Some(admission), Some(prepared)) =
        (isolation_admission.as_mut(), isolation_preparation)
    {
        let spec = prepared.spec();
        let routed = prepared
            .commit(admission, guest)
            .map_err(|(_, error, _)| anyhow!("WHP isolation commit failed: {:?}", error))?;
        if routed.system_generation() != admission.system_generation() {
            return Err(anyhow!("WHP active SystemGeneration changed during launch"));
        }
        let admitted_guest = routed.into_endpoint();
        if !admission.total_microvm_report().satisfied() {
            return Err(anyhow!("WHP Total MicroVM admission was not satisfied"));
        }
        if component_service_mode {
            let runtime = match isolation_admission.take() {
                Some(WhpTotalAdmission::Recovered(total)) => {
                    total.authorize_runtime().map_err(|error| {
                        anyhow!("WHP recovered runtime authorization failed: {:?}", error)
                    })?
                }
                _ => return Err(anyhow!("WHP component route lost installed Total owner")),
            };
            let proof = runtime.proof();
            println!(
                "component-total-inventory|status=PASS|backend=whp|classified={}|eligible={}|microvm={}|native_fallback={}",
                proof.classified_domains(),
                proof.running_microvm_eligible(),
                proof.running_in_microvm(),
                runtime.admission().total_microvm_report().native_fallback
            );
            installed_total_runtime = Some(runtime);
        }
        let mut launcher = PreparedMicrovmConfigurationLauncher::new(
            AdmittedConfigurationGuestFactory::new(spec, admitted_guest),
        );
        let endpoint = launcher
            .launch_microvm(spec)
            .map_err(|(_, error)| anyhow!("WHP configuration lifecycle failed: {:?}", error))?;
        WhpGuestOwner::Configuration { launcher, endpoint }
    } else {
        WhpGuestOwner::Direct(guest)
    };
    let preparation_micros = preparation_started.elapsed().as_micros();
    let execution_started = Instant::now();
    if pci_configuration_mode {
        run_pci_configuration_probe(
            guest.into_direct()?,
            &system,
            &executable,
            handoff.as_slice(),
            layout,
        )?;
        println!(
            "verified signed test-only attached MRML block PCI-MMIO write/read/flush, decode-coupled native BAR install/withdraw with checked CR3 reload and continuation, orderly VM replacement, and pending-I/O reset isolation under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if block_guest_driver_mode {
        run_block_guest_driver_probe(
            guest.into_direct()?,
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
    let mut exit = if hosted_smp {
        let (exits, elapsed) = run_scheduled_smp(&mut guest)?;
        let [bootstrap, application] = exits;
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
            "verified signed scheduled two-vCPU kernel startup under WHP: bootstrap={}us application={}us verify={}us prepare={}us execute={}us total={}us",
            elapsed[0],
            elapsed[1],
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    } else {
        let run_result = if component_smp_mode {
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
                "verified Total-mode component two-vCPU startup under WHP: bootstrap={}us application={}us",
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
                        Err(anyhow!("WHP component vCPU deadline expired"))
                    }
                    Err(error) => Err(anyhow!("WHP component execution failed: {:?}", error)),
                }
            })
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
                        Err(anyhow!("WHP component vCPU deadline expired"))
                    }
                    Err(error) => Err(anyhow!("WHP component execution failed: {:?}", error)),
                }
            })
        } else {
            VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP execution failed: {:?}", error))
        };
        match run_result {
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
    if boot_mode {
        if exit != VmExit::Halted {
            return Err(anyhow!("WHP boot kernel exit mismatch: {:?}", exit));
        }
        let mut marker = [0u8; 4];
        VmBackend::read_guest(&guest, FRAMEBUFFER, &mut marker)
            .map_err(|_| anyhow!("kernel framebuffer is unreadable"))?;
        if marker != [0x57, 0xc8, 0xff, 0] {
            return Err(anyhow!(
                "kernel did not paint its authenticated boot marker"
            ));
        }
        println!(
            "verified Boot kernel reached its expected halt under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
    }
    if application_mode {
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
                .map_err(|error| anyhow!("WHP application continuation failed: {:?}", error))?;
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
        let mut marker = [0u8; 4];
        VmBackend::read_guest(&guest, FRAMEBUFFER, &mut marker)
            .map_err(|_| anyhow!("application framebuffer is unreadable"))?;
        if marker != [0; 4] {
            return Err(anyhow!(
                "application probe unexpectedly modified the framebuffer"
            ));
        }
        println!(
            "verified ordered signed-kernel stages and authenticated CPL3 application exit under WHP"
        );
        guest.finish()?;
        println!(
            "verified signed generation-bound Total-mode application CPL3 launch and teardown under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        return Ok(());
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
    if component_service_mode {
        let mut exit = exit;
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
                        return Err(anyhow!("WHP component cleanup stage mismatch: {:?}", exit));
                    }
                    cleanup_stage += 1;
                    if value == 0x40 {
                        guest.finish()?;
                        let (
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
                        ) = active_component_ram
                            .take()
                            .ok_or_else(|| anyhow!("missing active component RAM authority"))?;
                        let expected_pages = active.pages();
                        let reservation = unsafe { active.retire() };
                        let released = unsafe {
                            release_microvm_guest_ram(
                                &mut memory,
                                reservation,
                                ram_capability,
                                &mut authorities,
                            )
                        }
                        .map_err(|error| anyhow!("component RAM release failed: {:?}", error))?;
                        let usage =
                            memory
                                .usage(pool, pool_capability, &authorities)
                                .map_err(|error| {
                                    anyhow!("component RAM inspection failed: {:?}", error)
                                })?;
                        let expected_control_pages = control.pages();
                        let consumer_plan = consumer_image.plan();
                        let provider_plan = provider_image.plan();
                        let expected_image_pages = consumer_plan
                            .total_pages()
                            .and_then(|pages| provider_plan.total_pages()?.checked_add(pages))
                            .ok_or_else(|| {
                                anyhow!("component image release expectation overflow")
                            })?;
                        let expected_image_mappings = u32::from(consumer_plan.regions())
                            .checked_add(u32::from(provider_plan.regions()))
                            .ok_or_else(|| {
                                anyhow!("component image mapping expectation overflow")
                            })?;
                        if released != expected_pages
                            || usage.object_pages()
                                != expected_control_pages + 2 + expected_image_pages
                            || usage.active_mappings() != 2 + expected_image_mappings
                        {
                            return Err(anyhow!("component RAM release state was invalid"));
                        }
                        unsafe {
                            memory
                                .release_mapping(
                                    shared_projection.mapping(),
                                    projection_target,
                                    &authorities,
                                )
                                .map_err(|error| {
                                    anyhow!(
                                        "component shared projection release failed: {:?}",
                                        error
                                    )
                                })?;
                            memory
                                .release_mapping(
                                    resource_projection.mapping(),
                                    projection_target,
                                    &authorities,
                                )
                                .map_err(|error| {
                                    anyhow!(
                                        "component resource projection release failed: {:?}",
                                        error
                                    )
                                })?;
                        }
                        let released_shared = memory
                            .release_object(
                                shared_projection.object(),
                                shared_capability,
                                &mut authorities,
                            )
                            .map_err(|error| {
                                anyhow!("component shared page release failed: {:?}", error)
                            })?;
                        let released_resource = memory
                            .release_object(
                                resource_projection.object(),
                                resource_capability,
                                &mut authorities,
                            )
                            .map_err(|error| {
                                anyhow!("component resource page release failed: {:?}", error)
                            })?;
                        let usage =
                            memory
                                .usage(pool, pool_capability, &authorities)
                                .map_err(|error| {
                                    anyhow!("component projection inspection failed: {:?}", error)
                                })?;
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
                        let usage =
                            memory
                                .usage(pool, pool_capability, &authorities)
                                .map_err(|error| {
                                    anyhow!("component image inspection failed: {:?}", error)
                                })?;
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
                        .map_err(|error| {
                            anyhow!("component control-memory release failed: {:?}", error)
                        })?;
                        let usage =
                            memory
                                .usage(pool, pool_capability, &authorities)
                                .map_err(|error| {
                                    anyhow!("component memory inspection failed: {:?}", error)
                                })?;
                        if released_control != expected_control_pages
                            || usage.object_pages() != 0
                            || usage.active_mappings() != 0
                        {
                            return Err(anyhow!("component memory was not completely reclaimed"));
                        }
                        let (
                            mut budgets,
                            mut capabilities,
                            budget,
                            capability,
                            reservation,
                            cpu_runtime_micros,
                        ) = component_cpu
                            .take()
                            .ok_or_else(|| anyhow!("missing component vCPU authority"))?;
                        let cpu_runtime_total = cpu_runtime_micros[0]
                            .checked_add(cpu_runtime_micros[1])
                            .ok_or_else(|| anyhow!("component CPU runtime total overflow"))?;
                        let expected_vcpus = if cpu_runtime_micros[1] == 0 { 1 } else { 2 };
                        if budgets
                            .release_vcpus(reservation, capability, &capabilities)
                            .map_err(|error| {
                                anyhow!("component vCPU release failed: {:?}", error)
                            })?
                            != expected_vcpus
                        {
                            return Err(anyhow!("component vCPU release count mismatch"));
                        }
                        let usage =
                            budgets
                                .usage(budget, capability, &capabilities)
                                .map_err(|error| {
                                    anyhow!("component CPU inspection failed: {:?}", error)
                                })?;
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
                            .map_err(|error| {
                                anyhow!("component CPU root retirement failed: {:?}", error)
                            })?;
                        let admission = installed_total_runtime
                            .as_ref()
                            .map(RecoveredDeploymentTotalRuntime::admission)
                            .or_else(|| isolation_admission.as_ref().map(|value| &**value))
                            .ok_or_else(|| anyhow!("missing component isolation admission"))?;
                        let report = admission.total_microvm_report();
                        println!(
                            "isolation|requested=total-microvm|status=satisfied|backend=whp|policy_generation={}|eligible={}|microvm={}|native_fallback={}",
                            admission.policy_generation(),
                            report.running_microvm_eligible,
                            report.running_in_microvm,
                            report.native_fallback
                        );
                        println!(
                            "verified exact-generation ZIM/Zstd component data path and lifecycle cleanup under WHP: cpu_runtime={}us logical_cpu=0 affinity=host-enforced priority=host-normal verify={}us prepare={}us execute={}us total={}us",
                            cpu_runtime_total,
                            verification_micros,
                            preparation_micros,
                            execution_started.elapsed().as_micros(),
                            total_started.elapsed().as_micros()
                        );
                        return Ok(());
                    }
                }
                _ => {
                    return Err(anyhow!(
                        "WHP component service stage mismatch after {} accepted exits: {:?}",
                        accepted_exits,
                        exit
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
                        Err(anyhow!("WHP component service vCPU deadline expired"))
                    }
                    Err(error) => Err(anyhow!(
                        "WHP component service execution failed: {:?}",
                        error
                    )),
                }
            })?;
        }
        return Err(anyhow!(
            "WHP component service probe exceeded its stage bound"
        ));
    }
    if block_service_mode {
        let mut exit = exit;
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
                return Err(anyhow!(
                    "WHP block-service stage mismatch after {} accepted exits: {:?}",
                    observed_stage,
                    exit
                ));
            }
            exit = VmBackend::run(&mut guest, 0)
                .map_err(|error| anyhow!("WHP block-service execution failed: {:?}", error))?;
        }
        return Err(anyhow!("WHP block-service probe exceeded its stage bound"));
    }
    if deadline_receive_mode {
        let expected = if deadline_receive_cancel_replay_mode {
            0x2e
        } else if deadline_receive_cancel_denied_mode {
            0x2d
        } else if deadline_receive_cancel_mode {
            0x2c
        } else if deadline_receive_message_mode {
            0x2b
        } else {
            0x2a
        };
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: expected,
            })
        {
            return Err(anyhow!("WHP deadline-receive proof mismatch: {:?}", exit));
        }
        println!(
            "verified exact deadline receive completion under WHP: verify={}us prepare={}us execute={}us total={}us",
            verification_micros,
            preparation_micros,
            execution_started.elapsed().as_micros(),
            total_started.elapsed().as_micros()
        );
        guest.finish()?;
        return Ok(());
    }
    if fat32_ready_mode {
        if exit
            != (VmExit::Io {
                port: SERVICE_PROBE_PORT,
                size: 4,
                write: true,
                value: 0xf320,
            })
        {
            return Err(anyhow!("WHP FAT32 readiness mismatch: {:?}", exit));
        }
        println!("verified authenticated native FAT32 readiness under WHP");
        guest.finish()?;
        return Ok(());
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
        guest.finish()?;
        if let Some(admission) = installed_total_runtime
            .as_ref()
            .map(RecoveredDeploymentTotalRuntime::admission)
            .or_else(|| isolation_admission.as_ref().map(|value| &**value))
        {
            let report = admission.total_microvm_report();
            println!(
                "isolation|requested=total-microvm|status=satisfied|backend=whp|policy_generation={}|eligible={}|microvm={}|native_fallback={}",
                admission.policy_generation(),
                report.running_microvm_eligible,
                report.running_in_microvm,
                report.native_fallback
            );
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
    guest.finish()?;
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
    bytes: [u8; 512],
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
                100,
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
    .map_err(|_| anyhow!("handoff construction failed"))?;
    if length
        != 240
            + usize::from(recovery_state.is_some()) * 40
            + usize::from(installed_recovery.is_some()) * 104
    {
        return Err(anyhow!("unexpected handoff length"));
    }
    Ok(EncodedHandoff {
        bytes: encoded,
        length,
    })
}

#[cfg(any(test, target_os = "windows"))]
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

#[cfg(any(test, target_os = "windows"))]
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
    let mut encoded = [0u8; 512];
    let length = if let Some(recovery_state) = recovery_state {
        let installed = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Hosted,
            [0x42; 32],
            1,
            1,
            4096,
            100,
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
    .map_err(|_| anyhow!("SMP handoff construction failed"))?;
    if length != 316 + usize::from(recovery_state.is_some()) * (40 + 104) {
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
    fn application_projection_namespaces_are_admissible() {
        assert!(MemoryPoolTable::<1, 1>::new(APPLICATION_MEMORY_NAMESPACE).is_ok());
        assert!(CpuBudgetTable::<1, 1>::new(APPLICATION_CPU_NAMESPACE).is_ok());
    }

    #[test]
    fn handoff_binds_entropy_and_measurement() {
        let encoded = boot_handoff(9, [0x35; 32], [0xa7; 64], 1, None, None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.evidence().image_version(), 9);
        assert_eq!(decoded.evidence().entropy(), &[0x35; 32]);
        assert_eq!(decoded.evidence().image_measurement(), &[0xa7; 64]);
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
        let encoded = application_boot_handoff(9, [0x35; 32], [0xa7; 64], application).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.application(), Some(application));
        assert_eq!(decoded.service(), None);
        assert_eq!(decoded.ap_trampoline(), None);
        assert_eq!(decoded.madt(encoded.as_slice()), None);
    }

    #[test]
    fn block_handoff_binds_two_disjoint_payload_pages() {
        let encoded = boot_handoff(11, [0x37; 32], [0xa9; 64], 2, None, None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert_eq!(decoded.framebuffer().base().get(), FRAMEBUFFER);
        assert_eq!(decoded.framebuffer().byte_length(), 8192);
        assert!(boot_handoff(11, [0x37; 32], [0xa9; 64], 0, None, None, false).is_err());
    }

    #[test]
    fn recovery_handoff_binds_fixed_probe_metadata() {
        let recovery = RecoveryStateMetadata::new(8, 2, Some([0x51; 16]), 1).unwrap();
        let encoded =
            boot_handoff(12, [0x38; 32], [0xaa; 64], 1, Some(recovery), None, false).unwrap();
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
            12,
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

    #[cfg(target_os = "windows")]
    #[test]
    fn total_policy_rejects_a_decoded_handoff_without_the_override() {
        let recovered_component =
            configured_isolation_service(ObjectId(1), ObjectId(2), 1, 1).unwrap();
        assert!(recovered_component.effective.is_none());
        let recovery = RecoveryStateMetadata::new(8, 1, None, 0).unwrap();
        let encoded =
            boot_handoff(12, [0x38; 32], [0xaa; 64], 1, Some(recovery), None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        assert!(configured_total_service_policy(ObjectId(1), ObjectId(2), 1, 1, &decoded).is_err());
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
        let encoded = smp_boot_handoff(10, [0x36; 32], [0xa8; 64], None, None, false).unwrap();
        let decoded = BootHandoff::decode(encoded.as_slice(), |_| {}).unwrap();
        let topology = decoded
            .madt(encoded.as_slice())
            .and_then(|madt| mrml_kernel::arch::x86_64::X86CpuTopology::parse_madt(madt).ok())
            .unwrap();
        assert_eq!(topology.len(), 2);
        assert_eq!(decoded.ap_trampoline(), Some(0x8000));
        assert_eq!(decoded.ap_stack_arena(), Some(0x100_0000));
    }

    #[test]
    fn smp_total_handoff_retains_installed_recovery_identity() {
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let encoded = smp_boot_handoff(
            10,
            [0x36; 32],
            [0xa8; 64],
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
