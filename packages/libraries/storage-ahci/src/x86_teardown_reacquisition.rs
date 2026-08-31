//! Concrete x86 controller-manager reconstruction after service freeze.

use crate::{
    ActiveAhciMappingVerificationError, AhciCommandBackendTeardown, AhciMappedCommandMemory,
    AhciMappedDataBuffer, AhciNativeMappedMemory, AhciNativeMappedMemoryError,
    AhciNativePortReconstructionError, AhciPlatformIo, AhciX86CoherentDataSync,
    BoundAhciServiceLaunch, KernelAhciTeardownReacquisitionBackend, NativeAhciRegisterIo,
    reconstruct_bound_ahci_port, verify_current_x86_ahci_mappings,
};
use core::marker::PhantomData;
use mrml_kernel::NativeDeviceServiceTask;
use mrml_kernel::arch::x86_64::PageTableStore;

/// Read-only active-root check used before any teardown view is reconstructed.
///
/// # Safety
///
/// Implementations must verify the exact current hierarchy for `native_task`
/// and `launch` without changing mappings, hardware, or linear owners. Success
/// must remain valid until the caller finishes synchronous reconstruction.
pub unsafe trait AhciX86ActiveMappingVerifier {
    type Error;

    unsafe fn verify(
        &mut self,
        native_task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        launch: BoundAhciServiceLaunch,
    ) -> Result<(), Self::Error>;
}

pub struct CurrentAhciX86ActiveMappingVerifier;

// SAFETY: the implementation delegates to the exact current-CR3 verifier and
// has no other state or side effect.
unsafe impl AhciX86ActiveMappingVerifier for CurrentAhciX86ActiveMappingVerifier {
    type Error = ActiveAhciMappingVerificationError;

    unsafe fn verify(
        &mut self,
        native_task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        launch: BoundAhciServiceLaunch,
    ) -> Result<(), Self::Error> {
        unsafe { verify_current_x86_ahci_mappings(native_task, launch) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciX86TeardownReacquisitionError<E> {
    Verification(E),
    InvalidCoherenceRegion,
    InvalidRegisterMapping,
    InvalidMappedMemory(AhciNativeMappedMemoryError),
    Port(AhciNativePortReconstructionError),
    AssemblyMismatch,
}

/// Controller-manager owner for the mechanisms needed to reconstruct one
/// frozen x86 AHCI service's teardown state.
pub struct AhciX86TeardownReacquisition<'views, V, D> {
    verifier: V,
    delay: D,
    views: PhantomData<&'views mut [u8]>,
}

impl<'views, V, D> AhciX86TeardownReacquisition<'views, V, D> {
    /// Mints the manager backend from platform-proven exclusive mechanisms.
    ///
    /// # Safety
    ///
    /// `verifier` must cover the service's current x86 hierarchy. `delay` must
    /// be the exclusive monotonic timing mechanism retained for this assigned
    /// controller. The manager must separately retain assignment, DMA/IOMMU,
    /// PAT-coherence, mapping-generation, and no-alias proofs.
    pub const unsafe fn new(verifier: V, delay: D) -> Self
    where
        V: AhciX86ActiveMappingVerifier,
    {
        Self {
            verifier,
            delay,
            views: PhantomData,
        }
    }

    pub fn into_parts(self) -> (V, D) {
        (self.verifier, self.delay)
    }
}

/// Mints the concrete x86 reacquisition backend from manager-retained
/// mechanisms and binds it to the exact active task and launch in one step.
///
/// # Safety
///
/// The caller must hold the controller manager's exclusive assignment,
/// mapping-generation, DMA/IOMMU, PAT-coherence, and no-alias proofs for
/// `active`. `verifier` and `delay` must satisfy
/// [`AhciX86TeardownReacquisition::new`] for that same assignment. The returned
/// slot must be retained until routed or explicitly
/// recovered with `KernelAhciServiceExitSlot::into_parts`.
#[allow(clippy::type_complexity)]
pub unsafe fn install_x86_ahci_service_exit_slot<
    'resources,
    'views,
    S: PageTableStore,
    V: AhciX86ActiveMappingVerifier,
    D,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    active: crate::ActiveKernelAhciMappingSetOwner<
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    verifier: V,
    delay: D,
) -> Result<
    crate::KernelAhciServiceExitSlot<
        'resources,
        S,
        crate::KernelAhciManagerTeardownLease<AhciX86TeardownReacquisition<'views, V, D>>,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
    crate::KernelAhciServiceExitSlotInstallError<
        'resources,
        S,
        crate::KernelAhciManagerTeardownLease<AhciX86TeardownReacquisition<'views, V, D>>,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
> {
    let native_task = active.native_task();
    let launch = active.launch();
    let backend = unsafe { AhciX86TeardownReacquisition::new(verifier, delay) };
    let lease =
        unsafe { crate::KernelAhciManagerTeardownLease::mint(native_task, launch, backend) };
    crate::KernelAhciServiceExitSlot::install(active, lease)
}

// SAFETY: verification precedes all raw-view construction. Every fallible
// stage returns the unchanged verifier and delay; short-lived derived pointer
// views are dropped before the backend is reconstructed. Success transfers the
// sole views into one typed teardown owner.
unsafe impl<'views, V: AhciX86ActiveMappingVerifier, D> KernelAhciTeardownReacquisitionBackend
    for AhciX86TeardownReacquisition<'views, V, D>
{
    type Registers = AhciPlatformIo<NativeAhciRegisterIo, D>;
    type CommandMemory = AhciMappedCommandMemory<'views>;
    type DataIo = AhciMappedDataBuffer<'views, AhciX86CoherentDataSync>;
    type Error = AhciX86TeardownReacquisitionError<V::Error>;

    unsafe fn reacquire(
        mut self,
        native_task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        launch: BoundAhciServiceLaunch,
    ) -> Result<
        AhciCommandBackendTeardown<Self::Registers, Self::CommandMemory, Self::DataIo>,
        (Self::Error, Self),
    > {
        if let Err(error) = unsafe { self.verifier.verify(native_task, launch) } {
            return Err((AhciX86TeardownReacquisitionError::Verification(error), self));
        }
        let spec = launch.spec();
        let sync = match unsafe { AhciX86CoherentDataSync::new(spec.data()) } {
            Some(sync) => sync,
            None => {
                return Err((
                    AhciX86TeardownReacquisitionError::InvalidCoherenceRegion,
                    self,
                ));
            }
        };
        let mapped = match unsafe { AhciNativeMappedMemory::from_bound_launch(launch, sync) } {
            Ok(mapped) => mapped,
            Err(error) => {
                return Err((
                    AhciX86TeardownReacquisitionError::InvalidMappedMemory(error),
                    self,
                ));
            }
        };
        let registers = match unsafe { NativeAhciRegisterIo::new(spec.mapping()) } {
            Some(registers) => registers,
            None => {
                drop(mapped);
                return Err((
                    AhciX86TeardownReacquisitionError::InvalidRegisterMapping,
                    self,
                ));
            }
        };
        let mut platform = AhciPlatformIo::new(registers, self.delay);
        let port = match reconstruct_bound_ahci_port(launch, &mut platform) {
            Ok(port) => port,
            Err(error) => {
                let (_, delay) = platform.into_parts();
                drop(mapped);
                return Err((
                    AhciX86TeardownReacquisitionError::Port(error),
                    Self {
                        verifier: self.verifier,
                        delay,
                        views: PhantomData,
                    },
                ));
            }
        };
        let (command_memory, data_io) = mapped.into_parts();
        match AhciCommandBackendTeardown::try_from_reacquired_parts(
            launch,
            port,
            platform,
            command_memory,
            data_io,
        ) {
            Ok(teardown) => Ok(teardown),
            Err((_port, platform, command_memory, data_io)) => {
                let (_, delay) = platform.into_parts();
                drop(command_memory);
                drop(data_io);
                Err((
                    AhciX86TeardownReacquisitionError::AssemblyMismatch,
                    Self {
                        verifier: self.verifier,
                        delay,
                        views: PhantomData,
                    },
                ))
            }
        }
    }
}
