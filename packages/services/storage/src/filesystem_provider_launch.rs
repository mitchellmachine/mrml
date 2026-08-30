use crate::{
    FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES, FilesystemBlockAssociation,
    FilesystemBlockAssociationHandoff,
};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, ComponentServiceReadTransferAttachment, Rights,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderLaunchReceipt<I> {
    association_generation: u64,
    filesystem_provider_generation: u64,
    block_provider_generation: u64,
    system_generation: u64,
    instance: I,
}

impl<I> FilesystemProviderLaunchReceipt<I> {
    pub const fn association_generation(&self) -> u64 {
        self.association_generation
    }

    pub const fn filesystem_provider_generation(&self) -> u64 {
        self.filesystem_provider_generation
    }

    pub const fn block_provider_generation(&self) -> u64 {
        self.block_provider_generation
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn instance(&self) -> &I {
        &self.instance
    }

    pub fn into_instance(self) -> I {
        self.instance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemProviderLaunchError<E> {
    Capability(CapabilityError),
    WrongEndpointAuthority,
    WrongTransferAuthority,
    TransferTooSmall,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderTeardownError<I, E> {
    receipt: FilesystemProviderLaunchReceipt<I>,
    error: E,
}

impl<I, E> FilesystemProviderTeardownError<I, E> {
    pub const fn receipt(&self) -> &FilesystemProviderLaunchReceipt<I> {
        &self.receipt
    }

    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_parts(self) -> (FilesystemProviderLaunchReceipt<I>, E) {
        (self.receipt, self.error)
    }
}

/// Placement-specific construction boundary for an isolated filesystem
/// provider with one exact block dependency.
///
/// # Safety
///
/// Implementations must create a fresh provider domain, project `handoff` as
/// read-only launch data, attenuate `block_endpoint` to exact SIGNAL, project
/// the attachment's local read and delegable provider-write handles, bind all
/// projections to that same domain generation, and publish no endpoint or ready
/// signal unless every projection and provider construction succeeds. Failure
/// must revoke and erase every partial projection and domain. A successful
/// return must be the exact live instance or cleanup owner for those resources;
/// the caller retains it in the launch receipt until supervised teardown.
pub unsafe trait FilesystemProviderLaunchBackend {
    type Error;
    type Instance;

    fn launch(
        &mut self,
        association: FilesystemBlockAssociation,
        handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        block_endpoint: Capability,
        transfer: ComponentServiceReadTransferAttachment,
    ) -> Result<Self::Instance, Self::Error>;
}

/// Placement-specific teardown boundary for a successfully launched provider.
///
/// # Safety
///
/// Implementations must advance `instance` only after each cleanup stage is
/// confirmed. On failure it must retain the exact live resources and progress
/// needed for a safe retry. Success means the complete provider domain and all
/// projections owned by the instance are retired.
pub unsafe trait FilesystemProviderTeardownBackend: FilesystemProviderLaunchBackend {
    type TeardownError;

    fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError>;
}

pub fn launch_filesystem_provider<B: FilesystemProviderLaunchBackend, const CAPABILITIES: usize>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    block_endpoint_capability: Capability,
    transfer: ComponentServiceReadTransferAttachment,
    association: FilesystemBlockAssociation,
    backend: &mut B,
) -> Result<FilesystemProviderLaunchReceipt<B::Instance>, FilesystemProviderLaunchError<B::Error>> {
    let endpoint_object = capabilities
        .authorize_exact(
            block_endpoint_capability,
            Rights::SIGNAL.union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if endpoint_object != association.block_binding.endpoint_object {
        return Err(FilesystemProviderLaunchError::WrongEndpointAuthority);
    }
    let local_object = capabilities
        .authorize_exact(
            transfer.local_read(),
            Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    let write_object = capabilities
        .authorize_exact(
            transfer.provider_write(),
            Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if local_object != transfer.shared_object() || write_object != transfer.shared_object() {
        return Err(FilesystemProviderLaunchError::WrongTransferAuthority);
    }
    if transfer.shared_bytes() < association.logical_block_bytes {
        return Err(FilesystemProviderLaunchError::TransferTooSmall);
    }
    let handoff = association.handoff();
    let mut encoded = handoff.encode();
    let launched = backend
        .launch(association, &encoded, block_endpoint_capability, transfer)
        .map_err(FilesystemProviderLaunchError::Backend);
    encoded.fill(0);
    Ok(receipt(handoff, launched?))
}

fn receipt<I>(
    handoff: FilesystemBlockAssociationHandoff,
    instance: I,
) -> FilesystemProviderLaunchReceipt<I> {
    FilesystemProviderLaunchReceipt {
        association_generation: handoff.association_generation(),
        filesystem_provider_generation: handoff.filesystem_provider_generation(),
        block_provider_generation: handoff.block_provider_generation(),
        system_generation: handoff.system_generation(),
        instance,
    }
}

pub fn teardown_filesystem_provider<B: FilesystemProviderTeardownBackend>(
    mut receipt: FilesystemProviderLaunchReceipt<B::Instance>,
    backend: &mut B,
) -> Result<(), FilesystemProviderTeardownError<B::Instance, B::TeardownError>> {
    match backend.teardown(&mut receipt.instance) {
        Ok(()) => Ok(()),
        Err(error) => Err(FilesystemProviderTeardownError { receipt, error }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StorageModuleBinding, StorageModuleClass};
    use mrml_interface_storage_block_provider_v1::OpaqueHandle as BlockOpaqueHandle;
    use mrml_interface_storage_filesystem_v3::OpaqueHandle as FilesystemOpaqueHandle;
    use mrml_kernel::ObjectId;
    use mrml_kernel::arch::x86_64::UserContext;

    struct Backend {
        fail: bool,
        fail_teardown: bool,
        calls: usize,
        teardown_calls: usize,
        observed: [u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
    }

    unsafe impl FilesystemProviderTeardownBackend for Backend {
        type TeardownError = ();

        fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError> {
            self.teardown_calls += 1;
            *instance += 1;
            if self.fail_teardown { Err(()) } else { Ok(()) }
        }
    }

    unsafe impl FilesystemProviderLaunchBackend for Backend {
        type Error = ();
        type Instance = u64;

        fn launch(
            &mut self,
            association: FilesystemBlockAssociation,
            handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
            block_endpoint: Capability,
            transfer: ComponentServiceReadTransferAttachment,
        ) -> Result<Self::Instance, Self::Error> {
            assert_eq!(association.association_generation, 12);
            assert_ne!(block_endpoint.token(), 0);
            assert_eq!(transfer.shared_bytes(), 4096);
            self.calls += 1;
            self.observed = *handoff;
            if self.fail { Err(()) } else { Ok(0xfeed) }
        }
    }

    fn association() -> FilesystemBlockAssociation {
        FilesystemBlockAssociation {
            filesystem_binding: StorageModuleBinding {
                class: StorageModuleClass::Filesystem,
                module_object: ObjectId(41),
                interface_object: ObjectId(42),
                provider_object: ObjectId(43),
                endpoint_object: ObjectId(44),
                interface_generation: 3,
                provider_generation: 5,
                system_generation: 9,
                binding_generation: 3,
            },
            block_binding: StorageModuleBinding {
                class: StorageModuleClass::BlockProvider,
                module_object: ObjectId(11),
                interface_object: ObjectId(10),
                provider_object: ObjectId(20),
                endpoint_object: ObjectId(21),
                interface_generation: 1,
                provider_generation: 7,
                system_generation: 9,
                binding_generation: 4,
            },
            volume: FilesystemOpaqueHandle::new(2, 6).unwrap(),
            block_session: BlockOpaqueHandle::new(8, 10).unwrap(),
            logical_block_bytes: 4096,
            association_generation: 12,
        }
    }

    fn provider_task() -> mrml_kernel::TaskId {
        let mut runtime = mrml_kernel::TaskRuntime::<1, 1>::new(100, 1).unwrap();
        runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap()
    }

    fn transfer_attachment<const C: usize>(
        capabilities: &mut CapabilitySpace<C>,
    ) -> ComponentServiceReadTransferAttachment {
        let local_read = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        ComponentServiceReadTransferAttachment::new(
            provider_task(),
            ObjectId(0x80),
            6,
            4096,
            local_read,
            provider_write,
            capabilities,
        )
        .unwrap()
    }

    #[test]
    fn exact_endpoint_launches_with_canonical_handoff_and_returns_bound_receipt() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let receipt = launch_filesystem_provider(
            &capabilities,
            endpoint,
            transfer,
            association,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&backend.observed),
            Ok(association.handoff())
        );
        assert_eq!(receipt.association_generation(), 12);
        assert_eq!(receipt.filesystem_provider_generation(), 5);
        assert_eq!(receipt.block_provider_generation(), 7);
        assert_eq!(receipt.system_generation(), 9);
        assert_eq!(*receipt.instance(), 0xfeed);
        assert_eq!(receipt.into_instance(), 0xfeed);
    }

    #[test]
    fn substituted_endpoint_and_backend_failure_never_become_success_receipts() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let substituted = capabilities
            .insert(ObjectId(22), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                substituted,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::WrongEndpointAuthority)
        );
        assert_eq!(backend.calls, 0);

        let mut oversized = association;
        oversized.logical_block_bytes = 8192;
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                oversized.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        assert_eq!(
            launch_filesystem_provider(&capabilities, endpoint, transfer, oversized, &mut backend,),
            Err(FilesystemProviderLaunchError::TransferTooSmall)
        );
        assert_eq!(backend.calls, 0);

        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        backend.fail = true;
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                endpoint,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::Backend(()))
        );
        assert_eq!(backend.calls, 1);
    }

    #[test]
    fn teardown_failure_returns_exact_progressed_receipt_for_retry() {
        let mut backend = Backend {
            fail: false,
            fail_teardown: true,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let receipt = receipt(association().handoff(), 40);
        let failure = teardown_filesystem_provider(receipt, &mut backend).unwrap_err();
        assert_eq!(backend.teardown_calls, 1);
        assert_eq!(*failure.receipt().instance(), 41);
        assert_eq!(failure.receipt().association_generation(), 12);
        assert_eq!(failure.error(), &());
        let (receipt, ()) = failure.into_parts();
        backend.fail_teardown = false;
        assert_eq!(teardown_filesystem_provider(receipt, &mut backend), Ok(()));
        assert_eq!(backend.teardown_calls, 2);
    }
}
