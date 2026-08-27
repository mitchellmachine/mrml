#[cfg(test)]
use mrml_kernel::arch::x86_64::PRIVILEGE_STACK_ARENA_PAGES;
use mrml_kernel::arch::x86_64::{
    Mapping, PagePermissions, PageTableBuilder, PerCpuPrivilegeStacks, PrivilegeStackLayout,
    VirtAddr,
};
use mrml_kernel::{
    ApplicationLaunch, ArtifactKind, BootHandoff, Capability, CapabilitySpace, DeadlineVmBackend,
    GpuSharedQueueLayout, GpuVmmMemory, MemoryResourceError, MicrovmPeerPageProjection, PAGE_SIZE,
    PhysAddr, PreparedComponentServiceLaunch, RevocableVmBackend, ServiceAddressSpaceEraser,
    SignedArtifact, TaskId, VerifiedExecutable, VirtualBlockConfigurationPage,
    VirtualBlockQueueLayout, VirtualBlockResumePage, VirtualBlockVmmMemory, VmBackend, VmExit,
};

use super::{
    KvmBackend, KvmError, KvmPageTableStore, KvmPeerHostPage, KvmSystem, KvmVcpuSnapshot,
    map_loaded_handoff, map_loaded_pe,
};

const XAPIC_BASE: u64 = 0xfee0_0000;
const MAX_ISOLATED_SERVICES: usize = 3;

#[derive(Clone, Copy)]
struct KernelDevices {
    framebuffer: bool,
    local_apic: bool,
    gpu_queue: Option<GpuSharedQueueLayout>,
    block_queue: Option<VirtualBlockQueueLayout>,
    block_configuration: Option<VirtualBlockConfigurationPage>,
    block_resume: Option<VirtualBlockResumePage>,
    trapped_mmio: Option<u64>,
    cpus: u8,
    service_shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KvmLaunchLayout {
    table_physical: u64,
    table_pages: u64,
    image_physical: u64,
    image_virtual: u64,
    handoff_physical: u64,
    handoff_virtual: u64,
    stack_physical: u64,
    stack_virtual: u64,
    stack_pages: u64,
    user: bool,
}

impl KvmLaunchLayout {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table_physical: u64,
        table_pages: u64,
        image_physical: u64,
        image_virtual: u64,
        handoff_physical: u64,
        handoff_virtual: u64,
        stack_physical: u64,
        stack_virtual: u64,
        stack_pages: u64,
        user: bool,
    ) -> Result<Self, KvmError> {
        if table_pages < 4
            || stack_pages == 0
            || [
                table_physical,
                image_physical,
                handoff_physical,
                stack_physical,
            ]
            .iter()
            .any(|address| *address == 0 || address % PAGE_SIZE != 0)
            || [image_virtual, handoff_virtual, stack_virtual]
                .iter()
                .any(|address| *address == 0 || address % PAGE_SIZE != 0)
        {
            return Err(KvmError::InvalidMapping);
        }
        PerCpuPrivilegeStacks::<1>::new(stack_physical, stack_virtual, stack_pages)
            .and_then(|set| set.cpu(0))
            .map_err(|_| KvmError::InvalidMapping)?;
        Ok(Self {
            table_physical,
            table_pages,
            image_physical,
            image_virtual,
            handoff_physical,
            handoff_virtual,
            stack_physical,
            stack_virtual,
            stack_pages,
            user,
        })
    }
}

pub struct PreparedKvmGuest<const N: usize> {
    backend: KvmBackend<N>,
    entry: u64,
    root: PhysAddr,
    table_physical: u64,
    table_pages: u64,
    trapped_mmio: Option<u64>,
    trapped_mmio_mapped: bool,
    trapped_mmio_retired: bool,
    service_entry: [Option<u64>; MAX_ISOLATED_SERVICES],
    service_root: [Option<PhysAddr>; MAX_ISOLATED_SERVICES],
    service_instance: [Option<ServiceInstance>; MAX_ISOLATED_SERVICES],
    service_shared: Option<Mapping>,
    service_shared_live: [bool; 2],
    service_resource: [Option<Mapping>; 2],
    service_resource_live: [bool; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvmPeerPageError {
    Policy(MemoryResourceError),
    Backend(KvmError),
}

pub struct PreparedKvmPeerPage<'guest, const FIRST: usize, const SECOND: usize> {
    first: &'guest mut PreparedKvmGuest<FIRST>,
    second: &'guest mut PreparedKvmGuest<SECOND>,
    backing: Option<KvmPeerHostPage>,
    first_physical: u64,
    second_physical: u64,
    first_virtual: u64,
    second_virtual: u64,
    first_virtual_live: bool,
    second_virtual_live: bool,
    first_live: bool,
    second_live: bool,
}

pub struct KvmPeerPagePrepareFailure<'guest, const FIRST: usize, const SECOND: usize> {
    error: KvmPeerPageError,
    retained: Option<PreparedKvmPeerPage<'guest, FIRST, SECOND>>,
}

impl<const FIRST: usize, const SECOND: usize> KvmPeerPagePrepareFailure<'_, FIRST, SECOND> {
    pub const fn error(&self) -> KvmPeerPageError {
        self.error
    }
}

impl<'guest, const FIRST: usize, const SECOND: usize>
    KvmPeerPagePrepareFailure<'guest, FIRST, SECOND>
{
    pub fn into_retained(self) -> Option<PreparedKvmPeerPage<'guest, FIRST, SECOND>> {
        self.retained
    }
}

impl<'guest, const FIRST: usize, const SECOND: usize> PreparedKvmPeerPage<'guest, FIRST, SECOND> {
    pub fn prepare<const C: usize>(
        first: &'guest mut PreparedKvmGuest<FIRST>,
        second: &'guest mut PreparedKvmGuest<SECOND>,
        projection: &MicrovmPeerPageProjection,
        first_target_capability: Capability,
        second_target_capability: Capability,
        capabilities: &CapabilitySpace<C>,
        first_physical: u64,
        second_physical: u64,
    ) -> Result<Self, KvmPeerPagePrepareFailure<'guest, FIRST, SECOND>> {
        projection
            .validate_targets(
                first_target_capability,
                second_target_capability,
                capabilities,
            )
            .map_err(|error| KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Policy(error),
                retained: None,
            })?;
        if !first_physical.is_multiple_of(PAGE_SIZE) || !second_physical.is_multiple_of(PAGE_SIZE) {
            return Err(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(KvmError::UnalignedMemory),
                retained: None,
            });
        }
        let first_virtual = projection
            .first_virtual_page()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(KvmError::InvalidMapping),
                retained: None,
            })?;
        let second_virtual = projection
            .second_virtual_page()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(KvmError::InvalidMapping),
                retained: None,
            })?;
        let backing = KvmPeerHostPage::allocate().map_err(|error| KvmPeerPagePrepareFailure {
            error: KvmPeerPageError::Backend(error),
            retained: None,
        })?;
        let host = backing.host();
        first
            .backend
            .map_external_peer_page(first_physical, host)
            .map_err(|error| KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(error),
                retained: None,
            })?;
        if let Err(error) = second.backend.map_external_peer_page(second_physical, host) {
            if let Err(cleanup) = first.backend.unmap_external_peer_page(first_physical, host) {
                return Err(KvmPeerPagePrepareFailure {
                    error: KvmPeerPageError::Backend(cleanup),
                    retained: Some(Self {
                        first,
                        second,
                        backing: Some(backing),
                        first_physical,
                        second_physical,
                        first_virtual,
                        second_virtual,
                        first_virtual_live: false,
                        second_virtual_live: false,
                        first_live: true,
                        second_live: false,
                    }),
                });
            }
            return Err(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(error),
                retained: None,
            });
        }
        if let Err(error) = first.install_peer_page(first_virtual, first_physical) {
            let first_virtual_live = first
                .peer_page_matches(first_virtual, first_physical)
                .unwrap_or(true);
            let mut retained = Self {
                first,
                second,
                backing: Some(backing),
                first_physical,
                second_physical,
                first_virtual,
                second_virtual,
                first_virtual_live,
                second_virtual_live: false,
                first_live: true,
                second_live: true,
            };
            if retained.withdraw_virtual().is_ok() && retained.retire_native().is_ok() {
                return Err(KvmPeerPagePrepareFailure {
                    error: KvmPeerPageError::Backend(error),
                    retained: None,
                });
            }
            return Err(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(error),
                retained: Some(retained),
            });
        }
        if let Err(error) = second.install_peer_page(second_virtual, second_physical) {
            let second_virtual_live = second
                .peer_page_matches(second_virtual, second_physical)
                .unwrap_or(true);
            let mut retained = Self {
                first,
                second,
                backing: Some(backing),
                first_physical,
                second_physical,
                first_virtual,
                second_virtual,
                first_virtual_live: true,
                second_virtual_live,
                first_live: true,
                second_live: true,
            };
            if retained.withdraw_virtual().is_ok() && retained.retire_native().is_ok() {
                return Err(KvmPeerPagePrepareFailure {
                    error: KvmPeerPageError::Backend(error),
                    retained: None,
                });
            }
            return Err(KvmPeerPagePrepareFailure {
                error: KvmPeerPageError::Backend(error),
                retained: Some(retained),
            });
        }
        Ok(Self {
            first,
            second,
            backing: Some(backing),
            first_physical,
            second_physical,
            first_virtual,
            second_virtual,
            first_virtual_live: true,
            second_virtual_live: true,
            first_live: true,
            second_live: true,
        })
    }

    pub fn write_first(&mut self, input: &[u8]) -> Result<(), KvmError> {
        if !self.first_live || input.len() > PAGE_SIZE as usize {
            return Err(KvmError::InvalidMapping);
        }
        VmBackend::write_guest(self.first, self.first_physical, input)
    }

    pub fn read_second(&self, output: &mut [u8]) -> Result<(), KvmError> {
        if !self.second_live || output.len() > PAGE_SIZE as usize {
            return Err(KvmError::InvalidMapping);
        }
        VmBackend::read_guest(self.second, self.second_physical, output)
    }

    pub fn write_second(&mut self, input: &[u8]) -> Result<(), KvmError> {
        if !self.second_live || input.len() > PAGE_SIZE as usize {
            return Err(KvmError::InvalidMapping);
        }
        VmBackend::write_guest(self.second, self.second_physical, input)
    }

    pub fn read_first(&self, output: &mut [u8]) -> Result<(), KvmError> {
        if !self.first_live || output.len() > PAGE_SIZE as usize {
            return Err(KvmError::InvalidMapping);
        }
        VmBackend::read_guest(self.first, self.first_physical, output)
    }

    pub fn first_translation(&mut self) -> Result<Option<u64>, KvmError> {
        Ok(self
            .first
            .page_walk(self.first_virtual)?
            .physical_address(self.first_virtual))
    }

    pub fn second_translation(&mut self) -> Result<Option<u64>, KvmError> {
        Ok(self
            .second
            .page_walk(self.second_virtual)?
            .physical_address(self.second_virtual))
    }

    pub fn retire(mut self) -> Result<(), (KvmError, Self)> {
        if let Err(error) = self.withdraw_virtual() {
            return Err((error, self));
        }
        if let Err(error) = self.retire_native() {
            return Err((error, self));
        }
        let _ = self.backing.take();
        Ok(())
    }

    fn withdraw_virtual(&mut self) -> Result<(), KvmError> {
        if self.second_virtual_live {
            self.second
                .withdraw_peer_page(self.second_virtual, self.second_physical)?;
            self.second_virtual_live = false;
        }
        if self.first_virtual_live {
            self.first
                .withdraw_peer_page(self.first_virtual, self.first_physical)?;
            self.first_virtual_live = false;
        }
        Ok(())
    }

    fn retire_native(&mut self) -> Result<(), KvmError> {
        let Some(backing) = self.backing.as_ref() else {
            return Err(KvmError::InvalidMapping);
        };
        let host = backing.host();
        if self.second_live {
            if let Err(error) = self
                .second
                .backend
                .unmap_external_peer_page(self.second_physical, host)
            {
                return Err(error);
            }
            self.second_live = false;
        }
        if self.first_live {
            if let Err(error) = self
                .first
                .backend
                .unmap_external_peer_page(self.first_physical, host)
            {
                return Err(error);
            }
            self.first_live = false;
        }
        Ok(())
    }
}

impl<const FIRST: usize, const SECOND: usize> Drop for PreparedKvmPeerPage<'_, FIRST, SECOND> {
    fn drop(&mut self) {
        let mut uncertain = false;
        if self.withdraw_virtual().is_err() {
            uncertain = true;
        }
        if uncertain {
            if let Some(backing) = self.backing.take() {
                core::mem::forget(backing);
            }
            return;
        }
        let Some(backing) = self.backing.as_ref() else {
            return;
        };
        let host = backing.host();
        if self.second_live {
            if self
                .second
                .backend
                .unmap_external_peer_page(self.second_physical, host)
                .is_ok()
            {
                self.second_live = false;
            } else {
                uncertain = true;
            }
        }
        if self.first_live {
            if self
                .first
                .backend
                .unmap_external_peer_page(self.first_physical, host)
                .is_ok()
            {
                self.first_live = false;
            } else {
                uncertain = true;
            }
        }
        if uncertain {
            if let Some(backing) = self.backing.take() {
                core::mem::forget(backing);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ServiceInstance {
    digest: [u8; 64],
    image_physical: u64,
    image_virtual: u64,
    image_bytes: u64,
    stack_physical: u64,
    stack_bytes: u64,
    table_physical: u64,
    table_pages: u64,
}

pub struct KvmServiceEraser<'guest, 'artifact, const N: usize> {
    guest: &'guest mut PreparedKvmGuest<N>,
    service: &'guest VerifiedExecutable<'artifact>,
    slot: usize,
    task: TaskId,
}

impl<const N: usize> ServiceAddressSpaceEraser for KvmServiceEraser<'_, '_, N> {
    type Error = KvmError;

    fn erase(
        &mut self,
        task: TaskId,
        context: mrml_kernel::arch::x86_64::UserContext,
    ) -> Result<(), Self::Error> {
        if task != self.task
            || self.guest.service_page_table_root_at(self.slot) != Some(context.page_table())
        {
            return Err(KvmError::InvalidMapping);
        }
        self.guest
            .reprovision_isolated_service_at(self.slot, self.service)?;
        Ok(())
    }
}

impl<const N: usize> PreparedKvmGuest<N> {
    /// Maps the exact signed application container and its unpublished boot
    /// resources. The kernel remains responsible for signature revalidation,
    /// final W^X page tables, CPL3 entry, and lifecycle publication.
    pub fn attach_application_boot_resources(
        mut self,
        application: ApplicationLaunch,
        container: &[u8],
        executable: &VerifiedExecutable<'_>,
    ) -> Result<Self, KvmError> {
        let signed = SignedArtifact::decode(container).map_err(|_| KvmError::InvalidMapping)?;
        let image_bytes = page_bytes(u64::from(executable.image().image_size()))?;
        let artifact_bytes =
            page_bytes(u64::try_from(container.len()).map_err(|_| KvmError::MemoryOverflow)?)?;
        let stack_bytes = application
            .stack_pages()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        let table_bytes = application
            .table_pages()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        if !signed.matches_verified_executable(executable)
            || executable.artifact().kind() != ArtifactKind::ApplicationImage
            || application.artifact_length() != container.len() as u64
            || application.version() != executable.artifact().version()
            || application.measurement() != *executable.artifact().digest()
            || application.image_pages().checked_mul(PAGE_SIZE) != Some(image_bytes)
            || application.image_virtual() != executable.image().image_base()
            || application.entry()
                != application
                    .image_virtual()
                    .checked_add(u64::from(executable.image().entry_rva()))
                    .ok_or(KvmError::MemoryOverflow)?
            || application.stack_pages() == 0
            || application.table_pages() < 4
        {
            return Err(KvmError::InvalidMapping);
        }
        validate_ranges(&[
            (application.artifact_physical().get(), artifact_bytes),
            (application.image_physical().get(), image_bytes),
            (application.stack_physical().get(), stack_bytes),
            (application.table_physical().get(), table_bytes),
        ])?;
        self.backend.map_memory(
            application.artifact_physical().get(),
            artifact_bytes as usize,
            false,
        )?;
        self.backend.map_memory(
            application.image_physical().get(),
            image_bytes as usize,
            false,
        )?;
        self.backend.map_memory(
            application.stack_physical().get(),
            stack_bytes as usize,
            false,
        )?;
        self.backend.map_memory(
            application.table_physical().get(),
            table_bytes as usize,
            false,
        )?;
        self.backend
            .memory
            .write_service(application.artifact_physical().get(), container)?;
        let loaded = self.backend.memory.load_verified_executable(
            executable,
            application.image_physical().get(),
            application.image_virtual(),
        )?;
        if loaded.entry() != application.entry() {
            return Err(KvmError::InvalidMapping);
        }
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            self.table_physical,
            self.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, self.root);
        for mapping in [
            Mapping::new(
                VirtAddr::new(application.artifact_physical().get())
                    .map_err(|_| KvmError::InvalidMapping)?,
                application.artifact_physical(),
                artifact_bytes / PAGE_SIZE,
                PagePermissions::KERNEL_SHARED_READ,
            )
            .map_err(|_| KvmError::InvalidMapping)?,
            Mapping::new(
                VirtAddr::new(application.table_physical().get())
                    .map_err(|_| KvmError::InvalidMapping)?,
                application.table_physical(),
                application.table_pages(),
                PagePermissions::KERNEL_LOW_READ_WRITE,
            )
            .map_err(|_| KvmError::InvalidMapping)?,
        ] {
            tables.map(mapping).map_err(|_| KvmError::PageTable)?;
        }
        Ok(self)
    }

    pub fn service_eraser<'guest, 'artifact>(
        &'guest mut self,
        slot: usize,
        task: TaskId,
        service: &'guest VerifiedExecutable<'artifact>,
    ) -> KvmServiceEraser<'guest, 'artifact, N> {
        KvmServiceEraser {
            guest: self,
            service,
            slot,
            task,
        }
    }

    pub fn run_smp(&mut self) -> Result<(VmExit, VmExit), KvmError> {
        self.backend.run_smp()
    }
    pub const fn entry(&self) -> u64 {
        self.entry
    }
    pub const fn page_table_root(&self) -> PhysAddr {
        self.root
    }

    fn install_peer_page(&mut self, virtual_address: u64, physical: u64) -> Result<(), KvmError> {
        let mapping = Mapping::new(
            VirtAddr::new(virtual_address).map_err(|_| KvmError::InvalidMapping)?,
            PhysAddr::new(physical).map_err(|_| KvmError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        {
            let store = KvmPageTableStore::open_existing(
                &mut self.backend.memory,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .map(mapping)
                .and_then(|()| tables.verify_mapped(mapping))
                .map_err(|_| KvmError::PageTable)?;
        }
        self.backend.reload_exact_page_table_root(self.root.get())
    }

    fn withdraw_peer_page(&mut self, virtual_address: u64, physical: u64) -> Result<(), KvmError> {
        let mapping = Mapping::new(
            VirtAddr::new(virtual_address).map_err(|_| KvmError::InvalidMapping)?,
            PhysAddr::new(physical).map_err(|_| KvmError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        {
            let store = KvmPageTableStore::open_existing(
                &mut self.backend.memory,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .unmap_exact(mapping)
                .and_then(|()| tables.verify_unmapped(mapping))
                .map_err(|_| KvmError::PageTable)?;
        }
        self.backend.reload_exact_page_table_root(self.root.get())
    }

    fn peer_page_matches(&self, virtual_address: u64, physical: u64) -> Result<bool, KvmError> {
        Ok(self
            .page_walk(virtual_address)?
            .physical_address(virtual_address)
            == Some(physical))
    }

    /// Irreversibly removes the exact first-level trap leaf from this stopped
    /// guest before native execution is destroyed. No vCPU may run afterward;
    /// resumable live unmapping requires a separate TLB-coherent protocol.
    pub fn retire_trapped_mmio_before_destroy(&mut self, address: u64) -> Result<(), KvmError> {
        if self.trapped_mmio != Some(address)
            || !self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(KvmError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            self.table_physical,
            self.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, self.root);
        // From this point any page-table rejection is uncertain with respect
        // to executable translation state, so re-entry stays forbidden.
        self.trapped_mmio_retired = true;
        tables
            .unmap_exact(mapping)
            .and_then(|()| tables.verify_unmapped(mapping))
            .map_err(|_| KvmError::PageTable)?;
        self.trapped_mmio_mapped = false;
        Ok(())
    }

    /// Installs the exact configured non-global trap leaf and reloads the
    /// stopped sole vCPU's exact CR3 before permitting entry.
    pub fn install_trapped_mmio(&mut self, address: u64) -> Result<(), KvmError> {
        if self.trapped_mmio != Some(address)
            || self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(KvmError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        self.trapped_mmio_retired = true;
        {
            let store = KvmPageTableStore::open_existing(
                &mut self.backend.memory,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .map(mapping)
                .and_then(|()| tables.verify_mapped(mapping))
                .map_err(|_| KvmError::PageTable)?;
        }
        self.backend.reload_exact_page_table_root(self.root.get())?;
        self.trapped_mmio_mapped = true;
        self.trapped_mmio_retired = false;
        Ok(())
    }

    /// Removes the exact non-global trap leaf and reloads the stopped sole
    /// vCPU's exact CR3 before permitting re-entry. Any uncertain step leaves
    /// the guest permanently quarantined.
    pub fn withdraw_trapped_mmio(&mut self, address: u64) -> Result<(), KvmError> {
        if self.trapped_mmio != Some(address)
            || !self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(KvmError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        self.trapped_mmio_retired = true;
        {
            let store = KvmPageTableStore::open_existing(
                &mut self.backend.memory,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .unmap_exact(mapping)
                .and_then(|()| tables.verify_unmapped(mapping))
                .map_err(|_| KvmError::PageTable)?;
        }
        self.backend.reload_exact_page_table_root(self.root.get())?;
        self.trapped_mmio_mapped = false;
        self.trapped_mmio_retired = false;
        Ok(())
    }
    pub const fn service_entry(&self) -> Option<u64> {
        self.service_entry[0]
    }
    pub const fn service_page_table_root(&self) -> Option<PhysAddr> {
        self.service_root[0]
    }
    pub const fn service_entry_at(&self, slot: usize) -> Option<u64> {
        if slot < MAX_ISOLATED_SERVICES {
            self.service_entry[slot]
        } else {
            None
        }
    }
    pub const fn service_page_table_root_at(&self, slot: usize) -> Option<PhysAddr> {
        if slot < MAX_ISOLATED_SERVICES {
            self.service_root[slot]
        } else {
            None
        }
    }
    /// Recreates one stopped service's writable state from its exact verified
    /// artifact. The caller must have observed kernel retirement while the
    /// vCPU is stopped. Publication is cleared before the first write.
    pub fn reprovision_isolated_service_at(
        &mut self,
        slot: usize,
        service: &VerifiedExecutable<'_>,
    ) -> Result<(u64, PhysAddr), KvmError> {
        let instance = self
            .service_instance
            .get(slot)
            .and_then(|instance| *instance)
            .ok_or(KvmError::InvalidMapping)?;
        if service.artifact().kind() != ArtifactKind::ServiceImage
            || service.artifact().digest() != &instance.digest
            || u64::from(service.image().image_size()) != instance.image_bytes
        {
            return Err(KvmError::InvalidMapping);
        }
        let root = self.service_root[slot].ok_or(KvmError::InvalidMapping)?;
        self.service_entry[slot] = None;
        self.service_root[slot] = None;
        zero_kvm_range(
            &mut self.backend.memory,
            instance.image_physical,
            instance.image_bytes,
        )?;
        zero_kvm_range(
            &mut self.backend.memory,
            instance.stack_physical,
            instance.stack_bytes,
        )?;
        let loaded = self.backend.memory.load_verified_executable(
            service,
            instance.image_physical,
            instance.image_virtual,
        )?;
        self.service_entry[slot] = Some(loaded.entry());
        self.service_root[slot] = Some(root);
        Ok((loaded.entry(), root))
    }

    /// Installs one exact user read/write page into both already constructed
    /// service roots. The backing is a single host-owned guest frame; only the
    /// page-table leaves are shared.
    pub fn attach_service_shared_page(mut self, mapping: Mapping) -> Result<Self, KvmError> {
        if self.service_shared.is_some()
            || mapping.pages() != 1
            || mapping.permissions() != PagePermissions::USER_READ_WRITE
            || self.service_instance[..2].iter().any(Option::is_none)
        {
            return Err(KvmError::InvalidMapping);
        }
        self.backend
            .map_memory(mapping.physical_start().get(), PAGE_SIZE as usize, false)?;
        for slot in 0..2 {
            self.mutate_service_shared_leaf(slot, mapping, true)?;
            self.service_shared_live[slot] = true;
        }
        self.service_shared = Some(mapping);
        Ok(self)
    }

    /// Removes only the stopped task's exact shared leaf. The sibling root and
    /// common backing remain live. Subsequent service entry reloads CR3 with
    /// PCID disabled, flushing translations before any peer can continue.
    pub fn revoke_service_shared_page(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = self.service_shared.ok_or(KvmError::InvalidMapping)?;
        if slot >= 2 || !self.service_shared_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        self.mutate_service_shared_leaf(slot, mapping, false)?;
        self.service_shared_live[slot] = false;
        Ok(())
    }

    /// Accepts kernel-side retirement only after the stopped service's exact
    /// shared leaf is observably absent. Host bookkeeping changes after the
    /// complete read-only verification succeeds.
    pub fn observe_service_shared_page_revoked(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = self.service_shared.ok_or(KvmError::InvalidMapping)?;
        if slot >= 2 || !self.service_shared_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        let instance = self.service_instance[slot].ok_or(KvmError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(KvmError::InvalidMapping)?;
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            instance.table_physical,
            instance.table_pages,
        )?;
        PageTableBuilder::from_existing_root(store, root)
            .verify_unmapped(mapping)
            .map_err(|_| KvmError::PageTable)?;
        self.service_shared_live[slot] = false;
        Ok(())
    }

    /// Installs one independently backed user read/write resource into exactly
    /// one service root. Neither the sibling service nor the common diagnostic
    /// page receives an alias.
    pub fn attach_service_resource_page(
        mut self,
        slot: usize,
        mapping: Mapping,
    ) -> Result<Self, KvmError> {
        if slot >= 2
            || self.service_resource[slot].is_some()
            || mapping.pages() != 1
            || mapping.permissions() != PagePermissions::USER_READ_WRITE
            || self.service_instance[slot].is_none()
            || self.service_shared.is_some_and(|shared| {
                shared.virtual_start() == mapping.virtual_start()
                    || shared.physical_start() == mapping.physical_start()
            })
            || self.service_resource.iter().flatten().any(|existing| {
                existing.physical_start() == mapping.physical_start()
                    || existing.virtual_start() == mapping.virtual_start()
            })
        {
            return Err(KvmError::InvalidMapping);
        }
        self.backend
            .map_memory(mapping.physical_start().get(), PAGE_SIZE as usize, false)?;
        self.mutate_service_resource_leaf(slot, mapping, true, true)?;
        self.service_resource[slot] = Some(mapping);
        self.service_resource_live[slot] = true;
        Ok(self)
    }

    pub fn revoke_service_resource_page(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(KvmError::InvalidMapping)?;
        if !self.service_resource_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        self.mutate_service_resource_leaf(slot, mapping, false, false)?;
        self.service_resource_live[slot] = false;
        Ok(())
    }

    pub fn observe_service_resource_page_revoked(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(KvmError::InvalidMapping)?;
        if !self.service_resource_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        self.verify_service_mapping_absent(slot, mapping)?;
        self.service_resource_live[slot] = false;
        Ok(())
    }

    pub fn restore_service_resource_page(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(KvmError::InvalidMapping)?;
        if self.service_resource_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        zero_kvm_range(
            &mut self.backend.memory,
            mapping.physical_start().get(),
            PAGE_SIZE,
        )?;
        self.mutate_service_resource_leaf(slot, mapping, true, false)?;
        self.service_resource_live[slot] = true;
        Ok(())
    }

    /// Re-arms the exact leaf only for a freshly created task generation.
    pub fn restore_service_shared_page(&mut self, slot: usize) -> Result<(), KvmError> {
        let mapping = self.service_shared.ok_or(KvmError::InvalidMapping)?;
        if slot >= 2 || self.service_shared_live[slot] {
            return Err(KvmError::InvalidMapping);
        }
        self.mutate_service_shared_leaf(slot, mapping, true)?;
        self.service_shared_live[slot] = true;
        Ok(())
    }

    fn mutate_service_shared_leaf(
        &mut self,
        slot: usize,
        mapping: Mapping,
        install: bool,
    ) -> Result<(), KvmError> {
        let initial = self.service_shared.is_none();
        let instance = self.service_instance[slot].ok_or(KvmError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(KvmError::InvalidMapping)?;
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            instance.table_physical,
            instance.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, root);
        let supervisor = Mapping::new(
            VirtAddr::new(mapping.physical_start().get()).map_err(|_| KvmError::InvalidMapping)?,
            mapping.physical_start(),
            1,
            PagePermissions::KERNEL_LOW_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        if install {
            if initial {
                tables.map(supervisor).and_then(|_| tables.map(mapping))
            } else {
                tables.map(mapping)
            }
        } else {
            tables.unmap_exact(mapping)
        }
        .map_err(|_| KvmError::PageTable)
    }

    fn mutate_service_resource_leaf(
        &mut self,
        slot: usize,
        mapping: Mapping,
        install: bool,
        initial: bool,
    ) -> Result<(), KvmError> {
        let instance = self.service_instance[slot].ok_or(KvmError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(KvmError::InvalidMapping)?;
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            instance.table_physical,
            instance.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, root);
        let supervisor = Mapping::new(
            VirtAddr::new(mapping.physical_start().get()).map_err(|_| KvmError::InvalidMapping)?,
            mapping.physical_start(),
            1,
            PagePermissions::KERNEL_LOW_READ_WRITE,
        )
        .map_err(|_| KvmError::InvalidMapping)?;
        if install {
            if initial {
                tables.map(supervisor).and_then(|_| tables.map(mapping))
            } else {
                tables.map(mapping)
            }
        } else {
            tables.unmap_exact(mapping)
        }
        .map_err(|_| KvmError::PageTable)
    }

    fn verify_service_mapping_absent(
        &mut self,
        slot: usize,
        mapping: Mapping,
    ) -> Result<(), KvmError> {
        let instance = self.service_instance[slot].ok_or(KvmError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(KvmError::InvalidMapping)?;
        let store = KvmPageTableStore::open_existing(
            &mut self.backend.memory,
            instance.table_physical,
            instance.table_pages,
        )?;
        PageTableBuilder::from_existing_root(store, root)
            .verify_unmapped(mapping)
            .map_err(|_| KvmError::PageTable)
    }
    pub fn snapshot(&self) -> Result<KvmVcpuSnapshot, KvmError> {
        self.backend.snapshot()
    }
    pub fn page_walk(&self, virtual_address: u64) -> Result<KvmPageWalk, KvmError> {
        if ((virtual_address << 16) as i64 >> 16) as u64 != virtual_address {
            return Err(KvmError::InvalidMapping);
        }
        let indexes = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let mut entries = [0u64; 4];
        let mut table = self.root.get();
        let mut levels = 0u8;
        for (level, index) in indexes.into_iter().enumerate() {
            let address = table
                .checked_add((index as u64) * 8)
                .ok_or(KvmError::MemoryOverflow)?;
            let mut encoded = [0u8; 8];
            self.backend.read_guest(address, &mut encoded)?;
            let entry = u64::from_le_bytes(encoded);
            entries[level] = entry;
            levels += 1;
            if entry & 1 == 0 || (level < 3 && entry & (1 << 7) != 0) {
                break;
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
        Ok(KvmPageWalk { entries, levels })
    }

    /// Registers the two validated mediated-GPU rings as dedicated KVM memory
    /// slots. The command ring is guest-writable; the completion ring is KVM
    /// read-only to the guest and remains writable by the isolated host GPU
    /// service. Consuming `self` makes failure transactional from the caller's
    /// perspective: a partially attached VM is dropped and cannot be run.
    pub fn attach_gpu_queue_memory(
        mut self,
        layout: GpuSharedQueueLayout,
    ) -> Result<Self, KvmError> {
        let bytes = layout
            .pages_per_ring()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        let bytes = usize::try_from(bytes).map_err(|_| KvmError::MemoryOverflow)?;
        self.backend
            .map_memory(layout.command_base(), bytes, false)?;
        self.backend
            .map_memory(layout.completion_base(), bytes, true)?;
        Ok(self)
    }

    /// Registers one validated MRML virtual-block request/completion pair as
    /// dedicated KVM memory slots. Requests are guest-writable; completions are
    /// guest-read-only and remain writable through `VirtualBlockVmmMemory`.
    /// Consuming `self` prevents a partially attached VM from being resumed if
    /// either native mapping fails.
    pub fn attach_virtual_block_queue_memory(
        mut self,
        layout: VirtualBlockQueueLayout,
    ) -> Result<Self, KvmError> {
        let bytes = layout
            .pages_per_queue()
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        let bytes = usize::try_from(bytes).map_err(|_| KvmError::MemoryOverflow)?;
        self.backend
            .map_memory(layout.request_base(), bytes, false)?;
        self.backend
            .map_memory(layout.completion_base(), bytes, true)?;
        Ok(self)
    }

    /// Adds one separately authenticated service image and constructs a fresh
    /// root containing supervisor-only kernel PE mappings plus only that
    /// service's user PE and guarded stack mapping.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_isolated_service(
        self,
        kernel: &VerifiedExecutable<'_>,
        kernel_layout: KvmLaunchLayout,
        service: &VerifiedExecutable<'_>,
        service_physical: u64,
        service_virtual: u64,
        stack_physical: u64,
        stack_virtual: u64,
        stack_pages: u64,
        table_physical: u64,
        table_pages: u64,
    ) -> Result<Self, KvmError> {
        self.attach_isolated_service_at(
            0,
            kernel,
            kernel_layout,
            service,
            service_physical,
            service_virtual,
            stack_physical,
            stack_virtual,
            stack_pages,
            table_physical,
            table_pages,
            false,
        )
    }

    /// Atomically prepares the two exact service images retained by one
    /// generation-bound component launch. A digest/kind mismatch is rejected
    /// before either KVM memory slot is created; failure while attaching the
    /// second image consumes and drops the unpublished guest builder.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_component_service_pair(
        self,
        launch: &PreparedComponentServiceLaunch,
        kernel: &VerifiedExecutable<'_>,
        kernel_layout: KvmLaunchLayout,
        consumer: &VerifiedExecutable<'_>,
        consumer_physical: u64,
        consumer_virtual: u64,
        consumer_stack_physical: u64,
        consumer_stack_virtual: u64,
        consumer_stack_pages: u64,
        consumer_table_physical: u64,
        consumer_table_pages: u64,
        provider: &VerifiedExecutable<'_>,
        provider_physical: u64,
        provider_virtual: u64,
        provider_stack_physical: u64,
        provider_stack_virtual: u64,
        provider_stack_pages: u64,
        provider_table_physical: u64,
        provider_table_pages: u64,
        local_apic: bool,
    ) -> Result<Self, KvmError> {
        launch
            .verify_artifacts(
                consumer.artifact().kind(),
                consumer.artifact().digest(),
                provider.artifact().kind(),
                provider.artifact().digest(),
            )
            .map_err(|_| KvmError::InvalidMapping)?;
        let guest = self.attach_isolated_service_at(
            0,
            kernel,
            kernel_layout,
            consumer,
            consumer_physical,
            consumer_virtual,
            consumer_stack_physical,
            consumer_stack_virtual,
            consumer_stack_pages,
            consumer_table_physical,
            consumer_table_pages,
            local_apic,
        )?;
        guest.attach_isolated_service_at(
            1,
            kernel,
            kernel_layout,
            provider,
            provider_physical,
            provider_virtual,
            provider_stack_physical,
            provider_stack_virtual,
            provider_stack_pages,
            provider_table_physical,
            provider_table_pages,
            local_apic,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attach_isolated_service_at(
        mut self,
        slot: usize,
        kernel: &VerifiedExecutable<'_>,
        kernel_layout: KvmLaunchLayout,
        service: &VerifiedExecutable<'_>,
        service_physical: u64,
        service_virtual: u64,
        stack_physical: u64,
        stack_virtual: u64,
        stack_pages: u64,
        table_physical: u64,
        table_pages: u64,
        local_apic: bool,
    ) -> Result<Self, KvmError> {
        if slot >= MAX_ISOLATED_SERVICES
            || self.service_root[slot].is_some()
            || kernel.artifact().kind() != ArtifactKind::Kernel
            || service.artifact().kind() != ArtifactKind::ServiceImage
            || stack_pages == 0
            || table_pages < 4
            || service_virtual == 0
            || service_virtual >= 1 << 47
            || !(PAGE_SIZE..1 << 47).contains(&stack_virtual)
            || [
                service_physical,
                stack_physical,
                table_physical,
                service_virtual,
                stack_virtual,
            ]
            .iter()
            .any(|address| !address.is_multiple_of(PAGE_SIZE))
        {
            return Err(KvmError::InvalidMapping);
        }
        let image_bytes = page_bytes(service.image().image_size() as u64)?;
        let stack_bytes = stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        let table_bytes = table_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        validate_ranges(&[
            (service_physical, image_bytes),
            (stack_physical, stack_bytes),
            (table_physical, table_bytes),
        ])?;
        validate_ranges(&[
            (service_virtual, image_bytes),
            (
                stack_virtual - PAGE_SIZE,
                stack_bytes
                    .checked_add(PAGE_SIZE)
                    .ok_or(KvmError::MemoryOverflow)?,
            ),
        ])?;
        self.backend
            .map_memory(service_physical, image_bytes as usize, false)?;
        self.backend
            .map_memory(stack_physical, stack_bytes as usize, false)?;
        self.backend
            .map_memory(table_physical, table_bytes as usize, false)?;
        let loaded_service = self.backend.memory.load_verified_executable(
            service,
            service_physical,
            service_virtual,
        )?;
        let loaded_kernel = super::KvmLoadedImage {
            entry: self.entry,
            virtual_base: kernel_layout.image_virtual,
            physical_base: kernel_layout.image_physical,
            image_bytes: kernel.image().image_size(),
        };
        let mut tables = self.backend.page_tables(table_physical, table_pages)?;
        map_loaded_pe(&mut tables, kernel, loaded_kernel, false)?;
        map_loaded_pe(&mut tables, service, loaded_service, true)?;
        let kernel_cpus = if kernel_layout.stack_virtual == kernel_layout.stack_physical {
            2u64
        } else {
            1u64
        };
        let kernel_stack_stride = kernel_layout
            .stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        for cpu in 0..kernel_cpus {
            let offset = cpu
                .checked_mul(kernel_stack_stride)
                .ok_or(KvmError::MemoryOverflow)?;
            let kernel_stack = PrivilegeStackLayout::new(
                kernel_layout
                    .stack_virtual
                    .checked_add(offset)
                    .ok_or(KvmError::MemoryOverflow)?,
                kernel_layout.stack_pages,
            )
            .map_err(|_| KvmError::InvalidMapping)?;
            let kernel_stack_physical = PrivilegeStackLayout::new(
                kernel_layout
                    .stack_physical
                    .checked_add(offset)
                    .ok_or(KvmError::MemoryOverflow)?,
                kernel_layout.stack_pages,
            )
            .map_err(|_| KvmError::InvalidMapping)?;
            for (virtual_base, physical_base, pages) in [
                (
                    kernel_stack.entry_base(),
                    kernel_stack_physical.entry_base(),
                    kernel_stack.entry_pages(),
                ),
                (
                    kernel_stack.double_fault_base(),
                    kernel_stack_physical.double_fault_base(),
                    kernel_stack.double_fault_pages(),
                ),
            ] {
                let virtual_base = virtual_base.map_err(|_| KvmError::InvalidMapping)?;
                let permissions = if virtual_base < 1 << 47 {
                    PagePermissions::KERNEL_LOW_READ_WRITE
                } else {
                    PagePermissions::KERNEL_READ_WRITE
                };
                tables
                    .map(
                        Mapping::new(
                            VirtAddr::new(virtual_base).map_err(|_| KvmError::InvalidMapping)?,
                            PhysAddr::new(physical_base.map_err(|_| KvmError::InvalidMapping)?)
                                .map_err(|_| KvmError::InvalidMapping)?,
                            pages,
                            permissions,
                        )
                        .map_err(|_| KvmError::InvalidMapping)?,
                    )
                    .map_err(|_| KvmError::PageTable)?;
            }
        }
        if local_apic {
            tables
                .map_page(
                    VirtAddr::new(XAPIC_BASE).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(XAPIC_BASE).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_MMIO_READ_WRITE,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(stack_virtual).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(stack_physical).map_err(|_| KvmError::InvalidMapping)?,
                    stack_pages,
                    PagePermissions::USER_READ_WRITE,
                )
                .map_err(|_| KvmError::InvalidMapping)?,
            )
            .map_err(|_| KvmError::PageTable)?;
        tables
            .map_page(
                VirtAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                PhysAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                PagePermissions::KERNEL_LOW_READ_WRITE,
            )
            .map_err(|_| KvmError::PageTable)?;
        let mut frame_index = 0;
        while frame_index < tables.store().allocated_pages() {
            let frame = tables
                .store()
                .allocated_frame(frame_index)
                .ok_or(KvmError::PageTable)?;
            tables
                .map_page(
                    VirtAddr::new(frame.get()).map_err(|_| KvmError::InvalidMapping)?,
                    frame,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| KvmError::PageTable)?;
            frame_index += 1;
        }
        tables
            .unmap_exact(
                Mapping::new(
                    VirtAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                    1,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| KvmError::InvalidMapping)?,
            )
            .map_err(|_| KvmError::PageTable)?;
        let root = tables.root();
        let _ = tables.into_store();
        self.service_entry[slot] = Some(loaded_service.entry());
        self.service_root[slot] = Some(root);
        self.service_instance[slot] = Some(ServiceInstance {
            digest: *service.artifact().digest(),
            image_physical: service_physical,
            image_virtual: service_virtual,
            image_bytes,
            stack_physical,
            stack_bytes,
            table_physical,
            table_pages,
        });
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KvmPageWalk {
    entries: [u64; 4],
    levels: u8,
}

impl KvmPageWalk {
    pub const fn entries(self) -> [u64; 4] {
        self.entries
    }
    pub const fn levels(self) -> u8 {
        self.levels
    }
    pub fn physical_address(self, virtual_address: u64) -> Option<u64> {
        if self.levels != 4 || self.entries[3] & 1 == 0 {
            return None;
        }
        (self.entries[3] & 0x000f_ffff_ffff_f000).checked_add(virtual_address & 0xfff)
    }
}

impl<const N: usize> VmBackend for PreparedKvmGuest<N> {
    type Error = KvmError;
    fn run(&mut self, vcpu: u32) -> Result<VmExit, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(KvmError::InvalidMapping);
        }
        self.backend.run(vcpu)
    }
    fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.backend.read_guest(address, output)
    }
    fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.backend.write_guest(address, input)
    }
    fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error> {
        self.backend.inject_interrupt(vcpu, vector)
    }
}

impl<const N: usize> DeadlineVmBackend for PreparedKvmGuest<N> {
    fn run_with_deadline(
        &mut self,
        vcpu: u32,
        maximum_micros: u32,
    ) -> Result<mrml_kernel::VmDeadlineOutcome, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(KvmError::InvalidMapping);
        }
        self.backend.run_with_deadline(vcpu, maximum_micros)
    }
}

impl<const N: usize> mrml_kernel::AffinityDeadlineVmBackend for PreparedKvmGuest<N> {
    fn run_with_affinity_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        maximum_micros: u32,
    ) -> Result<mrml_kernel::VmDeadlineOutcome, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(KvmError::InvalidMapping);
        }
        self.backend
            .run_with_affinity_deadline(vcpu, logical_cpu, maximum_micros)
    }
}

impl<const N: usize> mrml_kernel::ScheduledDeadlineVmBackend for PreparedKvmGuest<N> {
    fn run_with_scheduling_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        priority: u8,
        maximum_micros: u32,
    ) -> Result<mrml_kernel::VmDeadlineOutcome, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(KvmError::InvalidMapping);
        }
        self.backend
            .run_with_scheduling_deadline(vcpu, logical_cpu, priority, maximum_micros)
    }
}

impl<const N: usize> mrml_kernel::ScheduledSmpVmBackend for PreparedKvmGuest<N> {
    fn run_smp_with_scheduling_deadlines(
        &mut self,
        logical_cpus: [u8; 2],
        priorities: [u8; 2],
        maximum_micros: [u32; 2],
    ) -> Result<[mrml_kernel::ScheduledVcpuOutcome; 2], Self::Error> {
        if self.trapped_mmio_retired {
            return Err(KvmError::InvalidMapping);
        }
        self.backend
            .run_smp_with_scheduling_deadlines(logical_cpus, priorities, maximum_micros)
    }
}

impl<const N: usize> mrml_kernel::IoReadCompleter for PreparedKvmGuest<N> {
    fn complete_io_read(
        &mut self,
        vcpu: u32,
        port: u16,
        size: u8,
        value: u32,
    ) -> Result<(), Self::Error> {
        self.backend.complete_io_read(vcpu, port, size, value)
    }
}

impl<const N: usize> mrml_kernel::MmioWriteCompleter for PreparedKvmGuest<N> {
    fn complete_mmio_write(
        &mut self,
        vcpu: u32,
        guest_address: u64,
        size: u8,
        value: u64,
    ) -> Result<(), Self::Error> {
        self.backend
            .complete_mmio_write(vcpu, guest_address, size, value)
    }
}

impl<const N: usize> RevocableVmBackend for PreparedKvmGuest<N> {
    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error> {
        self.backend.revoke_guest_mapping(guest_address, bytes)
    }
}

impl<const N: usize> GpuVmmMemory for PreparedKvmGuest<N> {
    fn write_gpu_service(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.backend.memory.write_service(address, input)
    }
}

impl<const N: usize> VirtualBlockVmmMemory for PreparedKvmGuest<N> {
    fn write_virtual_block(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.backend.memory.write_service(address, input)
    }
}

impl KvmSystem {
    pub fn prepare_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: false,
                local_apic: false,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares a kernel guest and maps the authenticated handoff framebuffer
    /// as writable, non-executable memory at its identity address.
    pub fn prepare_kernel_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: false,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares the hosted service kernel with one supervisor-only identity
    /// mapping for the later shared service-launch metadata page.
    pub fn prepare_isolated_service_kernel_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: false,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 1,
                service_shared: true,
            },
        )
    }

    /// Prepares one hosted service domain with two vCPUs behind KVM's in-kernel
    /// interrupt controller. The authenticated SMP handoff and component pair
    /// remain part of one guest construction transaction.
    pub fn prepare_isolated_service_smp_kernel_guest<const N: usize>(
        &self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            0,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: true,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 2,
                service_shared: true,
            },
        )
    }

    /// Prepares a kernel guest with an in-kernel local APIC and its MMIO page.
    pub fn prepare_timer_kernel_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: true,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares two KVM vCPUs behind the in-kernel interrupt controller. The
    /// handoff must bind a two-CPU MADT, low trampoline, and stack arena.
    pub fn prepare_smp_kernel_guest<const N: usize>(
        &self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            0,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: true,
                gpu_queue: None,
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 2,
                service_shared: false,
            },
        )
    }

    /// Prepares a kernel guest with its authenticated framebuffer and mediated
    /// GPU rings present in the initial address space. Both rings are identity
    /// mapped NX; only the command ring is guest-writable.
    pub fn prepare_kernel_gpu_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
        queue: GpuSharedQueueLayout,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: false,
                gpu_queue: Some(queue),
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares a kernel guest with one MRML-specific virtual-block queue in
    /// its initial address space. Request pages are writable/NX and completion
    /// pages are read-only/NX to the guest while retaining device-path writes.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_kernel_block_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: false,
                gpu_queue: None,
                block_queue: Some(queue),
                block_configuration: Some(configuration),
                block_resume: Some(resume),
                trapped_mmio: None,
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares the MRML-native block queue plus one first-level MMIO trap
    /// page. No second-level RAM slot is created for the page.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_kernel_block_mmio_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
        mmio_address: u64,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        if !mmio_address.is_multiple_of(PAGE_SIZE) {
            return Err(KvmError::InvalidMapping);
        }
        self.prepare_guest_inner(
            vcpu_id,
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: true,
                local_apic: false,
                gpu_queue: None,
                block_queue: Some(queue),
                block_configuration: Some(configuration),
                block_resume: Some(resume),
                trapped_mmio: Some(mmio_address),
                cpus: 1,
                service_shared: false,
            },
        )
    }

    /// Prepares the bounded translation path, removes its exact MMIO leaf while
    /// the guest is still non-runnable, and returns it for mapper installation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_kernel_block_dynamic_mmio_guest<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
        mmio_address: u64,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        if !mmio_address.is_multiple_of(PAGE_SIZE) {
            return Err(KvmError::InvalidMapping);
        }
        let mut guest = self.prepare_kernel_block_mmio_guest(
            vcpu_id,
            executable,
            handoff,
            layout,
            queue,
            configuration,
            resume,
            mmio_address,
        )?;
        guest.withdraw_trapped_mmio(mmio_address)?;
        Ok(guest)
    }

    fn prepare_guest_inner<const N: usize>(
        &self,
        vcpu_id: u32,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: KvmLaunchLayout,
        devices: KernelDevices,
    ) -> Result<PreparedKvmGuest<N>, KvmError> {
        let map_framebuffer = devices.framebuffer;
        let local_apic = devices.local_apic;
        let queue = devices.gpu_queue;
        let block_queue = devices.block_queue;
        let block_configuration = devices.block_configuration;
        let block_resume = devices.block_resume;
        let trapped_mmio = devices.trapped_mmio;
        let smp = devices.cpus == 2;
        if !matches!(devices.cpus, 1 | 2)
            || N < 4
                + usize::from(map_framebuffer)
                + usize::from(queue.is_some()) * 2
                + usize::from(block_queue.is_some()) * 2
                + usize::from(block_configuration.is_some())
                + usize::from(block_resume.is_some())
                + usize::from(smp)
        {
            return Err(KvmError::MemoryTableFull);
        }
        if block_configuration
            .is_some_and(|configuration| block_queue != Some(configuration.configuration().queue()))
            || block_resume.is_some_and(|resume| {
                block_configuration.is_none_or(|configuration| {
                    resume.state().configuration() != configuration.configuration()
                        || resume.configuration_base() != configuration.base()
                })
            })
            || block_configuration.is_some() != block_resume.is_some()
        {
            return Err(KvmError::InvalidMapping);
        }
        let decoded = BootHandoff::decode(handoff, |_| {}).map_err(KvmError::Handoff)?;
        let trampoline = match (
            smp,
            decoded.ap_trampoline(),
            decoded.ap_stack_arena(),
            decoded.madt(handoff),
        ) {
            (true, Some(page), Some(arena), Some(_))
                if arena == layout.stack_physical
                    && layout.stack_virtual == layout.stack_physical =>
            {
                page
            }
            (false, None, None, _) => 0,
            _ => return Err(KvmError::InvalidMapping),
        };
        let image_bytes = page_bytes(executable.image().image_size() as u64)?;
        let handoff_bytes = page_bytes(handoff.len() as u64)?;
        let table_bytes = layout
            .table_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(KvmError::MemoryOverflow)?;
        let stack_bytes = layout
            .stack_pages
            .checked_mul(u64::from(devices.cpus))
            .and_then(|pages| pages.checked_mul(PAGE_SIZE))
            .ok_or(KvmError::MemoryOverflow)?;
        if smp {
            PerCpuPrivilegeStacks::<2>::new(
                layout.stack_physical,
                layout.stack_virtual,
                layout.stack_pages,
            )
            .map_err(|_| KvmError::InvalidMapping)?;
        }
        let stack_layout = PrivilegeStackLayout::new(layout.stack_virtual, layout.stack_pages)
            .map_err(|_| KvmError::InvalidMapping)?;
        let physical_stack = PrivilegeStackLayout::new(layout.stack_physical, layout.stack_pages)
            .map_err(|_| KvmError::InvalidMapping)?;
        let framebuffer = decoded.framebuffer();
        let framebuffer_bytes = page_bytes(framebuffer.byte_length())?;
        let queue_bytes = match queue {
            Some(value) => value
                .pages_per_ring()
                .checked_mul(PAGE_SIZE)
                .ok_or(KvmError::MemoryOverflow)?,
            None => PAGE_SIZE,
        };
        let (command_base, completion_base) = queue
            .map(|value| (value.command_base(), value.completion_base()))
            .unwrap_or((0, 0));
        let block_queue_bytes = match block_queue {
            Some(value) => value
                .pages_per_queue()
                .checked_mul(PAGE_SIZE)
                .ok_or(KvmError::MemoryOverflow)?,
            None => PAGE_SIZE,
        };
        let (block_request_base, block_completion_base) = block_queue
            .map(|value| (value.request_base(), value.completion_base()))
            .unwrap_or((0, 0));
        if smp {
            validate_ranges(&[
                (layout.table_physical, table_bytes),
                (layout.image_physical, image_bytes),
                (layout.handoff_physical, handoff_bytes),
                (layout.stack_physical, stack_bytes),
                (framebuffer.base().get(), framebuffer_bytes),
                (trampoline, PAGE_SIZE),
            ])?;
            validate_ranges(&[
                (layout.image_virtual, image_bytes),
                (layout.handoff_virtual, handoff_bytes),
                (layout.stack_virtual, stack_bytes),
                (trampoline, PAGE_SIZE),
            ])?;
        } else {
            let mut physical_ranges = [(0, 0); 11];
            physical_ranges[..4].copy_from_slice(&[
                (layout.table_physical, table_bytes),
                (layout.image_physical, image_bytes),
                (layout.handoff_physical, handoff_bytes),
                (layout.stack_physical, stack_bytes),
            ]);
            let mut physical_count = 4;
            if map_framebuffer {
                physical_ranges[physical_count] = (framebuffer.base().get(), framebuffer_bytes);
                physical_count += 1;
            }
            if queue.is_some() {
                physical_ranges[physical_count] = (command_base, queue_bytes);
                physical_ranges[physical_count + 1] = (completion_base, queue_bytes);
                physical_count += 2;
            }
            if block_queue.is_some() {
                physical_ranges[physical_count] = (block_request_base, block_queue_bytes);
                physical_ranges[physical_count + 1] = (block_completion_base, block_queue_bytes);
                physical_count += 2;
            }
            if let Some(configuration) = block_configuration {
                physical_ranges[physical_count] = (configuration.base(), PAGE_SIZE);
                physical_count += 1;
            }
            if let Some(resume) = block_resume {
                physical_ranges[physical_count] = (resume.base(), PAGE_SIZE);
                physical_count += 1;
            }
            validate_ranges(&physical_ranges[..physical_count])?;
            let mut virtual_ranges = [(0, 0); 10];
            virtual_ranges[..3].copy_from_slice(&[
                (layout.image_virtual, image_bytes),
                (layout.handoff_virtual, handoff_bytes),
                (layout.stack_virtual, stack_bytes),
            ]);
            let mut virtual_count = 3;
            if queue.is_some() {
                virtual_ranges[virtual_count] = (command_base, queue_bytes);
                virtual_ranges[virtual_count + 1] = (completion_base, queue_bytes);
                virtual_count += 2;
            }
            if block_queue.is_some() {
                virtual_ranges[virtual_count] = (block_request_base, block_queue_bytes);
                virtual_ranges[virtual_count + 1] = (block_completion_base, block_queue_bytes);
                virtual_count += 2;
            }
            if let Some(configuration) = block_configuration {
                virtual_ranges[virtual_count] = (configuration.base(), PAGE_SIZE);
                virtual_count += 1;
            }
            if let Some(resume) = block_resume {
                virtual_ranges[virtual_count] = (resume.base(), PAGE_SIZE);
                virtual_count += 1;
            }
            if let Some(address) = trapped_mmio {
                virtual_ranges[virtual_count] = (address, PAGE_SIZE);
                virtual_count += 1;
            }
            validate_ranges(&virtual_ranges[..virtual_count])?;
        }

        let mut backend = if smp {
            self.create_smp_backend::<N>()?
        } else if local_apic {
            self.create_apic_backend::<N>(vcpu_id)?
        } else {
            self.create_backend::<N>(vcpu_id)?
        };
        backend.map_memory(layout.table_physical, table_bytes as usize, false)?;
        backend.map_memory(layout.image_physical, image_bytes as usize, false)?;
        backend.map_memory(layout.handoff_physical, handoff_bytes as usize, false)?;
        backend.map_memory(layout.stack_physical, stack_bytes as usize, false)?;
        if smp {
            backend.map_memory(trampoline, PAGE_SIZE as usize, false)?;
        }
        if map_framebuffer {
            backend.map_memory(framebuffer.base().get(), framebuffer_bytes as usize, false)?;
        }
        if let Some(queue) = queue {
            let bytes = usize::try_from(queue_bytes).map_err(|_| KvmError::MemoryOverflow)?;
            backend.map_memory(queue.command_base(), bytes, false)?;
            backend.map_memory(queue.completion_base(), bytes, true)?;
        }
        if let Some(queue) = block_queue {
            let bytes = usize::try_from(block_queue_bytes).map_err(|_| KvmError::MemoryOverflow)?;
            backend.map_memory(queue.request_base(), bytes, false)?;
            backend.map_memory(queue.completion_base(), bytes, true)?;
        }
        if let Some(configuration) = block_configuration {
            backend.map_memory(configuration.base(), PAGE_SIZE as usize, true)?;
            let mut encoded = [0; PAGE_SIZE as usize];
            configuration.encode_page(&mut encoded);
            backend
                .memory
                .write_service(configuration.base(), &encoded)?;
        }
        if let Some(resume) = block_resume {
            backend.map_memory(resume.base(), PAGE_SIZE as usize, true)?;
            let mut encoded = [0; PAGE_SIZE as usize];
            resume.encode_page(&mut encoded);
            backend.memory.write_service(resume.base(), &encoded)?;
        }
        let loaded_image = backend.memory.load_verified_executable(
            executable,
            layout.image_physical,
            layout.image_virtual,
        )?;
        let loaded_handoff = backend
            .memory
            .load_boot_handoff(handoff, layout.handoff_physical)?;
        backend.memory.write(
            physical_stack
                .early_top()
                .map_err(|_| KvmError::MemoryOverflow)?,
            &0u64.to_le_bytes(),
        )?;
        let stack = stack_layout
            .early_top()
            .map_err(|_| KvmError::MemoryOverflow)?;
        let mut tables = backend.page_tables(layout.table_physical, layout.table_pages)?;
        map_loaded_pe(&mut tables, executable, loaded_image, layout.user)?;
        map_loaded_handoff(
            &mut tables,
            loaded_handoff,
            layout.handoff_virtual,
            layout.user,
        )?;
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(layout.table_physical).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(layout.table_physical).map_err(|_| KvmError::InvalidMapping)?,
                    layout.table_pages,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| KvmError::InvalidMapping)?,
            )
            .map_err(|_| KvmError::PageTable)?;
        let stack_permissions = if smp {
            PagePermissions::KERNEL_LOW_READ_WRITE
        } else {
            PagePermissions::KERNEL_READ_WRITE
        };
        for cpu in 0..usize::from(devices.cpus) {
            let offset = (cpu as u64)
                .checked_mul(layout.stack_pages)
                .and_then(|pages| pages.checked_mul(PAGE_SIZE))
                .ok_or(KvmError::MemoryOverflow)?;
            let virtual_stack = PrivilegeStackLayout::new(
                layout
                    .stack_virtual
                    .checked_add(offset)
                    .ok_or(KvmError::MemoryOverflow)?,
                layout.stack_pages,
            )
            .map_err(|_| KvmError::InvalidMapping)?;
            let physical_stack = PrivilegeStackLayout::new(
                layout
                    .stack_physical
                    .checked_add(offset)
                    .ok_or(KvmError::MemoryOverflow)?,
                layout.stack_pages,
            )
            .map_err(|_| KvmError::InvalidMapping)?;
            for (virtual_base, physical_base, pages, permissions) in [
                (
                    virtual_stack.early_base(),
                    physical_stack.early_base(),
                    virtual_stack.early_pages(),
                    stack_permissions,
                ),
                (
                    virtual_stack
                        .entry_base()
                        .map_err(|_| KvmError::MemoryOverflow)?,
                    physical_stack
                        .entry_base()
                        .map_err(|_| KvmError::MemoryOverflow)?,
                    virtual_stack.entry_pages(),
                    stack_permissions,
                ),
                (
                    virtual_stack
                        .double_fault_base()
                        .map_err(|_| KvmError::MemoryOverflow)?,
                    physical_stack
                        .double_fault_base()
                        .map_err(|_| KvmError::MemoryOverflow)?,
                    virtual_stack.double_fault_pages(),
                    stack_permissions,
                ),
            ] {
                tables
                    .map(
                        Mapping::new(
                            VirtAddr::new(virtual_base).map_err(|_| KvmError::InvalidMapping)?,
                            PhysAddr::new(physical_base).map_err(|_| KvmError::InvalidMapping)?,
                            pages,
                            permissions,
                        )
                        .map_err(|_| KvmError::InvalidMapping)?,
                    )
                    .map_err(|_| KvmError::PageTable)?;
            }
        }
        if smp {
            tables
                .map_page(
                    VirtAddr::new(trampoline).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(trampoline).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if let Some(address) = trapped_mmio {
            tables
                .map_page(
                    VirtAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(address).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_MMIO_READ_WRITE,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if local_apic {
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(XAPIC_BASE).map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(XAPIC_BASE).map_err(|_| KvmError::InvalidMapping)?,
                        1,
                        PagePermissions::KERNEL_MMIO_READ_WRITE,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if devices.service_shared {
            tables
                .map_page(
                    VirtAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(0x00f0_0000).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if map_framebuffer {
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(framebuffer.base().get())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(framebuffer.base().get())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        framebuffer_bytes / PAGE_SIZE,
                        PagePermissions::KERNEL_MMIO_READ_WRITE,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if let Some(queue) = queue {
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(queue.command_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(queue.command_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        queue.pages_per_ring(),
                        PagePermissions::KERNEL_SHARED_READ_WRITE,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(queue.completion_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(queue.completion_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        queue.pages_per_ring(),
                        PagePermissions::KERNEL_SHARED_READ,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if let Some(queue) = block_queue {
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(queue.request_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(queue.request_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        queue.pages_per_queue(),
                        PagePermissions::KERNEL_SHARED_READ_WRITE,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(queue.completion_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        PhysAddr::new(queue.completion_base())
                            .map_err(|_| KvmError::InvalidMapping)?,
                        queue.pages_per_queue(),
                        PagePermissions::KERNEL_SHARED_READ,
                    )
                    .map_err(|_| KvmError::InvalidMapping)?,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if let Some(configuration) = block_configuration {
            tables
                .map_page(
                    VirtAddr::new(configuration.base()).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(configuration.base()).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_SHARED_READ,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        if let Some(resume) = block_resume {
            tables
                .map_page(
                    VirtAddr::new(resume.base()).map_err(|_| KvmError::InvalidMapping)?,
                    PhysAddr::new(resume.base()).map_err(|_| KvmError::InvalidMapping)?,
                    PagePermissions::KERNEL_SHARED_READ,
                )
                .map_err(|_| KvmError::PageTable)?;
        }
        let root = tables.root();
        let _ = tables.into_store();
        backend.vcpu.configure_long_mode_entry(
            loaded_image.entry(),
            stack,
            root.get(),
            layout.handoff_virtual,
            loaded_handoff.bytes() as u64,
            stack_layout
                .entry_top()
                .map_err(|_| KvmError::MemoryOverflow)?,
            stack_layout
                .double_fault_top()
                .map_err(|_| KvmError::MemoryOverflow)?,
        )?;
        Ok(PreparedKvmGuest {
            backend,
            entry: loaded_image.entry(),
            root,
            table_physical: layout.table_physical,
            table_pages: layout.table_pages,
            trapped_mmio,
            trapped_mmio_mapped: trapped_mmio.is_some(),
            trapped_mmio_retired: false,
            service_entry: [None; MAX_ISOLATED_SERVICES],
            service_root: [None; MAX_ISOLATED_SERVICES],
            service_instance: [None; MAX_ISOLATED_SERVICES],
            service_shared: None,
            service_shared_live: [false; 2],
            service_resource: [None; 2],
            service_resource_live: [false; 2],
        })
    }
}

fn zero_kvm_range<const N: usize>(
    memory: &mut super::KvmGuestMemory<N>,
    mut address: u64,
    mut bytes: u64,
) -> Result<(), KvmError> {
    let zero = [0u8; PAGE_SIZE as usize];
    while bytes != 0 {
        let count = bytes.min(PAGE_SIZE) as usize;
        memory.write(address, &zero[..count])?;
        address = address
            .checked_add(count as u64)
            .ok_or(KvmError::MemoryOverflow)?;
        bytes -= count as u64;
    }
    Ok(())
}

fn page_bytes(bytes: u64) -> Result<u64, KvmError> {
    if bytes == 0 {
        return Err(KvmError::EmptyMemory);
    }
    bytes
        .checked_add(PAGE_SIZE - 1)
        .ok_or(KvmError::MemoryOverflow)
        .map(|value| value / PAGE_SIZE * PAGE_SIZE)
}

fn validate_ranges(ranges: &[(u64, u64)]) -> Result<(), KvmError> {
    for (index, &(start, bytes)) in ranges.iter().enumerate() {
        let end = start.checked_add(bytes).ok_or(KvmError::MemoryOverflow)?;
        for &(other_start, other_bytes) in &ranges[..index] {
            let other_end = other_start
                .checked_add(other_bytes)
                .ok_or(KvmError::MemoryOverflow)?;
            if start < other_end && other_start < end {
                return Err(KvmError::MemoryOverlap);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512,
        lamport_public_key, lamport_sign,
    };
    use mrml_kernel::{
        ArtifactKind, CapabilitySpace, GuestMemory, HypercallRouter, InterruptPolicy, IoDirection,
        IoPortPolicy, IoPortRule, MemoryPoolTable, ObjectId, Rights, SIGNED_ARTIFACT_HEADER_BYTES,
        SIGNED_ARTIFACT_OVERHEAD_BYTES, SignedArtifact, TrustRoot,
        VIRTUAL_BLOCK_COMPLETION_ACK_PORT, VIRTUAL_BLOCK_COMPLETION_BYTES,
        VIRTUAL_BLOCK_CONFIGURATION_BYTES, VIRTUAL_BLOCK_DOORBELL_PORT,
        VIRTUAL_BLOCK_RESUME_STATE_BYTES, VirtualBlockBackend, VirtualBlockCompletion,
        VirtualBlockCompletionStatus, VirtualBlockConfiguration, VirtualBlockDevice,
        VirtualBlockMutationError, VirtualBlockProcessOutcome, VirtualBlockQueueBridge,
        VirtualBlockRequest, VmTable, artifact_statement, release_microvm_peer_page_projection,
        reserve_microvm_peer_page_projection, run_virtual_block_completion_ack_once,
        run_virtual_block_doorbell_once,
    };

    fn block_configuration(layout: VirtualBlockQueueLayout) -> VirtualBlockConfiguration {
        let mut device = VirtualBlockDevice::<1>::new(4096, 1, 0).unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        device.configuration().unwrap()
    }

    fn framebuffer_pe() -> [u8; 1024] {
        let mut pe = [0u8; 1024];
        pe[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&2u16.to_le_bytes());
        let optional = 0x98;
        pe[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[optional + 24..optional + 32].copy_from_slice(&0xffff_8001_4000_0000u64.to_le_bytes());
        pe[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        pe[optional + 70..optional + 72].copy_from_slice(&0x100u16.to_le_bytes());
        let section = optional + 240;
        pe[section..section + 5].copy_from_slice(b".text");
        pe[section + 8..section + 12].copy_from_slice(&17u32.to_le_bytes());
        pe[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 36..section + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        // mov rax, 0xa0000; mov dword ptr [rax], 0x00ffc857; hlt
        pe[0x200..0x211].copy_from_slice(&[
            0x48, 0xb8, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x00, 0x57, 0xc8,
            0xff, 0x00, 0xf4,
        ]);
        pe
    }

    fn deadline_pe() -> [u8; 1024] {
        let mut pe = framebuffer_pe();
        pe[0x200..0x211].fill(0x90);
        pe[0x200..0x202].copy_from_slice(&[0xeb, 0xfe]);
        pe
    }

    fn emit(code: &mut [u8; 512], at: &mut usize, bytes: &[u8]) {
        let end = *at + bytes.len();
        code[*at..end].copy_from_slice(bytes);
        *at = end;
    }

    fn emit_mov(code: &mut [u8; 512], at: &mut usize, opcode: u8, value: u64) {
        emit(code, at, &[0x48, opcode]);
        emit(code, at, &value.to_le_bytes());
    }

    fn emit_store_rax(code: &mut [u8; 512], at: &mut usize, offset: u8) {
        if offset == 0 {
            emit(code, at, &[0x48, 0x89, 0x07]);
        } else {
            emit(code, at, &[0x48, 0x89, 0x47, offset]);
        }
    }

    fn emit_completion_ack(code: &mut [u8; 512], at: &mut usize, request_id: u32) {
        emit_mov(code, at, 0xbf, 0x60_2080);
        let mut failures = [0usize; 4];
        for (index, (offset, expected)) in [
            (0, 0x0000_0001_4342_524d),
            (8, 1),
            (16, u64::from(request_id)),
            (24, 4096),
        ]
        .into_iter()
        .enumerate()
        {
            if offset == 0 {
                emit(code, at, &[0x48, 0x8b, 0x07]);
            } else {
                emit(code, at, &[0x48, 0x8b, 0x47, offset]);
            }
            if index == 0 {
                emit_mov(code, at, 0xbb, expected);
                emit(code, at, &[0x48, 0x39, 0xd8]);
            } else {
                emit(code, at, &[0x48, 0x3d]);
                emit(code, at, &(expected as u32).to_le_bytes());
            }
            emit(code, at, &[0x75, 0]);
            failures[index] = *at - 1;
        }
        emit(
            code,
            at,
            &[
                0x66,
                0xba,
                VIRTUAL_BLOCK_COMPLETION_ACK_PORT as u8,
                (VIRTUAL_BLOCK_COMPLETION_ACK_PORT >> 8) as u8,
                0xb8,
                1,
                0,
                0,
                0,
                0xef,
            ],
        );
        let failure = *at;
        emit(code, at, &[0xeb, 1, 0xf4]);
        for displacement in failures {
            code[displacement] = u8::try_from(failure + 2 - (displacement + 1)).unwrap();
        }
    }

    const GDT_OFFSET: usize = 0x1b0;
    const GDT_DESCRIPTOR_OFFSET: usize = 0x1c8;
    const IDT_GATE_OFFSET: usize = 0x1d8;
    const IDT_DESCRIPTOR_OFFSET: usize = 0x1e8;
    const INTERRUPT_HANDLER_OFFSET: usize = 0x1f8;

    fn emit_descriptor_load(code: &mut [u8; 512], at: &mut usize, operation: u8, target: usize) {
        let following = *at + 7;
        emit(code, at, &[0x0f, 0x01, operation]);
        emit(
            code,
            at,
            &i32::try_from(target as isize - following as isize)
                .unwrap()
                .to_le_bytes(),
        );
    }

    fn install_interrupt_tables(code: &mut [u8; 512], entry: u64) {
        code[GDT_OFFSET + 8..GDT_OFFSET + 16]
            .copy_from_slice(&0x00af_9b00_0000_ffffu64.to_le_bytes());
        code[GDT_OFFSET + 16..GDT_OFFSET + 24]
            .copy_from_slice(&0x00cf_9300_0000_ffffu64.to_le_bytes());
        code[GDT_DESCRIPTOR_OFFSET..GDT_DESCRIPTOR_OFFSET + 2]
            .copy_from_slice(&23u16.to_le_bytes());
        code[GDT_DESCRIPTOR_OFFSET + 2..GDT_DESCRIPTOR_OFFSET + 10]
            .copy_from_slice(&(entry + GDT_OFFSET as u64).to_le_bytes());

        let handler = entry + INTERRUPT_HANDLER_OFFSET as u64;
        let gate_low =
            (handler & 0xffff) | (8 << 16) | (0x8e << 40) | (((handler >> 16) & 0xffff) << 48);
        code[IDT_GATE_OFFSET..IDT_GATE_OFFSET + 8].copy_from_slice(&gate_low.to_le_bytes());
        code[IDT_GATE_OFFSET + 8..IDT_GATE_OFFSET + 16]
            .copy_from_slice(&(handler >> 32).to_le_bytes());
        code[IDT_DESCRIPTOR_OFFSET..IDT_DESCRIPTOR_OFFSET + 2]
            .copy_from_slice(&0x30fu16.to_le_bytes());
        let idt_base = entry + IDT_GATE_OFFSET as u64 - (48 * 16);
        code[IDT_DESCRIPTOR_OFFSET + 2..IDT_DESCRIPTOR_OFFSET + 10]
            .copy_from_slice(&idt_base.to_le_bytes());
        code[INTERRUPT_HANDLER_OFFSET..INTERRUPT_HANDLER_OFFSET + 2].copy_from_slice(&[0x48, 0xcf]);
    }

    fn producer_pe() -> [u8; 1024] {
        let mut pe = framebuffer_pe();
        let mut code = [0; 512];
        let mut at = 0;
        let entry = 0xffff_8001_4000_1000;
        emit_descriptor_load(&mut code, &mut at, 0x15, GDT_DESCRIPTOR_OFFSET);
        emit_descriptor_load(&mut code, &mut at, 0x1d, IDT_DESCRIPTOR_OFFSET);

        // Fill one mapped page with the probe payload.
        emit_mov(&mut code, &mut at, 0xbf, 0xa0000);
        emit_mov(&mut code, &mut at, 0xb8, 0x6d6d_6d6d_6d6d_6d6d);
        emit(
            &mut code,
            &mut at,
            &[0xb9, 0x00, 0x02, 0x00, 0x00, 0xf3, 0x48, 0xab],
        );
        // Zero and encode one canonical 64-byte write request at slot zero.
        emit_mov(&mut code, &mut at, 0xbf, 0x60_0080);
        emit(
            &mut code,
            &mut at,
            &[0x31, 0xc0, 0xb9, 0x08, 0x00, 0x00, 0x00, 0xf3, 0x48, 0xab],
        );
        emit_mov(&mut code, &mut at, 0xbf, 0x60_0080);
        for (offset, value) in [
            (0, 0x0000_0201_5142_524d),
            (8, 1),
            (16, 1),
            (32, 1),
            (40, 0xa0000),
            (48, 4096),
        ] {
            emit_mov(&mut code, &mut at, 0xb8, value);
            emit_store_rax(&mut code, &mut at, offset);
        }
        // Publish only after payload and request stores, then ring once.
        emit_mov(&mut code, &mut at, 0xbf, 0x60_0000);
        emit_mov(&mut code, &mut at, 0xb8, 1);
        emit_store_rax(&mut code, &mut at, 0);
        emit(&mut code, &mut at, &[0xfb]);
        emit(
            &mut code,
            &mut at,
            &[0x66, 0xba, 0x42, 0x4d, 0xb8, 1, 0, 0, 0, 0xef],
        );
        emit_completion_ack(&mut code, &mut at, 1);

        // Reuse slot zero only after acknowledgement, then read the same block.
        emit_mov(&mut code, &mut at, 0xbf, 0xa0000);
        emit(&mut code, &mut at, &[0x31, 0xc0]);
        emit_store_rax(&mut code, &mut at, 0);
        emit_mov(&mut code, &mut at, 0xbf, 0x60_0080);
        emit_mov(&mut code, &mut at, 0xb8, 0x0000_0101_5142_524d);
        emit_store_rax(&mut code, &mut at, 0);
        emit_mov(&mut code, &mut at, 0xb8, 2);
        emit_store_rax(&mut code, &mut at, 16);
        emit(&mut code, &mut at, &[0x48, 0x81, 0xef, 0x80, 0, 0, 0]);
        emit_mov(&mut code, &mut at, 0xb8, 2);
        emit_store_rax(&mut code, &mut at, 0);
        emit(
            &mut code,
            &mut at,
            &[0x66, 0xba, 0x42, 0x4d, 0xb8, 1, 0, 0, 0, 0xef],
        );
        emit_completion_ack(&mut code, &mut at, 2);
        assert!(at < GDT_OFFSET);
        install_interrupt_tables(&mut code, entry);
        pe[0x200..0x400].copy_from_slice(&code);
        let section = 0x98 + 240;
        pe[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe
    }

    fn valid_handoff() -> [u8; 240] {
        let mut encoded = [0u8; 240];
        encoded[..16].copy_from_slice(b"MRML-HANDOFF-v1\0");
        encoded[16..20].copy_from_slice(&240u32.to_le_bytes());
        encoded[20..22].copy_from_slice(&3u16.to_le_bytes());
        encoded[22..24].copy_from_slice(&7u16.to_le_bytes());
        encoded[24..32].copy_from_slice(&7u64.to_le_bytes());
        encoded[32..64].fill(1);
        encoded[64..128].fill(2);
        encoded[128..136].copy_from_slice(&0x9000u64.to_le_bytes());
        encoded[136..144].copy_from_slice(&0xa0000u64.to_le_bytes());
        encoded[144..152].copy_from_slice(&0x1000u64.to_le_bytes());
        encoded[152..156].copy_from_slice(&16u32.to_le_bytes());
        encoded[156..160].copy_from_slice(&16u32.to_le_bytes());
        encoded[160..164].copy_from_slice(&16u32.to_le_bytes());
        encoded[164] = 1;
        encoded[168..176].copy_from_slice(&0x1000u64.to_le_bytes());
        encoded[176..184].copy_from_slice(&2u64.to_le_bytes());
        encoded[192..200].copy_from_slice(&0x3000u64.to_le_bytes());
        encoded[200..208].copy_from_slice(&1u64.to_le_bytes());
        encoded[208] = 1;
        encoded[216..224].copy_from_slice(&0xa0000u64.to_le_bytes());
        encoded[224..232].copy_from_slice(&1u64.to_le_bytes());
        encoded[232] = 3;
        encoded
    }

    fn signed_payload(payload: [u8; 1024]) -> [u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024] {
        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(61).wrapping_add(17) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let digest = Sha3_512::digest(&payload);
        let statement = artifact_statement(ArtifactKind::VmImage, 1, payload.len() as u64, digest);
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let mut encoded = [0u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024];
        encoded[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        encoded[16] = ArtifactKind::VmImage as u8;
        encoded[24..32].copy_from_slice(&1u64.to_le_bytes());
        encoded[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        encoded[40..104].copy_from_slice(&digest);
        let signature_at = SIGNED_ARTIFACT_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES;
        let payload_at = signature_at + LAMPORT_SIGNATURE_BYTES;
        encoded[SIGNED_ARTIFACT_HEADER_BYTES..signature_at].copy_from_slice(&public);
        encoded[signature_at..payload_at].copy_from_slice(&signature);
        encoded[payload_at..].copy_from_slice(&payload);
        encoded
    }

    fn signed_pe() -> [u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024] {
        signed_payload(framebuffer_pe())
    }

    struct ProbeBlock([u8; 4096]);

    unsafe impl VirtualBlockBackend for ProbeBlock {
        type Error = ();

        fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if block != 0 || output.len() != self.0.len() {
                return Err(());
            }
            output.copy_from_slice(&self.0);
            Ok(())
        }

        fn write_blocks(
            &mut self,
            block: u64,
            input: &[u8],
        ) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            if block != 0 || input.len() != self.0.len() {
                return Err(VirtualBlockMutationError::Rejected(()));
            }
            self.0.copy_from_slice(input);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            Ok(())
        }
    }

    #[test]
    fn launch_layout_rejects_small_table_arenas_and_overlaps() {
        assert_eq!(
            KvmLaunchLayout::new(
                0x1000,
                3,
                0x10000,
                0x140000000,
                0x20000,
                0x200000,
                0x30000,
                0xffff_8000_0030_0000,
                2,
                true
            ),
            Err(KvmError::InvalidMapping)
        );
        assert_eq!(
            validate_ranges(&[(0x1000, 0x2000), (0x2000, 0x1000)]),
            Err(KvmError::MemoryOverlap)
        );
        assert!(
            KvmLaunchLayout::new(
                0x1000,
                8,
                0x10000,
                0x140000000,
                0x20000,
                0x200000,
                0x30000,
                0x300000,
                PRIVILEGE_STACK_ARENA_PAGES,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn live_signed_high_half_pe_writes_authenticated_framebuffer() {
        let system = match KvmSystem::open() {
            Ok(system) => system,
            Err(KvmError::SystemCall) => return,
            Err(error) => panic!("available KVM failed validation: {error:?}"),
        };
        let encoded = signed_pe();
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        let public_end = public_at + LAMPORT_PUBLIC_KEY_BYTES;
        let root = TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_end]),
            1,
        );
        let signed = SignedArtifact::decode(&encoded).unwrap();
        let executable = signed
            .verify_executable(&root, ArtifactKind::VmImage)
            .unwrap();
        let layout = KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0xffff_8001_4000_0000,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap();
        let queue_layout = GpuSharedQueueLayout::new(0x50_0000, 0x50_2000, 64).unwrap();
        let block_layout = VirtualBlockQueueLayout::new(0x60_0000, 0x60_2000, 64).unwrap();
        let mut guest = system
            .prepare_kernel_gpu_guest::<9>(0, &executable, &valid_handoff(), layout, queue_layout)
            .unwrap()
            .attach_virtual_block_queue_memory(block_layout)
            .unwrap();
        assert_eq!(guest.entry(), 0xffff_8001_4000_1000);
        let walk = guest.page_walk(guest.entry()).unwrap();
        assert_eq!(walk.levels(), 4);
        assert_eq!(walk.physical_address(guest.entry()), Some(0x20_1000));
        assert_eq!(walk.entries()[3] & (1 << 63), 0);
        let stack_layout =
            PrivilegeStackLayout::new(0xffff_8001_6000_0000, PRIVILEGE_STACK_ARENA_PAGES).unwrap();
        assert_eq!(
            guest
                .page_walk(stack_layout.early_base())
                .unwrap()
                .physical_address(stack_layout.early_base()),
            Some(0x40_0000)
        );
        assert_eq!(
            guest
                .page_walk(stack_layout.entry_guard().unwrap())
                .unwrap()
                .physical_address(stack_layout.entry_guard().unwrap()),
            None
        );
        assert_eq!(
            guest
                .page_walk(stack_layout.double_fault_guard().unwrap())
                .unwrap()
                .physical_address(stack_layout.double_fault_guard().unwrap()),
            None
        );
        assert_eq!(
            guest
                .page_walk(stack_layout.double_fault_base().unwrap())
                .unwrap()
                .physical_address(stack_layout.double_fault_base().unwrap()),
            Some(0x43_2000)
        );
        assert_eq!(
            guest.page_walk(0x0000_8000_0000_0000),
            Err(KvmError::InvalidMapping)
        );
        let mut opcode = [0u8; 1];
        VmBackend::read_guest(&guest, 0x20_1000, &mut opcode).unwrap();
        assert_eq!(opcode, [0x48]);
        let command_walk = guest.page_walk(queue_layout.command_base()).unwrap();
        assert_eq!(
            command_walk.physical_address(queue_layout.command_base()),
            Some(queue_layout.command_base())
        );
        assert_ne!(command_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(command_walk.entries()[3] & (1 << 63), 0);
        let completion_walk = guest.page_walk(queue_layout.completion_base()).unwrap();
        assert_eq!(
            completion_walk.physical_address(queue_layout.completion_base()),
            Some(queue_layout.completion_base())
        );
        assert_eq!(completion_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(completion_walk.entries()[3] & (1 << 63), 0);
        VmBackend::write_guest(&mut guest, queue_layout.command_base(), &[1]).unwrap();
        assert_eq!(
            VmBackend::write_guest(&mut guest, queue_layout.completion_base(), &[1]),
            Err(KvmError::ReadOnlyMemory)
        );
        VmBackend::write_guest(&mut guest, block_layout.request_base(), &[0x31]).unwrap();
        assert_eq!(
            VmBackend::write_guest(&mut guest, block_layout.completion_base(), &[0x32]),
            Err(KvmError::ReadOnlyMemory)
        );
        VirtualBlockVmmMemory::write_virtual_block(
            &mut guest,
            block_layout.completion_base(),
            &[0x33],
        )
        .unwrap();
        let mut block_completion = [0; 1];
        VmBackend::read_guest(
            &guest,
            block_layout.completion_base(),
            &mut block_completion,
        )
        .unwrap();
        assert_eq!(block_completion, [0x33]);
        assert_eq!(VmBackend::run(&mut guest, 0), Ok(VmExit::Halted));
        let mut pixel = [0u8; 4];
        VmBackend::read_guest(&guest, 0xa0000, &mut pixel).unwrap();
        assert_eq!(pixel, [0x57, 0xc8, 0xff, 0x00]);
    }

    #[test]
    fn live_two_vm_peer_page_shares_and_retires_exact_backing() {
        let system = match KvmSystem::open() {
            Ok(system) => system,
            Err(KvmError::SystemCall) => return,
            Err(error) => panic!("available KVM failed validation: {error:?}"),
        };
        let encoded = signed_pe();
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        let root = TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_at + LAMPORT_PUBLIC_KEY_BYTES]),
            1,
        );
        let signed = SignedArtifact::decode(&encoded).unwrap();
        let executable = signed
            .verify_executable(&root, ArtifactKind::VmImage)
            .unwrap();
        let layout = KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0xffff_8001_4000_0000,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap();
        let mut first = system
            .prepare_guest::<8>(0, &executable, &valid_handoff(), layout)
            .unwrap();
        let mut second = system
            .prepare_guest::<8>(0, &executable, &valid_handoff(), layout)
            .unwrap();

        let target_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 1, 2>::new(0x781).unwrap();
        let (pool, pool_capability) = memory
            .create_root(1, 2, 0, pool_rights, &mut capabilities)
            .unwrap();
        let first_target = capabilities.insert(ObjectId(0x782), target_rights).unwrap();
        let second_target = capabilities.insert(ObjectId(0x783), target_rights).unwrap();
        let (projection, object_capability) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            pool_capability,
            first_target,
            second_target,
            0xffff_8001_400f_0000 / PAGE_SIZE,
            0xffff_8001_400f_0000 / PAGE_SIZE,
            &mut capabilities,
        )
        .unwrap();
        let peer_virtual = 0xffff_8001_400f_0000;
        first.install_peer_page(peer_virtual, 0x20_0000).unwrap();
        let failure = PreparedKvmPeerPage::prepare(
            &mut first,
            &mut second,
            &projection,
            first_target,
            second_target,
            &capabilities,
            0x70_0000,
            0x80_0000,
        )
        .err()
        .expect("conflicting exact leaf must reject");
        assert_eq!(
            failure.error(),
            KvmPeerPageError::Backend(KvmError::PageTable)
        );
        assert!(failure.into_retained().is_none());
        let mut absent = [0; 1];
        assert_eq!(
            VmBackend::read_guest(&first, 0x70_0000, &mut absent),
            Err(KvmError::UnmappedMemory)
        );
        assert_eq!(
            VmBackend::read_guest(&second, 0x80_0000, &mut absent),
            Err(KvmError::UnmappedMemory)
        );
        first.withdraw_peer_page(peer_virtual, 0x20_0000).unwrap();
        let queue_pair = mrml_kernel::MicrovmInterfaceQueuePair::bind(
            mrml_kernel::MicrovmInterfaceQueueIdentity::new([0x5a; 32], 3, 14, 9, 7, 11).unwrap(),
            &projection,
            first_target,
            second_target,
            &capabilities,
        )
        .unwrap();
        let (mut consumer_queue, mut provider_queue) = queue_pair.split();
        let mut peer = PreparedKvmPeerPage::prepare(
            &mut first,
            &mut second,
            &projection,
            first_target,
            second_target,
            &capabilities,
            0x70_0000,
            0x80_0000,
        )
        .unwrap_or_else(|failure| panic!("KVM peer mapping failed: {:?}", failure.error()));
        assert_eq!(peer.first_translation().unwrap(), Some(0x70_0000));
        assert_eq!(peer.second_translation().unwrap(), Some(0x80_0000));
        let mut consumer_page = [0_u8; PAGE_SIZE as usize];
        consumer_queue
            .initialize(&mut consumer_page, &projection, &capabilities)
            .unwrap();
        consumer_queue
            .submit(&mut consumer_page, &projection, &capabilities, 1, b"zim")
            .unwrap();
        peer.write_first(&consumer_page).unwrap();
        let mut provider_page = [0_u8; PAGE_SIZE as usize];
        peer.read_second(&mut provider_page).unwrap();
        let mut request = [0_u8; 8];
        assert_eq!(
            provider_queue
                .receive_request(&provider_page, &projection, &capabilities, &mut request)
                .unwrap(),
            (1, 1, 3)
        );
        assert_eq!(&request[..3], b"zim");
        provider_queue
            .respond(
                &mut provider_page,
                &projection,
                &capabilities,
                1,
                1,
                b"zstd",
            )
            .unwrap();
        peer.write_second(&provider_page).unwrap();
        peer.read_first(&mut consumer_page).unwrap();
        let mut response = [0_u8; 8];
        assert_eq!(
            consumer_queue
                .consume_response(
                    &mut consumer_page,
                    &projection,
                    &capabilities,
                    &mut response,
                )
                .unwrap(),
            (1, 4)
        );
        assert_eq!(&response[..4], b"zstd");
        let mut observed = [0; 4];
        peer.retire()
            .unwrap_or_else(|(error, _)| panic!("KVM peer retirement failed: {error:?}"));
        assert_eq!(
            first
                .page_walk(0xffff_8001_400f_0000)
                .unwrap()
                .physical_address(0xffff_8001_400f_0000),
            None
        );
        assert_eq!(
            second
                .page_walk(0xffff_8001_400f_0000)
                .unwrap()
                .physical_address(0xffff_8001_400f_0000),
            None
        );
        assert_eq!(
            VmBackend::read_guest(&first, 0x70_0000, &mut observed),
            Err(KvmError::UnmappedMemory)
        );
        assert_eq!(
            VmBackend::read_guest(&second, 0x80_0000, &mut observed),
            Err(KvmError::UnmappedMemory)
        );
        assert_eq!(
            unsafe {
                release_microvm_peer_page_projection(
                    &mut memory,
                    projection,
                    object_capability,
                    first_target,
                    second_target,
                    &mut capabilities,
                )
            },
            Ok(1)
        );
        let usage = memory.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 0);
        assert_eq!(usage.active_mappings(), 0);
    }

    #[test]
    fn live_signed_high_half_pe_is_cancelled_at_deadline() {
        let system = match KvmSystem::open() {
            Ok(system) => system,
            Err(KvmError::SystemCall) => return,
            Err(error) => panic!("available KVM failed validation: {error:?}"),
        };
        let encoded = signed_payload(deadline_pe());
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        let public_end = public_at + LAMPORT_PUBLIC_KEY_BYTES;
        let root = TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_end]),
            1,
        );
        let executable = SignedArtifact::decode(&encoded)
            .unwrap()
            .verify_executable(&root, ArtifactKind::VmImage)
            .unwrap();
        let layout = KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0xffff_8001_4000_0000,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap();
        let mut guest = system
            .prepare_kernel_guest::<7>(0, &executable, &valid_handoff(), layout)
            .unwrap();
        let affinity_before = crate::native::current_thread_affinity().unwrap();
        let priority_before = crate::native::current_thread_priority().unwrap();
        assert_eq!(
            DeadlineVmBackend::run_with_deadline(&mut guest, 0, 0),
            Err(KvmError::InvalidDeadline)
        );
        assert_eq!(
            mrml_kernel::AffinityDeadlineVmBackend::run_with_affinity_deadline(
                &mut guest, 0, 64, 10_000,
            ),
            Err(KvmError::InvalidAffinity)
        );
        assert_eq!(
            mrml_kernel::ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
                &mut guest, 0, 0, 1, 10_000,
            ),
            Err(KvmError::InvalidPriority)
        );
        assert_eq!(
            mrml_kernel::ScheduledDeadlineVmBackend::run_with_scheduling_deadline(
                &mut guest, 0, 0, 0, 10_000,
            ),
            Ok(mrml_kernel::VmDeadlineOutcome::Expired)
        );
        assert_eq!(
            crate::native::current_thread_affinity().unwrap(),
            affinity_before
        );
        assert_eq!(
            crate::native::current_thread_priority().unwrap(),
            priority_before
        );
    }

    #[test]
    fn live_signed_guest_reuses_one_virtual_block_slot_for_write_and_read() {
        let system = match KvmSystem::open() {
            Ok(system) => system,
            Err(KvmError::SystemCall) => return,
            Err(error) => panic!("available KVM failed validation: {error:?}"),
        };
        let encoded = signed_payload(producer_pe());
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        let public_end = public_at + LAMPORT_PUBLIC_KEY_BYTES;
        let root = TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_end]),
            1,
        );
        let signed = SignedArtifact::decode(&encoded).unwrap();
        let executable = signed
            .verify_executable(&root, ArtifactKind::VmImage)
            .unwrap();
        let launch = KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0xffff_8001_4000_0000,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap();
        let layout = VirtualBlockQueueLayout::new(0x60_0000, 0x60_2000, 1).unwrap();
        let overlapping = VirtualBlockQueueLayout::new(0x20_0000, 0x60_2000, 1).unwrap();
        let configuration = block_configuration(layout);
        assert!(matches!(
            system.prepare_kernel_block_guest::<9>(
                0,
                &executable,
                &valid_handoff(),
                launch,
                overlapping,
                VirtualBlockConfigurationPage::new(0x60_4000, block_configuration(overlapping),)
                    .unwrap(),
                VirtualBlockResumePage::fresh(
                    0x60_5000,
                    VirtualBlockConfigurationPage::new(
                        0x60_4000,
                        block_configuration(overlapping),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Err(KvmError::MemoryOverlap)
        ));
        assert_eq!(
            VirtualBlockConfigurationPage::new(layout.request_base(), configuration),
            Err(mrml_kernel::VirtualBlockError::InvalidConfiguration)
        );
        assert!(matches!(
            system.prepare_kernel_block_guest::<11>(
                0,
                &executable,
                &valid_handoff(),
                launch,
                layout,
                VirtualBlockConfigurationPage::new(0x60_4000, block_configuration(overlapping),)
                    .unwrap(),
                VirtualBlockResumePage::fresh(
                    0x60_5000,
                    VirtualBlockConfigurationPage::new(
                        0x60_4000,
                        block_configuration(overlapping),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Err(KvmError::InvalidMapping)
        ));
        assert!(matches!(
            system.prepare_kernel_block_guest::<6>(
                0,
                &executable,
                &valid_handoff(),
                launch,
                layout,
                VirtualBlockConfigurationPage::new(0x60_4000, configuration).unwrap(),
                VirtualBlockResumePage::fresh(
                    0x60_5000,
                    VirtualBlockConfigurationPage::new(0x60_4000, configuration).unwrap(),
                )
                .unwrap(),
            ),
            Err(KvmError::MemoryTableFull)
        ));
        let mut guest = system
            .prepare_kernel_block_guest::<11>(
                0,
                &executable,
                &valid_handoff(),
                launch,
                layout,
                VirtualBlockConfigurationPage::new(0x60_4000, configuration).unwrap(),
                VirtualBlockResumePage::fresh(
                    0x60_5000,
                    VirtualBlockConfigurationPage::new(0x60_4000, configuration).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

        let request_walk = guest.page_walk(layout.request_base()).unwrap();
        assert_eq!(
            request_walk.physical_address(layout.request_base()),
            Some(layout.request_base())
        );
        assert_ne!(request_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(request_walk.entries()[3] & (1 << 63), 0);
        let completion_walk = guest.page_walk(layout.completion_base()).unwrap();
        assert_eq!(
            completion_walk.physical_address(layout.completion_base()),
            Some(layout.completion_base())
        );
        assert_eq!(completion_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(completion_walk.entries()[3] & (1 << 63), 0);
        let configuration_walk = guest.page_walk(0x60_4000).unwrap();
        assert_eq!(
            configuration_walk.physical_address(0x60_4000),
            Some(0x60_4000)
        );
        assert_eq!(configuration_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(configuration_walk.entries()[3] & (1 << 63), 0);
        let mut encoded_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        VmBackend::read_guest(&guest, 0x60_4000, &mut encoded_configuration).unwrap();
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded_configuration),
            Ok(configuration)
        );
        assert_eq!(
            VmBackend::write_guest(&mut guest, 0x60_4000, &[1]),
            Err(KvmError::ReadOnlyMemory)
        );
        let resume_walk = guest.page_walk(0x60_5000).unwrap();
        assert_eq!(resume_walk.physical_address(0x60_5000), Some(0x60_5000));
        assert_eq!(resume_walk.entries()[3] & (1 << 1), 0);
        assert_ne!(resume_walk.entries()[3] & (1 << 63), 0);
        let mut encoded_resume = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        VmBackend::read_guest(&guest, 0x60_5000, &mut encoded_resume).unwrap();
        assert_eq!(
            mrml_kernel::VirtualBlockResumeState::decode(&encoded_resume)
                .unwrap()
                .configuration(),
            configuration
        );
        assert_eq!(
            VmBackend::write_guest(&mut guest, 0x60_5000, &[1]),
            Err(KvmError::ReadOnlyMemory)
        );
        VirtualBlockVmmMemory::write_virtual_block(&mut guest, 0x60_5000, &[0x4d]).unwrap();
        let mut marker = [0];
        VmBackend::read_guest(&guest, 0x60_5000, &mut marker).unwrap();
        assert_eq!(marker, [0x4d]);

        let block_object = ObjectId(0x200);
        let interrupt_object = ObjectId(0x201);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                Rights::READ.union(Rights::WRITE).union(Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, Rights::SIGNAL)
            .unwrap();
        let mut interrupt_policy = InterruptPolicy::deny_all();
        interrupt_policy.allow(48).unwrap();
        let mut io_policy = IoPortPolicy::<2>::deny_all();
        io_policy
            .allow(IoPortRule::new(VIRTUAL_BLOCK_DOORBELL_PORT, 4, IoDirection::Write).unwrap())
            .unwrap();
        io_policy
            .allow(
                IoPortRule::new(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, IoDirection::Write).unwrap(),
            )
            .unwrap();
        let mut vms = VmTable::<1>::new();
        let vm = vms.create(4).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();
        let mut router = HypercallRouter::new(ObjectId(0x202), ObjectId(0x203), ObjectId(0x204));
        let guest_memory = GuestMemory::<0>::new();
        let mut device = VirtualBlockDevice::<1>::new(4096, 1, 0).unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout).unwrap();
        let mut storage = ProbeBlock([0; 4096]);
        let mut scratch = [0; 4096];

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut guest,
                &mut storage,
                mrml_kernel::VirtualBlockBackendAuthority::new(
                    block_capability,
                    block_object,
                    0,
                    1,
                )
                .unwrap(),
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
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(storage.0, [0x6d; 4096]);
        let mut encoded_request = [0; 64];
        VmBackend::read_guest(&guest, layout.request_base() + 128, &mut encoded_request).unwrap();
        assert_eq!(
            VirtualBlockRequest::decode(&encoded_request).unwrap(),
            VirtualBlockRequest::write(1, 1, 0, 1, 0xa0000, 4096)
        );
        let mut counters = [0; 72];
        VmBackend::read_guest(&guest, layout.request_base(), &mut counters).unwrap();
        assert_eq!(u64::from_le_bytes(counters[..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(counters[64..].try_into().unwrap()), 1);
        let mut encoded_completion = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        VmBackend::read_guest(
            &guest,
            layout.completion_base() + 128,
            &mut encoded_completion,
        )
        .unwrap();
        let completion = VirtualBlockCompletion::decode(&encoded_completion).unwrap();
        assert_eq!(completion.request_id(), 1);
        assert_eq!(completion.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(completion.transferred(), 4096);
        assert_eq!(device.pending_interrupt_vector(), None);
        let acknowledgement = run_virtual_block_completion_ack_once(
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
        );
        assert_eq!(acknowledgement, Ok(1));

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut guest,
                &mut storage,
                mrml_kernel::VirtualBlockBackendAuthority::new(
                    block_capability,
                    block_object,
                    0,
                    1,
                )
                .unwrap(),
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
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        VmBackend::read_guest(&guest, layout.request_base() + 128, &mut encoded_request).unwrap();
        assert_eq!(
            VirtualBlockRequest::decode(&encoded_request).unwrap(),
            VirtualBlockRequest::read(1, 2, 0, 1, 0xa0000, 4096)
        );
        VmBackend::read_guest(&guest, layout.request_base(), &mut counters).unwrap();
        assert_eq!(u64::from_le_bytes(counters[..8].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(counters[64..].try_into().unwrap()), 2);
        let mut payload = [0; 4096];
        VmBackend::read_guest(&guest, 0xa0000, &mut payload).unwrap();
        assert_eq!(payload, [0x6d; 4096]);
        VmBackend::read_guest(
            &guest,
            layout.completion_base() + 128,
            &mut encoded_completion,
        )
        .unwrap();
        let completion = VirtualBlockCompletion::decode(&encoded_completion).unwrap();
        assert_eq!(completion.request_id(), 2);
        assert_eq!(completion.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(completion.transferred(), 4096);
        assert_eq!(
            run_virtual_block_completion_ack_once(
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
            ),
            Ok(2)
        );
        let mut completion_counters = [0; 72];
        VmBackend::read_guest(&guest, layout.completion_base(), &mut completion_counters).unwrap();
        assert_eq!(
            u64::from_le_bytes(completion_counters[..8].try_into().unwrap()),
            2
        );
        assert_eq!(
            u64::from_le_bytes(completion_counters[64..].try_into().unwrap()),
            2
        );
        assert_eq!(vms.state(vm), Ok(mrml_kernel::VmState::Running));
    }
}
