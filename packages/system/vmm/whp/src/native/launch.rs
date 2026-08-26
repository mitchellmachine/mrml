#[cfg(test)]
use mrml_kernel::arch::x86_64::PRIVILEGE_STACK_ARENA_PAGES;
use mrml_kernel::arch::x86_64::{
    AddressSpace, Mapping, PagePermissions, PageTableBuildError, PageTableBuilder, PageTableStore,
    PerCpuPrivilegeStacks, PrivilegeStackLayout, VirtAddr,
};
use mrml_kernel::{
    ArtifactKind, BootHandoff, DeadlineVmBackend, GpuSharedQueueLayout, GpuVmmMemory,
    MAX_PE_SECTIONS, PAGE_SIZE, PeImage, PhysAddr, PreparedComponentServiceLaunch,
    RevocableVmBackend, ServiceAddressSpaceEraser, TaskId, VerifiedExecutable,
    VirtualBlockConfigurationPage, VirtualBlockQueueLayout, VirtualBlockResumePage,
    VirtualBlockVmmMemory, VmBackend, VmExit,
};

use crate::{GuestRange, MapPermissions, WhpError};

use super::{PreparedWhpPartition, WhpSystem};

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
    intercept_breakpoint: bool,
    cpus: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WhpLaunchLayout {
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

impl WhpLaunchLayout {
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
    ) -> Result<Self, WhpError> {
        if table_pages < 5
            || stack_pages == 0
            || [
                table_physical,
                image_physical,
                handoff_physical,
                stack_physical,
            ]
            .iter()
            .any(|value| *value == 0 || !value.is_multiple_of(PAGE_SIZE))
            || [image_virtual, handoff_virtual, stack_virtual]
                .iter()
                .any(|value| *value == 0 || !value.is_multiple_of(PAGE_SIZE))
        {
            return Err(WhpError::InvalidMapping);
        }
        PerCpuPrivilegeStacks::<1>::new(stack_physical, stack_virtual, stack_pages)
            .and_then(|set| set.cpu(0))
            .map_err(|_| WhpError::InvalidMapping)?;
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

pub struct PreparedWhpGuest<'system> {
    partition: PreparedWhpPartition<'system>,
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
    ap_trampoline: Option<u64>,
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

pub struct WhpServiceEraser<'guest, 'artifact, 'system> {
    guest: &'guest mut PreparedWhpGuest<'system>,
    service: &'guest VerifiedExecutable<'artifact>,
    slot: usize,
    task: TaskId,
}

impl ServiceAddressSpaceEraser for WhpServiceEraser<'_, '_, '_> {
    type Error = WhpError;

    fn erase(
        &mut self,
        task: TaskId,
        context: mrml_kernel::arch::x86_64::UserContext,
    ) -> Result<(), Self::Error> {
        if task != self.task
            || self.guest.service_page_table_root_at(self.slot) != Some(context.page_table())
        {
            return Err(WhpError::InvalidMapping);
        }
        self.guest
            .reprovision_isolated_service_at(self.slot, self.service)?;
        Ok(())
    }
}

impl<'system> PreparedWhpGuest<'system> {
    pub fn service_eraser<'guest, 'artifact>(
        &'guest mut self,
        slot: usize,
        task: TaskId,
        service: &'guest VerifiedExecutable<'artifact>,
    ) -> WhpServiceEraser<'guest, 'artifact, 'system> {
        WhpServiceEraser {
            guest: self,
            service,
            slot,
            task,
        }
    }

    pub const fn entry(&self) -> u64 {
        self.entry
    }
    pub const fn page_table_root(&self) -> PhysAddr {
        self.root
    }

    /// Irreversibly removes the exact first-level trap leaf from this stopped
    /// guest before partition destruction. No vCPU may run afterward;
    /// resumable live unmapping requires a separate TLB-coherent protocol.
    pub fn retire_trapped_mmio_before_destroy(&mut self, address: u64) -> Result<(), WhpError> {
        if self.trapped_mmio != Some(address)
            || !self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(WhpError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        let store = WhpPageTableStore::open_existing(
            &mut self.partition,
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
            .map_err(|_| WhpError::PageTable)?;
        self.trapped_mmio_mapped = false;
        Ok(())
    }

    /// Installs the exact configured non-global trap leaf and reloads the
    /// stopped sole vCPU's exact CR3 before permitting entry.
    pub fn install_trapped_mmio(&mut self, address: u64) -> Result<(), WhpError> {
        if self.trapped_mmio != Some(address)
            || self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(WhpError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        self.trapped_mmio_retired = true;
        {
            let store = WhpPageTableStore::open_existing(
                &mut self.partition,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .map(mapping)
                .and_then(|()| tables.verify_mapped(mapping))
                .map_err(|_| WhpError::PageTable)?;
        }
        self.partition
            .reload_exact_page_table_root(self.root.get())?;
        self.trapped_mmio_mapped = true;
        self.trapped_mmio_retired = false;
        Ok(())
    }

    /// Removes the exact non-global trap leaf and reloads the stopped sole
    /// vCPU's exact CR3 before permitting re-entry. Any uncertain step leaves
    /// the guest permanently quarantined.
    pub fn withdraw_trapped_mmio(&mut self, address: u64) -> Result<(), WhpError> {
        if self.trapped_mmio != Some(address)
            || !self.trapped_mmio_mapped
            || self.trapped_mmio_retired
            || !address.is_multiple_of(PAGE_SIZE)
        {
            return Err(WhpError::InvalidMapping);
        }
        let mapping = Mapping::new(
            VirtAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            PhysAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
            1,
            PagePermissions::KERNEL_MMIO_READ_WRITE,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        self.trapped_mmio_retired = true;
        {
            let store = WhpPageTableStore::open_existing(
                &mut self.partition,
                self.table_physical,
                self.table_pages,
            )?;
            let mut tables = PageTableBuilder::from_existing_root(store, self.root);
            tables
                .unmap_exact(mapping)
                .and_then(|()| tables.verify_unmapped(mapping))
                .map_err(|_| WhpError::PageTable)?;
        }
        self.partition
            .reload_exact_page_table_root(self.root.get())?;
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
    /// virtual processor is stopped. Publication is cleared before mutation.
    pub fn reprovision_isolated_service_at(
        &mut self,
        slot: usize,
        service: &VerifiedExecutable<'_>,
    ) -> Result<(u64, PhysAddr), WhpError> {
        let instance = self
            .service_instance
            .get(slot)
            .and_then(|instance| *instance)
            .ok_or(WhpError::InvalidMapping)?;
        if service.artifact().kind() != ArtifactKind::ServiceImage
            || service.artifact().digest() != &instance.digest
            || u64::from(service.image().image_size()) != instance.image_bytes
        {
            return Err(WhpError::InvalidMapping);
        }
        let root = self.service_root[slot].ok_or(WhpError::InvalidMapping)?;
        self.service_entry[slot] = None;
        self.service_root[slot] = None;
        let image_bytes =
            usize::try_from(instance.image_bytes).map_err(|_| WhpError::MemoryOverflow)?;
        let destination = self
            .partition
            .mutable_service(instance.image_physical, image_bytes)?;
        destination.fill(0);
        let entry = service
            .image()
            .materialize_at(destination, instance.image_virtual)
            .map_err(WhpError::Pe)?;
        let stack_bytes =
            usize::try_from(instance.stack_bytes).map_err(|_| WhpError::MemoryOverflow)?;
        self.partition
            .mutable_service(instance.stack_physical, stack_bytes)?
            .fill(0);
        self.service_entry[slot] = Some(entry);
        self.service_root[slot] = Some(root);
        Ok((entry, root))
    }

    pub fn attach_service_shared_page(mut self, mapping: Mapping) -> Result<Self, WhpError> {
        if self.service_shared.is_some()
            || mapping.pages() != 1
            || mapping.permissions() != PagePermissions::USER_READ_WRITE
            || self.service_instance[..2].iter().any(Option::is_none)
        {
            return Err(WhpError::InvalidMapping);
        }
        self.partition.map_zeroed(range(
            mapping.physical_start().get(),
            PAGE_SIZE,
            MapPermissions::read_write(),
        )?)?;
        for slot in 0..2 {
            self.mutate_service_shared_leaf(slot, mapping, true)?;
            self.service_shared_live[slot] = true;
        }
        self.service_shared = Some(mapping);
        Ok(self)
    }

    pub fn revoke_service_shared_page(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = self.service_shared.ok_or(WhpError::InvalidMapping)?;
        if slot >= 2 || !self.service_shared_live[slot] {
            return Err(WhpError::InvalidMapping);
        }
        self.mutate_service_shared_leaf(slot, mapping, false)?;
        self.service_shared_live[slot] = false;
        Ok(())
    }

    /// Accepts kernel-side retirement only after the stopped service's exact
    /// shared leaf is observably absent. Host bookkeeping changes after the
    /// complete read-only verification succeeds.
    pub fn observe_service_shared_page_revoked(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = self.service_shared.ok_or(WhpError::InvalidMapping)?;
        if slot >= 2 || !self.service_shared_live[slot] {
            return Err(WhpError::InvalidMapping);
        }
        let instance = self.service_instance[slot].ok_or(WhpError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(WhpError::InvalidMapping)?;
        let store = WhpPageTableStore::open_existing(
            &mut self.partition,
            instance.table_physical,
            instance.table_pages,
        )?;
        PageTableBuilder::from_existing_root(store, root)
            .verify_unmapped(mapping)
            .map_err(|_| WhpError::PageTable)?;
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
    ) -> Result<Self, WhpError> {
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
            return Err(WhpError::InvalidMapping);
        }
        self.partition.map_zeroed(range(
            mapping.physical_start().get(),
            PAGE_SIZE,
            MapPermissions::read_write(),
        )?)?;
        self.mutate_service_resource_leaf(slot, mapping, true, true)?;
        self.service_resource[slot] = Some(mapping);
        self.service_resource_live[slot] = true;
        Ok(self)
    }

    pub fn revoke_service_resource_page(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(WhpError::InvalidMapping)?;
        if !self.service_resource_live[slot] {
            return Err(WhpError::InvalidMapping);
        }
        self.mutate_service_resource_leaf(slot, mapping, false, false)?;
        self.service_resource_live[slot] = false;
        Ok(())
    }

    pub fn observe_service_resource_page_revoked(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(WhpError::InvalidMapping)?;
        if !self.service_resource_live[slot] {
            return Err(WhpError::InvalidMapping);
        }
        self.verify_service_mapping_absent(slot, mapping)?;
        self.service_resource_live[slot] = false;
        Ok(())
    }

    pub fn restore_service_resource_page(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = *self
            .service_resource
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(WhpError::InvalidMapping)?;
        if self.service_resource_live[slot] {
            return Err(WhpError::InvalidMapping);
        }
        self.partition
            .write_guest(mapping.physical_start().get(), &[0; PAGE_SIZE as usize])?;
        self.mutate_service_resource_leaf(slot, mapping, true, false)?;
        self.service_resource_live[slot] = true;
        Ok(())
    }

    pub fn restore_service_shared_page(&mut self, slot: usize) -> Result<(), WhpError> {
        let mapping = self.service_shared.ok_or(WhpError::InvalidMapping)?;
        if slot >= 2 || self.service_shared_live[slot] {
            return Err(WhpError::InvalidMapping);
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
    ) -> Result<(), WhpError> {
        let initial = self.service_shared.is_none();
        let instance = self.service_instance[slot].ok_or(WhpError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(WhpError::InvalidMapping)?;
        let store = WhpPageTableStore::open_existing(
            &mut self.partition,
            instance.table_physical,
            instance.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, root);
        let supervisor = Mapping::new(
            VirtAddr::new(mapping.physical_start().get()).map_err(|_| WhpError::InvalidMapping)?,
            mapping.physical_start(),
            1,
            PagePermissions::KERNEL_LOW_READ_WRITE,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        if install {
            if initial {
                tables.map(supervisor).and_then(|_| tables.map(mapping))
            } else {
                tables.map(mapping)
            }
        } else {
            tables.unmap_exact(mapping)
        }
        .map_err(|_| WhpError::PageTable)
    }

    fn mutate_service_resource_leaf(
        &mut self,
        slot: usize,
        mapping: Mapping,
        install: bool,
        initial: bool,
    ) -> Result<(), WhpError> {
        let instance = self.service_instance[slot].ok_or(WhpError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(WhpError::InvalidMapping)?;
        let store = WhpPageTableStore::open_existing(
            &mut self.partition,
            instance.table_physical,
            instance.table_pages,
        )?;
        let mut tables = PageTableBuilder::from_existing_root(store, root);
        let supervisor = Mapping::new(
            VirtAddr::new(mapping.physical_start().get()).map_err(|_| WhpError::InvalidMapping)?,
            mapping.physical_start(),
            1,
            PagePermissions::KERNEL_LOW_READ_WRITE,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        if install {
            if initial {
                tables.map(supervisor).and_then(|_| tables.map(mapping))
            } else {
                tables.map(mapping)
            }
        } else {
            tables.unmap_exact(mapping)
        }
        .map_err(|_| WhpError::PageTable)
    }

    fn verify_service_mapping_absent(
        &mut self,
        slot: usize,
        mapping: Mapping,
    ) -> Result<(), WhpError> {
        let instance = self.service_instance[slot].ok_or(WhpError::InvalidMapping)?;
        let root = self.service_root[slot].ok_or(WhpError::InvalidMapping)?;
        let store = WhpPageTableStore::open_existing(
            &mut self.partition,
            instance.table_physical,
            instance.table_pages,
        )?;
        PageTableBuilder::from_existing_root(store, root)
            .verify_unmapped(mapping)
            .map_err(|_| WhpError::PageTable)
    }
    pub fn run(&mut self) -> Result<VmExit, WhpError> {
        if self.trapped_mmio_retired {
            return Err(WhpError::InvalidMapping);
        }
        self.partition.run()
    }
    pub fn run_smp(&mut self) -> Result<(VmExit, VmExit), WhpError> {
        self.partition.ensure_mapping_coherent()?;
        let trampoline = self.ap_trampoline.ok_or(WhpError::InvalidMapping)?;
        let mut secondary = None;
        let result = mrml_runtime::Shared::new(mrml_runtime::SpinMutex::new(None));
        let bootstrap = loop {
            let exit = self.partition.run()?;
            if let VmExit::Io {
                port: 0x00e9,
                size: 1,
                write: true,
                value,
            } = exit
            {
                mrml_runtime::mrml_println!("WHP_SMP_TRACE stage={:#04x}", value);
            }
            if let VmExit::Io {
                port: 0x00e9,
                size: 1,
                write: true,
                value: 0x21,
            } = exit
            {
                if secondary.is_some() {
                    return Err(WhpError::InvalidVcpu);
                }
                self.partition
                    .protect_runtime_trampoline(trampoline, true)?;
                let mut runner = self.partition.secondary_runner(trampoline)?;
                let worker_result = result.clone();
                mrml_runtime::spawn_detached(move || {
                    let first = loop {
                        let exit = runner.run();
                        if let Ok(VmExit::Io {
                            port: 0x00e9,
                            size: 1,
                            write: true,
                            value,
                        }) = exit
                        {
                            mrml_runtime::mrml_println!("WHP_SMP_TRACE stage={:#04x}", value);
                            continue;
                        }
                        break exit;
                    };
                    let exit = match first {
                        Ok(VmExit::Io {
                            port: 0x4d5d,
                            size: 4,
                            write: true,
                            value: 0x0001_0001,
                        }) => runner.restore_trampoline_rw().and_then(|()| {
                            loop {
                                let exit = runner.run()?;
                                if let VmExit::Io {
                                    port: 0x00e9,
                                    size: 1,
                                    write: true,
                                    value,
                                } = exit
                                {
                                    mrml_runtime::mrml_println!(
                                        "WHP_SMP_TRACE stage={:#04x}",
                                        value
                                    );
                                    continue;
                                }
                                if matches!(
                                    exit,
                                    VmExit::Io {
                                        port: 0x4d5e | 0x4d60,
                                        size: 4,
                                        write: true,
                                        ..
                                    }
                                ) {
                                    continue;
                                }
                                break Ok(exit);
                            }
                        }),
                        Ok(_) => Err(WhpError::MalformedExit),
                        Err(error) => Err(error),
                    };
                    *worker_result.lock() = Some(exit);
                })
                .map_err(|_| WhpError::PlatformUnavailable)?;
                secondary = Some(());
                continue;
            }
            if matches!(exit, VmExit::Io { port: 0x00e9, .. }) {
                continue;
            }
            break exit;
        };
        if secondary.is_none() {
            return Err(WhpError::InvalidVcpu);
        }
        let deadline = mrml_runtime::Instant::now();
        while result.lock().is_none() && deadline.elapsed() < core::time::Duration::from_secs(2) {
            mrml_runtime::yield_now();
        }
        let application = result
            .lock()
            .take()
            .ok_or(WhpError::PlatformUnavailable)??;
        self.partition
            .protect_runtime_trampoline(trampoline, false)?;
        Ok((bootstrap, application))
    }
    pub fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), WhpError> {
        self.partition.read_guest(address, output)
    }
    pub fn inject_interrupt(&mut self, vector: u8) -> Result<(), WhpError> {
        self.partition.inject_interrupt(vector)
    }

    pub fn page_walk(&self, virtual_address: u64) -> Result<WhpPageWalk, WhpError> {
        if ((virtual_address << 16) as i64 >> 16) as u64 != virtual_address {
            return Err(WhpError::InvalidMapping);
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
                .ok_or(WhpError::MemoryOverflow)?;
            let mut encoded = [0u8; 8];
            self.partition.read_guest(address, &mut encoded)?;
            let entry = u64::from_le_bytes(encoded);
            entries[level] = entry;
            levels += 1;
            if entry & 1 == 0 || (level < 3 && entry & (1 << 7) != 0) {
                break;
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
        Ok(WhpPageWalk { entries, levels })
    }

    /// Attaches the common mediated-GPU queue layout using separate WHP GPA
    /// ranges. Command memory is guest-writable and completion memory is
    /// guest-read-only. Consuming `self` prevents use of a partially attached
    /// partition if the second platform mapping fails.
    pub fn attach_gpu_queue_memory(
        mut self,
        layout: GpuSharedQueueLayout,
    ) -> Result<Self, WhpError> {
        let bytes = layout
            .pages_per_ring()
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
        self.partition.map_zeroed(range(
            layout.command_base(),
            bytes,
            MapPermissions::read_write(),
        )?)?;
        self.partition.map_zeroed_service_readonly(range(
            layout.completion_base(),
            bytes,
            MapPermissions::read_only(),
        )?)?;
        Ok(self)
    }

    /// Attaches one validated MRML virtual-block request/completion pair using
    /// separate WHP GPA ranges. Requests are guest-writable; completions are
    /// guest-read-only and writable only through the device-memory path.
    /// Consuming `self` prevents use after a partial native attachment failure.
    pub fn attach_virtual_block_queue_memory(
        mut self,
        layout: VirtualBlockQueueLayout,
    ) -> Result<Self, WhpError> {
        let bytes = layout
            .pages_per_queue()
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
        self.partition.map_zeroed(range(
            layout.request_base(),
            bytes,
            MapPermissions::read_write(),
        )?)?;
        self.partition.map_zeroed_service_readonly(range(
            layout.completion_base(),
            bytes,
            MapPermissions::read_only(),
        )?)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attach_isolated_service(
        self,
        kernel: &VerifiedExecutable<'_>,
        kernel_layout: WhpLaunchLayout,
        service: &VerifiedExecutable<'_>,
        service_physical: u64,
        service_virtual: u64,
        stack_physical: u64,
        stack_virtual: u64,
        stack_pages: u64,
        table_physical: u64,
        table_pages: u64,
    ) -> Result<Self, WhpError> {
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
    /// before either WHP mapping is created; failure while attaching the second
    /// image consumes and drops the unpublished guest builder.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_component_service_pair(
        self,
        launch: &PreparedComponentServiceLaunch,
        kernel: &VerifiedExecutable<'_>,
        kernel_layout: WhpLaunchLayout,
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
    ) -> Result<Self, WhpError> {
        launch
            .verify_artifacts(
                consumer.artifact().kind(),
                consumer.artifact().digest(),
                provider.artifact().kind(),
                provider.artifact().digest(),
            )
            .map_err(|_| WhpError::InvalidMapping)?;
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
        kernel_layout: WhpLaunchLayout,
        service: &VerifiedExecutable<'_>,
        service_physical: u64,
        service_virtual: u64,
        stack_physical: u64,
        stack_virtual: u64,
        stack_pages: u64,
        table_physical: u64,
        table_pages: u64,
        local_apic: bool,
    ) -> Result<Self, WhpError> {
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
                service_virtual,
                stack_physical,
                stack_virtual,
                table_physical,
            ]
            .iter()
            .any(|address| !address.is_multiple_of(PAGE_SIZE))
        {
            return Err(WhpError::InvalidMapping);
        }
        let image_bytes = page_bytes(service.image().image_size() as u64)?;
        let stack_bytes = stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
        let table_bytes = table_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
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
                    .ok_or(WhpError::MemoryOverflow)?,
            ),
        ])?;
        let service_mapping = self.partition.map_zeroed(range(
            service_physical,
            image_bytes,
            MapPermissions::read_write(),
        )?)?;
        self.partition.map_zeroed(range(
            stack_physical,
            stack_bytes,
            MapPermissions::read_write(),
        )?)?;
        self.partition.map_zeroed(range(
            table_physical,
            table_bytes,
            MapPermissions::read_write(),
        )?)?;
        let image = service.image();
        let destination = self
            .partition
            .mutable_guest(service_physical, image.image_size() as usize)?;
        let service_entry = image
            .materialize_at(destination, service_virtual)
            .map_err(WhpError::Pe)?;
        self.partition.seal_pe(service_mapping, image)?;

        let store = WhpPageTableStore::new(&mut self.partition, table_physical, table_pages)?;
        let mut tables =
            PageTableBuilder::new(store).map_err(|_| WhpError::InvalidRegisterState)?;
        map_pe(
            &mut tables,
            kernel.image(),
            kernel_layout.image_physical,
            kernel_layout.image_virtual,
            false,
        )?;
        map_pe(&mut tables, image, service_physical, service_virtual, true)?;
        let kernel_cpus = if kernel_layout.stack_virtual == kernel_layout.stack_physical {
            2u64
        } else {
            1u64
        };
        let kernel_stack_stride = kernel_layout
            .stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
        for cpu in 0..kernel_cpus {
            let offset = cpu
                .checked_mul(kernel_stack_stride)
                .ok_or(WhpError::MemoryOverflow)?;
            let kernel_stack = PrivilegeStackLayout::new(
                kernel_layout
                    .stack_virtual
                    .checked_add(offset)
                    .ok_or(WhpError::MemoryOverflow)?,
                kernel_layout.stack_pages,
            )
            .map_err(|_| WhpError::InvalidMapping)?;
            let kernel_stack_physical = PrivilegeStackLayout::new(
                kernel_layout
                    .stack_physical
                    .checked_add(offset)
                    .ok_or(WhpError::MemoryOverflow)?,
                kernel_layout.stack_pages,
            )
            .map_err(|_| WhpError::InvalidMapping)?;
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
                let virtual_base = virtual_base.map_err(|_| WhpError::InvalidMapping)?;
                let permissions = if virtual_base < 1 << 47 {
                    PagePermissions::KERNEL_LOW_READ_WRITE
                } else {
                    PagePermissions::KERNEL_READ_WRITE
                };
                tables
                    .map(
                        Mapping::new(
                            VirtAddr::new(virtual_base).map_err(|_| WhpError::InvalidMapping)?,
                            PhysAddr::new(physical_base.map_err(|_| WhpError::InvalidMapping)?)
                                .map_err(|_| WhpError::InvalidMapping)?,
                            pages,
                            permissions,
                        )
                        .map_err(|_| WhpError::InvalidMapping)?,
                    )
                    .map_err(|_| WhpError::InvalidRegisterState)?;
            }
        }
        if local_apic {
            tables
                .map_page(
                    VirtAddr::new(XAPIC_BASE).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(XAPIC_BASE).map_err(|_| WhpError::InvalidMapping)?,
                    PagePermissions::KERNEL_MMIO_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidRegisterState)?;
        }
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(stack_virtual).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(stack_physical).map_err(|_| WhpError::InvalidMapping)?,
                    stack_pages,
                    PagePermissions::USER_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::InvalidRegisterState)?;
        tables
            .map_page(
                VirtAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_LOW_READ_WRITE,
            )
            .map_err(|_| WhpError::PageTable)?;
        let mut frame_index = 0;
        while frame_index < tables.store().allocated_pages() {
            let frame = tables
                .store()
                .allocated_frame(frame_index)
                .ok_or(WhpError::PageTable)?;
            tables
                .map_page(
                    VirtAddr::new(frame.get()).map_err(|_| WhpError::InvalidMapping)?,
                    frame,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| WhpError::PageTable)?;
            frame_index += 1;
        }
        tables
            .unmap_exact(
                Mapping::new(
                    VirtAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                    1,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
        let service_root = tables.root();
        let _ = tables.into_store();
        self.service_entry[slot] = Some(service_entry);
        self.service_root[slot] = Some(service_root);
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
pub struct WhpPageWalk {
    entries: [u64; 4],
    levels: u8,
}

impl WhpPageWalk {
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

impl VmBackend for PreparedWhpGuest<'_> {
    type Error = WhpError;

    fn run(&mut self, vcpu: u32) -> Result<VmExit, Self::Error> {
        if vcpu != 0 {
            return Err(WhpError::InvalidVcpu);
        }
        if self.trapped_mmio_retired {
            return Err(WhpError::InvalidMapping);
        }
        self.partition.run()
    }

    fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.partition.read_guest(address, output)
    }

    fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.partition.write_guest(address, input)
    }

    fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error> {
        if vcpu != 0 {
            return Err(WhpError::InvalidVcpu);
        }
        self.partition.inject_interrupt(vector)
    }
}

impl DeadlineVmBackend for PreparedWhpGuest<'_> {
    fn run_with_deadline(
        &mut self,
        vcpu: u32,
        maximum_micros: u32,
    ) -> Result<mrml_kernel::VmDeadlineOutcome, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(WhpError::InvalidMapping);
        }
        self.partition.run_vp_with_deadline(vcpu, maximum_micros)
    }
}

impl mrml_kernel::AffinityDeadlineVmBackend for PreparedWhpGuest<'_> {
    fn run_with_affinity_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        maximum_micros: u32,
    ) -> Result<mrml_kernel::VmDeadlineOutcome, Self::Error> {
        if self.trapped_mmio_retired {
            return Err(WhpError::InvalidMapping);
        }
        self.partition
            .run_vp_with_affinity_deadline(vcpu, logical_cpu, maximum_micros)
    }
}

impl mrml_kernel::IoReadCompleter for PreparedWhpGuest<'_> {
    fn complete_io_read(
        &mut self,
        vcpu: u32,
        port: u16,
        size: u8,
        value: u32,
    ) -> Result<(), Self::Error> {
        self.partition.complete_io_read(vcpu, port, size, value)
    }
}

impl mrml_kernel::MmioWriteCompleter for PreparedWhpGuest<'_> {
    fn complete_mmio_write(
        &mut self,
        vcpu: u32,
        guest_address: u64,
        size: u8,
        value: u64,
    ) -> Result<(), Self::Error> {
        self.partition
            .complete_mmio_write(vcpu, guest_address, size, value)
    }
}

impl RevocableVmBackend for PreparedWhpGuest<'_> {
    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error> {
        self.partition.revoke_guest_mapping(guest_address, bytes)
    }
}

impl GpuVmmMemory for PreparedWhpGuest<'_> {
    fn write_gpu_service(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.partition.write_service(address, input)
    }
}

impl VirtualBlockVmmMemory for PreparedWhpGuest<'_> {
    fn write_virtual_block(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.partition.write_service(address, input)
    }
}

impl WhpSystem {
    /// Prepares the ordinary one-vCPU boot kernel without an emulated APIC so
    /// its terminal HLT remains an observable hosted-test exit.
    pub fn prepare_boot_kernel<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    pub fn prepare_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares a standalone kernel whose architectural exceptions are
    /// delivered through its guest IDT instead of intercepted by WHP.
    pub fn prepare_isolated_service_kernel<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: false,
                cpus: 1,
            },
        )
    }

    /// Prepares a kernel with its framebuffer and supervisor-only local APIC.
    pub fn prepare_timer_kernel<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares the timer kernel with guest-IDT delivery for CPL3 proof traps.
    pub fn prepare_preemption_kernel<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: false,
                cpus: 1,
            },
        )
    }

    /// Prepares a signed guest with mediated GPU rings in its initial address
    /// space. Command memory is writable/NX and completion memory is
    /// read-only/NX to the guest.
    pub fn prepare_gpu_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        queue: GpuSharedQueueLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
            executable,
            handoff,
            layout,
            KernelDevices {
                framebuffer: false,
                local_apic: false,
                gpu_queue: Some(queue),
                block_queue: None,
                block_configuration: None,
                block_resume: None,
                trapped_mmio: None,
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares the standalone kernel with its authenticated framebuffer and
    /// mediated GPU queues present before the vCPU can execute.
    pub fn prepare_kernel_gpu_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        queue: GpuSharedQueueLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares a kernel guest with one MRML-specific virtual-block queue in
    /// its initial address space. Request pages are writable/NX and completion
    /// pages are read-only/NX to the guest while retaining device-path writes.
    pub fn prepare_kernel_block_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares the MRML-native block queue plus one first-level MMIO trap
    /// page without creating a WHP GPA RAM mapping for that page.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_kernel_block_mmio_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
        mmio_address: u64,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        if !mmio_address.is_multiple_of(PAGE_SIZE) {
            return Err(WhpError::InvalidMapping);
        }
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 1,
            },
        )
    }

    /// Prepares the bounded translation path, removes its exact MMIO leaf while
    /// the guest is still non-runnable, and returns it for mapper installation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_kernel_block_dynamic_mmio_guest<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        queue: VirtualBlockQueueLayout,
        configuration: VirtualBlockConfigurationPage,
        resume: VirtualBlockResumePage,
        mmio_address: u64,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        if !mmio_address.is_multiple_of(PAGE_SIZE) {
            return Err(WhpError::InvalidMapping);
        }
        let mut guest = self.prepare_kernel_block_mmio_guest(
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

    /// Prepares two WHP virtual processors behind the emulated local APIC.
    /// The authenticated handoff must bind their MADT, trampoline, and stack
    /// arena as one indivisible boot contract.
    pub fn prepare_smp_kernel<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        self.prepare_guest_inner(
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
                intercept_breakpoint: true,
                cpus: 2,
            },
        )
    }

    fn prepare_guest_inner<'system>(
        &'system self,
        executable: &VerifiedExecutable<'_>,
        handoff: &[u8],
        layout: WhpLaunchLayout,
        devices: KernelDevices,
    ) -> Result<PreparedWhpGuest<'system>, WhpError> {
        let map_framebuffer = devices.framebuffer;
        let queue = devices.gpu_queue;
        let block_queue = devices.block_queue;
        let block_configuration = devices.block_configuration;
        let block_resume = devices.block_resume;
        let trapped_mmio = devices.trapped_mmio;
        let smp = devices.cpus == 2;
        if !matches!(devices.cpus, 1 | 2) {
            return Err(WhpError::InvalidVcpu);
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
            return Err(WhpError::InvalidMapping);
        }
        let decoded = BootHandoff::decode(handoff, |_| {}).map_err(WhpError::Handoff)?;
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
                Some(page)
            }
            (false, None, None, _) => None,
            _ => return Err(WhpError::InvalidMapping),
        };
        let image_bytes = page_bytes(executable.image().image_size() as u64)?;
        let handoff_bytes = page_bytes(handoff.len() as u64)?;
        let table_bytes = layout
            .table_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(WhpError::MemoryOverflow)?;
        let stack_bytes = layout
            .stack_pages
            .checked_mul(u64::from(devices.cpus))
            .and_then(|pages| pages.checked_mul(PAGE_SIZE))
            .ok_or(WhpError::MemoryOverflow)?;
        if smp {
            PerCpuPrivilegeStacks::<2>::new(
                layout.stack_physical,
                layout.stack_virtual,
                layout.stack_pages,
            )
            .map_err(|_| WhpError::InvalidMapping)?;
        }
        let stack_layout = PrivilegeStackLayout::new(layout.stack_virtual, layout.stack_pages)
            .map_err(|_| WhpError::InvalidMapping)?;
        let physical_stack = PrivilegeStackLayout::new(layout.stack_physical, layout.stack_pages)
            .map_err(|_| WhpError::InvalidMapping)?;
        let framebuffer = decoded.framebuffer();
        let framebuffer_bytes = page_bytes(framebuffer.byte_length())?;
        let queue_bytes = match queue {
            Some(value) => value
                .pages_per_ring()
                .checked_mul(PAGE_SIZE)
                .ok_or(WhpError::MemoryOverflow)?,
            None => PAGE_SIZE,
        };
        let (command_base, completion_base) = queue
            .map(|value| (value.command_base(), value.completion_base()))
            .unwrap_or((0, 0));
        let block_queue_bytes = match block_queue {
            Some(value) => value
                .pages_per_queue()
                .checked_mul(PAGE_SIZE)
                .ok_or(WhpError::MemoryOverflow)?,
            None => PAGE_SIZE,
        };
        let (block_request_base, block_completion_base) = block_queue
            .map(|value| (value.request_base(), value.completion_base()))
            .unwrap_or((0, 0));
        let mut physical_ranges = [(0, 0); 12];
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
        if let Some(trampoline) = trampoline {
            physical_ranges[physical_count] = (trampoline, PAGE_SIZE);
            physical_count += 1;
        }
        validate_ranges(&physical_ranges[..physical_count])?;
        let mut virtual_ranges = [(0, 0); 12];
        virtual_ranges[..4].copy_from_slice(&[
            (layout.table_physical, PAGE_SIZE),
            (layout.image_virtual, image_bytes),
            (layout.handoff_virtual, handoff_bytes),
            (layout.stack_virtual, stack_bytes),
        ]);
        let mut virtual_count = 4;
        if map_framebuffer {
            virtual_ranges[virtual_count] = (framebuffer.base().get(), framebuffer_bytes);
            virtual_count += 1;
        }
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
        if let Some(trampoline) = trampoline {
            virtual_ranges[virtual_count] = (trampoline, PAGE_SIZE);
            virtual_count += 1;
        }
        if let Some(address) = trapped_mmio {
            virtual_ranges[virtual_count] = (address, PAGE_SIZE);
            virtual_count += 1;
        }
        validate_ranges(&virtual_ranges[..virtual_count])?;

        let plain_boot = devices.framebuffer
            && !devices.local_apic
            && devices.gpu_queue.is_none()
            && devices.block_queue.is_none();
        let mut partition = if smp {
            self.prepare_smp_partition()?
        } else if plain_boot {
            self.prepare_partition_without_xapic(devices.intercept_breakpoint)?
        } else {
            self.prepare_partition_with_breakpoint_exit(devices.intercept_breakpoint)?
        };
        partition.map_zeroed(range(
            layout.table_physical,
            table_bytes,
            MapPermissions::read_write(),
        )?)?;
        if map_framebuffer {
            partition.map_zeroed(range(
                framebuffer.base().get(),
                framebuffer_bytes,
                MapPermissions::read_write(),
            )?)?;
        }
        if let Some(queue) = queue {
            partition.map_zeroed(range(
                queue.command_base(),
                queue_bytes,
                MapPermissions::read_write(),
            )?)?;
            partition.map_zeroed_service_readonly(range(
                queue.completion_base(),
                queue_bytes,
                MapPermissions::read_only(),
            )?)?;
        }
        if let Some(queue) = block_queue {
            partition.map_zeroed(range(
                queue.request_base(),
                block_queue_bytes,
                MapPermissions::read_write(),
            )?)?;
            partition.map_zeroed_service_readonly(range(
                queue.completion_base(),
                block_queue_bytes,
                MapPermissions::read_only(),
            )?)?;
        }
        if let Some(configuration) = block_configuration {
            partition.map_zeroed_service_readonly(range(
                configuration.base(),
                PAGE_SIZE,
                MapPermissions::read_only(),
            )?)?;
            let mut encoded = [0; PAGE_SIZE as usize];
            configuration.encode_page(&mut encoded);
            partition.write_service(configuration.base(), &encoded)?;
        }
        if let Some(resume) = block_resume {
            partition.map_zeroed_service_readonly(range(
                resume.base(),
                PAGE_SIZE,
                MapPermissions::read_only(),
            )?)?;
            let mut encoded = [0; PAGE_SIZE as usize];
            resume.encode_page(&mut encoded);
            partition.write_service(resume.base(), &encoded)?;
        }
        let image_mapping = partition.map_zeroed(range(
            layout.image_physical,
            image_bytes,
            MapPermissions::read_write(),
        )?)?;
        partition.map_initialized(
            range(
                layout.handoff_physical,
                handoff_bytes,
                MapPermissions::read_only(),
            )?,
            handoff,
        )?;
        partition.map_zeroed(range(
            layout.stack_physical,
            stack_bytes,
            MapPermissions::read_write(),
        )?)?;
        if let Some(trampoline) = trampoline {
            partition.map_zeroed(range(trampoline, PAGE_SIZE, MapPermissions::read_write())?)?;
        }

        let image = executable.image();
        let destination =
            partition.mutable_guest(layout.image_physical, image.image_size() as usize)?;
        let entry = image
            .materialize_at(destination, layout.image_virtual)
            .map_err(WhpError::Pe)?;
        partition.seal_pe(image_mapping, image)?;

        let stack = stack_layout
            .early_top()
            .map_err(|_| WhpError::MemoryOverflow)?;
        partition.write_guest(
            physical_stack
                .early_top()
                .map_err(|_| WhpError::MemoryOverflow)?,
            &0u64.to_le_bytes(),
        )?;

        let root = build_page_tables(
            &mut partition,
            image,
            PageTableLaunchContext {
                layout,
                handoff_bytes,
                framebuffer: map_framebuffer
                    .then_some((framebuffer.base().get(), framebuffer_bytes)),
                local_apic: devices.local_apic,
                queue,
                block_queue,
                block_configuration,
                block_resume,
                trapped_mmio,
                cpus: devices.cpus,
                trampoline,
                service_shared: !devices.intercept_breakpoint && !devices.framebuffer,
            },
        )?;
        partition.configure_long_mode(
            entry,
            stack,
            root.get(),
            layout.table_physical,
            layout.handoff_virtual,
            handoff.len() as u64,
            stack_layout
                .entry_top()
                .map_err(|_| WhpError::MemoryOverflow)?,
            stack_layout
                .double_fault_top()
                .map_err(|_| WhpError::MemoryOverflow)?,
        )?;
        Ok(PreparedWhpGuest {
            partition,
            entry,
            root,
            table_physical: layout
                .table_physical
                .checked_add(PAGE_SIZE)
                .ok_or(WhpError::MemoryOverflow)?,
            table_pages: layout
                .table_pages
                .checked_sub(1)
                .ok_or(WhpError::InvalidMapping)?,
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
            ap_trampoline: trampoline,
        })
    }
}

#[derive(Clone, Copy)]
struct PageTableLaunchContext {
    layout: WhpLaunchLayout,
    handoff_bytes: u64,
    framebuffer: Option<(u64, u64)>,
    local_apic: bool,
    queue: Option<GpuSharedQueueLayout>,
    block_queue: Option<VirtualBlockQueueLayout>,
    block_configuration: Option<VirtualBlockConfigurationPage>,
    block_resume: Option<VirtualBlockResumePage>,
    trapped_mmio: Option<u64>,
    cpus: u8,
    trampoline: Option<u64>,
    service_shared: bool,
}

fn build_page_tables(
    partition: &mut PreparedWhpPartition<'_>,
    image: &PeImage<'_>,
    context: PageTableLaunchContext,
) -> Result<PhysAddr, WhpError> {
    let PageTableLaunchContext {
        layout,
        handoff_bytes,
        framebuffer,
        local_apic,
        queue,
        block_queue,
        block_configuration,
        block_resume,
        trapped_mmio,
        cpus,
        trampoline,
        service_shared,
    } = context;
    partition.write_guest(layout.table_physical, &0u64.to_le_bytes())?;
    partition.write_guest(
        layout.table_physical + 8,
        &0x00af_9b00_0000_ffffu64.to_le_bytes(),
    )?;
    let table_start = layout
        .table_physical
        .checked_add(PAGE_SIZE)
        .ok_or(WhpError::MemoryOverflow)?;
    let store = WhpPageTableStore::new(partition, table_start, layout.table_pages - 1)?;
    let mut tables = PageTableBuilder::new(store).map_err(|_| WhpError::InvalidRegisterState)?;
    map_pe(
        &mut tables,
        image,
        layout.image_physical,
        layout.image_virtual,
        layout.user,
    )?;
    let handoff_permissions = if layout.user {
        PagePermissions::USER_READ
    } else {
        PagePermissions::KERNEL_READ
    };
    tables
        .map(
            Mapping::new(
                VirtAddr::new(layout.handoff_virtual).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(layout.handoff_physical).map_err(|_| WhpError::InvalidMapping)?,
                handoff_bytes / PAGE_SIZE,
                handoff_permissions,
            )
            .map_err(|_| WhpError::InvalidMapping)?,
        )
        .map_err(|_| WhpError::PageTable)?;
    if let Some((base, bytes)) = framebuffer {
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(base).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(base).map_err(|_| WhpError::InvalidMapping)?,
                    bytes / PAGE_SIZE,
                    PagePermissions::KERNEL_MMIO_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if local_apic {
        tables
            .map_page(
                VirtAddr::new(XAPIC_BASE).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(XAPIC_BASE).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_MMIO_READ_WRITE,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if service_shared {
        tables
            .map_page(
                VirtAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(0x00f0_0000).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_LOW_READ_WRITE,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    tables
        .map_page(
            VirtAddr::new(layout.table_physical).map_err(|_| WhpError::InvalidMapping)?,
            PhysAddr::new(layout.table_physical).map_err(|_| WhpError::InvalidMapping)?,
            if layout.user {
                PagePermissions::USER_READ
            } else {
                PagePermissions::KERNEL_READ
            },
        )
        .map_err(|_| WhpError::PageTable)?;
    let stack_permissions = if cpus == 2 {
        PagePermissions::KERNEL_LOW_READ_WRITE
    } else {
        PagePermissions::KERNEL_READ_WRITE
    };
    for cpu in 0..usize::from(cpus) {
        let offset = (cpu as u64)
            .checked_mul(layout.stack_pages)
            .and_then(|pages| pages.checked_mul(PAGE_SIZE))
            .ok_or(WhpError::MemoryOverflow)?;
        let stack_layout = PrivilegeStackLayout::new(
            layout
                .stack_virtual
                .checked_add(offset)
                .ok_or(WhpError::MemoryOverflow)?,
            layout.stack_pages,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        let physical_stack = PrivilegeStackLayout::new(
            layout
                .stack_physical
                .checked_add(offset)
                .ok_or(WhpError::MemoryOverflow)?,
            layout.stack_pages,
        )
        .map_err(|_| WhpError::InvalidMapping)?;
        for (virtual_base, physical_base, pages, permissions) in [
            (
                stack_layout.early_base(),
                physical_stack.early_base(),
                stack_layout.early_pages(),
                stack_permissions,
            ),
            (
                stack_layout
                    .entry_base()
                    .map_err(|_| WhpError::MemoryOverflow)?,
                physical_stack
                    .entry_base()
                    .map_err(|_| WhpError::MemoryOverflow)?,
                stack_layout.entry_pages(),
                stack_permissions,
            ),
            (
                stack_layout
                    .double_fault_base()
                    .map_err(|_| WhpError::MemoryOverflow)?,
                physical_stack
                    .double_fault_base()
                    .map_err(|_| WhpError::MemoryOverflow)?,
                stack_layout.double_fault_pages(),
                stack_permissions,
            ),
        ] {
            tables
                .map(
                    Mapping::new(
                        VirtAddr::new(virtual_base).map_err(|_| WhpError::InvalidMapping)?,
                        PhysAddr::new(physical_base).map_err(|_| WhpError::InvalidMapping)?,
                        pages,
                        permissions,
                    )
                    .map_err(|_| WhpError::InvalidMapping)?,
                )
                .map_err(|_| WhpError::PageTable)?;
        }
    }
    if let Some(trampoline) = trampoline {
        tables
            .map_page(
                VirtAddr::new(trampoline).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(trampoline).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_LOW_READ_WRITE,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if let Some(queue) = queue {
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(queue.command_base()).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(queue.command_base()).map_err(|_| WhpError::InvalidMapping)?,
                    queue.pages_per_ring(),
                    PagePermissions::KERNEL_SHARED_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(queue.completion_base()).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(queue.completion_base()).map_err(|_| WhpError::InvalidMapping)?,
                    queue.pages_per_ring(),
                    PagePermissions::KERNEL_SHARED_READ,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if let Some(queue) = block_queue {
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(queue.request_base()).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(queue.request_base()).map_err(|_| WhpError::InvalidMapping)?,
                    queue.pages_per_queue(),
                    PagePermissions::KERNEL_SHARED_READ_WRITE,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
        tables
            .map(
                Mapping::new(
                    VirtAddr::new(queue.completion_base()).map_err(|_| WhpError::InvalidMapping)?,
                    PhysAddr::new(queue.completion_base()).map_err(|_| WhpError::InvalidMapping)?,
                    queue.pages_per_queue(),
                    PagePermissions::KERNEL_SHARED_READ,
                )
                .map_err(|_| WhpError::InvalidMapping)?,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if let Some(configuration) = block_configuration {
        tables
            .map_page(
                VirtAddr::new(configuration.base()).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(configuration.base()).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_SHARED_READ,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if let Some(resume) = block_resume {
        tables
            .map_page(
                VirtAddr::new(resume.base()).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(resume.base()).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_SHARED_READ,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if let Some(address) = trapped_mmio {
        tables
            .map_page(
                VirtAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
                PhysAddr::new(address).map_err(|_| WhpError::InvalidMapping)?,
                PagePermissions::KERNEL_MMIO_READ_WRITE,
            )
            .map_err(|_| WhpError::PageTable)?;
    }
    if cpus == 2 {
        let mut frame_index = 0;
        while frame_index < tables.store().allocated_pages() {
            let frame = tables
                .store()
                .allocated_frame(frame_index)
                .ok_or(WhpError::PageTable)?;
            tables
                .map_page(
                    VirtAddr::new(frame.get()).map_err(|_| WhpError::InvalidMapping)?,
                    frame,
                    PagePermissions::KERNEL_LOW_READ_WRITE,
                )
                .map_err(|_| WhpError::PageTable)?;
            frame_index += 1;
        }
    }
    Ok(tables.root())
}

pub(super) struct WhpPageTableStore<'a, 'system> {
    partition: &'a mut PreparedWhpPartition<'system>,
    start: u64,
    next: u64,
    end: u64,
}

impl<'a, 'system> WhpPageTableStore<'a, 'system> {
    pub(super) fn new(
        partition: &'a mut PreparedWhpPartition<'system>,
        start: u64,
        pages: u64,
    ) -> Result<Self, WhpError> {
        let end = start
            .checked_add(
                pages
                    .checked_mul(PAGE_SIZE)
                    .ok_or(WhpError::MemoryOverflow)?,
            )
            .ok_or(WhpError::MemoryOverflow)?;
        Ok(Self {
            partition,
            start,
            next: start,
            end,
        })
    }

    fn open_existing(
        partition: &'a mut PreparedWhpPartition<'system>,
        start: u64,
        pages: u64,
    ) -> Result<Self, WhpError> {
        let mut store = Self::new(partition, start, pages)?;
        store.next = store.end;
        Ok(store)
    }

    fn entry_address(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        if index >= 512
            || table.get() < self.start
            || table.get() >= self.next
            || !table.get().is_multiple_of(PAGE_SIZE)
        {
            return Err(PageTableBuildError::Storage);
        }
        table
            .get()
            .checked_add(index as u64 * 8)
            .ok_or(PageTableBuildError::AddressOverflow)
    }

    const fn allocated_pages(&self) -> u64 {
        (self.next - self.start) / PAGE_SIZE
    }

    fn allocated_frame(&self, index: u64) -> Option<PhysAddr> {
        (index < self.allocated_pages())
            .then(|| self.start + index * PAGE_SIZE)
            .and_then(|address| PhysAddr::new(address).ok())
    }
}

impl PageTableStore for WhpPageTableStore<'_, '_> {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
        let following = self
            .next
            .checked_add(PAGE_SIZE)
            .ok_or(PageTableBuildError::AddressOverflow)?;
        if following > self.end {
            return Err(PageTableBuildError::Storage);
        }
        let address = PhysAddr::new(self.next).map_err(|_| PageTableBuildError::Storage)?;
        self.partition
            .write_guest(self.next, &[0u8; PAGE_SIZE as usize])
            .map_err(|_| PageTableBuildError::Storage)?;
        self.next = following;
        Ok(address)
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        let mut bytes = [0u8; 8];
        self.partition
            .read_guest(self.entry_address(table, index)?, &mut bytes)
            .map_err(|_| PageTableBuildError::Storage)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write(
        &mut self,
        table: PhysAddr,
        index: usize,
        value: u64,
    ) -> Result<(), PageTableBuildError> {
        let address = self.entry_address(table, index)?;
        self.partition
            .write_guest(address, &value.to_le_bytes())
            .map_err(|_| PageTableBuildError::Storage)
    }
}

fn map_pe<S: PageTableStore>(
    tables: &mut PageTableBuilder<S>,
    image: &PeImage<'_>,
    physical: u64,
    virtual_base: u64,
    user: bool,
) -> Result<(), WhpError> {
    let mut validated = AddressSpace::<{ MAX_PE_SECTIONS + 1 }>::new();
    for index in 0..image.load_region_count() {
        validated
            .map(pe_mapping(image, physical, virtual_base, index, user)?)
            .map_err(|_| WhpError::InvalidMapping)?;
    }
    for index in 0..image.load_region_count() {
        tables
            .map(pe_mapping(image, physical, virtual_base, index, user)?)
            .map_err(|_| WhpError::PageTable)?;
    }
    Ok(())
}

fn pe_mapping(
    image: &PeImage<'_>,
    physical: u64,
    virtual_base: u64,
    index: usize,
    user: bool,
) -> Result<Mapping, WhpError> {
    let region = image.load_region(index).map_err(WhpError::Pe)?;
    let permissions = match (user, region.writable(), region.executable()) {
        (true, true, false) => PagePermissions::USER_READ_WRITE,
        (true, false, true) => PagePermissions::USER_READ_EXECUTE,
        (true, false, false) => PagePermissions::USER_READ,
        (false, true, false) => PagePermissions::KERNEL_READ_WRITE,
        (false, false, true) => PagePermissions::KERNEL_READ_EXECUTE,
        (false, false, false) => PagePermissions::KERNEL_READ,
        (_, true, true) => return Err(WhpError::InvalidMapping),
    };
    let offset = region.virtual_address() as u64;
    Mapping::new(
        VirtAddr::new(
            virtual_base
                .checked_add(offset)
                .ok_or(WhpError::InvalidMapping)?,
        )
        .map_err(|_| WhpError::InvalidMapping)?,
        PhysAddr::new(
            physical
                .checked_add(offset)
                .ok_or(WhpError::InvalidMapping)?,
        )
        .map_err(|_| WhpError::InvalidMapping)?,
        region.pages() as u64,
        permissions,
    )
    .map_err(|_| WhpError::InvalidMapping)
}

fn range(start: u64, bytes: u64, permissions: MapPermissions) -> Result<GuestRange, WhpError> {
    GuestRange::new(start, bytes, permissions)
}

fn page_bytes(bytes: u64) -> Result<u64, WhpError> {
    if bytes == 0 {
        return Err(WhpError::EmptyMemory);
    }
    bytes
        .checked_add(PAGE_SIZE - 1)
        .ok_or(WhpError::MemoryOverflow)
        .map(|value| value / PAGE_SIZE * PAGE_SIZE)
}

fn validate_ranges(ranges: &[(u64, u64)]) -> Result<(), WhpError> {
    for (index, &(start, bytes)) in ranges.iter().enumerate() {
        let end = start.checked_add(bytes).ok_or(WhpError::MemoryOverflow)?;
        for &(other, other_bytes) in &ranges[..index] {
            let other_end = other
                .checked_add(other_bytes)
                .ok_or(WhpError::MemoryOverflow)?;
            if start < other_end && other < end {
                return Err(WhpError::MemoryOverlap);
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
        IoPortPolicy, IoPortRule, ObjectId, Rights, SIGNED_ARTIFACT_HEADER_BYTES,
        SIGNED_ARTIFACT_OVERHEAD_BYTES, SignedArtifact, TrustRoot,
        VIRTUAL_BLOCK_COMPLETION_ACK_PORT, VIRTUAL_BLOCK_COMPLETION_BYTES,
        VIRTUAL_BLOCK_CONFIGURATION_BYTES, VIRTUAL_BLOCK_DOORBELL_PORT,
        VIRTUAL_BLOCK_RESUME_STATE_BYTES, VirtualBlockBackend, VirtualBlockCompletion,
        VirtualBlockCompletionStatus, VirtualBlockConfiguration, VirtualBlockDevice,
        VirtualBlockMutationError, VirtualBlockProcessOutcome, VirtualBlockQueueBridge,
        VirtualBlockRequest, VmTable, artifact_statement, run_virtual_block_completion_ack_once,
        run_virtual_block_doorbell_once,
    };

    fn block_configuration(layout: VirtualBlockQueueLayout) -> VirtualBlockConfiguration {
        let mut device = VirtualBlockDevice::<1>::new(4096, 1, 0).unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        device.configuration().unwrap()
    }

    fn valid_pe() -> [u8; 1024] {
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
        pe[optional + 24..optional + 32].copy_from_slice(&0x20_0000u64.to_le_bytes());
        pe[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        pe[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        pe[optional + 70..optional + 72].copy_from_slice(&0x100u16.to_le_bytes());
        let section = optional + 240;
        pe[section..section + 5].copy_from_slice(b".text");
        pe[section + 8..section + 12].copy_from_slice(&0x20u32.to_le_bytes());
        pe[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 36..section + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        pe[0x200] = 0xcc;
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
        emit(code, at, &[0xeb, 1, 0xcc]);
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
        let mut pe = valid_pe();
        let mut code = [0; 512];
        let mut at = 0;
        let entry = 0x20_1000;
        emit_descriptor_load(&mut code, &mut at, 0x15, GDT_DESCRIPTOR_OFFSET);
        emit_descriptor_load(&mut code, &mut at, 0x1d, IDT_DESCRIPTOR_OFFSET);

        emit_mov(&mut code, &mut at, 0xbf, 0xa0000);
        emit_mov(&mut code, &mut at, 0xb8, 0x6d6d_6d6d_6d6d_6d6d);
        emit(
            &mut code,
            &mut at,
            &[0xb9, 0x00, 0x02, 0x00, 0x00, 0xf3, 0x48, 0xab],
        );
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
            *byte = (index as u64).wrapping_mul(73).wrapping_add(29) as u8;
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
        signed_payload(valid_pe())
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
    fn launch_layout_rejects_aliases_and_weak_arenas() {
        assert_eq!(
            WhpLaunchLayout::new(
                0x1000,
                3,
                0x10000,
                0x140000000,
                0x20000,
                0x200000,
                0x30000,
                0xffff_8000_0030_0000,
                2,
                false
            ),
            Err(WhpError::InvalidMapping)
        );
        assert_eq!(
            validate_ranges(&[(0x1000, 0x2000), (0x2000, 0x1000)]),
            Err(WhpError::MemoryOverlap)
        );
        assert!(
            WhpLaunchLayout::new(
                0x1000,
                8,
                0x10000,
                0x140000000,
                0x20000,
                0x200000,
                0x30000,
                0x300000,
                PRIVILEGE_STACK_ARENA_PAGES,
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn backend_rejects_nonexistent_virtual_processors() {
        let system = WhpSystem::open().unwrap();
        if !system.hypervisor_present().unwrap() {
            return;
        }
        let partition = system.prepare_partition().unwrap();
        let mut guest = PreparedWhpGuest {
            partition,
            entry: 0x20_0000,
            root: PhysAddr::new(0x10_0000).unwrap(),
            table_physical: 0,
            table_pages: 0,
            trapped_mmio: None,
            trapped_mmio_mapped: false,
            trapped_mmio_retired: false,
            service_entry: [None; MAX_ISOLATED_SERVICES],
            service_root: [None; MAX_ISOLATED_SERVICES],
            service_instance: [None; MAX_ISOLATED_SERVICES],
            service_shared: None,
            service_shared_live: [false; 2],
            service_resource: [None; 2],
            service_resource_live: [false; 2],
            ap_trampoline: None,
        };
        assert_eq!(VmBackend::run(&mut guest, 1), Err(WhpError::InvalidVcpu));
        assert_eq!(
            VmBackend::inject_interrupt(&mut guest, 1, 48),
            Err(WhpError::InvalidVcpu)
        );
    }

    #[test]
    fn live_long_mode_guest_reaches_breakpoint_and_deadline_exits() {
        let system = WhpSystem::open().unwrap();
        if !system.hypervisor_present().unwrap() {
            return;
        }
        let mut partition = system.prepare_partition().unwrap();
        partition
            .map_zeroed(GuestRange::new(0x10_0000, 0x8000, MapPermissions::read_write()).unwrap())
            .unwrap();
        partition
            .map_initialized(
                GuestRange::new(0x20_0000, 0x1000, MapPermissions::read_execute()).unwrap(),
                &[0xcc],
            )
            .unwrap();
        partition
            .map_initialized(
                GuestRange::new(0x21_0000, 0x1000, MapPermissions::read_execute()).unwrap(),
                &[0xeb, 0xfe],
            )
            .unwrap();
        partition
            .map_zeroed(GuestRange::new(0x30_0000, 0x1000, MapPermissions::read_write()).unwrap())
            .unwrap();
        let root = {
            partition
                .write_guest(0x10_0008, &0x00af_9b00_0000_ffffu64.to_le_bytes())
                .unwrap();
            let store = WhpPageTableStore::new(&mut partition, 0x10_1000, 7).unwrap();
            let mut tables = PageTableBuilder::new(store).unwrap();
            for (address, permissions) in [
                (0x10_0000, PagePermissions::KERNEL_READ),
                (0x20_0000, PagePermissions::KERNEL_READ_EXECUTE),
                (0x21_0000, PagePermissions::KERNEL_READ_EXECUTE),
                (0x30_0000, PagePermissions::KERNEL_READ_WRITE),
            ] {
                tables
                    .map_page(
                        VirtAddr::new(address).unwrap(),
                        PhysAddr::new(address).unwrap(),
                        permissions,
                    )
                    .unwrap();
            }
            tables.root()
        };
        partition
            .configure_long_mode(
                0x20_0000,
                0x30_0ff8,
                root.get(),
                0x10_0000,
                0x30_0000,
                8,
                0x50_0000,
                0x60_0000,
            )
            .unwrap();
        let affinity_before = crate::native::current_thread_affinity().unwrap();
        assert_eq!(
            partition.run(),
            Ok(VmExit::Unknown {
                reason: (0x1002u64 << 32) | 3,
            })
        );
        partition
            .configure_long_mode(
                0x21_0000,
                0x30_0ff8,
                root.get(),
                0x10_0000,
                0x30_0000,
                8,
                0x50_0000,
                0x60_0000,
            )
            .unwrap();
        assert_eq!(
            partition.run_vp_with_deadline(0, 0),
            Err(WhpError::InvalidDeadline)
        );
        assert_eq!(
            partition.run_vp_with_affinity_deadline(0, 64, 10_000),
            Err(WhpError::InvalidAffinity)
        );
        assert_eq!(
            partition.run_vp_with_affinity_deadline(0, 0, 10_000),
            Ok(mrml_kernel::VmDeadlineOutcome::Expired)
        );
        assert_eq!(
            crate::native::current_thread_affinity().unwrap(),
            affinity_before
        );
    }

    #[test]
    fn live_verified_pe_reaches_signed_entry_point() {
        let system = WhpSystem::open().unwrap();
        if !system.hypervisor_present().unwrap() {
            return;
        }
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
        let layout = WhpLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0x20_0000,
            0x30_0000,
            0x30_0000,
            0x40_0000,
            0xffff_8000_0040_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            true,
        )
        .unwrap();
        let queue_layout = GpuSharedQueueLayout::new(0x50_0000, 0x50_2000, 64).unwrap();
        let block_layout = VirtualBlockQueueLayout::new(0x60_0000, 0x60_2000, 64).unwrap();
        let mut guest = system
            .prepare_gpu_guest(&executable, &valid_handoff(), layout, queue_layout)
            .unwrap()
            .attach_virtual_block_queue_memory(block_layout)
            .unwrap();
        assert_eq!(guest.entry(), 0x20_1000);
        let stack_layout =
            PrivilegeStackLayout::new(0xffff_8000_0040_0000, PRIVILEGE_STACK_ARENA_PAGES).unwrap();
        assert_eq!(
            guest
                .page_walk(stack_layout.early_base())
                .unwrap()
                .physical_address(stack_layout.early_base()),
            Some(0x40_0000)
        );
        for guard in [
            stack_layout.entry_guard().unwrap(),
            stack_layout.double_fault_guard().unwrap(),
        ] {
            assert_eq!(
                guest.page_walk(guard).unwrap().physical_address(guard),
                None
            );
        }
        let double_fault_base = stack_layout.double_fault_base().unwrap();
        assert_eq!(
            guest
                .page_walk(double_fault_base)
                .unwrap()
                .physical_address(double_fault_base),
            Some(0x42_2000)
        );
        let command_walk = guest.page_walk(queue_layout.command_base()).unwrap();
        assert_eq!(command_walk.levels(), 4);
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
        assert_eq!(
            VmBackend::write_guest(&mut guest, 0x20_1000, &[0xf4]),
            Err(WhpError::ReadOnlyMemory)
        );
        GpuVmmMemory::write_gpu_service(&mut guest, queue_layout.completion_base(), &[0x5a])
            .unwrap();
        let mut service_byte = [0; 1];
        VmBackend::read_guest(&guest, queue_layout.completion_base(), &mut service_byte).unwrap();
        assert_eq!(service_byte, [0x5a]);
        VmBackend::write_guest(&mut guest, queue_layout.command_base(), &[1]).unwrap();
        assert_eq!(
            VmBackend::write_guest(&mut guest, queue_layout.completion_base(), &[1]),
            Err(WhpError::ReadOnlyMemory)
        );
        VmBackend::write_guest(&mut guest, block_layout.request_base(), &[0x31]).unwrap();
        assert_eq!(
            VmBackend::write_guest(&mut guest, block_layout.completion_base(), &[0x32]),
            Err(WhpError::ReadOnlyMemory)
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
        assert_eq!(
            guest.run(),
            Ok(VmExit::Unknown {
                reason: (0x1002u64 << 32) | 3,
            })
        );
    }

    #[test]
    fn live_signed_guest_reuses_one_virtual_block_slot_for_write_and_read() {
        let system = WhpSystem::open().unwrap();
        if !system.hypervisor_present().unwrap() {
            return;
        }
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
        let launch = WhpLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            0x20_0000,
            0x30_0000,
            0x30_0000,
            0x40_0000,
            0xffff_8000_0040_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            true,
        )
        .unwrap();
        let layout = VirtualBlockQueueLayout::new(0x60_0000, 0x60_2000, 1).unwrap();
        let overlapping = VirtualBlockQueueLayout::new(0x20_0000, 0x60_2000, 1).unwrap();
        let configuration = block_configuration(layout);
        assert_eq!(
            VirtualBlockConfigurationPage::new(layout.request_base(), configuration),
            Err(mrml_kernel::VirtualBlockError::InvalidConfiguration)
        );
        assert!(matches!(
            system.prepare_kernel_block_guest(
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
            Err(WhpError::InvalidMapping)
        ));
        assert!(matches!(
            system.prepare_kernel_block_guest(
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
            Err(WhpError::MemoryOverlap)
        ));
        let mut guest = system
            .prepare_kernel_block_guest(
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
            Err(WhpError::ReadOnlyMemory)
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
            Err(WhpError::ReadOnlyMemory)
        );
        VirtualBlockVmmMemory::write_virtual_block(&mut guest, 0x60_5000, &[0x4d]).unwrap();
        let mut marker = [0];
        VmBackend::read_guest(&guest, 0x60_5000, &mut marker).unwrap();
        assert_eq!(marker, [0x4d]);

        let block_object = ObjectId(0x210);
        let interrupt_object = ObjectId(0x211);
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
        let mut router = HypercallRouter::new(ObjectId(0x212), ObjectId(0x213), ObjectId(0x214));
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
            Ok(1)
        );

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
