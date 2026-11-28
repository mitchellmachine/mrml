use core::arch::asm;

use super::{
    ADDRESS_MASK, Mapping, PageError, PagePermissions, PageTableEntry, PassivePciPage, UserBufferAccess,
    UserBufferError, VirtAddr,
};
use crate::{
    BootDmaReservation, Capability, CapabilitySpace, GuestMappingRevoker, MemoryBackingKind,
    MemoryMappingBackend, MemoryMappingBackendRequest, MemoryMappingRevocationBackend,
    MemoryObjectId, MemoryPoolId, MemoryPoolTable, MemoryRegion, MemoryResourceError, ObjectId,
    PAGE_SIZE, PhysAddr, Rights,
};

const LEAF_ACCESSED_DIRTY: u64 = (1 << 5) | (1 << 6);
const LEAF_DEVICE_PAT_INDEX_THREE: u64 = (1 << 3) | (1 << 4);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableBuildError {
    Storage,
    InterruptsEnabled,
    InvalidIntermediate,
    AlreadyMapped,
    NotMapped,
    MappingMismatch,
    PhysicalAlias,
    AliasWalkLimit,
    AddressOverflow,
    Page(PageError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountedPageTableStoreError {
    PageTable(PageTableBuildError),
    Memory(MemoryResourceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InactivePageTableMappingError {
    WrongTarget,
    MissingPhysicalBacking,
    UnsupportedAccess,
    InvalidMapping,
    PageTable(PageTableBuildError),
    Poisoned,
}

impl From<PageTableBuildError> for AccountedPageTableStoreError {
    fn from(value: PageTableBuildError) -> Self {
        Self::PageTable(value)
    }
}

impl From<MemoryResourceError> for AccountedPageTableStoreError {
    fn from(value: MemoryResourceError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveLeaf {
    physical: PhysAddr,
    writable: bool,
    executable: bool,
    user: bool,
    device_pat_index_three: bool,
}

impl ActiveLeaf {
    pub const fn physical(self) -> PhysAddr {
        self.physical
    }
    pub const fn writable(self) -> bool {
        self.writable
    }
    pub const fn executable(self) -> bool {
        self.executable
    }
    pub const fn user(self) -> bool {
        self.user
    }
    /// Whether this 4 KiB leaf selects PAT index 3 through PWT=PCD=1.
    /// This is an encoding fact, not proof that the active PAT maps index 3
    /// to UC or that no cacheable aliases exist.
    pub const fn device_pat_index_three(self) -> bool {
        self.device_pat_index_three
    }
}

fn decode_leaf_entry(bits: u64) -> Result<Option<ActiveLeaf>, PageTableBuildError> {
    if bits & 1 == 0 {
        return Ok(None);
    }
    let allowed =
        ADDRESS_MASK | (1 << 63) | LEAF_ACCESSED_DIRTY | 0b111 | LEAF_DEVICE_PAT_INDEX_THREE;
    if bits & !allowed != 0 {
        return Err(PageTableBuildError::MappingMismatch);
    }
    let device_pat_bits = bits & LEAF_DEVICE_PAT_INDEX_THREE;
    if device_pat_bits != 0 && device_pat_bits != LEAF_DEVICE_PAT_INDEX_THREE {
        return Err(PageTableBuildError::MappingMismatch);
    }
    let physical =
        PhysAddr::new(bits & ADDRESS_MASK).map_err(|_| PageTableBuildError::MappingMismatch)?;
    Ok(Some(ActiveLeaf {
        physical,
        writable: bits & (1 << 1) != 0,
        executable: bits & (1 << 63) == 0,
        user: bits & (1 << 2) != 0,
        device_pat_index_three: device_pat_bits == LEAF_DEVICE_PAT_INDEX_THREE,
    }))
}

fn active_leaf_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    address: VirtAddr,
) -> Result<Option<ActiveLeaf>, PageTableBuildError> {
    let mut table = root;
    let mut effective_writable = true;
    let mut effective_executable = true;
    let mut effective_user = true;
    for index in [
        address.pml4_index(),
        address.pdpt_index(),
        address.directory_index(),
    ] {
        let entry = store.read(table, index)?;
        if entry & 1 == 0 {
            return Ok(None);
        }
        if entry & (1 << 7) != 0 || entry & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0 {
            return Err(PageTableBuildError::InvalidIntermediate);
        }
        effective_writable &= entry & (1 << 1) != 0;
        effective_user &= entry & (1 << 2) != 0;
        effective_executable &= entry & (1 << 63) == 0;
        table = PhysAddr::new(entry & ADDRESS_MASK)
            .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
    }
    let bits = store.read(table, address.table_index())?;
    let Some(mut leaf) = decode_leaf_entry(bits)? else {
        return Ok(None);
    };
    leaf.writable &= effective_writable;
    leaf.user &= effective_user;
    leaf.executable &= effective_executable;
    Ok(Some(leaf))
}

fn validate_user_buffer_leaf(
    leaf: ActiveLeaf,
    access: UserBufferAccess,
) -> Result<(), UserBufferError> {
    if !leaf.user()
        || leaf.device_pat_index_three()
        || (access == UserBufferAccess::Write && !leaf.writable())
    {
        return Err(UserBufferError::AccessDenied);
    }
    Ok(())
}

/// Minimal storage contract for physical 4 KiB page-table frames. A platform
/// implementation must return a new zeroed frame on every allocation and make
/// reads/writes address the direct physical table contents.
pub trait PageTableStore {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError>;
    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError>;
    fn write(
        &mut self,
        table: PhysAddr,
        index: usize,
        value: u64,
    ) -> Result<(), PageTableBuildError>;
}

/// Monotonic page-table storage backed by a caller-owned, identity-mapped
/// physical arena. This is used after firmware allocation is unavailable.
pub struct PreallocatedPageTableStore {
    base: PhysAddr,
    capacity: usize,
    allocated: usize,
}

impl PreallocatedPageTableStore {
    /// Opens a zeroable arena for exclusive page-table construction.
    ///
    /// # Safety
    ///
    /// Every page in `[base, base + pages * PAGE_SIZE)` must be identity
    /// mapped, supervisor-writable, exclusively owned by the caller, and not
    /// observable by another CPU for the lifetime of this store.
    pub unsafe fn new(base: PhysAddr, pages: u64) -> Result<Self, PageTableBuildError> {
        let capacity = usize::try_from(pages).map_err(|_| PageTableBuildError::Storage)?;
        if capacity == 0
            || capacity > 256
            || !base.get().is_multiple_of(PAGE_SIZE)
            || pages
                .checked_mul(PAGE_SIZE)
                .and_then(|bytes| base.get().checked_add(bytes))
                .is_none_or(|end| end >> 52 != 0)
        {
            return Err(PageTableBuildError::Storage);
        }
        Ok(Self {
            base,
            capacity,
            allocated: 0,
        })
    }

    pub const fn allocated_pages(&self) -> usize {
        self.allocated
    }

    fn issued_table(&self, table: PhysAddr) -> Result<usize, PageTableBuildError> {
        let offset = table
            .get()
            .checked_sub(self.base.get())
            .ok_or(PageTableBuildError::Storage)?;
        if !offset.is_multiple_of(PAGE_SIZE) {
            return Err(PageTableBuildError::Storage);
        }
        let page = usize::try_from(offset / PAGE_SIZE).map_err(|_| PageTableBuildError::Storage)?;
        if page >= self.allocated {
            return Err(PageTableBuildError::Storage);
        }
        Ok(page)
    }
}

impl PageTableStore for PreallocatedPageTableStore {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
        if self.allocated == self.capacity {
            return Err(PageTableBuildError::Storage);
        }
        let address = self
            .base
            .get()
            .checked_add((self.allocated as u64) * PAGE_SIZE)
            .ok_or(PageTableBuildError::Storage)?;
        let frame = PhysAddr::new(address).map_err(|_| PageTableBuildError::Storage)?;
        for index in 0..512 {
            unsafe { (address as *mut u64).add(index).write_volatile(0) };
        }
        self.allocated += 1;
        Ok(frame)
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        if index >= 512 {
            return Err(PageTableBuildError::Storage);
        }
        self.issued_table(table)?;
        Ok(unsafe { (table.get() as *const u64).add(index).read_volatile() })
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
        self.issued_table(table)?;
        unsafe { (table.get() as *mut u64).add(index).write_volatile(value) };
        Ok(())
    }
}

/// A preallocated page-table arena whose complete physical capacity is charged
/// to one exact memory pool before the store becomes available.
///
/// The commitment accounts capacity, not content authority or physical-frame
/// identity. The caller retains the unsafe ownership obligations of
/// `PreallocatedPageTableStore`.
pub struct AccountedPreallocatedPageTableStore {
    store: PreallocatedPageTableStore,
    charge: MemoryObjectId,
    charge_capability: Capability,
    committed_pages: u64,
}

impl AccountedPreallocatedPageTableStore {
    /// Validates the complete physical arena, then commits its exact page count
    /// before publishing a usable store.
    ///
    /// # Safety
    ///
    /// The physical arena must satisfy `PreallocatedPageTableStore::new` for
    /// the complete lifetime of this wrapper. The selected pool must be the
    /// policy-designated owner of that arena commitment.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        base: PhysAddr,
        pages: u64,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedPageTableStoreError> {
        let store = unsafe { PreallocatedPageTableStore::new(base, pages) }?;
        let (charge, charge_capability) = memory.allocate_object(
            pool,
            pool_capability,
            pages,
            MemoryBackingKind::Anonymous,
            Rights::CONTROL,
            authorities,
        )?;
        Ok(Self {
            store,
            charge,
            charge_capability,
            committed_pages: pages,
        })
    }

    pub const fn charge(&self) -> MemoryObjectId {
        self.charge
    }

    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    pub const fn allocated_pages(&self) -> usize {
        self.store.allocated_pages()
    }

    /// Returns the quantitative commitment after the physical arena is no
    /// longer reachable from any active or resumable address space.
    ///
    /// On failure the complete store and charge are returned unchanged.
    /// Releasing accounting is not evidence that page-table contents were
    /// erased.
    ///
    /// # Safety
    ///
    /// No CPU, task, VM, recovery image, or cached root may reference a table
    /// in this arena, and required TLB invalidation must already be complete.
    #[allow(clippy::result_large_err)]
    pub unsafe fn release<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        self,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<u64, (Self, MemoryResourceError)> {
        match memory.release_object(self.charge, self.charge_capability, authorities) {
            Ok(pages) => Ok(pages),
            Err(error) => Err((self, error)),
        }
    }
}

impl PageTableStore for AccountedPreallocatedPageTableStore {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
        self.store.allocate_zeroed()
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        self.store.read(table, index)
    }

    fn write(
        &mut self,
        table: PhysAddr,
        index: usize,
        value: u64,
    ) -> Result<(), PageTableBuildError> {
        self.store.write(table, index, value)
    }
}

pub struct PageTableBuilder<S> {
    store: S,
    root: PhysAddr,
}

impl<S: PageTableStore> PageTableBuilder<S> {
    pub fn new(mut store: S) -> Result<Self, PageTableBuildError> {
        let root = store.allocate_zeroed()?;
        Ok(Self { store, root })
    }

    /// Creates a fresh lower half while sharing only the current kernel's
    /// supervisor upper-half hierarchy.
    ///
    /// # Safety
    ///
    /// The current CR3 and every referenced upper-half table must remain live
    /// and immutable while the returned address space can run. The caller must
    /// exclude concurrent mutation during this snapshot.
    pub unsafe fn new_with_current_supervisor_half(store: S) -> Result<Self, PageTableBuildError> {
        let source: u64;
        unsafe { asm!("mov {}, cr3", out(reg) source, options(nomem, nostack, preserves_flags)) };
        let source = PhysAddr::new(source & ADDRESS_MASK)
            .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
        Self::new_with_supervisor_half_from(store, &IdentityMappedPageTables, source)
    }

    /// Creates a private copy of every live supervisor mapping, including
    /// lower-half identity mappings used during early boot.
    ///
    /// # Safety
    ///
    /// Every table reachable from the current CR3 must be identity mapped and
    /// stable for the bounded clone. Current mappings must not be user-visible
    /// or use huge-page entries.
    pub unsafe fn clone_current_supervisor_mappings(
        mut store: S,
    ) -> Result<Self, PageTableBuildError> {
        let source: u64;
        unsafe { asm!("mov {}, cr3", out(reg) source, options(nomem, nostack, preserves_flags)) };
        let source = PhysAddr::new(source & ADDRESS_MASK)
            .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
        let root = clone_supervisor_table(&mut store, &IdentityMappedPageTables, source, 4)?;
        Ok(Self { store, root })
    }

    fn new_with_supervisor_half_from<R: PageTableStore>(
        mut store: S,
        source_store: &R,
        source: PhysAddr,
    ) -> Result<Self, PageTableBuildError> {
        let root = store.allocate_zeroed()?;
        for index in 256..512 {
            let entry = source_store.read(source, index)?;
            if entry & 1 == 0 {
                if entry != 0 {
                    return Err(PageTableBuildError::InvalidIntermediate);
                }
                continue;
            }
            if entry & (1 << 2) != 0
                || entry & (1 << 7) != 0
                || entry & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0
                || entry & ADDRESS_MASK == 0
            {
                return Err(PageTableBuildError::InvalidIntermediate);
            }
            store.write(root, index, entry)?;
        }
        Ok(Self { store, root })
    }
    pub const fn root(&self) -> PhysAddr {
        self.root
    }
    pub const fn store(&self) -> &S {
        &self.store
    }
    pub const fn from_existing_root(store: S, root: PhysAddr) -> Self {
        Self { store, root }
    }
    pub fn into_store(self) -> S {
        self.store
    }

    pub fn map(&mut self, mapping: Mapping) -> Result<(), PageTableBuildError> {
        for page in 0..mapping.pages() {
            let offset = page
                .checked_mul(PAGE_SIZE)
                .ok_or(PageTableBuildError::AddressOverflow)?;
            let virtual_address = mapping
                .virtual_start()
                .get()
                .checked_add(offset)
                .ok_or(PageTableBuildError::AddressOverflow)?;
            let physical_address = mapping
                .physical_start()
                .get()
                .checked_add(offset)
                .ok_or(PageTableBuildError::AddressOverflow)?;
            self.map_page(
                VirtAddr::new(virtual_address).map_err(PageTableBuildError::Page)?,
                PhysAddr::new(physical_address)
                    .map_err(|_| PageTableBuildError::AddressOverflow)?,
                mapping.permissions(),
            )?;
        }
        Ok(())
    }

    /// Installs the boot DMA reservation into an exclusively owned inactive
    /// hierarchy. No alias scan, activation or device authorization occurs.
    /// On a recoverable failure, newly installed leaves are removed; empty
    /// intermediate tables can remain allocated. A rollback failure requires
    /// discarding the hierarchy without activating it.
    pub fn install_boot_dma(
        &mut self,
        reservation: BootDmaReservation,
        virtual_start: VirtAddr,
    ) -> Result<InstalledBootDma, BootDmaInstallError> {
        let mapping = Mapping::new(
            virtual_start,
            reservation.physical_base(),
            u64::from(reservation.pages()),
            PagePermissions::KERNEL_READ_WRITE,
        )
        .map_err(|_| BootDmaInstallError::PageTable(PageTableBuildError::MappingMismatch))?;
        self.verify_available(mapping)
            .map_err(BootDmaInstallError::PageTable)?;
        let mut attempted = 0;
        let install = (|| {
            for page in 0..mapping.pages() {
                let (virt, phys) = mapping_page(mapping, page)?;
                attempted = page + 1;
                self.map_page(virt, phys, mapping.permissions())?;
            }
            verify_active_mapping_from_store(&self.store, self.root, self.root, mapping)
        })();
        if let Err(error) = install {
            return match self.rollback_new_mapping(mapping, attempted) {
                Ok(()) => Err(BootDmaInstallError::PageTable(error)),
                Err(_) => Err(BootDmaInstallError::RollbackUncertain),
            };
        }
        Ok(InstalledBootDma {
            reservation,
            root: self.root,
            mapping,
        })
    }

    pub fn map_page(
        &mut self,
        virtual_address: VirtAddr,
        physical_address: PhysAddr,
        permissions: PagePermissions,
    ) -> Result<(), PageTableBuildError> {
        let user = permissions.user();
        let pdpt = self.descend(self.root, virtual_address.pml4_index(), user)?;
        let directory = self.descend(pdpt, virtual_address.pdpt_index(), user)?;
        let table = self.descend(directory, virtual_address.directory_index(), user)?;
        let index = virtual_address.table_index();
        if self.store.read(table, index)? & 1 != 0 {
            return Err(PageTableBuildError::AlreadyMapped);
        }
        let leaf = PageTableEntry::leaf(physical_address, permissions)
            .map_err(PageTableBuildError::Page)?;
        self.store.write(table, index, leaf.bits())
    }

    /// Replaces leaf permissions only when every page still matches the exact
    /// expected physical frame and old permissions. Logical validation is
    /// completed for the full range before the first write.
    pub fn protect(
        &mut self,
        expected: Mapping,
        final_permissions: PagePermissions,
    ) -> Result<(), PageTableBuildError> {
        if expected.permissions().user() != final_permissions.user()
            || expected.permissions().device_memory() != final_permissions.device_memory()
        {
            return Err(PageTableBuildError::MappingMismatch);
        }
        for page in 0..expected.pages() {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            let current = self.store.read(table, index)?;
            if current & 1 == 0 {
                return Err(PageTableBuildError::NotMapped);
            }
            let wanted = PageTableEntry::leaf(physical_address, expected.permissions())
                .map_err(PageTableBuildError::Page)?
                .bits();
            if current & !LEAF_ACCESSED_DIRTY != wanted {
                return Err(PageTableBuildError::MappingMismatch);
            }
            PageTableEntry::leaf(physical_address, final_permissions)
                .map_err(PageTableBuildError::Page)?;
        }
        for page in 0..expected.pages() {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            let final_entry = PageTableEntry::leaf(physical_address, final_permissions)
                .map_err(PageTableBuildError::Page)?;
            let accessed_dirty = self.store.read(table, index)? & LEAF_ACCESSED_DIRTY;
            self.store
                .write(table, index, final_entry.bits() | accessed_dirty)?;
        }
        Ok(())
    }

    pub fn unmap_exact(&mut self, expected: Mapping) -> Result<(), PageTableBuildError> {
        for page in 0..expected.pages() {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            let current = self.store.read(table, index)?;
            if current & 1 == 0 {
                return Err(PageTableBuildError::NotMapped);
            }
            let wanted = PageTableEntry::leaf(physical_address, expected.permissions())
                .map_err(PageTableBuildError::Page)?
                .bits();
            if current & !LEAF_ACCESSED_DIRTY != wanted {
                return Err(PageTableBuildError::MappingMismatch);
            }
        }
        for page in 0..expected.pages() {
            let (virtual_address, _) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            self.store.write(table, index, 0)?;
        }
        Ok(())
    }

    /// Verifies that every leaf in an exact expected range is absent without
    /// changing page-table state.
    pub fn verify_unmapped(&self, expected: Mapping) -> Result<(), PageTableBuildError> {
        for page in 0..expected.pages() {
            let (virtual_address, _) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            if self.store.read(table, index)? & 1 != 0 {
                return Err(PageTableBuildError::AlreadyMapped);
            }
        }
        Ok(())
    }

    fn verify_available(&self, expected: Mapping) -> Result<(), PageTableBuildError> {
        for page in 0..expected.pages() {
            let (virtual_address, _) = mapping_page(expected, page)?;
            match self.leaf_location(virtual_address) {
                Ok((table, index)) => {
                    if self.store.read(table, index)? & 1 != 0 {
                        return Err(PageTableBuildError::AlreadyMapped);
                    }
                }
                Err(PageTableBuildError::NotMapped) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn rollback_new_mapping(
        &mut self,
        expected: Mapping,
        attempted_pages: u64,
    ) -> Result<(), PageTableBuildError> {
        let mut page = 0;
        while page < attempted_pages {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            match self.leaf_location(virtual_address) {
                Ok((table, index)) => {
                    let current = self.store.read(table, index)?;
                    if current & 1 != 0 {
                        let wanted = PageTableEntry::leaf(physical_address, expected.permissions())
                            .map_err(PageTableBuildError::Page)?
                            .bits();
                        if current & !LEAF_ACCESSED_DIRTY != wanted {
                            return Err(PageTableBuildError::MappingMismatch);
                        }
                        self.store.write(table, index, 0)?;
                    }
                }
                Err(PageTableBuildError::NotMapped) => {}
                Err(error) => return Err(error),
            }
            page += 1;
        }
        Ok(())
    }

    fn restore_removed_mapping(
        &mut self,
        expected: Mapping,
        attempted_pages: u64,
    ) -> Result<(), PageTableBuildError> {
        let mut page = 0;
        while page < attempted_pages {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            let current = self.store.read(table, index)?;
            let wanted = PageTableEntry::leaf(physical_address, expected.permissions())
                .map_err(PageTableBuildError::Page)?
                .bits();
            if current & 1 == 0 {
                self.store.write(table, index, wanted)?;
            } else if current & !LEAF_ACCESSED_DIRTY != wanted {
                return Err(PageTableBuildError::MappingMismatch);
            }
            page += 1;
        }
        Ok(())
    }

    /// Verifies every leaf still matches the exact expected frame and
    /// permissions without changing page-table state.
    pub fn verify_mapped(&self, expected: Mapping) -> Result<(), PageTableBuildError> {
        for page in 0..expected.pages() {
            let (virtual_address, physical_address) = mapping_page(expected, page)?;
            let (table, index) = self.leaf_location(virtual_address)?;
            let current = self.store.read(table, index)?;
            if current & 1 == 0 {
                return Err(PageTableBuildError::NotMapped);
            }
            let wanted = PageTableEntry::leaf(physical_address, expected.permissions())
                .map_err(PageTableBuildError::Page)?
                .bits();
            if current & !LEAF_ACCESSED_DIRTY != wanted {
                return Err(PageTableBuildError::MappingMismatch);
            }
        }
        Ok(())
    }

    fn leaf_location(
        &self,
        virtual_address: VirtAddr,
    ) -> Result<(PhysAddr, usize), PageTableBuildError> {
        let mut table = self.root;
        for index in [
            virtual_address.pml4_index(),
            virtual_address.pdpt_index(),
            virtual_address.directory_index(),
        ] {
            let entry = self.store.read(table, index)?;
            if entry & 1 == 0 {
                return Err(PageTableBuildError::NotMapped);
            }
            if entry & (1 << 7) != 0 || entry & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0 {
                return Err(PageTableBuildError::InvalidIntermediate);
            }
            table = PhysAddr::new(entry & ADDRESS_MASK)
                .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
        }
        Ok((table, virtual_address.table_index()))
    }

    fn descend(
        &mut self,
        parent: PhysAddr,
        index: usize,
        user: bool,
    ) -> Result<PhysAddr, PageTableBuildError> {
        let current = self.store.read(parent, index)?;
        if current & 1 == 0 {
            let child = self.store.allocate_zeroed()?;
            let entry = PageTableEntry::table(child, user).map_err(PageTableBuildError::Page)?;
            self.store.write(parent, index, entry.bits())?;
            return Ok(child);
        }
        if current & (1 << 7) != 0 || current & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0 {
            return Err(PageTableBuildError::InvalidIntermediate);
        }
        if user && current & (1 << 2) == 0 {
            self.store.write(parent, index, current | (1 << 2))?;
        }
        PhysAddr::new(current & ADDRESS_MASK).map_err(|_| PageTableBuildError::InvalidIntermediate)
    }
}

/// Backend for constructing or editing one exclusively owned, inactive x86-64
/// page-table hierarchy.
///
/// This adapter deliberately performs no TLB invalidation: its hierarchy must
/// remain unreachable by every CPU while any adapter operation can occur. A
/// higher-level activation owner may retain the adapter only after exact final
/// verification and must make every inactive mutation entry unreachable.
/// Active/SMP retirement requires a separate lifecycle boundary.
pub struct InactivePageTableMappingBackend<S> {
    builder: PageTableBuilder<S>,
    target: ObjectId,
    poisoned: bool,
}

impl<S: PageTableStore> InactivePageTableMappingBackend<S> {
    /// Binds an inactive hierarchy to one exact target address-space object.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the complete hierarchy and keep its
    /// root unreachable from every CPU, VM, and resumable context while any
    /// method on this adapter can be called. A consuming higher-level owner may
    /// activate the root only after final exact verification if it retains this
    /// adapter privately and exposes none of its inactive mutation operations.
    /// `target` must be the exact address-space object represented by that root;
    /// it identifies the bound target but does not itself grant mapping
    /// authority. No concurrent page-table access or mutation is permitted. If
    /// the adapter reports `Poisoned`, the hierarchy must never become
    /// reachable.
    pub unsafe fn new(builder: PageTableBuilder<S>, target: ObjectId) -> Self {
        Self {
            builder,
            target,
            poisoned: false,
        }
    }

    pub const fn root(&self) -> PhysAddr {
        self.builder.root()
    }

    pub const fn target(&self) -> ObjectId {
        self.target
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Installs one exact task-local user RW/NX device range in the bound,
    /// inactive address space. PWT=PCD=1 selects PAT index 3.
    ///
    /// # Safety
    ///
    /// The bound target/root must belong to one exact construction-pending
    /// native device task, not an ordinary application. The caller must also
    /// establish that index 3 is UC for every CPU that could execute this
    /// hierarchy and exclude every cacheable physical alias for the complete
    /// installed lifetime. After this backend is consumed, the caller must keep
    /// the exact root and device leaves unreachable and unchanged until a later
    /// activation owner consumes and revalidates them.
    pub unsafe fn install_user_device_rw_nx(
        &mut self,
        target: ObjectId,
        virtual_start: VirtAddr,
        physical_start: PhysAddr,
        pages: u64,
    ) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        if target != self.target {
            return Err(InactivePageTableMappingError::WrongTarget);
        }
        let mapping = Mapping::new(
            virtual_start,
            physical_start,
            pages,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .map_err(|_| InactivePageTableMappingError::InvalidMapping)?;
        self.install_exact(mapping)
    }

    /// Removes the exact task-local user device range while the hierarchy is
    /// still unreachable, so no translation-cache invalidation is required.
    pub fn remove_user_device_rw_nx(
        &mut self,
        target: ObjectId,
        virtual_start: VirtAddr,
        physical_start: PhysAddr,
        pages: u64,
    ) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        if target != self.target {
            return Err(InactivePageTableMappingError::WrongTarget);
        }
        let mapping = Mapping::new(
            virtual_start,
            physical_start,
            pages,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .map_err(|_| InactivePageTableMappingError::InvalidMapping)?;
        self.remove_exact(mapping)
    }

    /// Verifies one exact task-local user device range without changing the
    /// inactive hierarchy or creating an activation proof.
    pub fn verify_user_device_rw_nx(
        &self,
        target: ObjectId,
        virtual_start: VirtAddr,
        physical_start: PhysAddr,
        pages: u64,
    ) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        if target != self.target {
            return Err(InactivePageTableMappingError::WrongTarget);
        }
        let mapping = Mapping::new(
            virtual_start,
            physical_start,
            pages,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .map_err(|_| InactivePageTableMappingError::InvalidMapping)?;
        self.builder
            .verify_mapped(mapping)
            .map_err(InactivePageTableMappingError::PageTable)
    }

    /// Verifies one exact task-local ordinary user RW/NX range without the
    /// device-memory PAT selector. This is used for launch-owned CPU/DMA
    /// buffers that share the same inactive hierarchy as a device mapping.
    pub fn verify_user_rw_nx(
        &self,
        target: ObjectId,
        virtual_start: VirtAddr,
        physical_start: PhysAddr,
        pages: u64,
    ) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        if target != self.target {
            return Err(InactivePageTableMappingError::WrongTarget);
        }
        let mapping = Mapping::new(
            virtual_start,
            physical_start,
            pages,
            PagePermissions::USER_READ_WRITE,
        )
        .map_err(|_| InactivePageTableMappingError::InvalidMapping)?;
        self.builder
            .verify_mapped(mapping)
            .map_err(InactivePageTableMappingError::PageTable)
    }

    /// Returns the hierarchy only when every adapter operation remained exact.
    pub fn into_builder(self) -> Result<PageTableBuilder<S>, InactivePageTableMappingError> {
        if self.poisoned {
            Err(InactivePageTableMappingError::Poisoned)
        } else {
            Ok(self.builder)
        }
    }

    fn native_mapping(
        &self,
        request: MemoryMappingBackendRequest,
    ) -> Result<Mapping, InactivePageTableMappingError> {
        if request.target() != self.target {
            return Err(InactivePageTableMappingError::WrongTarget);
        }
        native_user_mapping(request)
    }

    fn install_exact(&mut self, mapping: Mapping) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        self.builder
            .verify_available(mapping)
            .map_err(InactivePageTableMappingError::PageTable)?;
        for page in 0..mapping.pages() {
            let (virtual_address, physical_address) =
                mapping_page(mapping, page).map_err(InactivePageTableMappingError::PageTable)?;
            if let Err(error) =
                self.builder
                    .map_page(virtual_address, physical_address, mapping.permissions())
            {
                if self
                    .builder
                    .rollback_new_mapping(mapping, page + 1)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(InactivePageTableMappingError::Poisoned);
                }
                return Err(InactivePageTableMappingError::PageTable(error));
            }
        }
        Ok(())
    }

    fn remove_exact(&mut self, mapping: Mapping) -> Result<(), InactivePageTableMappingError> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        self.builder
            .verify_mapped(mapping)
            .map_err(InactivePageTableMappingError::PageTable)?;
        for page in 0..mapping.pages() {
            let (virtual_address, _) =
                mapping_page(mapping, page).map_err(InactivePageTableMappingError::PageTable)?;
            let (table, index) = self
                .builder
                .leaf_location(virtual_address)
                .map_err(InactivePageTableMappingError::PageTable)?;
            if let Err(error) = self.builder.store.write(table, index, 0) {
                if self
                    .builder
                    .restore_removed_mapping(mapping, page + 1)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(InactivePageTableMappingError::Poisoned);
                }
                return Err(InactivePageTableMappingError::PageTable(error));
            }
        }
        Ok(())
    }
}

fn native_user_mapping(
    request: MemoryMappingBackendRequest,
) -> Result<Mapping, InactivePageTableMappingError> {
    let physical = request
        .physical()
        .ok_or(InactivePageTableMappingError::MissingPhysicalBacking)?;
    let mapping = request.mapping();
    let access = mapping.access();
    let permissions = if access == Rights::READ {
        PagePermissions::USER_READ
    } else if access == Rights::READ.union(Rights::WRITE) {
        PagePermissions::USER_READ_WRITE
    } else if access == Rights::READ.union(Rights::EXECUTE) {
        PagePermissions::USER_READ_EXECUTE
    } else {
        return Err(InactivePageTableMappingError::UnsupportedAccess);
    };
    let virtual_address = mapping
        .virtual_page()
        .checked_mul(PAGE_SIZE)
        .ok_or(InactivePageTableMappingError::InvalidMapping)?;
    let virtual_start = VirtAddr::new(virtual_address)
        .map_err(|_| InactivePageTableMappingError::InvalidMapping)?;
    Mapping::new(
        virtual_start,
        physical.start(),
        mapping.pages(),
        permissions,
    )
    .map_err(|_| InactivePageTableMappingError::InvalidMapping)
}

// SAFETY: construction requires an inactive, exclusively owned hierarchy.
// Install preflights the complete virtual range, and a late failure removes
// every leaf that this attempt could have published. Cleanup uncertainty
// permanently poisons the hierarchy. Removal exact-matches every leaf before
// mutation; inactivity makes translation-cache invalidation unnecessary.
unsafe impl<S: PageTableStore> MemoryMappingBackend for InactivePageTableMappingBackend<S> {
    type Error = InactivePageTableMappingError;

    fn install(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        let mapping = self.native_mapping(request)?;
        self.install_exact(mapping)
    }

    fn remove(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(InactivePageTableMappingError::Poisoned);
        }
        let mapping = self.native_mapping(request)?;
        self.remove_exact(mapping)
    }
}

fn clone_supervisor_table<S: PageTableStore, R: PageTableStore>(
    destination: &mut S,
    source_store: &R,
    source: PhysAddr,
    level: u8,
) -> Result<PhysAddr, PageTableBuildError> {
    if !(1..=4).contains(&level) {
        return Err(PageTableBuildError::InvalidIntermediate);
    }
    let clone = destination.allocate_zeroed()?;
    for index in 0..512 {
        let entry = source_store.read(source, index)?;
        if entry & 1 == 0 {
            if entry != 0 {
                return Err(PageTableBuildError::InvalidIntermediate);
            }
            continue;
        }
        if entry & (1 << 2) != 0
            || entry & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0
            || entry & ADDRESS_MASK == 0
        {
            return Err(PageTableBuildError::InvalidIntermediate);
        }
        if level == 1 {
            destination.write(clone, index, entry)?;
            continue;
        }
        if entry & (1 << 7) != 0 {
            return Err(PageTableBuildError::InvalidIntermediate);
        }
        let child = PhysAddr::new(entry & ADDRESS_MASK)
            .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
        let child_clone = clone_supervisor_table(destination, source_store, child, level - 1)?;
        destination.write(clone, index, (entry & !ADDRESS_MASK) | child_clone.get())?;
    }
    Ok(clone)
}

struct IdentityMappedPageTables;

impl PageTableStore for IdentityMappedPageTables {
    fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
        Err(PageTableBuildError::Storage)
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
        if index >= 512 {
            return Err(PageTableBuildError::Storage);
        }
        Ok(unsafe { (table.get() as *const u64).add(index).read_volatile() })
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
        unsafe { (table.get() as *mut u64).add(index).write_volatile(value) };
        Ok(())
    }
}

pub struct ActivePageTables {
    root: PhysAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootDmaInstallError {
    PageTable(PageTableBuildError),
    RollbackUncertain,
}

/// Owns a reservation and the identity of the inactive root and mapping
/// built for it. Consumed by active initialization; not proof of activation.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct InstalledBootDma {
    reservation: BootDmaReservation,
    root: PhysAddr,
    mapping: Mapping,
}

/// Boot-lifetime RAM after a complete CPU mapping check and initial zeroing.
/// This is not a runtime pin, a live mapping guard or permission for device DMA.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct InitializedBootDma {
    reservation: BootDmaReservation,
    root: PhysAddr,
    mapping: Mapping,
}

impl InitializedBootDma {
    pub const fn reservation(&self) -> &BootDmaReservation {
        &self.reservation
    }

    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    pub const fn mapping(&self) -> Mapping {
        self.mapping
    }
}

const fn interrupts_disabled(flags: u64) -> bool {
    flags & (1 << 9) == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveMappingRevocationError {
    WrongRoot,
    WrongMapping,
    AlreadyRevoked,
    PageTable(PageTableBuildError),
}

/// One exact active service mapping authorized for native retirement.
pub struct ActiveServiceMappingRevoker<'a> {
    tables: &'a mut ActivePageTables,
    expected_root: PhysAddr,
    expected: Mapping,
    retired: bool,
}

impl<'a> ActiveServiceMappingRevoker<'a> {
    /// Creates a one-use exact active-mapping retirement adapter.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the expected leaf entries, keep the
    /// active hierarchy identity-mapped, and exclude interrupts and concurrent
    /// page-table mutation until this adapter is dropped.
    pub unsafe fn new(
        tables: &'a mut ActivePageTables,
        expected_root: PhysAddr,
        expected: Mapping,
    ) -> Result<Self, ActiveMappingRevocationError> {
        if tables.root() != expected_root {
            return Err(ActiveMappingRevocationError::WrongRoot);
        }
        Ok(Self {
            tables,
            expected_root,
            expected,
            retired: false,
        })
    }

    /// Creates a one-use active revoker from the complete descriptor returned
    /// by the memory-resource table's capability-authorized revocation
    /// preflight.
    ///
    /// # Safety
    ///
    /// The safety contract of [`Self::new`] applies. `request` must be the
    /// unmodified result of the policy table's exact mapping preflight.
    pub unsafe fn from_request(
        tables: &'a mut ActivePageTables,
        expected_root: PhysAddr,
        request: MemoryMappingBackendRequest,
    ) -> Result<Self, ActiveMappingRevocationError> {
        let expected =
            native_user_mapping(request).map_err(|_| ActiveMappingRevocationError::WrongMapping)?;
        unsafe { Self::new(tables, expected_root, expected) }
    }
}

impl GuestMappingRevoker for ActiveServiceMappingRevoker<'_> {
    type Error = ActiveMappingRevocationError;

    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error> {
        if self.retired {
            return Err(ActiveMappingRevocationError::AlreadyRevoked);
        }
        let expected_bytes = self
            .expected
            .pages()
            .checked_mul(PAGE_SIZE)
            .ok_or(ActiveMappingRevocationError::WrongMapping)?;
        if self.tables.root() != self.expected_root {
            return Err(ActiveMappingRevocationError::WrongRoot);
        }
        if guest_address != self.expected.virtual_start().get() || bytes != expected_bytes {
            return Err(ActiveMappingRevocationError::WrongMapping);
        }
        // SAFETY: established by the constructor contract; unmap_exact
        // preflights the complete physical/permission identity before writes.
        unsafe { self.tables.unmap_exact(self.expected) }
            .map_err(ActiveMappingRevocationError::PageTable)?;
        self.retired = true;
        Ok(())
    }
}

// SAFETY: construction binds this one-use adapter to one exact active mapping
// and root. The request is converted back into its complete native mapping and
// exact-matched before unmap_exact clears any leaf and invalidates every page.
unsafe impl MemoryMappingRevocationBackend for ActiveServiceMappingRevoker<'_> {
    type Error = ActiveMappingRevocationError;

    fn revoke(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
        let mapping =
            native_user_mapping(request).map_err(|_| ActiveMappingRevocationError::WrongMapping)?;
        if mapping != self.expected {
            return Err(ActiveMappingRevocationError::WrongMapping);
        }
        let bytes = mapping
            .pages()
            .checked_mul(PAGE_SIZE)
            .ok_or(ActiveMappingRevocationError::WrongMapping)?;
        self.revoke_guest_mapping(mapping.virtual_start().get(), bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveUserBuffer {
    virtual_address: u64,
    length: usize,
}

impl ActiveUserBuffer {
    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }

    pub const fn length(self) -> usize {
        self.length
    }
}

impl ActivePageTables {
    /// Opens the current CR3 for exact-match leaf protection without allocating
    /// new page-table frames.
    ///
    /// # Safety
    ///
    /// Every page-table frame reachable from the current CR3 must be mapped at
    /// its identical supervisor-writable virtual address and owned exclusively
    /// by this CPU for the duration of each mutation. Interrupts and concurrent
    /// address-space mutation must be excluded by the caller. This constructor
    /// rejects a snapshot with IF set but does not disable or later restore
    /// interrupts for the caller.
    pub unsafe fn current() -> Result<Self, PageTableBuildError> {
        let flags: u64;
        unsafe {
            asm!(
                "pushfq",
                "pop {}",
                out(reg) flags,
                options(nomem, preserves_flags)
            )
        };
        if !interrupts_disabled(flags) {
            return Err(PageTableBuildError::InterruptsEnabled);
        }
        let root: u64;
        unsafe { asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags)) };
        let root = PhysAddr::new(root & ADDRESS_MASK)
            .map_err(|_| PageTableBuildError::InvalidIntermediate)?;
        Ok(Self { root })
    }

    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    pub fn leaf(&self, address: VirtAddr) -> Result<Option<ActiveLeaf>, PageTableBuildError> {
        active_leaf_from_store(&IdentityMappedPageTables, self.root, address)
    }

    /// Verifies one complete 4 KiB mapping against the current effective leaf
    /// state without changing the hierarchy.
    pub fn verify_mapped(
        &self,
        expected_root: PhysAddr,
        mapping: Mapping,
    ) -> Result<(), PageTableBuildError> {
        verify_active_mapping_from_store(
            &IdentityMappedPageTables,
            self.root,
            expected_root,
            mapping,
        )
    }

    /// Verifies a supervisor RO/NX device mapping has no second physical
    /// mapping in this four-level hierarchy. Does not inspect CPU PAT, old
    /// translations in the TLB, or any other root. It does not access MMIO.
    pub fn verify_read_only_mmio_leaves(
        &self,
        mapping: Mapping,
    ) -> Result<(), PageTableBuildError> {
        verify_read_only_mmio_from_store(&IdentityMappedPageTables, self.root, mapping)
    }

    /// Scan the trusted boot root for any leaf or page-table frame in this
    /// physical range. This only checks current CPU page-table structure.
    pub fn verify_no_physical_mapping(
        &self,
        expected_root: PhysAddr,
        start: PhysAddr,
        pages: u64,
    ) -> Result<(), PageTableBuildError> {
        if self.root != expected_root {
            return Err(PageTableBuildError::MappingMismatch);
        }
        verify_physical_coverage_from_store(&IdentityMappedPageTables, self.root, start, pages, None)
    }

    /// Check the exact single-page mapping proposed for passive PCI sampling.
    /// The expected root must come from the diagnostic's own page-table build,
    /// not from this snapshot. No register reads or mapping changes occur.
    ///
    /// This is only a structural check. A caller must independently establish
    /// firmware exit, exclusive BSP/root lifetime, CPU cache policy and
    /// retirement of stale translations before it may read configuration.
    pub fn verify_passive_pci_mapping(
        &self,
        expected_root: PhysAddr,
        plan: PassivePciPage,
        mapping: Mapping,
    ) -> Result<(), PageTableBuildError> {
        verify_passive_pci_mapping_from_store(
            &IdentityMappedPageTables,
            self.root,
            expected_root,
            plan.physical(),
            mapping,
        )
    }

    /// Exercise the passive mapping verifier on the sealed Q35 endpoint page.
    /// This uses the emulator's fixed fixture address rather than admitting
    /// an address from an incomplete firmware map on physical machines.
    pub fn verify_q35_passive_pci_leaf(
        &self,
        expected_root: PhysAddr,
        topology: super::Q35FixtureTopology,
    ) -> Result<(), PageTableBuildError> {
        let proposal = super::q35_fixture_probe_mappings(topology)
            .map_err(|_| PageTableBuildError::MappingMismatch)?[1]
            .ok_or(PageTableBuildError::MappingMismatch)?;
        verify_passive_pci_mapping_from_store(
            &IdentityMappedPageTables,
            self.root,
            expected_root,
            proposal.physical_start(),
            proposal,
        )
    }

    /// Verify the exact signed QEMU shutdown fixture, not arbitrary PCI
    /// memory. No MMIO access, permission changes, or TLB changes occur.
    pub fn verify_q35_shutdown_leaves(&self) -> Result<(), PageTableBuildError> {
        for mapping in super::q35_fixture_shutdown_mappings()
            .map_err(|_| PageTableBuildError::MappingMismatch)?
            .into_iter()
            .flatten()
        {
            verify_exclusive_mapping_from_store(&IdentityMappedPageTables, self.root, mapping)?;
        }
        Ok(())
    }

    /// Rechecks every leaf of the distinct, exact cold-activation model.
    pub fn verify_q35_activation_leaves(&self) -> Result<(), PageTableBuildError> {
        for mapping in super::q35_fixture_activation_mappings()
            .map_err(|_| PageTableBuildError::MappingMismatch)?
            .into_iter()
            .flatten()
        {
            verify_exclusive_mapping_from_store(&IdentityMappedPageTables, self.root, mapping)?;
        }
        Ok(())
    }

    /// Verify the entire initialized DMA range is uniquely mapped and WB
    /// on the current BSP. This check neither pins frames nor grants DMA.
    ///
    /// # Safety
    /// The caller must hold this root current at CPL0, with interrupts and
    /// APs off, and exclude CPU cache policy and page-table changes. The
    /// loader must have retired stale firmware translations before entry.
    pub unsafe fn verify_boot_dma_write_back(
        &self,
        dma: &InitializedBootDma,
    ) -> Result<(), super::PlatformMmioError> {
        use super::PlatformMmioError;

        let mapping = dma.mapping();
        if dma.root() != self.root || mapping.permissions() != PagePermissions::KERNEL_READ_WRITE {
            return Err(PlatformMmioError::MappingMismatch);
        }
        verify_exclusive_mapping_from_store(&IdentityMappedPageTables, self.root, mapping)
            .map_err(|_| PlatformMmioError::PageTable)?;
        let start = mapping.physical_start().get();
        let end = start
            .checked_add(dma.reservation().bytes())
            .ok_or(PlatformMmioError::InvalidRange)?;
        // SAFETY: caller holds the current BSP root and excludes cache
        // policy changes. The cache check reads registers, not DMA memory.
        if !unsafe { super::platform_mmio::check_boot_dma_write_back(start..end) } {
            return Err(PlatformMmioError::CpuProtection);
        }
        Ok(())
    }

    /// Checks the exact preinstalled supervisor RW/NX mapping and clears all
    /// of the reserved RAM before returning it as initialized.
    ///
    /// # Safety
    ///
    /// The caller must keep this root current and its table access valid as
    /// required by `current`. The checked translations must be live (no stale
    /// TLB entries) and stable, and the entire range must be exclusively
    /// writable, naturally aligned normal RAM with no conflicting CPU
    /// aliases, Rust references or DMA accesses throughout the clear. The
    /// platform must establish the RAM cache type independently of the PTE
    /// check. Later device publication has its own coherency and ordering rules.
    pub unsafe fn initialize_boot_dma(
        &mut self,
        installed: InstalledBootDma,
    ) -> Result<InitializedBootDma, PageTableBuildError> {
        initialize_boot_dma_from_store(&IdentityMappedPageTables, self.root, installed, |mapping| {
            // SAFETY: all leaves have been checked; their current,
            // exclusive normal-RAM translations are the caller's contract.
            unsafe {
                let start = mapping.virtual_start().get() as *mut u64;
                let words = (mapping.pages() * (PAGE_SIZE / 8)) as usize;
                zero_boot_dma_words(start, words);
                if !(0..words).all(|word| start.wrapping_add(word).read_volatile() == 0) {
                    return Err(PageTableBuildError::Storage);
                }
            }
            Ok(())
        })
    }

    /// Adopts and initializes the dedicated mapping from the UEFI handoff.
    ///
    /// # Safety
    ///
    /// The allocation must come from the trusted loader and the contract of
    /// `initialize_boot_dma` applies. The tag is not itself authority to write
    /// RAM or use DMA. Invoke only once before the range is shared.
    pub unsafe fn initialize_uefi_boot_dma(
        &mut self,
        region: MemoryRegion,
    ) -> Result<InitializedBootDma, PageTableBuildError> {
        let reservation = BootDmaReservation::from_handoff_region(region)
            .map_err(|_| PageTableBuildError::MappingMismatch)?;
        let mapping = Mapping::new(
            VirtAddr::new(super::BOOT_DMA_VIRTUAL_START).map_err(PageTableBuildError::Page)?,
            reservation.physical_base(),
            u64::from(reservation.pages()),
            PagePermissions::KERNEL_READ_WRITE,
        )
        .map_err(|_| PageTableBuildError::MappingMismatch)?;
        // SAFETY: the caller owns the loader allocation, and initialization
        // independently checks every active translation before touching RAM.
        unsafe {
            self.initialize_boot_dma(InstalledBootDma {
                reservation,
                root: self.root,
                mapping,
            })
        }
    }

    /// Validates every active leaf touched by a bounded user copy. The caller
    /// must keep page-table mutation excluded through the subsequent copy.
    pub fn resolve_user_buffer(
        &self,
        expected_root: PhysAddr,
        virtual_address: u64,
        length: usize,
        maximum_length: usize,
        access: UserBufferAccess,
    ) -> Result<ActiveUserBuffer, UserBufferError> {
        if self.root != expected_root {
            return Err(UserBufferError::AccessDenied);
        }
        if length == 0 {
            return Err(UserBufferError::Empty);
        }
        if length > maximum_length {
            return Err(UserBufferError::TooLarge);
        }
        let length_u64 = u64::try_from(length).map_err(|_| UserBufferError::Overflow)?;
        let end = virtual_address
            .checked_add(length_u64)
            .ok_or(UserBufferError::Overflow)?;
        if virtual_address == 0 || virtual_address >= 1 << 47 || end > 1 << 47 {
            return Err(UserBufferError::Overflow);
        }
        let first_page = virtual_address & !(PAGE_SIZE - 1);
        let last_page = (end - 1) & !(PAGE_SIZE - 1);
        let mut page = first_page;
        loop {
            let leaf = self
                .leaf(VirtAddr::new(page).map_err(|_| UserBufferError::Overflow)?)
                .map_err(|_| UserBufferError::Unmapped)?
                .ok_or(UserBufferError::Unmapped)?;
            validate_user_buffer_leaf(leaf, access)?;
            if page == last_page {
                break;
            }
            page = page
                .checked_add(PAGE_SIZE)
                .ok_or(UserBufferError::Overflow)?;
        }
        Ok(ActiveUserBuffer {
            virtual_address,
            length,
        })
    }

    /// Applies an exact-match permission transition and invalidates every
    /// affected local translation before returning.
    ///
    /// # Safety
    ///
    /// The mapping and identity-map ownership requirements from
    /// [`Self::current`] must still hold.
    pub unsafe fn protect(
        &mut self,
        expected: Mapping,
        final_permissions: PagePermissions,
    ) -> Result<(), PageTableBuildError> {
        let mut tables = PageTableBuilder::from_existing_root(IdentityMappedPageTables, self.root);
        tables.protect(expected, final_permissions)?;
        for page in 0..expected.pages() {
            let address = expected
                .virtual_start()
                .get()
                .checked_add(
                    page.checked_mul(PAGE_SIZE)
                        .ok_or(PageTableBuildError::AddressOverflow)?,
                )
                .ok_or(PageTableBuildError::AddressOverflow)?;
            unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags)) };
        }
        Ok(())
    }

    /// Removes only the exact expected mapping and invalidates its local TLB
    /// entries. The safety requirements from [`Self::current`] apply.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own all affected leaf entries, ensure the
    /// complete active hierarchy is identity mapped, and prevent concurrent
    /// page-table mutation for the duration of this operation.
    pub unsafe fn unmap_exact(&mut self, expected: Mapping) -> Result<(), PageTableBuildError> {
        let mut tables = PageTableBuilder::from_existing_root(IdentityMappedPageTables, self.root);
        tables.unmap_exact(expected)?;
        invalidate_mapping(expected)
    }
}

fn initialize_boot_dma_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    installed: InstalledBootDma,
    zero: impl FnOnce(Mapping) -> Result<(), PageTableBuildError>,
) -> Result<InitializedBootDma, PageTableBuildError> {
    verify_active_mapping_from_store(store, root, installed.root, installed.mapping)?;
    zero(installed.mapping)?;
    Ok(InitializedBootDma {
        reservation: installed.reservation,
        root,
        mapping: installed.mapping,
    })
}

/// # Safety
///
/// The aligned pointer must cover `words` exclusively writable normal RAM
/// words for the duration of the clear.
unsafe fn zero_boot_dma_words(start: *mut u64, words: usize) {
    for word in 0..words {
        // SAFETY: the caller guarantees the whole extent; one aligned word
        // is written per iteration and the initialization cannot be elided.
        unsafe { start.wrapping_add(word).write_volatile(0) };
    }
}

fn verify_active_mapping_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    expected_root: PhysAddr,
    mapping: Mapping,
) -> Result<(), PageTableBuildError> {
    if root != expected_root {
        return Err(PageTableBuildError::MappingMismatch);
    }
    for page in 0..mapping.pages() {
        let offset = page
            .checked_mul(PAGE_SIZE)
            .ok_or(PageTableBuildError::MappingMismatch)?;
        let virtual_address = mapping
            .virtual_start()
            .get()
            .checked_add(offset)
            .and_then(|address| VirtAddr::new(address).ok())
            .ok_or(PageTableBuildError::MappingMismatch)?;
        let expected_physical = mapping
            .physical_start()
            .get()
            .checked_add(offset)
            .and_then(|address| PhysAddr::new(address).ok())
            .ok_or(PageTableBuildError::MappingMismatch)?;
        let leaf = active_leaf_from_store(store, root, virtual_address)?
            .ok_or(PageTableBuildError::MappingMismatch)?;
        let permissions = mapping.permissions();
        if leaf.physical() != expected_physical
            || leaf.writable() != permissions.writable()
            || leaf.executable() != permissions.executable()
            || leaf.user() != permissions.user()
            || leaf.device_pat_index_three() != permissions.device_memory()
        {
            return Err(PageTableBuildError::MappingMismatch);
        }
    }
    Ok(())
}

const BOOT_ALIAS_MAX_TABLES: usize = 1024;

fn verify_passive_pci_mapping_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    expected_root: PhysAddr,
    expected_page: PhysAddr,
    mapping: Mapping,
) -> Result<(), PageTableBuildError> {
    if root != expected_root
        || mapping.pages() != 1
        || mapping.physical_start() != expected_page
        || mapping.permissions() != PagePermissions::KERNEL_MMIO_READ
    {
        return Err(PageTableBuildError::MappingMismatch);
    }
    verify_read_only_mmio_from_store(store, root, mapping)
}

fn verify_read_only_mmio_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    mapping: Mapping,
) -> Result<(), PageTableBuildError> {
    if mapping.permissions() != PagePermissions::KERNEL_MMIO_READ {
        return Err(PageTableBuildError::MappingMismatch);
    }
    verify_exclusive_mapping_from_store(store, root, mapping)
}

fn verify_exclusive_mapping_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    mapping: Mapping,
) -> Result<(), PageTableBuildError> {
    verify_physical_coverage_from_store(store, root, mapping.physical_start(), mapping.pages(), Some(mapping))?;
    verify_active_mapping_from_store(store, root, root, mapping)
}

fn verify_physical_coverage_from_store<S: PageTableStore>(
    store: &S,
    root: PhysAddr,
    start: PhysAddr,
    pages: u64,
    mapping: Option<Mapping>,
) -> Result<(), PageTableBuildError> {
    let physical_start = start.get();
    let physical_end = pages.checked_mul(PAGE_SIZE)
        .filter(|&bytes| bytes != 0)
        .and_then(|bytes| physical_start.checked_add(bytes))
        .filter(|&end| end <= (1u64 << 52))
        .ok_or(PageTableBuildError::AddressOverflow)?;
    let mut budget = BOOT_ALIAS_MAX_TABLES;
    fn scan(
        store: &impl PageTableStore,
        table: PhysAddr,
        level: u32,
        virtual_prefix: u64,
        mapping: Option<Mapping>,
        physical: core::ops::Range<u64>,
        budget: &mut usize,
    ) -> Result<(), PageTableBuildError> {
        if physical.contains(&table.get()) {
            return Err(PageTableBuildError::PhysicalAlias);
        }
        *budget = budget
            .checked_sub(1)
            .ok_or(PageTableBuildError::AliasWalkLimit)?;
        let shift = 12 + (level - 1) * 9;
        for index in 0..512 {
            let entry = store.read(table, index)?;
            if entry & 1 == 0 {
                continue;
            }
            let va = virtual_prefix | ((index as u64) << shift);
            let frame = entry & ADDRESS_MASK;
            if level > 1 {
                // Boot hierarchies contain only 4 KiB leaves. Fail closed
                // instead of accidentally skipping a large-page alias.
                if entry & (1 << 7) != 0 || entry & !((1 << 63) | 0xfff | ADDRESS_MASK) != 0 {
                    return Err(PageTableBuildError::InvalidIntermediate);
                }
                let child =
                    PhysAddr::new(frame).map_err(|_| PageTableBuildError::InvalidIntermediate)?;
                scan(
                    store,
                    child,
                    level - 1,
                    va,
                    mapping,
                    physical.clone(),
                    budget,
                )?;
            } else if physical.contains(&frame) {
                let canonical = (((va << 16) as i64) >> 16) as u64;
                let expected = mapping.ok_or(PageTableBuildError::PhysicalAlias)?
                    .virtual_start()
                    .get()
                    .checked_add(frame - physical.start)
                    .ok_or(PageTableBuildError::AddressOverflow)?;
                if canonical != expected {
                    return Err(PageTableBuildError::PhysicalAlias);
                }
            }
        }
        Ok(())
    }
    scan(
        store,
        root,
        4,
        0,
        mapping,
        physical_start..physical_end,
        &mut budget,
    )
}

fn invalidate_mapping(mapping: Mapping) -> Result<(), PageTableBuildError> {
    for page in 0..mapping.pages() {
        let address = mapping
            .virtual_start()
            .get()
            .checked_add(
                page.checked_mul(PAGE_SIZE)
                    .ok_or(PageTableBuildError::AddressOverflow)?,
            )
            .ok_or(PageTableBuildError::AddressOverflow)?;
        unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags)) };
    }
    Ok(())
}

fn mapping_page(mapping: Mapping, page: u64) -> Result<(VirtAddr, PhysAddr), PageTableBuildError> {
    let offset = page
        .checked_mul(PAGE_SIZE)
        .ok_or(PageTableBuildError::AddressOverflow)?;
    let virtual_address = mapping
        .virtual_start()
        .get()
        .checked_add(offset)
        .ok_or(PageTableBuildError::AddressOverflow)?;
    let physical_address = mapping
        .physical_start()
        .get()
        .checked_add(offset)
        .ok_or(PageTableBuildError::AddressOverflow)?;
    Ok((
        VirtAddr::new(virtual_address).map_err(PageTableBuildError::Page)?,
        PhysAddr::new(physical_address).map_err(|_| PageTableBuildError::AddressOverflow)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4096))]
    struct IdentityArena([[u64; 512]; 5]);

    struct Tables {
        pages: [[u64; 512]; 8],
        used: usize,
    }
    impl Tables {
        fn slot(frame: PhysAddr) -> Result<usize, PageTableBuildError> {
            let page = frame.get() / PAGE_SIZE;
            usize::try_from(page.checked_sub(1).ok_or(PageTableBuildError::Storage)?)
                .map_err(|_| PageTableBuildError::Storage)
        }
    }
    impl PageTableStore for Tables {
        fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
            if self.used == self.pages.len() {
                return Err(PageTableBuildError::Storage);
            }
            self.pages[self.used].fill(0);
            self.used += 1;
            PhysAddr::new(self.used as u64 * PAGE_SIZE).map_err(|_| PageTableBuildError::Storage)
        }
        fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
            self.pages
                .get(Self::slot(table)?)
                .and_then(|page| page.get(index))
                .copied()
                .ok_or(PageTableBuildError::Storage)
        }
        fn write(
            &mut self,
            table: PhysAddr,
            index: usize,
            value: u64,
        ) -> Result<(), PageTableBuildError> {
            *self
                .pages
                .get_mut(Self::slot(table)?)
                .and_then(|page| page.get_mut(index))
                .ok_or(PageTableBuildError::Storage)? = value;
            Ok(())
        }
    }

    #[test]
    fn builds_hardware_tables_and_rejects_duplicate_leaves() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mut builder = PageTableBuilder::new(store).unwrap();
        let address = VirtAddr::new(0x4000).unwrap();
        builder
            .map_page(
                address,
                PhysAddr::new(0x9000).unwrap(),
                PagePermissions::USER_READ_EXECUTE,
            )
            .unwrap();
        assert_eq!(
            builder.map_page(
                address,
                PhysAddr::new(0xa000).unwrap(),
                PagePermissions::USER_READ
            ),
            Err(PageTableBuildError::AlreadyMapped)
        );
        let store = builder.store();
        let pml4 = store.read(builder.root(), address.pml4_index()).unwrap();
        assert_ne!(pml4 & (1 << 2), 0);
        let pdpt = store
            .read(
                PhysAddr::new(pml4 & ADDRESS_MASK).unwrap(),
                address.pdpt_index(),
            )
            .unwrap();
        let directory = store
            .read(
                PhysAddr::new(pdpt & ADDRESS_MASK).unwrap(),
                address.directory_index(),
            )
            .unwrap();
        let leaf = store
            .read(
                PhysAddr::new(directory & ADDRESS_MASK).unwrap(),
                address.table_index(),
            )
            .unwrap();
        assert_eq!(leaf & ADDRESS_MASK, 0x9000);
        assert_eq!(leaf & (1 << 63), 0);
        assert_eq!(leaf & (1 << 1), 0);
    }

    #[test]
    fn preallocated_store_zeros_and_confines_issued_tables() {
        let mut arena = IdentityArena([[u64::MAX; 512]; 5]);
        let base = PhysAddr::new(arena.0.as_mut_ptr() as u64).unwrap();
        let store = unsafe { PreallocatedPageTableStore::new(base, 4) }.unwrap();
        let mut builder = PageTableBuilder::new(store).unwrap();
        builder
            .map_page(
                VirtAddr::new(0x4000).unwrap(),
                PhysAddr::new(0x20_0000).unwrap(),
                PagePermissions::USER_READ_EXECUTE,
            )
            .unwrap();
        assert_eq!(builder.store().allocated_pages(), 4);
        assert_eq!(arena.0[0][511], 0);
        assert_eq!(arena.0[4][0], u64::MAX);
        let mut store = builder.into_store();
        assert_eq!(store.allocate_zeroed(), Err(PageTableBuildError::Storage));
        assert_eq!(
            store.read(PhysAddr::new(base.get() + 4 * PAGE_SIZE).unwrap(), 0),
            Err(PageTableBuildError::Storage)
        );
        assert_eq!(
            store.write(PhysAddr::new(base.get() + 4 * PAGE_SIZE).unwrap(), 0, 0),
            Err(PageTableBuildError::Storage)
        );
    }

    #[test]
    fn accounted_page_table_arena_charges_full_capacity_until_safe_release() {
        let mut arena = IdentityArena([[u64::MAX; 512]; 5]);
        let base = PhysAddr::new(arena.0.as_mut_ptr() as u64).unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(24).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let pool_rights = Rights::ALLOCATE.union(Rights::INSPECT);
        let (pool, pool_capability) = memory
            .create_root(4, 1, 0, pool_rights, &mut authorities)
            .unwrap();
        let store = unsafe {
            AccountedPreallocatedPageTableStore::new(
                base,
                4,
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            )
        }
        .unwrap();
        assert_eq!(store.committed_pages(), 4);
        assert_eq!(memory.object_pool(store.charge()), Ok(pool));
        let mut builder = PageTableBuilder::new(store).unwrap();
        builder
            .map_page(
                VirtAddr::new(0x4000).unwrap(),
                PhysAddr::new(0x20_0000).unwrap(),
                PagePermissions::USER_READ_EXECUTE,
            )
            .unwrap();
        assert_eq!(builder.store().allocated_pages(), 4);
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            4
        );
        let store = builder.into_store();
        assert!(matches!(
            unsafe { store.release(&mut memory, &mut authorities) },
            Ok(4)
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn page_table_arena_exhaustion_never_publishes_an_uncharged_store() {
        let mut arena = IdentityArena([[u64::MAX; 512]; 5]);
        let base = PhysAddr::new(arena.0.as_mut_ptr() as u64).unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(25).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let pool_rights = Rights::ALLOCATE.union(Rights::INSPECT);
        let (pool, pool_capability) = memory
            .create_root(3, 1, 0, pool_rights, &mut authorities)
            .unwrap();
        assert!(matches!(
            unsafe {
                AccountedPreallocatedPageTableStore::new(
                    base,
                    4,
                    pool,
                    pool_capability,
                    &mut memory,
                    &mut authorities,
                )
            },
            Err(AccountedPageTableStoreError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
        assert!(arena.0.iter().flatten().all(|entry| *entry == u64::MAX));
    }

    #[test]
    fn fresh_root_copies_only_valid_supervisor_upper_half() {
        let mut source = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let source_root = source.allocate_zeroed().unwrap();
        let kernel_entry = PageTableEntry::table(PhysAddr::new(0x20_0000).unwrap(), false)
            .unwrap()
            .bits();
        source.write(source_root, 300, kernel_entry).unwrap();
        let destination = Tables {
            pages: [[u64::MAX; 512]; 8],
            used: 0,
        };
        let builder =
            PageTableBuilder::new_with_supervisor_half_from(destination, &source, source_root)
                .unwrap();
        assert_eq!(builder.store().read(builder.root(), 255), Ok(0));
        assert_eq!(builder.store().read(builder.root(), 300), Ok(kernel_entry));

        source
            .write(source_root, 300, kernel_entry | (1 << 2))
            .unwrap();
        let destination = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        assert!(matches!(
            PageTableBuilder::new_with_supervisor_half_from(destination, &source, source_root),
            Err(PageTableBuildError::InvalidIntermediate)
        ));
    }

    #[test]
    fn supervisor_clone_is_private_and_retains_low_identity_mapping() {
        let source_store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let address = VirtAddr::new(0x20_0000).unwrap();
        let mapping = Mapping::new(
            address,
            PhysAddr::new(0x20_0000).unwrap(),
            1,
            PagePermissions::KERNEL_LOW_READ_EXECUTE,
        )
        .unwrap();
        let mut source = PageTableBuilder::new(source_store).unwrap();
        source.map(mapping).unwrap();
        let source_root = source.root();
        let source_store = source.into_store();
        let mut destination = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let cloned_root =
            clone_supervisor_table(&mut destination, &source_store, source_root, 4).unwrap();
        let cloned = PageTableBuilder::from_existing_root(destination, cloned_root);
        let (table, index) = cloned.leaf_location(address).unwrap();
        assert_eq!(
            cloned.store().read(table, index).unwrap() & ADDRESS_MASK,
            0x20_0000
        );
    }

    #[test]
    fn protection_requires_exact_old_mapping_before_any_write() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mut builder = PageTableBuilder::new(store).unwrap();
        let mapping = Mapping::new(
            VirtAddr::new(0x8000).unwrap(),
            PhysAddr::new(0x8000).unwrap(),
            1,
            PagePermissions::KERNEL_LOW_READ_WRITE,
        )
        .unwrap();
        builder.map(mapping).unwrap();
        let root = builder.root();
        let mut store = builder.into_store();
        let address = mapping.virtual_start();
        let pml4 =
            PhysAddr::new(store.read(root, address.pml4_index()).unwrap() & ADDRESS_MASK).unwrap();
        let pdpt =
            PhysAddr::new(store.read(pml4, address.pdpt_index()).unwrap() & ADDRESS_MASK).unwrap();
        let directory =
            PhysAddr::new(store.read(pdpt, address.directory_index()).unwrap() & ADDRESS_MASK)
                .unwrap();
        let leaf = store.read(directory, address.table_index()).unwrap();
        store
            .write(directory, address.table_index(), leaf | LEAF_ACCESSED_DIRTY)
            .unwrap();
        let mut builder = PageTableBuilder::from_existing_root(store, root);
        builder
            .protect(mapping, PagePermissions::KERNEL_LOW_READ_EXECUTE)
            .unwrap();
        assert_eq!(
            builder.protect(mapping, PagePermissions::KERNEL_LOW_READ_EXECUTE),
            Err(PageTableBuildError::MappingMismatch)
        );
        let executable = Mapping::new(
            VirtAddr::new(0x8000).unwrap(),
            PhysAddr::new(0x8000).unwrap(),
            1,
            PagePermissions::KERNEL_LOW_READ_EXECUTE,
        )
        .unwrap();
        assert_eq!(
            builder.protect(executable, PagePermissions::KERNEL_LOW_READ_WRITE),
            Ok(())
        );
        assert_eq!(builder.unmap_exact(mapping), Ok(()));
        assert_eq!(builder.verify_unmapped(mapping), Ok(()));
        assert_eq!(
            builder.unmap_exact(mapping),
            Err(PageTableBuildError::NotMapped)
        );

        let user = Mapping::new(
            VirtAddr::new(0xa000).unwrap(),
            PhysAddr::new(0xa000).unwrap(),
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        builder.map(user).unwrap();
        assert_eq!(
            builder.protect(user, PagePermissions::USER_MMIO_READ_WRITE),
            Err(PageTableBuildError::MappingMismatch)
        );
        assert_eq!(
            builder.protect(user, PagePermissions::KERNEL_LOW_READ_WRITE),
            Err(PageTableBuildError::MappingMismatch)
        );
        assert_eq!(builder.verify_mapped(user), Ok(()));
    }

    #[test]
    fn exact_mapping_rejects_device_cache_selector_substitution() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mut builder = PageTableBuilder::new(store).unwrap();
        let device = Mapping::new(
            VirtAddr::new(0x9000).unwrap(),
            PhysAddr::new(0x40_0000).unwrap(),
            1,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .unwrap();
        builder.map(device).unwrap();
        let (table, index) = builder.leaf_location(device.virtual_start()).unwrap();
        let substituted =
            builder.store().read(table, index).unwrap() & !LEAF_DEVICE_PAT_INDEX_THREE;
        builder.store.write(table, index, substituted).unwrap();

        assert_eq!(
            builder.verify_mapped(device),
            Err(PageTableBuildError::MappingMismatch)
        );
        let ordinary = Mapping::new(
            device.virtual_start(),
            device.physical_start(),
            device.pages(),
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        assert_eq!(builder.verify_mapped(ordinary), Ok(()));
    }

    #[test]
    fn inactive_backend_installs_only_exact_task_local_device_pages() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let builder = PageTableBuilder::new(store).unwrap();
        let target = ObjectId(0x7100);
        // SAFETY: the mock hierarchy is exclusively owned and unreachable,
        // and `target` is its exact test address-space identity.
        let mut backend = unsafe { InactivePageTableMappingBackend::new(builder, target) };
        let virtual_start = VirtAddr::new(0x20_0000).unwrap();
        let physical_start = PhysAddr::new(0x40_0000).unwrap();
        assert_eq!(backend.target(), target);
        assert_eq!(
            // SAFETY: this is an unreachable modeled root with the test's
            // assumed UC PAT3 layout and no other physical mappings.
            unsafe {
                backend.install_user_device_rw_nx(
                    ObjectId(0x7101),
                    virtual_start,
                    physical_start,
                    2,
                )
            },
            Err(InactivePageTableMappingError::WrongTarget)
        );
        // SAFETY: this is an unreachable modeled root with the test's assumed
        // UC PAT3 layout and no other physical mappings.
        unsafe {
            backend
                .install_user_device_rw_nx(target, virtual_start, physical_start, 2)
                .unwrap()
        };
        let expected = Mapping::new(
            virtual_start,
            physical_start,
            2,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .unwrap();
        assert_eq!(backend.builder.verify_mapped(expected), Ok(()));
        assert_eq!(
            // SAFETY: the same modeled PAT and alias assumptions remain live.
            unsafe { backend.install_user_device_rw_nx(target, virtual_start, physical_start, 2) },
            Err(InactivePageTableMappingError::PageTable(
                PageTableBuildError::AlreadyMapped
            ))
        );
        backend
            .remove_user_device_rw_nx(target, virtual_start, physical_start, 2)
            .unwrap();
        assert_eq!(backend.builder.verify_unmapped(expected), Ok(()));
    }

    #[test]
    fn active_leaf_decode_rejects_partial_device_selector() {
        let frame = PhysAddr::new(0x40_0000).unwrap();
        let device = PageTableEntry::leaf(frame, PagePermissions::USER_MMIO_READ_WRITE)
            .unwrap()
            .bits();
        let decoded = decode_leaf_entry(device).unwrap().unwrap();
        assert_eq!(decoded.physical(), frame);
        assert!(decoded.writable());
        assert!(decoded.user());
        assert!(!decoded.executable());
        assert!(decoded.device_pat_index_three());
        assert_eq!(
            validate_user_buffer_leaf(decoded, UserBufferAccess::Read),
            Err(UserBufferError::AccessDenied)
        );

        for partial in [device & !(1 << 3), device & !(1 << 4)] {
            assert_eq!(
                decode_leaf_entry(partial),
                Err(PageTableBuildError::MappingMismatch)
            );
        }
        let normal = PageTableEntry::leaf(frame, PagePermissions::USER_READ_WRITE)
            .unwrap()
            .bits();
        let normal = decode_leaf_entry(normal).unwrap().unwrap();
        assert!(!normal.device_pat_index_three());
        assert_eq!(
            validate_user_buffer_leaf(normal, UserBufferAccess::Write),
            Ok(())
        );

        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mapping = Mapping::new(
            VirtAddr::new(0x20_0000).unwrap(),
            frame,
            1,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .unwrap();
        let mut builder = PageTableBuilder::new(store).unwrap();
        builder.map(mapping).unwrap();
        let root = builder.root();
        let root_index = mapping.virtual_start().pml4_index();
        let parent = builder.store.read(root, root_index).unwrap();
        builder
            .store
            .write(root, root_index, parent & !((1 << 1) | (1 << 2)))
            .unwrap();
        let effective =
            active_leaf_from_store(builder.store(), builder.root(), mapping.virtual_start())
                .unwrap()
                .unwrap();
        assert!(!effective.writable());
        assert!(!effective.user());
        assert!(effective.device_pat_index_three());
    }

    #[test]
    fn absent_range_verification_rejects_any_live_leaf() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mut builder = PageTableBuilder::new(store).unwrap();
        let mapping = Mapping::new(
            VirtAddr::new(0x10_0000).unwrap(),
            PhysAddr::new(0x20_0000).unwrap(),
            2,
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        builder.map(mapping).unwrap();
        assert_eq!(builder.verify_mapped(mapping), Ok(()));
        let substituted = Mapping::new(
            mapping.virtual_start(),
            PhysAddr::new(0x30_0000).unwrap(),
            mapping.pages(),
            mapping.permissions(),
        )
        .unwrap();
        assert_eq!(
            builder.verify_mapped(substituted),
            Err(PageTableBuildError::MappingMismatch)
        );
        assert_eq!(
            builder.verify_unmapped(mapping),
            Err(PageTableBuildError::AlreadyMapped)
        );
        builder.unmap_exact(mapping).unwrap();
        assert_eq!(builder.verify_unmapped(mapping), Ok(()));
    }

    #[test]
    fn active_service_revoker_rejects_wrong_root_before_mutation() {
        assert!(interrupts_disabled(2));
        assert!(!interrupts_disabled(2 | (1 << 9)));
        let mut active = ActivePageTables {
            root: PhysAddr::new(0x1000).unwrap(),
        };
        let mapping = Mapping::new(
            VirtAddr::new(0x4000).unwrap(),
            PhysAddr::new(0x8000).unwrap(),
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        assert!(matches!(
            unsafe {
                ActiveServiceMappingRevoker::new(
                    &mut active,
                    PhysAddr::new(0x2000).unwrap(),
                    mapping,
                )
            },
            Err(ActiveMappingRevocationError::WrongRoot)
        ));
    }

    #[test]
    fn boot_dma_zeroes_the_complete_verified_extent_only() {
        let reservation = boot_dma_test_reservation();
        let virtual_start = VirtAddr::new(0xffff_9000_0000_0000).unwrap();
        let mapping = Mapping::new(
            virtual_start,
            reservation.physical_base(),
            2,
            PagePermissions::KERNEL_READ_WRITE,
        )
        .unwrap();
        let mut builder = PageTableBuilder::new(Tables {
            pages: [[0; 512]; 8],
            used: 0,
        })
        .unwrap();
        let installed = builder
            .install_boot_dma(reservation, virtual_start)
            .unwrap();
        let root = builder.root();
        let mut memory = [u64::MAX; 1026];
        let initialized =
            initialize_boot_dma_from_store(builder.store(), root, installed, |checked| {
                assert_eq!(checked, mapping);
                let backing = &mut memory[1..1025];
                // SAFETY: the test owns the writable aligned slice for its
                // full length, and the guard words lie outside the slice.
                unsafe { zero_boot_dma_words(backing.as_mut_ptr(), backing.len()) };
                Ok(())
            })
            .unwrap();
        assert_eq!(initialized.reservation().bytes(), 2 * PAGE_SIZE);
        assert_eq!(initialized.root(), root);
        assert_eq!(initialized.mapping(), mapping);
        assert!(memory[1..1025].iter().all(|&word| word == 0));
        assert_eq!(memory[0], u64::MAX);
        assert_eq!(memory[1025], u64::MAX);
    }

    #[test]
    fn boot_read_only_mmio_rejects_aliases_and_permission_mismatch() {
        let mut builder = PageTableBuilder::new(Tables {
            pages: [[0; 512]; 8],
            used: 0,
        })
        .unwrap();
        let virt = VirtAddr::new(0xffff_d900_0000_0000).unwrap();
        let phys = PhysAddr::new(0xfed9_0000).unwrap();
        let mapping = Mapping::new(virt, phys, 1, PagePermissions::KERNEL_MMIO_READ).unwrap();
        let verify = |builder: &PageTableBuilder<Tables>| {
            verify_read_only_mmio_from_store(builder.store(), builder.root(), mapping)
        };
        assert_eq!(verify(&builder), Err(PageTableBuildError::MappingMismatch));
        builder.map(mapping).unwrap();
        assert_eq!(verify(&builder), Ok(()));
        let root = builder.root();
        let (table, index) = builder.leaf_location(virt).unwrap();
        let mut store = builder.into_store();
        let bits = store.read(table, index).unwrap();
        store.write(table, index, bits | (1 << 1)).unwrap();
        assert_eq!(
            verify_read_only_mmio_from_store(&store, root, mapping),
            Err(PageTableBuildError::MappingMismatch)
        );
        store.write(table, index, bits).unwrap();
        let mut builder = PageTableBuilder::from_existing_root(store, root);
        builder
            .map_page(
                VirtAddr::new(virt.get() + PAGE_SIZE).unwrap(),
                phys,
                PagePermissions::KERNEL_READ_WRITE,
            )
            .unwrap();
        assert_eq!(verify(&builder), Err(PageTableBuildError::PhysicalAlias));
    }

    #[test]
    fn passive_pci_mapping_requires_the_prepared_root_and_exact_exclusive_read_only_leaf() {
        let mut builder = PageTableBuilder::new(Tables {
            pages: [[0; 512]; 8],
            used: 0,
        })
        .unwrap();
        let root = builder.root();
        let virt = VirtAddr::new(0xffff_d900_0000_0000).unwrap();
        let phys = PhysAddr::new(0xe00a_0000).unwrap();
        let other = PhysAddr::new(phys.get() + PAGE_SIZE).unwrap();
        let ro = PagePermissions::KERNEL_MMIO_READ;
        let exact = Mapping::new(virt, phys, 1, ro).unwrap();
        let verify = |store: &Tables, expected_root, proposal| {
            verify_passive_pci_mapping_from_store(store, root, expected_root, phys, proposal)
        };
        assert_eq!(verify(builder.store(), root, exact), Err(PageTableBuildError::MappingMismatch));
        builder.map(exact).unwrap();
        assert_eq!(verify(builder.store(), root, exact), Ok(()));
        for (expected_root, proposal) in [
            (other, exact),
            (root, Mapping::new(virt, phys, 2, ro).unwrap()),
            (root, Mapping::new(virt, other, 1, ro).unwrap()),
            (
                root,
                Mapping::new(virt, phys, 1, PagePermissions::KERNEL_HIGH_MMIO_READ_WRITE).unwrap(),
            ),
            (root, Mapping::new(virt, phys, 1, PagePermissions::KERNEL_READ).unwrap()),
        ] {
            assert_eq!(verify(builder.store(), expected_root, proposal), Err(PageTableBuildError::MappingMismatch));
        }
        let (table, index) = builder.leaf_location(virt).unwrap();
        let mut store = builder.into_store();
        let bits = store.read(table, index).unwrap();
        for changed in [bits | (1 << 1), bits & !(1 << 63), bits & !(1 << 4)] {
            store.write(table, index, changed).unwrap();
            assert_eq!(verify(&store, root, exact), Err(PageTableBuildError::MappingMismatch));
        }
        store.write(table, index, bits).unwrap();
        let mut builder = PageTableBuilder::from_existing_root(store, root);
        builder
            .map_page(VirtAddr::new(virt.get() + PAGE_SIZE).unwrap(), phys, ro)
            .unwrap();
        assert_eq!(verify(builder.store(), root, exact), Err(PageTableBuildError::PhysicalAlias));
    }

    #[test]
    fn boot_read_only_mmio_rejects_table_frames_and_unknown_large_leaves() {
        let mut store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let root = store.allocate_zeroed().unwrap();
        let pdpt = store.allocate_zeroed().unwrap();
        let virt = VirtAddr::new(0xffff_d900_0000_0000).unwrap();
        let aliased = Mapping::new(virt, pdpt, 1, PagePermissions::KERNEL_MMIO_READ).unwrap();
        store.write(root, 0, pdpt.get() | 0b11).unwrap();
        assert_eq!(
            verify_read_only_mmio_from_store(&store, root, aliased),
            Err(PageTableBuildError::PhysicalAlias)
        );
        store.write(pdpt, 0, 0x4000_0000 | 0x83).unwrap();
        let mapping = Mapping::new(
            virt,
            PhysAddr::new(0xfed9_0000).unwrap(),
            1,
            PagePermissions::KERNEL_MMIO_READ,
        )
        .unwrap();
        assert_eq!(
            verify_read_only_mmio_from_store(&store, root, mapping),
            Err(PageTableBuildError::InvalidIntermediate)
        );
    }

    #[test]
    fn unmapped_boot_range_rejects_alternate_leaves_and_table_frames() {
        let mut builder = PageTableBuilder::new(Tables {
            pages: [[0; 512]; 8],
            used: 0,
        }).unwrap();
        let start = PhysAddr::new(0x8120_0000).unwrap();
        let root = builder.root();
        let check = |store: &Tables, address, pages| {
            verify_physical_coverage_from_store(store, root, address, pages, None)
        };
        assert_eq!(check(builder.store(), start, 4), Ok(()));
        assert_eq!(check(builder.store(), start, 0), Err(PageTableBuildError::AddressOverflow));
        assert_eq!(check(builder.store(), root, 1), Err(PageTableBuildError::PhysicalAlias));
        let last = PhysAddr::new(start.get() + 3 * PAGE_SIZE).unwrap();
        let next = PhysAddr::new(start.get() + 4 * PAGE_SIZE).unwrap();
        let arbitrary = VirtAddr::new(0xffff_da00_0000_0000).unwrap();
        builder.map_page(arbitrary, last, PagePermissions::KERNEL_READ).unwrap();
        assert_eq!(check(builder.store(), start, 4), Err(PageTableBuildError::PhysicalAlias));
        assert_eq!(check(builder.store(), start, 3), Ok(()));
        assert_eq!(check(builder.store(), next, 1), Ok(()));
        let (table, _) = builder.leaf_location(arbitrary).unwrap();
        assert_eq!(check(builder.store(), table, 1), Err(PageTableBuildError::PhysicalAlias));
        let mut store = builder.into_store();
        let pdpt = PhysAddr::new(store.read(root, ((arbitrary.get() >> 39) & 511) as usize).unwrap() & ADDRESS_MASK).unwrap();
        store.write(pdpt, 0, 0x8000_0000 | 0x83).unwrap();
        assert_eq!(check(&store, start, 4), Err(PageTableBuildError::InvalidIntermediate));
    }

    fn boot_dma_test_reservation() -> BootDmaReservation {
        use crate::{FrameAllocator, MemoryKind, MemoryMap, MemoryRegion};

        let memory =
            [MemoryRegion::new(PhysAddr::new(0x40_0000).unwrap(), 2, MemoryKind::Free).unwrap()];
        FrameAllocator::new(MemoryMap::new(&memory).unwrap())
            .reserve_boot_dma(2, 32)
            .unwrap()
    }

    #[test]
    fn boot_dma_rejects_bad_root_or_later_leaf_before_any_clear() {
        let virtual_start = VirtAddr::new(0xffff_9000_0000_0000).unwrap();
        for case in 0..5 {
            let reservation = boot_dma_test_reservation();
            let physical_start = reservation.physical_base();
            let mut builder = PageTableBuilder::new(Tables {
                pages: [[0; 512]; 8],
                used: 0,
            })
            .unwrap();
            builder
                .map(
                    Mapping::new(
                        virtual_start,
                        physical_start,
                        1,
                        PagePermissions::KERNEL_READ_WRITE,
                    )
                    .unwrap(),
                )
                .unwrap();
            if case != 0 {
                let second_physical =
                    PhysAddr::new(physical_start.get() + if case == 1 { 3 } else { 1 } * PAGE_SIZE)
                        .unwrap();
                let second_permissions = match case {
                    2 => PagePermissions::KERNEL_READ,
                    3 => PagePermissions::KERNEL_READ_EXECUTE,
                    _ => PagePermissions::KERNEL_READ_WRITE,
                };
                builder
                    .map(
                        Mapping::new(
                            VirtAddr::new(virtual_start.get() + PAGE_SIZE).unwrap(),
                            second_physical,
                            1,
                            second_permissions,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            let root = builder.root();
            let expected_root = if case == 4 {
                PhysAddr::new(root.get() + PAGE_SIZE).unwrap()
            } else {
                root
            };
            assert_eq!(
                initialize_boot_dma_from_store(
                    builder.store(),
                    root,
                    InstalledBootDma {
                        reservation,
                        root: expected_root,
                        mapping: Mapping::new(
                            virtual_start,
                            physical_start,
                            2,
                            PagePermissions::KERNEL_READ_WRITE,
                        )
                        .unwrap(),
                    },
                    |_| panic!("must preflight the complete mapping before clearing"),
                ),
                Err(PageTableBuildError::MappingMismatch),
            );
        }
    }

    #[test]
    fn boot_dma_install_preserves_occupied_slots_and_rolls_back_late_failure() {
        // The reservation spans the last leaf of one table and the first
        // leaf of the next table. Keep a neighboring mapping in the first.
        let start = VirtAddr::new(0xffff_9000_001f_f000).unwrap();
        let guard = VirtAddr::new(start.get() - PAGE_SIZE).unwrap();
        let guard_frame = PhysAddr::new(0x60_0000).unwrap();
        let second = VirtAddr::new(start.get() + PAGE_SIZE).unwrap();
        for collide in [true, false] {
            let mut builder = PageTableBuilder::new(Tables {
                pages: [[0; 512]; 8],
                used: 0,
            })
            .unwrap();
            builder
                .map_page(guard, guard_frame, PagePermissions::KERNEL_READ)
                .unwrap();
            let root = builder.root();
            let existing = if collide {
                builder
                    .map_page(second, guard_frame, PagePermissions::KERNEL_READ)
                    .unwrap();
                PageTableBuildError::AlreadyMapped
            } else {
                builder.store.used = builder.store.pages.len();
                PageTableBuildError::Storage
            };
            assert_eq!(
                builder.install_boot_dma(boot_dma_test_reservation(), start),
                Err(BootDmaInstallError::PageTable(existing))
            );
            let leaf = |addr| active_leaf_from_store(builder.store(), root, addr).unwrap();
            assert_eq!(leaf(start), None);
            assert_eq!(
                leaf(second).map(ActiveLeaf::physical),
                collide.then_some(guard_frame)
            );
            assert_eq!(leaf(guard).unwrap().physical(), guard_frame);
        }
    }

    #[test]
    fn active_mapping_verification_exact_matches_root_extent_and_permissions() {
        let store = Tables {
            pages: [[0; 512]; 8],
            used: 0,
        };
        let mapping = Mapping::new(
            VirtAddr::new(0x20_0000).unwrap(),
            PhysAddr::new(0x40_0000).unwrap(),
            2,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .unwrap();
        let mut builder = PageTableBuilder::new(store).unwrap();
        builder.map(mapping).unwrap();
        let root = builder.root();
        assert_eq!(
            verify_active_mapping_from_store(builder.store(), root, root, mapping),
            Ok(())
        );
        assert_eq!(
            verify_active_mapping_from_store(
                builder.store(),
                root,
                PhysAddr::new(root.get() + PAGE_SIZE).unwrap(),
                mapping,
            ),
            Err(PageTableBuildError::MappingMismatch)
        );
        let normal = Mapping::new(
            mapping.virtual_start(),
            mapping.physical_start(),
            mapping.pages(),
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        assert_eq!(
            verify_active_mapping_from_store(builder.store(), root, root, normal),
            Err(PageTableBuildError::MappingMismatch)
        );
        let substituted = Mapping::new(
            mapping.virtual_start(),
            PhysAddr::new(mapping.physical_start().get() + PAGE_SIZE).unwrap(),
            mapping.pages(),
            mapping.permissions(),
        )
        .unwrap();
        assert_eq!(
            verify_active_mapping_from_store(builder.store(), root, root, substituted),
            Err(PageTableBuildError::MappingMismatch)
        );
    }

    #[test]
    fn active_service_revoker_requires_the_exact_virtual_extent() {
        let root = PhysAddr::new(0x1000).unwrap();
        let mut active = ActivePageTables { root };
        let mapping = Mapping::new(
            VirtAddr::new(0x4000).unwrap(),
            PhysAddr::new(0x8000).unwrap(),
            2,
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap();
        let mut revoker =
            unsafe { ActiveServiceMappingRevoker::new(&mut active, root, mapping) }.unwrap();
        assert_eq!(
            revoker.revoke_guest_mapping(0x5000, 2 * PAGE_SIZE),
            Err(ActiveMappingRevocationError::WrongMapping)
        );
        assert_eq!(
            revoker.revoke_guest_mapping(0x4000, PAGE_SIZE),
            Err(ActiveMappingRevocationError::WrongMapping)
        );
    }
}
