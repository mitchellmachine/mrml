use crate::{
    ArtifactError, ArtifactKind, MAX_SERVICE_IMAGE_BYTES, PAGE_SIZE, PeError, PeImage,
    RetainedBootEnvelope, ServiceLaunch, SignedArtifact,
};
use mrml_crypto::Sha3_512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootServiceImageError {
    Container(ArtifactError),
    WrongKind,
    ReleaseMismatch,
    MeasurementMismatch,
    Image(PeError),
    LayoutMismatch,
}

/// A retained boot payload checked against the loader's service handoff.
/// This is data for a future guest builder, not signature verification, a
/// supervisor identity, a capability, or permission to execute natively.
pub struct BootServiceImage<'a> {
    image: PeImage<'a>,
    release: u64,
    measurement: [u8; 64],
}

impl<'a> BootServiceImage<'a> {
    /// The caller must separately trust the handoff: the expected digest
    /// comes from the loader's authenticated coherent release, not the
    /// envelope's self-declared digest or a key supplied by the payload.
    pub fn check(
        launch: ServiceLaunch,
        accepted_release: u64,
        bytes: &'a [u8],
    ) -> Result<Self, BootServiceImageError> {
        let checked = Self::check_envelope(launch.envelope(), accepted_release, bytes)?;
        let image = checked.image();
        if u64::from(image.image_size()).div_ceil(PAGE_SIZE) != launch.image_pages()
            || image.image_base() != launch.image_virtual()
            || image.image_base().checked_add(u64::from(image.entry_rva())) != Some(launch.entry())
        {
            return Err(BootServiceImageError::LayoutMismatch);
        }
        Ok(checked)
    }

    /// Check the retained source without adopting an existing image, stack
    /// or page-table layout. The caller still needs an authenticated handoff
    /// and must establish that the envelope's bytes are the retained bytes.
    pub fn check_envelope(
        envelope: RetainedBootEnvelope,
        accepted_release: u64,
        bytes: &'a [u8],
    ) -> Result<Self, BootServiceImageError> {
        if u64::try_from(bytes.len()).ok() != Some(envelope.artifact_length()) {
            return Err(BootServiceImageError::LayoutMismatch);
        }
        let artifact = SignedArtifact::decode(bytes).map_err(BootServiceImageError::Container)?;
        if artifact.kind() != ArtifactKind::ServiceImage {
            return Err(BootServiceImageError::WrongKind);
        }
        if artifact.version() != accepted_release || envelope.version() != accepted_release {
            return Err(BootServiceImageError::ReleaseMismatch);
        }
        if Sha3_512::digest(artifact.payload()) != envelope.measurement() {
            return Err(BootServiceImageError::MeasurementMismatch);
        }
        let image = PeImage::parse_with_limit(artifact.payload(), MAX_SERVICE_IMAGE_BYTES)
            .map_err(BootServiceImageError::Image)?;
        Ok(Self {
            image,
            release: accepted_release,
            measurement: envelope.measurement(),
        })
    }

    /// Guests must be materialized from these checked source bytes, not
    /// by adopting the loader's legacy native page tables or staging image.
    pub const fn image(&self) -> &PeImage<'a> {
        &self.image
    }
}

/// Canonical boot-owner policy record for the first supervisor role. Decoding
/// does not grant authority. The enrolled owner policy must pin the hash of the
/// record separately from the publisher's release and build receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootSupervisorSelection {
    release: u64,
    manifest: [u8; 64],
    service: [u8; 64],
}

pub const BOOT_SUPERVISOR_SELECTION_BYTES: usize = 152;
const SUPERVISOR_ROLE: &[u8; 16] = b"MRML-SUPERVISOR1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSupervisorError {
    InvalidSelection,
    NotOwnerSelected,
    WrongRelease,
    WrongService,
    Image(PeError),
}

impl BootSupervisorSelection {
    pub fn new(
        release: u64,
        manifest: [u8; 64],
        service: [u8; 64],
    ) -> Result<Self, BootSupervisorError> {
        if release == 0 || manifest == [0; 64] || service == [0; 64] {
            return Err(BootSupervisorError::InvalidSelection);
        }
        Ok(Self {
            release,
            manifest,
            service,
        })
    }

    pub(crate) fn matches_envelope(self, release: u64, envelope: RetainedBootEnvelope) -> bool {
        self.release == release
            && envelope.version() == release
            && self.service == envelope.measurement()
    }

    pub fn encode(self) -> [u8; BOOT_SUPERVISOR_SELECTION_BYTES] {
        let mut bytes = [0; BOOT_SUPERVISOR_SELECTION_BYTES];
        bytes[..16].copy_from_slice(SUPERVISOR_ROLE);
        bytes[16..24].copy_from_slice(&self.release.to_le_bytes());
        bytes[24..88].copy_from_slice(&self.manifest);
        bytes[88..].copy_from_slice(&self.service);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BootSupervisorError> {
        if bytes.len() != BOOT_SUPERVISOR_SELECTION_BYTES || &bytes[..16] != SUPERVISOR_ROLE {
            return Err(BootSupervisorError::InvalidSelection);
        }
        Self::new(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            bytes[24..88].try_into().unwrap(),
            bytes[88..].try_into().unwrap(),
        )
    }

    /// Bind checked transport to independently authenticated owner policy and
    /// the manifest identity of the accepted coherent release. Neither input
    /// may come from the untrusted record itself or the service image.
    pub fn bind<'a>(
        self,
        owner_selected_digest: [u8; 64],
        accepted_manifest: [u8; 64],
        service: BootServiceImage<'a>,
    ) -> Result<SelectedBootSupervisor<'a>, BootSupervisorError> {
        if owner_selected_digest == [0; 64]
            || Sha3_512::digest(&self.encode()) != owner_selected_digest
        {
            return Err(BootSupervisorError::NotOwnerSelected);
        }
        if self.release != service.release || self.manifest != accepted_manifest {
            return Err(BootSupervisorError::WrongRelease);
        }
        if self.service != service.measurement {
            return Err(BootSupervisorError::WrongService);
        }
        Ok(SelectedBootSupervisor {
            image: service.image,
        })
    }
}

/// An owner-selected source, not a launched guest or a capability.
///
/// The fresh backing and its eventual EPT ownership remain the responsibility
/// of the guest builder. No references to the loader's native PE, stack or
/// page-table mappings are accepted by this interface.
pub struct SelectedBootSupervisor<'a> {
    image: PeImage<'a>,
}

impl<'image> SelectedBootSupervisor<'image> {
    pub const fn image_size(&self) -> u32 {
        self.image.image_size()
    }

    /// Populate a caller-owned, non-executable buffer. The returned entry is
    /// a guest virtual address at the PE's preferred base, not a host pointer.
    /// The final guest plan maps only the validated PE regions.
    pub fn stage<'a>(
        self,
        destination: &'a mut [u8],
    ) -> Result<StagedBootSupervisor<'a, 'image>, BootSupervisorError> {
        let entry = self
            .image
            .materialize(destination)
            .map_err(BootSupervisorError::Image)?;
        Ok(StagedBootSupervisor {
            image: self.image,
            bytes: destination,
            entry,
        })
    }
}

pub struct StagedBootSupervisor<'memory, 'image> {
    image: PeImage<'image>,
    bytes: &'memory [u8],
    entry: u64,
}

impl StagedBootSupervisor<'_, '_> {
    pub const fn guest_entry(&self) -> u64 {
        self.entry
    }

    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub const fn guest_image_base(&self) -> u64 {
        self.image.image_base()
    }

    pub const fn load_region_count(&self) -> usize {
        self.image.load_region_count()
    }

    pub fn load_region(&self, index: usize) -> Result<crate::PeLoadRegion, PeError> {
        self.image.load_region(index)
    }
}

const BOOT_GUEST_IMAGE_REGIONS: usize = crate::MAX_PE_SECTIONS + 1;
const BOOT_GUEST_PHYSICAL_LIMIT: u64 = 1 << 48;
const BOOT_GUEST_VIRTUAL_LIMIT: u64 = 1 << 47;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSupervisorMemoryError {
    InvalidGuestAperture,
    Memory(crate::MemoryError),
    Image(PeError),
    Guest(crate::VmError),
}

/// Owns the boot allocator's reservation and the proposed guest mappings.
/// Reservation does not install EPT, create a VM, or imply a host write alias.
pub struct ReservedBootSupervisorImage<'image> {
    image: PeImage<'image>,
    physical_base: crate::PhysAddr,
    guest_physical_base: u64,
    host_physical_bits: u8,
    layout: crate::GuestMemory<BOOT_GUEST_IMAGE_REGIONS>,
}

impl<'image> SelectedBootSupervisor<'image> {
    /// The allocator must be the boot owner's unique allocator for this map.
    /// Guest-physical offsets are independent of the PE's preferred virtual
    /// base. Headers are RO/NX, sections retain their PE permissions, and
    /// gaps receive no guest mapping. Failed reservations are never recycled.
    pub fn reserve_guest_image(
        self,
        allocator: &mut crate::FrameAllocator<'_>,
        guest_physical_base: u64,
        host_physical_bits: u8,
    ) -> Result<ReservedBootSupervisorImage<'image>, BootSupervisorMemoryError> {
        let image_bytes = u64::from(self.image.image_size());
        if self.image.image_base() == 0
            || self
                .image
                .image_base()
                .checked_add(image_bytes)
                .is_none_or(|end| end > BOOT_GUEST_VIRTUAL_LIMIT)
            || guest_physical_base == 0
            || !guest_physical_base.is_multiple_of(PAGE_SIZE)
            || guest_physical_base
                .checked_add(image_bytes)
                .is_none_or(|end| end > BOOT_GUEST_PHYSICAL_LIMIT)
            || !(32..=52).contains(&host_physical_bits)
        {
            return Err(BootSupervisorMemoryError::InvalidGuestAperture);
        }
        let physical_base = allocator
            .allocate_contiguous_in(
                image_bytes / PAGE_SIZE,
                1,
                PAGE_SIZE,
                1 << host_physical_bits,
            )
            .map_err(BootSupervisorMemoryError::Memory)?;
        let mut layout = crate::GuestMemory::new();
        for index in 0..self.image.load_region_count() {
            let region = self
                .image
                .load_region(index)
                .map_err(BootSupervisorMemoryError::Image)?;
            let offset = u64::from(region.virtual_address());
            let host = crate::PhysAddr::new(physical_base.get() + offset)
                .map_err(BootSupervisorMemoryError::Memory)?;
            let mapping = crate::GuestRegion::new(
                guest_physical_base + offset,
                host,
                u64::from(region.pages()),
                region.writable(),
                region.executable(),
            )
            .map_err(BootSupervisorMemoryError::Guest)?;
            layout
                .map(mapping)
                .map_err(BootSupervisorMemoryError::Guest)?;
        }
        layout
            .prepare_range(
                guest_physical_base + u64::from(self.image.entry_rva()),
                1,
                crate::GuestAccess::Execute,
            )
            .map_err(BootSupervisorMemoryError::Guest)?;
        Ok(ReservedBootSupervisorImage {
            image: self.image,
            physical_base,
            guest_physical_base,
            host_physical_bits,
            layout,
        })
    }
}

/// Completed but unpublished EPT for the image only. Guest page tables,
/// stack, and launch controls are still required.
pub struct BootSupervisorImageTables<'image, Store> {
    _reservation: ReservedBootSupervisorImage<'image>,
    _store: Store,
    root: crate::PhysAddr,
}

impl<Store> BootSupervisorImageTables<'_, Store> {
    pub const fn root(&self) -> crate::PhysAddr {
        self.root
    }
}

impl<'image> ReservedBootSupervisorImage<'image> {
    /// Build against fresh, inactive table storage. The platform must keep
    /// it exclusive and outside the image backing, and preserve it for the
    /// entire lifetime of the result. No VMCS has consumed this root.
    pub fn build_inactive_ept<Store: crate::arch::x86_64::PageTableStore>(
        self,
        mut store: Store,
    ) -> Result<BootSupervisorImageTables<'image, Store>, crate::arch::x86_64::BootImageEptError>
    {
        let start = self.physical_base.get();
        let end = start + u64::from(self.image_size());
        let root = crate::arch::x86_64::build_boot_image_ept(
            &mut store,
            start..end,
            self.host_physical_bits,
            self.layout.regions(),
        )?;
        Ok(BootSupervisorImageTables {
            _reservation: self,
            _store: store,
            root,
        })
    }

    pub const fn physical_base(&self) -> crate::PhysAddr {
        self.physical_base
    }

    pub const fn guest_physical_base(&self) -> u64 {
        self.guest_physical_base
    }

    pub const fn guest_virtual_base(&self) -> u64 {
        self.image.image_base()
    }

    pub const fn image_size(&self) -> u32 {
        self.image.image_size()
    }

    pub const fn layout(&self) -> &crate::GuestMemory<BOOT_GUEST_IMAGE_REGIONS> {
        &self.layout
    }

    /// Initialize an exact-size NX view of the reserved backing supplied by
    /// the platform. This routine does not create or authenticate that view.
    /// No guest mapping may be installed or active while bytes are written.
    pub fn initialize_nx_view(&self, view: &mut [u8]) -> Result<u64, PeError> {
        self.image.materialize(view)
    }
}

const SUPERVISOR_MAX_STACK_PAGES: u64 = 16;
const SUPERVISOR_MAX_LINEAR_TABLES: u64 = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorBootstrapError {
    InvalidLayout,
    InvalidView,
    Memory(crate::MemoryError),
    Guest(crate::VmError),
    Linear(crate::arch::x86_64::PageTableBuildError),
}

/// Guest-private bootstrap reservations. The guard is absent from both
/// address spaces. This does not map host RAM or authorize VM entry.
pub struct ReservedSupervisorBootstrap<'image> {
    image: ReservedBootSupervisorImage<'image>,
    stack: crate::GuestRegion,
    stack_top: u64,
    table_arena: crate::GuestRegion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorLinearState {
    pub guest_cr3: crate::PhysAddr,
    pub guest_stack_top: u64,
}

impl<'image> ReservedBootSupervisorImage<'image> {
    /// Reserve distinct tables and stack beside the PE. Use the same
    /// monotonic allocator which issued the image reservation.
    pub fn reserve_guest_bootstrap(
        self,
        allocator: &mut crate::FrameAllocator<'_>,
        guard_gva: u64,
        guard_gpa: u64,
        stack_pages: u64,
        table_gpa: u64,
        table_pages: u64,
    ) -> Result<ReservedSupervisorBootstrap<'image>, SupervisorBootstrapError> {
        if !(1..=SUPERVISOR_MAX_STACK_PAGES).contains(&stack_pages)
            || !(1..=SUPERVISOR_MAX_LINEAR_TABLES).contains(&table_pages)
        {
            return Err(SupervisorBootstrapError::InvalidLayout);
        }
        let range = |start: u64, pages: u64, limit: u64| {
            start
                .checked_add(pages * PAGE_SIZE)
                .filter(|&end| start != 0 && start.is_multiple_of(PAGE_SIZE) && end <= limit)
                .map(|end| start..end)
                .ok_or(SupervisorBootstrapError::InvalidLayout)
        };
        let stack_gva = range(guard_gva, stack_pages + 1, BOOT_GUEST_VIRTUAL_LIMIT)?;
        let stack_gpa = range(guard_gpa, stack_pages + 1, BOOT_GUEST_PHYSICAL_LIMIT)?;
        let tables = range(table_gpa, table_pages, BOOT_GUEST_PHYSICAL_LIMIT)?;
        let image_bytes = u64::from(self.image_size());
        let image_gpa = self.guest_physical_base..self.guest_physical_base + image_bytes;
        let image_gva = self.guest_virtual_base()..self.guest_virtual_base() + image_bytes;
        let overlap = |a: &core::ops::Range<u64>, b: &core::ops::Range<u64>| {
            a.start < b.end && b.start < a.end
        };
        if overlap(&stack_gva, &image_gva)
            || overlap(&stack_gpa, &image_gpa)
            || overlap(&tables, &image_gpa)
            || overlap(&tables, &stack_gpa)
        {
            return Err(SupervisorBootstrapError::InvalidLayout);
        }
        let mut allocate = |pages| {
            allocator
                .allocate_contiguous_in(pages, 1, PAGE_SIZE, 1 << self.host_physical_bits)
                .map_err(SupervisorBootstrapError::Memory)
        };
        let stack = crate::GuestRegion::new(
            stack_gpa.start + PAGE_SIZE,
            allocate(stack_pages)?,
            stack_pages,
            true,
            false,
        )
        .map_err(SupervisorBootstrapError::Guest)?;
        let table_arena = crate::GuestRegion::new(
            tables.start,
            allocate(table_pages)?,
            table_pages,
            true,
            false,
        )
        .map_err(SupervisorBootstrapError::Guest)?;
        let host_range = |region: crate::GuestRegion| {
            region.host_start().get()..region.host_start().get() + region.pages() * PAGE_SIZE
        };
        let image_host = self.physical_base.get()..self.physical_base.get() + image_bytes;
        if overlap(&image_host, &host_range(stack))
            || overlap(&image_host, &host_range(table_arena))
            || overlap(&host_range(stack), &host_range(table_arena))
        {
            return Err(SupervisorBootstrapError::InvalidLayout);
        }
        Ok(ReservedSupervisorBootstrap {
            image: self,
            stack,
            stack_top: stack_gva.end,
            table_arena,
        })
    }
}

impl ReservedSupervisorBootstrap<'_> {
    pub const fn stack_region(&self) -> crate::GuestRegion {
        self.stack
    }
    pub const fn table_region(&self) -> crate::GuestRegion {
        self.table_arena
    }

    /// Populate the exact reserved NX views. The platform must bind slices
    /// to the reservations, not to active or shared mappings. Entries are
    /// addressed by guest physical addresses even though the host writes them.
    /// A failed build publishes no CR3 or stack pointer.
    pub fn initialize_linear(
        &self,
        tables: &mut [[u64; 512]],
        stack: &mut [u8],
    ) -> Result<SupervisorLinearState, SupervisorBootstrapError> {
        use crate::arch::x86_64::{PagePermissions, PageTableBuilder, VirtAddr};
        if tables.len() as u64 != self.table_arena.pages()
            || stack.len() as u64 != self.stack.pages() * PAGE_SIZE
        {
            return Err(SupervisorBootstrapError::InvalidView);
        }
        let mut builder = PageTableBuilder::new(GuestLinearArena {
            pages: tables,
            base: self.table_arena.guest_start(),
            count: 0,
        })
        .map_err(SupervisorBootstrapError::Linear)?;
        let mut map = |guest_virtual, region: crate::GuestRegion| {
            let permissions = match (region.is_writable(), region.is_executable()) {
                (true, false) => PagePermissions::KERNEL_READ_WRITE,
                (false, true) => PagePermissions::KERNEL_READ_EXECUTE,
                (false, false) => PagePermissions::KERNEL_READ,
                _ => return Err(SupervisorBootstrapError::InvalidLayout),
            };
            // This is a fresh guest CR3, not a host address space.
            for page in 0..region.pages() {
                let offset = page * PAGE_SIZE;
                let virtual_page = VirtAddr::new(guest_virtual + offset)
                    .map_err(|_| SupervisorBootstrapError::InvalidLayout)?;
                let guest_page = crate::PhysAddr::new(region.guest_start() + offset)
                    .map_err(SupervisorBootstrapError::Memory)?;
                builder
                    .map_page(virtual_page, guest_page, permissions)
                    .map_err(SupervisorBootstrapError::Linear)?;
            }
            Ok(())
        };
        for region in self.image.layout.regions() {
            let offset = region.guest_start() - self.image.guest_physical_base;
            map(self.image.guest_virtual_base() + offset, region)?;
        }
        map(self.stack_top - self.stack.pages() * PAGE_SIZE, self.stack)?;
        stack.fill(0);
        // Even unused arena pages must never expose old host contents.
        let guest_cr3 = builder.root();
        let arena = builder.into_store();
        arena.pages[arena.count..].fill([0; 512]);
        Ok(SupervisorLinearState {
            guest_cr3,
            guest_stack_top: self.stack_top,
        })
    }
}

struct GuestLinearArena<'a> {
    pages: &'a mut [[u64; 512]],
    base: u64,
    count: usize,
}

use crate::arch::x86_64::PageTableBuildError as LinearError;

impl GuestLinearArena<'_> {
    fn index(&self, table: crate::PhysAddr) -> Result<usize, LinearError> {
        let page = table
            .get()
            .checked_sub(self.base)
            .ok_or(LinearError::Storage)?
            / PAGE_SIZE;
        (page < self.count as u64)
            .then_some(page as usize)
            .ok_or(LinearError::Storage)
    }
}

impl crate::arch::x86_64::PageTableStore for GuestLinearArena<'_> {
    fn allocate_zeroed(&mut self) -> Result<crate::PhysAddr, LinearError> {
        self.pages
            .get_mut(self.count)
            .ok_or(LinearError::Storage)?
            .fill(0);
        let table = crate::PhysAddr::new(self.base + self.count as u64 * PAGE_SIZE)
            .map_err(|_| LinearError::Storage)?;
        self.count += 1;
        Ok(table)
    }

    fn read(&self, table: crate::PhysAddr, index: usize) -> Result<u64, LinearError> {
        self.pages[self.index(table)?]
            .get(index)
            .copied()
            .ok_or(LinearError::Storage)
    }

    fn write(
        &mut self,
        table: crate::PhysAddr,
        index: usize,
        value: u64,
    ) -> Result<(), LinearError> {
        let page = self.index(table)?;
        *self.pages[page]
            .get_mut(index)
            .ok_or(LinearError::Storage)? = value;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PhysAddr, SIGNED_ARTIFACT_OVERHEAD_BYTES};

    const BASE: u64 = 0x0000_0001_4000_0000;

    fn bundle(
        payload: [u8; 1024],
        kind: ArtifactKind,
        version: u64,
    ) -> [u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024] {
        // Only the envelope and its digest are relevant to this test. This
        // intentionally has no valid signature; check() is a transport check.
        let mut bytes = [0; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024];
        bytes[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        bytes[16] = kind as u8;
        bytes[24..32].copy_from_slice(&version.to_le_bytes());
        bytes[32..40].copy_from_slice(&1024u64.to_le_bytes());
        bytes[40..104].copy_from_slice(&Sha3_512::digest(&payload));
        bytes[SIGNED_ARTIFACT_OVERHEAD_BYTES..].copy_from_slice(&payload);
        bytes
    }

    fn launch(payload: &[u8], pages: u64, entry: u64) -> ServiceLaunch {
        let phys = |at| PhysAddr::new(at).unwrap();
        ServiceLaunch::new(
            phys(0x10000),
            (SIGNED_ARTIFACT_OVERHEAD_BYTES + payload.len()) as u64,
            phys(0x30000),
            pages,
            BASE,
            entry,
            phys(0x40000),
            4,
            0x0000_0002_0000_0000,
            phys(0x50000),
            4,
            7,
            Sha3_512::digest(payload),
        )
        .unwrap()
    }

    #[test]
    fn retained_service_matches_exact_release_digest_and_single_image_layout() {
        let payload = crate::pe::tests::valid_pe();
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let expected = launch(&payload, 2, BASE + PAGE_SIZE);
        assert_eq!(
            BootServiceImage::check(expected, 7, &original)
                .unwrap()
                .image()
                .entry_rva(),
            4096
        );
        assert_eq!(
            BootServiceImage::check(expected, 8, &original).err(),
            Some(BootServiceImageError::ReleaseMismatch)
        );
        assert_eq!(
            BootServiceImage::check(expected, 7, &bundle(payload, ArtifactKind::ServiceImage, 8))
                .err(),
            Some(BootServiceImageError::ReleaseMismatch)
        );
        assert_eq!(
            BootServiceImage::check(
                expected,
                7,
                &bundle(payload, ArtifactKind::ApplicationImage, 7)
            )
            .err(),
            Some(BootServiceImageError::WrongKind)
        );
        let mut changed = payload;
        changed[0x200] ^= 1;
        assert_eq!(
            BootServiceImage::check(expected, 7, &bundle(changed, ArtifactKind::ServiceImage, 7))
                .err(),
            Some(BootServiceImageError::MeasurementMismatch)
        );
        assert_eq!(
            BootServiceImage::check(expected, 7, &original[1..]).err(),
            Some(BootServiceImageError::LayoutMismatch)
        );
        for mismatched in [
            launch(&payload, 4, BASE + PAGE_SIZE),
            launch(&payload, 2, BASE + PAGE_SIZE + 1),
        ] {
            assert_eq!(
                BootServiceImage::check(mismatched, 7, &original).err(),
                Some(BootServiceImageError::LayoutMismatch)
            );
        }
        let invalid = [0; 1024];
        assert!(matches!(
            BootServiceImage::check(
                launch(&invalid, 2, BASE + PAGE_SIZE),
                7,
                &bundle(invalid, ArtifactKind::ServiceImage, 7)
            ),
            Err(BootServiceImageError::Image(_))
        ));
    }

    #[test]
    fn envelope_check_does_not_reuse_native_staging() {
        let payload = crate::pe::tests::valid_pe();
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let staging = launch(&payload, 4, BASE + PAGE_SIZE + 1);
        let envelope = staging.envelope();
        assert_eq!(envelope.artifact_physical(), staging.artifact_physical());
        assert_eq!(envelope.artifact_length(), original.len() as u64);
        assert_eq!(
            BootServiceImage::check_envelope(envelope, 7, &original)
                .unwrap()
                .image()
                .entry_rva(),
            PAGE_SIZE as u32
        );
        assert_eq!(
            BootServiceImage::check(staging, 7, &original).err(),
            Some(BootServiceImageError::LayoutMismatch)
        );
        assert_eq!(
            BootServiceImage::check_envelope(envelope, 8, &original).err(),
            Some(BootServiceImageError::ReleaseMismatch)
        );
        assert_eq!(
            BootServiceImage::check_envelope(envelope, 7, &original[1..]).err(),
            Some(BootServiceImageError::LayoutMismatch)
        );
        let mut changed = payload;
        changed[0x200] ^= 1;
        assert_eq!(
            BootServiceImage::check_envelope(
                envelope,
                7,
                &bundle(changed, ArtifactKind::ServiceImage, 7)
            )
            .err(),
            Some(BootServiceImageError::MeasurementMismatch)
        );
    }

    #[test]
    fn owner_selected_supervisor_stages_exact_pe_from_source() {
        let payload = crate::pe::tests::valid_pe();
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let expected = launch(&payload, 2, BASE + PAGE_SIZE);
        let checked = || BootServiceImage::check(expected, 7, &original).unwrap();
        let manifest = [0x12; 64];
        let selection =
            BootSupervisorSelection::new(7, manifest, Sha3_512::digest(&payload)).unwrap();
        let record = selection.encode();
        let pin = Sha3_512::digest(&record);
        assert_eq!(BootSupervisorSelection::decode(&record), Ok(selection));
        assert_eq!(
            selection.bind([0; 64], manifest, checked()).err(),
            Some(BootSupervisorError::NotOwnerSelected),
        );
        assert_eq!(
            selection.bind(pin, [0x13; 64], checked()).err(),
            Some(BootSupervisorError::WrongRelease),
        );
        let old = BootSupervisorSelection::new(6, manifest, Sha3_512::digest(&payload)).unwrap();
        assert_eq!(
            old.bind(Sha3_512::digest(&old.encode()), manifest, checked())
                .err(),
            Some(BootSupervisorError::WrongRelease),
        );
        let substitute = BootSupervisorSelection::new(7, manifest, [0x24; 64]).unwrap();
        assert_eq!(
            substitute.bind(pin, manifest, checked()).err(),
            Some(BootSupervisorError::NotOwnerSelected),
        );
        assert_eq!(
            substitute
                .bind(Sha3_512::digest(&substitute.encode()), manifest, checked())
                .err(),
            Some(BootSupervisorError::WrongService),
        );
        let selected = || selection.bind(pin, manifest, checked()).unwrap();
        assert_eq!(selected().image_size(), 8192);
        let mut short = [0xa5; 8191];
        assert_eq!(
            selected().stage(&mut short).err(),
            Some(BootSupervisorError::Image(PeError::InvalidDestination)),
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));
        let mut backing = [0xa5; 8192];
        let staged = selected().stage(&mut backing).unwrap();
        assert_eq!(staged.guest_image_base(), BASE);
        assert_eq!(staged.guest_entry(), BASE + PAGE_SIZE);
        assert_eq!(&staged.bytes()[4096..4608], &payload[0x200..0x400]);
        assert!(staged.bytes()[4608..].iter().all(|byte| *byte == 0));
        assert_eq!(staged.load_region_count(), 2);
        assert!(!staged.load_region(0).unwrap().executable());
        assert!(!staged.load_region(0).unwrap().writable());
        assert!(staged.load_region(1).unwrap().executable());
        assert!(!staged.load_region(1).unwrap().writable());
        assert_eq!(staged.load_region(2), Err(PeError::InvalidSection));
    }

    #[test]
    fn supervisor_selection_rejects_noncanonical_records() {
        let mut record = BootSupervisorSelection::new(7, [1; 64], [2; 64])
            .unwrap()
            .encode();
        assert_eq!(
            BootSupervisorSelection::decode(&record[..151]),
            Err(BootSupervisorError::InvalidSelection),
        );
        for (offset, width) in [(0, 16), (16, 8), (24, 64), (88, 64)] {
            let original = record;
            record[offset..offset + width].fill(0);
            assert_eq!(
                BootSupervisorSelection::decode(&record),
                Err(BootSupervisorError::InvalidSelection),
            );
            record = original;
        }
    }

    #[test]
    fn supervisor_guest_reservation_uses_free_pages_and_distinct_address_spaces() {
        use crate::{FrameAllocator, GuestAccess, MemoryKind, MemoryMap, MemoryRegion, VmError};
        let mut payload = crate::pe::tests::valid_pe();
        const OPTIONAL: usize = 0x98;
        const SECTION: usize = OPTIONAL + 240;
        payload[OPTIONAL + 16..OPTIONAL + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        payload[OPTIONAL + 56..OPTIONAL + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        payload[SECTION + 12..SECTION + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        payload[0x200] = 0x90;
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let expected = launch(&payload, 3, BASE + 2 * PAGE_SIZE);
        let manifest = [0x12; 64];
        let selection =
            BootSupervisorSelection::new(7, manifest, Sha3_512::digest(&payload)).unwrap();
        let selected = || {
            selection
                .bind(
                    Sha3_512::digest(&selection.encode()),
                    manifest,
                    BootServiceImage::check(expected, 7, &original).unwrap(),
                )
                .unwrap()
        };
        let region =
            |at, pages, kind| MemoryRegion::new(PhysAddr::new(at).unwrap(), pages, kind).unwrap();
        let regions = [
            region(0, 1, MemoryKind::Free),
            region(0x10000, 128, MemoryKind::Reserved),
            region(0x100000, 8, MemoryKind::Free),
        ];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        let gpa = 0x200000;
        for (start, bits) in [
            (0, 48),
            (gpa + 1, 48),
            ((1 << 48) - PAGE_SIZE, 48),
            (gpa, 53),
        ] {
            assert_eq!(
                selected()
                    .reserve_guest_image(&mut allocator, start, bits)
                    .err(),
                Some(BootSupervisorMemoryError::InvalidGuestAperture),
            );
        }
        let reserved = selected()
            .reserve_guest_image(&mut allocator, gpa, 48)
            .unwrap();
        assert_eq!(reserved.physical_base().get(), 0x100000);
        assert_eq!(reserved.guest_physical_base(), gpa);
        assert_eq!(reserved.guest_virtual_base(), BASE);
        assert_eq!(reserved.image_size(), 12288);
        assert_eq!(allocator.allocate().unwrap().get(), 0x103000);
        let layout = reserved.layout();
        let code = layout
            .prepare_range(gpa + 2 * PAGE_SIZE, 1, GuestAccess::Execute)
            .unwrap();
        assert_eq!(
            layout.region(code.mapping()).unwrap().host_start().get(),
            0x102000
        );
        assert_eq!(
            layout.prepare_range(gpa + 2 * PAGE_SIZE, 1, GuestAccess::Write),
            Err(VmError::PermissionDenied)
        );
        assert_eq!(
            layout.prepare_range(gpa, 1, GuestAccess::Execute),
            Err(VmError::PermissionDenied)
        );
        assert_eq!(
            layout.prepare_range(gpa, 1, GuestAccess::Write),
            Err(VmError::PermissionDenied)
        );
        assert_eq!(
            layout.prepare_range(gpa + PAGE_SIZE, 1, GuestAccess::Read),
            Err(VmError::Unmapped)
        );
        let mut backing = [0xa5; 12288];
        assert_eq!(
            reserved.initialize_nx_view(&mut backing),
            Ok(BASE + 2 * PAGE_SIZE)
        );
        assert_eq!(&backing[8192..8704], &payload[0x200..]);
        assert!(backing[4096..8192].iter().all(|&byte| byte == 0));
        assert!(backing[8704..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn supervisor_linear_tables_use_guest_addresses_and_guard_the_stack() {
        use crate::{FrameAllocator, MemoryKind, MemoryMap, MemoryRegion};
        const IMAGE_GPA: u64 = 0x200000;
        const STACK_GPA: u64 = 0x300000;
        const STACK_GVA: u64 = 0x2_0000_0000;
        const TABLE_GPA: u64 = 0x400000;
        let payload = crate::pe::tests::valid_pe();
        let envelope = bundle(payload, ArtifactKind::ServiceImage, 7);
        let metadata = launch(&payload, 2, BASE + PAGE_SIZE);
        let manifest = [0x38; 64];
        let selection = BootSupervisorSelection::new(7, manifest, metadata.measurement()).unwrap();
        let regions =
            [MemoryRegion::new(PhysAddr::new(0x800000).unwrap(), 40, MemoryKind::Free).unwrap()];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        let selected = || {
            selection
                .bind(
                    Sha3_512::digest(&selection.encode()),
                    manifest,
                    BootServiceImage::check(metadata, 7, &envelope).unwrap(),
                )
                .unwrap()
        };
        let image = selected()
            .reserve_guest_image(&mut allocator, IMAGE_GPA, 48)
            .unwrap();
        assert_eq!(
            image
                .reserve_guest_bootstrap(&mut allocator, BASE, STACK_GPA, 2, TABLE_GPA, 8)
                .err(),
            Some(SupervisorBootstrapError::InvalidLayout),
        );
        let image = selected()
            .reserve_guest_image(&mut allocator, IMAGE_GPA, 48)
            .unwrap();
        assert_eq!(
            image
                .reserve_guest_bootstrap(&mut allocator, STACK_GVA, STACK_GPA, 2, STACK_GPA, 8)
                .err(),
            Some(SupervisorBootstrapError::InvalidLayout),
        );
        let image = selected()
            .reserve_guest_image(&mut allocator, IMAGE_GPA, 48)
            .unwrap();
        let guest = image
            .reserve_guest_bootstrap(&mut allocator, STACK_GVA, STACK_GPA, 2, TABLE_GPA, 8)
            .unwrap();
        assert_eq!(guest.stack_region().guest_start(), STACK_GPA + PAGE_SIZE);
        assert_ne!(guest.table_region().host_start().get(), TABLE_GPA);
        let mut stack = [0xa5; 8192];
        let mut tables = [[u64::MAX; 512]; 8];
        assert_eq!(
            guest.initialize_linear(&mut tables[..7], &mut stack),
            Err(SupervisorBootstrapError::InvalidView)
        );
        assert!(stack.iter().all(|&b| b == 0xa5));
        assert_eq!(tables[0][0], u64::MAX);
        let state = guest.initialize_linear(&mut tables, &mut stack).unwrap();
        assert_eq!(state.guest_cr3.get(), TABLE_GPA);
        assert_eq!(state.guest_stack_top, STACK_GVA + PAGE_SIZE * 3);
        assert!(stack.iter().all(|&b| b == 0));
        assert_eq!(tables[7], [0; 512]);
        let mask = 0x000f_ffff_ffff_f000;
        let lookup = |gva: u64| {
            let mut table = state.guest_cr3.get();
            for shift in [39, 30, 21, 12] {
                let index = ((gva >> shift) & 511) as usize;
                let entry = tables[((table - TABLE_GPA) / PAGE_SIZE) as usize][index];
                if entry == 0 || shift == 12 {
                    return entry;
                }
                table = entry & mask;
            }
            unreachable!()
        };
        let nx = 1 << 63;
        assert_eq!(lookup(BASE), IMAGE_GPA | nx | 1);
        assert_eq!(lookup(BASE + PAGE_SIZE), (IMAGE_GPA + PAGE_SIZE) | 1);
        assert_eq!(lookup(STACK_GVA), 0);
        assert_eq!(
            lookup(STACK_GVA + PAGE_SIZE),
            (STACK_GPA + PAGE_SIZE) | nx | 3
        );
        assert_eq!(lookup(STACK_GVA + PAGE_SIZE * 3), 0);
        assert_eq!(lookup(TABLE_GPA), 0);
    }
}
