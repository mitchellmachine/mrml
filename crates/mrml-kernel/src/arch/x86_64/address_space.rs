use core::array;

use super::{MAX_PHYSICAL_ADDRESS, PagePermissions, VirtAddr};
use crate::{PAGE_SIZE, PhysAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceError {
    Empty,
    Overflow,
    CrossesCanonicalBoundary,
    WrongPrivilegeHalf,
    VirtualOverlap,
    PhysicalAlias,
    Full,
    InvalidMapping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserBufferError {
    Empty,
    TooLarge,
    Overflow,
    Unmapped,
    AccessDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserBufferAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBuffer {
    virtual_address: u64,
    physical_address: u64,
    length: usize,
}

pub trait UserMemory {
    type Error;

    fn copy_from_user(
        &mut self,
        physical_address: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
    fn copy_to_user(&mut self, physical_address: u64, input: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserCopyError<E> {
    Buffer(UserBufferError),
    Memory(E),
}

impl UserBuffer {
    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }

    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    pub const fn length(self) -> usize {
        self.length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    virtual_start: VirtAddr,
    physical_start: PhysAddr,
    pages: u64,
    permissions: PagePermissions,
}

impl Mapping {
    pub fn new(
        virtual_start: VirtAddr,
        physical_start: PhysAddr,
        pages: u64,
        permissions: PagePermissions,
    ) -> Result<Self, AddressSpaceError> {
        if pages == 0 {
            return Err(AddressSpaceError::Empty);
        }
        let length = pages
            .checked_mul(PAGE_SIZE)
            .ok_or(AddressSpaceError::Overflow)?;
        virtual_start
            .get()
            .checked_add(length)
            .ok_or(AddressSpaceError::Overflow)?;
        physical_start
            .get()
            .checked_add(length)
            .ok_or(AddressSpaceError::Overflow)?;
        let virtual_last = virtual_start
            .get()
            .checked_add(length - PAGE_SIZE)
            .ok_or(AddressSpaceError::Overflow)?;
        let virtual_last =
            VirtAddr::new(virtual_last).map_err(|_| AddressSpaceError::CrossesCanonicalBoundary)?;
        let physical_last = physical_start
            .get()
            .checked_add(length - PAGE_SIZE)
            .ok_or(AddressSpaceError::Overflow)?;
        if physical_last > MAX_PHYSICAL_ADDRESS {
            return Err(AddressSpaceError::Overflow);
        }
        let user_half = virtual_start.get() < 1u64 << 47 && virtual_last.get() < 1u64 << 47;
        let kernel_half = virtual_start.get() >= 0xffff_8000_0000_0000
            && virtual_last.get() >= 0xffff_8000_0000_0000;
        if (permissions.user() && !user_half)
            || (!permissions.user() && !permissions.low_supervisor_mmio() && !kernel_half)
            || (permissions.low_supervisor_mmio() && !user_half)
        {
            return Err(AddressSpaceError::WrongPrivilegeHalf);
        }
        Ok(Self {
            virtual_start,
            physical_start,
            pages,
            permissions,
        })
    }

    pub const fn virtual_start(self) -> VirtAddr {
        self.virtual_start
    }
    pub const fn physical_start(self) -> PhysAddr {
        self.physical_start
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
    pub const fn permissions(self) -> PagePermissions {
        self.permissions
    }
    fn virtual_end(self) -> u64 {
        self.virtual_start.get() + self.pages * PAGE_SIZE
    }
    fn physical_end(self) -> u64 {
        self.physical_start.get() + self.pages * PAGE_SIZE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingId {
    slot: u32,
    generation: u32,
}

#[derive(Clone, Copy)]
struct Slot {
    mapping: Option<Mapping>,
    generation: u32,
}

impl Slot {
    const EMPTY: Self = Self {
        mapping: None,
        generation: 1,
    };
}

/// Fixed-capacity mapping policy. Physical aliasing is prohibited entirely so
/// a frame cannot be made executable through one virtual address and writable
/// through another.
pub struct AddressSpace<const MAPPINGS: usize> {
    slots: [Slot; MAPPINGS],
}

impl<const MAPPINGS: usize> AddressSpace<MAPPINGS> {
    pub fn new() -> Self {
        Self {
            slots: array::from_fn(|_| Slot::EMPTY),
        }
    }

    pub fn map(&mut self, mapping: Mapping) -> Result<MappingId, AddressSpaceError> {
        for existing in self.slots.iter().filter_map(|slot| slot.mapping) {
            if overlaps(
                mapping.virtual_start.get(),
                mapping.virtual_end(),
                existing.virtual_start.get(),
                existing.virtual_end(),
            ) {
                return Err(AddressSpaceError::VirtualOverlap);
            }
            if overlaps(
                mapping.physical_start.get(),
                mapping.physical_end(),
                existing.physical_start.get(),
                existing.physical_end(),
            ) {
                return Err(AddressSpaceError::PhysicalAlias);
            }
        }
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.mapping.is_none() && slot.generation != 0)
            .ok_or(AddressSpaceError::Full)?;
        slot.mapping = Some(mapping);
        Ok(MappingId {
            slot: index as u32,
            generation: slot.generation,
        })
    }

    pub fn get(&self, id: MappingId) -> Result<Mapping, AddressSpaceError> {
        self.slots
            .get(id.slot as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.mapping)
            .ok_or(AddressSpaceError::InvalidMapping)
    }

    pub fn unmap(&mut self, id: MappingId) -> Result<Mapping, AddressSpaceError> {
        let slot = self
            .slots
            .get_mut(id.slot as usize)
            .filter(|slot| slot.generation == id.generation && slot.mapping.is_some())
            .ok_or(AddressSpaceError::InvalidMapping)?;
        let mapping = slot
            .mapping
            .take()
            .ok_or(AddressSpaceError::InvalidMapping)?;
        slot.generation = slot.generation.checked_add(1).unwrap_or(0);
        Ok(mapping)
    }

    pub fn mappings(&self) -> impl Iterator<Item = Mapping> + '_ {
        self.slots.iter().filter_map(|slot| slot.mapping)
    }

    /// Resolves a complete user buffer against one live mapping. Callers may
    /// copy only after this succeeds and only in the requested direction.
    /// Crossing mappings is rejected even when both leaves happen to be live,
    /// keeping validation and the subsequent bounded copy one indivisible
    /// mapping-lifetime decision.
    pub fn resolve_user_buffer(
        &self,
        virtual_address: u64,
        length: usize,
        maximum_length: usize,
        access: UserBufferAccess,
    ) -> Result<UserBuffer, UserBufferError> {
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
        let mapping = self
            .mappings()
            .find(|mapping| {
                mapping.permissions().user()
                    && virtual_address >= mapping.virtual_start().get()
                    && end <= mapping.virtual_end()
            })
            .ok_or(UserBufferError::Unmapped)?;
        if access == UserBufferAccess::Write && !mapping.permissions().writable() {
            return Err(UserBufferError::AccessDenied);
        }
        let offset = virtual_address - mapping.virtual_start().get();
        let physical_address = mapping
            .physical_start()
            .get()
            .checked_add(offset)
            .ok_or(UserBufferError::Overflow)?;
        Ok(UserBuffer {
            virtual_address,
            physical_address,
            length,
        })
    }

    pub fn copy_from_user<M: UserMemory>(
        &self,
        memory: &mut M,
        virtual_address: u64,
        output: &mut [u8],
        maximum_length: usize,
    ) -> Result<(), UserCopyError<M::Error>> {
        let buffer = self
            .resolve_user_buffer(
                virtual_address,
                output.len(),
                maximum_length,
                UserBufferAccess::Read,
            )
            .map_err(UserCopyError::Buffer)?;
        memory
            .copy_from_user(buffer.physical_address(), output)
            .map_err(UserCopyError::Memory)
    }

    pub fn copy_to_user<M: UserMemory>(
        &self,
        memory: &mut M,
        virtual_address: u64,
        input: &[u8],
        maximum_length: usize,
    ) -> Result<(), UserCopyError<M::Error>> {
        let buffer = self
            .resolve_user_buffer(
                virtual_address,
                input.len(),
                maximum_length,
                UserBufferAccess::Write,
            )
            .map_err(UserCopyError::Buffer)?;
        memory
            .copy_to_user(buffer.physical_address(), input)
            .map_err(UserCopyError::Memory)
    }
}

impl<const MAPPINGS: usize> Default for AddressSpace<MAPPINGS> {
    fn default() -> Self {
        Self::new()
    }
}

const fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestMemory {
        calls: usize,
        address: u64,
        bytes: [u8; 32],
    }

    impl UserMemory for TestMemory {
        type Error = ();

        fn copy_from_user(
            &mut self,
            physical_address: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            self.address = physical_address;
            output.copy_from_slice(&self.bytes[..output.len()]);
            Ok(())
        }

        fn copy_to_user(&mut self, physical_address: u64, input: &[u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            self.address = physical_address;
            self.bytes[..input.len()].copy_from_slice(input);
            Ok(())
        }
    }

    fn user_mapping(virtual_address: u64, physical_address: u64) -> Mapping {
        Mapping::new(
            VirtAddr::new(virtual_address).unwrap(),
            PhysAddr::new(physical_address).unwrap(),
            1,
            PagePermissions::USER_READ_WRITE,
        )
        .unwrap()
    }

    #[test]
    fn user_pages_are_confined_but_supervisor_mmio_may_be_low() {
        assert_eq!(
            Mapping::new(
                VirtAddr::new(0xffff_8000_0000_0000).unwrap(),
                PhysAddr::new(0).unwrap(),
                1,
                PagePermissions::USER_READ,
            ),
            Err(AddressSpaceError::WrongPrivilegeHalf)
        );
        assert!(
            Mapping::new(
                VirtAddr::new(0x4000).unwrap(),
                PhysAddr::new(0).unwrap(),
                1,
                PagePermissions::KERNEL_MMIO_READ_WRITE,
            )
            .is_ok()
        );
        assert_eq!(
            Mapping::new(
                VirtAddr::new(0x5000).unwrap(),
                PhysAddr::new(0x1000).unwrap(),
                1,
                PagePermissions::KERNEL_READ_WRITE,
            ),
            Err(AddressSpaceError::WrongPrivilegeHalf)
        );
    }

    #[test]
    fn rejects_virtual_overlap_and_physical_aliases() {
        let mut space = AddressSpace::<3>::new();
        space.map(user_mapping(0x1000, 0x1000)).unwrap();
        assert_eq!(
            space.map(user_mapping(0x1000, 0x2000)),
            Err(AddressSpaceError::VirtualOverlap)
        );
        assert_eq!(
            space.map(user_mapping(0x2000, 0x1000)),
            Err(AddressSpaceError::PhysicalAlias)
        );
    }

    #[test]
    fn stale_mapping_ids_cannot_unmap_reused_slots() {
        let mut space = AddressSpace::<1>::new();
        let old = space.map(user_mapping(0x1000, 0x1000)).unwrap();
        space.unmap(old).unwrap();
        let replacement = space.map(user_mapping(0x2000, 0x2000)).unwrap();
        assert_ne!(old, replacement);
        assert_eq!(space.unmap(old), Err(AddressSpaceError::InvalidMapping));
        assert_eq!(
            space.get(replacement).unwrap().virtual_start().get(),
            0x2000
        );
    }

    #[test]
    fn user_buffer_resolution_binds_complete_range_access_and_translation() {
        let mut space = AddressSpace::<2>::new();
        space
            .map(
                Mapping::new(
                    VirtAddr::new(0x4000).unwrap(),
                    PhysAddr::new(0x20_0000).unwrap(),
                    2,
                    PagePermissions::USER_READ_WRITE,
                )
                .unwrap(),
            )
            .unwrap();
        let buffer = space
            .resolve_user_buffer(0x4ff0, 32, 368, UserBufferAccess::Write)
            .unwrap();
        assert_eq!(buffer.virtual_address(), 0x4ff0);
        assert_eq!(buffer.physical_address(), 0x20_0ff0);
        assert_eq!(buffer.length(), 32);
        assert_eq!(
            space.resolve_user_buffer(0x4ff0, 369, 368, UserBufferAccess::Read),
            Err(UserBufferError::TooLarge)
        );
        assert_eq!(
            space.resolve_user_buffer(0x5ff0, 32, 368, UserBufferAccess::Read),
            Err(UserBufferError::Unmapped)
        );
    }

    #[test]
    fn user_buffer_resolution_rejects_empty_overflow_and_read_only_output() {
        let mut space = AddressSpace::<1>::new();
        space
            .map(
                Mapping::new(
                    VirtAddr::new(0x8000).unwrap(),
                    PhysAddr::new(0x30_0000).unwrap(),
                    1,
                    PagePermissions::USER_READ,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            space.resolve_user_buffer(0x8000, 0, 64, UserBufferAccess::Read),
            Err(UserBufferError::Empty)
        );
        assert_eq!(
            space.resolve_user_buffer(0, 1, 64, UserBufferAccess::Read),
            Err(UserBufferError::Overflow)
        );
        assert_eq!(
            space.resolve_user_buffer(0x8000, 1, 64, UserBufferAccess::Write),
            Err(UserBufferError::AccessDenied)
        );
        assert_eq!(
            space.resolve_user_buffer(u64::MAX, 2, 64, UserBufferAccess::Read),
            Err(UserBufferError::Overflow)
        );
    }

    #[test]
    fn user_copy_never_touches_memory_before_complete_validation() {
        let mut space = AddressSpace::<1>::new();
        space.map(user_mapping(0x4000, 0x10_0000)).unwrap();
        let mut memory = TestMemory::default();
        memory.bytes[..4].copy_from_slice(b"ping");
        let mut output = [0; 4];
        space
            .copy_from_user(&mut memory, 0x4010, &mut output, 16)
            .unwrap();
        assert_eq!(output, *b"ping");
        assert_eq!(memory.address, 0x10_0010);
        space
            .copy_to_user(&mut memory, 0x4020, b"pong", 16)
            .unwrap();
        assert_eq!(&memory.bytes[..4], b"pong");
        assert_eq!(memory.address, 0x10_0020);
        assert_eq!(memory.calls, 2);
        assert_eq!(
            space.copy_from_user(&mut memory, 0x4fff, &mut output, 16),
            Err(UserCopyError::Buffer(UserBufferError::Unmapped))
        );
        assert_eq!(memory.calls, 2);
    }
}
