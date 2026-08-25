use core::ptr;

use crate::{HostResourceHandle, HostResourceRetirer, IpcSharedBufferBackend};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostResourceTableError {
    InvalidResource,
    InvalidLength,
    DuplicateResource,
    Full,
    SequenceExhausted,
    StaleHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostResourceIoError<E> {
    Empty,
    OutOfRange,
    StaleHandle,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostResourceRetireError<E> {
    StaleHandle,
    Backend(E),
}

/// Accesses a kernel-owned resource token without exposing its representation.
///
/// # Safety
///
/// Implementations must complete exactly the requested transfer or fail. They
/// must not redirect a resource token, access outside the requested range, or
/// report success after a short or indeterminate transfer.
pub unsafe trait HostResourceMemory {
    type Error;

    /// Copies one exact range from the selected resource.
    ///
    /// # Safety
    ///
    /// The caller must prove that the registered resource is live and that
    /// the requested range lies within its declared extent.
    unsafe fn read(
        &mut self,
        resource: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Copies one exact range into the selected resource.
    ///
    /// # Safety
    ///
    /// The caller must prove that the registered resource is live and that
    /// the requested range lies within its declared extent.
    unsafe fn write(&mut self, resource: u64, offset: u64, input: &[u8])
    -> Result<(), Self::Error>;

    /// Retires a resource after its final authorized reference.
    ///
    /// # Safety
    ///
    /// No live entry or operation may still use the resource. Failure must
    /// leave retirement retryable.
    unsafe fn retire(&mut self, resource: u64, bytes: u64) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectHostResourceError {
    AddressOverflow,
}

/// A supervisor-only adapter for resources represented by virtual addresses.
pub struct DirectHostResourceMemory;

impl DirectHostResourceMemory {
    fn address(
        resource: u64,
        offset: u64,
        length: usize,
    ) -> Result<usize, DirectHostResourceError> {
        let address = resource
            .checked_add(offset)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(DirectHostResourceError::AddressOverflow)?;
        if length > isize::MAX as usize || address.checked_add(length).is_none() {
            return Err(DirectHostResourceError::AddressOverflow);
        }
        Ok(address)
    }
}

// SAFETY: the caller must register only live supervisor-owned address ranges;
// this adapter checks address arithmetic and performs exact copies.
unsafe impl HostResourceMemory for DirectHostResourceMemory {
    type Error = DirectHostResourceError;

    unsafe fn read(
        &mut self,
        resource: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let address = Self::address(resource, offset, output.len())?;
        // SAFETY: required by the trait caller; arithmetic was checked above.
        unsafe {
            ptr::copy_nonoverlapping(address as *const u8, output.as_mut_ptr(), output.len())
        };
        Ok(())
    }

    unsafe fn write(
        &mut self,
        resource: u64,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let address = Self::address(resource, offset, input.len())?;
        // SAFETY: required by the trait caller; arithmetic was checked above.
        unsafe { ptr::copy_nonoverlapping(input.as_ptr(), address as *mut u8, input.len()) };
        Ok(())
    }

    unsafe fn retire(&mut self, _resource: u64, _bytes: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct HostResourceEntry {
    handle: HostResourceHandle,
    resource: u64,
    bytes: u64,
}

/// Fixed-capacity ownership table for opaque host resources.
pub struct HostResourceTable<M, const N: usize> {
    memory: M,
    entries: [Option<HostResourceEntry>; N],
    next_handle: u64,
}

impl<M, const N: usize> HostResourceTable<M, N> {
    pub const fn new(memory: M) -> Self {
        Self {
            memory,
            entries: [None; N],
            next_handle: 1,
        }
    }

    /// Registers a supervisor-owned resource and returns a fresh opaque handle.
    ///
    /// # Safety
    ///
    /// `resource..resource + bytes` must remain live and exclusively governed
    /// by this entry until its handle is removed. For address-backed adapters,
    /// the range must be valid for reads and writes for that entire lifetime.
    pub unsafe fn register(
        &mut self,
        resource: u64,
        bytes: u64,
    ) -> Result<HostResourceHandle, HostResourceTableError> {
        if resource == 0 {
            return Err(HostResourceTableError::InvalidResource);
        }
        if bytes == 0 {
            return Err(HostResourceTableError::InvalidLength);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.resource == resource)
        {
            return Err(HostResourceTableError::DuplicateResource);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(HostResourceTableError::Full)?;
        let next = self
            .next_handle
            .checked_add(1)
            .ok_or(HostResourceTableError::SequenceExhausted)?;
        let handle = HostResourceHandle::new(self.next_handle)
            .map_err(|_| HostResourceTableError::SequenceExhausted)?;
        *slot = Some(HostResourceEntry {
            handle,
            resource,
            bytes,
        });
        self.next_handle = next;
        Ok(handle)
    }

    pub fn remove(
        &mut self,
        handle: HostResourceHandle,
    ) -> Result<(), HostResourceRetireError<M::Error>>
    where
        M: HostResourceMemory,
    {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.handle == handle))
            .ok_or(HostResourceRetireError::StaleHandle)?;
        let entry = self.entries[index].ok_or(HostResourceRetireError::StaleHandle)?;
        // SAFETY: this exact entry remains live during the attempt and is
        // removed only after the backend confirms retirement.
        unsafe { self.memory.retire(entry.resource, entry.bytes) }
            .map_err(HostResourceRetireError::Backend)?;
        self.entries[index] = None;
        Ok(())
    }

    pub const fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    fn resolve(
        &self,
        handle: HostResourceHandle,
        offset: u64,
        length: usize,
    ) -> Result<(u64, u64), HostResourceIoError<M::Error>>
    where
        M: HostResourceMemory,
    {
        if length == 0 {
            return Err(HostResourceIoError::Empty);
        }
        let entry = self
            .entries
            .iter()
            .flatten()
            .find(|entry| entry.handle == handle)
            .ok_or(HostResourceIoError::StaleHandle)?;
        let length = u64::try_from(length).map_err(|_| HostResourceIoError::OutOfRange)?;
        let end = offset
            .checked_add(length)
            .ok_or(HostResourceIoError::OutOfRange)?;
        if end > entry.bytes {
            return Err(HostResourceIoError::OutOfRange);
        }
        Ok((entry.resource, offset))
    }
}

impl<M: HostResourceMemory, const N: usize> HostResourceRetirer for HostResourceTable<M, N> {
    type Error = HostResourceRetireError<M::Error>;

    fn retire(&mut self, handle: HostResourceHandle) -> Result<(), Self::Error> {
        self.remove(handle)
    }
}

// SAFETY: handles are table-issued, live entries cannot alias a resource, all
// requests are independently bounded, and backend uncertainty is propagated.
unsafe impl<M: HostResourceMemory, const N: usize> IpcSharedBufferBackend
    for HostResourceTable<M, N>
{
    type Error = HostResourceIoError<M::Error>;

    fn read(
        &mut self,
        handle: HostResourceHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let (resource, offset) = self.resolve(handle, offset, output.len())?;
        // SAFETY: registration establishes the resource lifetime and resolve
        // proves that this exact request lies within its declared extent.
        unsafe { self.memory.read(resource, offset, output) }.map_err(HostResourceIoError::Backend)
    }

    fn write(
        &mut self,
        handle: HostResourceHandle,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let (resource, offset) = self.resolve(handle, offset, input.len())?;
        // SAFETY: registration establishes the resource lifetime and resolve
        // proves that this exact request lies within its declared extent.
        unsafe { self.memory.write(resource, offset, input) }.map_err(HostResourceIoError::Backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryError {
        Failed,
    }

    struct TestMemory {
        bytes: [u8; 16],
        calls: usize,
        fail: bool,
    }

    unsafe impl HostResourceMemory for TestMemory {
        type Error = MemoryError;

        unsafe fn read(
            &mut self,
            _resource: u64,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail {
                return Err(MemoryError::Failed);
            }
            let start = usize::try_from(offset).unwrap();
            output.copy_from_slice(&self.bytes[start..start + output.len()]);
            Ok(())
        }

        unsafe fn write(
            &mut self,
            _resource: u64,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail {
                return Err(MemoryError::Failed);
            }
            let start = usize::try_from(offset).unwrap();
            self.bytes[start..start + input.len()].copy_from_slice(input);
            Ok(())
        }

        unsafe fn retire(&mut self, _resource: u64, _bytes: u64) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail {
                Err(MemoryError::Failed)
            } else {
                Ok(())
            }
        }
    }

    fn table<const N: usize>() -> HostResourceTable<TestMemory, N> {
        HostResourceTable::new(TestMemory {
            bytes: [0; 16],
            calls: 0,
            fail: false,
        })
    }

    #[test]
    fn table_bounds_io_before_backend_access() {
        let mut table = table::<1>();
        // SAFETY: the test backend treats the token as an opaque identifier.
        let handle = unsafe { table.register(0x1000, 8) }.unwrap();
        assert_eq!(table.write(handle, 2, &[1, 2, 3]), Ok(()));
        let mut output = [0; 3];
        assert_eq!(table.read(handle, 2, &mut output), Ok(()));
        assert_eq!(output, [1, 2, 3]);
        assert_eq!(table.memory().calls, 2);
        assert_eq!(table.write(handle, 0, &[]), Err(HostResourceIoError::Empty));
        assert_eq!(
            table.write(handle, 7, &[1, 2]),
            Err(HostResourceIoError::OutOfRange)
        );
        assert_eq!(table.memory().calls, 2);
    }

    #[test]
    fn removal_stales_handles_and_reregistration_never_reuses_them() {
        let mut table = table::<1>();
        // SAFETY: the test backend treats the token as an opaque identifier.
        let old = unsafe { table.register(0x2000, 8) }.unwrap();
        assert_eq!(table.remove(old), Ok(()));
        assert_eq!(
            table.write(old, 0, &[1]),
            Err(HostResourceIoError::StaleHandle)
        );
        // SAFETY: the prior entry was removed and the test token is opaque.
        let new = unsafe { table.register(0x2000, 8) }.unwrap();
        assert_ne!(old, new);
        assert_eq!(
            table.write(old, 0, &[1]),
            Err(HostResourceIoError::StaleHandle)
        );
        assert_eq!(table.write(new, 0, &[1]), Ok(()));
    }

    #[test]
    fn registration_rejects_aliases_invalid_entries_and_capacity() {
        let mut table = table::<1>();
        assert_eq!(
            unsafe { table.register(0, 1) },
            Err(HostResourceTableError::InvalidResource)
        );
        assert_eq!(
            unsafe { table.register(1, 0) },
            Err(HostResourceTableError::InvalidLength)
        );
        let handle = unsafe { table.register(1, 1) }.unwrap();
        assert_eq!(
            unsafe { table.register(1, 1) },
            Err(HostResourceTableError::DuplicateResource)
        );
        assert_eq!(
            unsafe { table.register(2, 1) },
            Err(HostResourceTableError::Full)
        );
        assert_eq!(table.retire(handle), Ok(()));
    }

    #[test]
    fn backend_uncertainty_is_preserved() {
        let mut table = table::<1>();
        let handle = unsafe { table.register(1, 8) }.unwrap();
        table.memory_mut().fail = true;
        assert_eq!(
            table.write(handle, 0, &[1]),
            Err(HostResourceIoError::Backend(MemoryError::Failed))
        );
    }

    #[test]
    fn uncertain_retirement_keeps_the_handle_retryable() {
        let mut table = table::<1>();
        let handle = unsafe { table.register(1, 8) }.unwrap();
        table.memory_mut().fail = true;
        assert_eq!(
            table.remove(handle),
            Err(HostResourceRetireError::Backend(MemoryError::Failed))
        );
        table.memory_mut().fail = false;
        assert_eq!(table.write(handle, 0, &[1]), Ok(()));
        assert_eq!(table.remove(handle), Ok(()));
        assert_eq!(
            table.write(handle, 0, &[1]),
            Err(HostResourceIoError::StaleHandle)
        );
    }

    #[test]
    fn direct_memory_adapter_copies_exact_ranges() {
        let mut source = [1_u8, 2, 3, 4];
        let resource = source.as_mut_ptr() as usize as u64;
        let mut memory = DirectHostResourceMemory;
        let mut output = [0; 2];
        // SAFETY: source is live and both requested ranges are in bounds.
        unsafe { memory.read(resource, 1, &mut output) }.unwrap();
        assert_eq!(output, [2, 3]);
        // SAFETY: source is live and both requested ranges are in bounds.
        unsafe { memory.write(resource, 2, &[8, 9]) }.unwrap();
        assert_eq!(source, [1, 2, 8, 9]);
    }
}
