use super::{ActivePageTables, UserBufferAccess, UserBufferError};
use crate::{
    MAX_SHARED_BUFFER_SYSCALL_BYTES, PhysAddr, SharedBufferUserAccess, SharedBufferUserCopy, TaskId,
};

trait ActiveUserRangeResolver {
    fn resolve(
        &self,
        expected_root: PhysAddr,
        address: u64,
        length: usize,
        access: UserBufferAccess,
    ) -> Result<(), UserBufferError>;
}

impl ActiveUserRangeResolver for ActivePageTables {
    fn resolve(
        &self,
        expected_root: PhysAddr,
        address: u64,
        length: usize,
        access: UserBufferAccess,
    ) -> Result<(), UserBufferError> {
        self.resolve_user_buffer(
            expected_root,
            address,
            length,
            MAX_SHARED_BUFFER_SYSCALL_BYTES,
            access,
        )
        .map(|_| ())
    }
}

/// Copies bytes through the currently active userspace virtual mapping.
///
/// # Safety
///
/// Implementations must copy the complete exact range or return an error and
/// must not switch address spaces, redirect the address, or permit page-table
/// mutation between resolver validation and the corresponding copy.
pub unsafe trait ActiveUserMemory {
    type Error;

    /// # Safety
    ///
    /// `address..address + output.len()` must be the exact active readable
    /// range authorized by a still-live validation ticket.
    unsafe fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), Self::Error>;

    /// # Safety
    ///
    /// `address..address + input.len()` must be the exact active writable
    /// range authorized by a still-live validation ticket.
    unsafe fn write(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error>;
}

pub struct DirectActiveUserMemory;

unsafe impl ActiveUserMemory for DirectActiveUserMemory {
    type Error = core::convert::Infallible;

    unsafe fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        unsafe {
            core::ptr::copy_nonoverlapping(address as *const u8, output.as_mut_ptr(), output.len())
        };
        Ok(())
    }

    unsafe fn write(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), address as *mut u8, input.len()) };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveTaskUserCopyError<E> {
    WrongTask,
    PendingValidation,
    TicketMismatch,
    Buffer(UserBufferError),
    Memory(E),
}

#[derive(Clone, Copy)]
struct Ticket {
    task: TaskId,
    address: u64,
    length: usize,
    access: SharedBufferUserAccess,
}

pub struct ActiveTaskUserCopy<'a, M> {
    active: &'a ActivePageTables,
    expected_root: PhysAddr,
    expected_task: TaskId,
    memory: M,
    ticket: Option<Ticket>,
}

impl<'a, M> ActiveTaskUserCopy<'a, M> {
    pub const fn new(
        active: &'a ActivePageTables,
        expected_root: PhysAddr,
        expected_task: TaskId,
        memory: M,
    ) -> Self {
        Self {
            active,
            expected_root,
            expected_task,
            memory,
            ticket: None,
        }
    }

    pub fn into_memory(self) -> M {
        self.memory
    }
}

unsafe impl<M: ActiveUserMemory> SharedBufferUserCopy for ActiveTaskUserCopy<'_, M> {
    type Error = ActiveTaskUserCopyError<M::Error>;

    fn validate(
        &mut self,
        task: TaskId,
        address: u64,
        length: usize,
        access: SharedBufferUserAccess,
    ) -> Result<(), Self::Error> {
        if task != self.expected_task {
            return Err(ActiveTaskUserCopyError::WrongTask);
        }
        if self.ticket.is_some() {
            return Err(ActiveTaskUserCopyError::PendingValidation);
        }
        let page_access = match access {
            SharedBufferUserAccess::Read => UserBufferAccess::Read,
            SharedBufferUserAccess::Write => UserBufferAccess::Write,
        };
        self.active
            .resolve(self.expected_root, address, length, page_access)
            .map_err(ActiveTaskUserCopyError::Buffer)?;
        self.ticket = Some(Ticket {
            task,
            address,
            length,
            access,
        });
        Ok(())
    }

    fn read(&mut self, task: TaskId, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.consume(task, address, output.len(), SharedBufferUserAccess::Read)?;
        unsafe { self.memory.read(address, output) }.map_err(ActiveTaskUserCopyError::Memory)
    }

    fn write(&mut self, task: TaskId, address: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.consume(task, address, input.len(), SharedBufferUserAccess::Write)?;
        unsafe { self.memory.write(address, input) }.map_err(ActiveTaskUserCopyError::Memory)
    }

    fn cancel(&mut self) {
        self.ticket = None;
    }
}

impl<M: ActiveUserMemory> ActiveTaskUserCopy<'_, M> {
    fn consume(
        &mut self,
        task: TaskId,
        address: u64,
        length: usize,
        access: SharedBufferUserAccess,
    ) -> Result<(), ActiveTaskUserCopyError<M::Error>> {
        consume_ticket(&mut self.ticket, task, address, length, access)
    }
}

fn consume_ticket<E>(
    ticket: &mut Option<Ticket>,
    task: TaskId,
    address: u64,
    length: usize,
    access: SharedBufferUserAccess,
) -> Result<(), ActiveTaskUserCopyError<E>> {
    let ticket = ticket
        .take()
        .ok_or(ActiveTaskUserCopyError::TicketMismatch)?;
    if ticket.task != task
        || ticket.address != address
        || ticket.length != length
        || ticket.access != access
    {
        return Err(ActiveTaskUserCopyError::TicketMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KernelScheduler, Priority};

    fn tasks() -> (TaskId, TaskId) {
        let mut scheduler = KernelScheduler::<2>::new(1_000, 1).unwrap();
        (
            scheduler.create(Priority::NORMAL).unwrap(),
            scheduler.create(Priority::NORMAL).unwrap(),
        )
    }

    #[test]
    fn validation_ticket_is_exact_directional_and_single_use() {
        let (task, other) = tasks();
        for (candidate_task, address, length, access) in [
            (other, 0x6000, 8, SharedBufferUserAccess::Read),
            (task, 0x6001, 8, SharedBufferUserAccess::Read),
            (task, 0x6000, 7, SharedBufferUserAccess::Read),
            (task, 0x6000, 8, SharedBufferUserAccess::Write),
        ] {
            let mut ticket = Some(Ticket {
                task,
                address: 0x6000,
                length: 8,
                access: SharedBufferUserAccess::Read,
            });
            assert_eq!(
                consume_ticket::<()>(&mut ticket, candidate_task, address, length, access,),
                Err(ActiveTaskUserCopyError::TicketMismatch)
            );
            assert!(ticket.is_none());
        }
        let mut ticket = Some(Ticket {
            task,
            address: 0x6000,
            length: 8,
            access: SharedBufferUserAccess::Read,
        });
        assert_eq!(
            consume_ticket::<()>(&mut ticket, task, 0x6000, 8, SharedBufferUserAccess::Read,),
            Ok(())
        );
        assert_eq!(
            consume_ticket::<()>(&mut ticket, task, 0x6000, 8, SharedBufferUserAccess::Read,),
            Err(ActiveTaskUserCopyError::TicketMismatch)
        );
    }

    #[test]
    fn direct_active_copy_transfers_the_exact_validated_bytes() {
        let mut source = [1u8, 2, 3, 4];
        let mut output = [0u8; 4];
        let mut memory = DirectActiveUserMemory;
        unsafe { memory.read(source.as_ptr() as u64, &mut output) }.unwrap();
        assert_eq!(output, source);
        unsafe { memory.write(source.as_mut_ptr() as u64, &[5, 6, 7, 8]) }.unwrap();
        assert_eq!(source, [5, 6, 7, 8]);
    }
}
