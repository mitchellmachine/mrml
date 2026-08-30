use core::array;

use crate::{
    BlockedReceive, DeadlineReceive, Message, ReceiveDeadlineTick, ReceiveTimeout, ScheduleOutcome,
    TaskId, TaskRuntime, TaskRuntimeError,
};

#[must_use = "deadline receive admission must be completed or retained"]
pub enum DeadlineReceiveStart {
    Ready(Message),
    TimedOut,
    Blocked(ScheduleOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineReceiveSyscallError {
    Runtime(TaskRuntimeError),
    OwnerFull,
    OwnerMismatch,
}

pub struct DeadlineReceiveSyscallExecutor<const TASKS: usize> {
    owners: [Option<BlockedReceive>; TASKS],
}

impl<const TASKS: usize> DeadlineReceiveSyscallExecutor<TASKS> {
    pub fn new() -> Self {
        Self {
            owners: array::from_fn(|_| None),
        }
    }

    pub fn start<const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        timeout: ReceiveTimeout,
    ) -> Result<DeadlineReceiveStart, DeadlineReceiveSyscallError> {
        let task = runtime
            .current()
            .ok_or(DeadlineReceiveSyscallError::Runtime(
                TaskRuntimeError::NoCurrentTask,
            ))?;
        if self.owner_slot(task)?.is_some() {
            return Err(DeadlineReceiveSyscallError::OwnerMismatch);
        }
        let free_slot = self
            .owners
            .iter()
            .position(Option::is_none)
            .ok_or(DeadlineReceiveSyscallError::OwnerFull)?;
        match runtime
            .receive_or_block_current_for(timeout)
            .map_err(DeadlineReceiveSyscallError::Runtime)?
        {
            DeadlineReceive::Ready(message) => Ok(DeadlineReceiveStart::Ready(message)),
            DeadlineReceive::TimedOut => Ok(DeadlineReceiveStart::TimedOut),
            DeadlineReceive::Blocked(wait) => {
                if wait.task() != task || wait.is_control() {
                    return Err(DeadlineReceiveSyscallError::OwnerMismatch);
                }
                self.owners[free_slot] = Some(wait);
                Ok(DeadlineReceiveStart::Blocked(wait.outcome()))
            }
        }
    }

    pub fn complete_ready<const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        task: TaskId,
    ) -> Result<(), DeadlineReceiveSyscallError> {
        let slot = self
            .owner_slot(task)?
            .ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
        let owner = self.owners[slot].ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
        if owner.is_control() {
            return Err(DeadlineReceiveSyscallError::OwnerMismatch);
        }
        runtime
            .context(task)
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        let message = runtime
            .receive_ipc(task)
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        if self.owners[slot] != Some(owner) {
            return Err(DeadlineReceiveSyscallError::OwnerMismatch);
        }
        self.owners[slot] = None;
        runtime
            .context_mut(task)
            .expect("ready completion preserves the prevalidated task context")
            .complete_message(message.payload());
        Ok(())
    }

    pub fn timer_tick<const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ReceiveDeadlineTick<TASKS>, DeadlineReceiveSyscallError> {
        let tick = runtime
            .timer_tick_and_expire_receives()
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        let mut slots = [None; TASKS];
        for (index, expired) in tick.expired().iter().enumerate() {
            let Some(expired) = expired else {
                continue;
            };
            let mut matches = self.owners.iter().enumerate().filter_map(|(slot, owner)| {
                owner
                    .as_ref()
                    .is_some_and(|owner| expired.matches(owner))
                    .then_some(slot)
            });
            let slot = matches
                .next()
                .ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
            if matches.next().is_some() || runtime.context(expired.task()).is_err() {
                return Err(DeadlineReceiveSyscallError::OwnerMismatch);
            }
            slots[index] = Some(slot);
        }
        for (index, expired) in tick.expired().iter().enumerate() {
            let Some(expired) = expired else {
                continue;
            };
            let slot = slots[index].ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
            let owner = self.owners[slot]
                .take()
                .ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
            if !expired.matches(&owner) {
                return Err(DeadlineReceiveSyscallError::OwnerMismatch);
            }
            runtime
                .context_mut(expired.task())
                .expect("expiry completion preserves every prevalidated task context")
                .complete_timeout();
        }
        Ok(tick)
    }

    pub fn has_pending(&self, task: TaskId) -> Result<bool, DeadlineReceiveSyscallError> {
        self.owner_slot(task).map(|slot| slot.is_some())
    }

    fn owner_slot(&self, task: TaskId) -> Result<Option<usize>, DeadlineReceiveSyscallError> {
        let mut found = None;
        for (slot, owner) in self.owners.iter().enumerate() {
            if owner.is_some_and(|owner| owner.task() == task) && found.replace(slot).is_some() {
                return Err(DeadlineReceiveSyscallError::OwnerMismatch);
            }
        }
        Ok(found)
    }
}

impl<const TASKS: usize> Default for DeadlineReceiveSyscallExecutor<TASKS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::UserContext;
    use crate::{Endpoint, ObjectId, PhysAddr, Priority, Rights};

    fn context(root: u64, stack: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), 0x40_1000, stack).unwrap()
    }

    #[test]
    fn exact_deadline_completes_suspended_context_and_selects_from_idle() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(1).unwrap()),
            Ok(DeadlineReceiveStart::Blocked(ScheduleOutcome::Idle))
        ));
        let tick = executor.timer_tick(&mut runtime).unwrap();
        assert!(matches!(
            tick.scheduling(),
            ScheduleOutcome::Switch { from: None, to } if to == task
        ));
        assert!(!executor.has_pending(task).unwrap());
        let context = runtime.context(task).unwrap();
        assert_eq!(context.rax, crate::SyscallCompletionStatus::TimedOut.code());
        assert_eq!(
            (context.rdx, context.r10, context.r8, context.r9),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn message_wakeup_consumes_owner_before_payload_completion() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x91);
        let capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(5).unwrap()),
            Ok(DeadlineReceiveStart::Blocked(ScheduleOutcome::Switch { to, .. })) if to == sender
        ));
        runtime
            .deliver_ipc(sender, receiver, &mut endpoint, capability, b"ready", &[])
            .unwrap();
        executor.complete_ready(&mut runtime, receiver).unwrap();
        assert!(!executor.has_pending(receiver).unwrap());
        let context = runtime.context(receiver).unwrap();
        assert_eq!(context.rax, crate::SyscallCompletionStatus::Success.code());
        assert_eq!(context.rdx, 5);
        assert_eq!(context.r10.to_le_bytes()[..5], *b"ready");
    }

    #[test]
    fn timeout_winner_rejects_stale_completion_and_preserves_late_message() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x92);
        let capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(1).unwrap()),
            Ok(DeadlineReceiveStart::Blocked(ScheduleOutcome::Switch { to, .. })) if to == sender
        ));
        let tick = executor.timer_tick(&mut runtime).unwrap();
        assert!(matches!(tick.scheduling(), ScheduleOutcome::Continue(task) if task == sender));
        assert!(!executor.has_pending(receiver).unwrap());
        let timed_out = *runtime.context(receiver).unwrap();
        assert_eq!(
            timed_out.rax,
            crate::SyscallCompletionStatus::TimedOut.code()
        );

        runtime
            .deliver_ipc(sender, receiver, &mut endpoint, capability, b"late", &[])
            .unwrap();
        assert_eq!(
            executor.complete_ready(&mut runtime, receiver),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );
        assert_eq!(*runtime.context(receiver).unwrap(), timed_out);
        assert_eq!(
            runtime.receive_ipc(receiver).unwrap().payload(),
            b"late"
        );
    }
}
