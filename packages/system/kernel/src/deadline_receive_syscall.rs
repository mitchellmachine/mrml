use core::array;

use crate::{
    BlockedReceive, Capability, DeadlineReceive, Endpoint, MAX_SYSCALL_INLINE_PAYLOAD, Message,
    ReceiveDeadlineTick, ReceiveTimeout, Rights, ScheduleOutcome, TaskId, TaskRuntime,
    TaskRuntimeError,
};

#[must_use = "deadline receive admission must be completed or retained"]
pub enum DeadlineReceiveStart {
    Ready(Message),
    TimedOut,
    IncompatibleMessage,
    Blocked {
        scheduling: ScheduleOutcome,
        cancellation: DeadlineReceiveCancellation,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "deadline receive cancellation authority must be retained or discarded deliberately"]
pub struct DeadlineReceiveCancellation {
    owner: BlockedReceive,
}

impl DeadlineReceiveCancellation {
    pub const fn task(self) -> TaskId {
        self.owner.task()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineReceiveSyscallError {
    Runtime(TaskRuntimeError),
    OwnerFull,
    OwnerMismatch,
    MessageShape,
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
        match runtime.receive_ipc_bounded(task, MAX_SYSCALL_INLINE_PAYLOAD, 0) {
            Ok(message) => return Ok(DeadlineReceiveStart::Ready(message)),
            Err(TaskRuntimeError::ReceiveCapacity) => {
                return Ok(DeadlineReceiveStart::IncompatibleMessage);
            }
            Err(TaskRuntimeError::InboxEmpty) => {}
            Err(error) => return Err(DeadlineReceiveSyscallError::Runtime(error)),
        }
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
                Ok(DeadlineReceiveStart::Blocked {
                    scheduling: wait.outcome(),
                    cancellation: DeadlineReceiveCancellation { owner: wait },
                })
            }
        }
    }

    pub fn cancel<const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        cancellation: DeadlineReceiveCancellation,
    ) -> Result<(), DeadlineReceiveSyscallError> {
        let task = cancellation.owner.task();
        let slot = self
            .owner_slot(task)?
            .filter(|slot| self.owners[*slot] == Some(cancellation.owner))
            .ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
        runtime
            .context(task)
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        runtime
            .cancel_blocked_receive(cancellation.owner)
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        let owner = self.owners[slot]
            .take()
            .ok_or(DeadlineReceiveSyscallError::OwnerMismatch)?;
        if owner != cancellation.owner {
            return Err(DeadlineReceiveSyscallError::OwnerMismatch);
        }
        runtime
            .context_mut(task)
            .expect("cancellation preserves the prevalidated task context")
            .complete_error();
        Ok(())
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

    /// Publishes one IPC delivery and, when the exact receiver owns a pending
    /// deadline syscall, completes that retained syscall before returning.
    pub fn deliver<const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        sender: TaskId,
        receiver: TaskId,
        endpoint: &mut Endpoint,
        endpoint_capability: Capability,
        payload: &[u8],
        requested: &[(Capability, Rights)],
    ) -> Result<u64, DeadlineReceiveSyscallError> {
        let completes_deadline = self.owner_slot(receiver)?.is_some();
        self.validate_delivery(receiver, payload.len(), requested.len())?;
        let sequence = runtime
            .deliver_ipc(
                sender,
                receiver,
                endpoint,
                endpoint_capability,
                payload,
                requested,
            )
            .map_err(DeadlineReceiveSyscallError::Runtime)?;
        if completes_deadline {
            self.complete_ready(runtime, receiver)?;
        }
        Ok(sequence)
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

    fn validate_delivery(
        &self,
        task: TaskId,
        payload_length: usize,
        capability_count: usize,
    ) -> Result<(), DeadlineReceiveSyscallError> {
        if self.owner_slot(task)?.is_some()
            && (payload_length > MAX_SYSCALL_INLINE_PAYLOAD || capability_count != 0)
        {
            return Err(DeadlineReceiveSyscallError::MessageShape);
        }
        Ok(())
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
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Idle,
                ..
            })
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
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == sender
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
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == sender
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
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"late");
    }

    #[test]
    fn staggered_deadlines_complete_only_their_exact_retained_owners() {
        let mut runtime = TaskRuntime::<3, 0>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let third = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(1).unwrap()),
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == second
        ));
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(2).unwrap()),
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == third
        ));

        executor.timer_tick(&mut runtime).unwrap();
        assert!(!executor.has_pending(first).unwrap());
        assert!(executor.has_pending(second).unwrap());
        assert!(!executor.has_pending(third).unwrap());
        assert_eq!(
            runtime.context(first).unwrap().rax,
            crate::SyscallCompletionStatus::TimedOut.code()
        );
        assert_ne!(
            runtime.context(second).unwrap().rax,
            crate::SyscallCompletionStatus::TimedOut.code()
        );

        executor.timer_tick(&mut runtime).unwrap();
        assert!(!executor.has_pending(second).unwrap());
        assert_eq!(
            runtime.context(second).unwrap().rax,
            crate::SyscallCompletionStatus::TimedOut.code()
        );
        for task in [first, second] {
            let context = runtime.context(task).unwrap();
            assert_eq!(
                (context.rdx, context.r10, context.r8, context.r9),
                (0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn incompatible_queued_message_is_not_consumed_or_truncated() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x93);
        let capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        let payload = [0x5a; MAX_SYSCALL_INLINE_PAYLOAD + 1];
        runtime
            .deliver_ipc(sender, receiver, &mut endpoint, capability, &payload, &[])
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(3).unwrap()),
            Ok(DeadlineReceiveStart::IncompatibleMessage)
        ));
        assert!(!executor.has_pending(receiver).unwrap());
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), payload);
    }

    #[test]
    fn pending_inline_deadline_rejects_unrepresentable_delivery_shapes() {
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(3).unwrap()),
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == sender
        ));
        assert_eq!(
            executor.validate_delivery(receiver, MAX_SYSCALL_INLINE_PAYLOAD + 1, 0),
            Err(DeadlineReceiveSyscallError::MessageShape)
        );
        assert_eq!(
            executor.validate_delivery(receiver, 0, 1),
            Err(DeadlineReceiveSyscallError::MessageShape)
        );
        assert_eq!(
            executor.validate_delivery(receiver, MAX_SYSCALL_INLINE_PAYLOAD, 0),
            Ok(())
        );
        assert_eq!(
            executor.validate_delivery(sender, usize::MAX, usize::MAX),
            Ok(())
        );
        assert!(executor.has_pending(receiver).unwrap());
    }

    #[test]
    fn exact_cancellation_completes_error_once_without_consuming_messages() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x96);
        let capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut runtime, ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                cancellation,
            } if to == sender && cancellation.task() == receiver => cancellation,
            _ => panic!("expected exact blocked deadline owner"),
        };

        let mut other_executor = DeadlineReceiveSyscallExecutor::new();
        assert_eq!(
            other_executor.cancel(&mut runtime, cancellation),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );
        assert!(executor.has_pending(receiver).unwrap());
        executor.cancel(&mut runtime, cancellation).unwrap();
        assert!(!executor.has_pending(receiver).unwrap());
        let context = runtime.context(receiver).unwrap();
        assert_eq!(context.rax, crate::SyscallCompletionStatus::Error.code());
        assert_eq!(
            (context.rdx, context.r10, context.r8, context.r9),
            (0, 0, 0, 0)
        );
        assert_eq!(
            executor.cancel(&mut runtime, cancellation),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );

        assert_eq!(
            executor
                .deliver(
                    &mut runtime,
                    sender,
                    receiver,
                    &mut endpoint,
                    capability,
                    b"after",
                    &[],
                )
                .unwrap(),
            1
        );
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"after");
    }

    #[test]
    fn cancellation_loses_to_message_completion_without_overwriting_it() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x97);
        let capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut runtime, ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            DeadlineReceiveStart::Blocked { cancellation, .. } => cancellation,
            _ => panic!("expected blocked deadline receive"),
        };
        executor
            .deliver(
                &mut runtime,
                sender,
                receiver,
                &mut endpoint,
                capability,
                b"ready",
                &[],
            )
            .unwrap();
        let completed = *runtime.context(receiver).unwrap();

        assert_eq!(
            executor.cancel(&mut runtime, cancellation),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );
        assert_eq!(*runtime.context(receiver).unwrap(), completed);
        assert_eq!(
            completed.rax,
            crate::SyscallCompletionStatus::Success.code()
        );
        assert_eq!(completed.rdx, 5);
    }

    #[test]
    fn cancellation_loses_to_timeout_completion_without_overwriting_it() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut runtime, ReceiveTimeout::new(1).unwrap())
            .unwrap()
        {
            DeadlineReceiveStart::Blocked { cancellation, .. } => cancellation,
            _ => panic!("expected blocked deadline receive"),
        };
        executor.timer_tick(&mut runtime).unwrap();
        let completed = *runtime.context(receiver).unwrap();

        assert_eq!(
            executor.cancel(&mut runtime, cancellation),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );
        assert_eq!(*runtime.context(receiver).unwrap(), completed);
        assert_eq!(
            completed.rax,
            crate::SyscallCompletionStatus::TimedOut.code()
        );
        assert_eq!(
            (completed.rdx, completed.r10, completed.r8, completed.r9),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn rejected_delivery_preserves_every_prepublication_state() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x94);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let delegated = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x95), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        assert!(matches!(
            executor.start(&mut runtime, ReceiveTimeout::new(3).unwrap()),
            Ok(DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                ..
            }) if to == sender
        ));

        assert_eq!(
            executor.deliver(
                &mut runtime,
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"blocked",
                &[(delegated, Rights::READ)],
            ),
            Err(DeadlineReceiveSyscallError::MessageShape)
        );
        assert!(executor.has_pending(receiver).unwrap());
        assert!(matches!(
            runtime.receive_ipc(receiver),
            Err(TaskRuntimeError::InboxEmpty)
        ));
        assert!(runtime.capabilities(receiver).unwrap().is_empty());

        assert_eq!(
            executor
                .deliver(
                    &mut runtime,
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"ready",
                    &[],
                )
                .unwrap(),
            1
        );
        assert!(!executor.has_pending(receiver).unwrap());
        let context = runtime.context(receiver).unwrap();
        assert_eq!(context.rax, crate::SyscallCompletionStatus::Success.code());
        assert_eq!(context.rdx, 5);
        assert_eq!(context.r10, u64::from_le_bytes(*b"ready\0\0\0"));
    }
}
