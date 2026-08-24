use crate::{
    BootRecoveryDelivery, BootRecoveryDeliveryError, Capability, HANDOFF_RECOVERY_STATE_BYTES,
    SharedBufferUserAccess, SharedBufferUserCopy, TaskId, TaskRuntime,
};

pub const BOOT_RECOVERY_SYSCALL_OPERATION: u64 = 13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootRecoverySyscallRequest {
    pub capability: Capability,
    pub output_address: u64,
}

impl BootRecoverySyscallRequest {
    pub fn decode(
        operation: u64,
        capability: u64,
        output_address: u64,
        reserved: [u64; 4],
    ) -> Result<Self, BootRecoverySyscallError<(), ()>> {
        if operation != BOOT_RECOVERY_SYSCALL_OPERATION {
            return Err(BootRecoverySyscallError::Unsupported);
        }
        if reserved.iter().any(|value| *value != 0) {
            return Err(BootRecoverySyscallError::Malformed);
        }
        if capability == 0 || capability >> 32 == 0 {
            return Err(BootRecoverySyscallError::Malformed);
        }
        let end = output_address
            .checked_add(HANDOFF_RECOVERY_STATE_BYTES as u64)
            .ok_or(BootRecoverySyscallError::Malformed)?;
        if output_address == 0 || output_address >= 1 << 47 || end > 1 << 47 {
            return Err(BootRecoverySyscallError::Malformed);
        }
        Ok(Self {
            capability: Capability::from_token(capability),
            output_address,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootRecoverySyscallError<U, D> {
    Unsupported,
    Malformed,
    User(U),
    Delivery(D),
}

pub struct BootRecoverySyscallExecutor;

impl BootRecoverySyscallExecutor {
    pub fn execute<const TASKS: usize, const CAPS: usize, U: SharedBufferUserCopy>(
        request: BootRecoverySyscallRequest,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        delivery: &mut BootRecoveryDelivery,
        user: &mut U,
    ) -> Result<(), BootRecoverySyscallError<U::Error, BootRecoveryDeliveryError>> {
        let mut scratch = [0u8; HANDOFF_RECOVERY_STATE_BYTES];
        let result = Self::execute_inner(request, runtime, task, delivery, user, &mut scratch);
        user.cancel();
        scratch.fill(0);
        result
    }

    fn execute_inner<const TASKS: usize, const CAPS: usize, U: SharedBufferUserCopy>(
        request: BootRecoverySyscallRequest,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        delivery: &mut BootRecoveryDelivery,
        user: &mut U,
        scratch: &mut [u8; HANDOFF_RECOVERY_STATE_BYTES],
    ) -> Result<(), BootRecoverySyscallError<U::Error, BootRecoveryDeliveryError>> {
        user.validate(
            task,
            request.output_address,
            HANDOFF_RECOVERY_STATE_BYTES,
            SharedBufferUserAccess::Write,
        )
        .map_err(BootRecoverySyscallError::User)?;
        delivery
            .deliver(runtime, task, request.capability, scratch)
            .map_err(BootRecoverySyscallError::Delivery)?;
        user.write(task, request.output_address, scratch)
            .map_err(BootRecoverySyscallError::User)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectId, Priority, RecoveryStateMetadata, Rights, arch::x86_64::UserContext};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CopyError {
        Validate,
        Write,
    }

    struct UserCopy {
        fail_validate: bool,
        fail_write: bool,
        ticket: bool,
        output: [u8; HANDOFF_RECOVERY_STATE_BYTES],
    }

    unsafe impl SharedBufferUserCopy for UserCopy {
        type Error = CopyError;

        fn validate(
            &mut self,
            _task: TaskId,
            address: u64,
            length: usize,
            access: SharedBufferUserAccess,
        ) -> Result<(), Self::Error> {
            if self.fail_validate {
                return Err(CopyError::Validate);
            }
            assert_eq!(address, 0x6000);
            assert_eq!(length, HANDOFF_RECOVERY_STATE_BYTES);
            assert_eq!(access, SharedBufferUserAccess::Write);
            assert!(!self.ticket);
            self.ticket = true;
            Ok(())
        }

        fn read(&mut self, _: TaskId, _: u64, _: &mut [u8]) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn write(&mut self, _: TaskId, _: u64, input: &[u8]) -> Result<(), Self::Error> {
            assert!(self.ticket);
            self.ticket = false;
            if self.fail_write {
                return Err(CopyError::Write);
            }
            self.output.copy_from_slice(input);
            Ok(())
        }

        fn cancel(&mut self) {
            self.ticket = false;
        }
    }

    fn setup() -> (
        TaskRuntime<1, 1>,
        TaskId,
        Capability,
        BootRecoveryDelivery,
        RecoveryStateMetadata,
    ) {
        let mut runtime = TaskRuntime::new(1_000, 1).unwrap();
        let context = UserContext::new(
            crate::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let object = ObjectId(0x99);
        let capability = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(object, Rights::READ)
            .unwrap();
        let metadata = RecoveryStateMetadata::new(9, 3, Some([0x55; 16]), 21).unwrap();
        let delivery = BootRecoveryDelivery::new(task, object, metadata).unwrap();
        (runtime, task, capability, delivery, metadata)
    }

    fn user_copy(fail_validate: bool, fail_write: bool) -> UserCopy {
        UserCopy {
            fail_validate,
            fail_write,
            ticket: false,
            output: [0xa5; HANDOFF_RECOVERY_STATE_BYTES],
        }
    }

    #[test]
    fn decoder_rejects_wrong_operation_reserved_and_hostile_ranges() {
        let token = (1u64 << 32) | 1;
        for result in [
            BootRecoverySyscallRequest::decode(12, token, 0x6000, [0; 4]),
            BootRecoverySyscallRequest::decode(13, 0, 0x6000, [0; 4]),
            BootRecoverySyscallRequest::decode(13, token, 0, [0; 4]),
            BootRecoverySyscallRequest::decode(13, token, (1 << 47) - 1, [0; 4]),
            BootRecoverySyscallRequest::decode(13, token, u64::MAX - 1, [0; 4]),
            BootRecoverySyscallRequest::decode(13, token, 0x6000, [0, 0, 1, 0]),
        ] {
            assert!(result.is_err());
        }
    }

    #[test]
    fn validated_exact_copy_revokes_authority_and_consumes_delivery() {
        let (mut runtime, task, capability, mut delivery, metadata) = setup();
        let request =
            BootRecoverySyscallRequest::decode(13, capability.token(), 0x6000, [0; 4]).unwrap();
        let mut user = user_copy(false, false);
        assert_eq!(
            BootRecoverySyscallExecutor::execute(
                request,
                &mut runtime,
                task,
                &mut delivery,
                &mut user
            ),
            Ok(())
        );
        assert_eq!(RecoveryStateMetadata::decode(&user.output), Ok(metadata));
        assert!(
            runtime
                .authorize_capability_exact(task, capability, Rights::READ, ObjectId(0x99))
                .is_err()
        );
        assert!(!user.ticket);
    }

    #[test]
    fn validation_failure_preserves_one_use_authority_but_copy_uncertainty_consumes_it() {
        let (mut runtime, task, capability, mut delivery, _) = setup();
        let request = BootRecoverySyscallRequest {
            capability,
            output_address: 0x6000,
        };
        let mut invalid = user_copy(true, false);
        assert_eq!(
            BootRecoverySyscallExecutor::execute(
                request,
                &mut runtime,
                task,
                &mut delivery,
                &mut invalid
            ),
            Err(BootRecoverySyscallError::User(CopyError::Validate))
        );
        assert!(
            runtime
                .authorize_capability_exact(task, capability, Rights::READ, ObjectId(0x99))
                .is_ok()
        );

        let mut uncertain = user_copy(false, true);
        assert_eq!(
            BootRecoverySyscallExecutor::execute(
                request,
                &mut runtime,
                task,
                &mut delivery,
                &mut uncertain
            ),
            Err(BootRecoverySyscallError::User(CopyError::Write))
        );
        assert!(
            runtime
                .authorize_capability_exact(task, capability, Rights::READ, ObjectId(0x99))
                .is_err()
        );
        assert!(!uncertain.ticket);

        let mut retry = user_copy(false, false);
        assert!(matches!(
            BootRecoverySyscallExecutor::execute(
                request,
                &mut runtime,
                task,
                &mut delivery,
                &mut retry
            ),
            Err(BootRecoverySyscallError::Delivery(
                BootRecoveryDeliveryError::AlreadyDelivered
            ))
        ));
        assert!(retry.output.iter().all(|byte| *byte == 0xa5));
        assert!(!retry.ticket);
    }
}
