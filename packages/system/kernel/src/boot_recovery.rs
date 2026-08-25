use crate::{
    Capability, HANDOFF_RECOVERY_STATE_BYTES, ObjectId, RecoveryStateMetadata, Rights, TaskId,
    TaskRuntime, TaskRuntimeError,
};

/// One-use, capability-scoped delivery of authenticated recovery metadata to
/// one exact service task generation. The metadata remains data; this mechanism
/// grants no storage or recovery authority.
pub struct BootRecoveryDelivery {
    target: TaskId,
    object: ObjectId,
    metadata: Option<RecoveryStateMetadata>,
}

impl BootRecoveryDelivery {
    pub fn new(
        target: TaskId,
        object: ObjectId,
        metadata: RecoveryStateMetadata,
    ) -> Result<Self, BootRecoveryDeliveryError> {
        if object == ObjectId(0) {
            return Err(BootRecoveryDeliveryError::InvalidObject);
        }
        Ok(Self {
            target,
            object,
            metadata: Some(metadata),
        })
    }

    pub fn deliver<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        requester: TaskId,
        capability: Capability,
        output: &mut [u8; HANDOFF_RECOVERY_STATE_BYTES],
    ) -> Result<(), BootRecoveryDeliveryError> {
        output.fill(0);
        if self.metadata.is_none() {
            return Err(BootRecoveryDeliveryError::AlreadyDelivered);
        }
        if requester != self.target {
            return Err(BootRecoveryDeliveryError::WrongTask);
        }
        runtime
            .authorize_capability_exact(requester, capability, Rights::READ, self.object)
            .map_err(BootRecoveryDeliveryError::Runtime)?;
        runtime
            .revoke_capability(requester, capability)
            .map_err(BootRecoveryDeliveryError::Runtime)?;
        let metadata = self
            .metadata
            .take()
            .ok_or(BootRecoveryDeliveryError::AlreadyDelivered)?;
        *output = metadata.encode();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootRecoveryDeliveryError {
    InvalidObject,
    WrongTask,
    AlreadyDelivered,
    Runtime(TaskRuntimeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Priority, ScheduleOutcome, arch::x86_64::UserContext};

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(crate::PhysAddr::new(root).unwrap(), entry, 0x7000_0000).unwrap()
    }

    #[test]
    fn exact_service_consumes_recovery_metadata_once_after_revocation() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let storage = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let other = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x91);
        let capability = runtime
            .capabilities_mut(storage)
            .unwrap()
            .insert(object, Rights::READ)
            .unwrap();
        let wrong_capability = runtime
            .capabilities_mut(other)
            .unwrap()
            .insert(object, Rights::READ)
            .unwrap();
        let metadata = RecoveryStateMetadata::new(8, 2, Some([0x44; 16]), 17).unwrap();
        let mut delivery = BootRecoveryDelivery::new(storage, object, metadata).unwrap();
        let mut output = [0xa5; HANDOFF_RECOVERY_STATE_BYTES];

        assert_eq!(
            delivery.deliver(&mut runtime, other, wrong_capability, &mut output),
            Err(BootRecoveryDeliveryError::WrongTask)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(
            delivery.deliver(&mut runtime, storage, capability, &mut output),
            Ok(())
        );
        assert_eq!(u64::from_le_bytes(output[..8].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(output[8..12].try_into().unwrap()), 2);
        assert_eq!(&output[16..32], &[0x44; 16]);
        assert_eq!(u64::from_le_bytes(output[32..].try_into().unwrap()), 17);
        assert_eq!(RecoveryStateMetadata::decode(&output), Ok(metadata));
        assert!(
            runtime
                .authorize_capability_exact(storage, capability, Rights::READ, object)
                .is_err()
        );
        assert_eq!(
            delivery.deliver(&mut runtime, storage, capability, &mut output),
            Err(BootRecoveryDeliveryError::AlreadyDelivered)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == storage));
    }

    #[test]
    fn overbroad_stale_and_replacement_service_authority_fail_closed() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let storage = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let object = ObjectId(0x92);
        let overbroad = runtime
            .capabilities_mut(storage)
            .unwrap()
            .insert(object, Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let wrong_object = runtime
            .capabilities_mut(storage)
            .unwrap()
            .insert(ObjectId(0x93), Rights::READ)
            .unwrap();
        let metadata = RecoveryStateMetadata::new(8, 2, None, 0).unwrap();
        let mut delivery = BootRecoveryDelivery::new(storage, object, metadata).unwrap();
        let mut output = [0xa5; HANDOFF_RECOVERY_STATE_BYTES];
        assert!(matches!(
            delivery.deliver(&mut runtime, storage, overbroad, &mut output),
            Err(BootRecoveryDeliveryError::Runtime(_))
        ));
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            delivery.deliver(&mut runtime, storage, wrong_object, &mut output),
            Err(BootRecoveryDeliveryError::Runtime(_))
        ));
        assert!(output.iter().all(|byte| *byte == 0));

        runtime.revoke_capability(storage, overbroad).unwrap();
        let detached = runtime.detach_domain(storage).unwrap();
        drop(detached);
        let replacement = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        assert_ne!(replacement, storage);
        assert_eq!(
            delivery.deliver(&mut runtime, replacement, overbroad, &mut output),
            Err(BootRecoveryDeliveryError::WrongTask)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }
}
