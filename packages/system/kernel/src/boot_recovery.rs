use crate::{
    BootIsolationOverride, Capability, EarlyKernelContext, HANDOFF_RECOVERY_STATE_BYTES,
    INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES, INSTALLED_RECOVERY_SATA_ROUTE_BYTES,
    InstalledRecoveryBootIdentity, InstalledRecoverySataRoute, InstalledRecoverySource, ObjectId,
    RecoveryStateMetadata, Rights, TaskId, TaskRuntime, TaskRuntimeError,
};

pub const BOOT_RECOVERY_ENVELOPE_BYTES: usize = 8
    + HANDOFF_RECOVERY_STATE_BYTES
    + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES
    + INSTALLED_RECOVERY_SATA_ROUTE_BYTES;

const BOOT_RECOVERY_ENVELOPE_MAGIC: [u8; 4] = *b"MRBR";
const BOOT_RECOVERY_ENVELOPE_VERSION: u16 = 1;
const BOOT_RECOVERY_FLAG_INSTALLED: u16 = 1 << 0;
const BOOT_RECOVERY_FLAG_SATA_ROUTE: u16 = 1 << 1;
const BOOT_RECOVERY_FLAG_TOTAL_ONCE: u16 = 1 << 2;
const BOOT_RECOVERY_KNOWN_FLAGS: u16 = BOOT_RECOVERY_FLAG_INSTALLED
    | BOOT_RECOVERY_FLAG_SATA_ROUTE
    | BOOT_RECOVERY_FLAG_TOTAL_ONCE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootRecoveryEnvelope {
    recovery: RecoveryStateMetadata,
    installed: Option<InstalledRecoveryBootIdentity>,
    sata_route: Option<InstalledRecoverySataRoute>,
    isolation_override: Option<BootIsolationOverride>,
}

impl BootRecoveryEnvelope {
    pub fn new(
        recovery: RecoveryStateMetadata,
        installed: Option<InstalledRecoveryBootIdentity>,
        sata_route: Option<InstalledRecoverySataRoute>,
        isolation_override: Option<BootIsolationOverride>,
    ) -> Result<Self, BootRecoveryEnvelopeError> {
        match (installed, sata_route) {
            (None, Some(_)) => return Err(BootRecoveryEnvelopeError::NonCanonical),
            (Some(identity), Some(route))
                if identity.source() != InstalledRecoverySource::Uefi
                    || identity.stable_id() != route.stable_id() =>
            {
                return Err(BootRecoveryEnvelopeError::NonCanonical);
            }
            (Some(identity), None) if identity.source() == InstalledRecoverySource::Uefi => {
                return Err(BootRecoveryEnvelopeError::NonCanonical);
            }
            _ => {}
        }
        if let Some(identity) = installed
            && (recovery.accepted_volume() != Some(identity.volume())
                || recovery.accepted_root_generation() != identity.root_generation())
        {
            return Err(BootRecoveryEnvelopeError::NonCanonical);
        }
        Ok(Self {
            recovery,
            installed,
            sata_route,
            isolation_override,
        })
    }

    pub fn from_early(early: &EarlyKernelContext<'_>) -> Result<Self, BootRecoveryEnvelopeError> {
        Self::new(
            early
                .recovery_state()
                .ok_or(BootRecoveryEnvelopeError::MissingRecovery)?,
            early.installed_recovery(),
            early.installed_recovery_sata_route(),
            early.isolation_override(),
        )
    }

    pub const fn recovery(self) -> RecoveryStateMetadata {
        self.recovery
    }

    pub const fn installed(self) -> Option<InstalledRecoveryBootIdentity> {
        self.installed
    }

    pub const fn sata_route(self) -> Option<InstalledRecoverySataRoute> {
        self.sata_route
    }

    pub const fn isolation_override(self) -> Option<BootIsolationOverride> {
        self.isolation_override
    }

    pub fn encode(self) -> [u8; BOOT_RECOVERY_ENVELOPE_BYTES] {
        let mut output = [0; BOOT_RECOVERY_ENVELOPE_BYTES];
        output[..4].copy_from_slice(&BOOT_RECOVERY_ENVELOPE_MAGIC);
        output[4..6].copy_from_slice(&BOOT_RECOVERY_ENVELOPE_VERSION.to_le_bytes());
        let mut flags = 0u16;
        if let Some(installed) = self.installed {
            flags |= BOOT_RECOVERY_FLAG_INSTALLED;
            output[48..48 + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES]
                .copy_from_slice(&installed.encode());
        }
        if let Some(route) = self.sata_route {
            flags |= BOOT_RECOVERY_FLAG_SATA_ROUTE;
            output[152..].copy_from_slice(&route.encode());
        }
        if self.isolation_override == Some(BootIsolationOverride::TotalMicrovmOnce) {
            flags |= BOOT_RECOVERY_FLAG_TOTAL_ONCE;
        }
        output[6..8].copy_from_slice(&flags.to_le_bytes());
        output[8..48].copy_from_slice(&self.recovery.encode());
        output
    }

    pub fn decode(
        input: &[u8; BOOT_RECOVERY_ENVELOPE_BYTES],
    ) -> Result<Self, BootRecoveryEnvelopeError> {
        if input[..4] != BOOT_RECOVERY_ENVELOPE_MAGIC
            || u16::from_le_bytes(input[4..6].try_into().unwrap())
                != BOOT_RECOVERY_ENVELOPE_VERSION
        {
            return Err(BootRecoveryEnvelopeError::NonCanonical);
        }
        let flags = u16::from_le_bytes(input[6..8].try_into().unwrap());
        if flags & !BOOT_RECOVERY_KNOWN_FLAGS != 0 {
            return Err(BootRecoveryEnvelopeError::NonCanonical);
        }
        let recovery = RecoveryStateMetadata::decode(input[8..48].try_into().unwrap())
            .map_err(|_| BootRecoveryEnvelopeError::NonCanonical)?;
        let installed = if flags & BOOT_RECOVERY_FLAG_INSTALLED != 0 {
            Some(
                InstalledRecoveryBootIdentity::decode(input[48..152].try_into().unwrap())
                    .map_err(|_| BootRecoveryEnvelopeError::NonCanonical)?,
            )
        } else {
            if input[48..152].iter().any(|byte| *byte != 0) {
                return Err(BootRecoveryEnvelopeError::NonCanonical);
            }
            None
        };
        let sata_route = if flags & BOOT_RECOVERY_FLAG_SATA_ROUTE != 0 {
            Some(
                InstalledRecoverySataRoute::decode(input[152..].try_into().unwrap())
                    .map_err(|_| BootRecoveryEnvelopeError::NonCanonical)?,
            )
        } else {
            if input[152..].iter().any(|byte| *byte != 0) {
                return Err(BootRecoveryEnvelopeError::NonCanonical);
            }
            None
        };
        let isolation_override = (flags & BOOT_RECOVERY_FLAG_TOTAL_ONCE != 0)
            .then_some(BootIsolationOverride::TotalMicrovmOnce);
        Self::new(recovery, installed, sata_route, isolation_override)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootRecoveryEnvelopeError {
    MissingRecovery,
    NonCanonical,
}

/// One-use, capability-scoped delivery of authenticated recovery metadata to
/// one exact service task generation. The metadata remains data; this mechanism
/// grants no storage or recovery authority.
pub struct BootRecoveryDelivery {
    target: TaskId,
    object: ObjectId,
    envelope: Option<BootRecoveryEnvelope>,
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
            envelope: Some(
                BootRecoveryEnvelope::new(metadata, None, None, None)
                    .map_err(|_| BootRecoveryDeliveryError::InvalidEnvelope)?,
            ),
        })
    }

    pub fn from_early(
        target: TaskId,
        object: ObjectId,
        early: &EarlyKernelContext<'_>,
    ) -> Result<Self, BootRecoveryDeliveryError> {
        if object == ObjectId(0) {
            return Err(BootRecoveryDeliveryError::InvalidObject);
        }
        Ok(Self {
            target,
            object,
            envelope: Some(
                BootRecoveryEnvelope::from_early(early)
                    .map_err(|_| BootRecoveryDeliveryError::InvalidEnvelope)?,
            ),
        })
    }

    pub fn deliver<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        requester: TaskId,
        capability: Capability,
        output: &mut [u8; BOOT_RECOVERY_ENVELOPE_BYTES],
    ) -> Result<(), BootRecoveryDeliveryError> {
        output.fill(0);
        if self.envelope.is_none() {
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
        let envelope = self
            .envelope
            .take()
            .ok_or(BootRecoveryDeliveryError::AlreadyDelivered)?;
        *output = envelope.encode();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootRecoveryDeliveryError {
    InvalidObject,
    InvalidEnvelope,
    WrongTask,
    AlreadyDelivered,
    Runtime(TaskRuntimeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InstalledRecoveryHardDriveMedia, InstalledRecoveryPciHop, Priority, ScheduleOutcome,
        arch::x86_64::UserContext,
    };

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(crate::PhysAddr::new(root).unwrap(), entry, 0x7000_0000).unwrap()
    }

    #[test]
    fn canonical_envelope_binds_recovery_installed_route_and_total_request() {
        let recovery = RecoveryStateMetadata::new(8, 2, Some([0x44; 16]), 17).unwrap();
        let installed = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Uefi,
            [0x31; 32],
            3,
            4,
            4096,
            8192,
            [0x44; 16],
            2,
            17,
        )
        .unwrap();
        let hops = [InstalledRecoveryPciHop::new(31, 2).unwrap()];
        let media = InstalledRecoveryHardDriveMedia::new(2, 2048, 4096, [0x55; 16], 2, 2)
            .unwrap();
        let route = InstalledRecoverySataRoute::new(
            0,
            0,
            &hops,
            0,
            0,
            0,
            Some(media),
            [0x31; 32],
        )
        .unwrap();
        let envelope = BootRecoveryEnvelope::new(
            recovery,
            Some(installed),
            Some(route),
            Some(BootIsolationOverride::TotalMicrovmOnce),
        )
        .unwrap();
        let encoded = envelope.encode();
        assert_eq!(BootRecoveryEnvelope::decode(&encoded), Ok(envelope));

        let mut malformed = encoded;
        malformed[6] |= 0x80;
        assert_eq!(
            BootRecoveryEnvelope::decode(&malformed),
            Err(BootRecoveryEnvelopeError::NonCanonical)
        );
        let metadata_only = BootRecoveryEnvelope::new(recovery, None, None, None)
            .unwrap()
            .encode();
        let mut hidden = metadata_only;
        hidden[48] = 1;
        assert_eq!(
            BootRecoveryEnvelope::decode(&hidden),
            Err(BootRecoveryEnvelopeError::NonCanonical)
        );
        assert_eq!(
            BootRecoveryEnvelope::new(recovery, Some(installed), None, None),
            Err(BootRecoveryEnvelopeError::NonCanonical)
        );
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
        let mut output = [0xa5; BOOT_RECOVERY_ENVELOPE_BYTES];

        assert_eq!(
            delivery.deliver(&mut runtime, other, wrong_capability, &mut output),
            Err(BootRecoveryDeliveryError::WrongTask)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(
            delivery.deliver(&mut runtime, storage, capability, &mut output),
            Ok(())
        );
        let envelope = BootRecoveryEnvelope::decode(&output).unwrap();
        assert_eq!(envelope.recovery(), metadata);
        assert_eq!(envelope.installed(), None);
        assert_eq!(envelope.sata_route(), None);
        assert_eq!(envelope.isolation_override(), None);
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
        let mut output = [0xa5; BOOT_RECOVERY_ENVELOPE_BYTES];
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
