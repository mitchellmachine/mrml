use crate::{IdentityManager, TlsIdentityId};

pub const MAX_MANAGED_IDENTITIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateManagerError {
    DuplicateIdentity,
    IdentityUnavailable,
    CapacityExceeded,
    InvalidPolicyGeneration,
    IdentityInUse,
}

/// Bounded owner of independent certificate identity state machines.
///
/// This registry does not select an identity from SNI or multiplex identities
/// on a listener. Consumers must present the exact identity capability to the
/// corresponding `IdentityManager` through the certificate service ABI.
pub struct CertificateManager {
    identities: [Option<IdentityManager>; MAX_MANAGED_IDENTITIES],
    count: u8,
}

impl CertificateManager {
    pub const fn new() -> Self {
        Self {
            identities: [const { None }; MAX_MANAGED_IDENTITIES],
            count: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn enroll(
        &mut self,
        identity: TlsIdentityId,
        policy_generation: u64,
    ) -> Result<&mut IdentityManager, CertificateManagerError> {
        if policy_generation == 0 {
            return Err(CertificateManagerError::InvalidPolicyGeneration);
        }
        if self
            .identities
            .iter()
            .flatten()
            .any(|manager| manager.identity() == identity)
        {
            return Err(CertificateManagerError::DuplicateIdentity);
        }
        let slot = self
            .identities
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(CertificateManagerError::CapacityExceeded)?;
        *slot = Some(IdentityManager::new(identity, policy_generation));
        self.count += 1;
        Ok(slot.as_mut().unwrap())
    }

    pub fn get(
        &self,
        identity: TlsIdentityId,
    ) -> Result<&IdentityManager, CertificateManagerError> {
        self.identities
            .iter()
            .flatten()
            .find(|manager| manager.identity() == identity)
            .ok_or(CertificateManagerError::IdentityUnavailable)
    }

    pub fn get_mut(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<&mut IdentityManager, CertificateManagerError> {
        self.identities
            .iter_mut()
            .flatten()
            .find(|manager| manager.identity() == identity)
            .ok_or(CertificateManagerError::IdentityUnavailable)
    }

    pub fn remove_empty(&mut self, identity: TlsIdentityId) -> Result<(), CertificateManagerError> {
        let slot = self
            .identities
            .iter_mut()
            .find(|slot| {
                slot.as_ref()
                    .is_some_and(|manager| manager.identity() == identity)
            })
            .ok_or(CertificateManagerError::IdentityUnavailable)?;
        if slot
            .as_ref()
            .is_some_and(IdentityManager::has_deployment_state)
        {
            return Err(CertificateManagerError::IdentityInUse);
        }
        *slot = None;
        self.count -= 1;
        Ok(())
    }
}

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_exact_independent_and_bounded() {
        let mut registry = CertificateManager::new();
        let first = TlsIdentityId([1; 16]);
        let second = TlsIdentityId([2; 16]);
        registry.enroll(first, 4).unwrap();
        registry.enroll(second, 7).unwrap();
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get(first).unwrap().policy_generation(), 4);
        assert_eq!(registry.get(second).unwrap().policy_generation(), 7);
        assert_eq!(
            registry.enroll(first, 8).err(),
            Some(CertificateManagerError::DuplicateIdentity)
        );
        assert_eq!(
            registry.get(TlsIdentityId([3; 16])).err(),
            Some(CertificateManagerError::IdentityUnavailable)
        );
        registry.remove_empty(first).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get(second).is_ok());
    }

    #[test]
    fn capacity_and_zero_policy_fail_closed() {
        let mut registry = CertificateManager::new();
        assert_eq!(
            registry.enroll(TlsIdentityId([1; 16]), 0).err(),
            Some(CertificateManagerError::InvalidPolicyGeneration)
        );
        for index in 0..MAX_MANAGED_IDENTITIES {
            let mut id = [0; 16];
            id[0] = (index + 1) as u8;
            registry.enroll(TlsIdentityId(id), 1).unwrap();
        }
        assert_eq!(
            registry.enroll(TlsIdentityId([0xff; 16]), 1).err(),
            Some(CertificateManagerError::CapacityExceeded)
        );
    }
}
