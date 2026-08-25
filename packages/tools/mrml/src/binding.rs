use crate::abi::{AbiOpaqueHandle, InterfaceIdentity};
use crate::generation::SystemPackage;
use crate::resolver::{ProviderForm, ResolvedInterfaceProvider};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceBindingId {
    slot: u16,
    generation: u32,
}

impl InterfaceBindingId {
    pub const fn slot(self) -> u16 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderTarget {
    InProcess {
        executable: AbiOpaqueHandle,
        entry_operation: u32,
    },
    IsolatedService {
        endpoint: AbiOpaqueHandle,
    },
}

impl ProviderTarget {
    const fn form(self) -> ProviderForm {
        match self {
            Self::InProcess { .. } => ProviderForm::InProcess,
            Self::IsolatedService { .. } => ProviderForm::IsolatedService,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceBinding {
    consumer: SystemPackage,
    provider: SystemPackage,
    interface: InterfaceIdentity,
    fingerprint: [u8; 32],
    target: ProviderTarget,
}

impl InterfaceBinding {
    pub fn consumer(&self) -> &SystemPackage {
        &self.consumer
    }

    pub fn provider(&self) -> &SystemPackage {
        &self.provider
    }

    pub fn interface(&self) -> &InterfaceIdentity {
        &self.interface
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn target(&self) -> ProviderTarget {
        self.target
    }
}

pub struct InterfaceBindingTable<const N: usize> {
    slots: Vec<Option<InterfaceBinding>>,
    generations: Vec<u32>,
}

impl<const N: usize> InterfaceBindingTable<N> {
    pub fn new() -> Result<Self, BindingError> {
        if N == 0 || N > u16::MAX as usize {
            return Err(BindingError::InvalidCapacity);
        }
        Ok(Self {
            slots: (0..N).map(|_| None).collect(),
            generations: vec![1; N],
        })
    }

    pub fn bind(
        &mut self,
        resolved: &ResolvedInterfaceProvider,
        target: ProviderTarget,
    ) -> Result<InterfaceBindingId, BindingError> {
        if target.form() != resolved.form() {
            return Err(BindingError::ProviderFormMismatch);
        }
        if matches!(
            target,
            ProviderTarget::InProcess {
                entry_operation: 0,
                ..
            }
        ) {
            return Err(BindingError::InvalidEntryOperation);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(BindingError::CapacityExhausted)?;
        let generation = self.generations[slot];
        self.slots[slot] = Some(InterfaceBinding {
            consumer: resolved.consumer().clone(),
            provider: resolved.provider().clone(),
            interface: resolved.interface().clone(),
            fingerprint: resolved.fingerprint(),
            target,
        });
        Ok(InterfaceBindingId {
            slot: slot as u16,
            generation,
        })
    }

    pub fn get(&self, id: InterfaceBindingId) -> Result<&InterfaceBinding, BindingError> {
        let slot = id.slot as usize;
        if self.generations.get(slot).copied() != Some(id.generation) {
            return Err(BindingError::InvalidBinding);
        }
        self.slots
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(BindingError::InvalidBinding)
    }

    pub fn release(&mut self, id: InterfaceBindingId) -> Result<InterfaceBinding, BindingError> {
        let slot = id.slot as usize;
        if self.generations.get(slot).copied() != Some(id.generation)
            || self.slots.get(slot).is_none_or(Option::is_none)
        {
            return Err(BindingError::InvalidBinding);
        }
        let next = id
            .generation
            .checked_add(1)
            .ok_or(BindingError::GenerationExhausted)?;
        let binding = self.slots[slot]
            .take()
            .ok_or(BindingError::InvalidBinding)?;
        self.generations[slot] = next;
        Ok(binding)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    InvalidCapacity,
    CapacityExhausted,
    ProviderFormMismatch,
    InvalidEntryOperation,
    InvalidBinding,
    GenerationExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::InterfaceIdentity;
    use crate::generation::SystemGeneration;
    use crate::resolver::{InterfaceProvider, InterfaceRequirement, resolve_interface_providers};

    const ZSTD3: [u8; 32] = [
        106, 98, 189, 213, 148, 175, 40, 79, 81, 237, 193, 115, 74, 161, 88, 81, 229, 222, 55, 239,
        126, 33, 16, 59, 102, 84, 84, 199, 67, 226, 18, 108,
    ];

    fn package(id: &str, version: u64, marker: u8) -> SystemPackage {
        SystemPackage::new(id.into(), version, [marker; 64]).unwrap()
    }

    fn resolved(version: u64, marker: u8, form: ProviderForm) -> ResolvedInterfaceProvider {
        let interface =
            InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), 3).unwrap();
        let generation = SystemGeneration::new(
            version,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", version, marker),
            ],
        )
        .unwrap();
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface.clone(), ZSTD3).unwrap();
        let provider =
            InterfaceProvider::exact("org.mrml.zstd".into(), interface, ZSTD3, form).unwrap();
        resolve_interface_providers(&generation, &[requirement], &[provider])
            .unwrap()
            .remove(0)
    }

    fn executable(index: u32, generation: u32) -> ProviderTarget {
        ProviderTarget::InProcess {
            executable: AbiOpaqueHandle::new(index, generation).unwrap(),
            entry_operation: 1,
        }
    }

    #[test]
    fn existing_binding_retains_exact_provider_after_update() {
        let mut table = InterfaceBindingTable::<2>::new().unwrap();
        let old = table
            .bind(
                &resolved(14, 0x2e, ProviderForm::InProcess),
                executable(4, 1),
            )
            .unwrap();
        let new = table
            .bind(
                &resolved(15, 0x2f, ProviderForm::InProcess),
                executable(5, 1),
            )
            .unwrap();

        assert_eq!(table.get(old).unwrap().provider().version(), 14);
        assert_eq!(
            table.get(old).unwrap().provider().artifact_digest(),
            &[0x2e; 64]
        );
        assert_eq!(table.get(old).unwrap().target(), executable(4, 1));
        assert_eq!(table.get(new).unwrap().provider().version(), 15);
        assert_eq!(table.get(new).unwrap().target(), executable(5, 1));
    }

    #[test]
    fn released_binding_never_revalidates_after_slot_reuse() {
        let mut table = InterfaceBindingTable::<1>::new().unwrap();
        let stale = table
            .bind(
                &resolved(14, 0x2e, ProviderForm::InProcess),
                executable(4, 7),
            )
            .unwrap();
        let released = table.release(stale).unwrap();
        assert_eq!(released.provider().version(), 14);
        let fresh = table
            .bind(
                &resolved(15, 0x2f, ProviderForm::InProcess),
                executable(5, 8),
            )
            .unwrap();
        assert_eq!(fresh.slot(), stale.slot());
        assert_ne!(fresh.generation(), stale.generation());
        assert_eq!(table.get(stale), Err(BindingError::InvalidBinding));
        assert_eq!(table.get(fresh).unwrap().provider().version(), 15);
    }

    #[test]
    fn provider_form_and_entry_are_checked_before_publication() {
        let mut table = InterfaceBindingTable::<1>::new().unwrap();
        let service = resolved(15, 0x2f, ProviderForm::IsolatedService);
        assert_eq!(
            table.bind(&service, executable(4, 1)),
            Err(BindingError::ProviderFormMismatch)
        );
        let in_process = resolved(15, 0x2f, ProviderForm::InProcess);
        assert_eq!(
            table.bind(
                &in_process,
                ProviderTarget::InProcess {
                    executable: AbiOpaqueHandle::new(4, 1).unwrap(),
                    entry_operation: 0,
                }
            ),
            Err(BindingError::InvalidEntryOperation)
        );
        assert!(table.bind(&in_process, executable(4, 1)).is_ok());
    }
}
