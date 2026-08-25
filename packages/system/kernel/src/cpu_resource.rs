use core::array;

use crate::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const CPU_BUDGET_RIGHTS: Rights = Rights::ALLOCATE
    .union(Rights::CONTROL)
    .union(Rights::INSPECT)
    .union(Rights::DELEGATE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuBudgetId {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VcpuReservationId {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuBudgetSpec {
    maximum_parallelism: u16,
    runtime_micros: u32,
    period_micros: u32,
    priority_ceiling: u8,
    affinity_mask: u64,
}

impl CpuBudgetSpec {
    pub const fn new(
        maximum_parallelism: u16,
        runtime_micros: u32,
        period_micros: u32,
        priority_ceiling: u8,
        affinity_mask: u64,
    ) -> Result<Self, CpuResourceError> {
        if maximum_parallelism == 0
            || runtime_micros == 0
            || period_micros == 0
            || runtime_micros > period_micros
            || affinity_mask == 0
        {
            return Err(CpuResourceError::InvalidBudget);
        }
        Ok(Self {
            maximum_parallelism,
            runtime_micros,
            period_micros,
            priority_ceiling,
            affinity_mask,
        })
    }

    pub const fn maximum_parallelism(self) -> u16 {
        self.maximum_parallelism
    }

    pub const fn runtime_micros(self) -> u32 {
        self.runtime_micros
    }

    pub const fn period_micros(self) -> u32 {
        self.period_micros
    }

    pub const fn priority_ceiling(self) -> u8 {
        self.priority_ceiling
    }

    pub const fn affinity_mask(self) -> u64 {
        self.affinity_mask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuBudgetUsage {
    spec: CpuBudgetSpec,
    reserved_parallelism: u16,
    active_reservations: u16,
}

impl CpuBudgetUsage {
    pub const fn spec(self) -> CpuBudgetSpec {
        self.spec
    }

    pub const fn reserved_parallelism(self) -> u16 {
        self.reserved_parallelism
    }

    pub const fn active_reservations(self) -> u16 {
        self.active_reservations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuResourceError {
    InvalidNamespace,
    InvalidBudget,
    InvalidReservation,
    CapacityExhausted,
    ParallelismExhausted,
    DuplicateDomain,
    ReservationsActive,
    GenerationExhausted,
    Arithmetic,
    Capability(CapabilityError),
}

impl From<CapabilityError> for CpuResourceError {
    fn from(value: CapabilityError) -> Self {
        Self::Capability(value)
    }
}

#[derive(Clone, Copy)]
struct BudgetEntry {
    generation: u32,
    authority: ObjectId,
    spec: CpuBudgetSpec,
    reserved_parallelism: u16,
    active_reservations: u16,
    occupied: bool,
}

impl BudgetEntry {
    const EMPTY: Self = Self {
        generation: 1,
        authority: ObjectId(0),
        spec: CpuBudgetSpec {
            maximum_parallelism: 1,
            runtime_micros: 1,
            period_micros: 1,
            priority_ceiling: 0,
            affinity_mask: 1,
        },
        reserved_parallelism: 0,
        active_reservations: 0,
        occupied: false,
    };
}

#[derive(Clone, Copy)]
struct ReservationEntry {
    generation: u32,
    budget: CpuBudgetId,
    domain: ObjectId,
    parallelism: u16,
    occupied: bool,
}

impl ReservationEntry {
    const EMPTY: Self = Self {
        generation: 1,
        budget: CpuBudgetId {
            slot: 0,
            generation: 0,
        },
        domain: ObjectId(0),
        parallelism: 0,
        occupied: false,
    };
}

pub struct CpuBudgetTable<const B: usize, const R: usize> {
    namespace: u16,
    budgets: [BudgetEntry; B],
    reservations: [ReservationEntry; R],
}

impl<const B: usize, const R: usize> CpuBudgetTable<B, R> {
    pub fn new(namespace: u16) -> Result<Self, CpuResourceError> {
        if namespace == 0
            || namespace > 0x3fff
            || B == 0
            || R == 0
            || B > u16::MAX as usize
            || R > u16::MAX as usize
        {
            return Err(CpuResourceError::InvalidNamespace);
        }
        Ok(Self {
            namespace,
            budgets: array::from_fn(|_| BudgetEntry::EMPTY),
            reservations: array::from_fn(|_| ReservationEntry::EMPTY),
        })
    }

    pub fn create_root<const C: usize>(
        &mut self,
        spec: CpuBudgetSpec,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<(CpuBudgetId, Capability), CpuResourceError> {
        let slot = self
            .budgets
            .iter()
            .position(|entry| !entry.occupied)
            .ok_or(CpuResourceError::CapacityExhausted)?;
        let generation = self.budgets[slot].generation;
        let id = CpuBudgetId {
            slot: slot as u16,
            generation,
        };
        let authority = self.budget_authority(id)?;
        let capability = capabilities.insert(authority, CPU_BUDGET_RIGHTS)?;
        self.budgets[slot] = BudgetEntry {
            generation,
            authority,
            spec,
            reserved_parallelism: 0,
            active_reservations: 0,
            occupied: true,
        };
        Ok((id, capability))
    }

    pub fn reserve_vcpus<const C: usize>(
        &mut self,
        budget: CpuBudgetId,
        capability: Capability,
        domain: ObjectId,
        parallelism: u16,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<VcpuReservationId, CpuResourceError> {
        if parallelism == 0 {
            return Err(CpuResourceError::InvalidReservation);
        }
        let entry = *self.budget(budget)?;
        if capabilities.authorize(capability, Rights::ALLOCATE)? != entry.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        if self.reservations.iter().any(|reservation| {
            reservation.occupied && reservation.budget == budget && reservation.domain == domain
        }) {
            return Err(CpuResourceError::DuplicateDomain);
        }
        let next_parallelism = entry
            .reserved_parallelism
            .checked_add(parallelism)
            .ok_or(CpuResourceError::Arithmetic)?;
        if next_parallelism > entry.spec.maximum_parallelism {
            return Err(CpuResourceError::ParallelismExhausted);
        }
        let slot = self
            .reservations
            .iter()
            .position(|reservation| !reservation.occupied)
            .ok_or(CpuResourceError::CapacityExhausted)?;
        let generation = self.reservations[slot].generation;
        let next_count = entry
            .active_reservations
            .checked_add(1)
            .ok_or(CpuResourceError::Arithmetic)?;
        let budget_mut = self.budget_mut(budget)?;
        budget_mut.reserved_parallelism = next_parallelism;
        budget_mut.active_reservations = next_count;
        self.reservations[slot] = ReservationEntry {
            generation,
            budget,
            domain,
            parallelism,
            occupied: true,
        };
        Ok(VcpuReservationId {
            slot: slot as u16,
            generation,
        })
    }

    pub fn release_vcpus<const C: usize>(
        &mut self,
        reservation: VcpuReservationId,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<u16, CpuResourceError> {
        let slot = reservation.slot as usize;
        let entry = *self
            .reservations
            .get(slot)
            .filter(|entry| entry.occupied && entry.generation == reservation.generation)
            .ok_or(CpuResourceError::InvalidReservation)?;
        let budget = *self.budget(entry.budget)?;
        if capabilities.authorize(capability, Rights::CONTROL)? != budget.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let next_generation = entry
            .generation
            .checked_add(1)
            .ok_or(CpuResourceError::GenerationExhausted)?;
        let budget_mut = self.budget_mut(entry.budget)?;
        budget_mut.reserved_parallelism = budget_mut
            .reserved_parallelism
            .checked_sub(entry.parallelism)
            .ok_or(CpuResourceError::Arithmetic)?;
        budget_mut.active_reservations = budget_mut
            .active_reservations
            .checked_sub(1)
            .ok_or(CpuResourceError::Arithmetic)?;
        self.reservations[slot] = ReservationEntry {
            generation: next_generation,
            ..ReservationEntry::EMPTY
        };
        Ok(entry.parallelism)
    }

    pub fn usage<const C: usize>(
        &self,
        budget: CpuBudgetId,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<CpuBudgetUsage, CpuResourceError> {
        let entry = *self.budget(budget)?;
        if capabilities.authorize(capability, Rights::INSPECT)? != entry.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        Ok(CpuBudgetUsage {
            spec: entry.spec,
            reserved_parallelism: entry.reserved_parallelism,
            active_reservations: entry.active_reservations,
        })
    }

    pub fn retire_root<const C: usize>(
        &mut self,
        budget: CpuBudgetId,
        capability: Capability,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<(), CpuResourceError> {
        let entry = *self.budget(budget)?;
        if entry.active_reservations != 0 {
            return Err(CpuResourceError::ReservationsActive);
        }
        if capabilities.authorize(capability, Rights::CONTROL)? != entry.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let generation = entry
            .generation
            .checked_add(1)
            .ok_or(CpuResourceError::GenerationExhausted)?;
        capabilities.revoke(capability)?;
        self.budgets[budget.slot as usize] = BudgetEntry {
            generation,
            ..BudgetEntry::EMPTY
        };
        Ok(())
    }

    fn budget(&self, id: CpuBudgetId) -> Result<&BudgetEntry, CpuResourceError> {
        self.budgets
            .get(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(CpuResourceError::InvalidBudget)
    }

    fn budget_mut(&mut self, id: CpuBudgetId) -> Result<&mut BudgetEntry, CpuResourceError> {
        self.budgets
            .get_mut(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(CpuResourceError::InvalidBudget)
    }

    fn budget_authority(&self, id: CpuBudgetId) -> Result<ObjectId, CpuResourceError> {
        if id.generation == 0 {
            return Err(CpuResourceError::InvalidBudget);
        }
        if id.generation == u32::MAX {
            return Err(CpuResourceError::GenerationExhausted);
        }
        let slot = u64::from(id.slot)
            .checked_add(1)
            .ok_or(CpuResourceError::Arithmetic)?;
        Ok(ObjectId(
            (1_u64 << 62)
                | (u64::from(self.namespace) << 48)
                | (u64::from(id.generation) << 16)
                | slot,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(parallelism: u16) -> CpuBudgetSpec {
        CpuBudgetSpec::new(parallelism, 5_000, 10_000, 7, 0b11).unwrap()
    }

    #[test]
    fn exact_vcpu_reservation_is_bounded_and_reclaimable() {
        let mut capabilities = CapabilitySpace::<2>::new();
        let mut table = CpuBudgetTable::<1, 2>::new(1).unwrap();
        let (budget, capability) = table.create_root(spec(2), &mut capabilities).unwrap();
        let first = table
            .reserve_vcpus(budget, capability, ObjectId(10), 1, &capabilities)
            .unwrap();
        let second = table
            .reserve_vcpus(budget, capability, ObjectId(11), 1, &capabilities)
            .unwrap();
        let usage = table.usage(budget, capability, &capabilities).unwrap();
        assert_eq!(usage.reserved_parallelism(), 2);
        assert_eq!(usage.active_reservations(), 2);
        assert_eq!(
            table.reserve_vcpus(budget, capability, ObjectId(12), 1, &capabilities),
            Err(CpuResourceError::ParallelismExhausted)
        );
        assert_eq!(table.release_vcpus(first, capability, &capabilities), Ok(1));
        assert_eq!(
            table.release_vcpus(second, capability, &capabilities),
            Ok(1)
        );
        assert_eq!(
            table.retire_root(budget, capability, &mut capabilities),
            Ok(())
        );
    }

    #[test]
    fn stale_duplicate_and_wrong_authority_fail_without_mutation() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let mut table = CpuBudgetTable::<1, 1>::new(2).unwrap();
        let (budget, capability) = table.create_root(spec(1), &mut capabilities).unwrap();
        let wrong = capabilities
            .insert(ObjectId(99), CPU_BUDGET_RIGHTS)
            .unwrap();
        assert_eq!(
            table.reserve_vcpus(budget, wrong, ObjectId(20), 1, &capabilities),
            Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied
            ))
        );
        let reservation = table
            .reserve_vcpus(budget, capability, ObjectId(20), 1, &capabilities)
            .unwrap();
        assert_eq!(
            table.reserve_vcpus(budget, capability, ObjectId(20), 1, &capabilities),
            Err(CpuResourceError::DuplicateDomain)
        );
        assert_eq!(
            table.retire_root(budget, capability, &mut capabilities),
            Err(CpuResourceError::ReservationsActive)
        );
        table
            .release_vcpus(reservation, capability, &capabilities)
            .unwrap();
        assert_eq!(
            table.release_vcpus(reservation, capability, &capabilities),
            Err(CpuResourceError::InvalidReservation)
        );
        let usage = table.usage(budget, capability, &capabilities).unwrap();
        assert_eq!(usage.reserved_parallelism(), 0);
        assert_eq!(usage.active_reservations(), 0);
    }

    #[test]
    fn invalid_budget_shapes_fail_closed() {
        assert_eq!(
            CpuBudgetSpec::new(0, 1, 1, 0, 1),
            Err(CpuResourceError::InvalidBudget)
        );
        assert_eq!(
            CpuBudgetSpec::new(1, 2, 1, 0, 1),
            Err(CpuResourceError::InvalidBudget)
        );
        assert_eq!(
            CpuBudgetSpec::new(1, 1, 1, 0, 0),
            Err(CpuResourceError::InvalidBudget)
        );
    }
}
