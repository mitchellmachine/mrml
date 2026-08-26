use core::array;

use crate::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const CPU_BUDGET_RIGHTS: Rights = Rights::ALLOCATE
    .union(Rights::CONTROL)
    .union(Rights::INSPECT)
    .union(Rights::DELEGATE)
    .union(Rights::EXECUTE);

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
    runtime_period_start_micros: Option<u64>,
    consumed_runtime_micros: u32,
    in_flight_slices: u16,
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

    pub const fn runtime_period_start_micros(self) -> Option<u64> {
        self.runtime_period_start_micros
    }

    pub const fn consumed_runtime_micros(self) -> u32 {
        self.consumed_runtime_micros
    }

    pub const fn in_flight_slices(self) -> u16 {
        self.in_flight_slices
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuRuntimeSlice {
    reservation: VcpuReservationId,
    domain: ObjectId,
    vcpu_index: u16,
    logical_cpu: u8,
    priority: u8,
    charged_micros: u32,
    slice_start_micros: u64,
    remaining_micros: u32,
    period_end_micros: u64,
}

impl CpuRuntimeSlice {
    pub const fn reservation(self) -> VcpuReservationId {
        self.reservation
    }

    pub const fn domain(&self) -> ObjectId {
        self.domain
    }

    pub const fn vcpu_index(&self) -> u16 {
        self.vcpu_index
    }

    pub const fn logical_cpu(&self) -> u8 {
        self.logical_cpu
    }

    pub const fn priority(&self) -> u8 {
        self.priority
    }

    pub const fn charged_micros(self) -> u32 {
        self.charged_micros
    }

    pub const fn slice_start_micros(self) -> u64 {
        self.slice_start_micros
    }

    pub const fn remaining_micros(self) -> u32 {
        self.remaining_micros
    }

    pub const fn period_end_micros(self) -> u64 {
        self.period_end_micros
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuRuntimeReconciliation {
    actual_micros: u32,
    refunded_micros: u32,
    consumed_runtime_micros: u32,
}

impl CpuRuntimeReconciliation {
    pub const fn actual_micros(self) -> u32 {
        self.actual_micros
    }

    pub const fn refunded_micros(self) -> u32 {
        self.refunded_micros
    }

    pub const fn consumed_runtime_micros(self) -> u32 {
        self.consumed_runtime_micros
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
    RuntimeAlreadyStarted,
    RuntimeNotStarted,
    RuntimeSliceInFlight,
    RuntimeSliceMissing,
    RuntimeSliceMismatch,
    RuntimeOverrun,
    RuntimeExhausted,
    TimeRegression,
    SliceCrossesPeriod,
    VcpuOutsideReservation,
    AffinityDenied,
    PriorityDenied,
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
    runtime_period_start_micros: Option<u64>,
    consumed_runtime_micros: u32,
    in_flight_slices: u16,
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
        runtime_period_start_micros: None,
        consumed_runtime_micros: 0,
        in_flight_slices: 0,
        occupied: false,
    };
}

#[derive(Clone, Copy)]
struct ReservationEntry {
    generation: u32,
    budget: CpuBudgetId,
    domain: ObjectId,
    parallelism: u16,
    runtime_slice_start_micros: u64,
    runtime_slice_charged_micros: u32,
    runtime_slice_in_flight: bool,
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
        runtime_slice_start_micros: 0,
        runtime_slice_charged_micros: 0,
        runtime_slice_in_flight: false,
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
            runtime_period_start_micros: None,
            consumed_runtime_micros: 0,
            in_flight_slices: 0,
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
            runtime_slice_start_micros: 0,
            runtime_slice_charged_micros: 0,
            runtime_slice_in_flight: false,
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
        if entry.runtime_slice_in_flight {
            return Err(CpuResourceError::RuntimeSliceInFlight);
        }
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

    pub fn start_runtime_period<const C: usize>(
        &mut self,
        reservation: VcpuReservationId,
        capability: Capability,
        period_start_micros: u64,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), CpuResourceError> {
        let reservation_id = reservation;
        let reservation = self.reservation(reservation_id)?;
        let budget = *self.budget(reservation.budget)?;
        if capabilities.authorize(capability, Rights::EXECUTE)? != budget.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        if budget.runtime_period_start_micros.is_some() {
            return Err(CpuResourceError::RuntimeAlreadyStarted);
        }
        if budget.in_flight_slices != 0 {
            return Err(CpuResourceError::RuntimeSliceInFlight);
        }
        let budget = self.budget_mut(reservation.budget)?;
        budget.runtime_period_start_micros = Some(period_start_micros);
        budget.consumed_runtime_micros = 0;
        Ok(())
    }

    /// Charges one scheduler-authorized maximum runtime slice before vCPU entry.
    /// All reservations under a budget consume the same period allowance, so
    /// additional parallel reservations cannot amplify CPU time authority.
    pub fn authorize_runtime_slice<const C: usize>(
        &mut self,
        reservation: VcpuReservationId,
        capability: Capability,
        vcpu_index: u16,
        logical_cpu: u8,
        priority: u8,
        slice_start_micros: u64,
        slice_micros: u32,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<CpuRuntimeSlice, CpuResourceError> {
        if slice_micros == 0 {
            return Err(CpuResourceError::InvalidReservation);
        }
        let reservation_id = reservation;
        let reservation = self.reservation(reservation_id)?;
        if reservation.runtime_slice_in_flight {
            return Err(CpuResourceError::RuntimeSliceInFlight);
        }
        let budget = *self.budget(reservation.budget)?;
        if capabilities.authorize(capability, Rights::EXECUTE)? != budget.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        if vcpu_index >= reservation.parallelism {
            return Err(CpuResourceError::VcpuOutsideReservation);
        }
        let affinity_bit = 1_u64
            .checked_shl(u32::from(logical_cpu))
            .ok_or(CpuResourceError::AffinityDenied)?;
        if budget.spec.affinity_mask & affinity_bit == 0 {
            return Err(CpuResourceError::AffinityDenied);
        }
        if priority > budget.spec.priority_ceiling {
            return Err(CpuResourceError::PriorityDenied);
        }
        let mut period_start = budget
            .runtime_period_start_micros
            .ok_or(CpuResourceError::RuntimeNotStarted)?;
        if slice_start_micros < period_start {
            return Err(CpuResourceError::TimeRegression);
        }
        let period = u64::from(budget.spec.period_micros);
        let elapsed_periods = (slice_start_micros - period_start) / period;
        let mut consumed = budget.consumed_runtime_micros;
        if elapsed_periods != 0 {
            if budget.in_flight_slices != 0 {
                return Err(CpuResourceError::RuntimeSliceInFlight);
            }
            period_start = period_start
                .checked_add(
                    elapsed_periods
                        .checked_mul(period)
                        .ok_or(CpuResourceError::Arithmetic)?,
                )
                .ok_or(CpuResourceError::Arithmetic)?;
            consumed = 0;
        }
        let period_end = period_start
            .checked_add(period)
            .ok_or(CpuResourceError::Arithmetic)?;
        let slice_end = slice_start_micros
            .checked_add(u64::from(slice_micros))
            .ok_or(CpuResourceError::Arithmetic)?;
        if slice_end > period_end {
            return Err(CpuResourceError::SliceCrossesPeriod);
        }
        let next_consumed = consumed
            .checked_add(slice_micros)
            .ok_or(CpuResourceError::Arithmetic)?;
        if next_consumed > budget.spec.runtime_micros {
            return Err(CpuResourceError::RuntimeExhausted);
        }
        {
            let budget_mut = self.budget_mut(reservation.budget)?;
            budget_mut.runtime_period_start_micros = Some(period_start);
            budget_mut.consumed_runtime_micros = next_consumed;
            budget_mut.in_flight_slices = budget_mut
                .in_flight_slices
                .checked_add(1)
                .ok_or(CpuResourceError::Arithmetic)?;
        }
        let reservation_mut = self
            .reservations
            .get_mut(reservation_id.slot as usize)
            .ok_or(CpuResourceError::InvalidReservation)?;
        reservation_mut.runtime_slice_start_micros = slice_start_micros;
        reservation_mut.runtime_slice_charged_micros = slice_micros;
        reservation_mut.runtime_slice_in_flight = true;
        Ok(CpuRuntimeSlice {
            reservation: reservation_id,
            domain: reservation.domain,
            vcpu_index,
            logical_cpu,
            priority,
            charged_micros: slice_micros,
            slice_start_micros,
            remaining_micros: budget.spec.runtime_micros - next_consumed,
            period_end_micros: period_end,
        })
    }

    /// Reconciles one precharged slice exactly once. An overrun retains the
    /// complete precharge and fails closed; only a bounded verified underrun is
    /// refunded to the shared period allowance.
    pub fn reconcile_runtime_slice<const C: usize>(
        &mut self,
        slice: CpuRuntimeSlice,
        capability: Capability,
        slice_end_micros: u64,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<CpuRuntimeReconciliation, CpuResourceError> {
        let slot = slice.reservation.slot as usize;
        let reservation = *self
            .reservations
            .get(slot)
            .filter(|entry| entry.occupied && entry.generation == slice.reservation.generation)
            .ok_or(CpuResourceError::InvalidReservation)?;
        let budget = *self.budget(reservation.budget)?;
        if capabilities.authorize(capability, Rights::EXECUTE)? != budget.authority {
            return Err(CpuResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        if !reservation.runtime_slice_in_flight {
            return Err(CpuResourceError::RuntimeSliceMissing);
        }
        if slice.domain != reservation.domain
            || slice.slice_start_micros != reservation.runtime_slice_start_micros
            || slice.charged_micros != reservation.runtime_slice_charged_micros
        {
            return Err(CpuResourceError::RuntimeSliceMismatch);
        }
        let actual = slice_end_micros
            .checked_sub(slice.slice_start_micros)
            .ok_or(CpuResourceError::TimeRegression)?;
        let actual_fits = u32::try_from(actual).ok();
        let actual = actual_fits.unwrap_or(u32::MAX);
        let overrun = actual_fits.is_none()
            || actual > slice.charged_micros
            || slice_end_micros > slice.period_end_micros;
        let refund = if overrun {
            0
        } else {
            slice.charged_micros - actual
        };
        let consumed_runtime_micros = {
            let budget_mut = self.budget_mut(reservation.budget)?;
            budget_mut.consumed_runtime_micros = budget_mut
                .consumed_runtime_micros
                .checked_sub(refund)
                .ok_or(CpuResourceError::Arithmetic)?;
            budget_mut.in_flight_slices = budget_mut
                .in_flight_slices
                .checked_sub(1)
                .ok_or(CpuResourceError::Arithmetic)?;
            budget_mut.consumed_runtime_micros
        };
        let reservation_mut = &mut self.reservations[slot];
        reservation_mut.runtime_slice_start_micros = 0;
        reservation_mut.runtime_slice_charged_micros = 0;
        reservation_mut.runtime_slice_in_flight = false;
        if overrun {
            return Err(CpuResourceError::RuntimeOverrun);
        }
        Ok(CpuRuntimeReconciliation {
            actual_micros: actual,
            refunded_micros: refund,
            consumed_runtime_micros,
        })
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
            runtime_period_start_micros: entry.runtime_period_start_micros,
            consumed_runtime_micros: entry.consumed_runtime_micros,
            in_flight_slices: entry.in_flight_slices,
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

    fn reservation(&self, id: VcpuReservationId) -> Result<ReservationEntry, CpuResourceError> {
        self.reservations
            .get(id.slot as usize)
            .copied()
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(CpuResourceError::InvalidReservation)
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

    fn charge<const R: usize>(
        table: &mut CpuBudgetTable<1, R>,
        reservation: VcpuReservationId,
        capability: Capability,
        start: u64,
        micros: u32,
        capabilities: &CapabilitySpace<1>,
    ) -> Result<CpuRuntimeSlice, CpuResourceError> {
        let slice = table.authorize_runtime_slice(
            reservation,
            capability,
            0,
            0,
            0,
            start,
            micros,
            capabilities,
        )?;
        table.reconcile_runtime_slice(
            slice,
            capability,
            start + u64::from(micros),
            capabilities,
        )?;
        Ok(slice)
    }

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

    #[test]
    fn runtime_slices_are_precharged_bounded_and_periodic() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let mut table = CpuBudgetTable::<1, 1>::new(3).unwrap();
        let (budget, capability) = table.create_root(spec(1), &mut capabilities).unwrap();
        let reservation = table
            .reserve_vcpus(budget, capability, ObjectId(30), 1, &capabilities)
            .unwrap();
        assert_eq!(
            charge(&mut table, reservation, capability, 100, 1, &capabilities),
            Err(CpuResourceError::RuntimeNotStarted)
        );
        table
            .start_runtime_period(reservation, capability, 100, &capabilities)
            .unwrap();
        assert_eq!(
            table.start_runtime_period(reservation, capability, 100, &capabilities),
            Err(CpuResourceError::RuntimeAlreadyStarted)
        );
        assert_eq!(
            table.authorize_runtime_slice(reservation, capability, 1, 0, 0, 100, 1, &capabilities,),
            Err(CpuResourceError::VcpuOutsideReservation)
        );
        assert_eq!(
            table.authorize_runtime_slice(reservation, capability, 0, 2, 0, 100, 1, &capabilities,),
            Err(CpuResourceError::AffinityDenied)
        );
        assert_eq!(
            table.authorize_runtime_slice(reservation, capability, 0, 0, 8, 100, 1, &capabilities,),
            Err(CpuResourceError::PriorityDenied)
        );
        assert_eq!(
            table
                .usage(budget, capability, &capabilities)
                .unwrap()
                .consumed_runtime_micros(),
            0
        );
        let first = charge(
            &mut table,
            reservation,
            capability,
            100,
            3_000,
            &capabilities,
        )
        .unwrap();
        assert_eq!(first.charged_micros(), 3_000);
        assert_eq!(first.domain(), ObjectId(30));
        assert_eq!(first.vcpu_index(), 0);
        assert_eq!(first.logical_cpu(), 0);
        assert_eq!(first.priority(), 0);
        assert_eq!(first.remaining_micros(), 2_000);
        assert_eq!(first.period_end_micros(), 10_100);
        assert_eq!(
            charge(
                &mut table,
                reservation,
                capability,
                3_100,
                2_001,
                &capabilities,
            ),
            Err(CpuResourceError::RuntimeExhausted)
        );
        assert_eq!(
            charge(
                &mut table,
                reservation,
                capability,
                10_099,
                2,
                &capabilities,
            ),
            Err(CpuResourceError::SliceCrossesPeriod)
        );
        let next = charge(
            &mut table,
            reservation,
            capability,
            10_100,
            5_000,
            &capabilities,
        )
        .unwrap();
        assert_eq!(next.remaining_micros(), 0);
        assert_eq!(next.period_end_micros(), 20_100);
        let usage = table.usage(budget, capability, &capabilities).unwrap();
        assert_eq!(usage.runtime_period_start_micros(), Some(10_100));
        assert_eq!(usage.consumed_runtime_micros(), 5_000);
        assert_eq!(
            charge(
                &mut table,
                reservation,
                capability,
                10_099,
                1,
                &capabilities,
            ),
            Err(CpuResourceError::TimeRegression)
        );
    }

    #[test]
    fn parallel_reservations_share_one_runtime_allowance() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let mut table = CpuBudgetTable::<1, 2>::new(4).unwrap();
        let (budget, capability) = table.create_root(spec(2), &mut capabilities).unwrap();
        let first = table
            .reserve_vcpus(budget, capability, ObjectId(40), 1, &capabilities)
            .unwrap();
        let second = table
            .reserve_vcpus(budget, capability, ObjectId(41), 1, &capabilities)
            .unwrap();
        table
            .start_runtime_period(first, capability, 0, &capabilities)
            .unwrap();
        charge(&mut table, first, capability, 0, 4_000, &capabilities).unwrap();
        assert_eq!(
            charge(&mut table, second, capability, 4_000, 1_001, &capabilities,),
            Err(CpuResourceError::RuntimeExhausted)
        );
        assert_eq!(
            charge(&mut table, second, capability, 4_000, 1_000, &capabilities,)
                .unwrap()
                .remaining_micros(),
            0
        );
    }

    #[test]
    fn runtime_reconciliation_is_linear_refunds_underrun_and_retains_overrun_charge() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let mut table = CpuBudgetTable::<1, 1>::new(5).unwrap();
        let (budget, capability) = table.create_root(spec(1), &mut capabilities).unwrap();
        let reservation = table
            .reserve_vcpus(budget, capability, ObjectId(50), 1, &capabilities)
            .unwrap();
        table
            .start_runtime_period(reservation, capability, 100, &capabilities)
            .unwrap();
        let slice = table
            .authorize_runtime_slice(reservation, capability, 0, 0, 0, 100, 3_000, &capabilities)
            .unwrap();
        assert_eq!(
            table.release_vcpus(reservation, capability, &capabilities),
            Err(CpuResourceError::RuntimeSliceInFlight)
        );
        let mut substituted = slice;
        substituted.charged_micros += 1;
        assert_eq!(
            table.reconcile_runtime_slice(substituted, capability, 1_100, &capabilities),
            Err(CpuResourceError::RuntimeSliceMismatch)
        );
        let reconciled = table
            .reconcile_runtime_slice(slice, capability, 1_100, &capabilities)
            .unwrap();
        assert_eq!(reconciled.actual_micros(), 1_000);
        assert_eq!(reconciled.refunded_micros(), 2_000);
        assert_eq!(reconciled.consumed_runtime_micros(), 1_000);
        assert_eq!(
            table.reconcile_runtime_slice(slice, capability, 1_100, &capabilities),
            Err(CpuResourceError::RuntimeSliceMissing)
        );
        let overrun = table
            .authorize_runtime_slice(
                reservation,
                capability,
                0,
                0,
                0,
                1_100,
                4_000,
                &capabilities,
            )
            .unwrap();
        assert_eq!(
            table.reconcile_runtime_slice(overrun, capability, 5_101, &capabilities),
            Err(CpuResourceError::RuntimeOverrun)
        );
        let usage = table.usage(budget, capability, &capabilities).unwrap();
        assert_eq!(usage.consumed_runtime_micros(), 5_000);
        assert_eq!(usage.in_flight_slices(), 0);
        let oversized_elapsed = table
            .authorize_runtime_slice(
                reservation,
                capability,
                0,
                0,
                0,
                10_100,
                1_000,
                &capabilities,
            )
            .unwrap();
        assert_eq!(
            table.reconcile_runtime_slice(
                oversized_elapsed,
                capability,
                10_100 + u64::from(u32::MAX) + 1,
                &capabilities,
            ),
            Err(CpuResourceError::RuntimeOverrun)
        );
        let usage = table.usage(budget, capability, &capabilities).unwrap();
        assert_eq!(usage.consumed_runtime_micros(), 1_000);
        assert_eq!(usage.in_flight_slices(), 0);
        assert_eq!(
            table.release_vcpus(reservation, capability, &capabilities),
            Ok(1)
        );
    }
}
