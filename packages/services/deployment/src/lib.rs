#![no_std]

//! Bounded SystemGeneration candidate and activation control plane.
//!
//! Generation numbers, digests, and storage identities are data. Only an exact
//! live capability for the service root authorizes staging, activation, or
//! inspection. Activation is a two-phase, one-use transaction; stale tokens
//! never select or resurrect a generation.

use core::array;

use mrml_kernel::{Capability, CapabilitySpace, ObjectId, Rights};
use mrml_package_format::{ActivatedSystemGeneration, ActivatedSystemGenerationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCandidate {
    generation: u64,
    generation_digest: [u8; 64],
    source_object: u64,
    source_generation: u64,
}

impl GenerationCandidate {
    pub const fn new(
        generation: u64,
        generation_digest: [u8; 64],
        source_object: u64,
        source_generation: u64,
    ) -> Result<Self, DeploymentError> {
        if generation == 0 || source_generation == 0 {
            return Err(DeploymentError::InvalidGeneration);
        }
        if source_object == 0 {
            return Err(DeploymentError::InvalidSource);
        }
        if all_zero(&generation_digest) {
            return Err(DeploymentError::InvalidDigest);
        }
        Ok(Self {
            generation,
            generation_digest,
            source_object,
            source_generation,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateId {
    slot: u16,
    slot_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedActivation {
    candidate: CandidateId,
    expected_activation_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateState {
    Staged,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateSlot {
    slot_generation: u64,
    state: CandidateState,
    candidate: GenerationCandidate,
}

pub struct DeploymentService<const CANDIDATES: usize> {
    root: ObjectId,
    active: Option<ActivatedSystemGeneration>,
    candidates: [Option<CandidateSlot>; CANDIDATES],
    next_slot_generation: u64,
    next_activation_sequence: u64,
}

impl<const CANDIDATES: usize> DeploymentService<CANDIDATES> {
    pub fn new(root: ObjectId) -> Result<Self, DeploymentError> {
        if root.0 == 0 || CANDIDATES == 0 || CANDIDATES > u16::MAX as usize {
            return Err(DeploymentError::InvalidService);
        }
        Ok(Self {
            root,
            active: None,
            candidates: array::from_fn(|_| None),
            next_slot_generation: 1,
            next_activation_sequence: 1,
        })
    }

    pub fn stage<const N: usize>(
        &mut self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        candidate: GenerationCandidate,
    ) -> Result<CandidateId, DeploymentError> {
        self.authorize(capabilities, control, Rights::CONTROL)?;
        if self
            .active
            .is_some_and(|active| candidate.generation <= active.generation())
        {
            return Err(DeploymentError::RollbackRequiresSeparateAuthorization);
        }
        if self.candidates.iter().flatten().any(|slot| {
            slot.candidate.generation == candidate.generation
                || slot.candidate.generation_digest == candidate.generation_digest
        }) {
            return Err(DeploymentError::DuplicateCandidate);
        }
        let slot = self
            .candidates
            .iter()
            .position(Option::is_none)
            .ok_or(DeploymentError::Capacity)?;
        let slot_generation = self.next_slot_generation;
        self.next_slot_generation = slot_generation
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        self.candidates[slot] = Some(CandidateSlot {
            slot_generation,
            state: CandidateState::Staged,
            candidate,
        });
        Ok(CandidateId {
            slot: slot as u16,
            slot_generation,
        })
    }

    pub fn prepare_activation<const N: usize>(
        &mut self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        candidate: CandidateId,
        expected_active: Option<(u64, u64)>,
    ) -> Result<PreparedActivation, DeploymentError> {
        self.authorize(capabilities, control, Rights::CONTROL)?;
        let actual_active = self
            .active
            .map(|active| (active.generation(), active.activation_sequence()));
        if actual_active != expected_active {
            return Err(DeploymentError::StaleActiveGeneration);
        }
        let slot = self.slot_mut(candidate)?;
        if slot.state != CandidateState::Staged {
            return Err(DeploymentError::InvalidCandidate);
        }
        slot.state = CandidateState::Prepared;
        Ok(PreparedActivation {
            candidate,
            expected_activation_sequence: self.next_activation_sequence,
        })
    }

    pub fn commit_activation(
        &mut self,
        prepared: PreparedActivation,
    ) -> Result<ActivatedSystemGeneration, DeploymentError> {
        if prepared.expected_activation_sequence != self.next_activation_sequence {
            return Err(DeploymentError::StaleActivation);
        }
        let slot_index = prepared.candidate.slot as usize;
        let slot = self.slot(prepared.candidate)?;
        if slot.state != CandidateState::Prepared {
            return Err(DeploymentError::InvalidCandidate);
        }
        let candidate = slot.candidate;
        let active = ActivatedSystemGeneration::new(
            candidate.generation,
            candidate.generation_digest,
            self.next_activation_sequence,
            candidate.source_object,
            candidate.source_generation,
        )
        .map_err(DeploymentError::InvalidActivation)?;
        self.next_activation_sequence = self
            .next_activation_sequence
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        self.candidates[slot_index] = None;
        self.active = Some(active);
        Ok(active)
    }

    pub fn active<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        inspect: Capability,
    ) -> Result<Option<ActivatedSystemGeneration>, DeploymentError> {
        self.authorize(capabilities, inspect, Rights::READ)?;
        Ok(self.active)
    }

    fn authorize<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        capability: Capability,
        rights: Rights,
    ) -> Result<(), DeploymentError> {
        if capabilities.authorize(capability, rights).ok() != Some(self.root) {
            return Err(DeploymentError::Unauthorized);
        }
        Ok(())
    }

    fn slot(&self, candidate: CandidateId) -> Result<&CandidateSlot, DeploymentError> {
        self.candidates
            .get(candidate.slot as usize)
            .and_then(Option::as_ref)
            .filter(|slot| slot.slot_generation == candidate.slot_generation)
            .ok_or(DeploymentError::InvalidCandidate)
    }

    fn slot_mut(&mut self, candidate: CandidateId) -> Result<&mut CandidateSlot, DeploymentError> {
        self.candidates
            .get_mut(candidate.slot as usize)
            .and_then(Option::as_mut)
            .filter(|slot| slot.slot_generation == candidate.slot_generation)
            .ok_or(DeploymentError::InvalidCandidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentError {
    InvalidService,
    InvalidGeneration,
    InvalidDigest,
    InvalidSource,
    Unauthorized,
    Capacity,
    DuplicateCandidate,
    InvalidCandidate,
    StaleActiveGeneration,
    StaleActivation,
    RollbackRequiresSeparateAuthorization,
    GenerationExhausted,
    InvalidActivation(ActivatedSystemGenerationError),
}

const fn all_zero(value: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> (CapabilitySpace<3>, Capability, Capability) {
        let mut capabilities = CapabilitySpace::new();
        let control = capabilities
            .insert(ObjectId(0x4445_504c_4f59), Rights::CONTROL)
            .unwrap();
        let inspect = capabilities
            .insert(ObjectId(0x4445_504c_4f59), Rights::READ)
            .unwrap();
        (capabilities, control, inspect)
    }

    fn candidate(generation: u64, marker: u8) -> GenerationCandidate {
        GenerationCandidate::new(generation, [marker; 64], 0x700, generation + 10).unwrap()
    }

    #[test]
    fn activation_is_capability_authorized_two_phase_and_one_use() {
        let (capabilities, control, inspect) = authority();
        let mut service = DeploymentService::<2>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        assert_eq!(service.active(&capabilities, inspect), Ok(None));
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let active = service.commit_activation(prepared).unwrap();
        assert_eq!(active.generation(), 8);
        assert_eq!(active.generation_digest(), &[0x51; 64]);
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(active)));
        assert_eq!(
            service.commit_activation(prepared),
            Err(DeploymentError::StaleActivation)
        );
    }

    #[test]
    fn stale_authority_candidate_and_active_state_fail_without_activation() {
        let (mut capabilities, control, inspect) = authority();
        let wrong = capabilities.insert(ObjectId(9), Rights::CONTROL).unwrap();
        let mut service = DeploymentService::<2>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        assert_eq!(
            service.stage(&capabilities, wrong, candidate(8, 0x51)),
            Err(DeploymentError::Unauthorized)
        );
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        assert_eq!(
            service.prepare_activation(&capabilities, control, id, Some((7, 1))),
            Err(DeploymentError::StaleActiveGeneration)
        );
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let active = service.commit_activation(prepared).unwrap();
        assert_eq!(
            service.stage(&capabilities, control, candidate(7, 0x50)),
            Err(DeploymentError::RollbackRequiresSeparateAuthorization)
        );
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(active)));
    }
}
