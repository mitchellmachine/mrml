//! Executable model of the xHCI legacy ownership handshake (xHCI 1.2 §7.1).
//! This module is compiled only in tests. It cannot reset, program, or read
//! real hardware, grant a device assignment, or enable DMA.
use super::{
    LegacyOwnershipAcknowledgment, LegacyOwnershipPoll, LegacyOwnershipSequence, LegacySample,
    LegacyTransitionError, sample_legacy_ownership,
};

const FIRMWARE: u32 = 1 << 16;
const OS: u32 = 1 << 24;
const SEMAPHORES: u32 = FIRMWARE | OS;

#[derive(Clone, Copy)]
struct Prerequisites {
    exited_firmware: bool,
    source_closed: bool,
    same_lease: bool,
    dma_blocked: bool,
}

impl Prerequisites {
    const READY: Self = Self {
        exited_firmware: true,
        source_closed: true,
        same_lease: true,
        dma_blocked: true,
    };

    fn permit_request(self) -> bool {
        self.exited_firmware && self.source_closed && self.same_lease && self.dma_blocked
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Failure {
    Prerequisite,
    InitialOwner,
    ChangedCapability,
    ChangedLease,
    RequestLost,
    Timeout,
}

impl From<LegacyTransitionError> for Failure {
    fn from(value: LegacyTransitionError) -> Self {
        match value {
            LegacyTransitionError::InvalidInitialOwner => Self::InitialOwner,
            LegacyTransitionError::ChangedLease => Self::ChangedLease,
            LegacyTransitionError::ChangedCapability => Self::ChangedCapability,
            LegacyTransitionError::RequestLost => Self::RequestLost,
            LegacyTransitionError::Timeout => Self::Timeout,
        }
    }
}

#[derive(Clone, Copy)]
struct Sample {
    lease_generation: u64,
    hcc1: u32,
    offset: u32,
    raw: u32,
}

impl Sample {
    fn firmware(raw: u32) -> Self {
        Self {
            lease_generation: 1,
            hcc1: (0x90 / 4) << 16,
            offset: 0x90,
            raw: raw | 1,
        }
    }
}

struct Script<'a> {
    samples: &'a [Sample],
    observed: usize,
    request: Option<(u32, u8)>,
    at_request: Option<(Prerequisites, Sample)>,
    during_poll: Option<(usize, Prerequisites)>,
    at_accept: Option<(Prerequisites, Sample)>,
    accepted_generation: Option<u64>,
}

impl<'a> Script<'a> {
    fn new(samples: &'a [Sample]) -> Self {
        assert!(!samples.is_empty());
        Self {
            samples,
            observed: 0,
            request: None,
            at_request: None,
            during_poll: None,
            at_accept: None,
            accepted_generation: None,
        }
    }

    fn observe(&mut self) -> Result<(u64, LegacySample), Failure> {
        if self
            .during_poll
            .is_some_and(|(at, ready)| at == self.observed && !ready.permit_request())
        {
            return Err(Failure::Prerequisite);
        }
        let support = self.samples[self.observed.min(self.samples.len() - 1)];
        self.observed += 1;
        Self::decode(support)
    }

    fn decode(support: Sample) -> Result<(u64, LegacySample), Failure> {
        sample_legacy_ownership(0x200, |offset| match offset {
            0x10 => Ok(support.hcc1),
            offset if offset == support.offset => Ok(support.raw),
            _ => Err(Failure::ChangedCapability),
        })
        .map(|sample| (support.lease_generation, sample))
        .map_err(|_| Failure::ChangedCapability)
    }

    fn compare_and_request(
        &mut self,
        generation: u64,
        initial: LegacySample,
    ) -> Result<(), Failure> {
        // Model the compare and byte write under the same retained lease,
        // not another unlocked poll in the requester's loop.
        let (live_ready, sample) = self
            .at_request
            .unwrap_or((Prerequisites::READY, self.samples[0]));
        if !live_ready.permit_request() {
            return Err(Failure::Prerequisite);
        }
        let (live_generation, live) = Self::decode(sample)?;
        if live_generation != generation {
            return Err(Failure::ChangedLease);
        }
        if live != initial {
            return Err(Failure::ChangedCapability);
        }
        assert_eq!(
            self.request, None,
            "one request, with no retries or forced clear"
        );
        let (offset, _) = live.capability.ok_or(Failure::ChangedCapability)?;
        self.request = Some((offset + 3, 1));
        Ok(())
    }

    fn compare_and_accept(
        &mut self,
        acknowledged: LegacyOwnershipAcknowledgment,
    ) -> Result<(), Failure> {
        // The consuming owner rechecks the last acknowledged state and all
        // prerequisites under the same lease. A poll is not a transfer.
        let last = self.samples[(self.observed - 1).min(self.samples.len() - 1)];
        let (ready, sample) = self.at_accept.unwrap_or((Prerequisites::READY, last));
        if !ready.permit_request() {
            return Err(Failure::Prerequisite);
        }
        let (live_generation, live) = Self::decode(sample)?;
        self.accepted_generation = Some(acknowledged.finish(live_generation, live)?);
        Ok(())
    }
}

fn simulate(script: &mut Script<'_>, ready: Prerequisites) -> Result<(), Failure> {
    if !ready.permit_request() {
        return Err(Failure::Prerequisite);
    }
    let (generation, initial) = script.observe()?;
    let mut sequence = LegacyOwnershipSequence::begin(generation, initial)?;
    // The only modeled write is one byte to the OS-owned semaphore.
    script.compare_and_request(generation, initial)?;
    loop {
        let (live_generation, current) = script.observe()?;
        match sequence.poll(live_generation, current)? {
            LegacyOwnershipPoll::Pending(next) => sequence = next,
            LegacyOwnershipPoll::Acknowledged(seen) => return script.compare_and_accept(seen),
        }
    }
}

#[test]
fn model_accepts_stable_firmware_acknowledgment_after_one_os_byte_write() {
    let samples = [FIRMWARE, SEMAPHORES, SEMAPHORES, OS, OS].map(Sample::firmware);
    let mut script = Script::new(&samples);
    assert_eq!(simulate(&mut script, Prerequisites::READY), Ok(()));
    assert_eq!(script.request, Some((0x93, 1)));
    assert_eq!(script.observed, 5);
    assert_eq!(script.accepted_generation, Some(1));
}

#[test]
fn model_times_out_without_reasserting_or_clearing_firmware_ownership() {
    let samples = [FIRMWARE, SEMAPHORES].map(Sample::firmware);
    let mut script = Script::new(&samples);
    assert_eq!(
        simulate(&mut script, Prerequisites::READY),
        Err(Failure::Timeout)
    );
    assert_eq!(script.request, Some((0x93, 1)));
    assert_eq!(script.observed, 1 + 8);
    assert_eq!(script.accepted_generation, None);
}

#[test]
fn model_denies_non_quiescent_or_preclaimed_controller_without_writing() {
    for invalid in [
        Prerequisites {
            exited_firmware: false,
            ..Prerequisites::READY
        },
        Prerequisites {
            source_closed: false,
            ..Prerequisites::READY
        },
        Prerequisites {
            same_lease: false,
            ..Prerequisites::READY
        },
        Prerequisites {
            dma_blocked: false,
            ..Prerequisites::READY
        },
    ] {
        let samples = [Sample::firmware(FIRMWARE)];
        let mut script = Script::new(&samples);
        assert_eq!(simulate(&mut script, invalid), Err(Failure::Prerequisite));
        assert_eq!((script.request, script.observed), (None, 0));
    }
    for sample in [
        Sample::firmware(0),
        Sample::firmware(OS),
        Sample::firmware(SEMAPHORES),
        Sample {
            hcc1: 0,
            ..Sample::firmware(0)
        },
    ] {
        let samples = [sample];
        let mut script = Script::new(&samples);
        assert_eq!(
            simulate(&mut script, Prerequisites::READY),
            Err(Failure::InitialOwner)
        );
        assert_eq!((script.request, script.observed), (None, 1));
    }
}

#[test]
fn model_rejects_absent_changed_or_reclaimed_capability_after_request() {
    for (second, third, failure) in [
        (
            Sample::firmware(FIRMWARE),
            Sample::firmware(FIRMWARE),
            Failure::RequestLost,
        ),
        (
            Sample::firmware(0),
            Sample::firmware(0),
            Failure::RequestLost,
        ),
        (
            Sample::firmware(OS),
            Sample::firmware(SEMAPHORES),
            Failure::RequestLost,
        ),
        (
            Sample {
                hcc1: 0,
                ..Sample::firmware(OS)
            },
            Sample::firmware(OS),
            Failure::ChangedCapability,
        ),
        (
            Sample {
                hcc1: (0x94 / 4) << 16,
                offset: 0x94,
                ..Sample::firmware(OS)
            },
            Sample::firmware(OS),
            Failure::ChangedCapability,
        ),
        (
            Sample {
                raw: u32::MAX,
                ..Sample::firmware(OS)
            },
            Sample::firmware(OS),
            Failure::ChangedCapability,
        ),
    ] {
        let samples = [Sample::firmware(FIRMWARE), second, third];
        let mut script = Script::new(&samples);
        assert_eq!(simulate(&mut script, Prerequisites::READY), Err(failure));
        assert_eq!(script.request, Some((0x93, 1)));
        assert!(script.observed <= 3);
    }
}

#[test]
fn compare_and_request_denies_changes_at_the_write_boundary_without_writing() {
    let firmware = Sample::firmware(FIRMWARE);
    let samples = [firmware, Sample::firmware(OS), Sample::firmware(OS)];
    for (ready, replacement, expected) in [
        (
            Prerequisites::READY,
            Sample {
                lease_generation: 2,
                ..firmware
            },
            Failure::ChangedLease,
        ),
        (
            Prerequisites::READY,
            Sample::firmware(OS),
            Failure::ChangedCapability,
        ),
        (
            Prerequisites::READY,
            Sample::firmware(SEMAPHORES),
            Failure::ChangedCapability,
        ),
        (
            Prerequisites::READY,
            Sample {
                hcc1: 0,
                ..firmware
            },
            Failure::ChangedCapability,
        ),
        (
            Prerequisites {
                source_closed: false,
                ..Prerequisites::READY
            },
            firmware,
            Failure::Prerequisite,
        ),
        (
            Prerequisites {
                dma_blocked: false,
                ..Prerequisites::READY
            },
            firmware,
            Failure::Prerequisite,
        ),
    ] {
        let mut script = Script::new(&samples);
        script.at_request = Some((ready, replacement));
        assert_eq!(simulate(&mut script, Prerequisites::READY), Err(expected));
        assert_eq!(script.request, None);
        assert_eq!(script.observed, 1);
    }
}

#[test]
fn acknowledgment_cannot_be_used_after_prerequisites_or_lease_change() {
    let os = Sample::firmware(OS);
    let samples = [Sample::firmware(FIRMWARE), os, os];
    for (ready, final_sample, failure) in [
        (
            Prerequisites {
                dma_blocked: false,
                ..Prerequisites::READY
            },
            os,
            Failure::Prerequisite,
        ),
        (
            Prerequisites {
                source_closed: false,
                ..Prerequisites::READY
            },
            os,
            Failure::Prerequisite,
        ),
        (
            Prerequisites::READY,
            Sample {
                lease_generation: 2,
                ..os
            },
            Failure::ChangedLease,
        ),
        (
            Prerequisites::READY,
            Sample::firmware(SEMAPHORES),
            Failure::RequestLost,
        ),
        (
            Prerequisites::READY,
            Sample {
                raw: os.raw | (1 << 25),
                ..os
            },
            Failure::ChangedCapability,
        ),
    ] {
        let mut script = Script::new(&samples);
        script.at_accept = Some((ready, final_sample));
        assert_eq!(simulate(&mut script, Prerequisites::READY), Err(failure));
        assert_eq!(script.observed, 3);
        assert_eq!(script.request, Some((0x93, 1)));
        assert_eq!(script.accepted_generation, None);
    }
}

#[test]
fn lost_dma_containment_during_polling_never_accepts_or_retries_the_request() {
    let samples = [FIRMWARE, SEMAPHORES, OS, OS].map(Sample::firmware);
    for at in 1..samples.len() {
        let mut script = Script::new(&samples);
        script.during_poll = Some((
            at,
            Prerequisites {
                dma_blocked: false,
                ..Prerequisites::READY
            },
        ));
        assert_eq!(
            simulate(&mut script, Prerequisites::READY),
            Err(Failure::Prerequisite)
        );
        assert_eq!(script.observed, at);
        assert_eq!(script.request, Some((0x93, 1)));
        assert_eq!(script.accepted_generation, None);
    }
}

#[test]
fn model_rejects_a_replayed_register_sample_after_lease_replacement() {
    let samples = [
        Sample::firmware(FIRMWARE),
        Sample::firmware(OS),
        Sample {
            lease_generation: 2,
            ..Sample::firmware(OS)
        },
    ];
    let mut script = Script::new(&samples);
    assert_eq!(
        simulate(&mut script, Prerequisites::READY),
        Err(Failure::ChangedLease)
    );
    assert_eq!(script.request, Some((0x93, 1)));

    let samples = [Sample {
        lease_generation: 0,
        ..Sample::firmware(FIRMWARE)
    }];
    let mut script = Script::new(&samples);
    assert_eq!(
        simulate(&mut script, Prerequisites::READY),
        Err(Failure::ChangedLease)
    );
    assert_eq!(script.request, None);
}
