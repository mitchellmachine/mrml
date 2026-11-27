//! Executable model of the xHCI legacy ownership handshake (xHCI 1.2 §7.1).
//! This module is compiled only in tests. It cannot reset, program, or read
//! real hardware, grant a device assignment, or enable DMA.
use super::{LegacyOwnership, LegacySample, sample_legacy_ownership};

const FIRMWARE: u32 = 1 << 16;
const OS: u32 = 1 << 24;
const SEMAPHORES: u32 = FIRMWARE | OS;
const OBSERVATIONS: usize = 8;

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
}

impl<'a> Script<'a> {
    fn new(samples: &'a [Sample]) -> Self {
        assert!(!samples.is_empty());
        Self {
            samples,
            observed: 0,
            request: None,
            at_request: None,
        }
    }

    fn observe(&mut self) -> Result<(u64, LegacySample), Failure> {
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
}

fn simulate(script: &mut Script<'_>, ready: Prerequisites) -> Result<(), Failure> {
    if !ready.permit_request() {
        return Err(Failure::Prerequisite);
    }
    let (generation, initial) = script.observe()?;
    if generation == 0 {
        return Err(Failure::ChangedLease);
    }
    if initial.ownership != LegacyOwnership::Firmware {
        return Err(Failure::InitialOwner);
    }
    let (offset, raw) = initial.capability.ok_or(Failure::InitialOwner)?;
    // The only modeled write is one byte to the OS-owned semaphore. In
    // particular, it cannot clear firmware's byte or touch the next dword.
    script.compare_and_request(generation, initial)?;
    let mut acknowledged = false;
    for _ in 0..OBSERVATIONS {
        let (live_generation, current) = script.observe()?;
        if live_generation != generation {
            return Err(Failure::ChangedLease);
        }
        if current.hcc1 != initial.hcc1
            || current
                .capability
                .map(|(at, value)| (at, value & !SEMAPHORES))
                != Some((offset, raw & !SEMAPHORES))
        {
            return Err(Failure::ChangedCapability);
        }
        match current.ownership {
            LegacyOwnership::OperatingSystem if acknowledged => return Ok(()),
            LegacyOwnership::OperatingSystem => acknowledged = true,
            LegacyOwnership::Contended if !acknowledged => (),
            _ => return Err(Failure::RequestLost),
        }
    }
    Err(Failure::Timeout)
}

#[test]
fn model_accepts_stable_firmware_acknowledgment_after_one_os_byte_write() {
    let samples = [FIRMWARE, SEMAPHORES, SEMAPHORES, OS, OS].map(Sample::firmware);
    let mut script = Script::new(&samples);
    assert_eq!(simulate(&mut script, Prerequisites::READY), Ok(()));
    assert_eq!(script.request, Some((0x93, 1)));
    assert_eq!(script.observed, 5);
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
    assert_eq!(script.observed, 1 + OBSERVATIONS);
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
