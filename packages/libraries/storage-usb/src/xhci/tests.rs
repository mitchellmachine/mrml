use super::*;

const DMA: DmaLayout = DmaLayout {
    device_contexts: 0x10_0000,
    command_ring: 0x10_0100,
    event_segments: 0x10_0200,
    event_ring: 0x10_0300,
};
const OP: u32 = 0x40;
const RT: u32 = 0x1000;
const DB: u32 = 0x2000;

struct Fake {
    regs: [u32; 0x2400 / 4],
    dma: [u8; 1024],
    completion: bool,
    corrupt_event: bool,
    bell: u64,
    fail_run: bool,
    ignore_stop_once: bool,
    fail_revoke_once: bool,
    activation_fault: u8,
    activation_reads: u8,
    pci_command: u16,
    pci_writes: u8,
    releases: u8,
    ignore_pci_write: bool,
    native_binding: Option<NativePciBinding>,
    substitute_bar: bool,
}

impl Fake {
    fn new() -> Self {
        let mut fake = Self {
            regs: [0; 0x2400 / 4],
            dma: [0xff; 1024],
            completion: true,
            corrupt_event: false,
            bell: 0,
            fail_run: false,
            ignore_stop_once: false,
            fail_revoke_once: false,
            activation_fault: 0,
            activation_reads: 0,
            pci_command: 6,
            pci_writes: 0,
            releases: 0,
            ignore_pci_write: false,
            native_binding: None,
            substitute_bar: false,
        };
        fake.regs[0] = 0x0110_0040;
        fake.regs[1] = 0x0200_0108;
        fake.regs[4] = 1;
        fake.regs[5] = DB;
        fake.regs[6] = RT;
        fake.regs[(OP as usize + 4) / 4] = HALTED;
        fake.regs[(OP as usize + 8) / 4] = 1;
        fake.regs[(OP as usize + 0x400) / 4] = (3 << 10) | (1 << 9) | 1;
        fake
    }
}

impl Platform for Fake {
    type Error = ();
    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        Ok(self.regs[offset as usize / 4])
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        if offset == OP && value == 0 && self.ignore_stop_once {
            self.ignore_stop_once = false;
            return Ok(());
        }
        self.regs[offset as usize / 4] = value;
        if offset == OP {
            self.regs[(OP as usize + 4) / 4] = if value == RUN { 0 } else { HALTED };
            self.regs[OP as usize / 4] = if value == RESET { 0 } else { value };
        }
        if offset == OP && value == RUN && self.fail_run {
            return Err(());
        }
        if offset == DB && self.completion {
            assert_eq!(
                self.regs[(OP as usize + 0x30) / 4],
                DMA.device_contexts as u32
            );
            assert_eq!(
                self.regs[(RT as usize + 0x30) / 4],
                DMA.event_segments as u32
            );
            let target = DMA.command_ring + self.bell * TRB_BYTES;
            let mut command = [0; 16];
            self.dma_read(target, &mut command)?;
            assert_eq!(&command[..12], &[0; 12]);
            assert_eq!(
                u32::from_le_bytes(command[12..].try_into().unwrap()),
                (COMMAND_NOOP << 10) | 1
            );
            let mut done = [0; 16];
            done[..8].copy_from_slice(&(target + u64::from(self.corrupt_event) * 16).to_le_bytes());
            done[11] = 1;
            done[12..].copy_from_slice(&((COMMAND_COMPLETION << 10) | 1).to_le_bytes());
            self.dma_write(DMA.event_ring + self.bell * TRB_BYTES, &done)?;
            self.bell += 1;
        }
        Ok(())
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        let offset = (address - DMA.device_contexts) as usize;
        self.dma[offset..][..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        let offset = (address - DMA.device_contexts) as usize;
        bytes.copy_from_slice(&self.dma[offset..][..bytes.len()]);
        Ok(())
    }
    fn publish_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn acquire_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn wait_tick(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl RevocablePlatform for Fake {
    fn revoke_after_halt(&mut self) -> Result<(), ()> {
        assert_eq!(self.regs[OP as usize / 4], 0);
        assert_ne!(self.regs[(OP as usize + 4) / 4] & HALTED, 0);
        if core::mem::take(&mut self.fail_revoke_once) {
            return Err(());
        }
        Ok(())
    }
}

#[test]
fn programs_rings_and_requires_exact_command_completion() {
    let mut controller = Controller::start(Fake::new(), 0x2400, DMA, 10).unwrap();
    assert_eq!(
        controller.port_status(1),
        Ok(PortStatus {
            connected: true,
            powered: true,
            enabled: false,
            speed_id: 3
        })
    );
    assert_eq!(controller.port_status(3), Err(Error::InvalidPort));
    for _ in 0..15 {
        controller.no_op(5).unwrap();
    }
    assert_eq!(controller.no_op(5), Err(Error::QueueExhausted));
    controller.stop(5).unwrap().revoke().unwrap();
}

#[test]
fn rejects_invalid_resources_or_unreleased_firmware() {
    let bad_dma = DmaLayout {
        event_ring: DMA.command_ring,
        ..DMA
    };
    assert!(matches!(
        Controller::start(Fake::new(), 0x2400, bad_dma, 10),
        Err(StartFailure::Untouched {
            error: Error::InvalidDma,
            ..
        })
    ));
    assert!(matches!(
        Controller::start(Fake::new(), 0x1800, DMA, 10),
        Err(StartFailure::Untouched {
            error: Error::InvalidBar,
            ..
        })
    ));
    let mut fake = Fake::new();
    fake.regs[4] |= (0x900 / 4) << 16;
    fake.regs[0x900 / 4] = 1 | (1 << 16);
    assert!(matches!(
        Controller::start(fake, 0x2400, DMA, 10),
        Err(StartFailure::Untouched {
            error: Error::FirmwareOwned,
            ..
        })
    ));
    let Err(StartFailure::Programming(pending)) = Controller::start(Fake::new(), 0x2400, DMA, 0)
    else {
        panic!("expected a retryable startup failure");
    };
    assert_eq!(pending.error(), &Error::Timeout);
    pending.retry(5).unwrap().revoke().unwrap();
}

#[test]
fn a_timeout_or_wrong_command_pointer_faults_the_session() {
    for (inject, expected) in [(false, Error::Timeout), (true, Error::UnexpectedEvent)] {
        let mut fake = Fake::new();
        fake.completion = inject;
        fake.corrupt_event = inject;
        let mut controller = Controller::start(fake, 0x2400, DMA, 10).unwrap();
        assert_eq!(controller.no_op(3), Err(expected));
        assert_eq!(controller.no_op(3), Err(Error::Faulted));
        controller.stop(5).unwrap().revoke().unwrap();
    }
}

#[test]
fn failed_start_keeps_ownership_after_the_run_write() {
    let mut fake = Fake::new();
    fake.fail_run = true;
    let Err(StartFailure::Programming(pending)) = Controller::start(fake, 0x2400, DMA, 5) else {
        panic!("expected ownership of the partially programmed controller");
    };
    assert_eq!(pending.error(), &Error::Platform(()));
    pending.retry(5).unwrap().revoke().unwrap();
}

#[test]
fn halt_timeout_and_revocation_failure_allow_only_their_own_retry() {
    let mut controller = Controller::start(Fake::new(), 0x2400, DMA, 5).unwrap();
    controller.platform.ignore_stop_once = true;
    controller.platform.fail_revoke_once = true;
    let Err(pending) = controller.stop(5) else {
        panic!("must not release a running device");
    };
    assert_eq!(pending.error(), &Error::Timeout);
    let halted = pending.retry(5).unwrap();
    let failed = halted.revoke().unwrap_err();
    assert_eq!(failed.error(), &());
    failed.retry().unwrap();
}

fn activation_snapshot() -> pci::PciSnapshot {
    pci::PciSnapshot {
        location: pci::PciLocation {
            segment: 0,
            bus: 0,
            device: 3,
            function: 0,
        },
        configuration_generation: 1,
        vendor_device: 0x000d_1b36,
        class_revision: 0x0c03_3000,
        header_type: 0,
        command: 2,
        bar0: 0xfeb0_0004,
        bar1: 0,
        bar0_bytes: 0x4000,
    }
}

fn activation_assignment() -> DmaAssignment {
    DmaAssignment {
        controller: pci::PciController::discover(activation_snapshot()).unwrap(),
        mapping_generation: 1,
        device_base: DMA.device_contexts,
        bytes: 4096,
    }
}

impl PciActivation for Fake {
    fn activation_state(&mut self) -> Result<(pci::PciSnapshot, DmaAssignment), ()> {
        self.activation_reads += 1;
        let mut mapping = activation_assignment();
        if self.activation_fault == 1 && self.activation_reads == 2 {
            mapping.mapping_generation += 1;
        }
        // Neither activation error may reach the actual run write. This
        // emulates the command remaining unchanged after a reported success.
        let mut snapshot = activation_snapshot();
        if self.activation_fault == 3 && self.activation_reads >= 3 {
            snapshot.command |= 4;
        }
        Ok((snapshot, mapping))
    }

    fn enable_bus_master(&mut self, expected: DmaAssignment, before: u16) -> Result<(), ()> {
        assert!(
            matches!(self.activation_fault, 2 | 3),
            "must not arm after failed checks"
        );
        assert_eq!(expected, activation_assignment());
        assert_eq!(before, 2);
        assert_eq!(self.regs[OP as usize / 4], 0);
        assert_eq!(self.regs[(OP as usize + 0x30) / 4], 0);
        Ok(())
    }
}

#[test]
fn mapping_drift_or_missing_pci_readback_prevents_run_and_retains_cleanup() {
    for (fault, expected) in [
        (1, Error::InvalidDma),
        (2, Error::Pci(pci::PciError::CommandMismatch)),
    ] {
        let mut fake = Fake::new();
        fake.activation_fault = fault;
        fake.fail_run = true;
        let Err(StartFailure::Programming(pending)) =
            Controller::start_pci(fake, activation_assignment(), DMA, 5)
        else {
            panic!("activation must not start the controller");
        };
        assert_eq!(pending.error(), &expected);
        pending.retry(5).unwrap().revoke().unwrap();
    }
}

#[test]
fn independent_translation_check_blocks_programming_or_running_at_each_stage() {
    use mrml_kernel::arch::x86_64::VtdBindingError;

    for stage in 1..=3 {
        let mut backend = Fake::new();
        backend.activation_fault = if stage == 3 { 3 } else { 0 };
        backend.fail_run = true;
        let mut checks = 0;
        let error = Error::Vtd(VtdBindingError::TableSubstitution);
        let result =
            Controller::start_checked_pci(backend, activation_assignment(), DMA, 5, || {
                checks += 1;
                if checks == stage { Err(error) } else { Ok(()) }
            });
        assert_eq!(checks, stage);
        if stage == 1 {
            let Err(StartFailure::Untouched {
                error: actual,
                platform,
            }) = result
            else {
                panic!("first translation check must precede controller writes");
            };
            assert_eq!(actual, error);
            assert_eq!(platform.activation_reads, 1);
            assert_eq!(platform.dma, [0xff; 1024]);
        } else {
            let Err(StartFailure::Programming(pending)) = result else {
                panic!("late translation failure must preserve cleanup ownership");
            };
            assert_eq!(pending.error(), &error);
            pending.retry(5).unwrap().revoke().unwrap();
        }
    }
}

impl VtdPciPlatform for Fake {
    fn validate_aperture(&self, _: mrml_kernel::arch::x86_64::VtdDmaAperture) -> Result<(), ()> {
        Ok(())
    }
    fn live_pci(&mut self, expected: DmaAssignment) -> Result<pci::PciSnapshot, ()> {
        assert_eq!(expected, activation_assignment());
        let mut live = activation_snapshot();
        live.command = self.pci_command;
        Ok(live)
    }

    fn set_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
        enabled: bool,
    ) -> Result<(), ()> {
        assert_eq!(expected, activation_assignment());
        assert_eq!(before, self.pci_command);
        assert!(!enabled);
        self.pci_writes += 1;
        if !self.ignore_pci_write {
            self.pci_command &= !4;
        }
        Ok(())
    }

    fn release_revoked(&mut self, expected: DmaAssignment) -> Result<(), ()> {
        assert_eq!(expected, activation_assignment());
        assert_eq!(self.pci_command & 4, 0);
        self.releases += 1;
        if core::mem::take(&mut self.fail_revoke_once) {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[test]
fn managed_vtd_requires_pci_readback_before_withdrawal_and_resumes_release_only() {
    use managed_vtd::{Cleanup, finish_cleanup};
    use mrml_kernel::arch::x86_64::{VtdApertureRevokeError, VtdBindingError};
    let mut progress = Cleanup::Active;
    let mut fake = Fake::new();
    let assignment = activation_assignment();
    fake.ignore_pci_write = true;
    assert_eq!(
        finish_cleanup(&mut progress, &mut fake, assignment, || panic!(
            "DMA is still armed"
        )),
        Err(ManagedVtdError::Pci(pci::PciError::BusMasterEnabled))
    );
    assert_eq!(fake.releases, 0);
    fake.ignore_pci_write = false;
    let uncertain = ManagedVtdError::Revoke(VtdApertureRevokeError::Uncertain(
        VtdBindingError::TableSubstitution,
    ));
    assert_eq!(
        finish_cleanup(&mut progress, &mut fake, assignment, || Err(uncertain)),
        Err(uncertain)
    );
    assert_eq!(progress, Cleanup::Withdrawing);
    assert_eq!(fake.pci_command, 2);
    assert_eq!(fake.releases, 0);
    fake.fail_revoke_once = true;
    assert_eq!(
        finish_cleanup(&mut progress, &mut fake, assignment, || Ok(())),
        Err(ManagedVtdError::Platform(()))
    );
    assert_eq!(progress, Cleanup::Withdrawn);
    finish_cleanup(&mut progress, &mut fake, assignment, || {
        panic!("already drained")
    })
    .unwrap();
    assert_eq!(progress, Cleanup::Released);
    assert_eq!(fake.pci_writes, 2);
    assert_eq!(fake.releases, 2);
}

impl mrml_kernel::arch::x86_64::PciConfigSpace for Fake {
    fn read_u32(&mut self, address: mrml_kernel::DeviceAddress, offset: u16) -> Option<u32> {
        assert_eq!(
            (
                address.segment(),
                address.bus(),
                address.device(),
                address.function()
            ),
            (0, 0, 3, 0)
        );
        let live = activation_snapshot();
        match offset {
            0 => Some(live.vendor_device),
            4 => Some(0xabcd_0000 | u32::from(self.pci_command)),
            8 => Some(live.class_revision),
            12 => Some(u32::from(live.header_type) << 16),
            0x10 if self.substitute_bar => Some(live.bar0 + 0x4000),
            0x10 => Some(live.bar0),
            0x14 => Some(live.bar1),
            _ => None,
        }
    }
}

impl NativePciLease for Fake {
    fn binding(&self) -> NativePciBinding {
        self.native_binding.unwrap()
    }

    fn set_bus_master16(
        &mut self,
        address: mrml_kernel::DeviceAddress,
        before: u16,
        enabled: bool,
    ) -> Result<(), ()> {
        assert_eq!(
            address,
            NativePciLease::binding(self).aperture.route.requester()
        );
        self.pci_writes += 1;
        assert_eq!(self.pci_command, before);
        self.pci_command = (before & !4) | if enabled { 4 } else { 0 };
        Ok(())
    }

    fn release_bound_resources(&mut self, binding: NativePciBinding) -> Result<(), ()> {
        assert_eq!(binding, NativePciLease::binding(self));
        self.releases += 1;
        Ok(())
    }
}

fn native_binding() -> NativePciBinding {
    use mrml_kernel::arch::x86_64::{DmarTopology, VtdDmaAperture};
    use mrml_kernel::{DeviceAddress, ObjectId, PhysAddr};

    let mut fake = Fake::new();
    let dma = activation_assignment();
    let mut dmar = [0u8; 64];
    dmar[..4].copy_from_slice(b"DMAR");
    dmar[4..8].copy_from_slice(&64u32.to_le_bytes());
    dmar[36] = 47;
    dmar[50..52].copy_from_slice(&16u16.to_le_bytes());
    dmar[52] = 1;
    dmar[56..64].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
    dmar[9] = 0u8.wrapping_sub(dmar.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
    let route = DmarTopology::<1, 0>::parse(&dmar)
        .unwrap()
        .route_for_requester(DeviceAddress::new(0, 0, 3, 0).unwrap(), &mut fake)
        .unwrap();
    NativePciBinding {
        device: ObjectId(1),
        memory: ObjectId(2),
        bar_generation: 1,
        allocation_generation: 1,
        dma,
        aperture: VtdDmaAperture {
            route,
            hardware_domain: 1,
            device_base: dma.device_base,
            physical_base: PhysAddr::new(0x20_0000).unwrap(),
            pages: 1,
        },
    }
}

#[test]
fn native_owner_binds_capabilities_generations_and_exact_command_write() {
    use mrml_kernel::arch::x86_64::VtdDmaAperture;
    use mrml_kernel::{CapabilitySpace, PhysAddr, Rights};
    let binding = native_binding();
    let dma = binding.dma;
    let mut fake = Fake::new();
    let mut caps = CapabilitySpace::<3>::new();
    let device = caps.insert(binding.device, Rights::CONTROL).unwrap();
    let read_only = caps.insert(binding.memory, Rights::READ).unwrap();
    let memory = caps
        .insert(
            binding.memory,
            Rights::MAP
                .union(Rights::PIN)
                .union(Rights::READ)
                .union(Rights::WRITE),
        )
        .unwrap();
    assert!(matches!(
        NativePciOwner::admit(&caps, device, read_only, binding, Fake::new()),
        Err(NativePciOwnerError::Capability(_))
    ));
    fake.native_binding = Some(binding);
    assert!(matches!(
        NativePciOwner::admit(
            &caps,
            device,
            memory,
            NativePciBinding {
                allocation_generation: 2,
                ..binding
            },
            fake
        ),
        Err(NativePciOwnerError::Binding)
    ));
    let mut fake = Fake::new();
    fake.native_binding = Some(binding);
    fake.pci_command = 0x402;
    let mut owner = NativePciOwner::admit(&caps, device, memory, binding, fake)
        .ok()
        .unwrap();
    assert_eq!(owner.validate_aperture(binding.aperture), Ok(()));
    assert_eq!(
        owner.validate_aperture(VtdDmaAperture {
            physical_base: PhysAddr::new(0x21_0000).unwrap(),
            ..binding.aperture
        }),
        Err(NativePciOwnerError::Binding)
    );
    assert_eq!(
        owner.set_bus_master(dma, 2, true),
        Err(NativePciOwnerError::Pci(pci::PciError::CommandMismatch))
    );
    owner.set_bus_master(dma, 0x402, true).unwrap();
    assert_eq!(owner.live_pci(dma).unwrap().command, 0x406);
    owner.set_bus_master(dma, 0x406, false).unwrap();
    assert_eq!(owner.live_pci(dma).unwrap().command, 0x402);
    owner.release_revoked(dma).unwrap();
    assert_eq!(owner.live_pci(dma), Err(NativePciOwnerError::Binding));

    let mut fake = Fake::new();
    fake.native_binding = Some(binding);
    fake.substitute_bar = true;
    let mut changed = NativePciOwner::admit(&caps, device, memory, binding, fake)
        .ok()
        .unwrap();
    assert_eq!(
        changed.set_bus_master(dma, 6, false),
        Err(NativePciOwnerError::Pci(pci::PciError::AssignmentChanged))
    );
}

impl NativePciBacking for Fake {
    fn binding(&self) -> NativePciBinding {
        self.native_binding.unwrap()
    }

    fn release_after_drain(&mut self, binding: NativePciBinding) -> Result<(), ()> {
        self.release_bound_resources(binding)
    }
}

#[test]
fn ecam_lease_writes_only_the_bound_function_and_retires_after_release() {
    extern crate std;
    use mrml_kernel::DeviceAddress;
    use mrml_kernel::arch::x86_64::{EcamCommandError, NativeEcamSegment, PciConfigSpace};

    let binding = native_binding();
    let target = binding.aperture.route.requester();
    let other = DeviceAddress::new(0, 0, 4, 0).unwrap();
    let mut fake = Fake::new();
    fake.native_binding = Some(binding);
    let mut storage = std::vec![0_u8; (1 << 20) + 4095];
    let pad = storage.as_ptr().align_offset(4096);
    let window = &mut storage[pad..pad + (1 << 20)];
    for function in [3 << 15, 4 << 15] {
        window[function..function + 4].copy_from_slice(&0x000d_1b36u32.to_le_bytes());
        window[function + 4..function + 8].copy_from_slice(&0xa5a5_0402u32.to_le_bytes());
    }
    let len = window.len();
    let base = window.as_mut_ptr();
    // SAFETY: the aligned test buffer stays live and is exclusively accessed here.
    let mut ecam = unsafe { NativeEcamSegment::new(base, len, 0, 0, 0).unwrap() };
    // SAFETY: no hardware is involved and no other accessor can access the
    // bound function while this test lease exclusively borrows its window.
    let mut lease = unsafe { EcamPciLease::adopt(&mut ecam, fake).unwrap() };
    assert_eq!(lease.read_u32(other, 4), None);
    assert_eq!(
        lease.set_bus_master16(other, 0x402, true),
        Err(EcamLeaseError::Binding)
    );
    assert_eq!(
        lease.set_bus_master16(target, 2, true),
        Err(EcamLeaseError::Command(EcamCommandError::CommandChanged))
    );
    lease.set_bus_master16(target, 0x402, true).unwrap();
    assert_eq!(lease.read_u32(target, 4), Some(0xa5a5_0406));
    lease.set_bus_master16(target, 0x406, false).unwrap();
    lease.release_bound_resources(binding).unwrap();
    assert_eq!(lease.read_u32(target, 4), None);
    assert_eq!(
        lease.set_bus_master16(target, 0x402, true),
        Err(EcamLeaseError::Binding)
    );
    assert_eq!(ecam.read_u32(other, 4), Some(0xa5a5_0402));
}
