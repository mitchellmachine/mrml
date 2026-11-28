//! A hosted lifecycle proof, not an xHCI driver or device attachment.
use super::*;
use mrml_hardware_supervisor::{
    DriverMicrovmManager, HardwareSupervisor, PciInventoryProvider, PciObservation, PciSnapshot,
    XhciLaunch, XhciRouteBinding, XhciRouteCatalog,
};
use mrml_kernel::{
    DeviceAddress, IsolationAdmissionTable, IsolationMode, IsolationPlacement,
    IsolationServiceSpec, IsolationUnavailableReason, RoutedIsolationService, TotalMicrovmClass,
};

struct Inventory<'a>(PciSnapshot<'a>);

impl PciInventoryProvider for Inventory<'_> {
    type Error = ();

    fn snapshot(&mut self) -> Result<PciSnapshot<'_>, ()> {
        Ok(PciSnapshot {
            sequence: self.0.sequence,
            devices: self.0.devices,
        })
    }
}

struct HostedFixture<'a, F> {
    catalog: XhciRouteCatalog<'a>,
    caps: CapabilitySpace<2>,
    admission: IsolationAdmissionTable<2>,
    make_guest: F,
    guests: [Option<PreparedKvmGuest<7>>; 2],
    constructor_fails: bool,
}

impl<F: FnMut() -> Result<PreparedKvmGuest<7>, KvmError>> DriverMicrovmManager
    for HostedFixture<'_, F>
{
    type Instance = RoutedIsolationService<usize>;
    type Error = ();

    fn launch_xhci(&mut self, request: XhciLaunch) -> Result<Self::Instance, ()> {
        let (controller, prepared) = self
            .catalog
            .prepare(request, &mut self.admission, &self.caps)
            .map_err(|_| ())?
            .into_parts();
        let index = match controller.address.device() {
            5 => 0,
            6 => 1,
            _ => unreachable!("fixed test catalog"),
        };
        assert!(self.guests[index].is_none());
        let guest = match if self.constructor_fails {
            Err(KvmError::SystemCall)
        } else {
            (self.make_guest)()
        } {
            Ok(guest) => guest,
            Err(_) => {
                prepared
                    .unavailable(&mut self.admission, IsolationUnavailableReason::VmmResource)
                    .unwrap();
                return Err(());
            }
        };
        let route = prepared.commit(&mut self.admission, index).unwrap();
        self.guests[index] = Some(guest);
        Ok(route)
    }

    fn retire_xhci(&mut self, route: &mut Self::Instance) -> Result<(), ()> {
        assert!(route.is_live_in(&self.admission));
        self.admission.retire(route.domain()).map_err(|_| ())?;
        assert!(!route.is_live_in(&self.admission));
        // This fixture did not create a device projection. Closing this sole
        // KVM guest owner releases its private vCPU and memory.
        drop(self.guests[*route.endpoint()].take().unwrap());
        Ok(())
    }
}

fn controller(device: u8) -> PciObservation {
    PciObservation {
        address: DeviceAddress::new(0, 0, device, 0).unwrap(),
        vendor: 0x1b36,
        device: 0x000d,
        class_revision: 0x0c03_3001,
        incarnation: 1,
    }
}

#[test]
#[ignore = "requires KVM for the signed, device-free controller lifecycle fixture"]
fn live_controller_routes_start_and_retire_independent_guest_instances() {
    let system = KvmSystem::open().expect("live KVM required");
    let bytes = signed_payload_vector(framebuffer_pe(), ArtifactKind::Kernel);
    let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
    let digest = Sha3_512::digest(&bytes[public_at..public_at + LAMPORT_PUBLIC_KEY_BYTES]);
    let signed = SignedArtifact::decode(&bytes).unwrap();
    let executable = signed
        .verify_executable(
            &TrustRoot::new(ArtifactKind::Kernel, digest, 1),
            ArtifactKind::Kernel,
        )
        .unwrap();
    let layout = KvmLaunchLayout::new(
        0x10_0000,
        16,
        0x20_0000,
        0xffff_8001_4000_0000,
        0x30_0000,
        0xffff_8001_5000_0000,
        0x40_0000,
        0xffff_8001_6000_0000,
        PRIVILEGE_STACK_ARENA_PAGES,
        false,
    )
    .unwrap();

    let mut caps = CapabilitySpace::new();
    // Fixed catalog is independent of the provider's inventory snapshots.
    let bindings = [5, 6].map(|slot| {
        let device_object = ObjectId(u64::from(slot));
        XhciRouteBinding {
            controller: controller(slot),
            device_object,
            device_control: caps.insert(device_object, Rights::CONTROL).unwrap(),
            spec: IsolationServiceSpec::new(
                ObjectId(100 + u64::from(slot)),
                ObjectId(42),
                1,
                1,
                1,
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            )
            .unwrap(),
        }
    });
    let mut manager = HostedFixture {
        catalog: XhciRouteCatalog::new(&bindings).unwrap(),
        caps,
        admission: IsolationAdmissionTable::new(IsolationMode::TotalMicrovm, 1, 1).unwrap(),
        make_guest: || system.prepare_kernel_guest(0, &executable, &valid_handoff(), layout),
        guests: [None, None],
        constructor_fails: true,
    };
    let mut supervisor = HardwareSupervisor::<_, 2>::default();
    let scan = |sequence, devices| Inventory(PciSnapshot { sequence, devices });
    let both = [controller(5), controller(6)];
    let b_only = [controller(6)];
    assert_eq!(
        supervisor
            .refresh(&mut scan(1, &both), &mut manager)
            .ok()
            .unwrap()
            .launch_failed,
        2
    );
    assert!(manager.guests.iter().all(Option::is_none));
    assert_eq!(manager.admission.running().count(), 0);
    manager.constructor_fails = false;
    assert_eq!(
        supervisor
            .refresh(&mut scan(2, &both), &mut manager)
            .ok()
            .unwrap()
            .started,
        2
    );
    assert_eq!(manager.admission.running().count(), 2);
    let a = manager.guests[0].as_mut().unwrap();
    assert_eq!(VmBackend::run(a, 0), Ok(VmExit::Halted));
    let mut bytes = [0; 4];
    VmBackend::read_guest(a, 0xa0000, &mut bytes).unwrap();
    assert_eq!(bytes, [0x57, 0xc8, 0xff, 0]);
    VmBackend::read_guest(manager.guests[1].as_ref().unwrap(), 0xa0000, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 4]);

    let removed = supervisor
        .refresh(&mut scan(3, &b_only), &mut manager)
        .ok()
        .unwrap();
    assert_eq!(
        (removed.retired, removed.retained, removed.started),
        (1, 1, 0)
    );
    assert!(manager.guests[0].is_none());
    assert_eq!(manager.admission.running().count(), 1);
    let b = manager.guests[1].as_mut().unwrap();
    assert_eq!(VmBackend::run(b, 0), Ok(VmExit::Halted));
    VmBackend::read_guest(b, 0xa0000, &mut bytes).unwrap();
    assert_eq!(bytes, [0x57, 0xc8, 0xff, 0]);
    let end = supervisor
        .refresh(&mut scan(4, &[]), &mut manager)
        .ok()
        .unwrap();
    assert_eq!(end.retired, 1);
    assert_eq!(manager.admission.running().count(), 0);
    assert!(manager.guests.iter().all(Option::is_none));
}
