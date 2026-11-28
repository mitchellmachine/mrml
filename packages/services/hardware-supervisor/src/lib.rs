#![no_std]

//! Reconcile a complete, authority-free PCI inventory with driver microVMs.
//! Discovery policy runs here. The platform retains inventory and launch
//! capabilities; neither a PCI address nor a probe record grants access.

mod admission;

pub use admission::{PreparedXhciRoute, XhciAdmissionError, XhciRouteBinding, XhciRouteCatalog};

use mrml_kernel::DeviceAddress;

const XHCI_CLASS: u32 = 0x0c_03_30;
pub const MAX_PCI_OBSERVATIONS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciObservation {
    pub address: DeviceAddress,
    pub vendor: u16,
    pub device: u16,
    /// Standard PCI class/subclass/programming-interface followed by revision.
    pub class_revision: u32,
    /// Nonzero, broker-issued incarnation. Must change if a function is
    /// removed and reappears between snapshots, even at the same address.
    pub incarnation: u64,
}

impl PciObservation {
    fn is_xhci(self) -> bool {
        self.class_revision >> 8 == XHCI_CLASS
    }
}

pub struct PciSnapshot<'a> {
    /// Monotonically increasing sequence from one inventory provider lifetime.
    pub sequence: u64,
    pub devices: &'a [PciObservation],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XhciLaunch {
    controller: PciObservation,
}

impl XhciLaunch {
    pub const fn controller(self) -> PciObservation {
        self.controller
    }
}

/// Trusted service-manager boundary. No native execution branch.
/// Successful starts represent distinct, admitted MicroVM instances with
/// grants scoped to precisely the indicated controller incarnation. The
/// manager verifies identity, policy, transport and device/DMA containment
/// independently, and rolls back any incomplete start before returning Err.
pub trait DriverMicrovmManager {
    type Instance;
    type Error;

    fn launch_xhci(&mut self, launch: XhciLaunch) -> Result<Self::Instance, Self::Error>;

    /// Stop routing immediately, then retire the VM and revoke its grants.
    /// On failure the handle must remain available for cleanup, with no new
    /// routing, and the caller must not launch a successor for this address.
    fn retire_xhci(&mut self, instance: &mut Self::Instance) -> Result<(), Self::Error>;
}

/// A bound, trusted projection of OS discovery, not direct register access.
/// Incomplete or truncated scans must return an error rather than removing
/// controllers by omission. Bind each supervisor to one provider lifetime.
pub trait PciInventoryProvider {
    type Error;
    fn snapshot(&mut self) -> Result<PciSnapshot<'_>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryError {
    StaleSequence,
    TooManyObservations,
    InvalidObservation,
    DuplicateAddress,
    TooManyControllers,
}

pub enum RefreshError<E> {
    Discovery(E),
    Inventory(InventoryError),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RefreshReport {
    pub retained: usize,
    pub started: usize,
    pub retired: usize,
    pub launch_failed: usize,
    pub retirement_failed: usize,
    pub deferred: usize,
}

struct Slot<I> {
    controller: PciObservation,
    instance: I,
    retiring: bool,
}

pub struct HardwareSupervisor<I, const N: usize> {
    sequence: u64,
    slots: [Option<Slot<I>>; N],
}

impl<I, const N: usize> Default for HardwareSupervisor<I, N> {
    fn default() -> Self {
        Self {
            sequence: 0,
            slots: [const { None }; N],
        }
    }
}

impl<I, const N: usize> HardwareSupervisor<I, N> {
    pub fn refresh<P: PciInventoryProvider, B: DriverMicrovmManager<Instance = I>>(
        &mut self,
        provider: &mut P,
        manager: &mut B,
    ) -> Result<RefreshReport, RefreshError<P::Error>> {
        let snapshot = provider.snapshot().map_err(RefreshError::Discovery)?;
        self.reconcile(snapshot, manager)
            .map_err(RefreshError::Inventory)
    }

    fn reconcile<B: DriverMicrovmManager<Instance = I>>(
        &mut self,
        snapshot: PciSnapshot<'_>,
        manager: &mut B,
    ) -> Result<RefreshReport, InventoryError> {
        if snapshot.sequence <= self.sequence {
            return Err(InventoryError::StaleSequence);
        }
        if snapshot.devices.len() > MAX_PCI_OBSERVATIONS {
            return Err(InventoryError::TooManyObservations);
        }
        // Validate the entire input before deciding that anything disappeared.
        let mut controllers = 0;
        for (index, device) in snapshot.devices.iter().enumerate() {
            if matches!(device.vendor, 0 | u16::MAX) || device.incarnation == 0 {
                return Err(InventoryError::InvalidObservation);
            }
            if snapshot.devices[..index]
                .iter()
                .any(|prior| prior.address == device.address)
            {
                return Err(InventoryError::DuplicateAddress);
            }
            controllers += usize::from(device.is_xhci());
        }
        if controllers > N {
            return Err(InventoryError::TooManyControllers);
        }
        self.sequence = snapshot.sequence;
        let mut report = RefreshReport::default();
        for slot in &mut self.slots {
            let Some(active) = slot.as_mut() else {
                continue;
            };
            if !active.retiring && snapshot.devices.contains(&active.controller) {
                report.retained += 1;
                continue;
            }
            active.retiring = true;
            match manager.retire_xhci(&mut active.instance) {
                Ok(()) => {
                    *slot = None;
                    report.retired += 1;
                }
                Err(_) => report.retirement_failed += 1,
            }
        }

        for controller in snapshot
            .devices
            .iter()
            .copied()
            .filter(|device| device.is_xhci())
        {
            if let Some(existing) = self
                .slots
                .iter()
                .flatten()
                .find(|slot| slot.controller.address == controller.address)
            {
                report.deferred += usize::from(existing.retiring);
                continue;
            }
            let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
                report.deferred += 1;
                continue;
            };
            match manager.launch_xhci(XhciLaunch { controller }) {
                Ok(instance) => {
                    *slot = Some(Slot {
                        controller,
                        instance,
                        retiring: false,
                    });
                    report.started += 1;
                }
                Err(_) => report.launch_failed += 1,
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn xhci(device: u8, incarnation: u64) -> PciObservation {
        PciObservation {
            address: DeviceAddress::new(0, 0, device, 0).unwrap(),
            vendor: 0x1b36,
            device: 0x000d,
            class_revision: 0x0c03_3001,
            incarnation,
        }
    }

    #[derive(Default)]
    struct Manager {
        next: u32,
        events: Vec<(Option<PciObservation>, u32)>,
        refuse_launch: bool,
        refuse_retire: bool,
    }

    impl DriverMicrovmManager for Manager {
        type Instance = u32;
        type Error = ();

        fn launch_xhci(&mut self, launch: XhciLaunch) -> Result<u32, ()> {
            if self.refuse_launch {
                return Err(());
            }
            self.next += 1;
            self.events.push((Some(launch.controller()), self.next));
            Ok(self.next)
        }

        fn retire_xhci(&mut self, instance: &mut u32) -> Result<(), ()> {
            self.events.push((None, *instance));
            if self.refuse_retire { Err(()) } else { Ok(()) }
        }
    }

    struct Inventory<'a>(Option<PciSnapshot<'a>>);
    impl PciInventoryProvider for Inventory<'_> {
        type Error = ();
        fn snapshot(&mut self) -> Result<PciSnapshot<'_>, ()> {
            self.0.take().ok_or(())
        }
    }

    fn refresh<const N: usize>(
        supervisor: &mut HardwareSupervisor<u32, N>,
        sequence: u64,
        devices: &[PciObservation],
        manager: &mut Manager,
    ) -> RefreshReport {
        supervisor
            .refresh(
                &mut Inventory(Some(PciSnapshot { sequence, devices })),
                manager,
            )
            .ok()
            .unwrap()
    }

    #[test]
    fn separate_controllers_launch_separate_instances_and_reordering_retains_them() {
        let (a, b) = (xhci(5, 1), xhci(6, 1));
        let other = PciObservation {
            class_revision: 0x0106_0100,
            ..xhci(7, 1)
        };
        let mut supervisor = HardwareSupervisor::<u32, 2>::default();
        let mut manager = Manager::default();
        assert_eq!(
            refresh(&mut supervisor, 1, &[a, b, other], &mut manager).started,
            2
        );
        assert_eq!(manager.events.as_slice(), &[(Some(a), 1), (Some(b), 2)]);
        assert_eq!(
            refresh(&mut supervisor, 2, &[other, b, a], &mut manager).retained,
            2
        );
        assert_eq!(manager.events.len(), 2);
        assert_eq!(refresh(&mut supervisor, 3, &[b], &mut manager).retired, 1);
        assert_eq!(manager.events.last(), Some(&(None, 1)));
    }

    #[test]
    fn failed_retirement_blocks_replacement_without_disturbing_the_other_controller() {
        let (a, b, successor) = (xhci(5, 1), xhci(6, 1), xhci(5, 2));
        let mut supervisor = HardwareSupervisor::<u32, 2>::default();
        let mut manager = Manager::default();
        refresh(&mut supervisor, 1, &[a, b], &mut manager);
        manager.refuse_retire = true;
        let failed = refresh(&mut supervisor, 2, &[successor, b], &mut manager);
        assert_eq!(
            (
                failed.retirement_failed,
                failed.retained,
                failed.deferred,
                failed.started
            ),
            (1, 1, 1, 0)
        );
        assert_eq!(manager.events.last(), Some(&(None, 1)));
        manager.refuse_retire = false;
        let finished = refresh(&mut supervisor, 3, &[successor, b], &mut manager);
        assert_eq!(
            (finished.retired, finished.retained, finished.started),
            (1, 1, 1)
        );
        assert_eq!(&manager.events[3..], &[(None, 1), (Some(successor), 3)]);
    }

    #[test]
    fn invalid_or_unavailable_inventory_does_not_retire_existing_instances() {
        let a = xhci(5, 1);
        let mut supervisor = HardwareSupervisor::<u32, 1>::default();
        let mut manager = Manager::default();
        refresh(&mut supervisor, 1, &[a], &mut manager);
        assert!(matches!(
            supervisor.refresh(&mut Inventory(None), &mut manager),
            Err(RefreshError::Discovery(()))
        ));
        let invalid = PciObservation {
            incarnation: 0,
            ..a
        };
        for (sequence, devices, error) in [
            (1, &[][..], InventoryError::StaleSequence),
            (2, &[a, xhci(5, 2)][..], InventoryError::DuplicateAddress),
            (2, &[a, xhci(6, 1)][..], InventoryError::TooManyControllers),
            (2, &[invalid][..], InventoryError::InvalidObservation),
        ] {
            let mut inventory = Inventory(Some(PciSnapshot { sequence, devices }));
            assert!(matches!(supervisor.refresh(&mut inventory, &mut manager),
                Err(RefreshError::Inventory(actual)) if actual == error));
        }
        assert_eq!(manager.events.as_slice(), &[(Some(a), 1)]);
        assert_eq!(refresh(&mut supervisor, 2, &[], &mut manager).retired, 1);
    }

    #[test]
    fn unavailable_launch_is_retried_without_a_native_fallback() {
        let a = xhci(5, 1);
        let mut supervisor = HardwareSupervisor::<u32, 1>::default();
        let mut manager = Manager {
            refuse_launch: true,
            ..Manager::default()
        };
        assert_eq!(
            refresh(&mut supervisor, 1, &[a], &mut manager).launch_failed,
            1
        );
        assert!(manager.events.is_empty());
        manager.refuse_launch = false;
        assert_eq!(refresh(&mut supervisor, 2, &[a], &mut manager).started, 1);
        assert_eq!(manager.events.as_slice(), &[(Some(a), 1)]);
    }
}
