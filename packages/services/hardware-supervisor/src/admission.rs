//! Bridge from a discovery request to the existing kernel admission table.
//! This step never launches a VM or produces a hardware projection.

use crate::{MAX_PCI_OBSERVATIONS, PciObservation, XhciLaunch};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, IsolationAdmissionTable, IsolationLaunchError,
    IsolationMode, IsolationPlacement, IsolationServiceSpec, ObjectId,
    PreparedIsolationServiceRoute, Rights, TotalMicrovmClass, prepare_isolation_service_route,
};

/// Supplied by the trusted runtime's independently configured controller
/// registry. Never construct these rows from an inventory report or from
/// service-provided bytes. The capability is retained by the runtime.
#[derive(Clone, Copy)]
pub struct XhciRouteBinding {
    pub controller: PciObservation,
    pub device_object: ObjectId,
    pub device_control: Capability,
    pub spec: IsolationServiceSpec,
}

pub struct XhciRouteCatalog<'a> {
    entries: &'a [XhciRouteBinding],
}

#[derive(Debug, Eq, PartialEq)]
pub enum XhciAdmissionError {
    InvalidCatalog,
    DuplicateBinding,
    WrongController,
    NotTotalMicrovm,
    Capability(CapabilityError),
    WrongDeviceObject,
    Admission(IsolationLaunchError),
}

pub struct PreparedXhciRoute {
    controller: PciObservation,
    route: PreparedIsolationServiceRoute,
}

impl PreparedXhciRoute {
    /// Controller identity binds subsequent independent projection checks.
    /// This route alone is not device, interrupt, memory, or DMA authority.
    pub fn into_parts(self) -> (PciObservation, PreparedIsolationServiceRoute) {
        (self.controller, self.route)
    }
}

impl<'a> XhciRouteCatalog<'a> {
    pub fn new(entries: &'a [XhciRouteBinding]) -> Result<Self, XhciAdmissionError> {
        if entries.len() > MAX_PCI_OBSERVATIONS {
            return Err(XhciAdmissionError::InvalidCatalog);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !entry.controller.is_xhci()
                || matches!(entry.controller.vendor, 0 | u16::MAX)
                || entry.controller.incarnation == 0
                || entry.device_object.0 == 0
                || entry.spec.domain().0 == 0
                || entry.spec.interface().0 == 0
                || entry.spec.domain() == entry.device_object
            {
                return Err(XhciAdmissionError::InvalidCatalog);
            }
            if entry.spec.class() != TotalMicrovmClass::MicrovmEligible
                || entry.spec.placement() != IsolationPlacement::Microvm
            {
                return Err(XhciAdmissionError::NotTotalMicrovm);
            }
            if entries[..index].iter().any(|prior| {
                prior.controller.address == entry.controller.address
                    || prior.spec.domain() == entry.spec.domain()
                    || prior.device_object == entry.device_object
                    || prior.device_control == entry.device_control
            }) {
                return Err(XhciAdmissionError::DuplicateBinding);
            }
        }
        Ok(Self { entries })
    }

    pub fn prepare<const D: usize, const C: usize>(
        &self,
        launch: XhciLaunch,
        admission: &mut IsolationAdmissionTable<D>,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<PreparedXhciRoute, XhciAdmissionError> {
        if admission.mode() != IsolationMode::TotalMicrovm {
            return Err(XhciAdmissionError::NotTotalMicrovm);
        }
        let controller = launch.controller();
        let row = self
            .entries
            .iter()
            .find(|row| row.controller == controller)
            .ok_or(XhciAdmissionError::WrongController)?;
        let object = capabilities
            .authorize_exact(row.device_control, Rights::CONTROL)
            .map_err(XhciAdmissionError::Capability)?;
        if object != row.device_object {
            return Err(XhciAdmissionError::WrongDeviceObject);
        }
        let route = prepare_isolation_service_route(admission, row.spec)
            .map_err(XhciAdmissionError::Admission)?;
        Ok(PreparedXhciRoute { controller, route })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::DeviceAddress;

    fn launch(device: u8, incarnation: u64) -> XhciLaunch {
        XhciLaunch {
            controller: PciObservation {
                address: DeviceAddress::new(0, 0, device, 0).unwrap(),
                vendor: 0x1b36,
                device: 0x000d,
                class_revision: 0x0c03_3001,
                incarnation,
            },
        }
    }

    fn spec(domain: u64, system: u64, placement: IsolationPlacement) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(domain),
            ObjectId(42),
            1,
            1,
            system,
            1,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    #[test]
    fn prepares_distinct_exact_controller_domains_without_starting_a_vm() {
        let mut caps = CapabilitySpace::<4>::new();
        let a = launch(5, 1);
        let b = launch(6, 1);
        let entries = [a, b].map(|launch| {
            let index = u64::from(launch.controller().address.device());
            let object = ObjectId(index);
            XhciRouteBinding {
                controller: launch.controller(),
                device_object: object,
                device_control: caps.insert(object, Rights::CONTROL).unwrap(),
                spec: spec(100 + index, 1, IsolationPlacement::Microvm),
            }
        });
        let catalog = XhciRouteCatalog::new(&entries).unwrap();
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 1, 1).unwrap();
        let (id_a, route_a) = catalog.prepare(a, &mut table, &caps).unwrap().into_parts();
        let (id_b, route_b) = catalog.prepare(b, &mut table, &caps).unwrap().into_parts();
        assert_eq!((id_a, id_b), (a.controller(), b.controller()));
        assert_eq!(
            (route_a.spec().domain(), route_b.spec().domain()),
            (ObjectId(105), ObjectId(106))
        );
        assert!(matches!(
            catalog.prepare(a, &mut table, &caps),
            Err(XhciAdmissionError::Admission(_))
        ));
        route_a.cancel(&mut table).unwrap();
        route_b.cancel(&mut table).unwrap();
    }

    #[test]
    fn rejects_mismatched_reused_missing_or_revoked_bindings() {
        let mut caps = CapabilitySpace::<4>::new();
        let a = launch(5, 1);
        let object = ObjectId(5);
        let cap = caps.insert(object, Rights::CONTROL).unwrap();
        let original = XhciRouteBinding {
            controller: a.controller(),
            device_object: object,
            device_control: cap,
            spec: spec(105, 1, IsolationPlacement::Microvm),
        };
        let mut table =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 1, 1).unwrap();
        let entries = [original];
        let catalog = XhciRouteCatalog::new(&entries).unwrap();
        assert!(matches!(
            catalog.prepare(launch(5, 2), &mut table, &caps),
            Err(XhciAdmissionError::WrongController)
        ));
        assert!(matches!(
            catalog.prepare(launch(6, 1), &mut table, &caps),
            Err(XhciAdmissionError::WrongController)
        ));
        let mut changed = a;
        changed.controller.class_revision ^= 1;
        assert!(matches!(
            catalog.prepare(changed, &mut table, &caps),
            Err(XhciAdmissionError::WrongController)
        ));
        let duplicate = XhciRouteBinding {
            controller: launch(6, 1).controller(),
            ..original
        };
        assert!(matches!(
            XhciRouteCatalog::new(&[original, duplicate]),
            Err(XhciAdmissionError::DuplicateBinding)
        ));
        let wrong_object = [XhciRouteBinding {
            device_object: ObjectId(6),
            ..original
        }];
        assert!(matches!(
            XhciRouteCatalog::new(&wrong_object)
                .unwrap()
                .prepare(a, &mut table, &caps),
            Err(XhciAdmissionError::WrongDeviceObject)
        ));
        let stale = [XhciRouteBinding {
            spec: spec(105, 2, IsolationPlacement::Microvm),
            ..original
        }];
        assert!(matches!(
            XhciRouteCatalog::new(&stale)
                .unwrap()
                .prepare(a, &mut table, &caps),
            Err(XhciAdmissionError::Admission(_))
        ));
        caps.revoke(cap).unwrap();
        assert!(matches!(
            catalog.prepare(a, &mut table, &caps),
            Err(XhciAdmissionError::Capability(_))
        ));
    }

    #[test]
    fn rejects_native_placement_before_preparing_any_route() {
        let entry = XhciRouteBinding {
            controller: launch(5, 1).controller(),
            device_object: ObjectId(5),
            device_control: Capability::from_token(0),
            spec: spec(105, 1, IsolationPlacement::NativeService),
        };
        assert!(matches!(
            XhciRouteCatalog::new(&[entry]),
            Err(XhciAdmissionError::NotTotalMicrovm)
        ));
    }
}
