use crate::{
    IsolationApplicationBackend, IsolationApplicationSpec, IsolationBackendFailure,
    IsolationPlacement, IsolationUnavailableReason,
};

pub trait ApplicationMicrovmFactory {
    type Guest;
    type Error;

    fn prepare(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)>;

    fn destroy(&mut self, guest: &mut Self::Guest) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedApplicationGuestError {
    BindingMismatch,
    AlreadyConsumed,
}

/// Transfers one already constructed backend guest into the common application
/// lifecycle. Transfer revalidates the complete immutable application route and
/// consumes the guest at most once.
pub struct AdmittedApplicationGuestFactory<Guest> {
    expected: IsolationApplicationSpec,
    guest: Option<Guest>,
}

impl<Guest> AdmittedApplicationGuestFactory<Guest> {
    pub const fn new(expected: IsolationApplicationSpec, guest: Guest) -> Self {
        Self {
            expected,
            guest: Some(guest),
        }
    }
}

impl<Guest> ApplicationMicrovmFactory for AdmittedApplicationGuestFactory<Guest> {
    type Guest = Guest;
    type Error = AdmittedApplicationGuestError;

    fn prepare(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)> {
        if spec != self.expected {
            return Err((
                IsolationUnavailableReason::InterfaceTransport,
                AdmittedApplicationGuestError::BindingMismatch,
            ));
        }
        self.guest.take().ok_or((
            IsolationUnavailableReason::VmmResource,
            AdmittedApplicationGuestError::AlreadyConsumed,
        ))
    }

    fn destroy(&mut self, _guest: &mut Self::Guest) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationMicrovmEndpoint {
    launch_generation: u64,
    spec: IsolationApplicationSpec,
}

impl ApplicationMicrovmEndpoint {
    pub const fn launch_generation(self) -> u64 {
        self.launch_generation
    }

    pub const fn spec(self) -> IsolationApplicationSpec {
        self.spec
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationMicrovmError<E> {
    AlreadyRunning,
    WrongEndpoint,
    GenerationExhausted,
    AdmissionMismatch,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationMicrovmAccessError {
    WrongEndpoint,
}

/// Owns one backend-prepared application microVM until confirmed destruction.
/// Failed destruction retains the guest and its exact generational endpoint for
/// retry; neither construction nor teardown attempts native-process fallback.
pub struct PreparedMicrovmApplicationBackend<Factory: ApplicationMicrovmFactory> {
    factory: Factory,
    active: Option<(ApplicationMicrovmEndpoint, Factory::Guest)>,
    next_generation: u64,
}

impl<Factory: ApplicationMicrovmFactory> PreparedMicrovmApplicationBackend<Factory> {
    pub const fn new(factory: Factory) -> Self {
        Self {
            factory,
            active: None,
            next_generation: 1,
        }
    }

    pub const fn factory(&self) -> &Factory {
        &self.factory
    }

    pub fn factory_mut(&mut self) -> &mut Factory {
        &mut self.factory
    }

    pub fn active(&self) -> Option<ApplicationMicrovmEndpoint> {
        self.active.as_ref().map(|(endpoint, _)| *endpoint)
    }

    pub fn active_guest(
        &self,
        endpoint: ApplicationMicrovmEndpoint,
    ) -> Result<&Factory::Guest, ApplicationMicrovmAccessError> {
        match self.active.as_ref() {
            Some((active, guest)) if *active == endpoint => Ok(guest),
            _ => Err(ApplicationMicrovmAccessError::WrongEndpoint),
        }
    }

    pub fn active_guest_mut(
        &mut self,
        endpoint: ApplicationMicrovmEndpoint,
    ) -> Result<&mut Factory::Guest, ApplicationMicrovmAccessError> {
        match self.active.as_mut() {
            Some((active, guest)) if *active == endpoint => Ok(guest),
            _ => Err(ApplicationMicrovmAccessError::WrongEndpoint),
        }
    }
}

impl<Factory: ApplicationMicrovmFactory> IsolationApplicationBackend
    for PreparedMicrovmApplicationBackend<Factory>
{
    type Endpoint = ApplicationMicrovmEndpoint;
    type Error = ApplicationMicrovmError<Factory::Error>;

    #[cfg(not(target_os = "uefi"))]
    fn launch_native_process(
        &mut self,
        _spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        Err(IsolationBackendFailure::new(
            IsolationUnavailableReason::NativeProcessResource,
            ApplicationMicrovmError::AdmissionMismatch,
        ))
    }

    fn launch_microvm_application(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        if spec.placement() != IsolationPlacement::Microvm {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::InterfaceTransport,
                ApplicationMicrovmError::AdmissionMismatch,
            ));
        }
        if self.active.is_some() {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::VmmResource,
                ApplicationMicrovmError::AlreadyRunning,
            ));
        }
        let next_generation = self.next_generation.checked_add(1).ok_or_else(|| {
            IsolationBackendFailure::new(
                IsolationUnavailableReason::VmmResource,
                ApplicationMicrovmError::GenerationExhausted,
            )
        })?;
        let guest = self.factory.prepare(spec).map_err(|(reason, error)| {
            IsolationBackendFailure::new(reason, ApplicationMicrovmError::Backend(error))
        })?;
        let endpoint = ApplicationMicrovmEndpoint {
            launch_generation: self.next_generation,
            spec,
        };
        self.active = Some((endpoint, guest));
        self.next_generation = next_generation;
        Ok(endpoint)
    }

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        let (active, guest) = self
            .active
            .as_mut()
            .ok_or(ApplicationMicrovmError::WrongEndpoint)?;
        if active != endpoint {
            return Err(ApplicationMicrovmError::WrongEndpoint);
        }
        self.factory
            .destroy(guest)
            .map_err(ApplicationMicrovmError::Backend)?;
        self.active = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IsolationAdmissionTable, IsolationApplicationRouteError, IsolationMode, ObjectId,
        route_isolation_application,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FactoryError {
        Prepare,
        Destroy,
    }

    #[derive(Default)]
    struct Factory {
        prepare_calls: usize,
        destroy_calls: usize,
        fail_prepare: bool,
        fail_destroy: bool,
    }

    impl ApplicationMicrovmFactory for Factory {
        type Guest = u64;
        type Error = FactoryError;

        fn prepare(
            &mut self,
            spec: IsolationApplicationSpec,
        ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)> {
            self.prepare_calls += 1;
            if self.fail_prepare {
                Err((
                    IsolationUnavailableReason::VmmResource,
                    FactoryError::Prepare,
                ))
            } else {
                Ok(spec.application_generation())
            }
        }

        fn destroy(&mut self, _guest: &mut Self::Guest) -> Result<(), Self::Error> {
            self.destroy_calls += 1;
            if self.fail_destroy {
                Err(FactoryError::Destroy)
            } else {
                Ok(())
            }
        }
    }

    fn spec(generation: u64) -> IsolationApplicationSpec {
        IsolationApplicationSpec::new(
            ObjectId(0xa1),
            ObjectId(0x4d52_4d4c_4755_49),
            generation,
            [0x84; 64],
            14,
            9,
            IsolationPlacement::Microvm,
        )
        .unwrap()
    }

    #[test]
    fn microvm_owner_retains_exact_route_and_guest_until_destroyed() {
        let expected = spec(3);
        let mut backend = PreparedMicrovmApplicationBackend::new(Factory::default());
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 14, 9).unwrap();
        let routed = route_isolation_application(&mut admission, &mut backend, expected).unwrap();
        let endpoint = *routed.endpoint();
        assert_eq!(endpoint.launch_generation(), 1);
        assert_eq!(endpoint.spec(), expected);
        assert_eq!(backend.active_guest(endpoint), Ok(&3));
        *backend.active_guest_mut(endpoint).unwrap() = 4;
        assert_eq!(backend.active_guest(endpoint), Ok(&4));
        assert!(admission.total_microvm_report().satisfied());
        backend.revoke(&endpoint).unwrap();
        assert_eq!(backend.active(), None);
        assert_eq!(backend.factory().destroy_calls, 1);
    }

    #[test]
    fn failed_prepare_is_unavailable_and_never_attempts_native() {
        let mut backend = PreparedMicrovmApplicationBackend::new(Factory {
            fail_prepare: true,
            ..Factory::default()
        });
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 14, 9).unwrap();
        assert!(matches!(
            route_isolation_application(&mut admission, &mut backend, spec(3)),
            Err(IsolationApplicationRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                error: ApplicationMicrovmError::Backend(FactoryError::Prepare),
            })
        ));
        assert_eq!(backend.factory().prepare_calls, 1);
        assert_eq!(backend.active(), None);
        assert_eq!(admission.total_microvm_report().native_fallback, 0);
        assert!(admission.total_microvm_report().satisfied());
    }

    #[test]
    fn failed_destroy_retains_exact_guest_and_endpoint_for_retry() {
        let expected = spec(3);
        let mut backend = PreparedMicrovmApplicationBackend::new(Factory {
            fail_destroy: true,
            ..Factory::default()
        });
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 14, 9).unwrap();
        let routed = route_isolation_application(&mut admission, &mut backend, expected).unwrap();
        let endpoint = *routed.endpoint();
        assert_eq!(
            backend.revoke(&endpoint),
            Err(ApplicationMicrovmError::Backend(FactoryError::Destroy))
        );
        assert_eq!(backend.active(), Some(endpoint));
        assert_eq!(backend.active_guest(endpoint), Ok(&3));
        backend.factory_mut().fail_destroy = false;
        backend.revoke(&endpoint).unwrap();
        assert_eq!(backend.active(), None);
        assert_eq!(backend.factory().destroy_calls, 2);
    }

    #[test]
    fn stale_endpoint_and_second_active_launch_fail_closed() {
        let expected = spec(3);
        let mut backend = PreparedMicrovmApplicationBackend::new(Factory::default());
        let mut admission =
            IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 14, 9).unwrap();
        let first = route_isolation_application(&mut admission, &mut backend, expected).unwrap();
        let endpoint = *first.endpoint();
        let stale = ApplicationMicrovmEndpoint {
            launch_generation: endpoint.launch_generation() + 1,
            spec: expected,
        };
        assert_eq!(
            backend.active_guest(stale),
            Err(ApplicationMicrovmAccessError::WrongEndpoint)
        );
        assert_eq!(
            backend.revoke(&stale),
            Err(ApplicationMicrovmError::WrongEndpoint)
        );
        let second = IsolationApplicationSpec::new(
            ObjectId(0xa2),
            expected.application(),
            4,
            expected.application_artifact(),
            expected.system_generation(),
            expected.policy_generation(),
            IsolationPlacement::Microvm,
        )
        .unwrap();
        assert!(matches!(
            route_isolation_application(&mut admission, &mut backend, second),
            Err(IsolationApplicationRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                error: ApplicationMicrovmError::AlreadyRunning,
            })
        ));
        assert_eq!(backend.active(), Some(endpoint));
    }

    #[test]
    fn admitted_guest_transfer_rechecks_identity_and_is_one_use() {
        let expected = spec(3);
        let mut factory = AdmittedApplicationGuestFactory::new(expected, 0x55_u64);
        assert_eq!(
            factory.prepare(spec(4)),
            Err((
                IsolationUnavailableReason::InterfaceTransport,
                AdmittedApplicationGuestError::BindingMismatch,
            ))
        );
        assert_eq!(factory.prepare(expected), Ok(0x55));
        assert_eq!(
            factory.prepare(expected),
            Err((
                IsolationUnavailableReason::VmmResource,
                AdmittedApplicationGuestError::AlreadyConsumed,
            ))
        );
    }
}
