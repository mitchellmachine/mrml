use crate::arch::x86_64::UserContext;
use crate::{
    IsolationApplicationBackend, IsolationApplicationSpec, IsolationBackendFailure,
    IsolationPlacement, IsolationUnavailableReason, Priority, ScheduleOutcome,
    ServiceAddressSpaceEraser, TaskId, TaskRuntime, TaskRuntimeError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeApplicationEndpoint {
    task: TaskId,
    spec: IsolationApplicationSpec,
}

impl NativeApplicationEndpoint {
    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn spec(self) -> IsolationApplicationSpec {
        self.spec
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeApplicationError<E> {
    InvalidExpectedPlacement,
    AdmissionMismatch,
    RuntimeNotDedicated,
    AlreadyRunning,
    WrongEndpoint,
    Runtime(TaskRuntimeError),
    Eraser(E),
}

#[derive(Clone, Copy)]
enum NativeApplicationState {
    Running(NativeApplicationEndpoint),
    Cleanup {
        endpoint: NativeApplicationEndpoint,
        context: UserContext,
    },
}

/// Concrete native-process placement for one immutable application generation.
///
/// This first bounded adapter owns a dedicated task runtime. Launch creates no
/// `ServiceId` and grants no capability from package metadata. Revocation
/// removes the complete task authority domain before address-space erasure; an
/// uncertain erasure retains exact cleanup state for retry.
pub struct NativeApplicationBackend<'a, E, const TASKS: usize, const CAPS: usize> {
    runtime: &'a mut TaskRuntime<TASKS, CAPS>,
    eraser: &'a mut E,
    expected: IsolationApplicationSpec,
    priority: Priority,
    context: UserContext,
    state: Option<NativeApplicationState>,
}

impl<'a, E, const TASKS: usize, const CAPS: usize> NativeApplicationBackend<'a, E, TASKS, CAPS>
where
    E: ServiceAddressSpaceEraser,
{
    pub fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPS>,
        eraser: &'a mut E,
        expected: IsolationApplicationSpec,
        priority: Priority,
        context: UserContext,
    ) -> Result<Self, NativeApplicationError<E::Error>> {
        if expected.placement() != IsolationPlacement::NativeProcess {
            return Err(NativeApplicationError::InvalidExpectedPlacement);
        }
        if runtime.current().is_some() || runtime.load().occupied() != 0 {
            return Err(NativeApplicationError::RuntimeNotDedicated);
        }
        Ok(Self {
            runtime,
            eraser,
            expected,
            priority,
            context,
            state: None,
        })
    }

    pub const fn active(&self) -> Option<NativeApplicationEndpoint> {
        match self.state {
            Some(NativeApplicationState::Running(endpoint))
            | Some(NativeApplicationState::Cleanup { endpoint, .. }) => Some(endpoint),
            None => None,
        }
    }

    pub fn runtime(&self) -> &TaskRuntime<TASKS, CAPS> {
        self.runtime
    }

    fn complete_cleanup(
        &mut self,
        endpoint: NativeApplicationEndpoint,
        context: UserContext,
    ) -> Result<(), NativeApplicationError<E::Error>> {
        match self.eraser.erase(endpoint.task, context) {
            Ok(()) => {
                self.state = None;
                Ok(())
            }
            Err(error) => {
                self.state = Some(NativeApplicationState::Cleanup { endpoint, context });
                Err(NativeApplicationError::Eraser(error))
            }
        }
    }
}

impl<E: ServiceAddressSpaceEraser, const TASKS: usize, const CAPS: usize>
    IsolationApplicationBackend for NativeApplicationBackend<'_, E, TASKS, CAPS>
{
    type Endpoint = NativeApplicationEndpoint;
    type Error = NativeApplicationError<E::Error>;

    fn launch_native_process(
        &mut self,
        spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        if self.state.is_some() {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::NativeProcessResource,
                NativeApplicationError::AlreadyRunning,
            ));
        }
        if spec != self.expected || spec.placement() != IsolationPlacement::NativeProcess {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::InterfaceTransport,
                NativeApplicationError::AdmissionMismatch,
            ));
        }
        if self.runtime.current().is_some() || self.runtime.load().occupied() != 0 {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::NativeProcessResource,
                NativeApplicationError::RuntimeNotDedicated,
            ));
        }
        let task = self
            .runtime
            .create(self.priority, self.context)
            .map_err(|error| {
                IsolationBackendFailure::new(
                    IsolationUnavailableReason::NativeProcessResource,
                    NativeApplicationError::Runtime(error),
                )
            })?;
        if self.runtime.start()
            != (ScheduleOutcome::Switch {
                from: None,
                to: task,
            })
        {
            return Err(IsolationBackendFailure::new(
                IsolationUnavailableReason::NativeProcessResource,
                NativeApplicationError::Runtime(TaskRuntimeError::IntegrityFailure),
            ));
        }
        let endpoint = NativeApplicationEndpoint { task, spec };
        self.state = Some(NativeApplicationState::Running(endpoint));
        Ok(endpoint)
    }

    fn launch_microvm_application(
        &mut self,
        _spec: IsolationApplicationSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        Err(IsolationBackendFailure::new(
            IsolationUnavailableReason::VmmResource,
            NativeApplicationError::AdmissionMismatch,
        ))
    }

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        match self.state {
            Some(NativeApplicationState::Running(active)) if active == *endpoint => {
                if self.runtime.current() != Some(active.task) {
                    return Err(NativeApplicationError::WrongEndpoint);
                }
                let (termination, context) = self
                    .runtime
                    .terminate_current_with_context()
                    .map_err(NativeApplicationError::Runtime)?;
                if termination.task != active.task {
                    return Err(NativeApplicationError::WrongEndpoint);
                }
                self.runtime
                    .dispatch_after_termination(termination)
                    .map_err(|_| {
                        NativeApplicationError::Runtime(TaskRuntimeError::IntegrityFailure)
                    })?;
                self.state = Some(NativeApplicationState::Cleanup {
                    endpoint: active,
                    context,
                });
                self.complete_cleanup(active, context)
            }
            Some(NativeApplicationState::Cleanup {
                endpoint: active,
                context,
            }) if active == *endpoint => self.complete_cleanup(active, context),
            _ => Err(NativeApplicationError::WrongEndpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IsolationAdmissionTable, IsolationApplicationRouteError, IsolationMode, ObjectId, PhysAddr,
        route_isolation_application,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EraseError {
        Uncertain,
    }

    struct Eraser {
        fail: bool,
        calls: usize,
        last: Option<(TaskId, UserContext)>,
    }

    impl ServiceAddressSpaceEraser for Eraser {
        type Error = EraseError;

        fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error> {
            self.calls += 1;
            self.last = Some((task, context));
            if self.fail {
                Err(EraseError::Uncertain)
            } else {
                Ok(())
            }
        }
    }

    fn spec(placement: IsolationPlacement) -> IsolationApplicationSpec {
        IsolationApplicationSpec::new(
            ObjectId(0x91),
            ObjectId(0x4d52_4d4c_4755_49),
            3,
            [0x73; 64],
            14,
            9,
            placement,
        )
        .unwrap()
    }

    fn context() -> UserContext {
        UserContext::new(PhysAddr::new(0x2000).unwrap(), 0x4000_0000, 0x7000_0000).unwrap()
    }

    #[test]
    fn native_application_launches_one_task_without_service_identity() {
        let expected = spec(IsolationPlacement::NativeProcess);
        let mut runtime = TaskRuntime::<1, 2>::new(1_000, 1).unwrap();
        let mut eraser = Eraser {
            fail: false,
            calls: 0,
            last: None,
        };
        let mut backend = NativeApplicationBackend::new(
            &mut runtime,
            &mut eraser,
            expected,
            Priority::NORMAL,
            context(),
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 14, 9).unwrap();
        let routed = route_isolation_application(&mut admission, &mut backend, expected).unwrap();
        assert_eq!(routed.spec(), expected);
        assert_eq!(backend.active(), Some(*routed.endpoint()));
        assert_eq!(backend.runtime().load().occupied(), 1);
        assert_eq!(backend.runtime().current(), Some(routed.endpoint().task()));
        backend.revoke(routed.endpoint()).unwrap();
        assert_eq!(backend.active(), None);
        assert_eq!(backend.runtime().load().occupied(), 0);
        assert_eq!(eraser.calls, 1);
    }

    #[test]
    fn uncertain_erasure_retains_exact_cleanup_for_retry() {
        let expected = spec(IsolationPlacement::NativeProcess);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let mut eraser = Eraser {
            fail: true,
            calls: 0,
            last: None,
        };
        let mut backend = NativeApplicationBackend::new(
            &mut runtime,
            &mut eraser,
            expected,
            Priority::NORMAL,
            context(),
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 14, 9).unwrap();
        let routed = route_isolation_application(&mut admission, &mut backend, expected).unwrap();
        let endpoint = *routed.endpoint();
        assert_eq!(
            backend.revoke(&endpoint),
            Err(NativeApplicationError::Eraser(EraseError::Uncertain))
        );
        assert_eq!(backend.runtime().load().occupied(), 0);
        assert_eq!(backend.active(), Some(endpoint));
        backend.eraser.fail = false;
        backend.revoke(&endpoint).unwrap();
        assert_eq!(backend.active(), None);
        assert_eq!(backend.eraser.calls, 2);
        assert_eq!(backend.eraser.last.unwrap().0, endpoint.task());
    }

    #[test]
    fn mismatched_identity_and_microvm_entry_create_no_native_task() {
        let expected = spec(IsolationPlacement::NativeProcess);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let mut eraser = Eraser {
            fail: false,
            calls: 0,
            last: None,
        };
        let mut backend = NativeApplicationBackend::new(
            &mut runtime,
            &mut eraser,
            expected,
            Priority::NORMAL,
            context(),
        )
        .unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 14, 9).unwrap();
        let different = IsolationApplicationSpec::new(
            expected.domain(),
            expected.application(),
            expected.application_generation() + 1,
            expected.application_artifact(),
            expected.system_generation(),
            expected.policy_generation(),
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert!(matches!(
            route_isolation_application(&mut admission, &mut backend, different),
            Err(IsolationApplicationRouteError::Backend {
                reason: IsolationUnavailableReason::InterfaceTransport,
                ..
            })
        ));
        assert_eq!(backend.runtime().load().occupied(), 0);

        let mut microvm_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 14, 9).unwrap();
        assert!(matches!(
            route_isolation_application(
                &mut microvm_admission,
                &mut backend,
                spec(IsolationPlacement::Microvm),
            ),
            Err(IsolationApplicationRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                ..
            })
        ));
        assert_eq!(backend.runtime().load().occupied(), 0);
        assert_eq!(eraser.calls, 0);
    }

    #[test]
    fn constructor_rejects_non_dedicated_runtime_and_microvm_expectation() {
        let mut occupied = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        occupied.create(Priority::NORMAL, context()).unwrap();
        let mut eraser = Eraser {
            fail: false,
            calls: 0,
            last: None,
        };
        assert!(matches!(
            NativeApplicationBackend::new(
                &mut occupied,
                &mut eraser,
                spec(IsolationPlacement::NativeProcess),
                Priority::NORMAL,
                context(),
            ),
            Err(NativeApplicationError::RuntimeNotDedicated)
        ));
        let mut empty = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        assert!(matches!(
            NativeApplicationBackend::new(
                &mut empty,
                &mut eraser,
                spec(IsolationPlacement::Microvm),
                Priority::NORMAL,
                context(),
            ),
            Err(NativeApplicationError::InvalidExpectedPlacement)
        ));
    }
}
