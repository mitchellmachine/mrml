#![no_std]

//! Fixed-capacity policy/configuration service foundation.
//!
//! Setting identifiers select records; they never authorize access. Every
//! read and transaction update repeats exact capability checks against the
//! schema-bound object. Transactions preflight all schema, authority, revision,
//! capacity, and sequence conditions before the first mutation.
//! Control planes establish authority; data planes should take the shortest
//! safe path. Persisted policy is therefore typed control-plane input only: it
//! neither grants capabilities nor becomes an invocation-path data transport.

use core::array;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use mrml_crypto::Sha3_256;
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    ActivatedReleaseTotalMicrovmInventory, BootHandoff, BootIsolationOverride, Capability,
    CapabilityError, CapabilitySpace, IsolationAdmissionTable, IsolationBackendFailure,
    IsolationMode, IsolationPlacement, IsolationServiceBackend, IsolationServiceRouteError,
    IsolationServiceSpec, IsolationStatusSnapshot, IsolationUnavailableReason, MemoryBackingKind,
    MemoryObjectId, MemoryPoolId, MemoryPoolTable, MemoryResourceError, Message, ObjectId,
    PAGE_SIZE, PreparedIsolationServiceRoute, Priority, RestartPolicy, Rights,
    RoutedIsolationService, ServiceAddressSpaceEraser, ServiceCleanupError, ServiceError,
    ServiceId, ServiceRegistrationPlan, ServiceState, ServiceSupervisor, TaskId, TaskRuntime,
    TaskRuntimeError, prepare_isolation_service_route, route_isolation_service,
};
use mrml_storage::{
    AuthorityRecoveryValidator, BlockFileSession, BlockVolume, BlockVolumeError,
    CommittedRecoveredStorageAuthorities, ExtentMap, FileMetadata, FileReadBackend, FileReadError,
    FileState, FileWriteBackend, FileWriteError, MetadataPointer, PreparedFileWrite,
    ReachableFileSelection, RecoveredStorageAuthorities, StorageAuthorityTable, StorageBlockDevice,
    StorageHandle, StoragePrincipal, StorageTransaction, TransactionError, TransactionReceipt,
    VolumeId,
};

#[cfg(any(test, target_os = "windows", target_os = "linux"))]
pub mod hosted_recovery_probe;

pub const MAX_CONFIG_VALUE_BYTES: usize = 64;
pub const MAX_WIRE_UPDATES: usize = 4;
pub const CONFIG_REQUEST_HEADER_BYTES: usize = 48;
pub const CONFIG_UPDATE_BYTES: usize = 80;
pub const CONFIG_SCHEMA_BYTES: usize = 32;
pub const MAX_CONFIG_REQUEST_BYTES: usize =
    CONFIG_REQUEST_HEADER_BYTES + MAX_WIRE_UPDATES * CONFIG_UPDATE_BYTES;
pub const CONFIG_RESPONSE_BYTES: usize = 112;
pub const SUPERVISION_REQUEST_BYTES: usize = 48;
pub const SUPERVISION_RESPONSE_BYTES: usize = 48;
pub const SYSTEM_PROTOCOL_VERSION: u16 = 1;
pub const CONFIG_CHECKPOINT_HEADER_BYTES: usize = 96;
pub const CONFIG_CHECKPOINT_SETTING_BYTES: usize = 112;
pub const CONFIG_CHECKPOINT_AUDIT_BYTES: usize = 24;
pub const PERSISTED_RESTART_POLICY_BYTES: usize = 48;

const CONFIG_REQUEST_MAGIC: [u8; 4] = *b"MRCQ";
const CONFIG_RESPONSE_MAGIC: [u8; 4] = *b"MRCP";
const SUPERVISION_REQUEST_MAGIC: [u8; 4] = *b"MRSQ";
const SUPERVISION_RESPONSE_MAGIC: [u8; 4] = *b"MRSP";
const CONFIG_CHECKPOINT_MAGIC: [u8; 4] = *b"MRCK";
const PERSISTED_RESTART_POLICY_MAGIC: [u8; 4] = *b"MRRP";
const CONFIG_CHECKPOINT_DIGEST_OFFSET: usize = 64;
const CONFIG_CHECKPOINT_DIGEST_BYTES: usize = 32;

/// The service asks the kernel to validate opaque handles; it never owns or
/// enumerates the kernel capability space. Rejection deliberately carries no
/// object or rights detail.
pub trait CapabilityAuthorizer {
    fn authorize_exact(
        &self,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError>;
}

/// The supervision service asks the kernel to combine an opaque service token
/// with an independently delivered capability. Rejection deliberately exposes
/// no object, generation, rights, or lifecycle detail.
pub trait ServiceStateAuthorizer {
    fn query_state(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceState, ConfigError>;
}

pub trait ServiceRestartAuthorizer {
    fn restart_service(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceId, ConfigError>;
}

pub trait ServicePolicyAuthorizer {
    fn replace_policy(
        &self,
        capability: Capability,
        service: ServiceId,
        policy: RestartPolicy,
    ) -> Result<(), ConfigError>;
}

/// A concrete configuration-service launcher for the native-service form.
/// The returned endpoint is opaque; names and manifest metadata grant no
/// authority to use it.
pub trait NativeConfigurationServiceLauncher {
    type Endpoint;
    type Error;

    fn launch_native(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)>;

    fn revoke_native(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error>;
}

/// A concrete configuration-service launcher for the microVM form. The
/// implementation must return only after the projected endpoint is ready.
pub trait MicrovmConfigurationServiceLauncher {
    type Endpoint;
    type Error;

    fn launch_microvm(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)>;

    fn revoke_microvm(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error>;
}

/// Constructs and destroys one backend-native prepared guest. The guest remains
/// private to the launcher; callers receive only an exact generational endpoint
/// token after construction has completed.
pub trait ConfigurationMicrovmFactory {
    type Guest;
    type Error;

    fn prepare(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)>;

    fn destroy(&mut self, guest: &mut Self::Guest) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedConfigurationGuestError {
    BindingMismatch,
    AlreadyConsumed,
}

/// Transfers one guest already constructed by a backend transaction into the
/// common configuration-microVM lifecycle. The exact service specification is
/// rechecked at transfer, and the guest can be consumed only once.
pub struct AdmittedConfigurationGuestFactory<Guest> {
    expected: IsolationServiceSpec,
    guest: Option<Guest>,
}

impl<Guest> AdmittedConfigurationGuestFactory<Guest> {
    pub const fn new(expected: IsolationServiceSpec, guest: Guest) -> Self {
        Self {
            expected,
            guest: Some(guest),
        }
    }
}

impl<Guest> ConfigurationMicrovmFactory for AdmittedConfigurationGuestFactory<Guest> {
    type Guest = Guest;
    type Error = AdmittedConfigurationGuestError;

    fn prepare(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)> {
        if spec != self.expected {
            return Err((
                IsolationUnavailableReason::InterfaceTransport,
                AdmittedConfigurationGuestError::BindingMismatch,
            ));
        }
        self.guest.take().ok_or((
            IsolationUnavailableReason::VmmResource,
            AdmittedConfigurationGuestError::AlreadyConsumed,
        ))
    }

    fn destroy(&mut self, _guest: &mut Self::Guest) -> Result<(), Self::Error> {
        // Returning success authorizes the launcher to drop the backend-owned
        // guest and all of its native resources as one operation.
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationMicrovmEndpoint {
    launch_generation: u64,
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
    policy_generation: u64,
}

impl ConfigurationMicrovmEndpoint {
    pub const fn launch_generation(self) -> u64 {
        self.launch_generation
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn interface(self) -> ObjectId {
        self.interface
    }

    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedMicrovmConfigurationError<E> {
    AlreadyRunning,
    WrongEndpoint,
    GenerationExhausted,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedMicrovmConfigurationAccessError {
    WrongEndpoint,
}

/// Owns one backend-prepared configuration microVM from successful construction
/// through confirmed destruction. Failed destruction retains both the guest and
/// endpoint for an exact retry; there is no native-service fallback.
pub struct PreparedMicrovmConfigurationLauncher<Factory: ConfigurationMicrovmFactory> {
    factory: Factory,
    active: Option<(ConfigurationMicrovmEndpoint, Factory::Guest)>,
    next_generation: u64,
}

impl<Factory: ConfigurationMicrovmFactory> PreparedMicrovmConfigurationLauncher<Factory> {
    pub const fn new(factory: Factory) -> Self {
        Self {
            factory,
            active: None,
            next_generation: 1,
        }
    }

    pub fn factory(&self) -> &Factory {
        &self.factory
    }

    pub fn factory_mut(&mut self) -> &mut Factory {
        &mut self.factory
    }

    pub fn active(&self) -> Option<ConfigurationMicrovmEndpoint> {
        self.active.as_ref().map(|(endpoint, _)| *endpoint)
    }

    pub fn active_guest(
        &self,
        endpoint: ConfigurationMicrovmEndpoint,
    ) -> Result<&Factory::Guest, PreparedMicrovmConfigurationAccessError> {
        match self.active.as_ref() {
            Some((active, guest)) if *active == endpoint => Ok(guest),
            _ => Err(PreparedMicrovmConfigurationAccessError::WrongEndpoint),
        }
    }

    pub fn active_guest_mut(
        &mut self,
        endpoint: ConfigurationMicrovmEndpoint,
    ) -> Result<&mut Factory::Guest, PreparedMicrovmConfigurationAccessError> {
        match self.active.as_mut() {
            Some((active, guest)) if *active == endpoint => Ok(guest),
            _ => Err(PreparedMicrovmConfigurationAccessError::WrongEndpoint),
        }
    }
}

impl<Factory: ConfigurationMicrovmFactory> MicrovmConfigurationServiceLauncher
    for PreparedMicrovmConfigurationLauncher<Factory>
{
    type Endpoint = ConfigurationMicrovmEndpoint;
    type Error = PreparedMicrovmConfigurationError<Factory::Error>;

    fn launch_microvm(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
        if self.active.is_some() {
            return Err((
                IsolationUnavailableReason::VmmResource,
                PreparedMicrovmConfigurationError::AlreadyRunning,
            ));
        }
        let next_generation = self.next_generation.checked_add(1).ok_or((
            IsolationUnavailableReason::VmmResource,
            PreparedMicrovmConfigurationError::GenerationExhausted,
        ))?;
        let guest = self.factory.prepare(spec).map_err(|(reason, error)| {
            (reason, PreparedMicrovmConfigurationError::Backend(error))
        })?;
        let endpoint = ConfigurationMicrovmEndpoint {
            launch_generation: self.next_generation,
            domain: spec.domain(),
            interface: spec.interface(),
            interface_generation: spec.interface_generation(),
            provider_generation: spec.provider_generation(),
            policy_generation: spec.policy_generation(),
        };
        self.active = Some((endpoint, guest));
        self.next_generation = next_generation;
        Ok(endpoint)
    }

    fn revoke_microvm(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        let (active, guest) = self
            .active
            .as_mut()
            .ok_or(PreparedMicrovmConfigurationError::WrongEndpoint)?;
        if active != endpoint {
            return Err(PreparedMicrovmConfigurationError::WrongEndpoint);
        }
        self.factory
            .destroy(guest)
            .map_err(PreparedMicrovmConfigurationError::Backend)?;
        self.active = None;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConfigurationServiceEndpoint<Native, Microvm> {
    Native(Native),
    Microvm(Microvm),
}

impl<Native, Microvm> ConfigurationServiceEndpoint<Native, Microvm> {
    pub const fn placement(&self) -> IsolationPlacement {
        match self {
            Self::Native(_) => IsolationPlacement::NativeService,
            Self::Microvm(_) => IsolationPlacement::Microvm,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConfigurationPlacementError<Native, Microvm> {
    Native(Native),
    Microvm(Microvm),
}

/// Adapts the two concrete configuration-service forms to the kernel's one
/// fail-closed placement route. It does not choose placement or provider.
pub struct ConfigurationPlacementBackend<Native, Microvm> {
    native: Native,
    microvm: Microvm,
}

impl<Native, Microvm> ConfigurationPlacementBackend<Native, Microvm> {
    pub const fn new(native: Native, microvm: Microvm) -> Self {
        Self { native, microvm }
    }

    pub fn into_parts(self) -> (Native, Microvm) {
        (self.native, self.microvm)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeConfigurationEndpoint {
    service: ServiceId,
    task: TaskId,
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
}

impl NativeConfigurationEndpoint {
    pub const fn service(self) -> ServiceId {
        self.service
    }

    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn interface(self) -> ObjectId {
        self.interface
    }

    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeConfigurationLaunchError<E> {
    AlreadyRunning,
    NonEmptyRuntime,
    WrongEndpoint,
    Service(ServiceError),
    Cleanup(ServiceCleanupError<E>),
}

/// Owns one accounted native configuration-service runtime and its eraser.
/// Successful revocation is reported only after the exact retired address
/// space has been erased and the supervisor cleanup ticket is consumed.
pub struct SupervisedNativeConfigurationLauncher<
    E,
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> {
    substrate: AccountedPolicyServiceSubstrate<TASKS, CAPS, SERVICES, SETTINGS, AUDIT>,
    eraser: E,
    priority: Priority,
    context: UserContext,
    active: Option<NativeConfigurationEndpoint>,
}

impl<
    E,
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> SupervisedNativeConfigurationLauncher<E, TASKS, CAPS, SERVICES, SETTINGS, AUDIT>
{
    pub const fn new(
        substrate: AccountedPolicyServiceSubstrate<TASKS, CAPS, SERVICES, SETTINGS, AUDIT>,
        eraser: E,
        priority: Priority,
        context: UserContext,
    ) -> Self {
        Self {
            substrate,
            eraser,
            priority,
            context,
            active: None,
        }
    }

    pub const fn active(&self) -> Option<NativeConfigurationEndpoint> {
        self.active
    }

    pub const fn substrate(
        &self,
    ) -> &AccountedPolicyServiceSubstrate<TASKS, CAPS, SERVICES, SETTINGS, AUDIT> {
        &self.substrate
    }

    pub const fn eraser(&self) -> &E {
        &self.eraser
    }
}

impl<
    E: ServiceAddressSpaceEraser,
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> NativeConfigurationServiceLauncher
    for SupervisedNativeConfigurationLauncher<E, TASKS, CAPS, SERVICES, SETTINGS, AUDIT>
{
    type Endpoint = NativeConfigurationEndpoint;
    type Error = NativeConfigurationLaunchError<E::Error>;

    fn launch_native(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
        if self.active.is_some() {
            return Err((
                IsolationUnavailableReason::NativeServiceResource,
                NativeConfigurationLaunchError::AlreadyRunning,
            ));
        }
        if self.substrate.runtime.load().occupied() != 0 {
            return Err((
                IsolationUnavailableReason::NativeServiceResource,
                NativeConfigurationLaunchError::NonEmptyRuntime,
            ));
        }
        let (service, task) = self
            .substrate
            .supervisor
            .launch(
                spec.domain(),
                &mut self.substrate.runtime,
                self.priority,
                self.context,
            )
            .map_err(|error| {
                (
                    IsolationUnavailableReason::NativeServiceResource,
                    NativeConfigurationLaunchError::Service(error),
                )
            })?;
        let _ = self.substrate.runtime.start();
        debug_assert_eq!(self.substrate.runtime.current(), Some(task));
        let endpoint = NativeConfigurationEndpoint {
            service,
            task,
            domain: spec.domain(),
            interface: spec.interface(),
            interface_generation: spec.interface_generation(),
            provider_generation: spec.provider_generation(),
        };
        self.active = Some(endpoint);
        Ok(endpoint)
    }

    fn revoke_native(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        if self.active != Some(*endpoint) {
            return Err(NativeConfigurationLaunchError::WrongEndpoint);
        }
        let cleanup = match self.substrate.supervisor.state(endpoint.service) {
            Ok(ServiceState::Running) => {
                self.substrate
                    .supervisor
                    .exit_current(&mut self.substrate.runtime)
                    .map_err(NativeConfigurationLaunchError::Service)?
                    .cleanup
            }
            Ok(ServiceState::Exited | ServiceState::Faulted) => self
                .substrate
                .supervisor
                .pending_cleanup(endpoint.service)
                .map_err(NativeConfigurationLaunchError::Service)?
                .ok_or(NativeConfigurationLaunchError::WrongEndpoint)?,
            Err(error) => return Err(NativeConfigurationLaunchError::Service(error)),
        };
        if cleanup.task() != endpoint.task {
            return Err(NativeConfigurationLaunchError::WrongEndpoint);
        }
        self.substrate
            .supervisor
            .complete_cleanup(cleanup, &mut self.eraser)
            .map_err(NativeConfigurationLaunchError::Cleanup)?;
        self.active = None;
        Ok(())
    }
}

impl<Native, Microvm> IsolationServiceBackend for ConfigurationPlacementBackend<Native, Microvm>
where
    Native: NativeConfigurationServiceLauncher,
    Microvm: MicrovmConfigurationServiceLauncher,
{
    type Endpoint = ConfigurationServiceEndpoint<Native::Endpoint, Microvm::Endpoint>;
    type Error = ConfigurationPlacementError<Native::Error, Microvm::Error>;

    fn launch_native_service(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        self.native
            .launch_native(spec)
            .map(ConfigurationServiceEndpoint::Native)
            .map_err(|(reason, error)| {
                IsolationBackendFailure::new(reason, ConfigurationPlacementError::Native(error))
            })
    }

    fn launch_microvm_service(
        &mut self,
        spec: IsolationServiceSpec,
    ) -> Result<Self::Endpoint, IsolationBackendFailure<Self::Error>> {
        self.microvm
            .launch_microvm(spec)
            .map(ConfigurationServiceEndpoint::Microvm)
            .map_err(|(reason, error)| {
                IsolationBackendFailure::new(reason, ConfigurationPlacementError::Microvm(error))
            })
    }

    fn revoke(&mut self, endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
        match endpoint {
            ConfigurationServiceEndpoint::Native(endpoint) => self
                .native
                .revoke_native(endpoint)
                .map_err(ConfigurationPlacementError::Native),
            ConfigurationServiceEndpoint::Microvm(endpoint) => self
                .microvm
                .revoke_microvm(endpoint)
                .map_err(ConfigurationPlacementError::Microvm),
        }
    }
}

impl<const CAPS: usize> CapabilityAuthorizer for CapabilitySpace<CAPS> {
    fn authorize_exact(
        &self,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        let object = self
            .authorize(capability, rights)
            .map_err(ConfigError::Unauthorized)?;
        (object == expected)
            .then_some(())
            .ok_or(ConfigError::WrongObject)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingId(u32);

impl SettingId {
    pub const fn new(value: u32) -> Result<Self, ConfigError> {
        if value == 0 {
            return Err(ConfigError::InvalidSetting);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValueKind {
    Bool = 1,
    U64 = 2,
    Bytes = 3,
}

impl ValueKind {
    const fn decode(value: u8) -> Result<Self, ConfigError> {
        match value {
            1 => Ok(Self::Bool),
            2 => Ok(Self::U64),
            3 => Ok(Self::Bytes),
            _ => Err(ConfigError::InvalidValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigValue {
    kind: ValueKind,
    length: u8,
    bytes: [u8; MAX_CONFIG_VALUE_BYTES],
}

impl ConfigValue {
    pub const fn boolean(value: bool) -> Self {
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        bytes[0] = value as u8;
        Self {
            kind: ValueKind::Bool,
            length: 1,
            bytes,
        }
    }

    pub const fn unsigned(value: u64) -> Self {
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        let encoded = value.to_le_bytes();
        let mut index = 0;
        while index < encoded.len() {
            bytes[index] = encoded[index];
            index += 1;
        }
        Self {
            kind: ValueKind::U64,
            length: 8,
            bytes,
        }
    }

    pub fn bytes(value: &[u8]) -> Result<Self, ConfigError> {
        if value.len() > MAX_CONFIG_VALUE_BYTES {
            return Err(ConfigError::InvalidValue);
        }
        let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            kind: ValueKind::Bytes,
            length: value.len() as u8,
            bytes,
        })
    }

    pub const fn kind(self) -> ValueKind {
        self.kind
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub const fn as_bool(self) -> Option<bool> {
        if matches!(self.kind, ValueKind::Bool) && self.length == 1 {
            Some(self.bytes[0] != 0)
        } else {
            None
        }
    }

    pub const fn as_u64(self) -> Option<u64> {
        if !matches!(self.kind, ValueKind::U64) || self.length != 8 {
            return None;
        }
        let mut encoded = [0; 8];
        let mut index = 0;
        while index < encoded.len() {
            encoded[index] = self.bytes[index];
            index += 1;
        }
        Some(u64::from_le_bytes(encoded))
    }

    fn decode(
        kind: u8,
        length: u8,
        bytes: &[u8; MAX_CONFIG_VALUE_BYTES],
    ) -> Result<Self, ConfigError> {
        let kind = ValueKind::decode(kind)?;
        let length = usize::from(length);
        if length > MAX_CONFIG_VALUE_BYTES || bytes[length..].iter().any(|byte| *byte != 0) {
            return Err(ConfigError::NonCanonical);
        }
        match kind {
            ValueKind::Bool if length == 1 && bytes[0] <= 1 => {}
            ValueKind::U64 if length == 8 => {}
            ValueKind::Bytes => {}
            _ => return Err(ConfigError::InvalidValue),
        }
        Ok(Self {
            kind,
            length: length as u8,
            bytes: *bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Constraint {
    Bool,
    U64 { minimum: u64, maximum: u64 },
    Bytes { maximum_length: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingSchema {
    setting: SettingId,
    object: ObjectId,
    constraint: Constraint,
}

impl SettingSchema {
    pub const fn boolean(setting: SettingId, object: ObjectId) -> Result<Self, ConfigError> {
        Self::new(setting, object, Constraint::Bool)
    }

    pub const fn unsigned(
        setting: SettingId,
        object: ObjectId,
        minimum: u64,
        maximum: u64,
    ) -> Result<Self, ConfigError> {
        if minimum > maximum {
            return Err(ConfigError::InvalidSchema);
        }
        Self::new(setting, object, Constraint::U64 { minimum, maximum })
    }

    pub const fn bytes(
        setting: SettingId,
        object: ObjectId,
        maximum_length: u8,
    ) -> Result<Self, ConfigError> {
        if maximum_length == 0 || maximum_length as usize > MAX_CONFIG_VALUE_BYTES {
            return Err(ConfigError::InvalidSchema);
        }
        Self::new(setting, object, Constraint::Bytes { maximum_length })
    }

    const fn new(
        setting: SettingId,
        object: ObjectId,
        constraint: Constraint,
    ) -> Result<Self, ConfigError> {
        if object.0 == 0 {
            return Err(ConfigError::InvalidSchema);
        }
        Ok(Self {
            setting,
            object,
            constraint,
        })
    }

    pub const fn setting(self) -> SettingId {
        self.setting
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    fn validate(self, value: ConfigValue) -> Result<(), ConfigError> {
        match (self.constraint, value.kind) {
            (Constraint::Bool, ValueKind::Bool) => Ok(()),
            (Constraint::U64 { minimum, maximum }, ValueKind::U64) => value
                .as_u64()
                .filter(|value| (minimum..=maximum).contains(value))
                .map(|_| ())
                .ok_or(ConfigError::SchemaViolation),
            (Constraint::Bytes { maximum_length }, ValueKind::Bytes)
                if value.length <= maximum_length =>
            {
                Ok(())
            }
            _ => Err(ConfigError::SchemaViolation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidRoot,
    InvalidSetting,
    InvalidSchema,
    DuplicateSetting,
    DuplicateObject,
    Capacity,
    MissingSetting,
    InvalidValue,
    SchemaViolation,
    EmptyTransaction,
    RevisionConflict { current: u64 },
    RevisionExhausted,
    SequenceExhausted,
    SchemaFrozen,
    Unauthorized(CapabilityError),
    WrongObject,
    AuditUnavailable { oldest: u64 },
    InvalidProtocol,
    UnsupportedVersion,
    Truncated,
    NonCanonical,
    InvalidAuthorityEnvelope,
    InvalidCheckpoint,
    IsolationPolicyMismatch,
    RecoveryHandoffMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationCheckpoint {
    pub length: usize,
    pub digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
}

/// Canonical persistent input to trusted service registration. This record is
/// policy data, not authority: loading requires the setting's exact READ
/// capability and every later restart still requires exact service CONTROL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedRestartPolicy {
    service: ObjectId,
    maximum_restarts: u32,
    base_backoff_ticks: u64,
    maximum_backoff_ticks: u64,
}

impl PersistedRestartPolicy {
    pub fn new(
        service: ObjectId,
        maximum_restarts: u32,
        base_backoff_ticks: u64,
        maximum_backoff_ticks: u64,
    ) -> Result<Self, PersistedRestartPolicyError> {
        if service.0 == 0 {
            return Err(PersistedRestartPolicyError::InvalidRecord);
        }
        RestartPolicy::new(maximum_restarts, base_backoff_ticks, maximum_backoff_ticks)
            .map_err(PersistedRestartPolicyError::Service)?;
        Ok(Self {
            service,
            maximum_restarts,
            base_backoff_ticks,
            maximum_backoff_ticks,
        })
    }

    pub const fn service(self) -> ObjectId {
        self.service
    }

    pub fn restart_policy(self) -> Result<RestartPolicy, PersistedRestartPolicyError> {
        RestartPolicy::new(
            self.maximum_restarts,
            self.base_backoff_ticks,
            self.maximum_backoff_ticks,
        )
        .map_err(PersistedRestartPolicyError::Service)
    }

    pub fn encode(self, output: &mut [u8; PERSISTED_RESTART_POLICY_BYTES]) {
        output.fill(0);
        output[..4].copy_from_slice(&PERSISTED_RESTART_POLICY_MAGIC);
        output[4..6].copy_from_slice(&SYSTEM_PROTOCOL_VERSION.to_le_bytes());
        output[6..8].copy_from_slice(&(PERSISTED_RESTART_POLICY_BYTES as u16).to_le_bytes());
        output[8..16].copy_from_slice(&self.service.0.to_le_bytes());
        output[16..20].copy_from_slice(&self.maximum_restarts.to_le_bytes());
        output[24..32].copy_from_slice(&self.base_backoff_ticks.to_le_bytes());
        output[32..40].copy_from_slice(&self.maximum_backoff_ticks.to_le_bytes());
    }

    pub fn decode(input: &[u8]) -> Result<Self, PersistedRestartPolicyError> {
        if input.len() != PERSISTED_RESTART_POLICY_BYTES
            || input[..4] != PERSISTED_RESTART_POLICY_MAGIC
            || u16::from_le_bytes(
                input[4..6]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            ) != SYSTEM_PROTOCOL_VERSION
            || usize::from(u16::from_le_bytes(
                input[6..8]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            )) != PERSISTED_RESTART_POLICY_BYTES
            || input[20..24].iter().any(|byte| *byte != 0)
            || input[40..].iter().any(|byte| *byte != 0)
        {
            return Err(PersistedRestartPolicyError::InvalidRecord);
        }
        Self::new(
            ObjectId(u64::from_le_bytes(
                input[8..16]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            )),
            u32::from_le_bytes(
                input[16..20]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            ),
            u64::from_le_bytes(
                input[24..32]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            ),
            u64::from_le_bytes(
                input[32..40]
                    .try_into()
                    .map_err(|_| PersistedRestartPolicyError::InvalidRecord)?,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistedRestartPolicyError {
    Configuration(ConfigError),
    InvalidRecord,
    WrongService,
    PolicyChanged,
    Service(ServiceError),
}

/// A policy loaded from one exact configuration setting revision and bound to
/// one service object. It carries no capability and cannot authorize restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundRestartPolicy {
    policy: PersistedRestartPolicy,
    configuration_revision: u64,
    setting_revision: u64,
    setting: SettingId,
}

/// Explicitly labeled inputs to dynamic policy application. These handles are
/// reauthorized by their respective configuration and supervisor domains;
/// merely constructing this value grants nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicyApplicationAuthority {
    setting_read: Capability,
    service_control: Capability,
}

impl RestartPolicyApplicationAuthority {
    pub const fn new(setting_read: Capability, service_control: Capability) -> Self {
        Self {
            setting_read,
            service_control,
        }
    }
}

impl BoundRestartPolicy {
    pub const fn service(self) -> ObjectId {
        self.policy.service
    }

    pub const fn configuration_revision(self) -> u64 {
        self.configuration_revision
    }

    pub const fn setting_revision(self) -> u64 {
        self.setting_revision
    }

    pub fn register<
        const SETTINGS: usize,
        const AUDIT: usize,
        const SERVICES: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        policy_capability: Capability,
        supervisor: &mut ServiceSupervisor<SERVICES>,
        task: TaskId,
    ) -> Result<ServiceId, PersistedRestartPolicyError> {
        let plan = self.plan_registration(
            configuration,
            capabilities,
            policy_capability,
            supervisor,
            task,
        )?;
        supervisor
            .commit_registration(plan)
            .map_err(PersistedRestartPolicyError::Service)
    }

    pub fn plan_registration<
        const SETTINGS: usize,
        const AUDIT: usize,
        const SERVICES: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        policy_capability: Capability,
        supervisor: &ServiceSupervisor<SERVICES>,
        task: TaskId,
    ) -> Result<ServiceRegistrationPlan, PersistedRestartPolicyError> {
        let current = load_persisted_restart_policy(
            configuration,
            capabilities,
            policy_capability,
            self.setting,
            self.policy.service,
        )?;
        if current != self {
            return Err(PersistedRestartPolicyError::PolicyChanged);
        }
        supervisor
            .plan_registration(self.policy.service, task, self.policy.restart_policy()?)
            .map_err(PersistedRestartPolicyError::Service)
    }

    /// Revalidates the exact setting capability and both revisions immediately
    /// before replacing an existing service's restart policy. The separate
    /// service CONTROL capability remains the authority for mutation.
    pub fn replace<
        const SETTINGS: usize,
        const AUDIT: usize,
        const SERVICES: usize,
        const MANAGEMENT_CAPS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        supervisor: &mut ServiceSupervisor<SERVICES>,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        authority: RestartPolicyApplicationAuthority,
    ) -> Result<(), PersistedRestartPolicyError> {
        let current = load_persisted_restart_policy(
            configuration,
            capabilities,
            authority.setting_read,
            self.setting,
            self.policy.service,
        )?;
        if current != self {
            return Err(PersistedRestartPolicyError::PolicyChanged);
        }
        supervisor
            .replace_restart_policy(
                service,
                management,
                authority.service_control,
                self.policy.restart_policy()?,
            )
            .map_err(PersistedRestartPolicyError::Service)
    }
}

/// Loads a persisted restart policy through the ordinary exact setting READ
/// gate and rejects service-object substitution before trusted registration.
pub fn load_persisted_restart_policy<
    const SETTINGS: usize,
    const AUDIT: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    policy_capability: Capability,
    setting: SettingId,
    expected_service: ObjectId,
) -> Result<BoundRestartPolicy, PersistedRestartPolicyError> {
    if expected_service.0 == 0 {
        return Err(PersistedRestartPolicyError::WrongService);
    }
    let record = configuration
        .read(capabilities, policy_capability, setting)
        .map_err(PersistedRestartPolicyError::Configuration)?;
    let value = record
        .value
        .ok_or(PersistedRestartPolicyError::InvalidRecord)?;
    let policy = PersistedRestartPolicy::decode(value.as_bytes())?;
    if policy.service != expected_service {
        return Err(PersistedRestartPolicyError::WrongService);
    }
    Ok(BoundRestartPolicy {
        policy,
        configuration_revision: configuration.revision(),
        setting_revision: record.revision,
        setting,
    })
}

/// A checkpoint staged into a fresh stable-file generation. The successor
/// remains inactive until an exact storage transaction receipt is consumed.
pub struct PreparedStableConfiguration<const EXTENTS: usize> {
    file: PreparedFileWrite<EXTENTS>,
    checkpoint: ConfigurationCheckpoint,
    revision: u64,
}

impl<const EXTENTS: usize> PreparedStableConfiguration<EXTENTS> {
    pub const fn checkpoint(&self) -> ConfigurationCheckpoint {
        self.checkpoint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn admit<const PARTICIPANTS: usize, const WRITES: usize>(
        &self,
        transaction: &mut StorageTransaction<PARTICIPANTS, WRITES>,
    ) -> Result<(), TransactionError> {
        transaction.admit_file(&self.file)
    }

    pub fn commit<const PARTICIPANTS: usize>(
        self,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableConfiguration<EXTENTS>, TransactionError> {
        let file = self.file.commit_transaction(receipt)?;
        Ok(StableConfiguration {
            file,
            checkpoint: self.checkpoint,
            revision: self.revision,
        })
    }
}

/// Exact stable object generation containing one authenticated checkpoint.
pub struct StableConfiguration<const EXTENTS: usize> {
    file: FileState<EXTENTS>,
    checkpoint: ConfigurationCheckpoint,
    revision: u64,
}

impl<const EXTENTS: usize> StableConfiguration<EXTENTS> {
    pub const fn file(&self) -> &FileState<EXTENTS> {
        &self.file
    }

    pub const fn checkpoint(&self) -> ConfigurationCheckpoint {
        self.checkpoint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationStorageError<E> {
    Configuration(ConfigError),
    InvalidBinding,
    Read(FileReadError<E>),
    Write(FileWriteError<E>),
}

/// Exports and stages a checkpoint as the complete content of the next
/// capability-authorized stable file generation. Publication and activation
/// remain separate and require `StorageTransaction` plus its one-use receipt.
#[allow(clippy::too_many_arguments)]
pub fn prepare_stable_configuration<
    const SETTINGS: usize,
    const AUDIT: usize,
    const CURRENT_EXTENTS: usize,
    const NEXT_EXTENTS: usize,
    const AUTHORITIES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileWriteBackend,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    root_capability: Capability,
    current_file: &FileState<CURRENT_EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    next_extents: ExtentMap<NEXT_EXTENTS>,
    next_metadata: FileMetadata,
    file_metadata_pointer: MetadataPointer,
    protected_metadata: &[MetadataPointer],
    output: &mut [u8],
    backend: &mut B,
) -> Result<PreparedStableConfiguration<NEXT_EXTENTS>, ConfigurationStorageError<B::Error>> {
    let checkpoint = configuration
        .export_checkpoint(capabilities, root_capability, output)
        .map_err(ConfigurationStorageError::Configuration)?;
    let bytes = &output[..checkpoint.length];
    let checkpoint_length =
        u64::try_from(checkpoint.length).map_err(|_| ConfigurationStorageError::InvalidBinding)?;
    let mut content = Sha3_256::new();
    content.update(bytes);
    if next_metadata.object() != current_file.object()
        || next_metadata.generation() != current_file.generation().checked_add(1).unwrap_or(0)
        || next_metadata.length() != checkpoint_length
        || next_metadata.content_digest() != content.finalize()
    {
        return Err(ConfigurationStorageError::InvalidBinding);
    }
    let prepared = current_file
        .prepare_write(
            storage_authority,
            file,
            principal,
            0,
            bytes,
            checkpoint_length,
            next_extents,
            next_metadata,
            file_metadata_pointer,
            protected_metadata,
            backend,
        )
        .map_err(ConfigurationStorageError::Write)?;
    Ok(PreparedStableConfiguration {
        file: prepared,
        checkpoint,
        revision: configuration.revision(),
    })
}

/// Composes checkpoint staging with the MRML exact-block volume through one
/// bounded file session. The volume's `StorageBlockDevice` may itself be the
/// capability-selected block-service adapter; device identity and checkpoint
/// bytes never select or manufacture that authority.
#[allow(clippy::too_many_arguments)]
pub fn prepare_block_stable_configuration<
    const SETTINGS: usize,
    const AUDIT: usize,
    const CURRENT_EXTENTS: usize,
    const NEXT_EXTENTS: usize,
    const AUTHORITIES: usize,
    A: CapabilityAuthorizer + ?Sized,
    D: StorageBlockDevice,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    root_capability: Capability,
    current_file: &FileState<CURRENT_EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    next_extents: ExtentMap<NEXT_EXTENTS>,
    next_metadata: FileMetadata,
    file_metadata_pointer: MetadataPointer,
    protected_metadata: &[MetadataPointer],
    output: &mut [u8],
    volume: &mut BlockVolume<'_, D>,
    file_scratch: &mut [u8],
) -> Result<
    PreparedStableConfiguration<NEXT_EXTENTS>,
    ConfigurationStorageError<BlockVolumeError<D::Error>>,
> {
    let mut session = BlockFileSession::<D, CURRENT_EXTENTS, NEXT_EXTENTS>::new(
        volume,
        current_file,
        file_scratch,
    )
    .map_err(|error| ConfigurationStorageError::Write(FileWriteError::Backend(error)))?;
    prepare_stable_configuration(
        configuration,
        capabilities,
        root_capability,
        current_file,
        storage_authority,
        file,
        principal,
        next_extents,
        next_metadata,
        file_metadata_pointer,
        protected_metadata,
        output,
        &mut session,
    )
}

/// Recovers only from one exact file generation already selected by
/// authenticated reachable-storage recovery. It never searches older
/// generations or turns an I/O failure into rollback.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_configuration<
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    const AUTHORITIES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
>(
    file_state: &FileState<EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    capabilities: &A,
    root_capability: Capability,
    input: &mut [u8],
    backend: &mut B,
) -> Result<ConfigurationService<SETTINGS, AUDIT>, ConfigurationStorageError<B::Error>> {
    input.fill(0);
    if expected_file_generation == 0 || file_state.generation() != expected_file_generation {
        return Err(ConfigurationStorageError::InvalidBinding);
    }
    let setting_bytes = SETTINGS
        .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let audit_bytes = AUDIT
        .checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let maximum = CONFIG_CHECKPOINT_HEADER_BYTES
        .checked_add(setting_bytes)
        .and_then(|length| length.checked_add(audit_bytes))
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    let length = usize::try_from(file_state.length())
        .ok()
        .filter(|length| {
            *length >= CONFIG_CHECKPOINT_HEADER_BYTES
                && *length <= input.len()
                && *length <= maximum
        })
        .ok_or(ConfigurationStorageError::InvalidBinding)?;
    file_state
        .read(
            storage_authority,
            file,
            principal,
            0,
            &mut input[..length],
            backend,
        )
        .map_err(ConfigurationStorageError::Read)?;
    let digest = input[CONFIG_CHECKPOINT_DIGEST_OFFSET
        ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
        .try_into()
        .map_err(|_| ConfigurationStorageError::InvalidBinding)?;
    ConfigurationService::recover_checkpoint(
        capabilities,
        root_capability,
        &input[..length],
        digest,
    )
    .map_err(ConfigurationStorageError::Configuration)
}

/// Configuration and service policy validated through temporary reconstructed
/// storage authority. Neither value is released by the storage recovery
/// transaction until authenticated monotonic state has advanced.
pub struct RecoveredStableConfiguration<const SETTINGS: usize, const AUDIT: usize> {
    configuration: ConfigurationService<SETTINGS, AUDIT>,
    policy: BoundRestartPolicy,
}

impl<const SETTINGS: usize, const AUDIT: usize> RecoveredStableConfiguration<SETTINGS, AUDIT> {
    pub const fn configuration(&self) -> &ConfigurationService<SETTINGS, AUDIT> {
        &self.configuration
    }

    pub const fn policy(&self) -> BoundRestartPolicy {
        self.policy
    }

    pub fn into_parts(self) -> (ConfigurationService<SETTINGS, AUDIT>, BoundRestartPolicy) {
        (self.configuration, self.policy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableConfigurationRecoveryError<E> {
    Storage(ConfigurationStorageError<E>),
    MissingFileAuthority,
    RootSelectionMismatch,
    Policy(PersistedRestartPolicyError),
}

/// Side-effect-free dependent validator for the storage authority recovery
/// transaction. It uses one exact reconstructed file handle to recover the
/// selected configuration generation and bind its restart policy, retaining
/// both only as an unpublished return value.
pub struct StableConfigurationRecoveryValidator<
    'a,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> {
    file_state: &'a FileState<EXTENTS>,
    file_handle_index: usize,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    selected_volume: Option<VolumeId>,
    selected_root_generation: u64,
    capabilities: &'a A,
    root_capability: Capability,
    policy_capability: Capability,
    policy_setting: SettingId,
    expected_service: ObjectId,
    input: &'a mut [u8],
    backend: &'a mut B,
}

impl<
    'a,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> StableConfigurationRecoveryValidator<'a, SETTINGS, AUDIT, EXTENTS, A, B>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_state: &'a FileState<EXTENTS>,
        file_handle_index: usize,
        principal: StoragePrincipal,
        expected_file_generation: u64,
        capabilities: &'a A,
        root_capability: Capability,
        policy_capability: Capability,
        policy_setting: SettingId,
        expected_service: ObjectId,
        input: &'a mut [u8],
        backend: &'a mut B,
    ) -> Self {
        Self {
            file_state,
            file_handle_index,
            principal,
            expected_file_generation,
            selected_volume: None,
            selected_root_generation: 0,
            capabilities,
            root_capability,
            policy_capability,
            policy_setting,
            expected_service,
            input,
            backend,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_selected(
        selection: ReachableFileSelection<'a, EXTENTS>,
        file_handle_index: usize,
        principal: StoragePrincipal,
        capabilities: &'a A,
        root_capability: Capability,
        policy_capability: Capability,
        policy_setting: SettingId,
        expected_service: ObjectId,
        input: &'a mut [u8],
        backend: &'a mut B,
    ) -> Self {
        Self {
            file_state: selection.file_state(),
            file_handle_index,
            principal,
            expected_file_generation: selection.generation(),
            selected_volume: Some(selection.volume()),
            selected_root_generation: selection.root_generation(),
            capabilities,
            root_capability,
            policy_capability,
            policy_setting,
            expected_service,
            input,
            backend,
        }
    }
}

// SAFETY: validation performs only exact-file reads through the temporary
// table and builds unpublished in-memory configuration/policy values. It
// retains no storage handle or table reference and performs no mutation.
unsafe impl<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> AuthorityRecoveryValidator<GRANTS>
    for StableConfigurationRecoveryValidator<'_, SETTINGS, AUDIT, EXTENTS, A, B>
{
    type Output = RecoveredStableConfiguration<SETTINGS, AUDIT>;
    type Error = StableConfigurationRecoveryError<B::Error>;

    fn validate(
        &mut self,
        recovered: &RecoveredStorageAuthorities<GRANTS>,
    ) -> Result<Self::Output, Self::Error> {
        if !recovery_root_matches(
            self.selected_volume,
            self.selected_root_generation,
            recovered.volume(),
            recovered.root_generation(),
        ) {
            return Err(StableConfigurationRecoveryError::RootSelectionMismatch);
        }
        let file = recovered
            .handle(self.file_handle_index)
            .ok_or(StableConfigurationRecoveryError::MissingFileAuthority)?;
        let configuration = match recover_stable_configuration(
            self.file_state,
            recovered.authority_table(),
            file,
            self.principal,
            self.expected_file_generation,
            self.capabilities,
            self.root_capability,
            self.input,
            self.backend,
        ) {
            Ok(configuration) => configuration,
            Err(error) => {
                self.input.fill(0);
                return Err(StableConfigurationRecoveryError::Storage(error));
            }
        };
        let policy = load_persisted_restart_policy(
            &configuration,
            self.capabilities,
            self.policy_capability,
            self.policy_setting,
            self.expected_service,
        );
        self.input.fill(0);
        let policy = policy.map_err(StableConfigurationRecoveryError::Policy)?;
        Ok(RecoveredStableConfiguration {
            configuration,
            policy,
        })
    }
}

fn recovery_root_matches(
    selected_volume: Option<VolumeId>,
    selected_generation: u64,
    recovered_volume: VolumeId,
    recovered_generation: u64,
) -> bool {
    selected_volume.is_none_or(|volume| {
        volume == recovered_volume && selected_generation == recovered_generation
    })
}

/// Recovered configuration plus a non-mutating, exact-slot service
/// registration decision. Only the committed-authority wrapper can consume it
/// into a released system state.
pub struct PreparedRecoveredService<const SETTINGS: usize, const AUDIT: usize> {
    recovered: RecoveredStableConfiguration<SETTINGS, AUDIT>,
    registration: ServiceRegistrationPlan,
    authority_epoch: u64,
}

pub struct RecoveredSystemState<const GRANTS: usize, const SETTINGS: usize, const AUDIT: usize> {
    authorities: CommittedRecoveredStorageAuthorities<GRANTS>,
    configuration: ConfigurationService<SETTINGS, AUDIT>,
    service: ServiceId,
}

impl<const GRANTS: usize, const SETTINGS: usize, const AUDIT: usize>
    RecoveredSystemState<GRANTS, SETTINGS, AUDIT>
{
    pub const fn authorities(&self) -> &CommittedRecoveredStorageAuthorities<GRANTS> {
        &self.authorities
    }

    pub const fn configuration(&self) -> &ConfigurationService<SETTINGS, AUDIT> {
        &self.configuration
    }

    pub const fn service(&self) -> ServiceId {
        self.service
    }

    /// Revalidates isolation settings only after authenticated storage authority,
    /// monotonic recovery state, and service publication have committed, then
    /// composes the actual decoded trusted-loader overlay. The handoff remains
    /// authority-free: this result grants no capability and proves no placement.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_boot_isolation_policy<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        handoff: &BootHandoff,
    ) -> Result<RecoveredBootIsolationPolicy, ConfigError> {
        let recovery = handoff
            .recovery_state()
            .ok_or(ConfigError::RecoveryHandoffMismatch)?;
        if recovery.accepted_epoch().checked_add(1) != Some(self.authorities.epoch()) {
            return Err(ConfigError::RecoveryHandoffMismatch);
        }
        let plan = IsolationPolicyApplicationPlan::load(
            &self.configuration,
            capabilities,
            system,
            system_read,
            component,
            component_read,
        )?;
        let effective = plan
            .apply(&self.configuration, capabilities)?
            .compose_boot_override(handoff.isolation_override());
        Ok(RecoveredBootIsolationPolicy {
            effective,
            authority_epoch: self.authorities.epoch(),
            configuration_revision: self.configuration.revision(),
            configuration_service: self.service,
            boot_accepted_epoch: recovery.accepted_epoch(),
        })
    }

    /// Atomically joins committed recovery, the exact decoded boot handoff,
    /// capability-revalidated persistent policy, and one authenticated active
    /// release. Callers never receive a detached effective policy from this
    /// path; all subsequent preparation and finalization use the single
    /// release-owned admission table retained by the returned owner.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_total_boot_admission<const DOMAINS: usize, A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        handoff: &BootHandoff,
        release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
    ) -> Result<RecoveredTotalAdmission<DOMAINS>, ConfigError> {
        self.compose_boot_isolation_policy(
            capabilities,
            system,
            system_read,
            component,
            component_read,
            handoff,
        )?
        .bind_release_inventory(release)
    }

    /// Keeps the recovered effective policy private while allowing the caller
    /// to construct the exact authenticated release inventory with its policy
    /// generation. A failed builder publishes neither an admission table nor a
    /// detached policy value.
    #[allow(clippy::too_many_arguments)]
    pub fn build_total_boot_admission<
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
        F,
        E,
    >(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        handoff: &BootHandoff,
        build_release: F,
    ) -> Result<RecoveredTotalAdmission<DOMAINS>, RecoveredTotalAdmissionBuildError<E>>
    where
        F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
    {
        let policy = self
            .compose_boot_isolation_policy(
                capabilities,
                system,
                system_read,
                component,
                component_read,
                handoff,
            )
            .map_err(RecoveredTotalAdmissionBuildError::Policy)?;
        let release = build_release(policy.effective().policy_generation())
            .map_err(RecoveredTotalAdmissionBuildError::ReleaseBuilder)?;
        policy
            .bind_release_inventory(release)
            .map_err(RecoveredTotalAdmissionBuildError::Policy)
    }

    pub fn into_parts(
        self,
    ) -> (
        CommittedRecoveredStorageAuthorities<GRANTS>,
        ConfigurationService<SETTINGS, AUDIT>,
        ServiceId,
    ) {
        (self.authorities, self.configuration, self.service)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredTotalAdmissionBuildError<E> {
    Policy(ConfigError),
    ReleaseBuilder(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredSystemCommitError {
    AuthorityEpochMismatch,
    Service(ServiceError),
}

impl<const SETTINGS: usize, const AUDIT: usize> PreparedRecoveredService<SETTINGS, AUDIT> {
    pub fn commit<const GRANTS: usize, const SERVICES: usize>(
        self,
        authorities: CommittedRecoveredStorageAuthorities<GRANTS>,
        supervisor: &mut ServiceSupervisor<SERVICES>,
    ) -> Result<RecoveredSystemState<GRANTS, SETTINGS, AUDIT>, RecoveredSystemCommitError> {
        if authorities.epoch() != self.authority_epoch {
            return Err(RecoveredSystemCommitError::AuthorityEpochMismatch);
        }
        let service = supervisor
            .commit_registration(self.registration)
            .map_err(RecoveredSystemCommitError::Service)?;
        let (configuration, _) = self.recovered.into_parts();
        Ok(RecoveredSystemState {
            authorities,
            configuration,
            service,
        })
    }
}

pub struct StableServiceRecoveryValidator<
    'a,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    const SERVICES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> {
    configuration: StableConfigurationRecoveryValidator<'a, SETTINGS, AUDIT, EXTENTS, A, B>,
    supervisor: &'a ServiceSupervisor<SERVICES>,
    task: TaskId,
}

impl<
    'a,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    const SERVICES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> StableServiceRecoveryValidator<'a, SETTINGS, AUDIT, EXTENTS, SERVICES, A, B>
{
    pub const fn new(
        configuration: StableConfigurationRecoveryValidator<'a, SETTINGS, AUDIT, EXTENTS, A, B>,
        supervisor: &'a ServiceSupervisor<SERVICES>,
        task: TaskId,
    ) -> Self {
        Self {
            configuration,
            supervisor,
            task,
        }
    }
}

// SAFETY: the nested validator retains no storage authority. Registration is
// only planned against immutable supervisor state; no lifecycle mutation occurs
// until a committed-authority wrapper later consumes the output.
unsafe impl<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const EXTENTS: usize,
    const SERVICES: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: FileReadBackend,
> AuthorityRecoveryValidator<GRANTS>
    for StableServiceRecoveryValidator<'_, SETTINGS, AUDIT, EXTENTS, SERVICES, A, B>
{
    type Output = PreparedRecoveredService<SETTINGS, AUDIT>;
    type Error = StableConfigurationRecoveryError<B::Error>;

    fn validate(
        &mut self,
        authorities: &RecoveredStorageAuthorities<GRANTS>,
    ) -> Result<Self::Output, Self::Error> {
        let recovered = self.configuration.validate(authorities)?;
        let registration = recovered
            .policy
            .plan_registration(
                &recovered.configuration,
                self.configuration.capabilities,
                self.configuration.policy_capability,
                self.supervisor,
                self.task,
            )
            .map_err(StableConfigurationRecoveryError::Policy)?;
        Ok(PreparedRecoveredService {
            recovered,
            registration,
            authority_epoch: authorities.epoch(),
        })
    }
}

#[derive(Clone, Copy)]
struct SettingEntry {
    schema: SettingSchema,
    value: Option<ConfigValue>,
    revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigRecord {
    pub setting: SettingId,
    pub revision: u64,
    pub value: Option<ConfigValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigUpdate {
    setting: SettingId,
    capability: Capability,
    value: ConfigValue,
}

impl ConfigUpdate {
    pub const fn new(setting: SettingId, capability: Capability, value: ConfigValue) -> Self {
        Self {
            setting,
            capability,
            value,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigTransaction<const UPDATES: usize> {
    expected_revision: u64,
    updates: [Option<ConfigUpdate>; UPDATES],
    count: usize,
}

pub const ISOLATION_POLICY_VALUE_BYTES: usize = 16;
const ISOLATION_POLICY_VALUE_MAGIC: [u8; 8] = *b"MRMLISO1";
pub const ISOLATION_POLICY_EDIT_BYTES: usize = 32;
const ISOLATION_POLICY_EDIT_MAGIC: [u8; 8] = *b"MRMLIFE1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationPolicyScope {
    Component,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerIsolationSelection {
    Default,
    Native,
    Microvm,
    Balanced,
    MoreIsolated,
    TotalMicrovm,
    Custom,
}

impl OwnerIsolationSelection {
    const fn token(self) -> u8 {
        match self {
            Self::Default => 1,
            Self::Native => 2,
            Self::Microvm => 3,
            Self::Balanced => 4,
            Self::TotalMicrovm => 5,
            Self::MoreIsolated => 6,
            Self::Custom => 7,
        }
    }

    const fn scope(self) -> IsolationPolicyScope {
        match self {
            Self::Default | Self::Native | Self::Microvm => IsolationPolicyScope::Component,
            Self::Balanced | Self::MoreIsolated | Self::TotalMicrovm | Self::Custom => {
                IsolationPolicyScope::System
            }
        }
    }

    const fn decode(value: u8) -> Result<Self, ConfigError> {
        match value {
            1 => Ok(Self::Default),
            2 => Ok(Self::Native),
            3 => Ok(Self::Microvm),
            4 => Ok(Self::Balanced),
            5 => Ok(Self::TotalMicrovm),
            6 => Ok(Self::MoreIsolated),
            7 => Ok(Self::Custom),
            _ => Err(ConfigError::InvalidValue),
        }
    }
}

/// Typed control-plane descriptor for one capability-authorized persistent
/// placement setting. The object identifies the policy target; possession of
/// this descriptor or its serialized value grants no read or write authority.
/// Runtime code consumes a separately admitted generation-bound endpoint, not
/// this record, so steady-state data does not round-trip through policy storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationPolicySetting {
    setting: SettingId,
    object: ObjectId,
    scope: IsolationPolicyScope,
    native_placement: Option<IsolationPlacement>,
}

impl IsolationPolicySetting {
    pub const fn component(
        setting: SettingId,
        object: ObjectId,
        native_placement: IsolationPlacement,
    ) -> Result<Self, ConfigError> {
        if !matches!(
            native_placement,
            IsolationPlacement::InProcess
                | IsolationPlacement::NativeProcess
                | IsolationPlacement::NativeService
        ) {
            return Err(ConfigError::InvalidSchema);
        }
        Self::new(
            setting,
            object,
            IsolationPolicyScope::Component,
            Some(native_placement),
        )
    }

    pub const fn system(setting: SettingId, object: ObjectId) -> Result<Self, ConfigError> {
        Self::new(setting, object, IsolationPolicyScope::System, None)
    }

    const fn new(
        setting: SettingId,
        object: ObjectId,
        scope: IsolationPolicyScope,
        native_placement: Option<IsolationPlacement>,
    ) -> Result<Self, ConfigError> {
        if object.0 == 0 {
            return Err(ConfigError::InvalidSchema);
        }
        Ok(Self {
            setting,
            object,
            scope,
            native_placement,
        })
    }

    pub const fn setting(self) -> SettingId {
        self.setting
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn scope(self) -> IsolationPolicyScope {
        self.scope
    }

    pub const fn native_placement(self) -> Option<IsolationPlacement> {
        self.native_placement
    }

    const fn native_token(self) -> u8 {
        match self.native_placement {
            None => 0,
            Some(IsolationPlacement::InProcess) => 1,
            Some(IsolationPlacement::NativeProcess) => 2,
            Some(IsolationPlacement::NativeService) => 3,
            _ => 0,
        }
    }

    const fn component_from_token(
        setting: SettingId,
        object: ObjectId,
        token: u8,
    ) -> Result<Self, ConfigError> {
        let placement = match token {
            1 => IsolationPlacement::InProcess,
            2 => IsolationPlacement::NativeProcess,
            3 => IsolationPlacement::NativeService,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        Self::component(setting, object, placement)
    }

    pub const fn schema(self) -> Result<SettingSchema, ConfigError> {
        SettingSchema::bytes(
            self.setting,
            self.object,
            ISOLATION_POLICY_VALUE_BYTES as u8,
        )
    }

    pub fn stage<const UPDATES: usize>(
        self,
        transaction: &mut ConfigTransaction<UPDATES>,
        write_capability: Capability,
        selection: OwnerIsolationSelection,
    ) -> Result<(), ConfigError> {
        if selection.scope() != self.scope {
            return Err(ConfigError::SchemaViolation);
        }
        let mut encoded = [0u8; ISOLATION_POLICY_VALUE_BYTES];
        encoded[..8].copy_from_slice(&ISOLATION_POLICY_VALUE_MAGIC);
        encoded[8] = match self.scope {
            IsolationPolicyScope::Component => 1,
            IsolationPolicyScope::System => 2,
        };
        encoded[9] = selection.token();
        encoded[10] = self.native_token();
        transaction.push(ConfigUpdate::new(
            self.setting,
            write_capability,
            ConfigValue::bytes(&encoded)?,
        ))
    }

    pub fn read<const SETTINGS: usize, const AUDIT: usize, A: CapabilityAuthorizer + ?Sized>(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        read_capability: Capability,
    ) -> Result<PersistedIsolationPolicy, ConfigError> {
        let record = configuration.read(capabilities, read_capability, self.setting)?;
        let value = record.value.ok_or(ConfigError::MissingSetting)?;
        let encoded = value.as_bytes();
        if value.kind() != ValueKind::Bytes
            || encoded.len() != ISOLATION_POLICY_VALUE_BYTES
            || encoded[..8] != ISOLATION_POLICY_VALUE_MAGIC
            || encoded[11..].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        let scope = match encoded[8] {
            1 => IsolationPolicyScope::Component,
            2 => IsolationPolicyScope::System,
            _ => return Err(ConfigError::InvalidValue),
        };
        let selection = OwnerIsolationSelection::decode(encoded[9])?;
        if scope != self.scope
            || selection.scope() != scope
            || encoded[10] != self.native_token()
            || record.revision == 0
        {
            return Err(ConfigError::SchemaViolation);
        }
        Ok(PersistedIsolationPolicy {
            setting: self,
            selection,
            revision: record.revision,
        })
    }
}

/// Canonical authority-free edit shared by Settings, the object shell, recovery,
/// accessibility projections, and tests. It identifies the exact typed policy
/// record and expected configuration revision, but commit still requires live
/// root CONTROL and setting WRITE capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationPolicyEdit {
    setting: IsolationPolicySetting,
    selection: OwnerIsolationSelection,
    expected_revision: u64,
}

impl IsolationPolicyEdit {
    pub fn new(
        setting: IsolationPolicySetting,
        selection: OwnerIsolationSelection,
        expected_revision: u64,
    ) -> Result<Self, ConfigError> {
        if selection.scope() != setting.scope() {
            return Err(ConfigError::SchemaViolation);
        }
        Ok(Self {
            setting,
            selection,
            expected_revision,
        })
    }

    pub const fn setting(self) -> IsolationPolicySetting {
        self.setting
    }

    pub const fn selection(self) -> OwnerIsolationSelection {
        self.selection
    }

    pub const fn expected_revision(self) -> u64 {
        self.expected_revision
    }

    pub fn encode(self) -> [u8; ISOLATION_POLICY_EDIT_BYTES] {
        let mut output = [0; ISOLATION_POLICY_EDIT_BYTES];
        output[..8].copy_from_slice(&ISOLATION_POLICY_EDIT_MAGIC);
        output[8..12].copy_from_slice(&self.setting.setting().get().to_le_bytes());
        output[12] = match self.setting.scope() {
            IsolationPolicyScope::Component => 1,
            IsolationPolicyScope::System => 2,
        };
        output[13] = self.selection.token();
        output[14] = self.setting.native_token();
        output[16..24].copy_from_slice(&self.setting.object().0.to_le_bytes());
        output[24..32].copy_from_slice(&self.expected_revision.to_le_bytes());
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != ISOLATION_POLICY_EDIT_BYTES
            || input[..8] != ISOLATION_POLICY_EDIT_MAGIC
            || input[15] != 0
        {
            return Err(ConfigError::InvalidProtocol);
        }
        let setting = SettingId::new(u32::from_le_bytes(
            input[8..12]
                .try_into()
                .map_err(|_| ConfigError::InvalidProtocol)?,
        ))?;
        let object = ObjectId(u64::from_le_bytes(
            input[16..24]
                .try_into()
                .map_err(|_| ConfigError::InvalidProtocol)?,
        ));
        let descriptor = match input[12] {
            1 => IsolationPolicySetting::component_from_token(setting, object, input[14])?,
            2 if input[14] == 0 => IsolationPolicySetting::system(setting, object)?,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        Self::new(
            descriptor,
            OwnerIsolationSelection::decode(input[13])?,
            u64::from_le_bytes(
                input[24..32]
                    .try_into()
                    .map_err(|_| ConfigError::InvalidProtocol)?,
            ),
        )
    }

    pub fn commit<const SETTINGS: usize, const AUDIT: usize, A: CapabilityAuthorizer + ?Sized>(
        self,
        configuration: &mut ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        root_control: Capability,
        setting_write: Capability,
    ) -> Result<CommittedIsolationPolicyEdit, ConfigError> {
        let mut transaction = ConfigTransaction::<1>::new(self.expected_revision);
        self.setting
            .stage(&mut transaction, setting_write, self.selection)?;
        let policy_generation = configuration.commit(capabilities, root_control, &transaction)?;
        Ok(CommittedIsolationPolicyEdit {
            setting: self.setting,
            selection: self.selection,
            policy_generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedIsolationPolicyEdit {
    setting: IsolationPolicySetting,
    selection: OwnerIsolationSelection,
    policy_generation: u64,
}

impl CommittedIsolationPolicyEdit {
    pub const fn setting(self) -> IsolationPolicySetting {
        self.setting
    }

    pub const fn selection(self) -> OwnerIsolationSelection {
        self.selection
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

/// Semantic Settings action. Widget identity is deliberately absent: mapping a
/// control to this action grants no authority and commits through the same edit
/// path as every other frontend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationSettingsAction {
    selection: OwnerIsolationSelection,
    expected_revision: u64,
}

impl IsolationSettingsAction {
    pub const fn new(selection: OwnerIsolationSelection, expected_revision: u64) -> Self {
        Self {
            selection,
            expected_revision,
        }
    }

    pub fn edit(self, setting: IsolationPolicySetting) -> Result<IsolationPolicyEdit, ConfigError> {
        IsolationPolicyEdit::new(setting, self.selection, self.expected_revision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationShellCommand {
    Show,
    Set(IsolationPolicyEdit),
}

impl IsolationShellCommand {
    /// Parses the bounded object-shell form without accepting object IDs,
    /// capabilities, provider names, paths, or fallback instructions from text.
    ///
    /// `isolation show`
    /// `isolation set <selection> <expected-revision>`
    pub fn parse(input: &str, setting: IsolationPolicySetting) -> Result<Self, ConfigError> {
        let mut parts = input.split_whitespace();
        if parts.next() != Some("isolation") {
            return Err(ConfigError::InvalidProtocol);
        }
        match parts.next() {
            Some("show") if parts.next().is_none() => Ok(Self::Show),
            Some("set") => {
                let selection = match parts.next() {
                    Some("default") => OwnerIsolationSelection::Default,
                    Some("native") => OwnerIsolationSelection::Native,
                    Some("microvm") => OwnerIsolationSelection::Microvm,
                    Some("balanced") => OwnerIsolationSelection::Balanced,
                    Some("more-isolated") => OwnerIsolationSelection::MoreIsolated,
                    Some("total-microvm") => OwnerIsolationSelection::TotalMicrovm,
                    Some("custom") => OwnerIsolationSelection::Custom,
                    _ => return Err(ConfigError::InvalidValue),
                };
                let revision = parts
                    .next()
                    .ok_or(ConfigError::InvalidProtocol)?
                    .parse::<u64>()
                    .map_err(|_| ConfigError::InvalidValue)?;
                if parts.next().is_some() {
                    return Err(ConfigError::NonCanonical);
                }
                IsolationPolicyEdit::new(setting, selection, revision).map(Self::Set)
            }
            _ => Err(ConfigError::InvalidProtocol),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedIsolationPolicy {
    setting: IsolationPolicySetting,
    selection: OwnerIsolationSelection,
    revision: u64,
}

impl PersistedIsolationPolicy {
    pub const fn setting(self) -> IsolationPolicySetting {
        self.setting
    }

    pub const fn selection(self) -> OwnerIsolationSelection {
        self.selection
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub fn system_mode(self) -> Result<IsolationMode, ConfigError> {
        if self.setting.scope != IsolationPolicyScope::System {
            return Err(ConfigError::SchemaViolation);
        }
        match self.selection {
            OwnerIsolationSelection::Balanced => Ok(IsolationMode::Balanced),
            OwnerIsolationSelection::MoreIsolated => Ok(IsolationMode::MoreIsolated),
            OwnerIsolationSelection::TotalMicrovm => Ok(IsolationMode::TotalMicrovm),
            OwnerIsolationSelection::Custom => Ok(IsolationMode::Custom),
            _ => Err(ConfigError::SchemaViolation),
        }
    }

    pub fn component_request(self) -> Result<Option<IsolationPlacement>, ConfigError> {
        if self.setting.scope != IsolationPolicyScope::Component {
            return Err(ConfigError::SchemaViolation);
        }
        match self.selection {
            OwnerIsolationSelection::Default => Ok(None),
            OwnerIsolationSelection::Native => Ok(self.setting.native_placement),
            OwnerIsolationSelection::Microvm => Ok(Some(IsolationPlacement::Microvm)),
            _ => Err(ConfigError::SchemaViolation),
        }
    }
}

/// A capability-checked, revision-bound control-plane plan. Applying it repeats
/// both reads and rejects configuration drift or capability revocation before
/// producing input for package-policy resolution and kernel launch admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationPolicyApplicationPlan {
    system: PersistedIsolationPolicy,
    component: PersistedIsolationPolicy,
    system_read: Capability,
    component_read: Capability,
    configuration_revision: u64,
}

impl IsolationPolicyApplicationPlan {
    pub fn load<const SETTINGS: usize, const AUDIT: usize, A: CapabilityAuthorizer + ?Sized>(
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
    ) -> Result<Self, ConfigError> {
        if system.scope() != IsolationPolicyScope::System
            || component.scope() != IsolationPolicyScope::Component
            || configuration.revision() == 0
        {
            return Err(ConfigError::SchemaViolation);
        }
        Ok(Self {
            system: system.read(configuration, capabilities, system_read)?,
            component: component.read(configuration, capabilities, component_read)?,
            system_read,
            component_read,
            configuration_revision: configuration.revision(),
        })
    }

    pub fn apply<const SETTINGS: usize, const AUDIT: usize, A: CapabilityAuthorizer + ?Sized>(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
    ) -> Result<AppliedIsolationPolicy, ConfigError> {
        if configuration.revision() != self.configuration_revision
            || self
                .system
                .setting
                .read(configuration, capabilities, self.system_read)?
                != self.system
            || self
                .component
                .setting
                .read(configuration, capabilities, self.component_read)?
                != self.component
        {
            return Err(ConfigError::RevisionConflict {
                current: configuration.revision(),
            });
        }
        Ok(AppliedIsolationPolicy {
            mode: self.system.system_mode()?,
            component_request: self.component.component_request()?,
            system_selection: self.system.selection(),
            component_selection: self.component.selection(),
            policy_generation: self.configuration_revision,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedIsolationPolicy {
    mode: IsolationMode,
    component_request: Option<IsolationPlacement>,
    system_selection: OwnerIsolationSelection,
    component_selection: OwnerIsolationSelection,
    policy_generation: u64,
}

impl AppliedIsolationPolicy {
    pub const fn mode(self) -> IsolationMode {
        self.mode
    }

    pub const fn component_request(self) -> Option<IsolationPlacement> {
        self.component_request
    }

    pub const fn system_selection(self) -> OwnerIsolationSelection {
        self.system_selection
    }

    pub const fn component_selection(self) -> OwnerIsolationSelection {
        self.component_selection
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    /// Composes authority-free trusted-loader input over one exact persistent
    /// policy generation. The overlay can strengthen this boot to strict Total
    /// mode but cannot mutate the stored owner selection, invent a new policy
    /// generation, weaken a mandatory floor, or authorize fallback.
    pub const fn compose_boot_override(
        self,
        boot_override: Option<BootIsolationOverride>,
    ) -> EffectiveBootIsolationPolicy {
        let mode = match boot_override {
            Some(BootIsolationOverride::TotalMicrovmOnce) => IsolationMode::TotalMicrovm,
            None => self.mode,
        };
        EffectiveBootIsolationPolicy {
            persistent: self,
            mode,
            boot_override,
        }
    }

    pub fn admission_table<const DOMAINS: usize>(
        self,
        system_generation: u64,
    ) -> Result<IsolationAdmissionTable<DOMAINS>, ConfigError> {
        IsolationAdmissionTable::new(self.mode, system_generation, self.policy_generation)
            .map_err(|_| ConfigError::InvalidValue)
    }

    pub fn admit_service(
        self,
        bounds: IsolationServiceBounds,
    ) -> Result<AdmittedIsolationServicePolicy, ConfigError> {
        self.admit_service_for_mode(self.mode, bounds)
    }

    fn admit_service_for_mode(
        self,
        mode: IsolationMode,
        bounds: IsolationServiceBounds,
    ) -> Result<AdmittedIsolationServicePolicy, ConfigError> {
        let (placement, source) = if mode == IsolationMode::TotalMicrovm {
            (
                IsolationPlacement::Microvm,
                IsolationPolicySource::TotalMicrovm,
            )
        } else if let Some(requested) = self.component_request {
            (requested, IsolationPolicySource::Owner)
        } else {
            (bounds.preferred, IsolationPolicySource::PackageDefault)
        };
        if !bounds.supports(placement)
            || service_placement_rank(placement) < service_placement_rank(bounds.minimum)
            || service_placement_rank(placement) > service_placement_rank(bounds.maximum)
        {
            return Err(ConfigError::SchemaViolation);
        }
        Ok(AdmittedIsolationServicePolicy {
            placement,
            source,
            policy_generation: self.policy_generation,
        })
    }

    /// Produces one read-only semantic truth for Settings, shell,
    /// accessibility, automation, and authorized AI after the caller has
    /// separately acquired the persisted policy and kernel monitor snapshot.
    pub fn semantic_view(
        self,
        bounds: IsolationServiceBounds,
        status: IsolationStatusSnapshot,
    ) -> Result<IsolationPolicySemanticView, ConfigError> {
        self.semantic_view_for_mode(self.mode, bounds, status)
    }

    fn semantic_view_for_mode(
        self,
        mode: IsolationMode,
        bounds: IsolationServiceBounds,
        status: IsolationStatusSnapshot,
    ) -> Result<IsolationPolicySemanticView, ConfigError> {
        if status.policy_generation != self.policy_generation || status.requested_mode != mode {
            return Err(ConfigError::IsolationPolicyMismatch);
        }
        let admitted = self.admit_service_for_mode(mode, bounds).ok();
        Ok(IsolationPolicySemanticView {
            configured_system: self.system_selection,
            configured_component: self.component_selection,
            preferred: bounds.preferred,
            minimum: bounds.minimum,
            maximum: bounds.maximum,
            native_supported: bounds.native_supported,
            microvm_supported: bounds.microvm_supported,
            effective_placement: admitted.map(AdmittedIsolationServicePolicy::placement),
            policy_source: admitted.map(AdmittedIsolationServicePolicy::source),
            component_blocked: admitted.is_none(),
            status,
        })
    }
}

/// One boot's effective isolation control-plane input. The persistent policy
/// remains separately inspectable and unchanged; the loader overlay is retained
/// explicitly so monitoring and recovery never infer it from the resulting
/// mode. This value grants no capability and proves no runtime placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveBootIsolationPolicy {
    persistent: AppliedIsolationPolicy,
    mode: IsolationMode,
    boot_override: Option<BootIsolationOverride>,
}

/// Effective boot policy whose persistent inputs were revalidated from a fully
/// committed recovered system state. Recovery identity is retained for
/// monitoring and admission provenance; none of these identifiers authorize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredBootIsolationPolicy {
    effective: EffectiveBootIsolationPolicy,
    authority_epoch: u64,
    configuration_revision: u64,
    configuration_service: ServiceId,
    boot_accepted_epoch: u64,
}

impl RecoveredBootIsolationPolicy {
    pub const fn effective(self) -> EffectiveBootIsolationPolicy {
        self.effective
    }

    pub const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub const fn configuration_revision(self) -> u64 {
        self.configuration_revision
    }

    pub const fn configuration_service(self) -> ServiceId {
        self.configuration_service
    }

    pub const fn boot_accepted_epoch(self) -> u64 {
        self.boot_accepted_epoch
    }

    pub fn admission_table<const DOMAINS: usize>(
        self,
        system_generation: u64,
    ) -> Result<IsolationAdmissionTable<DOMAINS>, ConfigError> {
        self.effective.admission_table(system_generation)
    }

    /// Binds this recovered effective policy to the complete package
    /// classifications authenticated from one exact SystemRelease. Neither an
    /// ad hoc inventory nor a matching generation number can enter this path.
    pub fn bind_release_inventory<const DOMAINS: usize>(
        self,
        release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
    ) -> Result<RecoveredTotalAdmission<DOMAINS>, ConfigError> {
        let total = self.effective.bind_release_inventory(release)?;
        Ok(RecoveredTotalAdmission {
            policy: self,
            total,
        })
    }
}

/// One pre-launch control-plane state joining an exact effective boot policy,
/// authenticated complete release classification, and the only admission table
/// allowed to account the resulting domains. Recovery wraps this same owner
/// with committed recovery provenance rather than constructing another table.
pub struct BootTotalAdmission<const DOMAINS: usize> {
    policy: EffectiveBootIsolationPolicy,
    release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
    admission: IsolationAdmissionTable<DOMAINS>,
}

impl<const DOMAINS: usize> BootTotalAdmission<DOMAINS> {
    pub const fn policy(&self) -> EffectiveBootIsolationPolicy {
        self.policy
    }

    pub const fn release(&self) -> &ActivatedReleaseTotalMicrovmInventory<DOMAINS> {
        &self.release
    }

    pub const fn admission(&self) -> &IsolationAdmissionTable<DOMAINS> {
        &self.admission
    }

    pub fn admission_mut(&mut self) -> &mut IsolationAdmissionTable<DOMAINS> {
        &mut self.admission
    }

    /// Applies the effective boot policy and reserves one exact service
    /// route only when its domain/class is already present in the authenticated
    /// release inventory owned by this transaction. Package metadata and
    /// identity remain non-authorizing; the returned route is still
    /// uncommitted and backend construction must use this same admission table.
    pub fn prepare_service(
        &mut self,
        bounds: IsolationServiceBounds,
        identity: IsolationServiceIdentity,
    ) -> Result<PreparedIsolationServiceRoute, ConfiguredIsolationPreparationError> {
        if !self
            .release
            .release()
            .entries()
            .any(|entry| entry.domain() == identity.domain && entry.class() == identity.class)
        {
            return Err(ConfiguredIsolationPreparationError::Configuration(
                ConfigError::SchemaViolation,
            ));
        }
        let admitted = self
            .policy
            .admit_service(bounds)
            .map_err(ConfiguredIsolationPreparationError::Configuration)?;
        let spec = admitted
            .service_spec(
                self.release.system_generation(),
                identity.domain,
                identity.interface,
                identity.interface_generation,
                identity.provider_generation,
                identity.class,
            )
            .map_err(ConfiguredIsolationPreparationError::Configuration)?;
        prepare_isolation_service_route(&mut self.admission, spec)
            .map_err(ConfiguredIsolationPreparationError::Admission)
    }

    pub fn finalize(
        &self,
    ) -> Result<mrml_kernel::TotalMicrovmRuntimeProof, mrml_kernel::TotalMicrovmRuntimeError> {
        self.release.finalize(&self.admission)
    }
}

/// The common boot Total owner plus the committed recovery identity that
/// produced its effective policy. All route and proof operations delegate to
/// the contained owner so recovery cannot accidentally construct a parallel
/// admission table.
pub struct RecoveredTotalAdmission<const DOMAINS: usize> {
    policy: RecoveredBootIsolationPolicy,
    total: BootTotalAdmission<DOMAINS>,
}

impl<const DOMAINS: usize> RecoveredTotalAdmission<DOMAINS> {
    pub const fn policy(&self) -> RecoveredBootIsolationPolicy {
        self.policy
    }

    pub const fn release(&self) -> &ActivatedReleaseTotalMicrovmInventory<DOMAINS> {
        self.total.release()
    }

    pub const fn admission(&self) -> &IsolationAdmissionTable<DOMAINS> {
        self.total.admission()
    }

    pub fn admission_mut(&mut self) -> &mut IsolationAdmissionTable<DOMAINS> {
        self.total.admission_mut()
    }

    pub fn prepare_service(
        &mut self,
        bounds: IsolationServiceBounds,
        identity: IsolationServiceIdentity,
    ) -> Result<PreparedIsolationServiceRoute, ConfiguredIsolationPreparationError> {
        self.total.prepare_service(bounds, identity)
    }

    pub fn finalize(
        &self,
    ) -> Result<mrml_kernel::TotalMicrovmRuntimeProof, mrml_kernel::TotalMicrovmRuntimeError> {
        self.total.finalize()
    }
}

impl EffectiveBootIsolationPolicy {
    pub const fn configured(self) -> AppliedIsolationPolicy {
        self.persistent
    }

    pub const fn mode(self) -> IsolationMode {
        self.mode
    }

    pub const fn boot_override(self) -> Option<BootIsolationOverride> {
        self.boot_override
    }

    pub const fn policy_generation(self) -> u64 {
        self.persistent.policy_generation
    }

    pub fn admission_table<const DOMAINS: usize>(
        self,
        system_generation: u64,
    ) -> Result<IsolationAdmissionTable<DOMAINS>, ConfigError> {
        IsolationAdmissionTable::new(self.mode, system_generation, self.policy_generation())
            .map_err(|_| ConfigError::InvalidValue)
    }

    pub fn bind_release_inventory<const DOMAINS: usize>(
        self,
        release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
    ) -> Result<BootTotalAdmission<DOMAINS>, ConfigError> {
        if self.mode != IsolationMode::TotalMicrovm
            || release.policy_generation() != self.policy_generation()
        {
            return Err(ConfigError::IsolationPolicyMismatch);
        }
        let admission = IsolationAdmissionTable::new_activated(
            self.mode,
            release.active_release().generation(),
            self.policy_generation(),
        )
        .map_err(|_| ConfigError::InvalidValue)?;
        Ok(BootTotalAdmission {
            policy: self,
            release,
            admission,
        })
    }

    pub fn admit_service(
        self,
        bounds: IsolationServiceBounds,
    ) -> Result<AdmittedIsolationServicePolicy, ConfigError> {
        self.persistent.admit_service_for_mode(self.mode, bounds)
    }

    pub fn semantic_view(
        self,
        bounds: IsolationServiceBounds,
        status: IsolationStatusSnapshot,
    ) -> Result<IsolationPolicySemanticView, ConfigError> {
        self.persistent
            .semantic_view_for_mode(self.mode, bounds, status)
    }
}

/// Privacy-bounded semantic projection shared by every authorized frontend.
/// It contains aggregate kernel status and package-policy bounds, never domain
/// identities, capabilities, setting values outside isolation policy, or a
/// remediation/launch operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationPolicySemanticView {
    configured_system: OwnerIsolationSelection,
    configured_component: OwnerIsolationSelection,
    preferred: IsolationPlacement,
    minimum: IsolationPlacement,
    maximum: IsolationPlacement,
    native_supported: bool,
    microvm_supported: bool,
    effective_placement: Option<IsolationPlacement>,
    policy_source: Option<IsolationPolicySource>,
    component_blocked: bool,
    status: IsolationStatusSnapshot,
}

impl IsolationPolicySemanticView {
    pub const fn configured_system(self) -> OwnerIsolationSelection {
        self.configured_system
    }

    pub const fn configured_component(self) -> OwnerIsolationSelection {
        self.configured_component
    }

    pub const fn preferred(self) -> IsolationPlacement {
        self.preferred
    }

    pub const fn minimum(self) -> IsolationPlacement {
        self.minimum
    }

    pub const fn maximum(self) -> IsolationPlacement {
        self.maximum
    }

    pub const fn native_supported(self) -> bool {
        self.native_supported
    }

    pub const fn microvm_supported(self) -> bool {
        self.microvm_supported
    }

    pub const fn effective_placement(self) -> Option<IsolationPlacement> {
        self.effective_placement
    }

    pub const fn policy_source(self) -> Option<IsolationPolicySource> {
        self.policy_source
    }

    pub const fn component_blocked(self) -> bool {
        self.component_blocked
    }

    pub const fn status(self) -> IsolationStatusSnapshot {
        self.status
    }
}

const fn service_placement_rank(placement: IsolationPlacement) -> u8 {
    match placement {
        IsolationPlacement::NativeService => 1,
        IsolationPlacement::Microvm => 2,
        _ => 0,
    }
}

/// Runtime projection of one already authenticated service package's canonical
/// placement bounds. This is constraint input, not authority or provider
/// selection, and supports only the two service forms admitted by this path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationServiceBounds {
    preferred: IsolationPlacement,
    minimum: IsolationPlacement,
    maximum: IsolationPlacement,
    native_supported: bool,
    microvm_supported: bool,
}

impl IsolationServiceBounds {
    pub fn new(
        preferred: IsolationPlacement,
        minimum: IsolationPlacement,
        maximum: IsolationPlacement,
        native_supported: bool,
        microvm_supported: bool,
    ) -> Result<Self, ConfigError> {
        if !matches!(
            preferred,
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) || !matches!(
            minimum,
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) || !matches!(
            maximum,
            IsolationPlacement::NativeService | IsolationPlacement::Microvm
        ) || (!native_supported && !microvm_supported)
            || (preferred == IsolationPlacement::NativeService && !native_supported)
            || (preferred == IsolationPlacement::Microvm && !microvm_supported)
            || (minimum == IsolationPlacement::NativeService && !native_supported)
            || (minimum == IsolationPlacement::Microvm && !microvm_supported)
            || (maximum == IsolationPlacement::NativeService && !native_supported)
            || (maximum == IsolationPlacement::Microvm && !microvm_supported)
            || service_placement_rank(minimum) > service_placement_rank(preferred)
            || service_placement_rank(preferred) > service_placement_rank(maximum)
        {
            return Err(ConfigError::InvalidSchema);
        }
        Ok(Self {
            preferred,
            minimum,
            maximum,
            native_supported,
            microvm_supported,
        })
    }

    pub const fn supports(self, placement: IsolationPlacement) -> bool {
        match placement {
            IsolationPlacement::NativeService => self.native_supported,
            IsolationPlacement::Microvm => self.microvm_supported,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationPolicySource {
    PackageDefault,
    Owner,
    TotalMicrovm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedIsolationServicePolicy {
    placement: IsolationPlacement,
    source: IsolationPolicySource,
    policy_generation: u64,
}

impl AdmittedIsolationServicePolicy {
    pub const fn placement(self) -> IsolationPlacement {
        self.placement
    }

    pub const fn source(self) -> IsolationPolicySource {
        self.source
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    pub fn service_spec(
        self,
        system_generation: u64,
        domain: ObjectId,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        class: mrml_kernel::TotalMicrovmClass,
    ) -> Result<IsolationServiceSpec, ConfigError> {
        IsolationServiceSpec::new(
            domain,
            interface,
            interface_generation,
            provider_generation,
            system_generation,
            self.policy_generation,
            class,
            self.placement,
        )
        .map_err(|_| ConfigError::InvalidValue)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationServiceIdentity {
    domain: ObjectId,
    interface: ObjectId,
    interface_generation: u32,
    provider_generation: u64,
    class: mrml_kernel::TotalMicrovmClass,
}

impl IsolationServiceIdentity {
    pub const fn new(
        domain: ObjectId,
        interface: ObjectId,
        interface_generation: u32,
        provider_generation: u64,
        class: mrml_kernel::TotalMicrovmClass,
    ) -> Result<Self, ConfigError> {
        if domain.0 == 0
            || interface.0 == 0
            || interface_generation == 0
            || provider_generation == 0
        {
            return Err(ConfigError::InvalidValue);
        }
        Ok(Self {
            domain,
            interface,
            interface_generation,
            provider_generation,
            class,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn interface(self) -> ObjectId {
        self.interface
    }

    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn class(self) -> mrml_kernel::TotalMicrovmClass {
        self.class
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ConfiguredIsolationRouteError<E, Endpoint> {
    Configuration(ConfigError),
    Route(IsolationServiceRouteError<E, Endpoint>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredIsolationPreparationError {
    Configuration(ConfigError),
    Admission(mrml_kernel::IsolationLaunchError),
}

fn configured_isolation_service_spec<
    const SETTINGS: usize,
    const AUDIT: usize,
    const DOMAINS: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    plan: IsolationPolicyApplicationPlan,
    boot_override: Option<BootIsolationOverride>,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
    admission: &IsolationAdmissionTable<DOMAINS>,
) -> Result<IsolationServiceSpec, ConfigError> {
    let effective = plan
        .apply(configuration, capabilities)?
        .compose_boot_override(boot_override);
    if admission.mode() != effective.mode()
        || admission.policy_generation() != effective.policy_generation()
    {
        return Err(ConfigError::IsolationPolicyMismatch);
    }
    effective.admit_service(bounds)?.service_spec(
        admission.system_generation(),
        identity.domain,
        identity.interface,
        identity.interface_generation,
        identity.provider_generation,
        identity.class,
    )
}

/// Performs the complete configured control-plane check and reserves kernel
/// admission before a VMM starts guest construction. The returned transaction
/// retains the exact checked specification through later commit or rollback.
pub fn prepare_configured_isolation_service_route<
    const SETTINGS: usize,
    const AUDIT: usize,
    const DOMAINS: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    plan: IsolationPolicyApplicationPlan,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
    admission: &mut IsolationAdmissionTable<DOMAINS>,
) -> Result<PreparedIsolationServiceRoute, ConfiguredIsolationPreparationError> {
    let spec = configured_isolation_service_spec(
        configuration,
        capabilities,
        plan,
        None,
        bounds,
        identity,
        admission,
    )
    .map_err(ConfiguredIsolationPreparationError::Configuration)?;
    prepare_isolation_service_route(admission, spec)
        .map_err(ConfiguredIsolationPreparationError::Admission)
}

/// Applies one authority-free trusted-loader overlay after revalidating the
/// exact persistent policy revision, then reserves kernel admission before VMM
/// construction. The overlay is retained separately from persistent state and
/// can only select the strict Total mode represented by `BootIsolationOverride`.
pub fn prepare_boot_configured_isolation_service_route<
    const SETTINGS: usize,
    const AUDIT: usize,
    const DOMAINS: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    plan: IsolationPolicyApplicationPlan,
    boot_override: BootIsolationOverride,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
    admission: &mut IsolationAdmissionTable<DOMAINS>,
) -> Result<PreparedIsolationServiceRoute, ConfiguredIsolationPreparationError> {
    let spec = configured_isolation_service_spec(
        configuration,
        capabilities,
        plan,
        Some(boot_override),
        bounds,
        identity,
        admission,
    )
    .map_err(ConfiguredIsolationPreparationError::Configuration)?;
    prepare_isolation_service_route(admission, spec)
        .map_err(ConfiguredIsolationPreparationError::Admission)
}

/// Revalidates persistent policy, package bounds, kernel policy generation,
/// and the exact interface/provider identity before invoking one selected
/// backend. No backend is called on any control-plane mismatch, and backend
/// failure is never retried through the other placement.
pub fn route_configured_isolation_service<
    const SETTINGS: usize,
    const AUDIT: usize,
    const DOMAINS: usize,
    A: CapabilityAuthorizer + ?Sized,
    B: IsolationServiceBackend,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    plan: IsolationPolicyApplicationPlan,
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
    admission: &mut IsolationAdmissionTable<DOMAINS>,
    backend: &mut B,
) -> Result<RoutedIsolationService<B::Endpoint>, ConfiguredIsolationRouteError<B::Error, B::Endpoint>>
{
    let spec = configured_isolation_service_spec(
        configuration,
        capabilities,
        plan,
        None,
        bounds,
        identity,
        admission,
    )
    .map_err(ConfiguredIsolationRouteError::Configuration)?;
    route_isolation_service(admission, backend, spec).map_err(ConfiguredIsolationRouteError::Route)
}

impl<const UPDATES: usize> ConfigTransaction<UPDATES> {
    pub fn new(expected_revision: u64) -> Self {
        Self {
            expected_revision,
            updates: [None; UPDATES],
            count: 0,
        }
    }

    pub fn push(&mut self, update: ConfigUpdate) -> Result<(), ConfigError> {
        if self.count == UPDATES {
            return Err(ConfigError::Capacity);
        }
        self.updates[self.count] = Some(update);
        self.count += 1;
        Ok(())
    }

    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub revision: u64,
    pub setting: SettingId,
}

pub struct ConfigurationService<const SETTINGS: usize, const AUDIT: usize> {
    root: ObjectId,
    settings: [Option<SettingEntry>; SETTINGS],
    setting_count: usize,
    revision: u64,
    audit: [Option<AuditEvent>; AUDIT],
    audit_head: usize,
    audit_count: usize,
    next_audit_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountedConfigurationError {
    Configuration(ConfigError),
    Memory(MemoryResourceError),
    Arithmetic,
}

impl From<ConfigError> for AccountedConfigurationError {
    fn from(value: ConfigError) -> Self {
        Self::Configuration(value)
    }
}

impl From<MemoryResourceError> for AccountedConfigurationError {
    fn from(value: MemoryResourceError) -> Self {
        Self::Memory(value)
    }
}

/// Fixed-capacity configuration state whose complete concrete footprint is
/// committed to one exact memory pool before publication.
pub struct AccountedConfigurationService<const SETTINGS: usize, const AUDIT: usize> {
    service: ConfigurationService<SETTINGS, AUDIT>,
    charge: MemoryObjectId,
    charge_capability: Capability,
    committed_pages: u64,
}

impl<const SETTINGS: usize, const AUDIT: usize> AccountedConfigurationService<SETTINGS, AUDIT> {
    pub fn empty<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        root: ObjectId,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedConfigurationError> {
        Self::account(
            ConfigurationService::empty(root)?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        root: ObjectId,
        schemas: &[SettingSchema],
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedConfigurationError> {
        Self::account(
            ConfigurationService::new(root, schemas)?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_checkpoint<
        A: CapabilityAuthorizer + ?Sized,
        const POOLS: usize,
        const OBJECTS: usize,
        const AUTHORITIES: usize,
    >(
        capabilities: &A,
        root_capability: Capability,
        input: &[u8],
        expected_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedConfigurationError> {
        Self::account(
            ConfigurationService::recover_checkpoint(
                capabilities,
                root_capability,
                input,
                expected_digest,
            )?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    pub fn required_pages() -> Result<u64, AccountedConfigurationError> {
        let bytes = u64::try_from(size_of::<Self>())
            .map_err(|_| AccountedConfigurationError::Arithmetic)?;
        bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded / PAGE_SIZE)
            .filter(|pages| *pages != 0)
            .ok_or(AccountedConfigurationError::Arithmetic)
    }

    pub const fn charge(&self) -> MemoryObjectId {
        self.charge
    }

    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    #[allow(clippy::result_large_err)]
    pub fn release<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        self,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<u64, (Self, MemoryResourceError)> {
        match memory.release_object(self.charge, self.charge_capability, authorities) {
            Ok(pages) => Ok(pages),
            Err(error) => Err((self, error)),
        }
    }

    fn account<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        service: ConfigurationService<SETTINGS, AUDIT>,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedConfigurationError> {
        let committed_pages = Self::required_pages()?;
        let (charge, charge_capability) = memory.allocate_object(
            pool,
            pool_capability,
            committed_pages,
            MemoryBackingKind::Anonymous,
            Rights::CONTROL,
            authorities,
        )?;
        Ok(Self {
            service,
            charge,
            charge_capability,
            committed_pages,
        })
    }
}

impl<const SETTINGS: usize, const AUDIT: usize> Deref
    for AccountedConfigurationService<SETTINGS, AUDIT>
{
    type Target = ConfigurationService<SETTINGS, AUDIT>;

    fn deref(&self) -> &Self::Target {
        &self.service
    }
}

impl<const SETTINGS: usize, const AUDIT: usize> DerefMut
    for AccountedConfigurationService<SETTINGS, AUDIT>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.service
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountedPolicyServiceError {
    Runtime(TaskRuntimeError),
    Configuration(ConfigError),
    Memory(MemoryResourceError),
    Arithmetic,
}

impl From<TaskRuntimeError> for AccountedPolicyServiceError {
    fn from(value: TaskRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<ConfigError> for AccountedPolicyServiceError {
    fn from(value: ConfigError) -> Self {
        Self::Configuration(value)
    }
}

impl From<MemoryResourceError> for AccountedPolicyServiceError {
    fn from(value: MemoryResourceError) -> Self {
        Self::Memory(value)
    }
}

/// One fixed-capacity Phase 2 policy-service substrate admitted by one atomic
/// memory commitment.
///
/// The task runtime, service supervisor, and configuration state are owned
/// directly so their concrete aggregate footprint is charged once. Standalone
/// accounted wrappers remain appropriate when those components have separate
/// owners and lifetimes.
pub struct AccountedPolicyServiceSubstrate<
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> {
    runtime: TaskRuntime<TASKS, CAPS>,
    supervisor: ServiceSupervisor<SERVICES>,
    configuration: ConfigurationService<SETTINGS, AUDIT>,
    charge: MemoryObjectId,
    charge_capability: Capability,
    committed_pages: u64,
}

impl<
    const TASKS: usize,
    const CAPS: usize,
    const SERVICES: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> AccountedPolicyServiceSubstrate<TASKS, CAPS, SERVICES, SETTINGS, AUDIT>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        ticks_per_second: u32,
        quantum_ticks: u32,
        root: ObjectId,
        schemas: &[SettingSchema],
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedPolicyServiceError> {
        Self::account(
            TaskRuntime::new(ticks_per_second, quantum_ticks)?,
            ConfigurationService::new(root, schemas)?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn empty<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        ticks_per_second: u32,
        quantum_ticks: u32,
        root: ObjectId,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedPolicyServiceError> {
        Self::account(
            TaskRuntime::new(ticks_per_second, quantum_ticks)?,
            ConfigurationService::empty(root)?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_checkpoint<
        A: CapabilityAuthorizer + ?Sized,
        const POOLS: usize,
        const OBJECTS: usize,
        const AUTHORITIES: usize,
    >(
        ticks_per_second: u32,
        quantum_ticks: u32,
        capabilities: &A,
        root_capability: Capability,
        input: &[u8],
        expected_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedPolicyServiceError> {
        Self::account(
            TaskRuntime::new(ticks_per_second, quantum_ticks)?,
            ConfigurationService::recover_checkpoint(
                capabilities,
                root_capability,
                input,
                expected_digest,
            )?,
            pool,
            pool_capability,
            memory,
            authorities,
        )
    }

    pub fn required_pages() -> Result<u64, AccountedPolicyServiceError> {
        let bytes = u64::try_from(size_of::<Self>())
            .map_err(|_| AccountedPolicyServiceError::Arithmetic)?;
        bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded / PAGE_SIZE)
            .filter(|pages| *pages != 0)
            .ok_or(AccountedPolicyServiceError::Arithmetic)
    }

    pub const fn runtime(&self) -> &TaskRuntime<TASKS, CAPS> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut TaskRuntime<TASKS, CAPS> {
        &mut self.runtime
    }

    pub const fn supervisor(&self) -> &ServiceSupervisor<SERVICES> {
        &self.supervisor
    }

    pub fn supervisor_mut(&mut self) -> &mut ServiceSupervisor<SERVICES> {
        &mut self.supervisor
    }

    pub const fn configuration(&self) -> &ConfigurationService<SETTINGS, AUDIT> {
        &self.configuration
    }

    pub fn configuration_mut(&mut self) -> &mut ConfigurationService<SETTINGS, AUDIT> {
        &mut self.configuration
    }

    pub const fn charge(&self) -> MemoryObjectId {
        self.charge
    }

    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    /// Returns the aggregate commitment only after every dependent task and
    /// lifecycle authority has been retired externally.
    ///
    /// # Safety
    ///
    /// No task, service, cleanup ticket, prepared registration/restart, peer,
    /// recovery path, or external policy state may depend on this substrate.
    #[allow(clippy::result_large_err)]
    pub unsafe fn release<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        self,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<u64, (Self, MemoryResourceError)> {
        match memory.release_object(self.charge, self.charge_capability, authorities) {
            Ok(pages) => Ok(pages),
            Err(error) => Err((self, error)),
        }
    }

    fn account<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        runtime: TaskRuntime<TASKS, CAPS>,
        configuration: ConfigurationService<SETTINGS, AUDIT>,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedPolicyServiceError> {
        let committed_pages = Self::required_pages()?;
        let (charge, charge_capability) = memory.allocate_object(
            pool,
            pool_capability,
            committed_pages,
            MemoryBackingKind::Anonymous,
            Rights::CONTROL,
            authorities,
        )?;
        Ok(Self {
            runtime,
            supervisor: ServiceSupervisor::new(),
            configuration,
            charge,
            charge_capability,
            committed_pages,
        })
    }
}

impl<const SETTINGS: usize, const AUDIT: usize> ConfigurationService<SETTINGS, AUDIT> {
    pub fn empty(root: ObjectId) -> Result<Self, ConfigError> {
        if root.0 == 0 {
            return Err(ConfigError::InvalidRoot);
        }
        if SETTINGS == 0 || AUDIT == 0 {
            return Err(ConfigError::Capacity);
        }
        Ok(Self {
            root,
            settings: array::from_fn(|_| None),
            setting_count: 0,
            revision: 0,
            audit: [None; AUDIT],
            audit_head: 0,
            audit_count: 0,
            next_audit_sequence: 1,
        })
    }

    pub fn new(root: ObjectId, schemas: &[SettingSchema]) -> Result<Self, ConfigError> {
        if root.0 == 0 {
            return Err(ConfigError::InvalidRoot);
        }
        if schemas.is_empty() || schemas.len() > SETTINGS {
            return Err(ConfigError::Capacity);
        }
        let mut service = Self::empty(root)?;
        for schema in schemas.iter().copied() {
            service.insert_schema(schema)?;
        }
        Ok(service)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn setting_count(&self) -> usize {
        self.setting_count
    }

    pub fn admit_schema<A: CapabilityAuthorizer + ?Sized>(
        &mut self,
        capabilities: &A,
        root_capability: Capability,
        schema: SettingSchema,
    ) -> Result<(), ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::CONTROL, self.root)?;
        if self.revision != 0 {
            return Err(ConfigError::SchemaFrozen);
        }
        self.insert_schema(schema)
    }

    pub fn export_checkpoint<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        root_capability: Capability,
        output: &mut [u8],
    ) -> Result<ConfigurationCheckpoint, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::READ, self.root)?;
        let length = CONFIG_CHECKPOINT_HEADER_BYTES
            .checked_add(
                self.setting_count
                    .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
                    .ok_or(ConfigError::InvalidCheckpoint)?,
            )
            .and_then(|length| {
                length.checked_add(
                    self.audit_count
                        .checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)?,
                )
            })
            .ok_or(ConfigError::InvalidCheckpoint)?;
        if output.len() < length || length > u32::MAX as usize {
            return Err(ConfigError::Truncated);
        }
        output[..length].fill(0);
        output[..4].copy_from_slice(&CONFIG_CHECKPOINT_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, CONFIG_CHECKPOINT_HEADER_BYTES as u16)?;
        write_u32(output, 8, length as u32)?;
        write_u16(
            output,
            12,
            u16::try_from(self.setting_count).map_err(|_| ConfigError::InvalidCheckpoint)?,
        )?;
        write_u16(
            output,
            14,
            u16::try_from(self.audit_count).map_err(|_| ConfigError::InvalidCheckpoint)?,
        )?;
        write_u64(output, 16, self.root.0)?;
        write_u64(output, 24, self.revision)?;
        write_u64(output, 32, self.next_audit_sequence)?;

        for (index, entry) in self.settings[..self.setting_count]
            .iter()
            .flatten()
            .copied()
            .enumerate()
        {
            let start = CONFIG_CHECKPOINT_HEADER_BYTES + index * CONFIG_CHECKPOINT_SETTING_BYTES;
            write_u32(output, start, entry.schema.setting.get())?;
            write_u64(output, start + 8, entry.schema.object.0)?;
            write_u64(output, start + 16, entry.revision)?;
            match entry.schema.constraint {
                Constraint::Bool => output[start + 4] = 1,
                Constraint::U64 { minimum, maximum } => {
                    output[start + 4] = 2;
                    write_u64(output, start + 24, minimum)?;
                    write_u64(output, start + 32, maximum)?;
                }
                Constraint::Bytes { maximum_length } => {
                    output[start + 4] = 3;
                    output[start + 5] = maximum_length;
                }
            }
            if let Some(value) = entry.value {
                output[start + 6] = 1;
                output[start + 7] = value.kind as u8;
                output[start + 40] = value.length;
                output[start + 48..start + 112].copy_from_slice(&value.bytes);
            }
        }
        let audit_start =
            CONFIG_CHECKPOINT_HEADER_BYTES + self.setting_count * CONFIG_CHECKPOINT_SETTING_BYTES;
        for index in 0..self.audit_count {
            let event = self.audit[(self.audit_head + index) % AUDIT]
                .ok_or(ConfigError::InvalidCheckpoint)?;
            let start = audit_start + index * CONFIG_CHECKPOINT_AUDIT_BYTES;
            write_u64(output, start, event.sequence)?;
            write_u64(output, start + 8, event.revision)?;
            write_u32(output, start + 16, event.setting.get())?;
        }
        let digest = checkpoint_digest(&output[..length]);
        output[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        Ok(ConfigurationCheckpoint { length, digest })
    }

    pub fn recover_checkpoint<A: CapabilityAuthorizer + ?Sized>(
        capabilities: &A,
        root_capability: Capability,
        input: &[u8],
        expected_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES],
    ) -> Result<Self, ConfigError> {
        if input.len() < CONFIG_CHECKPOINT_HEADER_BYTES
            || input[..4] != CONFIG_CHECKPOINT_MAGIC
            || read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION
            || usize::from(read_u16(input, 6)?) != CONFIG_CHECKPOINT_HEADER_BYTES
            || usize::try_from(read_u32(input, 8)?).ok() != Some(input.len())
            || input[40..CONFIG_CHECKPOINT_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let embedded_digest: [u8; CONFIG_CHECKPOINT_DIGEST_BYTES] = input
            [CONFIG_CHECKPOINT_DIGEST_OFFSET
                ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .try_into()
            .map_err(|_| ConfigError::InvalidCheckpoint)?;
        if embedded_digest != expected_digest || checkpoint_digest(input) != expected_digest {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let setting_count = usize::from(read_u16(input, 12)?);
        let audit_count = usize::from(read_u16(input, 14)?);
        if setting_count > SETTINGS || audit_count > AUDIT {
            return Err(ConfigError::Capacity);
        }
        let wanted = CONFIG_CHECKPOINT_HEADER_BYTES
            .checked_add(
                setting_count
                    .checked_mul(CONFIG_CHECKPOINT_SETTING_BYTES)
                    .ok_or(ConfigError::InvalidCheckpoint)?,
            )
            .and_then(|length| {
                length.checked_add(audit_count.checked_mul(CONFIG_CHECKPOINT_AUDIT_BYTES)?)
            })
            .ok_or(ConfigError::InvalidCheckpoint)?;
        if wanted != input.len() {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let root = ObjectId(read_u64(input, 16)?);
        Self::authorize(capabilities, root_capability, Rights::CONTROL, root)?;
        let revision = read_u64(input, 24)?;
        let next_audit_sequence = read_u64(input, 32)?;
        let mut service = Self::empty(root)?;
        for index in 0..setting_count {
            let start = CONFIG_CHECKPOINT_HEADER_BYTES + index * CONFIG_CHECKPOINT_SETTING_BYTES;
            if input[start + 41..start + 48].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::InvalidCheckpoint);
            }
            let setting = SettingId::new(read_u32(input, start)?)?;
            let object = ObjectId(read_u64(input, start + 8)?);
            let minimum = read_u64(input, start + 24)?;
            let maximum = read_u64(input, start + 32)?;
            let schema = match input[start + 4] {
                1 if input[start + 5] == 0 && minimum == 0 && maximum == 0 => {
                    SettingSchema::boolean(setting, object)?
                }
                2 if input[start + 5] == 0 => {
                    SettingSchema::unsigned(setting, object, minimum, maximum)?
                }
                3 if minimum == 0 && maximum == 0 => {
                    SettingSchema::bytes(setting, object, input[start + 5])?
                }
                _ => return Err(ConfigError::InvalidCheckpoint),
            };
            service.insert_schema(schema)?;
            let entry_revision = read_u64(input, start + 16)?;
            let value = match input[start + 6] {
                0 if input[start + 7] == 0
                    && input[start + 40] == 0
                    && input[start + 48..start + 112].iter().all(|byte| *byte == 0)
                    && entry_revision == 0 =>
                {
                    None
                }
                1 if entry_revision != 0 && entry_revision <= revision => {
                    let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
                    bytes.copy_from_slice(&input[start + 48..start + 112]);
                    let value = ConfigValue::decode(input[start + 7], input[start + 40], &bytes)?;
                    schema.validate(value)?;
                    Some(value)
                }
                _ => return Err(ConfigError::InvalidCheckpoint),
            };
            let entry = service.entry_mut(setting)?;
            entry.value = value;
            entry.revision = entry_revision;
        }
        if next_audit_sequence == 0
            || next_audit_sequence <= audit_count as u64
            || (revision == 0 && (audit_count != 0 || next_audit_sequence != 1))
            || (revision != 0 && audit_count == 0)
        {
            return Err(ConfigError::InvalidCheckpoint);
        }
        let first_sequence = next_audit_sequence - audit_count as u64;
        let audit_start =
            CONFIG_CHECKPOINT_HEADER_BYTES + setting_count * CONFIG_CHECKPOINT_SETTING_BYTES;
        let mut prior_audit_revision = 0;
        for index in 0..audit_count {
            let start = audit_start + index * CONFIG_CHECKPOINT_AUDIT_BYTES;
            if input[start + 20..start + 24].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::InvalidCheckpoint);
            }
            let event = AuditEvent {
                sequence: read_u64(input, start)?,
                revision: read_u64(input, start + 8)?,
                setting: SettingId::new(read_u32(input, start + 16)?)?,
            };
            if event.sequence != first_sequence + index as u64
                || event.revision == 0
                || event.revision > revision
                || event.revision < prior_audit_revision
                || service
                    .entry(event.setting)
                    .map(|entry| entry.revision < event.revision)
                    .unwrap_or(true)
            {
                return Err(ConfigError::InvalidCheckpoint);
            }
            prior_audit_revision = event.revision;
            service.audit[index] = Some(event);
        }
        service.revision = revision;
        service.audit_head = 0;
        service.audit_count = audit_count;
        service.next_audit_sequence = next_audit_sequence;
        Ok(service)
    }

    pub fn read<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        capability: Capability,
        setting: SettingId,
    ) -> Result<ConfigRecord, ConfigError> {
        let entry = self.entry(setting)?;
        Self::authorize(capabilities, capability, Rights::READ, entry.schema.object)?;
        Ok(ConfigRecord {
            setting,
            revision: entry.revision,
            value: entry.value,
        })
    }

    pub fn commit<A: CapabilityAuthorizer + ?Sized, const UPDATES: usize>(
        &mut self,
        capabilities: &A,
        root_capability: Capability,
        transaction: &ConfigTransaction<UPDATES>,
    ) -> Result<u64, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::CONTROL, self.root)?;
        if transaction.is_empty() {
            return Err(ConfigError::EmptyTransaction);
        }
        if transaction.expected_revision != self.revision {
            return Err(ConfigError::RevisionConflict {
                current: self.revision,
            });
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ConfigError::RevisionExhausted)?;
        self.next_audit_sequence
            .checked_add(transaction.count as u64)
            .ok_or(ConfigError::SequenceExhausted)?;

        for index in 0..transaction.count {
            let update = transaction.updates[index].ok_or(ConfigError::NonCanonical)?;
            if transaction.updates[..index]
                .iter()
                .flatten()
                .any(|prior| prior.setting == update.setting)
            {
                return Err(ConfigError::DuplicateSetting);
            }
            let entry = self.entry(update.setting)?;
            Self::authorize(
                capabilities,
                update.capability,
                Rights::WRITE,
                entry.schema.object,
            )?;
            entry.schema.validate(update.value)?;
        }

        for update in transaction.updates[..transaction.count]
            .iter()
            .flatten()
            .copied()
        {
            let entry = self.entry_mut(update.setting)?;
            entry.value = Some(update.value);
            entry.revision = next_revision;
            self.push_audit(AuditEvent {
                sequence: self.next_audit_sequence,
                revision: next_revision,
                setting: update.setting,
            });
            self.next_audit_sequence += 1;
        }
        self.revision = next_revision;
        Ok(next_revision)
    }

    pub fn audit_event<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        root_capability: Capability,
        sequence: u64,
    ) -> Result<Option<AuditEvent>, ConfigError> {
        Self::authorize(capabilities, root_capability, Rights::READ, self.root)?;
        if sequence == 0 || sequence >= self.next_audit_sequence {
            return Ok(None);
        }
        let oldest = self.next_audit_sequence - self.audit_count as u64;
        if sequence < oldest {
            return Err(ConfigError::AuditUnavailable { oldest });
        }
        let offset = usize::try_from(sequence - oldest).map_err(|_| ConfigError::NonCanonical)?;
        Ok(self.audit[(self.audit_head + offset) % AUDIT])
    }

    fn authorize<A: CapabilityAuthorizer + ?Sized>(
        capabilities: &A,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        capabilities.authorize_exact(capability, rights, expected)
    }

    fn entry(&self, setting: SettingId) -> Result<&SettingEntry, ConfigError> {
        self.settings[..self.setting_count]
            .iter()
            .flatten()
            .find(|entry| entry.schema.setting == setting)
            .ok_or(ConfigError::MissingSetting)
    }

    fn entry_mut(&mut self, setting: SettingId) -> Result<&mut SettingEntry, ConfigError> {
        self.settings[..self.setting_count]
            .iter_mut()
            .flatten()
            .find(|entry| entry.schema.setting == setting)
            .ok_or(ConfigError::MissingSetting)
    }

    fn insert_schema(&mut self, schema: SettingSchema) -> Result<(), ConfigError> {
        if schema.object == self.root
            || self.settings[..self.setting_count]
                .iter()
                .flatten()
                .any(|entry| entry.schema.object == schema.object)
        {
            return Err(ConfigError::DuplicateObject);
        }
        if self.settings[..self.setting_count]
            .iter()
            .flatten()
            .any(|entry| entry.schema.setting == schema.setting)
        {
            return Err(ConfigError::DuplicateSetting);
        }
        let slot = self
            .settings
            .get_mut(self.setting_count)
            .ok_or(ConfigError::Capacity)?;
        *slot = Some(SettingEntry {
            schema,
            value: None,
            revision: 0,
        });
        self.setting_count += 1;
        Ok(())
    }

    fn push_audit(&mut self, event: AuditEvent) {
        if self.audit_count < AUDIT {
            let tail = (self.audit_head + self.audit_count) % AUDIT;
            self.audit[tail] = Some(event);
            self.audit_count += 1;
        } else {
            self.audit[self.audit_head] = Some(event);
            self.audit_head = (self.audit_head + 1) % AUDIT;
        }
    }
}

// The complete bounded transaction remains inline because this service crate
// has no allocator and decoded authority-bearing requests must own their bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq)]
pub enum ConfigurationRequest {
    Read {
        request_id: u64,
        setting: SettingId,
        capability: Capability,
    },
    Commit {
        request_id: u64,
        root: Capability,
        transaction: ConfigTransaction<MAX_WIRE_UPDATES>,
    },
    AdmitSchema {
        request_id: u64,
        root: Capability,
        schema: SettingSchema,
    },
}

impl ConfigurationRequest {
    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() < CONFIG_REQUEST_HEADER_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != CONFIG_REQUEST_MAGIC {
            return Err(ConfigError::InvalidProtocol);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let operation = read_u16(input, 6)?;
        let encoded_length = usize::from(read_u16(input, 8)?);
        let count = usize::from(input[10]);
        if encoded_length != input.len()
            || input[11..16].iter().any(|byte| *byte != 0)
            || input[44..48].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        let request_id = read_u64(input, 16)?;
        let expected_revision = read_u64(input, 24)?;
        let authority = Capability::from_token(read_u64(input, 32)?);
        let target = read_u32(input, 40)?;
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        match operation {
            1 if count == 0
                && encoded_length == CONFIG_REQUEST_HEADER_BYTES
                && expected_revision == 0 =>
            {
                Ok(Self::Read {
                    request_id,
                    setting: SettingId::new(target)?,
                    capability: authority,
                })
            }
            2 if (1..=MAX_WIRE_UPDATES).contains(&count) && target == 0 => {
                let wanted = CONFIG_REQUEST_HEADER_BYTES
                    .checked_add(count * CONFIG_UPDATE_BYTES)
                    .ok_or(ConfigError::NonCanonical)?;
                if encoded_length != wanted {
                    return Err(ConfigError::NonCanonical);
                }
                let mut transaction = ConfigTransaction::new(expected_revision);
                for index in 0..count {
                    let start = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES;
                    let setting = SettingId::new(read_u32(input, start)?)?;
                    let kind = input[start + 4];
                    let length = input[start + 5];
                    if input[start + 6..start + 8].iter().any(|byte| *byte != 0) {
                        return Err(ConfigError::NonCanonical);
                    }
                    let capability = Capability::from_token(read_u64(input, start + 8)?);
                    let mut value = [0; MAX_CONFIG_VALUE_BYTES];
                    value.copy_from_slice(&input[start + 16..start + 80]);
                    transaction.push(ConfigUpdate::new(
                        setting,
                        capability,
                        ConfigValue::decode(kind, length, &value)?,
                    ))?;
                }
                Ok(Self::Commit {
                    request_id,
                    root: authority,
                    transaction,
                })
            }
            3 if count == 0
                && expected_revision == 0
                && encoded_length == CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES =>
            {
                let object = ObjectId(read_u64(input, CONFIG_REQUEST_HEADER_BYTES)?);
                let kind = input[CONFIG_REQUEST_HEADER_BYTES + 8];
                let maximum_length = input[CONFIG_REQUEST_HEADER_BYTES + 9];
                if input[CONFIG_REQUEST_HEADER_BYTES + 10..CONFIG_REQUEST_HEADER_BYTES + 16]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(ConfigError::NonCanonical);
                }
                let minimum = read_u64(input, CONFIG_REQUEST_HEADER_BYTES + 16)?;
                let maximum = read_u64(input, CONFIG_REQUEST_HEADER_BYTES + 24)?;
                let setting = SettingId::new(target)?;
                let schema = match kind {
                    1 if maximum_length == 0 && minimum == 0 && maximum == 0 => {
                        SettingSchema::boolean(setting, object)?
                    }
                    2 if maximum_length == 0 => {
                        SettingSchema::unsigned(setting, object, minimum, maximum)?
                    }
                    3 if minimum == 0 && maximum == 0 => {
                        SettingSchema::bytes(setting, object, maximum_length)?
                    }
                    _ => return Err(ConfigError::NonCanonical),
                };
                Ok(Self::AdmitSchema {
                    request_id,
                    root: authority,
                    schema,
                })
            }
            _ => Err(ConfigError::NonCanonical),
        }
    }

    /// Resolves authority exclusively from capabilities derived by kernel IPC.
    /// Capability-token fields in the payload must be zero placeholders: a
    /// sender cannot predict the receiver-space generations created during
    /// transfer, and payload bytes never carry authority.
    pub fn decode_message(message: &Message) -> Result<Self, ConfigError> {
        let mut capabilities = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
        let count = message.capability_count();
        for (slot, capability) in capabilities.iter_mut().zip(message.capabilities()) {
            *slot = capability;
        }
        Self::decode_envelope(message.payload(), &capabilities[..count])
    }

    /// Decodes the exact payload and opaque receiver handles returned by the
    /// buffered CPL3 receive ABI. The handles remain inert until an authorizer
    /// asks the kernel to validate exact generation, rights, and object.
    pub fn decode_envelope(
        payload: &[u8],
        capabilities: &[Capability],
    ) -> Result<Self, ConfigError> {
        let mut request = Self::decode(payload)?;
        match &mut request {
            Self::Read { capability, .. } => {
                if payload[32..40].iter().any(|byte| *byte != 0) || capabilities.len() != 1 {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                *capability = capabilities
                    .iter()
                    .copied()
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
            }
            Self::Commit {
                root, transaction, ..
            } => {
                if payload[32..40].iter().any(|byte| *byte != 0)
                    || capabilities.len() != transaction.count + 1
                {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                let mut authorities = capabilities.iter().copied();
                *root = authorities
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
                for (index, update) in transaction.updates[..transaction.count]
                    .iter_mut()
                    .flatten()
                    .enumerate()
                {
                    let authority_offset =
                        CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES + 8;
                    if payload[authority_offset..authority_offset + 8]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(ConfigError::InvalidAuthorityEnvelope);
                    }
                    update.capability = authorities
                        .next()
                        .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
                }
                if authorities.next().is_some() {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
            }
            Self::AdmitSchema { root, .. } => {
                if payload[32..40].iter().any(|byte| *byte != 0) || capabilities.len() != 1 {
                    return Err(ConfigError::InvalidAuthorityEnvelope);
                }
                *root = capabilities[0];
            }
        }
        Ok(request)
    }
}

pub fn encode_schema_message_request(
    request_id: u64,
    schema: SettingSchema,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    encode_schema_request(request_id, Capability::from_token(0), schema, output)
}

pub fn encode_read_message_request(
    request_id: u64,
    setting: SettingId,
    output: &mut [u8; CONFIG_REQUEST_HEADER_BYTES],
) -> Result<(), ConfigError> {
    encode_read_request(request_id, setting, Capability::from_token(0), output)
}

pub fn encode_commit_message_request<const UPDATES: usize>(
    request_id: u64,
    transaction: &ConfigTransaction<UPDATES>,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    let length = encode_commit_request(request_id, Capability::from_token(0), transaction, output)?;
    for index in 0..transaction.count {
        let authority_offset = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES + 8;
        output[authority_offset..authority_offset + 8].fill(0);
    }
    Ok(length)
}

pub fn encode_read_request(
    request_id: u64,
    setting: SettingId,
    capability: Capability,
    output: &mut [u8; CONFIG_REQUEST_HEADER_BYTES],
) -> Result<(), ConfigError> {
    if request_id == 0 {
        return Err(ConfigError::NonCanonical);
    }
    *output = [0; CONFIG_REQUEST_HEADER_BYTES];
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 1)?;
    write_u16(output, 8, CONFIG_REQUEST_HEADER_BYTES as u16)?;
    write_u64(output, 16, request_id)?;
    write_u64(output, 32, capability.token())?;
    write_u32(output, 40, setting.get())
}

pub fn encode_schema_request(
    request_id: u64,
    root: Capability,
    schema: SettingSchema,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    let length = CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES;
    if request_id == 0 {
        return Err(ConfigError::NonCanonical);
    }
    if output.len() < length {
        return Err(ConfigError::Truncated);
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 3)?;
    write_u16(output, 8, length as u16)?;
    write_u64(output, 16, request_id)?;
    write_u64(output, 32, root.token())?;
    write_u32(output, 40, schema.setting.get())?;
    write_u64(output, CONFIG_REQUEST_HEADER_BYTES, schema.object.0)?;
    match schema.constraint {
        Constraint::Bool => output[CONFIG_REQUEST_HEADER_BYTES + 8] = 1,
        Constraint::U64 { minimum, maximum } => {
            output[CONFIG_REQUEST_HEADER_BYTES + 8] = 2;
            write_u64(output, CONFIG_REQUEST_HEADER_BYTES + 16, minimum)?;
            write_u64(output, CONFIG_REQUEST_HEADER_BYTES + 24, maximum)?;
        }
        Constraint::Bytes { maximum_length } => {
            output[CONFIG_REQUEST_HEADER_BYTES + 8] = 3;
            output[CONFIG_REQUEST_HEADER_BYTES + 9] = maximum_length;
        }
    }
    Ok(length)
}

pub fn encode_commit_request<const UPDATES: usize>(
    request_id: u64,
    root: Capability,
    transaction: &ConfigTransaction<UPDATES>,
    output: &mut [u8],
) -> Result<usize, ConfigError> {
    if request_id == 0 || transaction.is_empty() || transaction.len() > MAX_WIRE_UPDATES {
        return Err(ConfigError::NonCanonical);
    }
    let length = CONFIG_REQUEST_HEADER_BYTES + transaction.len() * CONFIG_UPDATE_BYTES;
    if output.len() < length {
        return Err(ConfigError::Truncated);
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&CONFIG_REQUEST_MAGIC);
    write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
    write_u16(output, 6, 2)?;
    write_u16(output, 8, length as u16)?;
    output[10] = transaction.len() as u8;
    write_u64(output, 16, request_id)?;
    write_u64(output, 24, transaction.expected_revision())?;
    write_u64(output, 32, root.token())?;
    for (index, update) in transaction.updates[..transaction.count]
        .iter()
        .flatten()
        .copied()
        .enumerate()
    {
        let start = CONFIG_REQUEST_HEADER_BYTES + index * CONFIG_UPDATE_BYTES;
        write_u32(output, start, update.setting.get())?;
        output[start + 4] = update.value.kind as u8;
        output[start + 5] = update.value.length;
        write_u64(output, start + 8, update.capability.token())?;
        output[start + 16..start + 80].copy_from_slice(&update.value.bytes);
    }
    Ok(length)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ResponseStatus {
    Ok = 0,
    Rejected = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationResponse {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub revision: u64,
    pub setting: Option<SettingId>,
    pub value: Option<ConfigValue>,
}

impl ConfigurationResponse {
    pub fn encode(self, output: &mut [u8; CONFIG_RESPONSE_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0
            || (self.value.is_some() && self.setting.is_none())
            || (self.status == ResponseStatus::Rejected
                && (self.setting.is_some() || self.value.is_some()))
        {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; CONFIG_RESPONSE_BYTES];
        output[..4].copy_from_slice(&CONFIG_RESPONSE_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.status as u16)?;
        write_u16(output, 8, CONFIG_RESPONSE_BYTES as u16)?;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.revision)?;
        if let Some(setting) = self.setting {
            write_u32(output, 32, setting.get())?;
            if let Some(value) = self.value {
                output[36] = value.kind as u8;
                output[37] = value.length;
                output[40..104].copy_from_slice(&value.bytes);
            }
        }
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != CONFIG_RESPONSE_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != CONFIG_RESPONSE_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[10..16].iter().any(|byte| *byte != 0)
            || input[38..40].iter().any(|byte| *byte != 0)
            || input[104..112].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let status = match read_u16(input, 6)? {
            0 => ResponseStatus::Ok,
            1 => ResponseStatus::Rejected,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        let revision = read_u64(input, 24)?;
        let setting = read_u32(input, 32)?;
        let kind = input[36];
        let length = input[37];
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        let (setting, value) = if setting == 0 {
            if kind != 0 || length != 0 || input[40..104].iter().any(|byte| *byte != 0) {
                return Err(ConfigError::NonCanonical);
            }
            (None, None)
        } else {
            if status == ResponseStatus::Rejected {
                return Err(ConfigError::NonCanonical);
            }
            let value = if kind == 0 {
                if length != 0 || input[40..104].iter().any(|byte| *byte != 0) {
                    return Err(ConfigError::NonCanonical);
                }
                None
            } else {
                let mut bytes = [0; MAX_CONFIG_VALUE_BYTES];
                bytes.copy_from_slice(&input[40..104]);
                Some(ConfigValue::decode(kind, length, &bytes)?)
            };
            (Some(SettingId::new(setting)?), value)
        };
        Ok(Self {
            request_id,
            status,
            revision,
            setting,
            value,
        })
    }
}

/// Dispatches one kernel-delivered configuration request. Malformed authority
/// envelopes fail without a response; well-formed requests receive either an
/// `Ok` result or a deliberately detail-free rejection so authorization errors
/// do not become an object-discovery oracle.
pub fn dispatch_configuration_message<
    const SETTINGS: usize,
    const AUDIT: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    service: &mut ConfigurationService<SETTINGS, AUDIT>,
    capabilities: &A,
    message: &Message,
    output: &mut [u8; CONFIG_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let mut capabilities_wire = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
    let count = message.capability_count();
    for (slot, capability) in capabilities_wire.iter_mut().zip(message.capabilities()) {
        *slot = capability;
    }
    dispatch_configuration_envelope(
        service,
        capabilities,
        message.payload(),
        &capabilities_wire[..count],
        output,
    )
}

pub fn dispatch_configuration_envelope<
    const SETTINGS: usize,
    const AUDIT: usize,
    A: CapabilityAuthorizer + ?Sized,
>(
    service: &mut ConfigurationService<SETTINGS, AUDIT>,
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; CONFIG_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let request = ConfigurationRequest::decode_envelope(payload, capabilities)?;
    let response = match request {
        ConfigurationRequest::Read {
            request_id,
            setting,
            capability,
        } => match service.read(authorizer, capability, setting) {
            Ok(record) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision: record.revision,
                setting: Some(record.setting),
                value: record.value,
            },
            Err(_) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Rejected,
                revision: service.revision(),
                setting: None,
                value: None,
            },
        },
        ConfigurationRequest::Commit {
            request_id,
            root,
            transaction,
        } => match service.commit(authorizer, root, &transaction) {
            Ok(revision) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision,
                setting: None,
                value: None,
            },
            Err(_) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Rejected,
                revision: service.revision(),
                setting: None,
                value: None,
            },
        },
        ConfigurationRequest::AdmitSchema {
            request_id,
            root,
            schema,
        } => match service.admit_schema(authorizer, root, schema) {
            Ok(()) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Ok,
                revision: service.revision(),
                setting: Some(schema.setting()),
                value: None,
            },
            Err(_) => ConfigurationResponse {
                request_id,
                status: ResponseStatus::Rejected,
                revision: service.revision(),
                setting: None,
                value: None,
            },
        },
    };
    response.encode(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SupervisionOperation {
    Query = 1,
    Restart = 2,
    ReplacePolicy = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionRequest {
    pub operation: SupervisionOperation,
    pub request_id: u64,
    pub service: ServiceId,
    pub capability: Capability,
    pub setting: Option<SettingId>,
    pub setting_capability: Capability,
}

impl SupervisionRequest {
    pub fn encode(self, output: &mut [u8; SUPERVISION_REQUEST_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0 || self.setting_capability.token() != 0 {
            return Err(ConfigError::NonCanonical);
        }
        let target = match (self.operation, self.setting) {
            (SupervisionOperation::Query | SupervisionOperation::Restart, None) => 0,
            (SupervisionOperation::ReplacePolicy, Some(setting)) => setting.get(),
            _ => return Err(ConfigError::NonCanonical),
        };
        *output = [0; SUPERVISION_REQUEST_BYTES];
        output[..4].copy_from_slice(&SUPERVISION_REQUEST_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.operation as u16)?;
        write_u16(output, 8, SUPERVISION_REQUEST_BYTES as u16)?;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.service.token())?;
        write_u64(output, 32, self.capability.token())?;
        write_u32(output, 40, target)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != SUPERVISION_REQUEST_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != SUPERVISION_REQUEST_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[10..16].iter().any(|byte| *byte != 0)
            || input[44..48].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let operation = match read_u16(input, 6)? {
            1 => SupervisionOperation::Query,
            2 => SupervisionOperation::Restart,
            3 => SupervisionOperation::ReplacePolicy,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        let target = read_u32(input, 40)?;
        let setting = match operation {
            SupervisionOperation::Query | SupervisionOperation::Restart if target == 0 => None,
            SupervisionOperation::ReplacePolicy => Some(SettingId::new(target)?),
            _ => return Err(ConfigError::NonCanonical),
        };
        Ok(Self {
            operation,
            request_id,
            service: ServiceId::from_token(read_u64(input, 24)?),
            capability: Capability::from_token(read_u64(input, 32)?),
            setting,
            setting_capability: Capability::from_token(0),
        })
    }

    pub fn encode_message(
        self,
        output: &mut [u8; SUPERVISION_REQUEST_BYTES],
    ) -> Result<(), ConfigError> {
        let mut request = self;
        request.capability = Capability::from_token(0);
        request.setting_capability = Capability::from_token(0);
        request.encode(output)
    }

    pub fn decode_message(message: &Message) -> Result<Self, ConfigError> {
        if message.payload().len() != SUPERVISION_REQUEST_BYTES
            || message.payload()[32..40].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::InvalidAuthorityEnvelope);
        }
        let mut request = Self::decode(message.payload())?;
        let mut capabilities = message.capabilities();
        match request.operation {
            SupervisionOperation::Query | SupervisionOperation::Restart
                if message.capability_count() == 1 =>
            {
                request.capability = capabilities
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
            }
            SupervisionOperation::ReplacePolicy if message.capability_count() == 2 => {
                request.setting_capability = capabilities
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
                request.capability = capabilities
                    .next()
                    .ok_or(ConfigError::InvalidAuthorityEnvelope)?;
            }
            _ => return Err(ConfigError::InvalidAuthorityEnvelope),
        }
        if capabilities.next().is_some() {
            return Err(ConfigError::InvalidAuthorityEnvelope);
        }
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SupervisionState {
    Running = 1,
    Exited = 2,
    Faulted = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionResponse {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub service: ServiceId,
    pub state: SupervisionState,
    pub detail: u64,
}

impl SupervisionResponse {
    pub fn encode(self, output: &mut [u8; SUPERVISION_RESPONSE_BYTES]) -> Result<(), ConfigError> {
        if self.request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        *output = [0; SUPERVISION_RESPONSE_BYTES];
        output[..4].copy_from_slice(&SUPERVISION_RESPONSE_MAGIC);
        write_u16(output, 4, SYSTEM_PROTOCOL_VERSION)?;
        write_u16(output, 6, self.status as u16)?;
        write_u16(output, 8, SUPERVISION_RESPONSE_BYTES as u16)?;
        output[10] = self.state as u8;
        write_u64(output, 16, self.request_id)?;
        write_u64(output, 24, self.service.token())?;
        write_u64(output, 32, self.detail)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ConfigError> {
        if input.len() != SUPERVISION_RESPONSE_BYTES {
            return Err(ConfigError::Truncated);
        }
        if input[..4] != SUPERVISION_RESPONSE_MAGIC
            || read_u16(input, 8)? as usize != input.len()
            || input[11..16].iter().any(|byte| *byte != 0)
            || input[40..48].iter().any(|byte| *byte != 0)
        {
            return Err(ConfigError::NonCanonical);
        }
        if read_u16(input, 4)? != SYSTEM_PROTOCOL_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        let status = match read_u16(input, 6)? {
            0 => ResponseStatus::Ok,
            1 => ResponseStatus::Rejected,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let state = match input[10] {
            1 => SupervisionState::Running,
            2 => SupervisionState::Exited,
            3 => SupervisionState::Faulted,
            _ => return Err(ConfigError::InvalidProtocol),
        };
        let request_id = read_u64(input, 16)?;
        if request_id == 0 {
            return Err(ConfigError::NonCanonical);
        }
        Ok(Self {
            request_id,
            status,
            service: ServiceId::from_token(read_u64(input, 24)?),
            state,
            detail: read_u64(input, 32)?,
        })
    }
}

/// Dispatches the query-only portion of the canonical supervision protocol at
/// the userspace service boundary. Restart remains a distinct trusted kernel
/// transition because its launch context cannot come from request bytes.
pub fn dispatch_supervision_query_envelope<A: ServiceStateAuthorizer + ?Sized>(
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let message =
        Message::new(payload, capabilities).map_err(|_| ConfigError::InvalidAuthorityEnvelope)?;
    let request = SupervisionRequest::decode_message(&message)?;
    if request.operation != SupervisionOperation::Query {
        return Err(ConfigError::InvalidProtocol);
    }
    let (status, state) = match authorizer.query_state(request.capability, request.service) {
        Ok(state) => (ResponseStatus::Ok, state.into()),
        Err(_) => (ResponseStatus::Rejected, SupervisionState::Exited),
    };
    SupervisionResponse {
        request_id: request.request_id,
        status,
        service: request.service,
        state,
        detail: 0,
    }
    .encode(output)
}

pub fn dispatch_supervision_restart_envelope<A: ServiceRestartAuthorizer + ?Sized>(
    authorizer: &A,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let message =
        Message::new(payload, capabilities).map_err(|_| ConfigError::InvalidAuthorityEnvelope)?;
    let request = SupervisionRequest::decode_message(&message)?;
    if request.operation != SupervisionOperation::Restart {
        return Err(ConfigError::InvalidProtocol);
    }
    let (status, service, state) =
        match authorizer.restart_service(request.capability, request.service) {
            Ok(replacement) => (ResponseStatus::Ok, replacement, SupervisionState::Running),
            Err(_) => (
                ResponseStatus::Rejected,
                request.service,
                SupervisionState::Exited,
            ),
        };
    SupervisionResponse {
        request_id: request.request_id,
        status,
        service,
        state,
        detail: 0,
    }
    .encode(output)
}

/// Re-reads one exact service-bound policy through the IPC-delivered setting
/// READ capability, then asks the kernel to apply it through the separately
/// delivered service CONTROL capability. The trusted userspace service supplies
/// the expected service object; a generational service token is never decoded
/// into or substituted for that object identity.
pub fn dispatch_supervision_policy_envelope<
    const SETTINGS: usize,
    const AUDIT: usize,
    C: CapabilityAuthorizer + ?Sized,
    K: ServicePolicyAuthorizer + ?Sized,
>(
    configuration: &ConfigurationService<SETTINGS, AUDIT>,
    configuration_authorizer: &C,
    kernel: &K,
    expected_service_object: ObjectId,
    payload: &[u8],
    capabilities: &[Capability],
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let message =
        Message::new(payload, capabilities).map_err(|_| ConfigError::InvalidAuthorityEnvelope)?;
    let request = SupervisionRequest::decode_message(&message)?;
    if request.operation != SupervisionOperation::ReplacePolicy {
        return Err(ConfigError::InvalidProtocol);
    }
    let setting = request.setting.ok_or(ConfigError::NonCanonical)?;
    let applied = match load_persisted_restart_policy(
        configuration,
        configuration_authorizer,
        request.setting_capability,
        setting,
        expected_service_object,
    ) {
        Ok(bound) => match bound.policy.restart_policy() {
            Ok(policy) => kernel
                .replace_policy(request.capability, request.service, policy)
                .is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    };
    SupervisionResponse {
        request_id: request.request_id,
        status: if applied {
            ResponseStatus::Ok
        } else {
            ResponseStatus::Rejected
        },
        service: request.service,
        state: if applied {
            SupervisionState::Running
        } else {
            SupervisionState::Exited
        },
        detail: 0,
    }
    .encode(output)
}

/// Composes a kernel-derived management capability with the existing bounded
/// supervisor. The caller supplies a trusted fresh launch context; no address,
/// priority, or executable choice is accepted from the untrusted request.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_supervision_message<
    const SERVICES: usize,
    const TASKS: usize,
    const TASK_CAPS: usize,
    const MANAGEMENT_CAPS: usize,
>(
    supervisor: &mut ServiceSupervisor<SERVICES>,
    management: &CapabilitySpace<MANAGEMENT_CAPS>,
    runtime: &mut TaskRuntime<TASKS, TASK_CAPS>,
    message: &Message,
    priority: Priority,
    fresh_context: UserContext,
    now: u64,
    output: &mut [u8; SUPERVISION_RESPONSE_BYTES],
) -> Result<(), ConfigError> {
    let request = SupervisionRequest::decode_message(message)?;
    let (status, service, state) = match request.operation {
        SupervisionOperation::Query => {
            match supervisor.state_authorized(request.service, management, request.capability) {
                Ok(state) => (ResponseStatus::Ok, request.service, state.into()),
                Err(_) => (
                    ResponseStatus::Rejected,
                    request.service,
                    SupervisionState::Exited,
                ),
            }
        }
        SupervisionOperation::Restart => match supervisor.restart_at(
            request.service,
            management,
            request.capability,
            runtime,
            priority,
            fresh_context,
            now,
        ) {
            Ok(replacement) => (ResponseStatus::Ok, replacement, SupervisionState::Running),
            Err(_) => (
                ResponseStatus::Rejected,
                request.service,
                SupervisionState::Exited,
            ),
        },
        SupervisionOperation::ReplacePolicy => (
            ResponseStatus::Rejected,
            request.service,
            SupervisionState::Exited,
        ),
    };
    SupervisionResponse {
        request_id: request.request_id,
        status,
        service,
        state,
        detail: 0,
    }
    .encode(output)
}

impl From<ServiceState> for SupervisionState {
    fn from(value: ServiceState) -> Self {
        match value {
            ServiceState::Running => Self::Running,
            ServiceState::Exited => Self::Exited,
            ServiceState::Faulted => Self::Faulted,
        }
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ConfigError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn checkpoint_digest(input: &[u8]) -> [u8; CONFIG_CHECKPOINT_DIGEST_BYTES] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..CONFIG_CHECKPOINT_DIGEST_OFFSET]);
    digest.update(&[0; CONFIG_CHECKPOINT_DIGEST_BYTES]);
    digest.update(&input[CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES..]);
    digest.finalize()
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ConfigError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, ConfigError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ConfigError::Truncated)
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 2)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), ConfigError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(ConfigError::Truncated)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, Sha3_512, lamport_public_key,
    };
    use mrml_kernel::{
        HostSubstrateCounts, IsolationUnavailableCounts, RuntimeDomainAssignment,
        RuntimeDomainAssignmentPlan, TotalMicrovmClass, TotalMicrovmState, route_isolation_service,
    };
    use mrml_package_format::{
        ActivatedSystemGeneration, ActivatedSystemRelease, ComponentInterfaceProvider,
        ComponentInterfaceRequirement, ComponentProviderForms, MAX_SYSTEM_RELEASE_BYTES,
        RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation, encode_system_release_with_runtime_inventory,
        parse_system_release,
    };
    use mrml_storage::{
        AUTHORITY_RECOVERY_STATE_BYTES, AuthenticatedAuthorityRecoveryState,
        AuthorityCheckpointProofIssuer, AuthorityRecoveryGuard, AuthorityRecoveryStateStore,
        BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockService, BlockServiceBackend,
        BlockServiceError, BlockVolume, BootRecoveryAdmission, CowMetadataImage, CowMetadataWrite,
        CowPublicationBackend, CowPublicationPlan, ExtentRecord, FileReadBackend, FileWriteBackend,
        OwnerApprovedAuthorityCheckpoint, ServicedBlockDevice, StorageObjectId, StorageObjectKind,
        StorageRecoveryGrant, StorageRights, StorageTransactionId, Superblock, VolumeHeader,
        VolumeId, authority_checkpoint_digest, encode_authority_checkpoint,
        recover_validate_and_commit_stable_authorities,
    };
    use std::vec;

    const MEMORY_POOL_RIGHTS: Rights = Rights::ALLOCATE.union(Rights::INSPECT);

    fn activated_configuration_release(
        domain: ObjectId,
        policy_generation: u64,
    ) -> ActivatedReleaseTotalMicrovmInventory<1> {
        let digest = [0x44; 64];
        let generation_record = SystemGenerationDigestRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
        };
        let mut generation = [0; 192];
        let generation_length =
            encode_system_generation(33, &[generation_record], &mut generation).unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(33, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length = encode_runtime_inventory(33, &[runtime_record], &mut runtime).unwrap();
        let private = [0x67; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = Sha3_512::digest(&public);
        let mut release = vec![0; MAX_SYSTEM_RELEASE_BYTES];
        let release_length = encode_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private,
            &mut release,
        )
        .unwrap();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let active_generation = ActivatedSystemGeneration::new(
            33,
            parsed.generation().digest(),
            parsed.interface_catalog().digest(),
            7,
            0x5155,
            3,
        )
        .unwrap();
        let active = ActivatedSystemRelease::new(active_generation, parsed.identity());
        let mut plan = RuntimeDomainAssignmentPlan::<1>::new(
            &release[..release_length],
            &key_id,
            active,
            policy_generation,
        )
        .unwrap();
        plan.assign_from_policy(|record| RuntimeDomainAssignment::new(record.package_id, domain))
            .unwrap();
        plan.seal().unwrap()
    }

    fn hosted_total_handoff(accepted_epoch: u64) -> ([u8; 512], usize) {
        let framebuffer = mrml_kernel::FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            mrml_kernel::PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let regions = [
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0xa0000).unwrap(),
                1,
                mrml_kernel::MemoryKind::Mmio,
            )
            .unwrap(),
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                64,
                mrml_kernel::MemoryKind::Reserved,
            )
            .unwrap(),
        ];
        let recovery = mrml_kernel::RecoveryStateMetadata::new(accepted_epoch, 1, None, 0).unwrap();
        let mut bytes = [0; 512];
        let length = mrml_kernel::encode_handoff_with_recovery_and_isolation(
            7,
            [1; 32],
            [2; 64],
            true,
            true,
            false,
            true,
            0x9000,
            framebuffer,
            &regions,
            recovery,
            Some(BootIsolationOverride::TotalMicrovmOnce),
            &mut bytes,
        )
        .unwrap();
        (bytes, length)
    }

    #[test]
    fn hosted_recovery_source_is_independent_of_the_decoded_handoff_epoch() {
        let domain = ObjectId(0x434f_4e46_4947_0001);
        let (current_bytes, current_length) = hosted_total_handoff(8);
        let current = BootHandoff::decode(&current_bytes[..current_length], |_| {}).unwrap();
        // SAFETY: this is the controlled hosted fixture named by the helper's
        // contract; it does not represent owner presence or durable hardware.
        let total = unsafe {
            hosted_recovery_probe::recover_total_admission_with(&current, |policy_generation| {
                Ok::<_, ()>(activated_configuration_release(domain, policy_generation))
            })
        }
        .unwrap();
        assert_eq!(total.policy().authority_epoch(), 9);
        assert_eq!(total.policy().boot_accepted_epoch(), 8);

        // The inventory builder sees only the recovered policy generation;
        // failure returns no detached policy or admission owner.
        assert!(matches!(
            unsafe {
                hosted_recovery_probe::recover_total_admission_with::<1, _, _>(
                    &current,
                    |policy_generation| {
                        assert_eq!(policy_generation, 1);
                        Err(7u8)
                    },
                )
            },
            Err(hosted_recovery_probe::HostedRecoveryProbeBuildError::ReleaseBuilder(7))
        ));

        let (stale_bytes, stale_length) = hosted_total_handoff(7);
        let stale = BootHandoff::decode(&stale_bytes[..stale_length], |_| {}).unwrap();
        // SAFETY: same controlled hosted fixture; the stale handoff must not
        // redefine its independently fixed authenticated recovery state.
        assert!(
            unsafe {
                hosted_recovery_probe::recover_total_admission_with(&stale, |policy_generation| {
                    Ok::<_, ()>(activated_configuration_release(domain, policy_generation))
                })
            }
            .is_err()
        );
    }
    const SYSTEM_GENERATION: u64 = 108;

    type TestPolicySubstrate = AccountedPolicyServiceSubstrate<2, 4, 2, 3, 2>;

    #[derive(Default)]
    struct NativePlacementProbe {
        launches: usize,
    }

    impl NativeConfigurationServiceLauncher for NativePlacementProbe {
        type Endpoint = u64;
        type Error = ();

        fn launch_native(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
            self.launches += 1;
            Ok(0x1000 | spec.provider_generation())
        }

        fn revoke_native(&mut self, _endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MicrovmPlacementProbe {
        launches: usize,
        unavailable: bool,
    }

    #[derive(Default)]
    struct NativeAddressSpaceEraser {
        attempts: usize,
        fail_first: bool,
        erased: Option<(TaskId, UserContext)>,
    }

    impl ServiceAddressSpaceEraser for NativeAddressSpaceEraser {
        type Error = ();

        fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error> {
            self.attempts += 1;
            if self.fail_first && self.attempts == 1 {
                return Err(());
            }
            self.erased = Some((task, context));
            Ok(())
        }
    }

    impl MicrovmConfigurationServiceLauncher for MicrovmPlacementProbe {
        type Endpoint = u64;
        type Error = ();

        fn launch_microvm(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
            self.launches += 1;
            if self.unavailable {
                Err((IsolationUnavailableReason::VmmResource, ()))
            } else {
                Ok(0x2000 | spec.provider_generation())
            }
        }

        fn revoke_microvm(&mut self, _endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct PreparedGuestFactoryProbe {
        preparations: usize,
        destructions: usize,
        fail_first_destruction: bool,
    }

    impl ConfigurationMicrovmFactory for PreparedGuestFactoryProbe {
        type Guest = IsolationServiceSpec;
        type Error = ();

        fn prepare(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)> {
            self.preparations += 1;
            Ok(spec)
        }

        fn destroy(&mut self, _guest: &mut Self::Guest) -> Result<(), Self::Error> {
            self.destructions += 1;
            if self.fail_first_destruction && self.destructions == 1 {
                return Err(());
            }
            Ok(())
        }
    }

    fn configuration_service_spec(placement: IsolationPlacement) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(0x434f_4e46_4947),
            ObjectId(0x434f_4e46_4947_0001),
            1,
            11,
            SYSTEM_GENERATION,
            5,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    #[test]
    fn configuration_backend_preserves_binding_across_both_placements() {
        let mut native_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut native_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let native = route_isolation_service(
            &mut native_admission,
            &mut native_backend,
            configuration_service_spec(IsolationPlacement::NativeService),
        )
        .unwrap();
        assert_eq!(
            native.endpoint().placement(),
            IsolationPlacement::NativeService
        );
        assert_eq!(native.interface_generation(), 1);
        assert_eq!(native.provider_generation(), 11);
        assert_eq!(native.system_generation(), SYSTEM_GENERATION);
        let (native_probe, microvm_probe) = native_backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (1, 0));

        let mut microvm_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut microvm_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let microvm = route_isolation_service(
            &mut microvm_admission,
            &mut microvm_backend,
            configuration_service_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        assert_eq!(microvm.endpoint().placement(), IsolationPlacement::Microvm);
        assert_eq!(microvm.interface(), native.interface());
        assert_eq!(
            microvm.interface_generation(),
            native.interface_generation()
        );
        assert_eq!(microvm.provider_generation(), native.provider_generation());
        let (native_probe, microvm_probe) = microvm_backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (0, 1));
    }

    #[test]
    fn unavailable_configuration_microvm_never_invokes_native_launcher() {
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe {
                launches: 0,
                unavailable: true,
            },
        );
        assert!(matches!(
            route_isolation_service(
                &mut admission,
                &mut backend,
                configuration_service_spec(IsolationPlacement::Microvm),
            ),
            Err(mrml_kernel::IsolationServiceRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                error: ConfigurationPlacementError::Microvm(()),
            })
        ));
        let (native_probe, microvm_probe) = backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (0, 1));
        assert_eq!(admission.unavailable_domains().count(), 1);
        assert_eq!(admission.total_microvm_report().native_fallback, 0);
    }

    #[test]
    fn prepared_microvm_retains_exact_guest_until_confirmed_teardown() {
        let microvm = PreparedMicrovmConfigurationLauncher::new(PreparedGuestFactoryProbe {
            fail_first_destruction: true,
            ..PreparedGuestFactoryProbe::default()
        });
        let mut backend =
            ConfigurationPlacementBackend::new(NativePlacementProbe::default(), microvm);
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let routed = route_isolation_service(
            &mut admission,
            &mut backend,
            configuration_service_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        let endpoint = match routed.endpoint() {
            ConfigurationServiceEndpoint::Microvm(endpoint) => *endpoint,
            ConfigurationServiceEndpoint::Native(_) => panic!("wrong placement"),
        };
        assert_eq!(endpoint.launch_generation(), 1);
        assert_eq!(endpoint.domain(), ObjectId(0x434f_4e46_4947));
        assert_eq!(endpoint.interface(), routed.interface());
        assert_eq!(endpoint.interface_generation(), 1);
        assert_eq!(endpoint.provider_generation(), 11);
        assert_eq!(endpoint.policy_generation(), 5);
        assert_eq!(
            backend.microvm.active_guest(endpoint),
            Ok(&configuration_service_spec(IsolationPlacement::Microvm))
        );

        let mut wrong = endpoint;
        wrong.launch_generation += 1;
        assert_eq!(
            backend.microvm.active_guest_mut(wrong),
            Err(PreparedMicrovmConfigurationAccessError::WrongEndpoint)
        );
        assert_eq!(
            backend.revoke(&ConfigurationServiceEndpoint::Microvm(wrong)),
            Err(ConfigurationPlacementError::Microvm(
                PreparedMicrovmConfigurationError::WrongEndpoint
            ))
        );
        assert_eq!(backend.microvm.factory().destructions, 0);
        assert_eq!(
            backend.revoke(routed.endpoint()),
            Err(ConfigurationPlacementError::Microvm(
                PreparedMicrovmConfigurationError::Backend(())
            ))
        );
        assert_eq!(backend.microvm.active(), Some(endpoint));
        backend.revoke(routed.endpoint()).unwrap();
        assert_eq!(backend.microvm.active(), None);
        assert_eq!(backend.microvm.factory().destructions, 2);
        assert_eq!(backend.native.launches, 0);

        let replacement = backend
            .microvm
            .launch_microvm(configuration_service_spec(IsolationPlacement::Microvm))
            .unwrap();
        assert_eq!(replacement.launch_generation(), 2);
        assert_ne!(replacement, endpoint);
        assert_eq!(backend.microvm.factory().preparations, 2);
    }

    #[test]
    fn admitted_guest_transfer_rechecks_exact_binding_and_is_one_use() {
        let expected = configuration_service_spec(IsolationPlacement::Microvm);
        let mut factory = AdmittedConfigurationGuestFactory::new(expected, 0x55aa_u64);
        let different = IsolationServiceSpec::new(
            expected.domain(),
            expected.interface(),
            expected.interface_generation(),
            expected.provider_generation() + 1,
            expected.system_generation(),
            expected.policy_generation(),
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::Microvm,
        )
        .unwrap();
        assert_eq!(
            factory.prepare(different),
            Err((
                IsolationUnavailableReason::InterfaceTransport,
                AdmittedConfigurationGuestError::BindingMismatch
            ))
        );
        assert_eq!(factory.prepare(expected), Ok(0x55aa));
        assert_eq!(
            factory.prepare(expected),
            Err((
                IsolationUnavailableReason::VmmResource,
                AdmittedConfigurationGuestError::AlreadyConsumed
            ))
        );
    }

    #[test]
    fn supervised_native_configuration_launch_retries_exact_cleanup_before_revocation() {
        type NativeSubstrate = AccountedPolicyServiceSubstrate<1, 1, 1, 1, 1>;

        let pages = NativeSubstrate::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(42).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let substrate = NativeSubstrate::new(
            1_000,
            1,
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let native = SupervisedNativeConfigurationLauncher::new(
            substrate,
            NativeAddressSpaceEraser {
                fail_first: true,
                ..NativeAddressSpaceEraser::default()
            },
            Priority::NORMAL,
            context,
        );
        let mut backend =
            ConfigurationPlacementBackend::new(native, MicrovmPlacementProbe::default());
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 5)
                .unwrap();
        let routed = route_isolation_service(
            &mut admission,
            &mut backend,
            configuration_service_spec(IsolationPlacement::NativeService),
        )
        .unwrap();
        let endpoint = match routed.endpoint() {
            ConfigurationServiceEndpoint::Native(endpoint) => *endpoint,
            ConfigurationServiceEndpoint::Microvm(_) => panic!("wrong placement"),
        };
        assert_eq!(endpoint.domain(), ObjectId(0x434f_4e46_4947));
        assert_eq!(endpoint.interface(), routed.interface());
        assert!(matches!(
            backend.revoke(routed.endpoint()),
            Err(ConfigurationPlacementError::Native(
                NativeConfigurationLaunchError::Cleanup(ServiceCleanupError::Eraser(()))
            ))
        ));
        assert_eq!(
            backend.native.active(),
            Some(endpoint),
            "uncertain cleanup must retain the endpoint for exact retry"
        );
        backend.revoke(routed.endpoint()).unwrap();
        let (native, _) = backend.into_parts();
        assert_eq!(native.active(), None);
        assert_eq!(native.eraser().attempts, 2);
        assert_eq!(native.eraser().erased, Some((endpoint.task(), context)));
        assert_eq!(
            native.substrate().supervisor().state(endpoint.service()),
            Ok(ServiceState::Exited)
        );
        assert_eq!(
            native
                .substrate()
                .supervisor()
                .pending_cleanup(endpoint.service()),
            Ok(None)
        );
        assert_eq!(
            native.substrate().runtime().context(endpoint.task()),
            Err(TaskRuntimeError::MissingTask)
        );
    }

    #[test]
    fn policy_substrate_uses_one_exact_aggregate_commitment_for_all_components() {
        let pages = TestPolicySubstrate::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(32).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let mut substrate = TestPolicySubstrate::new(
            1_000,
            1,
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(substrate.committed_pages(), pages);
        assert_eq!(memory.object_pool(substrate.charge()), Ok(pool));
        let usage = memory.usage(pool, pool_capability, &authorities).unwrap();
        assert_eq!((usage.committed_pages(), usage.live_objects()), (pages, 1));
        assert_eq!(substrate.configuration().setting_count(), 1);
        let task = substrate
            .runtime_mut()
            .create(
                Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let service = substrate
            .supervisor_mut()
            .register(ObjectId(0x90), task)
            .unwrap();
        assert_eq!(
            substrate.supervisor().state(service),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
    }

    #[test]
    fn policy_substrate_failure_is_atomic_and_empty_release_returns_one_charge() {
        let pages = TestPolicySubstrate::required_pages().unwrap();
        assert!(pages > 1);
        let mut memory = MemoryPoolTable::<1, 1>::new(33).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages - 1, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        assert!(matches!(
            TestPolicySubstrate::new(
                1_000,
                1,
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert!(matches!(
            TestPolicySubstrate::new(
                0,
                1,
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Runtime(_))
        ));
        assert!(matches!(
            TestPolicySubstrate::new(
                1_000,
                1,
                ObjectId(10),
                &[],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Configuration(
                ConfigError::Capacity
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );

        let mut exact_memory = MemoryPoolTable::<1, 1>::new(34).unwrap();
        let mut exact_authorities = CapabilitySpace::<3>::new();
        let (exact_pool, exact_pool_capability) = exact_memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut exact_authorities)
            .unwrap();
        let substrate = TestPolicySubstrate::empty(
            1_000,
            1,
            ObjectId(10),
            exact_pool,
            exact_pool_capability,
            &mut exact_memory,
            &mut exact_authorities,
        )
        .unwrap();
        assert!(matches!(
            unsafe { substrate.release(&mut exact_memory, &mut exact_authorities) },
            Ok(released) if released == pages
        ));
        assert_eq!(
            exact_memory
                .usage(exact_pool, exact_pool_capability, &exact_authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn accounted_configuration_charges_complete_state_until_consuming_release() {
        let pages = AccountedConfigurationService::<3, 2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(26).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let service = AccountedConfigurationService::<3, 2>::new(
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(service.setting_count(), 1);
        assert_eq!(service.committed_pages(), pages);
        assert_eq!(memory.object_pool(service.charge()), Ok(pool));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
        assert!(matches!(
            service.release(&mut memory, &mut authorities),
            Ok(released) if released == pages
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn configuration_validation_and_pool_exhaustion_never_publish_unaccounted_state() {
        let pages = AccountedConfigurationService::<64, 64>::required_pages().unwrap();
        assert!(pages > 1);
        let mut memory = MemoryPoolTable::<1, 1>::new(27).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages - 1, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        assert!(matches!(
            AccountedConfigurationService::<64, 64>::new(
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedConfigurationError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert!(matches!(
            AccountedConfigurationService::<64, 64>::new(
                ObjectId(10),
                &[],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedConfigurationError::Configuration(
                ConfigError::Capacity
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    fn fixture() -> (
        ConfigurationService<3, 2>,
        CapabilitySpace<4>,
        Capability,
        Capability,
        Capability,
    ) {
        let enabled = SettingId::new(1).unwrap();
        let limit = SettingId::new(2).unwrap();
        let schemas = [
            SettingSchema::boolean(enabled, ObjectId(11)).unwrap(),
            SettingSchema::unsigned(limit, ObjectId(12), 1, 100).unwrap(),
        ];
        let service = ConfigurationService::new(ObjectId(10), &schemas).unwrap();
        let mut capabilities = CapabilitySpace::new();
        let root = capabilities
            .insert(ObjectId(10), Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let enabled_capability = capabilities
            .insert(ObjectId(11), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let limit_capability = capabilities
            .insert(ObjectId(12), Rights::READ.union(Rights::WRITE))
            .unwrap();
        (
            service,
            capabilities,
            root,
            enabled_capability,
            limit_capability,
        )
    }

    #[test]
    fn atomic_commit_requires_root_and_each_exact_setting_capability() {
        let (mut service, capabilities, root, enabled, limit) = fixture();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        assert_eq!(service.commit(&capabilities, root, &transaction), Ok(1));
        assert_eq!(
            service
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );
        assert_eq!(
            service
                .read(&capabilities, limit, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
    }

    #[test]
    fn late_schema_or_authority_failure_rolls_back_every_update() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                enabled,
                ConfigValue::unsigned(101),
            ))
            .unwrap();
        assert_eq!(
            service.commit(&capabilities, root, &transaction),
            Err(ConfigError::WrongObject)
        );
        assert_eq!(service.revision(), 0);
        assert_eq!(
            service
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value,
            None
        );
    }

    #[test]
    fn stale_revision_duplicate_setting_and_stale_capability_fail_closed() {
        let (mut service, mut capabilities, root, enabled, _) = fixture();
        let stale = enabled;
        capabilities.revoke(enabled).unwrap();
        let replacement = capabilities
            .insert(ObjectId(11), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let mut stale_transaction = ConfigTransaction::<1>::new(0);
        stale_transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                stale,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        assert!(matches!(
            service.commit(&capabilities, root, &stale_transaction),
            Err(ConfigError::Unauthorized(CapabilityError::Invalid))
        ));
        let mut duplicate = ConfigTransaction::<2>::new(0);
        for value in [true, false] {
            duplicate
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    replacement,
                    ConfigValue::boolean(value),
                ))
                .unwrap();
        }
        assert_eq!(
            service.commit(&capabilities, root, &duplicate),
            Err(ConfigError::DuplicateSetting)
        );
        assert_eq!(service.revision(), 0);
    }

    #[test]
    fn bounded_audit_reports_overwrite_gap_with_monotonic_sequence() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        for revision in 0..3 {
            let mut transaction = ConfigTransaction::<1>::new(revision);
            transaction
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    enabled,
                    ConfigValue::boolean(revision % 2 == 0),
                ))
                .unwrap();
            service.commit(&capabilities, root, &transaction).unwrap();
        }
        assert_eq!(
            service.audit_event(&capabilities, root, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            service.audit_event(&capabilities, root, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 3,
                setting: SettingId::new(1).unwrap(),
            })
        );
    }

    #[test]
    fn configuration_wire_is_canonical_bounded_and_pointer_free() {
        let (_, _, root, enabled, limit) = fixture();
        let mut read_wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_request(8, SettingId::new(1).unwrap(), enabled, &mut read_wire).unwrap();
        assert_eq!(
            ConfigurationRequest::decode(&read_wire),
            Ok(ConfigurationRequest::Read {
                request_id: 8,
                setting: SettingId::new(1).unwrap(),
                capability: enabled,
            })
        );
        let mut transaction = ConfigTransaction::<2>::new(7);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(9),
            ))
            .unwrap();
        let mut wire = [0xa5; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_request(9, root, &transaction, &mut wire).unwrap();
        let decoded = ConfigurationRequest::decode(&wire[..length]).unwrap();
        let ConfigurationRequest::Commit {
            request_id,
            root: decoded_root,
            transaction: decoded_transaction,
        } = decoded
        else {
            panic!("expected commit");
        };
        assert_eq!(request_id, 9);
        assert_eq!(decoded_root, root);
        assert_eq!(decoded_transaction.len(), 2);
        let mut malformed = wire;
        malformed[11] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&malformed[..length]),
            Err(ConfigError::NonCanonical)
        );
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length - 1]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn kernel_message_authorities_replace_payload_tokens_and_dispatch_atomically() {
        let schemas = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap(),
            SettingSchema::unsigned(SettingId::new(2).unwrap(), ObjectId(12), 1, 100).unwrap(),
        ];
        let mut service = ConfigurationService::<2, 2>::new(ObjectId(10), &schemas).unwrap();
        let context = |root, entry| {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        };
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(99);
        let sender_space = runtime.capabilities_mut(sender).unwrap();
        let endpoint_capability = sender_space
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = sender_space
            .insert(ObjectId(10), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let enabled = sender_space
            .insert(ObjectId(11), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let limit = sender_space
            .insert(ObjectId(12), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(17),
            ))
            .unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_message_request(21, &transaction, &mut wire).unwrap();
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        assert!(wire[56..64].iter().all(|byte| *byte == 0));
        assert!(wire[136..144].iter().all(|byte| *byte == 0));
        let mut endpoint = mrml_kernel::Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                &wire[..length],
                &[
                    (root, Rights::CONTROL),
                    (enabled, Rights::WRITE),
                    (limit, Rights::WRITE),
                ],
            )
            .unwrap();
        let mut delivered_authorities = message.capabilities();
        let delivered = [
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
        ];
        assert!(delivered_authorities.next().is_none());
        assert_ne!(delivered[0], root);
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(
            &mut service,
            runtime.capabilities_mut(receiver).unwrap(),
            &message,
            &mut response_wire,
        )
        .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire)
                .unwrap()
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(service.revision(), 1);

        let extra = Message::new(
            &wire[..length],
            &[delivered[0], delivered[1], delivered[2], delivered[0]],
        )
        .unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&extra),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32] = 1;
        let forged = Message::new(&forged[..length], &delivered).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn message_dispatch_represents_an_authorized_unset_value() {
        let (mut service, capabilities, _, enabled, _) = fixture();
        let mut wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_message_request(22, SettingId::new(1).unwrap(), &mut wire).unwrap();
        let message = Message::new(&wire, &[enabled]).unwrap();
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response_wire)
            .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire),
            Ok(ConfigurationResponse {
                request_id: 22,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(SettingId::new(1).unwrap()),
                value: None,
            })
        );
    }

    #[test]
    fn supervision_wire_binds_generation_authority_time_and_version() {
        let (_, _, root, _, _) = fixture();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 4,
            service: ServiceId::from_token((3u64 << 32) | 2),
            capability: root,
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        assert_eq!(SupervisionRequest::decode(&wire), Ok(request));
        wire[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::UnsupportedVersion)
        );
        wire[4..6].copy_from_slice(&SYSTEM_PROTOCOL_VERSION.to_le_bytes());
        wire[12] = 1;
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::NonCanonical)
        );
        wire[12] = 0;
        wire[40..48].copy_from_slice(&99u64.to_le_bytes());
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let response = SupervisionResponse {
            request_id: 4,
            status: ResponseStatus::Ok,
            service: request.service,
            state: SupervisionState::Faulted,
            detail: 123,
        };
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        response.encode(&mut response_wire).unwrap();
        assert_eq!(SupervisionResponse::decode(&response_wire), Ok(response));
        response_wire[47] = 1;
        assert_eq!(
            SupervisionResponse::decode(&response_wire),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn supervision_message_uses_derived_control_and_trusted_restart_context() {
        struct Eraser;
        impl mrml_kernel::ServiceAddressSpaceEraser for Eraser {
            type Error = ();

            fn erase(&mut self, _: mrml_kernel::TaskId, _: UserContext) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        fn context(root: u64, entry: u64) -> UserContext {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        }

        let object = ObjectId(70);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let retired_service = supervisor.register(object, task).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 31,
            service: retired_service,
            capability: control,
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut request_wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode_message(&mut request_wire).unwrap();
        assert!(request_wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&request_wire, &[control]).unwrap();
        let fresh = context(0x30_0000, 0x50_0000);
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_message(
            &mut supervisor,
            &management,
            &mut runtime,
            &message,
            Priority::RESPONSIVE,
            fresh,
            0,
            &mut response_wire,
        )
        .unwrap();
        let response = SupervisionResponse::decode(&response_wire).unwrap();
        assert_eq!(response.status, ResponseStatus::Ok);
        assert_eq!(response.state, SupervisionState::Running);
        assert_ne!(response.service, retired_service);
        assert_eq!(
            supervisor.state(response.service),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            runtime.context(supervisor.task(response.service).unwrap().unwrap()),
            Ok(&fresh)
        );

        let forged = Message::new(&request_wire, &[]).unwrap();
        assert_eq!(
            SupervisionRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn supervision_query_envelope_uses_only_delivered_read_authority() {
        struct QueryAuthorizer {
            capability: Capability,
            service: ServiceId,
        }

        impl ServiceStateAuthorizer for QueryAuthorizer {
            fn query_state(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                if capability == self.capability && service == self.service {
                    Ok(ServiceState::Running)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((8u64 << 32) | 3);
        let service = ServiceId::from_token((4u64 << 32) | 2);
        let authorizer = QueryAuthorizer {
            capability,
            service,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 52,
            service,
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_query_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 52,
                status: ResponseStatus::Ok,
                service,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_query_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &forged, &[capability], &mut response,),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let wrong = Capability::from_token((9u64 << 32) | 3);
        dispatch_supervision_query_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        let rejected = SupervisionResponse::decode(&response).unwrap();
        assert_eq!(rejected.status, ResponseStatus::Rejected);
        assert_eq!(rejected.state, SupervisionState::Exited);
        assert_eq!(rejected.detail, 0);
    }

    #[test]
    fn userspace_supervision_dispatch_refuses_restart_requests() {
        struct RejectAll;
        impl ServiceStateAuthorizer for RejectAll {
            fn query_state(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                panic!("restart must be rejected before querying the kernel")
            }
        }

        let capability = Capability::from_token((2u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 53,
            service: ServiceId::from_token((3u64 << 32) | 1),
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_query_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn supervision_restart_envelope_uses_only_delivered_control_authority() {
        struct RestartAuthorizer {
            capability: Capability,
            retired: ServiceId,
            replacement: ServiceId,
        }

        impl ServiceRestartAuthorizer for RestartAuthorizer {
            fn restart_service(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                if capability == self.capability && service == self.retired {
                    Ok(self.replacement)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((11u64 << 32) | 2);
        let retired = ServiceId::from_token((7u64 << 32) | 1);
        let replacement = ServiceId::from_token((7u64 << 32) | 2);
        let authorizer = RestartAuthorizer {
            capability,
            retired,
            replacement,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 54,
            service: retired,
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Ok,
                service: replacement,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_restart_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &forged,
                &[capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );

        let wrong = Capability::from_token((12u64 << 32) | 2);
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Rejected,
                service: retired,
                state: SupervisionState::Exited,
                detail: 0,
            })
        );
    }

    #[test]
    fn restart_dispatch_refuses_query_before_calling_the_authorizer() {
        struct RejectAll;
        impl ServiceRestartAuthorizer for RejectAll {
            fn restart_service(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                panic!("query must be rejected before requesting a restart")
            }
        }

        let capability = Capability::from_token((13u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 55,
            service: ServiceId::from_token((8u64 << 32) | 1),
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_restart_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn configuration_responses_round_trip_and_reject_hidden_tail_data() {
        let response = ConfigurationResponse {
            request_id: 7,
            status: ResponseStatus::Ok,
            revision: 3,
            setting: Some(SettingId::new(2).unwrap()),
            value: Some(ConfigValue::unsigned(44)),
        };
        let mut wire = [0; CONFIG_RESPONSE_BYTES];
        response.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(response));
        wire[111] = 1;
        assert_eq!(
            ConfigurationResponse::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let rejected = ConfigurationResponse {
            request_id: 8,
            status: ResponseStatus::Rejected,
            revision: 3,
            setting: None,
            value: None,
        };
        rejected.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(rejected));
    }

    #[test]
    fn schema_and_identifiers_reject_ambiguous_inputs() {
        assert_eq!(SettingId::new(0), Err(ConfigError::InvalidSetting));
        assert!(SettingSchema::unsigned(SettingId::new(1).unwrap(), ObjectId(1), 2, 1).is_err());
        let duplicate = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(1)).unwrap(),
            SettingSchema::bytes(SettingId::new(1).unwrap(), ObjectId(2), 8).unwrap(),
        ];
        assert!(matches!(
            ConfigurationService::<2, 1>::new(ObjectId(9), &duplicate),
            Err(ConfigError::DuplicateSetting)
        ));
        let aliases_root =
            [SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(9)).unwrap()];
        assert!(matches!(
            ConfigurationService::<1, 1>::new(ObjectId(9), &aliases_root),
            Err(ConfigError::DuplicateObject)
        ));
    }

    #[test]
    fn schema_admission_uses_only_root_authority_from_the_message_envelope() {
        let root_object = ObjectId(10);
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let mut service = ConfigurationService::<2, 2>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_schema_message_request(41, schema, &mut wire).unwrap();
        assert_eq!(length, CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES);
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&wire[..length], &[root]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&message),
            Ok(ConfigurationRequest::AdmitSchema {
                request_id: 41,
                root,
                schema,
            })
        );
        let mut response = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response)
            .unwrap();
        assert_eq!(service.setting_count(), 1);
        assert_eq!(
            ConfigurationResponse::decode(&response).unwrap(),
            ConfigurationResponse {
                request_id: 41,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(schema.setting()),
                value: None,
            }
        );

        let missing = Message::new(&wire[..length], &[]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&missing),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        wire[CONFIG_REQUEST_HEADER_BYTES + 10] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn schema_admission_rejects_aliases_capacity_and_post_commit_mutation() {
        let root_object = ObjectId(20);
        let setting = SettingId::new(1).unwrap();
        let schema = SettingSchema::boolean(setting, ObjectId(21)).unwrap();
        let mut service = ConfigurationService::<1, 1>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let write = capabilities.insert(ObjectId(21), Rights::WRITE).unwrap();
        service.admit_schema(&capabilities, root, schema).unwrap();
        assert_eq!(
            service.admit_schema(&capabilities, root, schema),
            Err(ConfigError::DuplicateObject)
        );
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                write,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &transaction).unwrap();
        assert_eq!(
            service.admit_schema(
                &capabilities,
                root,
                SettingSchema::boolean(SettingId::new(2).unwrap(), ObjectId(22)).unwrap(),
            ),
            Err(ConfigError::SchemaFrozen)
        );
    }

    #[test]
    fn checkpoint_round_trip_preserves_schema_values_revisions_and_audit_window() {
        let (mut service, capabilities, root, enabled, limit) = fixture();
        let mut first = ConfigTransaction::<2>::new(0);
        first
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        first
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        service.commit(&capabilities, root, &first).unwrap();
        let mut second = ConfigTransaction::<1>::new(1);
        second
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(false),
            ))
            .unwrap();
        service.commit(&capabilities, root, &second).unwrap();

        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut bytes)
            .unwrap();
        assert_eq!(checkpoint.length, 368);
        let recovered = ConfigurationService::<3, 2>::recover_checkpoint(
            &capabilities,
            root,
            &bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 2);
        assert_eq!(recovered.setting_count(), 2);
        assert_eq!(
            recovered
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(false)
        );
        assert_eq!(
            recovered
                .read(&capabilities, limit, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 2).unwrap(),
            Some(AuditEvent {
                sequence: 2,
                revision: 1,
                setting: SettingId::new(2).unwrap(),
            })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 2,
                setting: SettingId::new(1).unwrap(),
            })
        );

        let pages = AccountedConfigurationService::<3, 2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(28).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let recovered = AccountedConfigurationService::<3, 2>::recover_checkpoint(
            &capabilities,
            root,
            &bytes[..checkpoint.length],
            checkpoint.digest,
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!((recovered.revision(), recovered.setting_count()), (2, 2));
        assert_eq!(recovered.committed_pages(), pages);
        assert!(matches!(
            recovered.release(&mut memory, &mut authorities),
            Ok(released) if released == pages
        ));
    }

    #[test]
    fn checkpoint_recovery_rejects_corruption_stale_digest_capacity_and_hidden_data() {
        let (service, capabilities, root, enabled, _) = fixture();
        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut bytes)
            .unwrap();
        let input = &mut bytes[..checkpoint.length];
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(
                &capabilities,
                root,
                input,
                checkpoint.digest,
            ),
            Err(ConfigError::InvalidCheckpoint)
        ));

        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 1;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::InvalidCheckpoint)
        ));
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 0;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<1, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::Capacity)
        ));
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, enabled, input, digest,),
            Err(ConfigError::Unauthorized(_))
        ));
    }

    const STABLE_BLOCK_BYTES: usize = 4096;
    const STABLE_BLOCK_COUNT: usize = 16;

    fn stable_volume() -> VolumeId {
        VolumeId::new([0x51; 16]).unwrap()
    }

    #[test]
    fn selected_configuration_root_requires_exact_authenticated_provenance() {
        let selected = stable_volume();
        let other = VolumeId::new([0x52; 16]).unwrap();
        assert!(recovery_root_matches(Some(selected), 9, selected, 9));
        assert!(!recovery_root_matches(Some(selected), 9, other, 9));
        assert!(!recovery_root_matches(Some(selected), 9, selected, 8));
        assert!(recovery_root_matches(None, 0, other, 8));
    }

    fn stable_header() -> VolumeHeader {
        VolumeHeader::new(stable_volume(), STABLE_BLOCK_BYTES as u32, 100, 1, 2).unwrap()
    }

    fn stable_object(local: u64) -> StorageObjectId {
        StorageObjectId::new(stable_volume(), local).unwrap()
    }

    fn stable_principal() -> StoragePrincipal {
        StoragePrincipal::new(7).unwrap()
    }

    fn stable_digest(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(bytes);
        digest.finalize()
    }

    struct StableBackend {
        bytes: [u8; STABLE_BLOCK_BYTES],
        staged: usize,
        flushed: usize,
        reads: usize,
        fail_read: bool,
        corrupt_read: bool,
    }

    unsafe impl FileWriteBackend for StableBackend {
        type Error = u8;

        fn stage_new_extent(
            &mut self,
            file: StorageObjectId,
            old_generation: u64,
            old_length: u64,
            next: ExtentRecord,
            new_length: u64,
            patch_offset: u64,
            patch: &[u8],
        ) -> Result<(), Self::Error> {
            if file != stable_object(9)
                || old_generation != 1
                || old_length != 0
                || next.file() != file
                || next.metadata_generation() != 2
                || next.physical_block() != Some(10)
                || next.block_count() != 1
                || patch_offset != 0
                || usize::try_from(new_length).ok() != Some(patch.len())
            {
                return Err(1);
            }
            self.bytes.fill(0);
            self.bytes[..patch.len()].copy_from_slice(patch);
            if next.content_digest() != stable_digest(&self.bytes) {
                return Err(2);
            }
            self.staged += 1;
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            let length = usize::try_from(length).map_err(|_| 3)?;
            if file != stable_object(9)
                || generation != 2
                || length > self.bytes.len()
                || content_digest != stable_digest(&self.bytes[..length])
            {
                return Err(3);
            }
            self.flushed += 1;
            Ok(())
        }
    }

    unsafe impl FileReadBackend for StableBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads += 1;
            if self.fail_read {
                return Err(4);
            }
            if record.file() != stable_object(9)
                || record.metadata_generation() != 2
                || record.content_digest() != stable_digest(&self.bytes)
            {
                return Err(5);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 5)?;
            let end = start.checked_add(output.len()).ok_or(5)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(5)?);
            if self.corrupt_read && !output.is_empty() {
                output[0] ^= 1;
            }
            Ok(())
        }
    }

    struct CheckpointReadBackend {
        object: StorageObjectId,
        bytes: [u8; STABLE_BLOCK_BYTES],
    }

    unsafe impl FileReadBackend for CheckpointReadBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if record.file() != self.object
                || record.metadata_generation() != 2
                || record.content_digest() != stable_digest(&self.bytes)
            {
                return Err(1);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 2)?;
            let end = start.checked_add(output.len()).ok_or(2)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(2)?);
            Ok(())
        }
    }

    struct RecoveryStateStore {
        bytes: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    }

    impl RecoveryStateStore {
        fn new(epoch: u64, generation: u32) -> Self {
            let mut bytes = [0; AUTHORITY_RECOVERY_STATE_BYTES];
            bytes[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
            bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
            bytes[24..28].copy_from_slice(&generation.to_le_bytes());
            Self { bytes }
        }
    }

    impl AuthorityRecoveryStateStore for RecoveryStateStore {
        type Error = u8;

        fn load_authenticated(
            &self,
            output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            output.copy_from_slice(&self.bytes);
            Ok(())
        }

        fn compare_and_store(
            &mut self,
            expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
            replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            if self.bytes != *expected {
                return Err(2);
            }
            self.bytes.copy_from_slice(replacement);
            Ok(())
        }
    }

    fn checkpoint_file(
        object: StorageObjectId,
        length: usize,
        bytes: &[u8; STABLE_BLOCK_BYTES],
    ) -> FileState<1> {
        let extent = ExtentRecord::data(object, 2, 0, 1, 11, stable_digest(bytes)).unwrap();
        let extents = ExtentMap::build(
            stable_header(),
            object,
            2,
            u64::try_from(length).unwrap(),
            &[extent],
        )
        .unwrap();
        FileState::new(object, 2, u64::try_from(length).unwrap(), extents).unwrap()
    }

    struct PublicationBackend;

    unsafe impl CowPublicationBackend for PublicationBackend {
        type Error = ();

        fn verify_new_metadata(&mut self, _: CowMetadataWrite) -> Result<(), Self::Error> {
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            (block == 2).then_some(()).ok_or(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StableBlockError {
        WrongDevice,
        Range,
    }

    struct StableBlockBackend {
        bytes: [u8; STABLE_BLOCK_BYTES * STABLE_BLOCK_COUNT],
        device: BlockDeviceId,
        reads: usize,
        writes: usize,
        flushes: usize,
        replacements: usize,
    }

    impl StableBlockBackend {
        fn new(device: BlockDeviceId) -> Self {
            Self {
                bytes: [0; STABLE_BLOCK_BYTES * STABLE_BLOCK_COUNT],
                device,
                reads: 0,
                writes: 0,
                flushes: 0,
                replacements: 0,
            }
        }

        fn range(
            &self,
            device: BlockDeviceId,
            block: u64,
            length: usize,
        ) -> Result<core::ops::Range<usize>, StableBlockError> {
            if device != self.device {
                return Err(StableBlockError::WrongDevice);
            }
            let start = usize::try_from(block)
                .ok()
                .and_then(|value| value.checked_mul(STABLE_BLOCK_BYTES))
                .ok_or(StableBlockError::Range)?;
            let end = start.checked_add(length).ok_or(StableBlockError::Range)?;
            (end <= self.bytes.len())
                .then_some(start..end)
                .ok_or(StableBlockError::Range)
        }

        fn install_block(&mut self, block: u64, bytes: &[u8; STABLE_BLOCK_BYTES]) {
            let range = self.range(self.device, block, bytes.len()).unwrap();
            self.bytes[range].copy_from_slice(bytes);
        }
    }

    unsafe impl BlockServiceBackend for StableBlockBackend {
        type Error = StableBlockError;

        fn read_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            self.reads += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, input.len())?;
            self.bytes[range].copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self, device: BlockDeviceId) -> Result<(), Self::Error> {
            if device != self.device {
                return Err(StableBlockError::WrongDevice);
            }
            self.flushes += 1;
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            encoded: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, STABLE_BLOCK_BYTES)?;
            self.bytes[range.clone()].fill(0);
            self.bytes[range.start..range.start + encoded.len()].copy_from_slice(encoded);
            self.replacements += 1;
            Ok(())
        }
    }

    fn stable_layout(
        checkpoint: &[u8],
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        [CowMetadataImage; 2],
    ) {
        let header = stable_header();
        let object = stable_object(9);
        let current_extents = ExtentMap::<0>::build(header, object, 1, 0, &[]).unwrap();
        let current = FileState::new(object, 1, 0, current_extents).unwrap();
        let mut block = [0; STABLE_BLOCK_BYTES];
        block[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object, 2, 0, 1, 10, stable_digest(&block)).unwrap();
        let next = ExtentMap::build(header, object, 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object,
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            stable_digest(checkpoint),
        )
        .unwrap();
        let mut encoded_metadata = [0; STABLE_BLOCK_BYTES];
        metadata.encode(
            (&mut encoded_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut encoded_extents = [0; STABLE_BLOCK_BYTES];
        record.encode(
            (&mut encoded_extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        (
            current,
            next,
            metadata,
            [
                CowMetadataImage::new(
                    MetadataPointer::new(21, 1).unwrap(),
                    stable_digest(&encoded_metadata),
                ),
                CowMetadataImage::new(
                    MetadataPointer::new(20, 1).unwrap(),
                    stable_digest(&encoded_extents),
                ),
            ],
        )
    }

    fn publication_plan(images: [CowMetadataImage; 2]) -> CowPublicationPlan<4> {
        let header = stable_header();
        let root = stable_object(1);
        let active = Superblock::new(
            header,
            1,
            0,
            root,
            MetadataPointer::new(30, 1).unwrap(),
            MetadataPointer::new(31, 1).unwrap(),
        )
        .unwrap();
        let root_write =
            CowMetadataWrite::new(MetadataPointer::new(40, 1).unwrap(), 2, [0x40; 32]).unwrap();
        let allocation_write =
            CowMetadataWrite::new(MetadataPointer::new(41, 1).unwrap(), 2, [0x41; 32]).unwrap();
        CowPublicationPlan::build(
            header,
            1,
            active,
            root,
            root_write.pointer(),
            allocation_write.pointer(),
            &[
                images[0].bind(2).unwrap(),
                images[1].bind(2).unwrap(),
                root_write,
                allocation_write,
            ],
            &[
                MetadataPointer::new(30, 1).unwrap(),
                MetadataPointer::new(31, 1).unwrap(),
            ],
        )
        .unwrap()
    }

    fn block_stable_layout(
        checkpoint: &[u8],
        backend: &mut StableBlockBackend,
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        CowPublicationPlan<4>,
    ) {
        let header = stable_header();
        let object = stable_object(9);
        let current = FileState::new(
            object,
            1,
            0,
            ExtentMap::<0>::build(header, object, 1, 0, &[]).unwrap(),
        )
        .unwrap();
        let mut data = [0; STABLE_BLOCK_BYTES];
        data[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object, 2, 0, 1, 3, stable_digest(&data)).unwrap();
        let next = ExtentMap::build(header, object, 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object,
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(4, 1).unwrap(),
            stable_digest(checkpoint),
        )
        .unwrap();

        let mut extents = [0; STABLE_BLOCK_BYTES];
        record.encode(
            (&mut extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut file_metadata = [0; STABLE_BLOCK_BYTES];
        metadata.encode(
            (&mut file_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let root = [0x61; STABLE_BLOCK_BYTES];
        let allocation = [0x71; STABLE_BLOCK_BYTES];
        backend.install_block(4, &extents);
        backend.install_block(5, &file_metadata);
        backend.install_block(6, &root);
        backend.install_block(7, &allocation);

        let active = Superblock::new(
            header,
            1,
            0,
            stable_object(1),
            MetadataPointer::new(8, 1).unwrap(),
            MetadataPointer::new(9, 1).unwrap(),
        )
        .unwrap();
        let plan = CowPublicationPlan::build(
            header,
            1,
            active,
            stable_object(1),
            MetadataPointer::new(6, 1).unwrap(),
            MetadataPointer::new(7, 1).unwrap(),
            &[
                CowMetadataWrite::new(
                    MetadataPointer::new(5, 1).unwrap(),
                    2,
                    stable_digest(&file_metadata),
                )
                .unwrap(),
                CowMetadataWrite::new(
                    MetadataPointer::new(4, 1).unwrap(),
                    2,
                    stable_digest(&extents),
                )
                .unwrap(),
                CowMetadataWrite::new(MetadataPointer::new(6, 1).unwrap(), 2, stable_digest(&root))
                    .unwrap(),
                CowMetadataWrite::new(
                    MetadataPointer::new(7, 1).unwrap(),
                    2,
                    stable_digest(&allocation),
                )
                .unwrap(),
            ],
            &[
                MetadataPointer::new(8, 1).unwrap(),
                MetadataPointer::new(9, 1).unwrap(),
            ],
        )
        .unwrap();
        (current, next, metadata, plan)
    }

    #[test]
    fn stable_checkpoint_requires_both_capabilities_and_one_use_publication_receipt() {
        let (mut service, capabilities, root, enabled, _) = fixture();
        let mut update = ConfigTransaction::<1>::new(0);
        update
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &update).unwrap();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut expected)
            .unwrap();
        let (current, next, metadata, images) = stable_layout(&expected[..checkpoint.length]);
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        let prepared = prepare_stable_configuration(
            &service,
            &capabilities,
            root,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        assert_eq!(prepared.checkpoint(), checkpoint);
        assert_eq!(prepared.revision(), 1);
        assert_eq!((backend.staged, backend.flushed), (1, 1));

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(70).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&mut receipt).unwrap();
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(stable.file().generation(), 2);
        assert_eq!(stable.checkpoint(), checkpoint);

        let mut recovered_bytes = [0xa5; 512];
        let recovered = recover_stable_configuration::<3, 2, _, _, _, _>(
            stable.file(),
            &authority,
            file,
            stable_principal(),
            stable.file().generation(),
            &capabilities,
            root,
            &mut recovered_bytes,
            &mut backend,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 1);
        assert_eq!(
            recovered
                .read(&capabilities, enabled, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );

        let grants = [StorageRecoveryGrant::root(
            stable_principal(),
            stable_object(9),
            StorageObjectKind::File,
            StorageRights::READ,
        )];
        let mut authority_bytes = [0; 128];
        let authority_length =
            encode_authority_checkpoint(9, stable_volume(), 14, 2, &grants, &mut authority_bytes)
                .unwrap();
        let authority_digest =
            authority_checkpoint_digest(&authority_bytes[..authority_length]).unwrap();
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(9, stable_volume(), 14, 2, authority_digest)
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let proof = issuer
            .issue::<1>(&authority_bytes[..authority_length])
            .unwrap();
        let authenticated = unsafe { AuthenticatedAuthorityRecoveryState::new(8, 1) };
        let mut guard = AuthorityRecoveryGuard::from_authenticated_state(authenticated);
        let recovered_authority = guard
            .recover::<1>(&authority_bytes[..authority_length], proof)
            .unwrap();
        let mut dependent_bytes = [0xa5; 512];
        let mut validator = StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new(
            stable.file(),
            0,
            stable_principal(),
            2,
            &capabilities,
            root,
            enabled,
            SettingId::new(1).unwrap(),
            ObjectId(99),
            &mut dependent_bytes,
            &mut backend,
        );
        assert_eq!(
            validator.validate(&recovered_authority).map(|_| ()),
            Err(StableConfigurationRecoveryError::Policy(
                PersistedRestartPolicyError::InvalidRecord
            ))
        );
        assert!(dependent_bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn stable_policy_and_boot_isolation_round_trip_use_committed_recovery() {
        let root_object = ObjectId(79);
        let setting_object = ObjectId(80);
        let service_object = ObjectId(81);
        let setting = SettingId::new(1).unwrap();
        let restart_schema = SettingSchema::bytes(
            setting,
            setting_object,
            PERSISTED_RESTART_POLICY_BYTES as u8,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(2).unwrap(), ObjectId(83)).unwrap();
        let component = IsolationPolicySetting::component(
            SettingId::new(3).unwrap(),
            ObjectId(84),
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let mut configuration = ConfigurationService::<3, 2>::new(
            root_object,
            &[
                restart_schema,
                system.schema().unwrap(),
                component.schema().unwrap(),
            ],
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<4>::new();
        let root = capabilities
            .insert(root_object, Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let setting_access = capabilities
            .insert(setting_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let system_access = capabilities
            .insert(system.object(), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let component_access = capabilities
            .insert(component.object(), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let policy = PersistedRestartPolicy::new(service_object, 3, 5, 20).unwrap();
        let mut encoded_policy = [0; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded_policy);
        let mut update = ConfigTransaction::<3>::new(0);
        update
            .push(ConfigUpdate::new(
                setting,
                setting_access,
                ConfigValue::bytes(&encoded_policy).unwrap(),
            ))
            .unwrap();
        system
            .stage(
                &mut update,
                system_access,
                OwnerIsolationSelection::Balanced,
            )
            .unwrap();
        component
            .stage(
                &mut update,
                component_access,
                OwnerIsolationSelection::Native,
            )
            .unwrap();
        configuration.commit(&capabilities, root, &update).unwrap();
        let mut checkpoint_bytes = [0; 512];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root, &mut checkpoint_bytes)
            .unwrap();

        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            STABLE_BLOCK_COUNT as u64,
        )
        .unwrap();
        let mut block_service = BlockService::<1, 2>::new();
        block_service.register_device(descriptor).unwrap();
        let block_session = block_service
            .grant(device, stable_principal(), BlockRights::ALL)
            .unwrap();
        let read_only_session = block_service
            .derive(
                block_session,
                stable_principal(),
                StoragePrincipal::new(8).unwrap(),
                BlockRights::READ,
            )
            .unwrap();
        let mut backend = StableBlockBackend::new(device);
        let (current, next, metadata, plan) =
            block_stable_layout(&checkpoint_bytes[..checkpoint.length], &mut backend);
        let (_, denied_next, denied_metadata, _) =
            block_stable_layout(&checkpoint_bytes[..checkpoint.length], &mut backend);
        let mut storage_authority = StorageAuthorityTable::<1>::new();
        let file = storage_authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();

        {
            let mut denied_volume_scratch = [0; STABLE_BLOCK_BYTES];
            let denied_serviced = ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                read_only_session,
                StoragePrincipal::new(8).unwrap(),
            )
            .unwrap();
            let mut denied_volume = BlockVolume::new(
                stable_header(),
                1,
                denied_serviced,
                &mut denied_volume_scratch,
            )
            .unwrap();
            let mut denied_file_scratch = [0; STABLE_BLOCK_BYTES];
            let mut denied_export = [0; 512];
            assert!(
                prepare_block_stable_configuration(
                    &configuration,
                    &capabilities,
                    root,
                    &current,
                    &storage_authority,
                    file,
                    stable_principal(),
                    denied_next,
                    denied_metadata,
                    MetadataPointer::new(5, 1).unwrap(),
                    &[],
                    &mut denied_export,
                    &mut denied_volume,
                    &mut denied_file_scratch,
                )
                .is_err()
            );
        }
        assert_eq!(backend.writes, 0);

        {
            let mut volume_scratch = [0; STABLE_BLOCK_BYTES];
            let serviced = ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                block_session,
                stable_principal(),
            )
            .unwrap();
            let mut volume =
                BlockVolume::new(stable_header(), 1, serviced, &mut volume_scratch).unwrap();
            let mut export = [0; 512];
            let mut file_scratch = [0; STABLE_BLOCK_BYTES];
            let prepared = prepare_block_stable_configuration(
                &configuration,
                &capabilities,
                root,
                &current,
                &storage_authority,
                file,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(5, 1).unwrap(),
                &[],
                &mut export,
                &mut volume,
                &mut file_scratch,
            )
            .unwrap();
            let mut transaction =
                StorageTransaction::<1, 2>::new(StorageTransactionId::new(72).unwrap(), 2).unwrap();
            prepared.admit(&mut transaction).unwrap();
            let mut receipt = transaction.publish(&plan, &mut volume).unwrap();
            let stable = prepared.commit(&mut receipt).unwrap();
            assert_eq!(receipt.remaining(), 0);

            let grants = [StorageRecoveryGrant::root(
                stable_principal(),
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ,
            )];
            let mut authority_bytes = [0; 128];
            let authority_length = encode_authority_checkpoint(
                9,
                stable_volume(),
                14,
                2,
                &grants,
                &mut authority_bytes,
            )
            .unwrap();
            let authority_digest =
                authority_checkpoint_digest(&authority_bytes[..authority_length]).unwrap();
            let admission = unsafe {
                OwnerApprovedAuthorityCheckpoint::new(9, stable_volume(), 14, 2, authority_digest)
            };
            let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
            let authority_object = stable_object(10);
            let mut authority_backend = CheckpointReadBackend {
                object: authority_object,
                bytes: [0; STABLE_BLOCK_BYTES],
            };
            authority_backend.bytes[..authority_length]
                .copy_from_slice(&authority_bytes[..authority_length]);
            let authority_file =
                checkpoint_file(authority_object, authority_length, &authority_backend.bytes);
            let mut bootstrap = StorageAuthorityTable::<1>::new();
            let bootstrap_file = bootstrap
                .insert(
                    authority_object,
                    StorageObjectKind::File,
                    StorageRights::READ,
                    stable_principal(),
                )
                .unwrap();
            let mut state_store = RecoveryStateStore::new(8, 1);
            let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
            let task = runtime
                .create(
                    Priority::NORMAL,
                    UserContext::new(
                        mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                        0x40_0000,
                        0x7000_0000,
                    )
                    .unwrap(),
                )
                .unwrap();
            let recovery_object = ObjectId(0xb0);
            let recovery_capability = runtime
                .capabilities_mut(task)
                .unwrap()
                .insert(recovery_object, Rights::READ)
                .unwrap();
            let recovery_metadata = mrml_kernel::RecoveryStateMetadata::new(8, 1, None, 0).unwrap();
            let mut delivery =
                mrml_kernel::BootRecoveryDelivery::new(task, recovery_object, recovery_metadata)
                    .unwrap();
            let mut delivered = [0xa5; mrml_kernel::HANDOFF_RECOVERY_STATE_BYTES];
            delivery
                .deliver(&mut runtime, task, recovery_capability, &mut delivered)
                .unwrap();
            let delivered = mrml_kernel::RecoveryStateMetadata::decode(&delivered).unwrap();
            let mut boot_store = BootRecoveryAdmission::new(delivered)
                .unwrap()
                .bind(&mut state_store);
            let mut supervisor = ServiceSupervisor::<1>::new();
            let mut recovered_bytes = [0xa5; 512];
            let configuration_validator =
                StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new(
                    stable.file(),
                    0,
                    stable_principal(),
                    2,
                    &capabilities,
                    root,
                    setting_access,
                    setting,
                    service_object,
                    &mut recovered_bytes,
                    &mut volume,
                );
            let mut validator =
                StableServiceRecoveryValidator::new(configuration_validator, &supervisor, task);
            let mut authority_scratch = [0xa5; 128];
            let (authorities, prepared_service) =
                recover_validate_and_commit_stable_authorities::<1, 1, 1, _, _, _>(
                    &authority_file,
                    &bootstrap,
                    bootstrap_file,
                    stable_principal(),
                    2,
                    &mut issuer,
                    &mut authority_scratch,
                    &mut authority_backend,
                    &mut boot_store,
                    &mut validator,
                )
                .unwrap();
            drop(boot_store);
            assert!(
                supervisor
                    .plan_registration(ObjectId(82), task, RestartPolicy::ONCE_IMMEDIATE)
                    .is_ok()
            );
            let recovered = prepared_service
                .commit(authorities, &mut supervisor)
                .unwrap();
            assert_eq!(recovered.service().token(), 1u64 << 32);
            assert_eq!(recovered.configuration().revision(), 1);
            assert_eq!(recovered.authorities().epoch(), 9);

            const HANDOFF_LENGTH: usize = mrml_kernel::HANDOFF_HEADER_BYTES
                + 2 * mrml_kernel::HANDOFF_REGION_BYTES
                + mrml_kernel::HANDOFF_SERVICE_BYTES
                + mrml_kernel::HANDOFF_RECOVERY_STATE_BYTES
                + 16
                + 52;
            let regions = [
                mrml_kernel::MemoryRegion::new(
                    mrml_kernel::PhysAddr::new(0xa0000).unwrap(),
                    1,
                    mrml_kernel::MemoryKind::Mmio,
                )
                .unwrap(),
                mrml_kernel::MemoryRegion::new(
                    mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                    64,
                    mrml_kernel::MemoryKind::Reserved,
                )
                .unwrap(),
            ];
            let framebuffer = mrml_kernel::FramebufferInfo::new(
                0xa0000,
                0x1000,
                16,
                16,
                16,
                mrml_kernel::PixelFormat::BlueGreenRedReserved,
            )
            .unwrap();
            let launch = mrml_kernel::ServiceLaunch::new(
                mrml_kernel::PhysAddr::new(0x11_0000).unwrap(),
                1024,
                mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                2,
                0x1_4000_0000,
                0x1_4000_0080,
                mrml_kernel::PhysAddr::new(0x10_4000).unwrap(),
                2,
                0x2_0000_2000,
                mrml_kernel::PhysAddr::new(0x10_8000).unwrap(),
                4,
                11,
                [9; 64],
            )
            .unwrap();
            let mut madt = [0u8; 52];
            madt[..4].copy_from_slice(b"APIC");
            madt[4..8].copy_from_slice(&52u32.to_le_bytes());
            madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
            madt[44..].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
            madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
            let mut handoff_bytes = [0u8; HANDOFF_LENGTH];
            mrml_kernel::encode_handoff_with_smp_service_recovery_and_isolation(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                launch,
                Some(delivered),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut handoff_bytes,
            )
            .unwrap();
            let handoff = BootHandoff::decode(&handoff_bytes, |_| {}).unwrap();
            let boot_policy = recovered
                .compose_boot_isolation_policy(
                    &capabilities,
                    system,
                    system_access,
                    component,
                    component_access,
                    &handoff,
                )
                .unwrap();
            assert_eq!(boot_policy.authority_epoch(), 9);
            assert_eq!(boot_policy.boot_accepted_epoch(), 8);
            assert_eq!(boot_policy.configuration_revision(), 1);
            assert_eq!(boot_policy.configuration_service(), recovered.service());
            assert_eq!(
                boot_policy.effective().configured().mode(),
                IsolationMode::Balanced
            );
            assert_eq!(boot_policy.effective().mode(), IsolationMode::TotalMicrovm);
            assert_eq!(
                boot_policy.effective().boot_override(),
                Some(BootIsolationOverride::TotalMicrovmOnce)
            );
            let admission = boot_policy.admission_table::<1>(33).unwrap();
            assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
            assert_eq!(admission.policy_generation(), 1);

            let domain = ObjectId(0x434f_4e46_4947_0001);
            let release = activated_configuration_release(domain, 1);
            let mut total = recovered
                .bind_total_boot_admission(
                    &capabilities,
                    system,
                    system_access,
                    component,
                    component_access,
                    &handoff,
                    release,
                )
                .unwrap();
            assert_eq!(total.policy().authority_epoch(), 9);
            assert_eq!(total.policy().boot_accepted_epoch(), 8);
            let bounds = IsolationServiceBounds::new(
                IsolationPlacement::NativeService,
                IsolationPlacement::NativeService,
                IsolationPlacement::Microvm,
                true,
                true,
            )
            .unwrap();
            let identity = IsolationServiceIdentity::new(
                domain,
                ObjectId(0x434f_4e46_0000_0001),
                1,
                5,
                TotalMicrovmClass::MicrovmEligible,
            )
            .unwrap();
            let prepared = total.prepare_service(bounds, identity).unwrap();
            assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
            let routed = prepared.commit(total.admission_mut(), 0x51u64).unwrap();
            assert_eq!(routed.domain(), domain);
            assert_eq!(routed.into_endpoint(), 0x51);
            let proof = total.finalize().unwrap();
            assert_eq!(proof.classified_domains, 1);
            assert_eq!(proof.running_microvm_eligible, 1);
            assert_eq!(proof.running_in_microvm, 1);

            let stale_recovery = mrml_kernel::RecoveryStateMetadata::new(7, 1, None, 0).unwrap();
            mrml_kernel::encode_handoff_with_smp_service_recovery_and_isolation(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                launch,
                Some(stale_recovery),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut handoff_bytes,
            )
            .unwrap();
            let stale_handoff = BootHandoff::decode(&handoff_bytes, |_| {}).unwrap();
            assert_eq!(
                recovered.compose_boot_isolation_policy(
                    &capabilities,
                    system,
                    system_access,
                    component,
                    component_access,
                    &stale_handoff,
                ),
                Err(ConfigError::RecoveryHandoffMismatch)
            );
            assert_eq!(
                recovered.authorities().authority_table().authorize(
                    recovered.authorities().handle(0).unwrap(),
                    stable_principal(),
                    StorageObjectKind::File,
                    StorageRights::READ,
                ),
                Ok(stable_object(9))
            );
            assert_eq!(
                u64::from_le_bytes(state_store.bytes[16..24].try_into().unwrap()),
                9
            );
            assert!(authority_scratch.iter().all(|byte| *byte == 0));
            assert!(recovered_bytes.iter().all(|byte| *byte == 0));
            assert_eq!(supervisor.task(recovered.service()), Ok(Some(task)));
        }
        assert!(backend.writes > 0);
        assert!(backend.reads > 0);
        assert!(backend.flushes >= 3);
        assert_eq!(backend.replacements, 1);

        assert_eq!(
            block_service
                .revoke(block_session, stable_principal())
                .unwrap(),
            2
        );
        assert_eq!(
            ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                block_session,
                stable_principal(),
            )
            .err(),
            Some(BlockServiceError::StaleHandle)
        );
    }

    #[test]
    fn stable_checkpoint_rejects_wrong_authority_binding_corruption_and_io_uncertainty() {
        let (service, capabilities, root, enabled, _) = fixture();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut expected)
            .unwrap();
        let (current, next, mut metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let mut denied_authority = StorageAuthorityTable::<1>::new();
        let denied = denied_authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::WRITE,
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &denied_authority,
                denied,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Write(FileWriteError::Authority(
                _
            )))
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, _, _) = stable_layout(&expected[..checkpoint.length]);
        metadata = FileMetadata::new(
            stable_header(),
            stable_object(9),
            2,
            checkpoint.length as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            [0xff; 32],
        )
        .unwrap();
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let (_, unauthorized_next, unauthorized_metadata, _) =
            stable_layout(&expected[..checkpoint.length]);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                enabled,
                &current,
                &authority,
                file,
                stable_principal(),
                unauthorized_next,
                unauthorized_metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::WrongObject
            ))
        ));
        assert_eq!(backend.staged, 0);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &authority,
                file,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let prepared = prepare_stable_configuration(
            &service,
            &capabilities,
            root,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(71).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let (_, _, _, images) = stable_layout(&expected[..checkpoint.length]);
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&mut receipt).unwrap();

        let mut recovered_bytes = [0xa5; 512];
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation() - 1,
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.reads, 0);

        backend.corrupt_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::InvalidCheckpoint
            ))
        ));
        backend.corrupt_read = false;
        backend.fail_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Read(FileReadError::Backend(4)))
        ));
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn persisted_restart_policy_is_canonical_and_service_bound() {
        assert_eq!(
            PersistedRestartPolicy::new(ObjectId(0), 1, 0, 0),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
        assert_eq!(
            PersistedRestartPolicy::new(ObjectId(70), 0, 0, 0),
            Err(PersistedRestartPolicyError::Service(
                ServiceError::InvalidRestartPolicy
            ))
        );
        let policy = PersistedRestartPolicy::new(ObjectId(70), 3, 10, 40).unwrap();
        let mut encoded = [0xa5; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded);
        assert_eq!(PersistedRestartPolicy::decode(&encoded), Ok(policy));

        for offset in [4usize, 6, 20, 40, 47] {
            let mut malformed = encoded;
            malformed[offset] ^= 1;
            assert_eq!(
                PersistedRestartPolicy::decode(&malformed),
                Err(PersistedRestartPolicyError::InvalidRecord)
            );
        }
        assert_eq!(
            PersistedRestartPolicy::decode(&encoded[..encoded.len() - 1]),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
        let mut substituted = encoded;
        substituted[8..16].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            PersistedRestartPolicy::decode(&substituted),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
    }

    #[test]
    fn recovered_restart_policy_requires_live_setting_read_and_trusted_registration() {
        let setting = SettingId::new(9).unwrap();
        let policy_object = ObjectId(80);
        let service_object = ObjectId(70);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 2>::new(ObjectId(79), &[schema]).unwrap();
        let mut capabilities = CapabilitySpace::<3>::new();
        let root = capabilities
            .insert(ObjectId(79), Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let policy_capability = capabilities
            .insert(policy_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let unrelated = capabilities.insert(ObjectId(81), Rights::READ).unwrap();
        let policy = PersistedRestartPolicy::new(service_object, 1, 10, 10).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_capability,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root, &transaction)
            .unwrap();

        assert!(matches!(
            load_persisted_restart_policy(
                &configuration,
                &capabilities,
                unrelated,
                setting,
                service_object,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::WrongObject
            ))
        ));
        assert_eq!(
            load_persisted_restart_policy(
                &configuration,
                &capabilities,
                policy_capability,
                setting,
                ObjectId(71),
            ),
            Err(PersistedRestartPolicyError::WrongService)
        );

        let mut checkpoint_bytes = [0; 256];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root, &mut checkpoint_bytes)
            .unwrap();
        let recovered = ConfigurationService::<1, 2>::recover_checkpoint(
            &capabilities,
            root,
            &checkpoint_bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        let bound = load_persisted_restart_policy(
            &recovered,
            &capabilities,
            policy_capability,
            setting,
            service_object,
        )
        .unwrap();
        assert_eq!(bound.service(), service_object);
        assert_eq!(bound.configuration_revision(), 1);
        assert_eq!(bound.setting_revision(), 1);

        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = bound
            .register(
                &recovered,
                &capabilities,
                policy_capability,
                &mut supervisor,
                task,
            )
            .unwrap();
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { .. }
        ));
        let retirement = supervisor.exit_current_at(&mut runtime, 0).unwrap();
        struct Eraser;
        impl mrml_kernel::ServiceAddressSpaceEraser for Eraser {
            type Error = ();

            fn erase(&mut self, _: TaskId, _: UserContext) -> Result<(), Self::Error> {
                Ok(())
            }
        }
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(service_object, Rights::CONTROL).unwrap();
        let replacement_context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x30_0000).unwrap(),
            0x50_0000,
            0x7000_0000,
        )
        .unwrap();
        assert_eq!(
            supervisor.restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                9,
            ),
            Err(ServiceError::RestartBackoff { eligible_at: 10 })
        );
        let replacement = supervisor
            .restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                10,
            )
            .unwrap();
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { .. }
        ));
        let retirement = supervisor.exit_current_at(&mut runtime, 20).unwrap();
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        assert_eq!(
            supervisor.restart_at(
                replacement,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                30,
            ),
            Err(ServiceError::RestartLimit)
        );

        capabilities.revoke(policy_capability).unwrap();
        assert!(matches!(
            bound.register(
                &recovered,
                &capabilities,
                policy_capability,
                &mut supervisor,
                task,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        ));
        assert!(matches!(
            load_persisted_restart_policy(
                &recovered,
                &capabilities,
                policy_capability,
                setting,
                service_object,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        ));
    }

    #[test]
    fn dynamic_restart_policy_revalidates_revisions_read_and_service_control() {
        let setting = SettingId::new(10).unwrap();
        let root_object = ObjectId(90);
        let policy_object = ObjectId(91);
        let service_object = ObjectId(92);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 3>::new(root_object, &[schema]).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let policy_capability = capabilities
            .insert(policy_object, Rights::READ.union(Rights::WRITE))
            .unwrap();

        let initial = PersistedRestartPolicy::new(service_object, 1, 10, 10).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        initial.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_capability,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root, &transaction)
            .unwrap();
        let stale = load_persisted_restart_policy(
            &configuration,
            &capabilities,
            policy_capability,
            setting,
            service_object,
        )
        .unwrap();

        let replacement = PersistedRestartPolicy::new(service_object, 3, 20, 40).unwrap();
        replacement.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(1);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_capability,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root, &transaction)
            .unwrap();

        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(service_object, task).unwrap();
        let mut management = CapabilitySpace::<2>::new();
        let wrong = management.insert(ObjectId(93), Rights::CONTROL).unwrap();
        let control = management.insert(service_object, Rights::CONTROL).unwrap();

        assert_eq!(
            stale.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_capability, control),
            ),
            Err(PersistedRestartPolicyError::PolicyChanged)
        );
        let current = load_persisted_restart_policy(
            &configuration,
            &capabilities,
            policy_capability,
            setting,
            service_object,
        )
        .unwrap();
        assert_eq!(current.configuration_revision(), 2);
        assert_eq!(current.setting_revision(), 2);
        assert_eq!(
            current.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_capability, wrong),
            ),
            Err(PersistedRestartPolicyError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied)
            ))
        );
        current
            .replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_capability, control),
            )
            .unwrap();
        capabilities.revoke(policy_capability).unwrap();
        assert_eq!(
            current.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_capability, control),
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        );
    }

    #[test]
    fn policy_envelope_requires_ordered_read_and_control_authorities() {
        struct Kernel {
            control: Capability,
            service: ServiceId,
            policy: RestartPolicy,
        }
        impl ServicePolicyAuthorizer for Kernel {
            fn replace_policy(
                &self,
                capability: Capability,
                service: ServiceId,
                policy: RestartPolicy,
            ) -> Result<(), ConfigError> {
                if capability == self.control && service == self.service && policy == self.policy {
                    Ok(())
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let setting = SettingId::new(11).unwrap();
        let root_object = ObjectId(100);
        let policy_object = ObjectId(101);
        let service_object = ObjectId(102);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 2>::new(root_object, &[schema]).unwrap();
        let mut configuration_capabilities = CapabilitySpace::<2>::new();
        let root = configuration_capabilities
            .insert(root_object, Rights::CONTROL)
            .unwrap();
        let setting_read = configuration_capabilities
            .insert(policy_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let persisted = PersistedRestartPolicy::new(service_object, 2, 5, 20).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        persisted.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                setting_read,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&configuration_capabilities, root, &transaction)
            .unwrap();

        let service = ServiceId::from_token((17u64 << 32) | 2);
        let control = Capability::from_token((18u64 << 32) | 3);
        let kernel = Kernel {
            control,
            service,
            policy: persisted.restart_policy().unwrap(),
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::ReplacePolicy,
            request_id: 56,
            service,
            capability: control,
            setting: Some(setting),
            setting_capability: setting_read,
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode_message(&mut wire).unwrap();
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        assert_eq!(read_u32(&wire, 40), Ok(setting.get()));
        let decoded_request = SupervisionRequest::decode_message(
            &Message::new(&wire, &[setting_read, control]).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded_request, request);

        let mut malformed = wire;
        malformed[32] = 1;
        assert_eq!(
            SupervisionRequest::decode_message(
                &Message::new(&malformed, &[setting_read, control]).unwrap()
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        malformed = wire;
        malformed[44] = 1;
        assert_eq!(
            SupervisionRequest::decode(&malformed),
            Err(ConfigError::NonCanonical)
        );
        malformed = wire;
        write_u16(&mut malformed, 6, SupervisionOperation::Query as u16).unwrap();
        assert_eq!(
            SupervisionRequest::decode(&malformed),
            Err(ConfigError::NonCanonical)
        );
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            service_object,
            &wire,
            &[setting_read, control],
            &mut response,
        )
        .unwrap();
        let decoded = SupervisionResponse::decode(&response).unwrap();
        assert_eq!(decoded.status, ResponseStatus::Ok);
        assert_eq!(decoded.service, service);
        assert_eq!(decoded.state, SupervisionState::Running);
        assert_eq!(decoded.detail, 0);

        for authorities in [
            &[][..],
            &[setting_read][..],
            &[setting_read, control, control][..],
        ] {
            assert_eq!(
                dispatch_supervision_policy_envelope(
                    &configuration,
                    &configuration_capabilities,
                    &kernel,
                    service_object,
                    &wire,
                    authorities,
                    &mut response,
                ),
                Err(ConfigError::InvalidAuthorityEnvelope)
            );
        }
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            service_object,
            &wire,
            &[control, setting_read],
            &mut response,
        )
        .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response).unwrap().status,
            ResponseStatus::Rejected
        );
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            ObjectId(103),
            &wire,
            &[setting_read, control],
            &mut response,
        )
        .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response).unwrap().status,
            ResponseStatus::Rejected
        );
    }

    #[test]
    fn isolation_policy_is_typed_capability_authorized_and_recoverable() {
        let root_object = ObjectId(0x4953_4f4c_4154_494f);
        let component_object = ObjectId(0x434f_4d50_4f4e_454e);
        let system_object = ObjectId(0x5359_5354_454d_504f);
        let component = IsolationPolicySetting::component(
            SettingId::new(40).unwrap(),
            component_object,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(41).unwrap(), system_object).unwrap();
        let system_edit = IsolationSettingsAction::new(OwnerIsolationSelection::TotalMicrovm, 0)
            .edit(system)
            .unwrap();
        assert_eq!(
            IsolationShellCommand::parse("isolation set total-microvm 0", system),
            Ok(IsolationShellCommand::Set(system_edit))
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set native 0", system),
            Err(ConfigError::SchemaViolation)
        );
        let schemas = [component.schema().unwrap(), system.schema().unwrap()];
        let mut configuration = ConfigurationService::<2, 4>::new(root_object, &schemas).unwrap();
        let mut capabilities = CapabilitySpace::<5>::new();
        let root = capabilities
            .insert(root_object, Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let component_access = capabilities
            .insert(component_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let system_access = capabilities
            .insert(system_object, Rights::READ.union(Rights::WRITE))
            .unwrap();

        let mut transaction = ConfigTransaction::<2>::new(0);
        component
            .stage(
                &mut transaction,
                component_access,
                OwnerIsolationSelection::Microvm,
            )
            .unwrap();
        system
            .stage(
                &mut transaction,
                system_access,
                OwnerIsolationSelection::TotalMicrovm,
            )
            .unwrap();
        assert_eq!(
            configuration.commit(&capabilities, root, &transaction),
            Ok(1)
        );

        let component_policy = component
            .read(&configuration, &capabilities, component_access)
            .unwrap();
        assert_eq!(
            component_policy.selection(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(component_policy.setting(), component);
        assert_eq!(component_policy.revision(), 1);
        let substituted_native_class = IsolationPolicySetting::component(
            component.setting(),
            component.object(),
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            substituted_native_class.read(&configuration, &capabilities, component_access),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(
            system
                .read(&configuration, &capabilities, system_access)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::TotalMicrovm
        );
        let plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            component_access,
        )
        .unwrap();
        let applied = plan.apply(&configuration, &capabilities).unwrap();
        assert_eq!(applied.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(
            applied.component_request(),
            Some(IsolationPlacement::Microvm)
        );
        assert_eq!(applied.policy_generation(), 1);
        let admission = applied.admission_table::<2>(SYSTEM_GENERATION).unwrap();
        assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(admission.policy_generation(), 1);
        let status = IsolationStatusSnapshot {
            system_generation: SYSTEM_GENERATION,
            policy_generation: 1,
            requested_mode: IsolationMode::TotalMicrovm,
            total_state: TotalMicrovmState::Satisfied,
            running_microvm_eligible: 1,
            running_in_microvm: 1,
            running_eligible_outside_microvm: 0,
            running_boot_only: 0,
            running_recovery_only: 0,
            running_unsupported_blockers: 0,
            unavailable_microvm_eligible: 0,
            native_fallback: 0,
            host_substrate: HostSubstrateCounts::default(),
            unavailable: IsolationUnavailableCounts::default(),
        };
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let view = applied.semantic_view(bounds, status).unwrap();
        assert_eq!(
            view.configured_system(),
            OwnerIsolationSelection::TotalMicrovm
        );
        assert_eq!(
            view.configured_component(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(
            view.effective_placement(),
            Some(IsolationPlacement::Microvm)
        );
        assert_eq!(
            view.policy_source(),
            Some(IsolationPolicySource::TotalMicrovm)
        );
        assert!(!view.component_blocked());
        assert_eq!(view.status(), status);
        let mut stale_status = status;
        stale_status.policy_generation = 2;
        assert_eq!(
            applied.semantic_view(bounds, stale_status),
            Err(ConfigError::IsolationPolicyMismatch)
        );
        stale_status = status;
        stale_status.requested_mode = IsolationMode::Balanced;
        assert_eq!(
            applied.semantic_view(bounds, stale_status),
            Err(ConfigError::IsolationPolicyMismatch)
        );
        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        let blocked = applied.semantic_view(native_only, status).unwrap();
        assert!(blocked.component_blocked());
        assert_eq!(blocked.effective_placement(), None);
        assert_eq!(blocked.policy_source(), None);
        assert!(!blocked.microvm_supported());
        assert!(matches!(
            component.read(&configuration, &capabilities, system_access),
            Err(ConfigError::WrongObject)
        ));

        let mut checkpoint_bytes = [0; 512];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root, &mut checkpoint_bytes)
            .unwrap();
        let recovered = ConfigurationService::<2, 4>::recover_checkpoint(
            &capabilities,
            root,
            &checkpoint_bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        assert_eq!(
            component
                .read(&recovered, &capabilities, component_access)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(
            system
                .read(&recovered, &capabilities, system_access)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::TotalMicrovm
        );

        let revocable_read = capabilities.insert(component_object, Rights::READ).unwrap();
        let revoked_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            revocable_read,
        )
        .unwrap();
        capabilities.revoke(revocable_read).unwrap();
        assert_eq!(
            revoked_plan.apply(&configuration, &capabilities),
            Err(ConfigError::Unauthorized(CapabilityError::Invalid))
        );

        let stale_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            component_access,
        )
        .unwrap();
        let mut replacement = ConfigTransaction::<1>::new(1);
        component
            .stage(
                &mut replacement,
                component_access,
                OwnerIsolationSelection::Default,
            )
            .unwrap();
        configuration
            .commit(&capabilities, root, &replacement)
            .unwrap();
        assert_eq!(
            stale_plan.apply(&configuration, &capabilities),
            Err(ConfigError::RevisionConflict { current: 2 })
        );
    }

    #[test]
    fn settings_and_shell_share_one_capability_checked_isolation_edit() {
        let root_object = ObjectId(0x4953_4f45_4449_5452);
        let component_object = ObjectId(0x4953_4f45_4449_5443);
        let setting = IsolationPolicySetting::component(
            SettingId::new(73).unwrap(),
            component_object,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        let mut configuration =
            ConfigurationService::<1, 4>::new(root_object, &[setting.schema().unwrap()]).unwrap();
        let mut capabilities = CapabilitySpace::<4>::new();
        let root_control = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let setting_access = capabilities
            .insert(component_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let wrong_write = capabilities.insert(ObjectId(99), Rights::WRITE).unwrap();

        let settings_edit =
            IsolationPolicyEdit::new(setting, OwnerIsolationSelection::Microvm, 0).unwrap();
        assert_eq!(
            IsolationSettingsAction::new(OwnerIsolationSelection::Microvm, 0)
                .edit(setting)
                .unwrap(),
            settings_edit
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 0", setting),
            Ok(IsolationShellCommand::Set(settings_edit))
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation show", setting),
            Ok(IsolationShellCommand::Show)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set total-microvm 0", setting),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 0 extra", setting),
            Err(ConfigError::NonCanonical)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 18446744073709551616", setting),
            Err(ConfigError::InvalidValue)
        );
        let wire = settings_edit.encode();
        let shell_edit = IsolationPolicyEdit::decode(&wire).unwrap();
        assert_eq!(shell_edit, settings_edit);
        assert_eq!(
            shell_edit.commit(&mut configuration, &capabilities, root_control, wrong_write,),
            Err(ConfigError::WrongObject)
        );
        let committed = shell_edit
            .commit(
                &mut configuration,
                &capabilities,
                root_control,
                setting_access,
            )
            .unwrap();
        assert_eq!(committed.setting(), setting);
        assert_eq!(committed.selection(), OwnerIsolationSelection::Microvm);
        assert_eq!(committed.policy_generation(), 1);
        assert_eq!(
            setting
                .read(&configuration, &capabilities, setting_access)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::Microvm
        );

        assert_eq!(
            settings_edit.commit(
                &mut configuration,
                &capabilities,
                root_control,
                setting_access,
            ),
            Err(ConfigError::RevisionConflict { current: 1 })
        );
        let mut tampered = wire;
        tampered[15] = 1;
        assert_eq!(
            IsolationPolicyEdit::decode(&tampered),
            Err(ConfigError::InvalidProtocol)
        );
        tampered = wire;
        tampered[12] = 2;
        assert_eq!(
            IsolationPolicyEdit::decode(&tampered),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn isolation_policy_rejects_scope_confusion_and_noncanonical_data() {
        let component = IsolationPolicySetting::component(
            SettingId::new(42).unwrap(),
            ObjectId(420),
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        let mut transaction = ConfigTransaction::<1>::new(0);
        assert_eq!(
            component.stage(
                &mut transaction,
                Capability::from_token(1),
                OwnerIsolationSelection::TotalMicrovm,
            ),
            Err(ConfigError::SchemaViolation)
        );
        assert!(transaction.is_empty());

        let mut configuration =
            ConfigurationService::<1, 2>::new(ObjectId(419), &[component.schema().unwrap()])
                .unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(ObjectId(419), Rights::CONTROL).unwrap();
        let access = capabilities
            .insert(ObjectId(420), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let mut malformed = [0; ISOLATION_POLICY_VALUE_BYTES];
        malformed[..8].copy_from_slice(&ISOLATION_POLICY_VALUE_MAGIC);
        malformed[8] = 1;
        malformed[9] = OwnerIsolationSelection::Microvm.token();
        malformed[15] = 1;
        let mut generic = ConfigTransaction::<1>::new(0);
        generic
            .push(ConfigUpdate::new(
                component.setting(),
                access,
                ConfigValue::bytes(&malformed).unwrap(),
            ))
            .unwrap();
        configuration.commit(&capabilities, root, &generic).unwrap();
        assert_eq!(
            component.read(&configuration, &capabilities, access),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn service_bounds_admit_exact_policy_without_fallback() {
        let dual = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let default = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: None,
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Default,
            policy_generation: 9,
        }
        .admit_service(dual)
        .unwrap();
        assert_eq!(default.placement(), IsolationPlacement::NativeService);
        assert_eq!(default.source(), IsolationPolicySource::PackageDefault);
        assert_eq!(default.policy_generation(), 9);

        let total = AppliedIsolationPolicy {
            mode: IsolationMode::TotalMicrovm,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::TotalMicrovm,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 10,
        }
        .admit_service(dual)
        .unwrap();
        assert_eq!(total.placement(), IsolationPlacement::Microvm);
        assert_eq!(total.source(), IsolationPolicySource::TotalMicrovm);
        let spec = total
            .service_spec(
                SYSTEM_GENERATION,
                ObjectId(501),
                ObjectId(502),
                3,
                17,
                TotalMicrovmClass::MicrovmEligible,
            )
            .unwrap();
        assert_eq!(spec.placement(), IsolationPlacement::Microvm);
        assert_eq!(spec.system_generation(), SYSTEM_GENERATION);
        assert_eq!(spec.policy_generation(), 10);
        assert_eq!(spec.interface_generation(), 3);
        assert_eq!(spec.provider_generation(), 17);

        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            AppliedIsolationPolicy {
                mode: IsolationMode::TotalMicrovm,
                component_request: None,
                system_selection: OwnerIsolationSelection::TotalMicrovm,
                component_selection: OwnerIsolationSelection::Default,
                policy_generation: 11,
            }
            .admit_service(native_only),
            Err(ConfigError::SchemaViolation)
        );

        let microvm_required = IsolationServiceBounds::new(
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            AppliedIsolationPolicy {
                mode: IsolationMode::Custom,
                component_request: Some(IsolationPlacement::NativeService),
                system_selection: OwnerIsolationSelection::Custom,
                component_selection: OwnerIsolationSelection::Native,
                policy_generation: 12,
            }
            .admit_service(microvm_required),
            Err(ConfigError::SchemaViolation)
        );
        assert!(
            IsolationServiceBounds::new(
                IsolationPlacement::NativeService,
                IsolationPlacement::Microvm,
                IsolationPlacement::Microvm,
                true,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn recovered_total_admission_prepares_only_release_classified_service_routes() {
        let persistent = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 9,
        };
        let policy = RecoveredBootIsolationPolicy {
            effective: persistent
                .compose_boot_override(Some(BootIsolationOverride::TotalMicrovmOnce)),
            authority_epoch: 12,
            configuration_revision: 9,
            configuration_service: ServiceId::from_token((3u64 << 32) | 1),
            boot_accepted_epoch: 11,
        };
        let domain = ObjectId(0x434f_4e46_4947_0001);
        let release = activated_configuration_release(domain, 9);
        let mut total = policy.bind_release_inventory(release).unwrap();
        let active_generation = total.release().active_release().generation();
        assert_eq!(
            total.admission().system_generation_digest(),
            Some(active_generation.generation_digest())
        );
        assert_eq!(
            total.admission().interface_catalog_digest(),
            Some(active_generation.interface_catalog_digest())
        );
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let identity = IsolationServiceIdentity::new(
            domain,
            ObjectId(0x434f_4e46_0000_0001),
            1,
            5,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        let prepared = total.prepare_service(bounds, identity).unwrap();
        assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
        assert_eq!(prepared.spec().system_generation(), 33);
        assert_eq!(prepared.spec().policy_generation(), 9);
        let routed = prepared.commit(total.admission_mut(), 0x51u64).unwrap();
        assert_eq!(routed.domain(), domain);
        assert_eq!(routed.into_endpoint(), 0x51);
        let proof = total.finalize().unwrap();
        assert_eq!(proof.classified_domains, 1);
        assert_eq!(proof.running_microvm_eligible, 1);
        assert_eq!(proof.running_in_microvm, 1);

        let release = activated_configuration_release(domain, 9);
        let mut rejected = policy.bind_release_inventory(release).unwrap();
        let unclassified = IsolationServiceIdentity::new(
            ObjectId(domain.0 + 1),
            ObjectId(0x434f_4e46_0000_0001),
            1,
            5,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        assert_eq!(
            rejected.prepare_service(bounds, unclassified),
            Err(ConfiguredIsolationPreparationError::Configuration(
                ConfigError::SchemaViolation
            ))
        );
        assert_eq!(rejected.admission().running().count(), 0);
        assert_eq!(rejected.admission().unavailable_domains().count(), 0);

        let release = activated_configuration_release(domain, 10);
        assert!(matches!(
            policy.bind_release_inventory(release),
            Err(ConfigError::IsolationPolicyMismatch)
        ));
    }

    #[test]
    fn one_boot_total_overlay_strengthens_without_mutating_persistent_policy() {
        let configured = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 27,
        };
        let ordinary = configured.compose_boot_override(None);
        assert_eq!(ordinary.configured(), configured);
        assert_eq!(ordinary.mode(), IsolationMode::Balanced);
        assert_eq!(ordinary.boot_override(), None);
        assert_eq!(ordinary.policy_generation(), 27);

        let total = configured.compose_boot_override(Some(BootIsolationOverride::TotalMicrovmOnce));
        assert_eq!(total.configured(), configured);
        assert_eq!(total.configured().mode(), IsolationMode::Balanced);
        assert_eq!(total.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(
            total.boot_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
        assert_eq!(total.policy_generation(), 27);
        let admission = total.admission_table::<1>(SYSTEM_GENERATION).unwrap();
        assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(admission.policy_generation(), 27);

        let dual = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let admitted = total.admit_service(dual).unwrap();
        assert_eq!(admitted.placement(), IsolationPlacement::Microvm);
        assert_eq!(admitted.source(), IsolationPolicySource::TotalMicrovm);
        assert_eq!(admitted.policy_generation(), 27);

        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            total.admit_service(native_only),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(configured.mode(), IsolationMode::Balanced);
        assert_eq!(
            configured.component_request(),
            Some(IsolationPlacement::NativeService)
        );
    }

    #[test]
    fn configured_route_revalidates_policy_binding_before_backend_launch() {
        let root_object = ObjectId(601);
        let component_object = ObjectId(602);
        let system_object = ObjectId(603);
        let component = IsolationPolicySetting::component(
            SettingId::new(60).unwrap(),
            component_object,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(61).unwrap(), system_object).unwrap();
        let mut configuration = ConfigurationService::<2, 4>::new(
            root_object,
            &[component.schema().unwrap(), system.schema().unwrap()],
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<3>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let component_access = capabilities
            .insert(component_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let system_access = capabilities
            .insert(system_object, Rights::READ.union(Rights::WRITE))
            .unwrap();
        let mut initial = ConfigTransaction::<2>::new(0);
        component
            .stage(
                &mut initial,
                component_access,
                OwnerIsolationSelection::Microvm,
            )
            .unwrap();
        system
            .stage(
                &mut initial,
                system_access,
                OwnerIsolationSelection::TotalMicrovm,
            )
            .unwrap();
        configuration.commit(&capabilities, root, &initial).unwrap();
        let plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            component_access,
        )
        .unwrap();
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let identity = IsolationServiceIdentity::new(
            ObjectId(604),
            ObjectId(605),
            3,
            19,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        let mut prepared_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let prepared = prepare_configured_isolation_service_route(
            &configuration,
            &capabilities,
            plan,
            bounds,
            identity,
            &mut prepared_admission,
        )
        .unwrap();
        assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
        assert_eq!(prepared.spec().provider_generation(), 19);
        prepared.cancel(&mut prepared_admission).unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let mut backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let routed = route_configured_isolation_service(
            &configuration,
            &capabilities,
            plan,
            bounds,
            identity,
            &mut admission,
            &mut backend,
        )
        .unwrap();
        assert_eq!(routed.placement(), IsolationPlacement::Microvm);
        assert_eq!(routed.interface(), ObjectId(605));
        assert_eq!(routed.interface_generation(), 3);
        assert_eq!(routed.provider_generation(), 19);
        let (native, microvm) = backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 1));

        let stale_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            component_access,
        )
        .unwrap();
        let mut replacement = ConfigTransaction::<1>::new(1);
        component
            .stage(
                &mut replacement,
                component_access,
                OwnerIsolationSelection::Default,
            )
            .unwrap();
        configuration
            .commit(&capabilities, root, &replacement)
            .unwrap();
        let mut stale_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let mut stale_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        assert!(matches!(
            route_configured_isolation_service(
                &configuration,
                &capabilities,
                stale_plan,
                bounds,
                identity,
                &mut stale_admission,
                &mut stale_backend,
            ),
            Err(ConfiguredIsolationRouteError::Configuration(
                ConfigError::RevisionConflict { current: 2 }
            ))
        ));
        let (native, microvm) = stale_backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 0));

        let current_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_access,
            component,
            component_access,
        )
        .unwrap();
        let mut wrong_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 2)
                .unwrap();
        let mut wrong_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        assert!(matches!(
            route_configured_isolation_service(
                &configuration,
                &capabilities,
                current_plan,
                bounds,
                identity,
                &mut wrong_admission,
                &mut wrong_backend,
            ),
            Err(ConfiguredIsolationRouteError::Configuration(
                ConfigError::IsolationPolicyMismatch
            ))
        ));
        let (native, microvm) = wrong_backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 0));
    }
}
