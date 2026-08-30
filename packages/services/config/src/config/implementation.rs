use core::array;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use mrml_crypto::Sha3_256;
use mrml_deployment::{
    DeploymentRecoveryStateStore, RecoveredDeploymentOwner, RecoveredRuntimeAssignment,
    RecoveredRuntimeAssignmentError, recover_and_read_runtime_assignment,
    recover_and_read_runtime_assignment_shared_backend,
};
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    ActivatedReleaseTotalMicrovmInventory, BootHandoff, BootIsolationOverride,
    BootRecoveryEnvelope, Capability, CapabilityError, CapabilitySpace, EarlyKernelContext,
    HostSubstrateReason, InstalledRecoveryBootIdentity, InstalledRecoverySataRoute,
    InstalledRecoverySource, IsolationAdmissionTable, IsolationBackendFailure, IsolationMode,
    IsolationPlacement, IsolationServiceBackend, IsolationServiceRouteError, IsolationServiceSpec,
    IsolationStatusSnapshot, IsolationUnavailableReason, MemoryBackingKind, MemoryObjectId,
    MemoryPoolId, MemoryPoolTable, MemoryResourceError, Message, ObjectId, PAGE_SIZE,
    PreparedIsolationServiceRoute, Priority, RecoveryStateMetadata, ReleaseInventoryError,
    RestartPolicy, Rights, RoutedIsolationService, RuntimeDomainAssignment,
    RuntimeDomainAssignmentPlan, RuntimeDomainPolicyAssignmentError, ServiceAddressSpaceEraser,
    ServiceCleanupError, ServiceError, ServiceId, ServiceRegistrationPlan, ServiceState,
    ServiceSupervisor, TaskId, TaskRuntime, TaskRuntimeError, prepare_isolation_service_route,
    route_isolation_service,
};
use mrml_storage::{
    AuthorityRecoveryValidator, BlockDeviceDescriptor, BlockDeviceId, BlockFileSession,
    BlockService, BlockServiceBackend, BlockServiceError, BlockSessionHandle, BlockVolume,
    BlockVolumeError, CommittedRecoveredStorageAuthorities, ExtentMap, FileMetadata,
    FileReadBackend, FileReadError, FileState, FileWriteBackend, FileWriteError,
    InstalledRecoverySessionError, MetadataError, MetadataPointer, NativeBlockCorrelationError,
    NativeSataBlockRoute, PlatformBlockDeviceDescriptor, PlatformBlockDeviceIdentity,
    PlatformBlockTransport, PreparedFileWrite, ReachableFileSelection, RecoveredReachableState,
    RecoveredStorageAuthorities, RecoveryError, RecoveryMetadataBackend, SUPERBLOCK_BYTES,
    SataNativeBlockCorrelationError, SataNativeBlockCorrelationVerifier, ServicedBlockDevice,
    StorageAuthorityTable, StorageBlockDevice, StorageHandle, StorageObjectId, StoragePrincipal,
    StorageTransaction, TransactionError, TransactionReceipt, VOLUME_HEADER_BYTES, VolumeHeader,
    VolumeId, recover_reachable_state,
};

#[cfg(any(test, target_os = "windows", target_os = "linux"))]
#[path = "../hosted_recovery_probe.rs"]
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
            .authorize_exact(capability, rights)
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
        const TASKS: usize,
        const CAPS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        configuration: &ConfigurationService<SETTINGS, AUDIT>,
        capabilities: &A,
        policy_capability: Capability,
        supervisor: &mut ServiceSupervisor<SERVICES>,
        runtime: &TaskRuntime<TASKS, CAPS>,
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
            .commit_registration_with_runtime(plan, runtime)
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
    root: ObjectId,
    root_capability: Capability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableConfigurationCommitError {
    Configuration(ConfigError),
    Transaction(TransactionError),
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

    pub fn commit<A: CapabilityAuthorizer + ?Sized, const PARTICIPANTS: usize>(
        self,
        capabilities: &A,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableConfiguration<EXTENTS>, StableConfigurationCommitError> {
        capabilities
            .authorize_exact(self.root_capability, Rights::READ, self.root)
            .map_err(StableConfigurationCommitError::Configuration)?;
        let file = self
            .file
            .commit_transaction(receipt)
            .map_err(StableConfigurationCommitError::Transaction)?;
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
        root: configuration.root,
        root_capability,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedStableSystemRecoveryError {
    RootMismatch,
    DuplicateObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableSystemSelectionError<E> {
    Recovery(RecoveryError<E>),
    MissingConfiguration,
    MissingAuthorityCheckpoint,
    InvalidPair(SelectedStableSystemRecoveryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableTotalSystemSelectionError<E> {
    Recovery(RecoveryError<E>),
    MissingConfiguration,
    MissingAuthorityCheckpoint,
    MissingDeploymentCheckpoint,
    MissingSystemRelease,
    InvalidSet(SelectedStableSystemRecoveryError),
}

/// Owns the exact reachable graph selected from redundant stable-storage roots
/// and the two object identities required for system recovery. File selections
/// borrow this owner, preventing them from outliving or detaching from the
/// integrity-validated graph that established their identity.
pub struct RecoveredStableSystemSelection<const EXTENTS: usize, const OBJECTS: usize> {
    reachable: RecoveredReachableState<EXTENTS, OBJECTS>,
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
}

impl<const EXTENTS: usize, const OBJECTS: usize> RecoveredStableSystemSelection<EXTENTS, OBJECTS> {
    pub fn selected(&self) -> SelectedStableSystemRecovery<'_, EXTENTS, EXTENTS> {
        let configuration = self
            .reachable
            .select_file(self.configuration)
            .expect("validated stable-system configuration remains reachable");
        let authority_checkpoint = self
            .reachable
            .select_file(self.authority_checkpoint)
            .expect("validated stable-system authority checkpoint remains reachable");
        SelectedStableSystemRecovery::new(configuration, authority_checkpoint)
            .expect("validated stable-system pair remains exact")
    }

    pub const fn reachable(&self) -> &RecoveredReachableState<EXTENTS, OBJECTS> {
        &self.reachable
    }
}

/// Owns the exact four-file installed Total control-plane selection from one
/// integrity-validated root. Names identify these files; this owner grants no
/// file, configuration, deployment, or launch authority.
pub struct RecoveredStableTotalSystemSelection<const EXTENTS: usize, const OBJECTS: usize> {
    reachable: RecoveredReachableState<EXTENTS, OBJECTS>,
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
    deployment_checkpoint: StorageObjectId,
    system_release: StorageObjectId,
}

impl<const EXTENTS: usize, const OBJECTS: usize>
    RecoveredStableTotalSystemSelection<EXTENTS, OBJECTS>
{
    pub fn selected(&self) -> SelectedStableTotalSystemRecovery<'_, EXTENTS> {
        let configuration = self
            .reachable
            .select_file(self.configuration)
            .expect("validated Total configuration remains reachable");
        let authority_checkpoint = self
            .reachable
            .select_file(self.authority_checkpoint)
            .expect("validated Total authority checkpoint remains reachable");
        let deployment_checkpoint = self
            .reachable
            .select_file(self.deployment_checkpoint)
            .expect("validated Total deployment checkpoint remains reachable");
        let system_release = self
            .reachable
            .select_file(self.system_release)
            .expect("validated Total SystemRelease remains reachable");
        SelectedStableTotalSystemRecovery::new(
            configuration,
            authority_checkpoint,
            deployment_checkpoint,
            system_release,
        )
        .expect("validated Total four-file set remains exact")
    }

    pub const fn reachable(&self) -> &RecoveredReachableState<EXTENTS, OBJECTS> {
        &self.reachable
    }
}

pub struct RecoveredBlockStableSystemSelection<
    'a,
    D: StorageBlockDevice,
    const EXTENTS: usize,
    const OBJECTS: usize,
> {
    selected: RecoveredStableSystemSelection<EXTENTS, OBJECTS>,
    volume: BlockVolume<'a, D>,
}

pub struct RecoveredBlockStableTotalSystemSelection<
    'a,
    D: StorageBlockDevice,
    const EXTENTS: usize,
    const OBJECTS: usize,
> {
    selected: RecoveredStableTotalSystemSelection<EXTENTS, OBJECTS>,
    volume: BlockVolume<'a, D>,
}

impl<'a, D: StorageBlockDevice, const EXTENTS: usize, const OBJECTS: usize>
    RecoveredBlockStableTotalSystemSelection<'a, D, EXTENTS, OBJECTS>
{
    pub fn selected(&self) -> SelectedStableTotalSystemRecovery<'_, EXTENTS> {
        self.selected.selected()
    }

    pub const fn volume(&self) -> &BlockVolume<'a, D> {
        &self.volume
    }

    pub fn into_parts(
        self,
    ) -> (
        RecoveredStableTotalSystemSelection<EXTENTS, OBJECTS>,
        BlockVolume<'a, D>,
    ) {
        (self.selected, self.volume)
    }
}

impl<'a, D: StorageBlockDevice, const EXTENTS: usize, const OBJECTS: usize>
    RecoveredBlockStableSystemSelection<'a, D, EXTENTS, OBJECTS>
{
    pub fn selected(&self) -> SelectedStableSystemRecovery<'_, EXTENTS, EXTENTS> {
        self.selected.selected()
    }

    pub const fn volume(&self) -> &BlockVolume<'a, D> {
        &self.volume
    }

    pub fn into_parts(
        self,
    ) -> (
        RecoveredStableSystemSelection<EXTENTS, OBJECTS>,
        BlockVolume<'a, D>,
    ) {
        (self.selected, self.volume)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockStableSystemSelectionError<E> {
    Volume(BlockVolumeError<E>),
    Selection(StableSystemSelectionError<BlockVolumeError<E>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockStableTotalSystemSelectionError<E> {
    Volume(BlockVolumeError<E>),
    Selection(StableTotalSystemSelectionError<BlockVolumeError<E>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicedStableSystemSelectionError<E> {
    Session(BlockServiceError<core::convert::Infallible>),
    Selection(BlockStableSystemSelectionError<BlockServiceError<E>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicedStableTotalSystemSelectionError<E> {
    Session(BlockServiceError<core::convert::Infallible>),
    Selection(BlockStableTotalSystemSelectionError<BlockServiceError<E>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledRecoveryDeviceSelectionError {
    Session(BlockServiceError<core::convert::Infallible>),
    DeviceMismatch,
    VolumeMismatch,
    GeometryMismatch,
    InvalidActiveRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffInstalledRecoveryError<E> {
    Session(InstalledRecoverySessionError),
    Scratch,
    Read(BlockServiceError<E>),
    Header(MetadataError),
    Selection(InstalledRecoveryDeviceSelectionError),
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSataHandoffRecoveryError<E> {
    Correlation(NativeBlockCorrelationError<SataNativeBlockCorrelationError>),
    Reacquire(HandoffInstalledRecoveryError<E>),
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedHandoffSataRecoveryError<E> {
    MissingInstalledIdentity,
    MissingSataRoute,
    Recovery(NativeSataHandoffRecoveryError<E>),
}

/// Converts one canonical boot identity into the existing installed-device
/// recovery owner. The identity first has to reacquire a fresh read-only block
/// session; block zero is then read through that session and exact-matched to
/// the handed volume, geometry, and selected redundant root. Every failure
/// revokes the newly created session before returning.
pub fn reacquire_handoff_installed_recovery_device<
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
>(
    service: &mut BlockService<DEVICES, SESSIONS>,
    backend: &mut B,
    boot: InstalledRecoveryBootIdentity,
    principal: StoragePrincipal,
    scratch: &mut [u8],
) -> Result<InstalledRecoveryDeviceSelection, HandoffInstalledRecoveryError<B::Error>> {
    let bound = service
        .grant_installed_recovery_read_session(boot, principal)
        .map_err(HandoffInstalledRecoveryError::Session)?;
    let result = (|| {
        let block_size = usize::try_from(boot.block_size())
            .map_err(|_| HandoffInstalledRecoveryError::Scratch)?;
        let block = scratch
            .get_mut(..block_size)
            .ok_or(HandoffInstalledRecoveryError::Scratch)?;
        service
            .read_blocks(backend, bound.session(), principal, 0, block)
            .map_err(HandoffInstalledRecoveryError::Read)?;
        let header = VolumeHeader::decode(&block[..VOLUME_HEADER_BYTES])
            .map_err(HandoffInstalledRecoveryError::Header)?;
        let expected_volume = VolumeId::new(boot.volume())
            .expect("installed recovery identity validates a nonzero volume");
        InstalledRecoveryDeviceSelection::new_platform(
            service,
            bound.session(),
            principal,
            bound.platform_descriptor(),
            expected_volume,
            header,
            boot.root_block(),
        )
        .map_err(HandoffInstalledRecoveryError::Selection)
    })();
    if result.is_err() && service.revoke(bound.session(), principal).is_err() {
        return Err(HandoffInstalledRecoveryError::Cleanup);
    }
    result
}

/// Correlates one independently supplied native SATA descriptor with the
/// canonical handoff route and completes installed recovery as one bounded
/// control-plane transaction. Correlation failure publishes no registration or
/// session. A later reacquisition failure revokes its session and removes the
/// newly registered descriptor before returning.
#[allow(clippy::too_many_arguments)]
pub fn correlate_and_reacquire_handoff_installed_sata_device<
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
>(
    service: &mut BlockService<DEVICES, SESSIONS>,
    backend: &mut B,
    boot: InstalledRecoveryBootIdentity,
    handoff_route: InstalledRecoverySataRoute,
    native_route: NativeSataBlockRoute,
    candidate: PlatformBlockDeviceDescriptor,
    principal: StoragePrincipal,
    scratch: &mut [u8],
) -> Result<InstalledRecoveryDeviceSelection, NativeSataHandoffRecoveryError<B::Error>> {
    service
        .register_correlated_installed_device(
            &mut SataNativeBlockCorrelationVerifier::new(handoff_route, native_route),
            boot,
            candidate,
        )
        .map_err(NativeSataHandoffRecoveryError::Correlation)?;
    match reacquire_handoff_installed_recovery_device(service, backend, boot, principal, scratch) {
        Ok(selected) => Ok(selected),
        Err(error) => {
            if service.remove_device(candidate.block().id()).is_err() {
                return Err(NativeSataHandoffRecoveryError::Cleanup);
            }
            Err(NativeSataHandoffRecoveryError::Reacquire(error))
        }
    }
}

/// Consumes the installed identity and typed route from one already validated
/// canonical handoff. Callers cannot replace either field with detached data;
/// absence fails before registration, session issuance, or block I/O.
pub fn recover_decoded_handoff_installed_sata_device<
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
>(
    service: &mut BlockService<DEVICES, SESSIONS>,
    backend: &mut B,
    handoff: &BootHandoff,
    native_route: NativeSataBlockRoute,
    candidate: PlatformBlockDeviceDescriptor,
    principal: StoragePrincipal,
    scratch: &mut [u8],
) -> Result<InstalledRecoveryDeviceSelection, DecodedHandoffSataRecoveryError<B::Error>> {
    let boot = handoff
        .installed_recovery()
        .ok_or(DecodedHandoffSataRecoveryError::MissingInstalledIdentity)?;
    let route = handoff
        .installed_recovery_sata_route()
        .ok_or(DecodedHandoffSataRecoveryError::MissingSataRoute)?;
    correlate_and_reacquire_handoff_installed_sata_device(
        service,
        backend,
        boot,
        route,
        native_route,
        candidate,
        principal,
        scratch,
    )
    .map_err(DecodedHandoffSataRecoveryError::Recovery)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveredRecoveryDevice {
    descriptor: BlockDeviceDescriptor,
    platform_identity: Option<PlatformBlockDeviceIdentity>,
    header: VolumeHeader,
    active_superblock: u64,
}

impl DiscoveredRecoveryDevice {
    pub fn new(
        descriptor: BlockDeviceDescriptor,
        header: VolumeHeader,
        active_superblock: u64,
    ) -> Result<Self, InstalledRecoveryDeviceSelectionError> {
        if descriptor.block_size() != header.block_size()
            || descriptor.block_count() != header.block_count()
        {
            return Err(InstalledRecoveryDeviceSelectionError::GeometryMismatch);
        }
        if active_superblock != header.primary_superblock()
            && active_superblock != header.secondary_superblock()
        {
            return Err(InstalledRecoveryDeviceSelectionError::InvalidActiveRoot);
        }
        Ok(Self {
            descriptor,
            platform_identity: None,
            header,
            active_superblock,
        })
    }

    pub const fn descriptor(self) -> BlockDeviceDescriptor {
        self.descriptor
    }

    pub fn new_platform(
        descriptor: PlatformBlockDeviceDescriptor,
        header: VolumeHeader,
        active_superblock: u64,
    ) -> Result<Self, InstalledRecoveryDeviceSelectionError> {
        let mut candidate = Self::new(descriptor.block(), header, active_superblock)?;
        candidate.platform_identity = Some(descriptor.identity());
        Ok(candidate)
    }

    pub const fn platform_identity(self) -> Option<PlatformBlockDeviceIdentity> {
        self.platform_identity
    }

    pub const fn header(self) -> VolumeHeader {
        self.header
    }

    pub const fn active_superblock(self) -> u64 {
        self.active_superblock
    }
}

/// Bounded platform adapter for already validated device/header candidates.
/// Candidate metadata identifies possible recovery volumes but carries no I/O
/// authority and cannot create a `BlockService` session.
pub trait InstalledRecoveryDeviceDiscovery {
    type Error;

    fn next_candidate(&mut self) -> Result<Option<DiscoveredRecoveryDevice>, Self::Error>;
}

/// Fixed-capacity candidates read through explicitly supplied live block
/// sessions. The inventory retains metadata only; it cannot perform I/O or
/// grant a session after construction.
pub struct ServicedRecoveryDeviceInventory<const CANDIDATES: usize> {
    candidates: [Option<DiscoveredRecoveryDevice>; CANDIDATES],
    count: usize,
    next: usize,
}

impl<const CANDIDATES: usize> ServicedRecoveryDeviceInventory<CANDIDATES> {
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl<const CANDIDATES: usize> InstalledRecoveryDeviceDiscovery
    for ServicedRecoveryDeviceInventory<CANDIDATES>
{
    type Error = core::convert::Infallible;

    fn next_candidate(&mut self) -> Result<Option<DiscoveredRecoveryDevice>, Self::Error> {
        let candidate = self.candidates.get(self.next).copied().flatten();
        self.next = self.next.saturating_add(1);
        Ok(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicedRecoveryDeviceInventoryError<E> {
    Capacity,
    Scratch,
    Session(BlockServiceError<core::convert::Infallible>),
    MissingPlatformIdentity,
    Read(BlockServiceError<E>),
    Candidate(InstalledRecoveryDeviceSelectionError),
}

/// Enumerates only devices for which the caller already holds an explicit live
/// block session. Each header read repeats that session's owner and `READ`
/// checks. Invalid or non-MRML headers are not candidates; transport
/// uncertainty fails the complete inventory rather than silently hiding a
/// potentially matching or duplicate installed volume.
pub fn enumerate_serviced_recovery_devices<
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const CANDIDATES: usize,
>(
    service: &BlockService<DEVICES, SESSIONS>,
    backend: &mut B,
    sessions: &[BlockSessionHandle],
    principal: StoragePrincipal,
    scratch: &mut [u8],
) -> Result<
    ServicedRecoveryDeviceInventory<CANDIDATES>,
    ServicedRecoveryDeviceInventoryError<B::Error>,
> {
    if CANDIDATES == 0 || sessions.len() > CANDIDATES {
        return Err(ServicedRecoveryDeviceInventoryError::Capacity);
    }
    let mut inventory = ServicedRecoveryDeviceInventory {
        candidates: [None; CANDIDATES],
        count: 0,
        next: 0,
    };
    for session in sessions.iter().copied() {
        let platform = service
            .session_platform_descriptor(session, principal)
            .map_err(ServicedRecoveryDeviceInventoryError::Session)?;
        let platform =
            platform.ok_or(ServicedRecoveryDeviceInventoryError::MissingPlatformIdentity)?;
        let descriptor = platform.block();
        let block_size = usize::try_from(descriptor.block_size())
            .map_err(|_| ServicedRecoveryDeviceInventoryError::Scratch)?;
        let block = scratch
            .get_mut(..block_size)
            .ok_or(ServicedRecoveryDeviceInventoryError::Scratch)?;
        service
            .read_blocks(backend, session, principal, 0, block)
            .map_err(ServicedRecoveryDeviceInventoryError::Read)?;
        let Ok(header) = VolumeHeader::decode(&block[..VOLUME_HEADER_BYTES]) else {
            continue;
        };
        let candidate =
            DiscoveredRecoveryDevice::new_platform(platform, header, header.primary_superblock())
                .map_err(ServicedRecoveryDeviceInventoryError::Candidate)?;
        inventory.candidates[inventory.count] = Some(candidate);
        inventory.count += 1;
    }
    Ok(inventory)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledRecoveryDeviceDiscoveryError<E> {
    Discovery(E),
    Capacity,
    Missing,
    Ambiguous,
    Selection(InstalledRecoveryDeviceSelectionError),
}

/// Typed control-plane binding for one installed recovery volume.
///
/// Device and volume identities describe the intended object but grant no I/O.
/// Construction authenticates the exact live session owner, binds the session's
/// registered device geometry to the expected volume header, and fixes one of
/// that header's redundant roots. The retained session is still reauthorized
/// for every data-plane read by `BlockService`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledRecoveryDeviceSelection {
    session: BlockSessionHandle,
    principal: StoragePrincipal,
    descriptor: BlockDeviceDescriptor,
    platform_identity: Option<PlatformBlockDeviceIdentity>,
    header: VolumeHeader,
    active_superblock: u64,
}

impl InstalledRecoveryDeviceSelection {
    pub fn new<const DEVICES: usize, const SESSIONS: usize>(
        service: &BlockService<DEVICES, SESSIONS>,
        session: BlockSessionHandle,
        principal: StoragePrincipal,
        expected_device: BlockDeviceId,
        expected_volume: VolumeId,
        header: VolumeHeader,
        active_superblock: u64,
    ) -> Result<Self, InstalledRecoveryDeviceSelectionError> {
        let descriptor = service
            .session_descriptor(session, principal)
            .map_err(InstalledRecoveryDeviceSelectionError::Session)?;
        if descriptor.id() != expected_device {
            return Err(InstalledRecoveryDeviceSelectionError::DeviceMismatch);
        }
        if header.volume() != expected_volume {
            return Err(InstalledRecoveryDeviceSelectionError::VolumeMismatch);
        }
        if descriptor.block_size() != header.block_size()
            || descriptor.block_count() != header.block_count()
        {
            return Err(InstalledRecoveryDeviceSelectionError::GeometryMismatch);
        }
        if active_superblock != header.primary_superblock()
            && active_superblock != header.secondary_superblock()
        {
            return Err(InstalledRecoveryDeviceSelectionError::InvalidActiveRoot);
        }
        Ok(Self {
            session,
            principal,
            descriptor,
            platform_identity: None,
            header,
            active_superblock,
        })
    }

    pub const fn descriptor(self) -> BlockDeviceDescriptor {
        self.descriptor
    }

    pub fn new_platform<const DEVICES: usize, const SESSIONS: usize>(
        service: &BlockService<DEVICES, SESSIONS>,
        session: BlockSessionHandle,
        principal: StoragePrincipal,
        expected: PlatformBlockDeviceDescriptor,
        expected_volume: VolumeId,
        header: VolumeHeader,
        active_superblock: u64,
    ) -> Result<Self, InstalledRecoveryDeviceSelectionError> {
        let live = service
            .session_platform_descriptor(session, principal)
            .map_err(InstalledRecoveryDeviceSelectionError::Session)?
            .ok_or(InstalledRecoveryDeviceSelectionError::DeviceMismatch)?;
        if live != expected {
            return Err(InstalledRecoveryDeviceSelectionError::DeviceMismatch);
        }
        let mut selected = Self::new(
            service,
            session,
            principal,
            expected.block().id(),
            expected_volume,
            header,
            active_superblock,
        )?;
        selected.platform_identity = Some(expected.identity());
        Ok(selected)
    }

    pub const fn platform_identity(self) -> Option<PlatformBlockDeviceIdentity> {
        self.platform_identity
    }

    pub const fn header(self) -> VolumeHeader {
        self.header
    }

    pub const fn active_superblock(self) -> u64 {
        self.active_superblock
    }
}

/// Selects exactly one bounded discovered volume and joins it to the exact live
/// block session. Discovery is identification only; successful return still
/// relies on `BlockService` to reauthorize every data-plane operation.
pub fn discover_installed_recovery_device<
    D: InstalledRecoveryDeviceDiscovery,
    const DEVICES: usize,
    const SESSIONS: usize,
    const MAX_CANDIDATES: usize,
>(
    service: &BlockService<DEVICES, SESSIONS>,
    session: BlockSessionHandle,
    principal: StoragePrincipal,
    expected_volume: VolumeId,
    discovery: &mut D,
) -> Result<InstalledRecoveryDeviceSelection, InstalledRecoveryDeviceDiscoveryError<D::Error>> {
    if MAX_CANDIDATES == 0 {
        return Err(InstalledRecoveryDeviceDiscoveryError::Capacity);
    }
    let mut selected = None;
    for _ in 0..MAX_CANDIDATES {
        let Some(candidate) = discovery
            .next_candidate()
            .map_err(InstalledRecoveryDeviceDiscoveryError::Discovery)?
        else {
            return finish_discovered_recovery_selection(
                service,
                session,
                principal,
                expected_volume,
                selected,
            );
        };
        if candidate.header.volume() == expected_volume {
            if selected.replace(candidate).is_some() {
                return Err(InstalledRecoveryDeviceDiscoveryError::Ambiguous);
            }
        }
    }
    if discovery
        .next_candidate()
        .map_err(InstalledRecoveryDeviceDiscoveryError::Discovery)?
        .is_some()
    {
        return Err(InstalledRecoveryDeviceDiscoveryError::Capacity);
    }
    finish_discovered_recovery_selection(service, session, principal, expected_volume, selected)
}

fn finish_discovered_recovery_selection<const DEVICES: usize, const SESSIONS: usize, E>(
    service: &BlockService<DEVICES, SESSIONS>,
    session: BlockSessionHandle,
    principal: StoragePrincipal,
    expected_volume: VolumeId,
    selected: Option<DiscoveredRecoveryDevice>,
) -> Result<InstalledRecoveryDeviceSelection, InstalledRecoveryDeviceDiscoveryError<E>> {
    let selected = selected.ok_or(InstalledRecoveryDeviceDiscoveryError::Missing)?;
    match selected.platform_identity {
        Some(identity) => InstalledRecoveryDeviceSelection::new_platform(
            service,
            session,
            principal,
            PlatformBlockDeviceDescriptor::new(selected.descriptor, identity),
            expected_volume,
            selected.header,
            selected.active_superblock,
        ),
        None => InstalledRecoveryDeviceSelection::new(
            service,
            session,
            principal,
            selected.descriptor.id(),
            expected_volume,
            selected.header,
            selected.active_superblock,
        ),
    }
    .map_err(InstalledRecoveryDeviceDiscoveryError::Selection)
}

pub struct RecoveredInstalledStableSystemSelection<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
> {
    installed: InstalledRecoveryDeviceSelection,
    recovered: RecoveredBlockStableSystemSelection<
        'a,
        ServicedBlockDevice<'a, B, DEVICES, SESSIONS>,
        EXTENTS,
        OBJECTS,
    >,
}

pub struct RecoveredInstalledStableTotalSystemSelection<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
> {
    installed: InstalledRecoveryDeviceSelection,
    recovered: RecoveredBlockStableTotalSystemSelection<
        'a,
        ServicedBlockDevice<'a, B, DEVICES, SESSIONS>,
        EXTENTS,
        OBJECTS,
    >,
}

impl<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
> RecoveredInstalledStableTotalSystemSelection<'a, B, DEVICES, SESSIONS, EXTENTS, OBJECTS>
{
    pub const fn installed(&self) -> InstalledRecoveryDeviceSelection {
        self.installed
    }

    pub fn selected(&self) -> SelectedStableTotalSystemRecovery<'_, EXTENTS> {
        self.recovered.selected()
    }

    pub const fn volume(&self) -> &BlockVolume<'a, ServicedBlockDevice<'a, B, DEVICES, SESSIONS>> {
        self.recovered.volume()
    }

    pub fn into_parts(
        self,
    ) -> (
        InstalledRecoveryDeviceSelection,
        RecoveredBlockStableTotalSystemSelection<
            'a,
            ServicedBlockDevice<'a, B, DEVICES, SESSIONS>,
            EXTENTS,
            OBJECTS,
        >,
    ) {
        (self.installed, self.recovered)
    }
}

impl<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
> RecoveredInstalledStableSystemSelection<'a, B, DEVICES, SESSIONS, EXTENTS, OBJECTS>
{
    pub const fn installed(&self) -> InstalledRecoveryDeviceSelection {
        self.installed
    }

    pub fn selected(&self) -> SelectedStableSystemRecovery<'_, EXTENTS, EXTENTS> {
        self.recovered.selected()
    }

    pub const fn volume(&self) -> &BlockVolume<'a, ServicedBlockDevice<'a, B, DEVICES, SESSIONS>> {
        self.recovered.volume()
    }

    pub fn into_parts(
        self,
    ) -> (
        InstalledRecoveryDeviceSelection,
        RecoveredBlockStableSystemSelection<
            'a,
            ServicedBlockDevice<'a, B, DEVICES, SESSIONS>,
            EXTENTS,
            OBJECTS,
        >,
    ) {
        (self.installed, self.recovered)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveredStableSystemSelectionError<DiscoveryError, BackendError> {
    Discovery(InstalledRecoveryDeviceDiscoveryError<DiscoveryError>),
    Recovery(ServicedStableSystemSelectionError<BackendError>),
}

/// Performs the bounded discovery/control-plane join and the complete serviced
/// recovery read as one owning operation. Callers cannot detach the recovered
/// graph from the exact installed-device binding that selected its data plane.
#[allow(clippy::too_many_arguments)]
pub fn discover_and_recover_serviced_stable_system_selection<
    'a,
    D: InstalledRecoveryDeviceDiscovery,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const MAX_CANDIDATES: usize,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    service: &'a BlockService<DEVICES, SESSIONS>,
    backend: &'a mut B,
    session: BlockSessionHandle,
    principal: StoragePrincipal,
    expected_volume: VolumeId,
    discovery: &mut D,
    volume_scratch: &'a mut [u8],
    primary_block: &mut [u8],
    secondary_block: &mut [u8],
    metadata_scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
) -> Result<
    RecoveredInstalledStableSystemSelection<'a, B, DEVICES, SESSIONS, EXTENTS, OBJECTS>,
    DiscoveredStableSystemSelectionError<D::Error, B::Error>,
> {
    let installed = discover_installed_recovery_device::<_, DEVICES, SESSIONS, MAX_CANDIDATES>(
        service,
        session,
        principal,
        expected_volume,
        discovery,
    )
    .map_err(DiscoveredStableSystemSelectionError::Discovery)?;
    let recovered = recover_serviced_stable_system_selection::<
        _,
        DEVICES,
        SESSIONS,
        ALLOCATIONS,
        DIRECTORIES,
        EXTENTS,
        OBJECTS,
    >(
        service,
        backend,
        installed,
        volume_scratch,
        primary_block,
        secondary_block,
        metadata_scratch,
        configuration,
        authority_checkpoint,
    )
    .map_err(DiscoveredStableSystemSelectionError::Recovery)?;
    Ok(RecoveredInstalledStableSystemSelection {
        installed,
        recovered,
    })
}

/// Consumes one completely established recovery-device control-plane binding
/// before any redundant-root or metadata data-plane read. Names and identities
/// do not authorize: the retained session and principal are checked again on
/// every block operation.
#[allow(clippy::too_many_arguments)]
pub fn recover_serviced_stable_system_selection<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    service: &'a BlockService<DEVICES, SESSIONS>,
    backend: &'a mut B,
    installed: InstalledRecoveryDeviceSelection,
    volume_scratch: &'a mut [u8],
    primary_block: &mut [u8],
    secondary_block: &mut [u8],
    metadata_scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
) -> Result<
    RecoveredBlockStableSystemSelection<
        'a,
        ServicedBlockDevice<'a, B, DEVICES, SESSIONS>,
        EXTENTS,
        OBJECTS,
    >,
    ServicedStableSystemSelectionError<B::Error>,
> {
    let device = ServicedBlockDevice::new(service, backend, installed.session, installed.principal)
        .map_err(ServicedStableSystemSelectionError::Session)?;
    recover_block_stable_system_selection::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
        installed.header,
        installed.active_superblock,
        device,
        volume_scratch,
        primary_block,
        secondary_block,
        metadata_scratch,
        configuration,
        authority_checkpoint,
    )
    .map_err(ServicedStableSystemSelectionError::Selection)
}

/// Serviced installed-device counterpart for the four-file Total recovery
/// owner. The selected session remains the only data-plane path; names and
/// recovered identities grant no block or file authority.
#[allow(clippy::too_many_arguments)]
pub fn recover_serviced_stable_total_system_selection<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    service: &'a BlockService<DEVICES, SESSIONS>,
    backend: &'a mut B,
    installed: InstalledRecoveryDeviceSelection,
    volume_scratch: &'a mut [u8],
    primary_block: &mut [u8],
    secondary_block: &mut [u8],
    metadata_scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
    deployment_checkpoint: StorageObjectId,
    system_release: StorageObjectId,
) -> Result<
    RecoveredInstalledStableTotalSystemSelection<'a, B, DEVICES, SESSIONS, EXTENTS, OBJECTS>,
    ServicedStableTotalSystemSelectionError<B::Error>,
> {
    let device = ServicedBlockDevice::new(service, backend, installed.session, installed.principal)
        .map_err(ServicedStableTotalSystemSelectionError::Session)?;
    let recovered = recover_block_stable_total_system_selection::<
        _,
        ALLOCATIONS,
        DIRECTORIES,
        EXTENTS,
        OBJECTS,
    >(
        installed.header,
        installed.active_superblock,
        device,
        volume_scratch,
        primary_block,
        secondary_block,
        metadata_scratch,
        configuration,
        authority_checkpoint,
        deployment_checkpoint,
        system_release,
    )
    .map_err(ServicedStableTotalSystemSelectionError::Selection)?;
    Ok(RecoveredInstalledStableTotalSystemSelection {
        installed,
        recovered,
    })
}

/// Reads both redundant roots and validates the complete selected graph through
/// one exclusive `BlockVolume`, retaining that same device generation beside
/// the resulting stable-system selection.
#[allow(clippy::too_many_arguments)]
pub fn recover_block_stable_system_selection<
    'a,
    D: StorageBlockDevice,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    header: VolumeHeader,
    active_superblock: u64,
    device: D,
    volume_scratch: &'a mut [u8],
    primary_block: &mut [u8],
    secondary_block: &mut [u8],
    metadata_scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
) -> Result<
    RecoveredBlockStableSystemSelection<'a, D, EXTENTS, OBJECTS>,
    BlockStableSystemSelectionError<D::Error>,
> {
    let mut volume = BlockVolume::new(header, active_superblock, device, volume_scratch)
        .map_err(BlockStableSystemSelectionError::Volume)?;
    volume
        .read_recovery_superblocks(primary_block, secondary_block)
        .map_err(BlockStableSystemSelectionError::Volume)?;
    if primary_block.len() < SUPERBLOCK_BYTES || secondary_block.len() < SUPERBLOCK_BYTES {
        return Err(BlockStableSystemSelectionError::Volume(
            BlockVolumeError::InvalidRange,
        ));
    }
    let selected =
        recover_stable_system_selection::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
            header,
            &primary_block[..SUPERBLOCK_BYTES],
            &secondary_block[..SUPERBLOCK_BYTES],
            &mut volume,
            metadata_scratch,
            configuration,
            authority_checkpoint,
        )
        .map_err(BlockStableSystemSelectionError::Selection)?;
    Ok(RecoveredBlockStableSystemSelection { selected, volume })
}

/// Reads redundant roots through one exclusive block volume and retains the
/// exact four-file Total control-plane selection beside that same data plane.
#[allow(clippy::too_many_arguments)]
pub fn recover_block_stable_total_system_selection<
    'a,
    D: StorageBlockDevice,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    header: VolumeHeader,
    active_superblock: u64,
    device: D,
    volume_scratch: &'a mut [u8],
    primary_block: &mut [u8],
    secondary_block: &mut [u8],
    metadata_scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
    deployment_checkpoint: StorageObjectId,
    system_release: StorageObjectId,
) -> Result<
    RecoveredBlockStableTotalSystemSelection<'a, D, EXTENTS, OBJECTS>,
    BlockStableTotalSystemSelectionError<D::Error>,
> {
    let mut volume = BlockVolume::new(header, active_superblock, device, volume_scratch)
        .map_err(BlockStableTotalSystemSelectionError::Volume)?;
    volume
        .read_recovery_superblocks(primary_block, secondary_block)
        .map_err(BlockStableTotalSystemSelectionError::Volume)?;
    if primary_block.len() < SUPERBLOCK_BYTES || secondary_block.len() < SUPERBLOCK_BYTES {
        return Err(BlockStableTotalSystemSelectionError::Volume(
            BlockVolumeError::InvalidRange,
        ));
    }
    let selected =
        recover_stable_total_system_selection::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
            header,
            &primary_block[..SUPERBLOCK_BYTES],
            &secondary_block[..SUPERBLOCK_BYTES],
            &mut volume,
            metadata_scratch,
            configuration,
            authority_checkpoint,
            deployment_checkpoint,
            system_release,
        )
        .map_err(BlockStableTotalSystemSelectionError::Selection)?;
    Ok(RecoveredBlockStableTotalSystemSelection { selected, volume })
}

/// Selects one complete redundant-root graph through the supplied hostile
/// metadata backend, then admits the exact configuration/authority pair. This
/// is non-authorizing and does not perform rollback, owner-approval, or file-
/// capability checks.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_system_selection<
    B: RecoveryMetadataBackend,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    backend: B,
    scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
) -> Result<RecoveredStableSystemSelection<EXTENTS, OBJECTS>, StableSystemSelectionError<B::Error>>
{
    let reachable = recover_reachable_state::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
        header, primary, secondary, backend, scratch,
    )
    .map_err(StableSystemSelectionError::Recovery)?;
    let configuration_selection = reachable
        .select_file(configuration)
        .ok_or(StableSystemSelectionError::MissingConfiguration)?;
    let authority_selection = reachable
        .select_file(authority_checkpoint)
        .ok_or(StableSystemSelectionError::MissingAuthorityCheckpoint)?;
    SelectedStableSystemRecovery::new(configuration_selection, authority_selection)
        .map_err(StableSystemSelectionError::InvalidPair)?;
    Ok(RecoveredStableSystemSelection {
        reachable,
        configuration,
        authority_checkpoint,
    })
}

/// Selects the four installed control-plane files required to recover Total
/// placement from one complete redundant-root graph. The result remains
/// non-authorizing; each later read still requires its exact live capability.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_total_system_selection<
    B: RecoveryMetadataBackend,
    const ALLOCATIONS: usize,
    const DIRECTORIES: usize,
    const EXTENTS: usize,
    const OBJECTS: usize,
>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    backend: B,
    scratch: &mut [u8],
    configuration: StorageObjectId,
    authority_checkpoint: StorageObjectId,
    deployment_checkpoint: StorageObjectId,
    system_release: StorageObjectId,
) -> Result<
    RecoveredStableTotalSystemSelection<EXTENTS, OBJECTS>,
    StableTotalSystemSelectionError<B::Error>,
> {
    let reachable = recover_reachable_state::<_, ALLOCATIONS, DIRECTORIES, EXTENTS, OBJECTS>(
        header, primary, secondary, backend, scratch,
    )
    .map_err(StableTotalSystemSelectionError::Recovery)?;
    let configuration_selection = reachable
        .select_file(configuration)
        .ok_or(StableTotalSystemSelectionError::MissingConfiguration)?;
    let authority_selection = reachable
        .select_file(authority_checkpoint)
        .ok_or(StableTotalSystemSelectionError::MissingAuthorityCheckpoint)?;
    let deployment_selection = reachable
        .select_file(deployment_checkpoint)
        .ok_or(StableTotalSystemSelectionError::MissingDeploymentCheckpoint)?;
    let release_selection = reachable
        .select_file(system_release)
        .ok_or(StableTotalSystemSelectionError::MissingSystemRelease)?;
    SelectedStableTotalSystemRecovery::new(
        configuration_selection,
        authority_selection,
        deployment_selection,
        release_selection,
    )
    .map_err(StableTotalSystemSelectionError::InvalidSet)?;
    Ok(RecoveredStableTotalSystemSelection {
        reachable,
        configuration,
        authority_checkpoint,
        deployment_checkpoint,
        system_release,
    })
}

/// Exact configuration and authority-checkpoint selections from one already
/// integrity-validated stable-storage root. The pair is non-authorizing: owner
/// approval, rollback freshness, file capabilities, and dependent validation
/// are still required by the recovery transaction that consumes it.
pub struct SelectedStableSystemRecovery<'a, const CONFIG_EXTENTS: usize, const AUTH_EXTENTS: usize>
{
    configuration: ReachableFileSelection<'a, CONFIG_EXTENTS>,
    authority_checkpoint: ReachableFileSelection<'a, AUTH_EXTENTS>,
}

impl<'a, const CONFIG_EXTENTS: usize, const AUTH_EXTENTS: usize>
    SelectedStableSystemRecovery<'a, CONFIG_EXTENTS, AUTH_EXTENTS>
{
    pub fn new(
        configuration: ReachableFileSelection<'a, CONFIG_EXTENTS>,
        authority_checkpoint: ReachableFileSelection<'a, AUTH_EXTENTS>,
    ) -> Result<Self, SelectedStableSystemRecoveryError> {
        if configuration.volume() != authority_checkpoint.volume()
            || configuration.root_generation() != authority_checkpoint.root_generation()
        {
            return Err(SelectedStableSystemRecoveryError::RootMismatch);
        }
        if configuration.object() == authority_checkpoint.object() {
            return Err(SelectedStableSystemRecoveryError::DuplicateObject);
        }
        Ok(Self {
            configuration,
            authority_checkpoint,
        })
    }

    pub const fn volume(&self) -> VolumeId {
        self.configuration.volume()
    }

    pub const fn root_generation(&self) -> u64 {
        self.configuration.root_generation()
    }

    pub const fn configuration(&self) -> ReachableFileSelection<'a, CONFIG_EXTENTS> {
        self.configuration
    }

    pub const fn authority_checkpoint(&self) -> ReachableFileSelection<'a, AUTH_EXTENTS> {
        self.authority_checkpoint
    }
}

/// Exact configuration, authority, deployment-checkpoint, and SystemRelease
/// selections from one integrity-validated installed root.
pub struct SelectedStableTotalSystemRecovery<'a, const EXTENTS: usize> {
    configuration: ReachableFileSelection<'a, EXTENTS>,
    authority_checkpoint: ReachableFileSelection<'a, EXTENTS>,
    deployment_checkpoint: ReachableFileSelection<'a, EXTENTS>,
    system_release: ReachableFileSelection<'a, EXTENTS>,
}

impl<'a, const EXTENTS: usize> SelectedStableTotalSystemRecovery<'a, EXTENTS> {
    pub fn new(
        configuration: ReachableFileSelection<'a, EXTENTS>,
        authority_checkpoint: ReachableFileSelection<'a, EXTENTS>,
        deployment_checkpoint: ReachableFileSelection<'a, EXTENTS>,
        system_release: ReachableFileSelection<'a, EXTENTS>,
    ) -> Result<Self, SelectedStableSystemRecoveryError> {
        let selections = [
            configuration,
            authority_checkpoint,
            deployment_checkpoint,
            system_release,
        ];
        for selection in &selections[1..] {
            if selection.volume() != configuration.volume()
                || selection.root_generation() != configuration.root_generation()
            {
                return Err(SelectedStableSystemRecoveryError::RootMismatch);
            }
        }
        for (index, selection) in selections.iter().enumerate() {
            if selections[..index]
                .iter()
                .any(|present| present.object() == selection.object())
            {
                return Err(SelectedStableSystemRecoveryError::DuplicateObject);
            }
        }
        Ok(Self {
            configuration,
            authority_checkpoint,
            deployment_checkpoint,
            system_release,
        })
    }

    pub const fn volume(&self) -> VolumeId {
        self.configuration.volume()
    }

    pub const fn root_generation(&self) -> u64 {
        self.configuration.root_generation()
    }

    pub const fn configuration(&self) -> ReachableFileSelection<'a, EXTENTS> {
        self.configuration
    }

    pub const fn authority_checkpoint(&self) -> ReachableFileSelection<'a, EXTENTS> {
        self.authority_checkpoint
    }

    pub const fn deployment_checkpoint(&self) -> ReachableFileSelection<'a, EXTENTS> {
        self.deployment_checkpoint
    }

    pub const fn system_release(&self) -> ReachableFileSelection<'a, EXTENTS> {
        self.system_release
    }
}

/// Recovers deployment state and reads its active SystemRelease only through
/// the two exact file generations selected from the same installed root as the
/// configuration and authority checkpoint. The selection is provenance, not
/// authority; both independent file capabilities remain mandatory.
#[allow(clippy::too_many_arguments)]
pub fn recover_selected_runtime_assignment<
    'release,
    const CANDIDATES: usize,
    const DOMAINS: usize,
    const CAPS: usize,
    const EXTENTS: usize,
    const CHECKPOINT_AUTHORITIES: usize,
    const RELEASE_AUTHORITIES: usize,
    CB: FileReadBackend,
    RB: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    selected: SelectedStableTotalSystemRecovery<'_, EXTENTS>,
    checkpoint_authority: &StorageAuthorityTable<CHECKPOINT_AUTHORITIES>,
    checkpoint_handle: StorageHandle,
    release_authority: &StorageAuthorityTable<RELEASE_AUTHORITIES>,
    release_handle: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    checkpoint_backend: &mut CB,
    release_backend: &mut RB,
    capabilities: &CapabilitySpace<CAPS>,
    inspect: Capability,
    output: &'release mut [u8],
    policy_generation: u64,
) -> Result<
    RecoveredRuntimeAssignment<'release, CANDIDATES, DOMAINS>,
    RecoveredRuntimeAssignmentError<CB::Error, RB::Error, S::Error>,
> {
    recover_and_read_runtime_assignment::<
        CANDIDATES,
        DOMAINS,
        CAPS,
        EXTENTS,
        EXTENTS,
        CHECKPOINT_AUTHORITIES,
        RELEASE_AUTHORITIES,
        _,
        _,
        _,
    >(
        root,
        selected.deployment_checkpoint().file_state(),
        checkpoint_authority,
        checkpoint_handle,
        selected.system_release().file_state(),
        release_authority,
        release_handle,
        principal,
        state_store,
        checkpoint_backend,
        release_backend,
        capabilities,
        inspect,
        output,
        policy_generation,
    )
}

/// Shared-volume form of [`recover_selected_runtime_assignment`]. The
/// deployment checkpoint and SystemRelease still require distinct file
/// capabilities, while their selected extents are read sequentially through
/// the one recovered block-volume backend.
#[allow(clippy::too_many_arguments)]
pub fn recover_selected_runtime_assignment_shared_backend<
    'release,
    const CANDIDATES: usize,
    const DOMAINS: usize,
    const CAPS: usize,
    const EXTENTS: usize,
    const CHECKPOINT_AUTHORITIES: usize,
    const RELEASE_AUTHORITIES: usize,
    B: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    selected: SelectedStableTotalSystemRecovery<'_, EXTENTS>,
    checkpoint_authority: &StorageAuthorityTable<CHECKPOINT_AUTHORITIES>,
    checkpoint_handle: StorageHandle,
    release_authority: &StorageAuthorityTable<RELEASE_AUTHORITIES>,
    release_handle: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    backend: &mut B,
    capabilities: &CapabilitySpace<CAPS>,
    inspect: Capability,
    output: &'release mut [u8],
    policy_generation: u64,
) -> Result<
    RecoveredRuntimeAssignment<'release, CANDIDATES, DOMAINS>,
    RecoveredRuntimeAssignmentError<B::Error, B::Error, S::Error>,
> {
    recover_and_read_runtime_assignment_shared_backend::<
        CANDIDATES,
        DOMAINS,
        CAPS,
        EXTENTS,
        EXTENTS,
        CHECKPOINT_AUTHORITIES,
        RELEASE_AUTHORITIES,
        _,
        _,
    >(
        root,
        selected.deployment_checkpoint().file_state(),
        checkpoint_authority,
        checkpoint_handle,
        selected.system_release().file_state(),
        release_authority,
        release_handle,
        principal,
        state_store,
        backend,
        capabilities,
        inspect,
        output,
        policy_generation,
    )
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
    policy_capability: Capability,
    authority_epoch: u64,
}

pub struct RecoveredSystemState<const GRANTS: usize, const SETTINGS: usize, const AUDIT: usize> {
    authorities: CommittedRecoveredStorageAuthorities<GRANTS>,
    configuration: ConfigurationService<SETTINGS, AUDIT>,
    service: ServiceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDomainPolicyBinding<'a> {
    package_id: &'a str,
    setting: IsolationPolicySetting,
    read: Capability,
    host_substrate_reason: Option<HostSubstrateReason>,
}

impl<'a> RuntimeDomainPolicyBinding<'a> {
    pub const fn new(
        package_id: &'a str,
        setting: IsolationPolicySetting,
        read: Capability,
    ) -> Result<Self, ConfigError> {
        Self::build(package_id, setting, read, None)
    }

    pub const fn host_substrate(
        package_id: &'a str,
        setting: IsolationPolicySetting,
        read: Capability,
        reason: HostSubstrateReason,
    ) -> Result<Self, ConfigError> {
        Self::build(package_id, setting, read, Some(reason))
    }

    const fn build(
        package_id: &'a str,
        setting: IsolationPolicySetting,
        read: Capability,
        host_substrate_reason: Option<HostSubstrateReason>,
    ) -> Result<Self, ConfigError> {
        if package_id.is_empty() || !matches!(setting.scope(), IsolationPolicyScope::Component) {
            return Err(ConfigError::InvalidSchema);
        }
        Ok(Self {
            package_id,
            setting,
            read,
            host_substrate_reason,
        })
    }

    pub const fn package_id(self) -> &'a str {
        self.package_id
    }

    pub const fn domain(self) -> ObjectId {
        self.setting.object()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredRuntimeDomainPolicyError {
    Configuration(ConfigError),
    Release(ReleaseInventoryError),
    PolicyGenerationMismatch,
    BindingCount,
    MissingBinding,
    DuplicateBinding,
}

/// The recovered configuration owner bound to the exact canonical boot record
/// delivered once to its service task. Retaining the record beside committed
/// recovery prevents later admission from accepting a detached replacement.
/// The record remains non-authorizing; capability, live-device, release, and
/// placement checks are still required by the operations below.
pub struct DeliveredRecoveredSystemState<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
> {
    recovered: RecoveredSystemState<GRANTS, SETTINGS, AUDIT>,
    delivered: BootRecoveryEnvelope,
}

/// Single Total-mode control-plane owner retaining both authenticated service
/// recoveries beside the only installed admission table they produced. It
/// grants no launch authority beyond the capabilities checked by the retained
/// admission owner.
pub struct RecoveredDeploymentTotalControlPlane<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const CANDIDATES: usize,
    const DOMAINS: usize,
> {
    configuration: DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT>,
    deployment: RecoveredDeploymentOwner<CANDIDATES>,
    admission: RecoveredInstalledTotalAdmission<DOMAINS>,
}

pub struct RecoveredDeploymentTotalRuntime<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const CANDIDATES: usize,
    const DOMAINS: usize,
> {
    configuration: DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT>,
    deployment: RecoveredDeploymentOwner<CANDIDATES>,
    runtime: RecoveredInstalledTotalRuntime<DOMAINS>,
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

    /// Applies one exact capability-readable component policy to every member
    /// enumerated by the authenticated active release. The assignment plan
    /// publishes atomically, and these identity decisions grant no domain
    /// capability or launch authority.
    pub fn assign_runtime_domains<
        'release,
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        &self,
        capabilities: &A,
        plan: &mut RuntimeDomainAssignmentPlan<'release, DOMAINS>,
        bindings: &[RuntimeDomainPolicyBinding<'_>],
    ) -> Result<(), RecoveredRuntimeDomainPolicyError> {
        if self.configuration.revision() == 0
            || plan.policy_generation() != self.configuration.revision()
        {
            return Err(RecoveredRuntimeDomainPolicyError::PolicyGenerationMismatch);
        }
        if bindings.len() != plan.expected_len() {
            return Err(RecoveredRuntimeDomainPolicyError::BindingCount);
        }
        for (index, binding) in bindings.iter().enumerate() {
            if bindings[..index]
                .iter()
                .any(|present| present.package_id == binding.package_id)
            {
                return Err(RecoveredRuntimeDomainPolicyError::DuplicateBinding);
            }
            binding
                .setting
                .read(&self.configuration, capabilities, binding.read)
                .and_then(PersistedIsolationPolicy::component_request)
                .map_err(RecoveredRuntimeDomainPolicyError::Configuration)?;
        }
        for package_id in plan.packages() {
            if !bindings
                .iter()
                .any(|binding| binding.package_id == package_id)
            {
                return Err(RecoveredRuntimeDomainPolicyError::MissingBinding);
            }
        }
        plan.assign_from_policy_transaction(|record| {
            let binding = bindings
                .iter()
                .find(|binding| binding.package_id == record.package_id)
                .ok_or(RecoveredRuntimeDomainPolicyError::MissingBinding)?;
            binding
                .setting
                .read(&self.configuration, capabilities, binding.read)
                .and_then(PersistedIsolationPolicy::component_request)
                .map_err(RecoveredRuntimeDomainPolicyError::Configuration)?;
            match binding.host_substrate_reason {
                Some(reason) => RuntimeDomainAssignment::host_substrate(
                    record.package_id,
                    binding.domain(),
                    reason,
                ),
                None => RuntimeDomainAssignment::new(record.package_id, binding.domain()),
            }
            .map_err(RecoveredRuntimeDomainPolicyError::Release)
        })
        .map_err(|error| match error {
            RuntimeDomainPolicyAssignmentError::Inventory(error) => {
                RecoveredRuntimeDomainPolicyError::Release(error)
            }
            RuntimeDomainPolicyAssignmentError::Decision(error) => error,
        })
    }

    /// Consumes committed recovery into an owner retaining the exact one-use
    /// service delivery. A stale or substituted recovery root fails before
    /// persistent isolation settings or release inventory can be consulted.
    pub fn bind_delivered_boot(
        self,
        delivered: BootRecoveryEnvelope,
    ) -> Result<DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT>, ConfigError> {
        self.validate_delivered_boot(delivered)?;
        Ok(DeliveredRecoveredSystemState {
            recovered: self,
            delivered,
        })
    }

    /// Checks whether a decoded one-use delivery names this exact committed
    /// recovery transaction. This is validation only and grants no authority.
    pub fn validate_delivered_boot(
        &self,
        delivered: BootRecoveryEnvelope,
    ) -> Result<(), ConfigError> {
        self.validate_delivered_recovery(delivered.recovery())
    }

    fn validate_delivered_recovery(
        &self,
        recovery: RecoveryStateMetadata,
    ) -> Result<(), ConfigError> {
        if recovery.accepted_epoch().checked_add(1) != Some(self.authorities.epoch())
            || recovery.accepted_volume() != Some(self.authorities.volume().bytes())
            || recovery.accepted_root_generation() != self.authorities.root_generation()
        {
            return Err(ConfigError::RecoveryHandoffMismatch);
        }
        Ok(())
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
        self.compose_boot_isolation_policy_from_parts(
            capabilities,
            system,
            system_read,
            component,
            component_read,
            handoff.recovery_state(),
            handoff.isolation_override(),
        )
    }

    /// Production-shaped counterpart that consumes only the typed values
    /// retained by first kernel entry. The original handoff cannot be replaced
    /// or re-decoded after `EarlyKernelContext` has admitted it.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_early_boot_isolation_policy<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        early: &EarlyKernelContext<'_>,
    ) -> Result<RecoveredBootIsolationPolicy, ConfigError> {
        self.compose_boot_isolation_policy_from_parts(
            capabilities,
            system,
            system_read,
            component,
            component_read,
            early.recovery_state(),
            early.isolation_override(),
        )
    }

    /// Service-side counterpart for the canonical record delivered exactly
    /// once from first kernel entry. Decoding the envelope grants no authority;
    /// all settings and recovered state are revalidated below.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_delivered_boot_isolation_policy<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        delivered: BootRecoveryEnvelope,
    ) -> Result<RecoveredBootIsolationPolicy, ConfigError> {
        self.compose_boot_isolation_policy_from_parts(
            capabilities,
            system,
            system_read,
            component,
            component_read,
            Some(delivered.recovery()),
            delivered.isolation_override(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compose_boot_isolation_policy_from_parts<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        recovery: Option<RecoveryStateMetadata>,
        isolation_override: Option<BootIsolationOverride>,
    ) -> Result<RecoveredBootIsolationPolicy, ConfigError> {
        let recovery = recovery.ok_or(ConfigError::RecoveryHandoffMismatch)?;
        self.validate_delivered_recovery(recovery)?;
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
            .compose_boot_override(isolation_override);
        Ok(RecoveredBootIsolationPolicy {
            effective,
            authority_epoch: self.authorities.epoch(),
            configuration_revision: self.configuration.revision(),
            configuration_service: self.service,
            boot_accepted_epoch: recovery.accepted_epoch(),
            recovery_volume: self.authorities.volume(),
            recovery_root_generation: self.authorities.root_generation(),
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

    /// Joins the exact installed-device selection recovered from this boot's
    /// decoded handoff to the release-owned Total admission transaction. The
    /// platform identity and generations are rechecked before policy or release
    /// construction, so a detached, substituted, or stale storage selection
    /// cannot authorize Total-mode launch.
    #[allow(clippy::too_many_arguments)]
    pub fn build_installed_total_boot_admission<
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
        F,
        E,
    >(
        &self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        handoff: &BootHandoff,
        build_release: F,
    ) -> Result<
        RecoveredInstalledTotalAdmission<DOMAINS>,
        RecoveredInstalledTotalAdmissionBuildError<E>,
    >
    where
        F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
    {
        let (recovery_volume, recovery_root_generation) =
            validate_installed_selection_for_handoff(installed, handoff)
                .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)?;
        let total = self
            .build_total_boot_admission(
                capabilities,
                system,
                system_read,
                component,
                component_read,
                handoff,
                build_release,
            )
            .map_err(|error| match error {
                RecoveredTotalAdmissionBuildError::Policy(error) => {
                    RecoveredInstalledTotalAdmissionBuildError::Policy(error)
                }
                RecoveredTotalAdmissionBuildError::ReleaseBuilder(error) => {
                    RecoveredInstalledTotalAdmissionBuildError::ReleaseBuilder(error)
                }
            })?;
        RecoveredInstalledTotalAdmission::bind_identity(
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        )
        .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)
    }

    /// Joins live installed recovery and release construction directly to the
    /// first-entry owner. This path cannot consume a detached replacement
    /// `BootHandoff`; all recovery and installed facts come from `early`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_early_installed_total_boot_admission<
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
        F,
        E,
    >(
        &self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        early: &EarlyKernelContext<'_>,
        build_release: F,
    ) -> Result<
        RecoveredInstalledTotalAdmission<DOMAINS>,
        RecoveredInstalledTotalAdmissionBuildError<E>,
    >
    where
        F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
    {
        let (recovery_volume, recovery_root_generation) = validate_installed_selection_for_parts(
            installed,
            early.installed_recovery(),
            early.installed_recovery_sata_route(),
        )
        .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)?;
        let policy = self
            .compose_early_boot_isolation_policy(
                capabilities,
                system,
                system_read,
                component,
                component_read,
                early,
            )
            .map_err(RecoveredInstalledTotalAdmissionBuildError::Policy)?;
        let release = build_release(policy.effective().policy_generation())
            .map_err(RecoveredInstalledTotalAdmissionBuildError::ReleaseBuilder)?;
        let total = policy
            .bind_release_inventory(release)
            .map_err(RecoveredInstalledTotalAdmissionBuildError::Policy)?;
        RecoveredInstalledTotalAdmission::bind_identity(
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        )
        .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)
    }

    /// Service-side installed Total join from the one-use canonical delivery.
    /// Neither package metadata nor the envelope grants storage or placement
    /// authority; the same live selection, capability, policy, release, and
    /// admission checks remain mandatory.
    #[allow(clippy::too_many_arguments)]
    pub fn build_delivered_installed_total_boot_admission<
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
        F,
        E,
    >(
        &self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        delivered: BootRecoveryEnvelope,
        build_release: F,
    ) -> Result<
        RecoveredInstalledTotalAdmission<DOMAINS>,
        RecoveredInstalledTotalAdmissionBuildError<E>,
    >
    where
        F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
    {
        let (recovery_volume, recovery_root_generation) = validate_installed_selection_for_parts(
            installed,
            delivered.installed(),
            delivered.sata_route(),
        )
        .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)?;
        let policy = self
            .compose_delivered_boot_isolation_policy(
                capabilities,
                system,
                system_read,
                component,
                component_read,
                delivered,
            )
            .map_err(RecoveredInstalledTotalAdmissionBuildError::Policy)?;
        let release = build_release(policy.effective().policy_generation())
            .map_err(RecoveredInstalledTotalAdmissionBuildError::ReleaseBuilder)?;
        let total = policy
            .bind_release_inventory(release)
            .map_err(RecoveredInstalledTotalAdmissionBuildError::Policy)?;
        RecoveredInstalledTotalAdmission::bind_identity(
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        )
        .map_err(RecoveredInstalledTotalAdmissionBuildError::Installed)
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

impl<const GRANTS: usize, const SETTINGS: usize, const AUDIT: usize>
    DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT>
{
    pub const fn recovered(&self) -> &RecoveredSystemState<GRANTS, SETTINGS, AUDIT> {
        &self.recovered
    }

    pub const fn delivered(&self) -> BootRecoveryEnvelope {
        self.delivered
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compose_boot_isolation_policy<A: CapabilityAuthorizer + ?Sized>(
        &self,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
    ) -> Result<RecoveredBootIsolationPolicy, ConfigError> {
        self.recovered.compose_delivered_boot_isolation_policy(
            capabilities,
            system,
            system_read,
            component,
            component_read,
            self.delivered,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_installed_total_boot_admission<
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
        F,
        E,
    >(
        &self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        build_release: F,
    ) -> Result<
        RecoveredInstalledTotalAdmission<DOMAINS>,
        RecoveredInstalledTotalAdmissionBuildError<E>,
    >
    where
        F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
    {
        self.recovered
            .build_delivered_installed_total_boot_admission(
                installed,
                capabilities,
                system,
                system_read,
                component,
                component_read,
                self.delivered,
                build_release,
            )
    }

    /// Completes the production-shaped delivered Total control-plane join
    /// without accepting a detached release builder. Installed recovery,
    /// effective boot policy, every capability-readable package assignment,
    /// authenticated release identity, and the only admission table either
    /// bind together or produce no admission owner.
    #[allow(clippy::too_many_arguments)]
    pub fn build_assigned_installed_total_boot_admission<
        'release,
        const DOMAINS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        &self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        mut plan: RuntimeDomainAssignmentPlan<'release, DOMAINS>,
        bindings: &[RuntimeDomainPolicyBinding<'_>],
    ) -> Result<RecoveredInstalledTotalAdmission<DOMAINS>, RecoveredAssignedTotalAdmissionError>
    {
        let (recovery_volume, recovery_root_generation) = validate_installed_selection_for_parts(
            installed,
            self.delivered.installed(),
            self.delivered.sata_route(),
        )
        .map_err(RecoveredAssignedTotalAdmissionError::Installed)?;
        let policy = self
            .compose_boot_isolation_policy(
                capabilities,
                system,
                system_read,
                component,
                component_read,
            )
            .map_err(RecoveredAssignedTotalAdmissionError::Policy)?;
        if plan.policy_generation() != policy.effective().policy_generation() {
            return Err(RecoveredAssignedTotalAdmissionError::Assignment(
                RecoveredRuntimeDomainPolicyError::PolicyGenerationMismatch,
            ));
        }
        self.recovered
            .assign_runtime_domains(capabilities, &mut plan, bindings)
            .map_err(RecoveredAssignedTotalAdmissionError::Assignment)?;
        let release = plan
            .seal()
            .map_err(RecoveredAssignedTotalAdmissionError::Release)?;
        let total = policy
            .bind_release_inventory(release)
            .map_err(RecoveredAssignedTotalAdmissionError::Policy)?;
        RecoveredInstalledTotalAdmission::bind_identity(
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        )
        .map_err(RecoveredAssignedTotalAdmissionError::Installed)
    }

    /// Consumes the authenticated deployment owner and its exact active-release
    /// assignment into one retained control-plane owner. Failure publishes no
    /// admission and cannot leave a detached sealed release behind.
    #[allow(clippy::too_many_arguments)]
    pub fn build_recovered_deployment_total_control_plane<
        'release,
        const CANDIDATES: usize,
        const DOMAINS: usize,
        const DEPLOYMENT_CAPS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        installed: InstalledRecoveryDeviceSelection,
        capabilities: &A,
        system: IsolationPolicySetting,
        system_read: Capability,
        component: IsolationPolicySetting,
        component_read: Capability,
        mut deployment: RecoveredRuntimeAssignment<'release, CANDIDATES, DOMAINS>,
        deployment_capabilities: &CapabilitySpace<DEPLOYMENT_CAPS>,
        bindings: &[RuntimeDomainPolicyBinding<'_>],
    ) -> Result<
        RecoveredDeploymentTotalControlPlane<GRANTS, SETTINGS, AUDIT, CANDIDATES, DOMAINS>,
        RecoveredAssignedTotalAdmissionError,
    > {
        let (recovery_volume, recovery_root_generation) = validate_installed_selection_for_parts(
            installed,
            self.delivered.installed(),
            self.delivered.sata_route(),
        )
        .map_err(RecoveredAssignedTotalAdmissionError::Installed)?;
        let policy = self
            .compose_boot_isolation_policy(
                capabilities,
                system,
                system_read,
                component,
                component_read,
            )
            .map_err(RecoveredAssignedTotalAdmissionError::Policy)?;
        if deployment.assignment().policy_generation() != policy.effective().policy_generation() {
            return Err(RecoveredAssignedTotalAdmissionError::Assignment(
                RecoveredRuntimeDomainPolicyError::PolicyGenerationMismatch,
            ));
        }
        self.recovered
            .assign_runtime_domains(capabilities, deployment.assignment_mut(), bindings)
            .map_err(RecoveredAssignedTotalAdmissionError::Assignment)?;
        let deployment = deployment
            .seal(deployment_capabilities)
            .map_err(|error| match error {
                mrml_deployment::RecoveredRuntimeAssignmentSealError::Deployment(error) => {
                    RecoveredAssignedTotalAdmissionError::Deployment(error)
                }
                mrml_deployment::RecoveredRuntimeAssignmentSealError::Release(error) => {
                    RecoveredAssignedTotalAdmissionError::Release(error)
                }
            })?;
        let (deployment, release) = deployment.into_parts();
        let total = policy
            .bind_release_inventory(release)
            .map_err(RecoveredAssignedTotalAdmissionError::Policy)?;
        let admission = RecoveredInstalledTotalAdmission::bind_identity(
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        )
        .map_err(RecoveredAssignedTotalAdmissionError::Installed)?;
        Ok(RecoveredDeploymentTotalControlPlane {
            configuration: self,
            deployment,
            admission,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        RecoveredSystemState<GRANTS, SETTINGS, AUDIT>,
        BootRecoveryEnvelope,
    ) {
        (self.recovered, self.delivered)
    }
}

impl<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const CANDIDATES: usize,
    const DOMAINS: usize,
> RecoveredDeploymentTotalControlPlane<GRANTS, SETTINGS, AUDIT, CANDIDATES, DOMAINS>
{
    pub const fn configuration(&self) -> &DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT> {
        &self.configuration
    }

    pub const fn deployment(&self) -> &RecoveredDeploymentOwner<CANDIDATES> {
        &self.deployment
    }

    pub const fn installed_admission(&self) -> &RecoveredInstalledTotalAdmission<DOMAINS> {
        &self.admission
    }

    pub const fn policy(&self) -> RecoveredBootIsolationPolicy {
        self.admission.policy()
    }

    pub const fn admission(&self) -> &IsolationAdmissionTable<DOMAINS> {
        self.admission.admission()
    }

    pub fn admission_mut(&mut self) -> &mut IsolationAdmissionTable<DOMAINS> {
        self.admission.admission_mut()
    }

    pub fn prepare_service(
        &mut self,
        bounds: IsolationServiceBounds,
        identity: IsolationServiceIdentity,
    ) -> Result<PreparedIsolationServiceRoute, ConfiguredIsolationPreparationError> {
        self.admission.prepare_service(bounds, identity)
    }

    pub fn prepare_complete_service_set(
        &mut self,
        bindings: &[TotalServicePreparationBinding],
    ) -> Result<PreparedTotalServiceSet<DOMAINS>, CompleteTotalServicePreparationError> {
        self.admission.prepare_complete_service_set(bindings)
    }

    pub fn authorize_runtime(
        self,
    ) -> Result<
        RecoveredDeploymentTotalRuntime<GRANTS, SETTINGS, AUDIT, CANDIDATES, DOMAINS>,
        mrml_kernel::TotalMicrovmRuntimeError,
    > {
        let runtime = self.admission.authorize_runtime()?;
        Ok(RecoveredDeploymentTotalRuntime {
            configuration: self.configuration,
            deployment: self.deployment,
            runtime,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT>,
        RecoveredDeploymentOwner<CANDIDATES>,
        RecoveredInstalledTotalAdmission<DOMAINS>,
    ) {
        (self.configuration, self.deployment, self.admission)
    }
}

impl<
    const GRANTS: usize,
    const SETTINGS: usize,
    const AUDIT: usize,
    const CANDIDATES: usize,
    const DOMAINS: usize,
> RecoveredDeploymentTotalRuntime<GRANTS, SETTINGS, AUDIT, CANDIDATES, DOMAINS>
{
    pub const fn configuration(&self) -> &DeliveredRecoveredSystemState<GRANTS, SETTINGS, AUDIT> {
        &self.configuration
    }

    pub const fn deployment(&self) -> &RecoveredDeploymentOwner<CANDIDATES> {
        &self.deployment
    }

    pub const fn installed(&self) -> InstalledRecoveryDeviceSelection {
        self.runtime.installed()
    }

    pub const fn admission(&self) -> &IsolationAdmissionTable<DOMAINS> {
        self.runtime.admission()
    }

    pub const fn proof(&self) -> &mrml_kernel::TotalMicrovmRuntimeProof {
        self.runtime.proof()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredTotalAdmissionBuildError<E> {
    Policy(ConfigError),
    ReleaseBuilder(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredInstalledTotalAdmissionBuildError<E> {
    Installed(ConfigError),
    Policy(ConfigError),
    ReleaseBuilder(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredAssignedTotalAdmissionError {
    Installed(ConfigError),
    Policy(ConfigError),
    Deployment(mrml_deployment::DeploymentError),
    Assignment(RecoveredRuntimeDomainPolicyError),
    Release(ReleaseInventoryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredSystemCommitError {
    AuthorityEpochMismatch,
    Policy(PersistedRestartPolicyError),
    Service(ServiceError),
}

impl<const SETTINGS: usize, const AUDIT: usize> PreparedRecoveredService<SETTINGS, AUDIT> {
    pub fn commit<
        const GRANTS: usize,
        const SERVICES: usize,
        const TASKS: usize,
        const CAPS: usize,
        A: CapabilityAuthorizer + ?Sized,
    >(
        self,
        authorities: CommittedRecoveredStorageAuthorities<GRANTS>,
        capabilities: &A,
        supervisor: &mut ServiceSupervisor<SERVICES>,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<RecoveredSystemState<GRANTS, SETTINGS, AUDIT>, RecoveredSystemCommitError> {
        if authorities.epoch() != self.authority_epoch {
            return Err(RecoveredSystemCommitError::AuthorityEpochMismatch);
        }
        let refreshed = self
            .recovered
            .policy
            .plan_registration(
                &self.recovered.configuration,
                capabilities,
                self.policy_capability,
                supervisor,
                self.registration.task(),
            )
            .map_err(RecoveredSystemCommitError::Policy)?;
        if refreshed != self.registration {
            return Err(RecoveredSystemCommitError::Policy(
                PersistedRestartPolicyError::PolicyChanged,
            ));
        }
        let service = supervisor
            .commit_registration_with_runtime(self.registration, runtime)
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
            policy_capability: self.configuration.policy_capability,
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
    recovery_volume: VolumeId,
    recovery_root_generation: u64,
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

    pub const fn recovery_volume(self) -> VolumeId {
        self.recovery_volume
    }

    pub const fn recovery_root_generation(self) -> u64 {
        self.recovery_root_generation
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotalServicePreparationBinding {
    bounds: IsolationServiceBounds,
    identity: IsolationServiceIdentity,
}

impl TotalServicePreparationBinding {
    pub const fn new(bounds: IsolationServiceBounds, identity: IsolationServiceIdentity) -> Self {
        Self { bounds, identity }
    }

    pub const fn domain(self) -> ObjectId {
        self.identity.domain()
    }
}

pub struct PreparedTotalServiceSet<const DOMAINS: usize> {
    routes: [Option<PreparedIsolationServiceRoute>; DOMAINS],
    expected_domains: [Option<ObjectId>; DOMAINS],
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteTotalServiceRestoreError {
    UnexpectedDomain,
    AlreadyPresent,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TotalServiceEndpointBinding<E> {
    domain: ObjectId,
    endpoint: E,
}

impl<E> TotalServiceEndpointBinding<E> {
    pub const fn new(domain: ObjectId, endpoint: E) -> Self {
        Self { domain, endpoint }
    }

    pub const fn domain(&self) -> ObjectId {
        self.domain
    }

    pub fn into_endpoint(self) -> E {
        self.endpoint
    }
}

pub struct RoutedTotalServiceSet<E, const DOMAINS: usize> {
    routes: [Option<RoutedIsolationService<E>>; DOMAINS],
    count: usize,
}

impl<E, const DOMAINS: usize> RoutedTotalServiceSet<E, DOMAINS> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn take(&mut self, domain: ObjectId) -> Option<RoutedIsolationService<E>> {
        let route = self
            .routes
            .iter_mut()
            .find(|route| route.as_ref().is_some_and(|route| route.domain() == domain))
            .and_then(Option::take);
        if route.is_some() {
            self.count -= 1;
        }
        route
    }

    pub fn into_endpoints(self) -> [Option<TotalServiceEndpointBinding<E>>; DOMAINS] {
        self.routes.map(|route| {
            route.map(|route| {
                let domain = route.domain();
                TotalServiceEndpointBinding::new(domain, route.into_endpoint())
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteTotalServiceCommitError {
    BindingCount,
    DuplicateDomain,
    MissingDomain,
    Admission(mrml_kernel::IsolationLaunchError),
    Rollback(mrml_kernel::IsolationLaunchError),
}

#[derive(Debug)]
pub struct CompleteTotalServiceCommitFailure<E, const DOMAINS: usize> {
    error: CompleteTotalServiceCommitError,
    endpoints: [Option<TotalServiceEndpointBinding<E>>; DOMAINS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteTotalServiceConstructionError<E> {
    IncompleteSet,
    Construction(E),
    Rollback(mrml_kernel::IsolationLaunchError),
}

#[derive(Debug)]
pub struct CompleteTotalServiceConstructionFailure<E, X, const DOMAINS: usize> {
    error: CompleteTotalServiceConstructionError<E>,
    endpoints: [Option<TotalServiceEndpointBinding<X>>; DOMAINS],
}

impl<E, X, const DOMAINS: usize> CompleteTotalServiceConstructionFailure<E, X, DOMAINS> {
    pub const fn error(&self) -> &CompleteTotalServiceConstructionError<E> {
        &self.error
    }

    pub fn into_endpoints(self) -> [Option<TotalServiceEndpointBinding<X>>; DOMAINS] {
        self.endpoints
    }
}

impl<E, const DOMAINS: usize> CompleteTotalServiceCommitFailure<E, DOMAINS> {
    pub const fn error(&self) -> CompleteTotalServiceCommitError {
        self.error
    }

    pub fn into_endpoints(self) -> [Option<TotalServiceEndpointBinding<E>>; DOMAINS] {
        self.endpoints
    }
}

impl<const DOMAINS: usize> PreparedTotalServiceSet<DOMAINS> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn spec(&self, domain: ObjectId) -> Option<mrml_kernel::IsolationServiceSpec> {
        self.routes
            .iter()
            .flatten()
            .find(|route| route.spec().domain() == domain)
            .map(PreparedIsolationServiceRoute::spec)
    }

    pub fn take(&mut self, domain: ObjectId) -> Option<PreparedIsolationServiceRoute> {
        let route = self
            .routes
            .iter_mut()
            .find(|route| {
                route
                    .as_ref()
                    .is_some_and(|route| route.spec().domain() == domain)
            })
            .and_then(Option::take);
        if route.is_some() {
            self.count -= 1;
        }
        route
    }

    /// Restores the same still-prepared domain after an artifact- or
    /// backend-binding transformation. The expected complete membership is
    /// retained independently of the temporarily empty route slot, preventing
    /// callers from substituting or silently dropping a domain before atomic
    /// publication.
    pub fn restore(
        &mut self,
        route: PreparedIsolationServiceRoute,
    ) -> Result<
        (),
        (
            CompleteTotalServiceRestoreError,
            PreparedIsolationServiceRoute,
        ),
    > {
        let domain = route.spec().domain();
        if !self.expected_domains.contains(&Some(domain)) {
            return Err((CompleteTotalServiceRestoreError::UnexpectedDomain, route));
        }
        if self
            .routes
            .iter()
            .flatten()
            .any(|present| present.spec().domain() == domain)
        {
            return Err((CompleteTotalServiceRestoreError::AlreadyPresent, route));
        }
        let Some(slot) = self
            .expected_domains
            .iter()
            .position(|expected| *expected == Some(domain))
        else {
            unreachable!("expected domain membership checked above");
        };
        if self.routes[slot].is_some() {
            return Err((CompleteTotalServiceRestoreError::AlreadyPresent, route));
        }
        self.routes[slot] = Some(route);
        self.count += 1;
        Ok(())
    }

    pub fn into_routes(self) -> [Option<PreparedIsolationServiceRoute>; DOMAINS] {
        self.routes
    }

    /// Constructs one backend endpoint for every exact prepared domain before
    /// any route is published. A late construction failure returns all earlier
    /// endpoints to the caller for backend teardown and cancels every prepared
    /// route still owned by the set, so no running domain or stranded admission
    /// slot remains.
    pub fn construct_complete_endpoints<E, X, F>(
        self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
        mut construct: F,
    ) -> Result<
        (Self, [Option<TotalServiceEndpointBinding<X>>; DOMAINS]),
        CompleteTotalServiceConstructionFailure<E, X, DOMAINS>,
    >
    where
        F: FnMut(mrml_kernel::IsolationServiceSpec) -> Result<X, E>,
    {
        let mut endpoints: [Option<TotalServiceEndpointBinding<X>>; DOMAINS] =
            [const { None }; DOMAINS];
        if self.count != self.expected_domains.iter().flatten().count()
            || self
                .expected_domains
                .iter()
                .zip(&self.routes)
                .any(|(expected, route)| expected.is_some() != route.is_some())
        {
            let mut error = CompleteTotalServiceConstructionError::IncompleteSet;
            for route in self.routes.into_iter().rev().flatten() {
                if let Err(rollback) = route.cancel(admission) {
                    error = CompleteTotalServiceConstructionError::Rollback(rollback);
                }
            }
            return Err(CompleteTotalServiceConstructionFailure { error, endpoints });
        }
        for (index, route) in self.routes.iter().enumerate() {
            let Some(route) = route.as_ref() else {
                continue;
            };
            let spec = route.spec();
            match construct(spec) {
                Ok(endpoint) => {
                    endpoints[index] =
                        Some(TotalServiceEndpointBinding::new(spec.domain(), endpoint));
                }
                Err(construction) => {
                    let mut error =
                        CompleteTotalServiceConstructionError::Construction(construction);
                    for route in self.routes.into_iter().rev().flatten() {
                        if let Err(rollback) = route.cancel(admission) {
                            if !matches!(error, CompleteTotalServiceConstructionError::Rollback(_))
                            {
                                error = CompleteTotalServiceConstructionError::Rollback(rollback);
                            }
                        }
                    }
                    return Err(CompleteTotalServiceConstructionFailure { error, endpoints });
                }
            }
        }
        Ok((self, endpoints))
    }

    /// Publishes one already-constructed endpoint for every prepared unique
    /// domain as a single fail-closed transaction. Endpoint identity remains
    /// non-authorizing: the exact prepared route and its admission owner still
    /// establish placement authority. Validation failure cancels every route;
    /// a later commit failure retires every earlier running domain in reverse
    /// order and returns all concrete endpoints for backend teardown.
    pub fn commit_complete<E>(
        mut self,
        admission: &mut IsolationAdmissionTable<DOMAINS>,
        mut endpoints: [Option<TotalServiceEndpointBinding<E>>; DOMAINS],
    ) -> Result<RoutedTotalServiceSet<E, DOMAINS>, CompleteTotalServiceCommitFailure<E, DOMAINS>>
    {
        let endpoint_count = endpoints.iter().flatten().count();
        let mut validation_error = if endpoint_count != self.count {
            Some(CompleteTotalServiceCommitError::BindingCount)
        } else {
            None
        };
        for (index, binding) in endpoints.iter().enumerate() {
            let Some(binding) = binding else { continue };
            if endpoints[..index]
                .iter()
                .flatten()
                .any(|present| present.domain == binding.domain)
            {
                validation_error = Some(CompleteTotalServiceCommitError::DuplicateDomain);
                break;
            }
            if !self.routes.iter().flatten().any(|route| {
                route.spec().domain() == binding.domain
                    && route.spec().placement() == IsolationPlacement::Microvm
            }) {
                validation_error = Some(CompleteTotalServiceCommitError::MissingDomain);
                break;
            }
        }
        if validation_error.is_none()
            && self.routes.iter().flatten().any(|route| {
                !endpoints
                    .iter()
                    .flatten()
                    .any(|binding| binding.domain == route.spec().domain())
            })
        {
            validation_error = Some(CompleteTotalServiceCommitError::MissingDomain);
        }
        if let Some(mut error) = validation_error {
            for route in self.routes.into_iter().rev().flatten() {
                if let Err(rollback) = route.cancel(admission) {
                    if !matches!(error, CompleteTotalServiceCommitError::Rollback(_)) {
                        error = CompleteTotalServiceCommitError::Rollback(rollback);
                    }
                }
            }
            return Err(CompleteTotalServiceCommitFailure { error, endpoints });
        }

        let mut routed: [Option<RoutedIsolationService<E>>; DOMAINS] = [const { None }; DOMAINS];
        let mut endpoint_slots: [Option<usize>; DOMAINS] = [None; DOMAINS];
        let mut committed = 0usize;
        for index in 0..DOMAINS {
            let Some(route) = self.routes[index].take() else {
                continue;
            };
            let domain = route.spec().domain();
            let endpoint_index = endpoints
                .iter()
                .position(|binding| {
                    binding
                        .as_ref()
                        .is_some_and(|binding| binding.domain == domain)
                })
                .expect("complete endpoint validation");
            let endpoint = endpoints[endpoint_index]
                .take()
                .expect("located endpoint binding")
                .endpoint;
            endpoint_slots[index] = Some(endpoint_index);
            match route.commit(admission, endpoint) {
                Ok(active) => {
                    routed[index] = Some(active);
                    committed += 1;
                }
                Err((failed_route, admission_error, endpoint)) => {
                    endpoints[endpoint_index] =
                        Some(TotalServiceEndpointBinding::new(domain, endpoint));
                    let mut error = CompleteTotalServiceCommitError::Admission(admission_error);
                    if let Err(rollback) = failed_route.cancel(admission) {
                        error = CompleteTotalServiceCommitError::Rollback(rollback);
                    }
                    for prior in (0..index).rev() {
                        if let Some(active) = routed[prior].take() {
                            let prior_domain = active.domain();
                            let prior_endpoint = active.into_endpoint();
                            let prior_endpoint_index = endpoint_slots[prior]
                                .expect("committed endpoint retains its source slot");
                            endpoints[prior_endpoint_index] = Some(
                                TotalServiceEndpointBinding::new(prior_domain, prior_endpoint),
                            );
                            if let Err(rollback) = admission.retire(prior_domain) {
                                if !matches!(error, CompleteTotalServiceCommitError::Rollback(_)) {
                                    error = CompleteTotalServiceCommitError::Rollback(rollback);
                                }
                            }
                        }
                    }
                    for remaining in self.routes.into_iter().skip(index + 1).flatten() {
                        if let Err(rollback) = remaining.cancel(admission) {
                            if !matches!(error, CompleteTotalServiceCommitError::Rollback(_)) {
                                error = CompleteTotalServiceCommitError::Rollback(rollback);
                            }
                        }
                    }
                    return Err(CompleteTotalServiceCommitFailure { error, endpoints });
                }
            }
        }
        Ok(RoutedTotalServiceSet {
            routes: routed,
            count: committed,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompleteTotalServicePreparationError {
    BindingCount,
    DuplicateDomain,
    MissingDomain,
    ClassMismatch,
    Preparation(ConfiguredIsolationPreparationError),
    Rollback(mrml_kernel::IsolationLaunchError),
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

    /// Prepares exactly one route for every unique runtime domain in the
    /// authenticated release. Multiple compatible packages may intentionally
    /// share one domain. No route set is returned unless membership and class
    /// match completely and every preparation succeeds; a later failure
    /// cancels all earlier preparations before returning.
    pub fn prepare_complete_service_set(
        &mut self,
        bindings: &[TotalServicePreparationBinding],
    ) -> Result<PreparedTotalServiceSet<DOMAINS>, CompleteTotalServicePreparationError> {
        if bindings.is_empty() || bindings.len() > DOMAINS {
            return Err(CompleteTotalServicePreparationError::BindingCount);
        }
        for (index, binding) in bindings.iter().enumerate() {
            if bindings[..index]
                .iter()
                .any(|present| present.domain() == binding.domain())
            {
                return Err(CompleteTotalServicePreparationError::DuplicateDomain);
            }
            let mut matched = false;
            for entry in self.release.release().entries() {
                if entry.domain() == binding.domain() {
                    if entry.class() != binding.identity.class() {
                        return Err(CompleteTotalServicePreparationError::ClassMismatch);
                    }
                    matched = true;
                }
            }
            if !matched {
                return Err(CompleteTotalServicePreparationError::MissingDomain);
            }
        }
        for entry in self.release.release().entries() {
            if !bindings
                .iter()
                .any(|binding| binding.domain() == entry.domain())
            {
                return Err(CompleteTotalServicePreparationError::MissingDomain);
            }
        }

        let mut routes = array::from_fn(|_| None);
        let mut count = 0;
        for binding in bindings {
            match self.prepare_service(binding.bounds, binding.identity) {
                Ok(route) => {
                    routes[count] = Some(route);
                    count += 1;
                }
                Err(error) => {
                    for route in routes[..count].iter_mut().rev().filter_map(Option::take) {
                        route
                            .cancel(&mut self.admission)
                            .map_err(CompleteTotalServicePreparationError::Rollback)?;
                    }
                    return Err(CompleteTotalServicePreparationError::Preparation(error));
                }
            }
        }
        let mut expected_domains = [None; DOMAINS];
        for (index, binding) in bindings.iter().enumerate() {
            expected_domains[index] = Some(binding.domain());
        }
        Ok(PreparedTotalServiceSet {
            routes,
            expected_domains,
            count,
        })
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

/// Installed recovery provenance retained for the complete lifetime of the
/// Total-mode admission that it authorized. This prevents early boot from
/// reducing the serviced device/session selection and recovered stable root to
/// detached scalar diagnostics before the admitted domains have completed.
pub struct RecoveredInstalledTotalAdmission<const DOMAINS: usize> {
    installed: InstalledRecoveryDeviceSelection,
    recovery_volume: VolumeId,
    recovery_root_generation: u64,
    total: RecoveredTotalAdmission<DOMAINS>,
}

/// Read-only runtime authorization produced only by consuming the complete
/// installed Total admission owner after every required domain has committed.
/// The installed storage selection, recovered policy, authenticated release,
/// admission table, and final proof remain one lifetime-bound object while
/// guests execute; callers cannot reopen preparation or mutate admission.
pub struct RecoveredInstalledTotalRuntime<const DOMAINS: usize> {
    total: RecoveredInstalledTotalAdmission<DOMAINS>,
    proof: mrml_kernel::TotalMicrovmRuntimeProof,
}

fn validate_installed_selection_for_handoff(
    installed: InstalledRecoveryDeviceSelection,
    handoff: &BootHandoff,
) -> Result<(VolumeId, u64), ConfigError> {
    validate_installed_selection_for_parts(
        installed,
        handoff.installed_recovery(),
        handoff.installed_recovery_sata_route(),
    )
}

fn validate_installed_selection_for_parts(
    installed: InstalledRecoveryDeviceSelection,
    boot: Option<InstalledRecoveryBootIdentity>,
    sata_route: Option<InstalledRecoverySataRoute>,
) -> Result<(VolumeId, u64), ConfigError> {
    let boot = boot.ok_or(ConfigError::RecoveryHandoffMismatch)?;
    if boot.source() == InstalledRecoverySource::Uefi && sata_route.is_none() {
        return Err(ConfigError::RecoveryHandoffMismatch);
    }
    let platform = installed
        .platform_identity()
        .ok_or(ConfigError::RecoveryHandoffMismatch)?;
    let transport_matches = match boot.source() {
        InstalledRecoverySource::Uefi => platform.transport() == PlatformBlockTransport::Ahci,
        InstalledRecoverySource::Ahci => platform.transport() == PlatformBlockTransport::Ahci,
        InstalledRecoverySource::Usb => platform.transport() == PlatformBlockTransport::Usb,
        InstalledRecoverySource::Virtio => platform.transport() == PlatformBlockTransport::Virtio,
        InstalledRecoverySource::Hosted => platform.transport() == PlatformBlockTransport::Hosted,
    };
    let descriptor = installed.descriptor();
    let header = installed.header();
    if !transport_matches
        || platform.stable_id() != boot.stable_id()
        || platform.controller_generation() != boot.controller_generation()
        || platform.media_generation() != boot.media_generation()
        || descriptor.block_size() != boot.block_size()
        || descriptor.block_count() != boot.block_count()
        || header.volume().bytes() != boot.volume()
        || installed.active_superblock() != boot.root_block()
    {
        return Err(ConfigError::RecoveryHandoffMismatch);
    }
    let volume = VolumeId::new(boot.volume()).map_err(|_| ConfigError::RecoveryHandoffMismatch)?;
    Ok((volume, boot.root_generation()))
}

impl<const DOMAINS: usize> RecoveredInstalledTotalAdmission<DOMAINS> {
    #[allow(dead_code)]
    fn bind<
        B: BlockServiceBackend,
        const DEVICES: usize,
        const SESSIONS: usize,
        const EXTENTS: usize,
        const OBJECTS: usize,
    >(
        recovered: &RecoveredInstalledStableSystemSelection<
            '_,
            B,
            DEVICES,
            SESSIONS,
            EXTENTS,
            OBJECTS,
        >,
        total: RecoveredTotalAdmission<DOMAINS>,
    ) -> Result<Self, ConfigError> {
        let installed = recovered.installed();
        let selected = recovered.selected();
        Self::bind_identity(
            installed,
            selected.volume(),
            selected.root_generation(),
            total,
        )
    }

    fn bind_identity(
        installed: InstalledRecoveryDeviceSelection,
        recovery_volume: VolumeId,
        recovery_root_generation: u64,
        total: RecoveredTotalAdmission<DOMAINS>,
    ) -> Result<Self, ConfigError> {
        let policy = total.policy();
        if installed.header().volume() != recovery_volume
            || recovery_volume != policy.recovery_volume()
            || recovery_root_generation != policy.recovery_root_generation()
        {
            return Err(ConfigError::RecoveryHandoffMismatch);
        }
        Ok(Self {
            installed,
            recovery_volume,
            recovery_root_generation,
            total,
        })
    }

    pub const fn installed(&self) -> InstalledRecoveryDeviceSelection {
        self.installed
    }

    pub const fn recovery_volume(&self) -> VolumeId {
        self.recovery_volume
    }

    pub const fn recovery_root_generation(&self) -> u64 {
        self.recovery_root_generation
    }

    pub const fn policy(&self) -> RecoveredBootIsolationPolicy {
        self.total.policy()
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

    pub fn prepare_complete_service_set(
        &mut self,
        bindings: &[TotalServicePreparationBinding],
    ) -> Result<PreparedTotalServiceSet<DOMAINS>, CompleteTotalServicePreparationError> {
        self.total.prepare_complete_service_set(bindings)
    }

    pub fn finalize(
        &self,
    ) -> Result<mrml_kernel::TotalMicrovmRuntimeProof, mrml_kernel::TotalMicrovmRuntimeError> {
        self.total.finalize()
    }

    pub fn authorize_runtime(
        self,
    ) -> Result<RecoveredInstalledTotalRuntime<DOMAINS>, mrml_kernel::TotalMicrovmRuntimeError>
    {
        let proof = self.finalize()?;
        Ok(RecoveredInstalledTotalRuntime { total: self, proof })
    }
}

impl<const DOMAINS: usize> RecoveredInstalledTotalRuntime<DOMAINS> {
    pub const fn installed(&self) -> InstalledRecoveryDeviceSelection {
        self.total.installed()
    }

    pub const fn policy(&self) -> RecoveredBootIsolationPolicy {
        self.total.policy()
    }

    pub const fn release(&self) -> &ActivatedReleaseTotalMicrovmInventory<DOMAINS> {
        self.total.release()
    }

    pub const fn admission(&self) -> &IsolationAdmissionTable<DOMAINS> {
        self.total.admission()
    }

    pub const fn proof(&self) -> &mrml_kernel::TotalMicrovmRuntimeProof {
        &self.proof
    }
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

    pub fn prepare_complete_service_set(
        &mut self,
        bindings: &[TotalServicePreparationBinding],
    ) -> Result<PreparedTotalServiceSet<DOMAINS>, CompleteTotalServicePreparationError> {
        self.total.prepare_complete_service_set(bindings)
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
