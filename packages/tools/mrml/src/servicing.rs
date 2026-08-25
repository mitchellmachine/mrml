use crate::binding::{BindingError, InterfaceBindingId, InterfaceBindingTable, ProviderTarget};
use crate::generation::SystemPackage;
use crate::resolver::ResolvedInterfaceProvider;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSecurityState {
    Admitted,
    Prohibited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionRoots {
    retained_system_generations: u32,
    rollback_roots: u32,
    snapshots: u32,
    exports: u32,
}

impl RetentionRoots {
    pub const fn new(
        retained_system_generations: u32,
        rollback_roots: u32,
        snapshots: u32,
        exports: u32,
    ) -> Self {
        Self {
            retained_system_generations,
            rollback_roots,
            snapshots,
            exports,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageGcPolicy {
    reclamation_enabled: bool,
}

impl PackageGcPolicy {
    pub const fn disabled() -> Self {
        Self {
            reclamation_enabled: false,
        }
    }

    pub const fn enabled() -> Self {
        Self {
            reclamation_enabled: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionBlockers(u8);

impl RetentionBlockers {
    pub const LIVE_BINDINGS: u8 = 1 << 0;
    pub const SYSTEM_GENERATIONS: u8 = 1 << 1;
    pub const ROLLBACK_ROOTS: u8 = 1 << 2;
    pub const SNAPSHOTS: u8 = 1 << 3;
    pub const EXPORTS: u8 = 1 << 4;
    pub const GC_POLICY: u8 = 1 << 5;

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, blocker: u8) -> bool {
        self.0 & blocker != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclamationDecision {
    Retain(RetentionBlockers),
    Eligible,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderInspection {
    package: SystemPackage,
    live_bindings: u32,
    roots: RetentionRoots,
    security: ProviderSecurityState,
    decision: ReclamationDecision,
}

impl ProviderInspection {
    pub fn package(&self) -> &SystemPackage {
        &self.package
    }

    pub const fn live_bindings(&self) -> u32 {
        self.live_bindings
    }

    pub const fn roots(&self) -> RetentionRoots {
        self.roots
    }

    pub const fn security(&self) -> ProviderSecurityState {
        self.security
    }

    pub const fn decision(&self) -> ReclamationDecision {
        self.decision
    }
}

pub fn inspect_provider<const N: usize>(
    package: &SystemPackage,
    bindings: &InterfaceBindingTable<N>,
    roots: RetentionRoots,
    gc_policy: PackageGcPolicy,
    security: ProviderSecurityState,
) -> ProviderInspection {
    let live_bindings = bindings
        .bindings()
        .filter(|binding| binding.provider() == package)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    let mut blockers = 0;
    if live_bindings != 0 {
        blockers |= RetentionBlockers::LIVE_BINDINGS;
    }
    if roots.retained_system_generations != 0 {
        blockers |= RetentionBlockers::SYSTEM_GENERATIONS;
    }
    if roots.rollback_roots != 0 {
        blockers |= RetentionBlockers::ROLLBACK_ROOTS;
    }
    if roots.snapshots != 0 {
        blockers |= RetentionBlockers::SNAPSHOTS;
    }
    if roots.exports != 0 {
        blockers |= RetentionBlockers::EXPORTS;
    }
    if !gc_policy.reclamation_enabled {
        blockers |= RetentionBlockers::GC_POLICY;
    }
    ProviderInspection {
        package: package.clone(),
        live_bindings,
        roots,
        security,
        decision: if blockers == 0 {
            ReclamationDecision::Eligible
        } else {
            ReclamationDecision::Retain(RetentionBlockers(blockers))
        },
    }
}

pub const fn permits_new_binding(security: ProviderSecurityState) -> bool {
    matches!(security, ProviderSecurityState::Admitted)
}

pub fn bind_admitted_provider<const N: usize>(
    bindings: &mut InterfaceBindingTable<N>,
    resolved: &ResolvedInterfaceProvider,
    target: ProviderTarget,
    security: ProviderSecurityState,
) -> Result<InterfaceBindingId, ServicingBindingError> {
    if !permits_new_binding(security) {
        return Err(ServicingBindingError::ProviderProhibited);
    }
    bindings
        .bind(resolved, target)
        .map_err(ServicingBindingError::Binding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicingBindingError {
    ProviderProhibited,
    Binding(BindingError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{AbiOpaqueHandle, InterfaceIdentity};
    use crate::binding::ProviderTarget;
    use crate::generation::SystemGeneration;
    use crate::resolver::{
        InterfaceProvider, InterfaceRequirement, ProviderForm, resolve_interface_providers,
    };

    const ZSTD3: [u8; 32] = [
        106, 98, 189, 213, 148, 175, 40, 79, 81, 237, 193, 115, 74, 161, 88, 81, 229, 222,
        55, 239, 126, 33, 16, 59, 102, 84, 84, 199, 67, 226, 18, 108,
    ];

    fn package(id: &str, version: u64, marker: u8) -> SystemPackage {
        SystemPackage::new(id.into(), version, [marker; 64]).unwrap()
    }

    fn resolved(version: u64, marker: u8) -> crate::resolver::ResolvedInterfaceProvider {
        let interface =
            InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), 3).unwrap();
        let generation = SystemGeneration::new(
            version,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", version, marker),
            ],
        )
        .unwrap();
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface.clone(), ZSTD3).unwrap();
        let provider = InterfaceProvider::exact(
            "org.mrml.zstd".into(),
            interface,
            ZSTD3,
            ProviderForm::InProcess,
        )
        .unwrap();
        resolve_interface_providers(&generation, &[requirement], &[provider])
            .unwrap()
            .remove(0)
    }

    #[test]
    fn old_and_new_providers_coexist_until_exact_live_binding_is_released() {
        let old = resolved(14, 0x2e);
        let new = resolved(15, 0x2f);
        let mut bindings = InterfaceBindingTable::<2>::new().unwrap();
        let old_id = bindings
            .bind(
                &old,
                ProviderTarget::InProcess {
                    executable: AbiOpaqueHandle::new(4, 1).unwrap(),
                    entry_operation: 1,
                },
            )
            .unwrap();
        bindings
            .bind(
                &new,
                ProviderTarget::InProcess {
                    executable: AbiOpaqueHandle::new(5, 1).unwrap(),
                    entry_operation: 1,
                },
            )
            .unwrap();

        let old_report = inspect_provider(
            old.provider(),
            &bindings,
            RetentionRoots::new(0, 0, 0, 0),
            PackageGcPolicy::enabled(),
            ProviderSecurityState::Admitted,
        );
        assert_eq!(old_report.live_bindings(), 1);
        assert!(matches!(
            old_report.decision(),
            ReclamationDecision::Retain(blockers)
                if blockers.contains(RetentionBlockers::LIVE_BINDINGS)
        ));
        bindings.release(old_id).unwrap();
        assert_eq!(
            inspect_provider(
                old.provider(),
                &bindings,
                RetentionRoots::new(0, 0, 0, 0),
                PackageGcPolicy::enabled(),
                ProviderSecurityState::Admitted,
            )
            .decision(),
            ReclamationDecision::Eligible
        );
    }

    #[test]
    fn every_durable_root_and_disabled_gc_blocks_reclamation() {
        let provider = resolved(14, 0x2e);
        let bindings = InterfaceBindingTable::<1>::new().unwrap();
        let report = inspect_provider(
            provider.provider(),
            &bindings,
            RetentionRoots::new(1, 2, 3, 4),
            PackageGcPolicy::disabled(),
            ProviderSecurityState::Admitted,
        );
        let ReclamationDecision::Retain(blockers) = report.decision() else {
            panic!("rooted provider must be retained")
        };
        assert_eq!(blockers.bits(), 0b11_1110);
    }

    #[test]
    fn prohibition_denies_new_bindings_without_erasing_retained_content() {
        let provider = resolved(14, 0x2e);
        let mut bindings = InterfaceBindingTable::<1>::new().unwrap();
        assert_eq!(
            bind_admitted_provider(
                &mut bindings,
                &provider,
                ProviderTarget::InProcess {
                    executable: AbiOpaqueHandle::new(4, 1).unwrap(),
                    entry_operation: 1,
                },
                ProviderSecurityState::Prohibited,
            ),
            Err(ServicingBindingError::ProviderProhibited)
        );
        let report = inspect_provider(
            provider.provider(),
            &bindings,
            RetentionRoots::new(0, 0, 1, 0),
            PackageGcPolicy::enabled(),
            ProviderSecurityState::Prohibited,
        );
        assert!(!permits_new_binding(report.security()));
        assert_eq!(report.package(), provider.provider());
        assert!(matches!(report.decision(), ReclamationDecision::Retain(_)));
    }
}
