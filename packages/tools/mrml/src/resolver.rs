use crate::abi::{AbiError, InterfaceIdentity};
use crate::generation::{SystemGeneration, SystemPackage, mrml_package_identifier};

pub const MAX_INTERFACE_REQUIREMENTS: usize = 256;
pub const MAX_INTERFACE_PROVIDERS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderForm {
    InProcess,
    IsolatedService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceRequirement {
    consumer_package: String,
    interface: InterfaceIdentity,
    fingerprint: [u8; 32],
}

impl InterfaceRequirement {
    pub fn exact(
        consumer_package: String,
        interface: InterfaceIdentity,
        fingerprint: [u8; 32],
    ) -> Result<Self, InterfaceResolutionError> {
        validate_edge(&consumer_package, &fingerprint)?;
        Ok(Self {
            consumer_package,
            interface,
            fingerprint,
        })
    }

    pub fn consumer_package(&self) -> &str {
        &self.consumer_package
    }

    pub fn interface(&self) -> &InterfaceIdentity {
        &self.interface
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceProvider {
    provider_package: String,
    interface: InterfaceIdentity,
    fingerprint: [u8; 32],
    form: ProviderForm,
}

impl InterfaceProvider {
    pub fn exact(
        provider_package: String,
        interface: InterfaceIdentity,
        fingerprint: [u8; 32],
        form: ProviderForm,
    ) -> Result<Self, InterfaceResolutionError> {
        validate_edge(&provider_package, &fingerprint)?;
        Ok(Self {
            provider_package,
            interface,
            fingerprint,
            form,
        })
    }

    pub fn provider_package(&self) -> &str {
        &self.provider_package
    }

    pub fn interface(&self) -> &InterfaceIdentity {
        &self.interface
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn form(&self) -> ProviderForm {
        self.form
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInterfaceProvider {
    consumer: SystemPackage,
    provider: SystemPackage,
    interface: InterfaceIdentity,
    fingerprint: [u8; 32],
    form: ProviderForm,
}

impl ResolvedInterfaceProvider {
    pub fn consumer(&self) -> &SystemPackage {
        &self.consumer
    }

    pub fn provider(&self) -> &SystemPackage {
        &self.provider
    }

    pub fn interface(&self) -> &InterfaceIdentity {
        &self.interface
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn form(&self) -> ProviderForm {
        self.form
    }
}

pub fn resolve_interface_providers(
    generation: &SystemGeneration,
    requirements: &[InterfaceRequirement],
    providers: &[InterfaceProvider],
) -> Result<Vec<ResolvedInterfaceProvider>, InterfaceResolutionError> {
    if requirements.is_empty() || requirements.len() > MAX_INTERFACE_REQUIREMENTS {
        return Err(InterfaceResolutionError::RequirementCount);
    }
    if providers.is_empty() || providers.len() > MAX_INTERFACE_PROVIDERS {
        return Err(InterfaceResolutionError::ProviderCount);
    }
    if !requirements
        .windows(2)
        .all(|pair| requirement_key(&pair[0]) < requirement_key(&pair[1]))
        || !providers
            .windows(2)
            .all(|pair| provider_key(&pair[0]) < provider_key(&pair[1]))
    {
        return Err(InterfaceResolutionError::NonCanonicalOrder);
    }
    for provider in providers {
        if generation.package(&provider.provider_package).is_none() {
            return Err(InterfaceResolutionError::PackageOutsideGeneration);
        }
    }

    let mut resolved = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let consumer = generation
            .package(&requirement.consumer_package)
            .ok_or(InterfaceResolutionError::PackageOutsideGeneration)?;
        let mut matching = providers.iter().filter(|provider| {
            provider.interface == requirement.interface
                && provider.fingerprint == requirement.fingerprint
        });
        let provider = matching
            .next()
            .ok_or(InterfaceResolutionError::MissingExactProvider)?;
        if matching.next().is_some() {
            return Err(InterfaceResolutionError::AmbiguousExactProvider);
        }
        let provider_package = generation
            .package(&provider.provider_package)
            .ok_or(InterfaceResolutionError::PackageOutsideGeneration)?;
        resolved.push(ResolvedInterfaceProvider {
            consumer: consumer.clone(),
            provider: provider_package.clone(),
            interface: requirement.interface.clone(),
            fingerprint: requirement.fingerprint,
            form: provider.form,
        });
    }
    Ok(resolved)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceResolutionError {
    InvalidPackageIdentity,
    InvalidFingerprint,
    RequirementCount,
    ProviderCount,
    NonCanonicalOrder,
    PackageOutsideGeneration,
    MissingExactProvider,
    AmbiguousExactProvider,
    InvalidInterface(AbiError),
}

impl From<AbiError> for InterfaceResolutionError {
    fn from(value: AbiError) -> Self {
        Self::InvalidInterface(value)
    }
}

fn validate_edge(package: &str, fingerprint: &[u8; 32]) -> Result<(), InterfaceResolutionError> {
    if !mrml_package_identifier(package) {
        return Err(InterfaceResolutionError::InvalidPackageIdentity);
    }
    if fingerprint.iter().all(|byte| *byte == 0) {
        return Err(InterfaceResolutionError::InvalidFingerprint);
    }
    Ok(())
}

fn requirement_key(requirement: &InterfaceRequirement) -> (&str, &str, u32, [u8; 32]) {
    (
        &requirement.consumer_package,
        requirement.interface.name(),
        requirement.interface.generation(),
        requirement.fingerprint,
    )
}

fn provider_key(provider: &InterfaceProvider) -> (&str, u32, [u8; 32], &str, ProviderForm) {
    (
        provider.interface.name(),
        provider.interface.generation(),
        provider.fingerprint,
        &provider.provider_package,
        provider.form,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::SystemPackage;

    const ZSTD3: [u8; 32] = [
        106, 98, 189, 213, 148, 175, 40, 79, 81, 237, 193, 115, 74, 161, 88, 81, 229, 222, 55, 239,
        126, 33, 16, 59, 102, 84, 84, 199, 67, 226, 18, 108,
    ];

    fn package(id: &str, version: u64, marker: u8) -> SystemPackage {
        SystemPackage::new(id.into(), version, [marker; 64]).unwrap()
    }

    fn generation() -> SystemGeneration {
        SystemGeneration::new(
            108,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", 15, 0x2f),
            ],
        )
        .unwrap()
    }

    fn interface(generation: u32) -> InterfaceIdentity {
        InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), generation).unwrap()
    }

    #[test]
    fn resolves_only_exact_typed_provider_inside_generation() {
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface(3), ZSTD3).unwrap();
        let provider = InterfaceProvider::exact(
            "org.mrml.zstd".into(),
            interface(3),
            ZSTD3,
            ProviderForm::InProcess,
        )
        .unwrap();
        let result =
            resolve_interface_providers(&generation(), &[requirement], &[provider]).unwrap();
        assert_eq!(result[0].consumer().package_id(), "org.mrml.zim");
        assert_eq!(result[0].provider().package_id(), "org.mrml.zstd");
        assert_eq!(result[0].provider().version(), 15);
        assert_eq!(result[0].interface().generation(), 3);
        assert_eq!(result[0].fingerprint(), ZSTD3);
    }

    #[test]
    fn abi_generation_and_fingerprint_are_never_substituted() {
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface(3), ZSTD3).unwrap();
        let abi4 = InterfaceProvider::exact(
            "org.mrml.zstd".into(),
            interface(4),
            [4; 32],
            ProviderForm::InProcess,
        )
        .unwrap();
        assert_eq!(
            resolve_interface_providers(&generation(), std::slice::from_ref(&requirement), &[abi4]),
            Err(InterfaceResolutionError::MissingExactProvider)
        );
        let changed_fingerprint = InterfaceProvider::exact(
            "org.mrml.zstd".into(),
            interface(3),
            [9; 32],
            ProviderForm::InProcess,
        )
        .unwrap();
        assert_eq!(
            resolve_interface_providers(&generation(), &[requirement], &[changed_fingerprint]),
            Err(InterfaceResolutionError::MissingExactProvider)
        );
    }

    #[test]
    fn ambiguity_and_packages_outside_generation_fail_closed() {
        let requirement =
            InterfaceRequirement::exact("org.mrml.zim".into(), interface(3), ZSTD3).unwrap();
        let first = InterfaceProvider::exact(
            "org.mrml.zstd".into(),
            interface(3),
            ZSTD3,
            ProviderForm::InProcess,
        )
        .unwrap();
        let alternate = InterfaceProvider::exact(
            "org.mrml.zstd-alt".into(),
            interface(3),
            ZSTD3,
            ProviderForm::InProcess,
        )
        .unwrap();
        assert_eq!(
            resolve_interface_providers(
                &generation(),
                std::slice::from_ref(&requirement),
                std::slice::from_ref(&alternate)
            ),
            Err(InterfaceResolutionError::PackageOutsideGeneration)
        );
        let expanded = SystemGeneration::new(
            109,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", 15, 0x2f),
                package("org.mrml.zstd-alt", 1, 0x30),
            ],
        )
        .unwrap();
        assert_eq!(
            resolve_interface_providers(&expanded, &[requirement], &[first, alternate]),
            Err(InterfaceResolutionError::AmbiguousExactProvider)
        );
    }
}
