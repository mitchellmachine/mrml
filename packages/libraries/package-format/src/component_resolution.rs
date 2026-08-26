use crate::{
    ActivatedSystemGeneration, ComponentServiceLaunchHandoff, ComponentServiceLaunchHandoffError,
    ComponentServicePlacement, SystemGenerationDecodeError, SystemGenerationPackage,
    SystemGenerationView,
};

pub const MAX_RUNTIME_INTERFACE_PROVIDERS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentInterfaceRequirement<'a> {
    consumer_package: &'a str,
    interface_name: &'a str,
    interface_generation: u32,
    fingerprint: [u8; 32],
}

impl<'a> ComponentInterfaceRequirement<'a> {
    pub fn exact(
        consumer_package: &'a str,
        interface_name: &'a str,
        interface_generation: u32,
        fingerprint: [u8; 32],
    ) -> Result<Self, ComponentResolutionError> {
        validate_edge(
            consumer_package,
            interface_name,
            interface_generation,
            &fingerprint,
        )?;
        Ok(Self {
            consumer_package,
            interface_name,
            interface_generation,
            fingerprint,
        })
    }

    pub const fn consumer_package(self) -> &'a str {
        self.consumer_package
    }

    pub const fn interface_name(self) -> &'a str {
        self.interface_name
    }

    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }

    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentProviderForms(u8);

impl ComponentProviderForms {
    pub const NATIVE_SERVICE: Self = Self(1 << 0);
    pub const MICROVM: Self = Self(1 << 1);
    pub const NATIVE_SERVICE_OR_MICROVM: Self = Self(Self::NATIVE_SERVICE.0 | Self::MICROVM.0);

    pub const fn from_bits(bits: u8) -> Option<Self> {
        let forms = Self(bits);
        if forms.valid() { Some(forms) } else { None }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn supports(self, placement: ComponentServicePlacement) -> bool {
        let required = match placement {
            ComponentServicePlacement::NativeService => Self::NATIVE_SERVICE.0,
            ComponentServicePlacement::Microvm => Self::MICROVM.0,
        };
        self.0 != 0 && self.0 & !Self::NATIVE_SERVICE_OR_MICROVM.0 == 0 && self.0 & required != 0
    }

    const fn valid(self) -> bool {
        self.0 != 0 && self.0 & !Self::NATIVE_SERVICE_OR_MICROVM.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentInterfaceProvider<'a> {
    provider_package: &'a str,
    interface_name: &'a str,
    interface_generation: u32,
    fingerprint: [u8; 32],
    forms: ComponentProviderForms,
}

impl<'a> ComponentInterfaceProvider<'a> {
    pub fn exact(
        provider_package: &'a str,
        interface_name: &'a str,
        interface_generation: u32,
        fingerprint: [u8; 32],
        forms: ComponentProviderForms,
    ) -> Result<Self, ComponentResolutionError> {
        validate_edge(
            provider_package,
            interface_name,
            interface_generation,
            &fingerprint,
        )?;
        if !forms.valid() {
            return Err(ComponentResolutionError::ProviderForms);
        }
        Ok(Self {
            provider_package,
            interface_name,
            interface_generation,
            fingerprint,
            forms,
        })
    }

    pub const fn provider_package(self) -> &'a str {
        self.provider_package
    }

    pub const fn interface_name(self) -> &'a str {
        self.interface_name
    }

    pub const fn interface_generation(self) -> u32 {
        self.interface_generation
    }

    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn forms(self) -> ComponentProviderForms {
        self.forms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentResolutionError {
    Generation(SystemGenerationDecodeError),
    ActiveGenerationMismatch,
    ActiveGenerationDigestMismatch,
    InvalidPackageIdentity,
    InterfaceIdentity,
    Fingerprint,
    ProviderForms,
    ProviderCount,
    NonCanonicalProviders,
    PackageOutsideGeneration,
    MissingExactProvider,
    AmbiguousExactProvider,
    LaunchHandoff(ComponentServiceLaunchHandoffError),
}

/// Resolves one exact service interface only from the authenticated active
/// `SystemGeneration` bytes and produces the immutable kernel/VMM handoff.
/// Metadata identifies candidates; this function grants no capability and does
/// not perform path, filename, or ambient library search.
#[allow(clippy::too_many_arguments)]
pub fn resolve_activated_component_service(
    active: ActivatedSystemGeneration,
    generation_bytes: &[u8],
    requirement: ComponentInterfaceRequirement<'_>,
    providers: &[ComponentInterfaceProvider<'_>],
    policy_generation: u64,
    domain_object: u64,
    interface_object: u64,
    placement: ComponentServicePlacement,
) -> Result<ComponentServiceLaunchHandoff, ComponentResolutionError> {
    let generation = SystemGenerationView::decode(generation_bytes)
        .map_err(ComponentResolutionError::Generation)?;
    if generation.generation() != active.generation() {
        return Err(ComponentResolutionError::ActiveGenerationMismatch);
    }
    if generation.digest() != *active.generation_digest() {
        return Err(ComponentResolutionError::ActiveGenerationDigestMismatch);
    }
    if providers.is_empty() || providers.len() > MAX_RUNTIME_INTERFACE_PROVIDERS {
        return Err(ComponentResolutionError::ProviderCount);
    }
    if !providers
        .windows(2)
        .all(|pair| provider_key(pair[0]) < provider_key(pair[1]))
    {
        return Err(ComponentResolutionError::NonCanonicalProviders);
    }
    let consumer = generation
        .package(requirement.consumer_package)
        .ok_or(ComponentResolutionError::PackageOutsideGeneration)?;

    let mut selected: Option<(ComponentInterfaceProvider<'_>, SystemGenerationPackage<'_>)> = None;
    for provider in providers {
        let package = generation
            .package(provider.provider_package)
            .ok_or(ComponentResolutionError::PackageOutsideGeneration)?;
        if provider.interface_name == requirement.interface_name
            && provider.interface_generation == requirement.interface_generation
            && provider.fingerprint == requirement.fingerprint
            && provider.forms.supports(placement)
        {
            if selected.is_some() {
                return Err(ComponentResolutionError::AmbiguousExactProvider);
            }
            selected = Some((*provider, package));
        }
    }
    let (_, provider) = selected.ok_or(ComponentResolutionError::MissingExactProvider)?;
    ComponentServiceLaunchHandoff::new(
        active.generation(),
        policy_generation,
        domain_object,
        interface_object,
        requirement.interface_generation,
        provider.version(),
        placement,
        *active.generation_digest(),
        *active.interface_catalog_digest(),
        requirement.fingerprint,
        *consumer.artifact_digest(),
        *provider.artifact_digest(),
    )
    .map_err(ComponentResolutionError::LaunchHandoff)
}

fn provider_key(provider: ComponentInterfaceProvider<'_>) -> (&str, &str, u32, [u8; 32], u8) {
    (
        provider.provider_package,
        provider.interface_name,
        provider.interface_generation,
        provider.fingerprint,
        provider.forms.0,
    )
}

fn validate_edge(
    package: &str,
    interface_name: &str,
    interface_generation: u32,
    fingerprint: &[u8; 32],
) -> Result<(), ComponentResolutionError> {
    if !package_identifier(package) {
        return Err(ComponentResolutionError::InvalidPackageIdentity);
    }
    if !interface_identifier(interface_name) || interface_generation == 0 {
        return Err(ComponentResolutionError::InterfaceIdentity);
    }
    if fingerprint.iter().all(|byte| *byte == 0) {
        return Err(ComponentResolutionError::Fingerprint);
    }
    Ok(())
}

fn interface_identifier(value: &str) -> bool {
    package_identifier(value) && value.starts_with("org.mrml.interface.")
}

fn package_identifier(value: &str) -> bool {
    crate::system_generation::package_identifier(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SystemGenerationDigestRecord, encode_system_generation};

    const INTERFACE: u64 = 0x5a53_5444_0000_0003;
    const INTERFACE_NAME: &str = "org.mrml.interface.compression.zstd";
    const FINGERPRINT: [u8; 32] = [0x35; 32];

    fn generation_bytes(output: &mut [u8]) -> (usize, ActivatedSystemGeneration) {
        let records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 8,
                artifact_digest: &[0x18; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 15,
                artifact_digest: &[0x2f; 64],
            },
        ];
        let length = encode_system_generation(108, &records, output).unwrap();
        let digest = SystemGenerationView::decode(&output[..length])
            .unwrap()
            .digest();
        (
            length,
            ActivatedSystemGeneration::new(108, digest, [0x61; 64], 4, 0x500, 9).unwrap(),
        )
    }

    #[test]
    fn activated_generation_selects_exact_provider_and_artifacts() {
        let mut bytes = [0u8; 256];
        let (length, active) = generation_bytes(&mut bytes);
        let requirement =
            ComponentInterfaceRequirement::exact("org.mrml.zim", INTERFACE_NAME, 3, FINGERPRINT)
                .unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            INTERFACE_NAME,
            3,
            FINGERPRINT,
            ComponentProviderForms::NATIVE_SERVICE_OR_MICROVM,
        )
        .unwrap();
        let handoff = resolve_activated_component_service(
            active,
            &bytes[..length],
            requirement,
            &[provider],
            7,
            0x700,
            INTERFACE,
            ComponentServicePlacement::Microvm,
        )
        .unwrap();
        assert_eq!(handoff.system_generation(), 108);
        assert_eq!(handoff.provider_generation(), 15);
        assert_eq!(handoff.consumer_artifact(), &[0x18; 64]);
        assert_eq!(handoff.provider_artifact(), &[0x2f; 64]);
    }

    #[test]
    fn substitution_ambiguity_and_inactive_bytes_fail_closed() {
        let mut bytes = [0u8; 256];
        let (length, active) = generation_bytes(&mut bytes);
        let requirement =
            ComponentInterfaceRequirement::exact("org.mrml.zim", INTERFACE_NAME, 3, FINGERPRINT)
                .unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            INTERFACE_NAME,
            3,
            FINGERPRINT,
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        bytes[length - 1] ^= 1;
        assert_eq!(
            resolve_activated_component_service(
                active,
                &bytes[..length],
                requirement,
                &[provider],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::ActiveGenerationDigestMismatch)
        );
        bytes[length - 1] ^= 1;
        assert_eq!(
            resolve_activated_component_service(
                active,
                &bytes[..length],
                requirement,
                &[provider, provider],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::NonCanonicalProviders)
        );

        let wrong_abi = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            INTERFACE_NAME,
            4,
            FINGERPRINT,
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        assert_eq!(
            resolve_activated_component_service(
                active,
                &bytes[..length],
                requirement,
                &[wrong_abi],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::MissingExactProvider)
        );

        let native_only = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            INTERFACE_NAME,
            3,
            FINGERPRINT,
            ComponentProviderForms::NATIVE_SERVICE,
        )
        .unwrap();
        assert_eq!(
            resolve_activated_component_service(
                active,
                &bytes[..length],
                requirement,
                &[native_only],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::MissingExactProvider)
        );

        let wrong_active = ActivatedSystemGeneration::new(
            109,
            *active.generation_digest(),
            *active.interface_catalog_digest(),
            4,
            0x500,
            9,
        )
        .unwrap();
        assert_eq!(
            resolve_activated_component_service(
                wrong_active,
                &bytes[..length],
                requirement,
                &[provider],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::ActiveGenerationMismatch)
        );

        let outside = ComponentInterfaceProvider::exact(
            "org.mrml.absent",
            INTERFACE_NAME,
            3,
            FINGERPRINT,
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        assert_eq!(
            resolve_activated_component_service(
                active,
                &bytes[..length],
                requirement,
                &[outside],
                7,
                0x700,
                INTERFACE,
                ComponentServicePlacement::Microvm,
            ),
            Err(ComponentResolutionError::PackageOutsideGeneration)
        );
    }
}
