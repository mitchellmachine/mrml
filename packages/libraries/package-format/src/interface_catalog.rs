use mrml_crypto::Sha3_512;

use crate::{
    ActivatedSystemGeneration, ComponentInterfaceProvider, ComponentInterfaceRequirement,
    ComponentProviderForms, ComponentResolutionError, ComponentServiceLaunchHandoff,
    ComponentServiceLaunchHandoffError, ComponentServicePlacement, MAX_PACKAGE_ID_BYTES,
    SystemGenerationDecodeError, SystemGenerationView,
};

const CATALOG_MAGIC: [u8; 8] = *b"MRMLIC1\0";
const CATALOG_HEADER_BYTES: usize = 24;
const DECLARATION_HEADER_BYTES: usize = 44;
pub const MAX_CATALOG_REQUIREMENTS: usize = 256;
pub const MAX_CATALOG_PROVIDERS: usize = 1024;
pub const MAX_INTERFACE_ID_BYTES: usize = 255;
pub const MAX_SINGLE_INTERFACE_CATALOG_BYTES: usize = CATALOG_HEADER_BYTES
    + 2 * (DECLARATION_HEADER_BYTES + MAX_PACKAGE_ID_BYTES + MAX_INTERFACE_ID_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum DeclarationKind {
    Requirement = 1,
    Provider = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceCatalogError {
    Format,
    Reserved,
    Generation,
    RequirementCount,
    ProviderCount,
    PackageIdentity,
    InterfaceIdentity,
    InterfaceGeneration,
    Fingerprint,
    ProviderForms,
    NonCanonicalOrder,
    Truncated,
    TrailingBytes,
    OutputTooSmall,
    LengthOverflow,
    Declaration(ComponentResolutionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestInterfaceDeclaration<'a> {
    Requirement(ComponentInterfaceRequirement<'a>),
    Provider(ComponentInterfaceProvider<'a>),
}

/// Extracts the single dynamic interface declaration from one canonical
/// Manifest V2 document without allocation. This is intentionally not a second
/// general TOML parser: the build frontend remains responsible for canonical
/// manifest validation before these exact declaration fields are embedded in a
/// release or focused probe.
pub fn decode_canonical_manifest_interface(
    bytes: &[u8],
) -> Result<ManifestInterfaceDeclaration<'_>, InterfaceCatalogError> {
    let text = core::str::from_utf8(bytes).map_err(|_| InterfaceCatalogError::Format)?;
    let mut section = "";
    let mut format = false;
    let mut version = false;
    let mut package = None;
    let mut binding = None;
    let mut form = None;
    let mut fingerprint = None;
    let mut interface = None;
    let mut generation = None;
    let mut declaration = 0u8;
    let mut provider_forms = 0u8;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line;
            if line == "[[requires]]" {
                if declaration != 0 {
                    return Err(InterfaceCatalogError::Format);
                }
                declaration = 1;
            } else if line == "[[provides]]" {
                if declaration != 0 {
                    return Err(InterfaceCatalogError::Format);
                }
                declaration = 2;
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(InterfaceCatalogError::Format)?;
        let key = key.trim();
        let value = value.trim();
        match (section, key) {
            ("[manifest]", "format") => format = quoted(value)? == "mrml",
            ("[manifest]", "version") => version = value == "2",
            ("[package]", "id") => package = Some(quoted(value)?),
            ("[[requires]]" | "[[provides]]", "binding") => {
                binding = Some(quoted(value)?)
            }
            ("[[requires]]" | "[[provides]]", "form") => form = Some(quoted(value)?),
            ("[[requires]]" | "[[provides]]", "fingerprint") => {
                fingerprint = Some(decode_fingerprint(quoted(value)?)?)
            }
            ("[[requires]]" | "[[provides]]", "interface") => {
                interface = Some(quoted(value)?)
            }
            ("[[requires]]" | "[[provides]]", "generation") => {
                generation = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|generation| *generation != 0)
                        .ok_or(InterfaceCatalogError::InterfaceGeneration)?,
                )
            }
            ("[isolation]", "supported") => provider_forms = decode_supported_forms(value)?,
            _ => {}
        }
    }
    if !format
        || !version
        || binding != Some("dynamic")
        || form != Some("isolated-service")
    {
        return Err(InterfaceCatalogError::Format);
    }
    let package = package.ok_or(InterfaceCatalogError::PackageIdentity)?;
    let interface = interface.ok_or(InterfaceCatalogError::InterfaceIdentity)?;
    let generation = generation.ok_or(InterfaceCatalogError::InterfaceGeneration)?;
    let fingerprint = fingerprint.ok_or(InterfaceCatalogError::Fingerprint)?;
    match declaration {
        1 => ComponentInterfaceRequirement::exact(package, interface, generation, fingerprint)
            .map(ManifestInterfaceDeclaration::Requirement)
            .map_err(InterfaceCatalogError::Declaration),
        2 => ComponentInterfaceProvider::exact(
            package,
            interface,
            generation,
            fingerprint,
            ComponentProviderForms::from_bits(provider_forms)
                .ok_or(InterfaceCatalogError::ProviderForms)?,
        )
        .map(ManifestInterfaceDeclaration::Provider)
        .map_err(InterfaceCatalogError::Declaration),
        _ => Err(InterfaceCatalogError::Format),
    }
}

fn quoted(value: &str) -> Result<&str, InterfaceCatalogError> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && !value.contains(['"', '\\']))
        .ok_or(InterfaceCatalogError::Format)
}

fn decode_fingerprint(value: &str) -> Result<[u8; 32], InterfaceCatalogError> {
    if value.len() != 64 {
        return Err(InterfaceCatalogError::Fingerprint);
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| InterfaceCatalogError::Fingerprint)?;
    }
    if output == [0; 32] {
        return Err(InterfaceCatalogError::Fingerprint);
    }
    Ok(output)
}

fn decode_supported_forms(value: &str) -> Result<u8, InterfaceCatalogError> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(InterfaceCatalogError::ProviderForms)?;
    let mut forms = 0;
    for item in inner.split(',') {
        forms |= match quoted(item.trim())? {
            "native-service" => ComponentProviderForms::NATIVE_SERVICE.bits(),
            "microvm" => ComponentProviderForms::MICROVM.bits(),
            _ => return Err(InterfaceCatalogError::ProviderForms),
        };
    }
    ComponentProviderForms::from_bits(forms)
        .map(ComponentProviderForms::bits)
        .ok_or(InterfaceCatalogError::ProviderForms)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivatedCatalogResolutionError {
    Generation(SystemGenerationDecodeError),
    Catalog(InterfaceCatalogError),
    ActiveGenerationMismatch,
    ActiveGenerationDigestMismatch,
    ActiveCatalogDigestMismatch,
    PackageOutsideGeneration,
    MissingRequirement,
    AmbiguousRequirement,
    MissingExactProvider,
    AmbiguousExactProvider,
    LaunchHandoff(ComponentServiceLaunchHandoffError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceCatalogView<'a> {
    bytes: &'a [u8],
    generation: u64,
    requirements: u16,
    providers: u16,
    provider_offset: usize,
}

impl<'a> InterfaceCatalogView<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, InterfaceCatalogError> {
        if bytes.len() < CATALOG_HEADER_BYTES || bytes[..8] != CATALOG_MAGIC {
            return Err(InterfaceCatalogError::Format);
        }
        let generation = read_u64(bytes, 8)?;
        if generation == 0 {
            return Err(InterfaceCatalogError::Generation);
        }
        let requirements = read_u16(bytes, 16)?;
        let providers = read_u16(bytes, 18)?;
        if requirements == 0 || requirements as usize > MAX_CATALOG_REQUIREMENTS {
            return Err(InterfaceCatalogError::RequirementCount);
        }
        if providers == 0 || providers as usize > MAX_CATALOG_PROVIDERS {
            return Err(InterfaceCatalogError::ProviderCount);
        }
        if read_u32(bytes, 20)? != 0 {
            return Err(InterfaceCatalogError::Reserved);
        }

        let mut offset = CATALOG_HEADER_BYTES;
        let mut provider_offset = CATALOG_HEADER_BYTES;
        let mut previous = None;
        for index in 0..usize::from(requirements) + usize::from(providers) {
            if index == usize::from(requirements) {
                previous = None;
                provider_offset = offset;
            }
            let expected = if index < usize::from(requirements) {
                DeclarationKind::Requirement
            } else {
                DeclarationKind::Provider
            };
            let (record, next) = decode_record(bytes, offset, expected)?;
            let key = record_key(record);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(InterfaceCatalogError::NonCanonicalOrder);
            }
            previous = Some(key);
            offset = next;
        }
        if offset != bytes.len() {
            return Err(InterfaceCatalogError::TrailingBytes);
        }
        Ok(Self {
            bytes,
            generation,
            requirements,
            providers,
            provider_offset,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub fn digest(self) -> [u8; 64] {
        Sha3_512::digest(self.bytes)
    }

    pub fn requirements(self) -> InterfaceRequirements<'a> {
        InterfaceRequirements {
            bytes: self.bytes,
            offset: CATALOG_HEADER_BYTES,
            remaining: self.requirements,
        }
    }

    pub fn providers(self) -> InterfaceProviders<'a> {
        InterfaceProviders {
            bytes: self.bytes,
            offset: self.provider_offset,
            remaining: self.providers,
        }
    }
}

pub struct InterfaceRequirements<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for InterfaceRequirements<'a> {
    type Item = ComponentInterfaceRequirement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (record, next) =
            decode_record(self.bytes, self.offset, DeclarationKind::Requirement).ok()?;
        self.offset = next;
        self.remaining -= 1;
        ComponentInterfaceRequirement::exact(
            record.package,
            record.interface,
            record.generation,
            *record.fingerprint,
        )
        .ok()
    }
}

pub struct InterfaceProviders<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for InterfaceProviders<'a> {
    type Item = ComponentInterfaceProvider<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (record, next) =
            decode_record(self.bytes, self.offset, DeclarationKind::Provider).ok()?;
        self.offset = next;
        self.remaining -= 1;
        ComponentInterfaceProvider::exact(
            record.package,
            record.interface,
            record.generation,
            *record.fingerprint,
            ComponentProviderForms::from_bits(record.forms)?,
        )
        .ok()
    }
}

pub fn encode_interface_catalog(
    generation: u64,
    requirements: &[ComponentInterfaceRequirement<'_>],
    providers: &[ComponentInterfaceProvider<'_>],
    output: &mut [u8],
) -> Result<usize, InterfaceCatalogError> {
    if generation == 0 {
        return Err(InterfaceCatalogError::Generation);
    }
    if requirements.is_empty() || requirements.len() > MAX_CATALOG_REQUIREMENTS {
        return Err(InterfaceCatalogError::RequirementCount);
    }
    if providers.is_empty() || providers.len() > MAX_CATALOG_PROVIDERS {
        return Err(InterfaceCatalogError::ProviderCount);
    }
    if !requirements
        .windows(2)
        .all(|pair| requirement_key(pair[0]) < requirement_key(pair[1]))
        || !providers
            .windows(2)
            .all(|pair| provider_key(pair[0]) < provider_key(pair[1]))
    {
        return Err(InterfaceCatalogError::NonCanonicalOrder);
    }
    let required = requirements
        .iter()
        .map(|item| (item.consumer_package().len(), item.interface_name().len()))
        .chain(
            providers
                .iter()
                .map(|item| (item.provider_package().len(), item.interface_name().len())),
        )
        .try_fold(CATALOG_HEADER_BYTES, |total, (package, interface)| {
            total
                .checked_add(DECLARATION_HEADER_BYTES)
                .and_then(|value| value.checked_add(package))
                .and_then(|value| value.checked_add(interface))
                .ok_or(InterfaceCatalogError::LengthOverflow)
        })?;
    if output.len() < required {
        return Err(InterfaceCatalogError::OutputTooSmall);
    }
    output[..required].fill(0);
    output[..8].copy_from_slice(&CATALOG_MAGIC);
    output[8..16].copy_from_slice(&generation.to_le_bytes());
    output[16..18].copy_from_slice(&(requirements.len() as u16).to_le_bytes());
    output[18..20].copy_from_slice(&(providers.len() as u16).to_le_bytes());
    let mut offset = CATALOG_HEADER_BYTES;
    for requirement in requirements {
        offset = encode_record(
            output,
            offset,
            DeclarationKind::Requirement,
            0,
            requirement.consumer_package(),
            requirement.interface_name(),
            requirement.interface_generation(),
            &requirement.fingerprint(),
        );
    }
    for provider in providers {
        offset = encode_record(
            output,
            offset,
            DeclarationKind::Provider,
            provider.forms().bits(),
            provider.provider_package(),
            provider.interface_name(),
            provider.interface_generation(),
            &provider.fingerprint(),
        );
    }
    Ok(offset)
}

/// Resolves a consumer's one exact interface declaration from canonical
/// catalog bytes committed by the same active generation. Names select only
/// metadata records; `interface_object` is supplied separately by the
/// capability-authorized control plane and metadata never grants it.
#[allow(clippy::too_many_arguments)]
pub fn resolve_activated_interface_catalog(
    active: ActivatedSystemGeneration,
    generation_bytes: &[u8],
    catalog_bytes: &[u8],
    consumer_package: &str,
    interface_name: &str,
    policy_generation: u64,
    domain_object: u64,
    interface_object: u64,
    placement: ComponentServicePlacement,
) -> Result<ComponentServiceLaunchHandoff, ActivatedCatalogResolutionError> {
    let generation = SystemGenerationView::decode(generation_bytes)
        .map_err(ActivatedCatalogResolutionError::Generation)?;
    let catalog = InterfaceCatalogView::decode(catalog_bytes)
        .map_err(ActivatedCatalogResolutionError::Catalog)?;
    if generation.generation() != active.generation() || catalog.generation() != active.generation()
    {
        return Err(ActivatedCatalogResolutionError::ActiveGenerationMismatch);
    }
    if generation.digest() != *active.generation_digest() {
        return Err(ActivatedCatalogResolutionError::ActiveGenerationDigestMismatch);
    }
    if catalog.digest() != *active.interface_catalog_digest() {
        return Err(ActivatedCatalogResolutionError::ActiveCatalogDigestMismatch);
    }
    for requirement in catalog.requirements() {
        if generation.package(requirement.consumer_package()).is_none() {
            return Err(ActivatedCatalogResolutionError::PackageOutsideGeneration);
        }
    }
    for provider in catalog.providers() {
        if generation.package(provider.provider_package()).is_none() {
            return Err(ActivatedCatalogResolutionError::PackageOutsideGeneration);
        }
    }

    let mut matching_requirements = catalog.requirements().filter(|requirement| {
        requirement.consumer_package() == consumer_package
            && requirement.interface_name() == interface_name
    });
    let requirement = matching_requirements
        .next()
        .ok_or(ActivatedCatalogResolutionError::MissingRequirement)?;
    if matching_requirements.next().is_some() {
        return Err(ActivatedCatalogResolutionError::AmbiguousRequirement);
    }
    let consumer = generation
        .package(requirement.consumer_package())
        .ok_or(ActivatedCatalogResolutionError::PackageOutsideGeneration)?;
    let mut matching_providers = catalog.providers().filter(|provider| {
        provider.interface_name() == requirement.interface_name()
            && provider.interface_generation() == requirement.interface_generation()
            && provider.fingerprint() == requirement.fingerprint()
            && provider.forms().supports(placement)
    });
    let provider_declaration = matching_providers
        .next()
        .ok_or(ActivatedCatalogResolutionError::MissingExactProvider)?;
    if matching_providers.next().is_some() {
        return Err(ActivatedCatalogResolutionError::AmbiguousExactProvider);
    }
    let provider = generation
        .package(provider_declaration.provider_package())
        .ok_or(ActivatedCatalogResolutionError::PackageOutsideGeneration)?;
    ComponentServiceLaunchHandoff::new(
        active.generation(),
        policy_generation,
        domain_object,
        interface_object,
        requirement.interface_generation(),
        provider.version(),
        placement,
        *active.generation_digest(),
        *active.interface_catalog_digest(),
        requirement.fingerprint(),
        *consumer.artifact_digest(),
        *provider.artifact_digest(),
    )
    .map_err(ActivatedCatalogResolutionError::LaunchHandoff)
}

#[allow(clippy::too_many_arguments)]
fn encode_record(
    output: &mut [u8],
    offset: usize,
    kind: DeclarationKind,
    forms: u8,
    package: &str,
    interface: &str,
    generation: u32,
    fingerprint: &[u8; 32],
) -> usize {
    output[offset] = kind as u8;
    output[offset + 1] = forms;
    output[offset + 4..offset + 6].copy_from_slice(&(package.len() as u16).to_le_bytes());
    output[offset + 6..offset + 8].copy_from_slice(&(interface.len() as u16).to_le_bytes());
    output[offset + 8..offset + 12].copy_from_slice(&generation.to_le_bytes());
    output[offset + 12..offset + 44].copy_from_slice(fingerprint);
    let package_start = offset + DECLARATION_HEADER_BYTES;
    let interface_start = package_start + package.len();
    let end = interface_start + interface.len();
    output[package_start..interface_start].copy_from_slice(package.as_bytes());
    output[interface_start..end].copy_from_slice(interface.as_bytes());
    end
}

#[derive(Clone, Copy)]
struct DecodedRecord<'a> {
    forms: u8,
    package: &'a str,
    interface: &'a str,
    generation: u32,
    fingerprint: &'a [u8; 32],
}

fn decode_record(
    bytes: &[u8],
    offset: usize,
    expected: DeclarationKind,
) -> Result<(DecodedRecord<'_>, usize), InterfaceCatalogError> {
    let header_end = offset
        .checked_add(DECLARATION_HEADER_BYTES)
        .ok_or(InterfaceCatalogError::Truncated)?;
    let header = bytes
        .get(offset..header_end)
        .ok_or(InterfaceCatalogError::Truncated)?;
    let kind = match header[0] {
        1 => DeclarationKind::Requirement,
        2 => DeclarationKind::Provider,
        _ => return Err(InterfaceCatalogError::Format),
    };
    if kind != expected {
        return Err(InterfaceCatalogError::NonCanonicalOrder);
    }
    if header[2..4] != [0; 2] {
        return Err(InterfaceCatalogError::Reserved);
    }
    let forms = header[1];
    if (kind == DeclarationKind::Requirement && forms != 0)
        || (kind == DeclarationKind::Provider && ComponentProviderForms::from_bits(forms).is_none())
    {
        return Err(InterfaceCatalogError::ProviderForms);
    }
    let package_len = u16::from_le_bytes([header[4], header[5]]) as usize;
    let interface_len = u16::from_le_bytes([header[6], header[7]]) as usize;
    if package_len == 0 || package_len > MAX_PACKAGE_ID_BYTES {
        return Err(InterfaceCatalogError::PackageIdentity);
    }
    if interface_len == 0 || interface_len > MAX_INTERFACE_ID_BYTES {
        return Err(InterfaceCatalogError::InterfaceIdentity);
    }
    let generation = u32::from_le_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| InterfaceCatalogError::Truncated)?,
    );
    if generation == 0 {
        return Err(InterfaceCatalogError::InterfaceGeneration);
    }
    let fingerprint: &[u8; 32] = header[12..44]
        .try_into()
        .map_err(|_| InterfaceCatalogError::Truncated)?;
    if fingerprint.iter().all(|byte| *byte == 0) {
        return Err(InterfaceCatalogError::Fingerprint);
    }
    let package_start = header_end;
    let interface_start = package_start
        .checked_add(package_len)
        .ok_or(InterfaceCatalogError::Truncated)?;
    let end = interface_start
        .checked_add(interface_len)
        .ok_or(InterfaceCatalogError::Truncated)?;
    let package = core::str::from_utf8(
        bytes
            .get(package_start..interface_start)
            .ok_or(InterfaceCatalogError::Truncated)?,
    )
    .map_err(|_| InterfaceCatalogError::PackageIdentity)?;
    let interface = core::str::from_utf8(
        bytes
            .get(interface_start..end)
            .ok_or(InterfaceCatalogError::Truncated)?,
    )
    .map_err(|_| InterfaceCatalogError::InterfaceIdentity)?;
    let declaration = match kind {
        DeclarationKind::Requirement => {
            ComponentInterfaceRequirement::exact(package, interface, generation, *fingerprint)
                .map(|_| ())
        }
        DeclarationKind::Provider => ComponentInterfaceProvider::exact(
            package,
            interface,
            generation,
            *fingerprint,
            ComponentProviderForms::from_bits(forms).ok_or(InterfaceCatalogError::ProviderForms)?,
        )
        .map(|_| ()),
    };
    declaration.map_err(InterfaceCatalogError::Declaration)?;
    Ok((
        DecodedRecord {
            forms,
            package,
            interface,
            generation,
            fingerprint,
        },
        end,
    ))
}

fn record_key(record: DecodedRecord<'_>) -> (&str, &str, u32, [u8; 32], u8) {
    (
        record.package,
        record.interface,
        record.generation,
        *record.fingerprint,
        record.forms,
    )
}

fn requirement_key(item: ComponentInterfaceRequirement<'_>) -> (&str, &str, u32, [u8; 32]) {
    (
        item.consumer_package(),
        item.interface_name(),
        item.interface_generation(),
        item.fingerprint(),
    )
}

fn provider_key(item: ComponentInterfaceProvider<'_>) -> (&str, &str, u32, [u8; 32], u8) {
    (
        item.provider_package(),
        item.interface_name(),
        item.interface_generation(),
        item.fingerprint(),
        item.forms().bits(),
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, InterfaceCatalogError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(InterfaceCatalogError::Truncated)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, InterfaceCatalogError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(InterfaceCatalogError::Truncated)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, InterfaceCatalogError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(InterfaceCatalogError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActivatedSystemGeneration, SystemGenerationDigestRecord, encode_system_generation,
    };

    const NAME: &str = "org.mrml.interface.compression.zstd";
    const FP: [u8; 32] = [0x6a; 32];

    fn declarations() -> (
        ComponentInterfaceRequirement<'static>,
        ComponentInterfaceProvider<'static>,
    ) {
        (
            ComponentInterfaceRequirement::exact("org.mrml.zim", NAME, 3, FP).unwrap(),
            ComponentInterfaceProvider::exact(
                "org.mrml.zstd",
                NAME,
                3,
                FP,
                ComponentProviderForms::NATIVE_SERVICE_OR_MICROVM,
            )
            .unwrap(),
        )
    }

    #[test]
    fn canonical_manifest_declarations_supply_exact_catalog_fields() {
        const REQUIREMENT: &[u8] = b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.zim\"\n\n[[requires]]\nbinding = \"dynamic\"\nfingerprint = \"6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\"\n";
        const PROVIDER: &[u8] = b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.zstd\"\n\n[isolation]\nsupported = [\"native-service\", \"microvm\"]\n\n[[provides]]\nbinding = \"dynamic\"\nfingerprint = \"6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\"\n";
        const MALFORMED: &[u8] = b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.zstd\"\n\n[isolation]\nsupported = [\"microvm\"]\n\n[[provides]]\nbinding = \"path\"\nfingerprint = \"6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\"\n";
        let requirement = match decode_canonical_manifest_interface(REQUIREMENT)
            .unwrap()
        {
            ManifestInterfaceDeclaration::Requirement(value) => value,
            ManifestInterfaceDeclaration::Provider(_) => panic!("wrong declaration kind"),
        };
        let provider = match decode_canonical_manifest_interface(PROVIDER)
            .unwrap()
        {
            ManifestInterfaceDeclaration::Provider(value) => value,
            ManifestInterfaceDeclaration::Requirement(_) => panic!("wrong declaration kind"),
        };
        assert_eq!(requirement.consumer_package(), "org.mrml.zim");
        assert_eq!(requirement.interface_generation(), 3);
        assert_eq!(provider.provider_package(), "org.mrml.zstd");
        assert_eq!(
            provider.forms(),
            ComponentProviderForms::NATIVE_SERVICE_OR_MICROVM
        );

        assert_eq!(
            decode_canonical_manifest_interface(MALFORMED),
            Err(InterfaceCatalogError::Format)
        );
    }

    #[test]
    fn canonical_catalog_round_trips_borrowed_declarations() {
        let (requirement, provider) = declarations();
        let mut bytes = [0u8; 256];
        let length = encode_interface_catalog(8, &[requirement], &[provider], &mut bytes).unwrap();
        let catalog = InterfaceCatalogView::decode(&bytes[..length]).unwrap();
        assert_eq!(catalog.generation(), 8);
        assert_ne!(catalog.digest(), [0; 64]);
        assert_eq!(catalog.requirements().next(), Some(requirement));
        assert_eq!(catalog.providers().next(), Some(provider));
    }

    #[test]
    fn catalog_rejects_truncation_reserved_forms_and_trailing_bytes() {
        let (requirement, provider) = declarations();
        let mut bytes = [0u8; 257];
        let length = encode_interface_catalog(8, &[requirement], &[provider], &mut bytes).unwrap();
        assert_eq!(
            InterfaceCatalogView::decode(&bytes[..length - 1]),
            Err(InterfaceCatalogError::Truncated)
        );
        bytes[20] = 1;
        assert_eq!(
            InterfaceCatalogView::decode(&bytes[..length]),
            Err(InterfaceCatalogError::Reserved)
        );
        bytes[20] = 0;
        bytes[CATALOG_HEADER_BYTES + 1] = 1;
        assert_eq!(
            InterfaceCatalogView::decode(&bytes[..length]),
            Err(InterfaceCatalogError::ProviderForms)
        );
        bytes[CATALOG_HEADER_BYTES + 1] = 0;
        bytes[length] = 1;
        assert_eq!(
            InterfaceCatalogView::decode(&bytes[..length + 1]),
            Err(InterfaceCatalogError::TrailingBytes)
        );
    }

    #[test]
    fn active_catalog_derives_exact_handoff_without_caller_declarations() {
        let (requirement, provider) = declarations();
        let mut catalog_bytes = [0u8; 256];
        let catalog_length =
            encode_interface_catalog(8, &[requirement], &[provider], &mut catalog_bytes).unwrap();
        let catalog_digest = InterfaceCatalogView::decode(&catalog_bytes[..catalog_length])
            .unwrap()
            .digest();
        let records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 4,
                artifact_digest: &[0x18; 64],
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 9,
                artifact_digest: &[0x2f; 64],
            },
        ];
        let mut generation_bytes = [0u8; 256];
        let generation_length =
            encode_system_generation(8, &records, &mut generation_bytes).unwrap();
        let generation_digest =
            SystemGenerationView::decode(&generation_bytes[..generation_length])
                .unwrap()
                .digest();
        let active =
            ActivatedSystemGeneration::new(8, generation_digest, catalog_digest, 2, 0x500, 3)
                .unwrap();
        let handoff = resolve_activated_interface_catalog(
            active,
            &generation_bytes[..generation_length],
            &catalog_bytes[..catalog_length],
            "org.mrml.zim",
            NAME,
            7,
            0x700,
            0x703,
            ComponentServicePlacement::Microvm,
        )
        .unwrap();
        assert_eq!(handoff.provider_generation(), 9);
        assert_eq!(handoff.interface_object(), 0x703);
        assert_eq!(handoff.consumer_artifact(), &[0x18; 64]);
        assert_eq!(handoff.provider_artifact(), &[0x2f; 64]);

        catalog_bytes[catalog_length - 1] ^= 1;
        assert_eq!(
            resolve_activated_interface_catalog(
                active,
                &generation_bytes[..generation_length],
                &catalog_bytes[..catalog_length],
                "org.mrml.zim",
                NAME,
                7,
                0x700,
                0x703,
                ComponentServicePlacement::Microvm,
            ),
            Err(ActivatedCatalogResolutionError::ActiveCatalogDigestMismatch)
        );
    }
}
