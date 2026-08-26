use crate::manifest::{Document, Error as ManifestError};
use crate::{
    ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
    ComponentResolutionError, InterfaceCatalogError, encode_interface_catalog,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestCatalogError {
    Manifest(ManifestError),
    MissingPackage,
    UnsupportedBinding,
    UnsupportedForm,
    InvalidGeneration,
    InvalidFingerprint,
    InvalidPlacement,
    Declaration(ComponentResolutionError),
    Catalog(InterfaceCatalogError),
}

pub fn encode_manifest_interface_catalog(
    generation: u64,
    manifests: &[Document],
    output: &mut [u8],
) -> Result<usize, ManifestCatalogError> {
    let mut requirements = Vec::new();
    let mut providers = Vec::new();
    for manifest in manifests {
        let package = manifest
            .section("package")
            .map_err(ManifestCatalogError::Manifest)?
            .string("id")
            .map_err(ManifestCatalogError::Manifest)?;
        for declaration in manifest.array_sections("requires") {
            if declaration
                .string("binding")
                .map_err(ManifestCatalogError::Manifest)?
                != "dynamic"
            {
                return Err(ManifestCatalogError::UnsupportedBinding);
            }
            validate_service_form(declaration.string("form").map_err(ManifestCatalogError::Manifest)?)?;
            requirements.push(
                ComponentInterfaceRequirement::exact(
                    package,
                    declaration
                        .string("interface")
                        .map_err(ManifestCatalogError::Manifest)?,
                    interface_generation(declaration.integer("generation").map_err(ManifestCatalogError::Manifest)?)?,
                    fingerprint(declaration.string("fingerprint").map_err(ManifestCatalogError::Manifest)?)?,
                )
                .map_err(ManifestCatalogError::Declaration)?,
            );
        }
        for declaration in manifest.array_sections("provides") {
            if declaration
                .string("binding")
                .map_err(ManifestCatalogError::Manifest)?
                != "dynamic"
            {
                return Err(ManifestCatalogError::UnsupportedBinding);
            }
            validate_service_form(declaration.string("form").map_err(ManifestCatalogError::Manifest)?)?;
            let isolation = manifest
                .section("isolation")
                .map_err(ManifestCatalogError::Manifest)?;
            let mut bits = 0;
            for placement in isolation
                .strings("supported")
                .map_err(ManifestCatalogError::Manifest)?
            {
                bits |= match placement.as_str() {
                    "native-service" => ComponentProviderForms::NATIVE_SERVICE.bits(),
                    "microvm" => ComponentProviderForms::MICROVM.bits(),
                    _ => return Err(ManifestCatalogError::InvalidPlacement),
                };
            }
            let forms = ComponentProviderForms::from_bits(bits)
                .ok_or(ManifestCatalogError::InvalidPlacement)?;
            providers.push(
                ComponentInterfaceProvider::exact(
                    package,
                    declaration
                        .string("interface")
                        .map_err(ManifestCatalogError::Manifest)?,
                    interface_generation(declaration.integer("generation").map_err(ManifestCatalogError::Manifest)?)?,
                    fingerprint(declaration.string("fingerprint").map_err(ManifestCatalogError::Manifest)?)?,
                    forms,
                )
                .map_err(ManifestCatalogError::Declaration)?,
            );
        }
    }
    if requirements.is_empty() || providers.is_empty() {
        return Err(ManifestCatalogError::MissingPackage);
    }
    requirements.sort_unstable_by_key(|requirement| {
        (
            requirement.consumer_package(),
            requirement.interface_name(),
            requirement.interface_generation(),
            requirement.fingerprint(),
        )
    });
    providers.sort_unstable_by_key(|provider| {
        (
            provider.interface_name(),
            provider.interface_generation(),
            provider.fingerprint(),
            provider.provider_package(),
            provider.forms().bits(),
        )
    });
    encode_interface_catalog(generation, &requirements, &providers, output)
        .map_err(ManifestCatalogError::Catalog)
}

fn validate_service_form(form: &str) -> Result<(), ManifestCatalogError> {
    if form == "isolated-service" {
        Ok(())
    } else {
        Err(ManifestCatalogError::UnsupportedForm)
    }
}

fn interface_generation(value: u64) -> Result<u32, ManifestCatalogError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(ManifestCatalogError::InvalidGeneration)
}

fn fingerprint(value: &str) -> Result<[u8; 32], ManifestCatalogError> {
    if value.len() != 64 {
        return Err(ManifestCatalogError::InvalidFingerprint);
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| ManifestCatalogError::InvalidFingerprint)?;
    }
    if output == [0; 32] {
        return Err(ManifestCatalogError::InvalidFingerprint);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InterfaceCatalogView;

    const FINGERPRINT: &str =
        "6a62bdd594af284f51edc1734aa15851e5de37ef7e21103b665454c743e2126c";

    fn manifest(package: &str, declaration: &str, isolation: &str) -> Document {
        Document::parse(
            format!(
                "[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"{package}\"\nname = \"test\"\n{isolation}\n{declaration}\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_catalog_is_derived_only_from_manifest_v2_declarations() {
        let consumer = manifest(
            "org.mrml.zim",
            &format!(
                "[[requires]]\nbinding = \"dynamic\"\nfingerprint = \"{FINGERPRINT}\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\""
            ),
            "",
        );
        let provider = manifest(
            "org.mrml.zstd",
            &format!(
                "[[provides]]\nbinding = \"dynamic\"\nfingerprint = \"{FINGERPRINT}\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\""
            ),
            "\n[isolation]\ndefault = \"native-service\"\nminimum = \"native-service\"\nsupported = [\"native-service\", \"microvm\"]\n",
        );
        let mut first = [0; 256];
        let first_len = encode_manifest_interface_catalog(
            9,
            &[consumer.clone(), provider.clone()],
            &mut first,
        )
        .unwrap();
        let mut reordered = [0; 256];
        let reordered_len =
            encode_manifest_interface_catalog(9, &[provider, consumer], &mut reordered).unwrap();
        assert_eq!(&first[..first_len], &reordered[..reordered_len]);
        let view = InterfaceCatalogView::decode(&first[..first_len]).unwrap();
        assert_eq!(view.generation(), 9);
        assert_eq!(view.requirements().next().unwrap().consumer_package(), "org.mrml.zim");
        assert_eq!(view.providers().next().unwrap().provider_package(), "org.mrml.zstd");
    }

    #[test]
    fn malformed_or_authority_ambiguous_manifest_fields_fail_closed() {
        let zero = "00".repeat(32);
        let invalid = manifest(
            "org.mrml.zim",
            &format!(
                "[[requires]]\nbinding = \"path\"\nfingerprint = \"{FINGERPRINT}\"\nform = \"isolated-service\"\ngeneration = 3\ninterface = \"org.mrml.interface.compression.zstd\""
            ),
            "",
        );
        assert_eq!(
            encode_manifest_interface_catalog(1, &[invalid], &mut [0; 256]),
            Err(ManifestCatalogError::UnsupportedBinding)
        );
        assert_eq!(fingerprint(&zero), Err(ManifestCatalogError::InvalidFingerprint));
        assert_eq!(interface_generation(0), Err(ManifestCatalogError::InvalidGeneration));
    }
}
