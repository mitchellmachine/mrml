const MAX_GENERATION_PACKAGES: usize = 256;
const MAX_PACKAGE_CANDIDATES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemPackage {
    package_id: String,
    version: u64,
    artifact_digest: [u8; 64],
}

impl SystemPackage {
    pub fn new(
        package_id: String,
        version: u64,
        artifact_digest: [u8; 64],
    ) -> Result<Self, GenerationError> {
        if !mrml_package_identifier(&package_id) {
            return Err(GenerationError::InvalidPackageIdentity);
        }
        if version == 0 {
            return Err(GenerationError::InvalidPackageVersion);
        }
        if artifact_digest.iter().all(|byte| *byte == 0) {
            return Err(GenerationError::InvalidArtifactDigest);
        }
        Ok(Self {
            package_id,
            version,
            artifact_digest,
        })
    }

    pub fn package_id(&self) -> &str {
        &self.package_id
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub const fn artifact_digest(&self) -> &[u8; 64] {
        &self.artifact_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemGeneration {
    generation: u64,
    packages: Vec<SystemPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageRequirement {
    package_id: String,
    version: u64,
    artifact_digest: [u8; 64],
}

impl PackageRequirement {
    pub fn exact(
        package_id: String,
        version: u64,
        artifact_digest: [u8; 64],
    ) -> Result<Self, GenerationError> {
        let package = SystemPackage::new(package_id, version, artifact_digest)?;
        Ok(Self {
            package_id: package.package_id,
            version: package.version,
            artifact_digest: package.artifact_digest,
        })
    }
}

pub fn resolve_exact_packages(
    generation: u64,
    requirements: &[PackageRequirement],
    candidates: &[SystemPackage],
) -> Result<SystemGeneration, ResolutionError> {
    if generation == 0 {
        return Err(ResolutionError::InvalidGeneration);
    }
    if requirements.is_empty() || requirements.len() > MAX_GENERATION_PACKAGES {
        return Err(ResolutionError::RequirementCount);
    }
    if candidates.is_empty() || candidates.len() > MAX_PACKAGE_CANDIDATES {
        return Err(ResolutionError::CandidateCount);
    }
    for pair in requirements.windows(2) {
        if pair[0].package_id >= pair[1].package_id {
            return Err(ResolutionError::NonCanonicalRequirements);
        }
    }

    let mut selected = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let mut matches = candidates.iter().filter(|candidate| {
            candidate.package_id == requirement.package_id
                && candidate.version == requirement.version
                && candidate.artifact_digest == requirement.artifact_digest
        });
        let candidate = matches.next().ok_or(ResolutionError::MissingExactPackage)?;
        if matches.next().is_some() {
            return Err(ResolutionError::AmbiguousExactPackage);
        }
        selected.push(candidate.clone());
    }
    SystemGeneration::new(generation, selected).map_err(ResolutionError::InvalidResult)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    InvalidGeneration,
    RequirementCount,
    CandidateCount,
    NonCanonicalRequirements,
    MissingExactPackage,
    AmbiguousExactPackage,
    InvalidResult(GenerationError),
}

impl SystemGeneration {
    pub fn new(generation: u64, packages: Vec<SystemPackage>) -> Result<Self, GenerationError> {
        if generation == 0 {
            return Err(GenerationError::InvalidGeneration);
        }
        if packages.is_empty() || packages.len() > MAX_GENERATION_PACKAGES {
            return Err(GenerationError::PackageCount);
        }
        for pair in packages.windows(2) {
            if pair[0].package_id() >= pair[1].package_id() {
                return Err(GenerationError::NonCanonicalPackageOrder);
            }
        }
        Ok(Self {
            generation,
            packages,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn packages(&self) -> &[SystemPackage] {
        &self.packages
    }

    pub fn package(&self, package_id: &str) -> Option<&SystemPackage> {
        self.packages
            .binary_search_by_key(&package_id, |package| package.package_id())
            .ok()
            .map(|index| &self.packages[index])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationError {
    InvalidGeneration,
    PackageCount,
    InvalidPackageIdentity,
    InvalidPackageVersion,
    InvalidArtifactDigest,
    NonCanonicalPackageOrder,
}

pub fn mrml_package_identifier(value: &str) -> bool {
    value.starts_with("org.mrml.")
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_lowercase)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: &str, version: u64, marker: u8) -> SystemPackage {
        SystemPackage::new(id.into(), version, [marker; 64]).unwrap()
    }

    #[test]
    fn generation_retains_exact_immutable_package_records() {
        let generation = SystemGeneration::new(
            104,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", 14, 0x2e),
            ],
        )
        .unwrap();
        assert_eq!(generation.generation(), 104);
        assert_eq!(generation.packages().len(), 2);
        let zstd = generation.package("org.mrml.zstd").unwrap();
        assert_eq!(zstd.version(), 14);
        assert_eq!(zstd.artifact_digest(), &[0x2e; 64]);
        assert!(generation.package("mrml-zstd").is_none());
    }

    #[test]
    fn generation_rejects_ambiguous_or_unbounded_graphs() {
        assert_eq!(
            SystemGeneration::new(0, vec![package("org.mrml.zstd", 14, 1)]),
            Err(GenerationError::InvalidGeneration)
        );
        assert_eq!(
            SystemGeneration::new(1, Vec::new()),
            Err(GenerationError::PackageCount)
        );
        let oversized = (0..=MAX_GENERATION_PACKAGES)
            .map(|index| package(&format!("org.mrml.p{index:03}"), 1, 1))
            .collect();
        assert_eq!(
            SystemGeneration::new(1, oversized),
            Err(GenerationError::PackageCount)
        );
        assert_eq!(
            SystemGeneration::new(
                1,
                vec![
                    package("org.mrml.zstd", 14, 1),
                    package("org.mrml.zim", 8, 2),
                ],
            ),
            Err(GenerationError::NonCanonicalPackageOrder)
        );
        assert_eq!(
            SystemGeneration::new(
                1,
                vec![
                    package("org.mrml.zstd", 14, 1),
                    package("org.mrml.zstd", 15, 2),
                ],
            ),
            Err(GenerationError::NonCanonicalPackageOrder)
        );
    }

    #[test]
    fn package_record_rejects_invalid_identity_version_and_digest() {
        assert_eq!(
            SystemPackage::new("mrml-zstd".into(), 14, [1; 64]),
            Err(GenerationError::InvalidPackageIdentity)
        );
        assert_eq!(
            SystemPackage::new("org.mrml.zstd".into(), 0, [1; 64]),
            Err(GenerationError::InvalidPackageVersion)
        );
        assert_eq!(
            SystemPackage::new("org.mrml.zstd".into(), 14, [0; 64]),
            Err(GenerationError::InvalidArtifactDigest)
        );
    }

    #[test]
    fn exact_resolution_selects_only_identical_package_generations() {
        let zim = package("org.mrml.zim", 8, 0x18);
        let zstd14 = package("org.mrml.zstd", 14, 0x2e);
        let zstd15 = package("org.mrml.zstd", 15, 0x2f);
        let requirements = vec![
            PackageRequirement::exact("org.mrml.zim".into(), 8, [0x18; 64]).unwrap(),
            PackageRequirement::exact("org.mrml.zstd".into(), 14, [0x2e; 64]).unwrap(),
        ];
        let generation =
            resolve_exact_packages(104, &requirements, &[zstd15, zim, zstd14]).unwrap();
        assert_eq!(generation.generation(), 104);
        assert_eq!(generation.package("org.mrml.zstd").unwrap().version(), 14);
    }

    #[test]
    fn exact_resolution_never_substitutes_version_digest_or_identity() {
        let requirement =
            PackageRequirement::exact("org.mrml.zstd".into(), 14, [0x2e; 64]).unwrap();
        assert_eq!(
            resolve_exact_packages(
                104,
                std::slice::from_ref(&requirement),
                &[package("org.mrml.zstd", 15, 0x2e)],
            ),
            Err(ResolutionError::MissingExactPackage)
        );
        assert_eq!(
            resolve_exact_packages(
                104,
                std::slice::from_ref(&requirement),
                &[package("org.mrml.zstd", 14, 0x2f)],
            ),
            Err(ResolutionError::MissingExactPackage)
        );
        assert_eq!(
            resolve_exact_packages(104, &[requirement], &[package("org.mrml.zim", 14, 0x2e)]),
            Err(ResolutionError::MissingExactPackage)
        );
    }

    #[test]
    fn exact_resolution_rejects_ambiguous_and_noncanonical_inputs() {
        let requirement =
            PackageRequirement::exact("org.mrml.zstd".into(), 14, [0x2e; 64]).unwrap();
        let duplicate = package("org.mrml.zstd", 14, 0x2e);
        assert_eq!(
            resolve_exact_packages(
                104,
                std::slice::from_ref(&requirement),
                &[duplicate.clone(), duplicate],
            ),
            Err(ResolutionError::AmbiguousExactPackage)
        );
        let reversed = vec![
            requirement,
            PackageRequirement::exact("org.mrml.zim".into(), 8, [0x18; 64]).unwrap(),
        ];
        assert_eq!(
            resolve_exact_packages(104, &reversed, &[package("org.mrml.zstd", 14, 0x2e)]),
            Err(ResolutionError::NonCanonicalRequirements)
        );
        assert_eq!(
            resolve_exact_packages(104, &[], &[package("org.mrml.zstd", 14, 0x2e)]),
            Err(ResolutionError::RequirementCount)
        );
        let oversized_candidates = (0..=MAX_PACKAGE_CANDIDATES)
            .map(|index| package(&format!("org.mrml.p{index:04}"), 1, 1))
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_exact_packages(
                104,
                &[PackageRequirement::exact("org.mrml.zstd".into(), 14, [0x2e; 64]).unwrap()],
                &oversized_candidates,
            ),
            Err(ResolutionError::CandidateCount)
        );
    }
}
