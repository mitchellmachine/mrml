const MAX_GENERATION_PACKAGES: usize = 256;
const MAX_PACKAGE_CANDIDATES: usize = 1024;
const MAX_PACKAGE_DEPENDENCIES: usize = 256;
const MAX_GENERATION_DEPENDENCY_EDGES: usize = 4096;
const MAX_PACKAGE_ID_BYTES: usize = 255;
const GENERATION_MAGIC: [u8; 8] = *b"MRMLSG2\0";
const GENERATION_HEADER_BYTES: usize = 24;
const PACKAGE_HEADER_BYTES: usize = 76;

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
pub struct PackageCandidate {
    package: SystemPackage,
    dependencies: Vec<PackageRequirement>,
}

impl PackageCandidate {
    pub fn exact(
        package: SystemPackage,
        dependencies: Vec<PackageRequirement>,
    ) -> Result<Self, GraphResolutionError> {
        if dependencies.len() > MAX_PACKAGE_DEPENDENCIES {
            return Err(GraphResolutionError::DependencyCount);
        }
        if !dependencies
            .windows(2)
            .all(|pair| pair[0].package_id < pair[1].package_id)
        {
            return Err(GraphResolutionError::NonCanonicalDependencies);
        }
        if dependencies
            .iter()
            .any(|dependency| dependency.package_id == package.package_id)
        {
            return Err(GraphResolutionError::SelfDependency);
        }
        Ok(Self {
            package,
            dependencies,
        })
    }

    pub fn package(&self) -> &SystemPackage {
        &self.package
    }

    pub fn dependencies(&self) -> &[PackageRequirement] {
        &self.dependencies
    }
}

pub fn resolve_exact_package_graph(
    generation: u64,
    roots: &[PackageRequirement],
    candidates: &[PackageCandidate],
) -> Result<SystemGeneration, GraphResolutionError> {
    if generation == 0 {
        return Err(GraphResolutionError::InvalidGeneration);
    }
    if roots.is_empty() || roots.len() > MAX_GENERATION_PACKAGES {
        return Err(GraphResolutionError::RootCount);
    }
    if candidates.is_empty() || candidates.len() > MAX_PACKAGE_CANDIDATES {
        return Err(GraphResolutionError::CandidateCount);
    }
    if !roots
        .windows(2)
        .all(|pair| pair[0].package_id < pair[1].package_id)
    {
        return Err(GraphResolutionError::NonCanonicalRoots);
    }

    let mut pending = roots.to_vec();
    let mut selected = Vec::<SystemPackage>::new();
    let mut cursor = 0usize;
    let mut edge_count = 0usize;
    while cursor < pending.len() {
        let requirement = &pending[cursor];
        cursor += 1;
        if let Some(existing) = selected
            .iter()
            .find(|package| package.package_id == requirement.package_id)
        {
            if existing.version != requirement.version
                || existing.artifact_digest != requirement.artifact_digest
            {
                return Err(GraphResolutionError::ConflictingExactRequirement);
            }
            continue;
        }
        let mut matching = candidates.iter().filter(|candidate| {
            candidate.package.package_id == requirement.package_id
                && candidate.package.version == requirement.version
                && candidate.package.artifact_digest == requirement.artifact_digest
        });
        let candidate = matching
            .next()
            .ok_or(GraphResolutionError::MissingExactPackage)?;
        if matching.next().is_some() {
            return Err(GraphResolutionError::AmbiguousExactPackage);
        }
        if selected.len() == MAX_GENERATION_PACKAGES {
            return Err(GraphResolutionError::PackageCount);
        }
        edge_count = edge_count
            .checked_add(candidate.dependencies.len())
            .ok_or(GraphResolutionError::DependencyEdgeCount)?;
        if edge_count > MAX_GENERATION_DEPENDENCY_EDGES {
            return Err(GraphResolutionError::DependencyEdgeCount);
        }
        selected.push(candidate.package.clone());
        pending.extend(candidate.dependencies.iter().cloned());
    }
    selected.sort_by(|left, right| left.package_id.cmp(&right.package_id));
    SystemGeneration::new(generation, selected).map_err(GraphResolutionError::InvalidResult)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphResolutionError {
    InvalidGeneration,
    RootCount,
    CandidateCount,
    DependencyCount,
    DependencyEdgeCount,
    NonCanonicalRoots,
    NonCanonicalDependencies,
    SelfDependency,
    MissingExactPackage,
    AmbiguousExactPackage,
    ConflictingExactRequirement,
    PackageCount,
    InvalidResult(GenerationError),
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

    pub fn encode_canonical(&self) -> Vec<u8> {
        let capacity = GENERATION_HEADER_BYTES
            + self
                .packages
                .iter()
                .map(|package| PACKAGE_HEADER_BYTES + package.package_id.len())
                .sum::<usize>();
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&GENERATION_MAGIC);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&(self.packages.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        for package in &self.packages {
            bytes.extend_from_slice(&(package.package_id.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&package.version.to_le_bytes());
            bytes.extend_from_slice(&package.artifact_digest);
            bytes.extend_from_slice(package.package_id.as_bytes());
        }
        bytes
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, GenerationCodecError> {
        if bytes.len() < GENERATION_HEADER_BYTES || bytes[..8] != GENERATION_MAGIC {
            return Err(GenerationCodecError::Header);
        }
        let generation = read_u64(bytes, 8)?;
        let count = read_u32(bytes, 16)? as usize;
        if read_u32(bytes, 20)? != 0 {
            return Err(GenerationCodecError::Reserved);
        }
        if count == 0 || count > MAX_GENERATION_PACKAGES {
            return Err(GenerationCodecError::PackageCount);
        }
        let mut cursor = GENERATION_HEADER_BYTES;
        let mut packages = Vec::with_capacity(count);
        for _ in 0..count {
            let fixed_end = cursor
                .checked_add(PACKAGE_HEADER_BYTES)
                .ok_or(GenerationCodecError::Truncated)?;
            if fixed_end > bytes.len() {
                return Err(GenerationCodecError::Truncated);
            }
            let id_length = read_u16(bytes, cursor)? as usize;
            if id_length == 0 || id_length > MAX_PACKAGE_ID_BYTES {
                return Err(GenerationCodecError::PackageIdentity);
            }
            if read_u16(bytes, cursor + 2)? != 0 {
                return Err(GenerationCodecError::Reserved);
            }
            let version = read_u64(bytes, cursor + 4)?;
            let mut digest = [0u8; 64];
            digest.copy_from_slice(&bytes[cursor + 12..fixed_end]);
            let id_end = fixed_end
                .checked_add(id_length)
                .ok_or(GenerationCodecError::Truncated)?;
            let id_bytes = bytes
                .get(fixed_end..id_end)
                .ok_or(GenerationCodecError::Truncated)?;
            let package_id = core::str::from_utf8(id_bytes)
                .map_err(|_| GenerationCodecError::PackageIdentity)?
                .to_owned();
            packages.push(
                SystemPackage::new(package_id, version, digest)
                    .map_err(GenerationCodecError::InvalidPackage)?,
            );
            cursor = id_end;
        }
        if cursor != bytes.len() {
            return Err(GenerationCodecError::TrailingBytes);
        }
        Self::new(generation, packages).map_err(GenerationCodecError::InvalidGeneration)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GenerationCodecError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(GenerationCodecError::Truncated)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GenerationCodecError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(GenerationCodecError::Truncated)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, GenerationCodecError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(GenerationCodecError::Truncated)?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationCodecError {
    Header,
    Truncated,
    Reserved,
    PackageCount,
    PackageIdentity,
    TrailingBytes,
    InvalidPackage(GenerationError),
    InvalidGeneration(GenerationError),
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
    value.len() <= MAX_PACKAGE_ID_BYTES
        && value.starts_with("org.mrml.")
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

    fn requirement(id: &str, version: u64, marker: u8) -> PackageRequirement {
        PackageRequirement::exact(id.into(), version, [marker; 64]).unwrap()
    }

    fn candidate(
        id: &str,
        version: u64,
        marker: u8,
        dependencies: Vec<PackageRequirement>,
    ) -> PackageCandidate {
        PackageCandidate::exact(package(id, version, marker), dependencies).unwrap()
    }

    #[test]
    fn exact_graph_resolution_constructs_a_canonical_transitive_generation() {
        let roots = [requirement("org.mrml.desktop", 3, 0x30)];
        let candidates = [
            candidate("org.mrml.zstd", 14, 0x2e, vec![]),
            candidate(
                "org.mrml.desktop",
                3,
                0x30,
                vec![requirement("org.mrml.zim", 8, 0x18)],
            ),
            candidate(
                "org.mrml.zim",
                8,
                0x18,
                vec![requirement("org.mrml.zstd", 14, 0x2e)],
            ),
        ];
        let generation = resolve_exact_package_graph(105, &roots, &candidates).unwrap();
        assert_eq!(generation.generation(), 105);
        assert_eq!(
            generation
                .packages()
                .iter()
                .map(SystemPackage::package_id)
                .collect::<Vec<_>>(),
            vec!["org.mrml.desktop", "org.mrml.zim", "org.mrml.zstd"]
        );
    }

    #[test]
    fn exact_graph_resolution_accepts_cycles_but_never_substitutes_or_conflicts() {
        let candidates = [
            candidate(
                "org.mrml.zim",
                8,
                0x18,
                vec![requirement("org.mrml.zstd", 14, 0x2e)],
            ),
            candidate(
                "org.mrml.zstd",
                14,
                0x2e,
                vec![requirement("org.mrml.zim", 8, 0x18)],
            ),
        ];
        assert_eq!(
            resolve_exact_package_graph(106, &[requirement("org.mrml.zim", 8, 0x18)], &candidates,)
                .unwrap()
                .packages()
                .len(),
            2
        );

        let conflicting = [
            candidate(
                "org.mrml.desktop",
                3,
                0x30,
                vec![requirement("org.mrml.zstd", 15, 0x2f)],
            ),
            candidates[0].clone(),
            candidates[1].clone(),
            candidate("org.mrml.zstd", 15, 0x2f, vec![]),
        ];
        assert_eq!(
            resolve_exact_package_graph(
                106,
                &[
                    requirement("org.mrml.desktop", 3, 0x30),
                    requirement("org.mrml.zim", 8, 0x18),
                ],
                &conflicting,
            ),
            Err(GraphResolutionError::ConflictingExactRequirement)
        );
    }

    #[test]
    fn exact_graph_resolution_rejects_missing_ambiguous_and_noncanonical_inputs() {
        let root = requirement("org.mrml.zim", 8, 0x18);
        assert_eq!(
            resolve_exact_package_graph(107, std::slice::from_ref(&root), &[]),
            Err(GraphResolutionError::CandidateCount)
        );
        assert_eq!(
            resolve_exact_package_graph(
                107,
                std::slice::from_ref(&root),
                &[candidate("org.mrml.zstd", 14, 0x2e, vec![])],
            ),
            Err(GraphResolutionError::MissingExactPackage)
        );
        let duplicate = candidate("org.mrml.zim", 8, 0x18, vec![]);
        assert_eq!(
            resolve_exact_package_graph(
                107,
                std::slice::from_ref(&root),
                &[duplicate.clone(), duplicate],
            ),
            Err(GraphResolutionError::AmbiguousExactPackage)
        );
        assert_eq!(
            PackageCandidate::exact(
                package("org.mrml.desktop", 3, 0x30),
                vec![
                    requirement("org.mrml.zstd", 14, 0x2e),
                    requirement("org.mrml.zim", 8, 0x18),
                ],
            ),
            Err(GraphResolutionError::NonCanonicalDependencies)
        );
        assert_eq!(
            PackageCandidate::exact(
                package("org.mrml.zim", 8, 0x18),
                vec![requirement("org.mrml.zim", 8, 0x18)],
            ),
            Err(GraphResolutionError::SelfDependency)
        );
    }

    #[test]
    fn generation_codec_round_trips_exact_canonical_records() {
        let generation = SystemGeneration::new(
            108,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", 14, 0x2e),
            ],
        )
        .unwrap();
        let bytes = generation.encode_canonical();
        assert_eq!(
            SystemGeneration::decode_canonical(&bytes).unwrap(),
            generation
        );
        assert_eq!(
            SystemGeneration::decode_canonical(&bytes)
                .unwrap()
                .encode_canonical(),
            bytes
        );
    }

    #[test]
    fn generation_codec_rejects_mutation_truncation_and_ambiguity() {
        let generation =
            SystemGeneration::new(109, vec![package("org.mrml.zstd", 14, 0x2e)]).unwrap();
        let bytes = generation.encode_canonical();
        for length in 0..bytes.len() {
            assert!(SystemGeneration::decode_canonical(&bytes[..length]).is_err());
        }
        let mut reserved = bytes.clone();
        reserved[20] = 1;
        assert_eq!(
            SystemGeneration::decode_canonical(&reserved),
            Err(GenerationCodecError::Reserved)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SystemGeneration::decode_canonical(&trailing),
            Err(GenerationCodecError::TrailingBytes)
        );
        let mut reordered = SystemGeneration::new(
            109,
            vec![
                package("org.mrml.zim", 8, 0x18),
                package("org.mrml.zstd", 14, 0x2e),
            ],
        )
        .unwrap()
        .encode_canonical();
        let first_id = GENERATION_HEADER_BYTES + PACKAGE_HEADER_BYTES;
        reordered[first_id..first_id + "org.mrml.zim".len()].copy_from_slice(b"org.mrml.zzz");
        assert!(SystemGeneration::decode_canonical(&reordered).is_err());
    }
}
