use mrml_package_format::SystemGenerationView;

use crate::{
    ArtifactKind, IsolationApplicationSpec, IsolationApplicationSpecError, IsolationPlacement,
    ObjectId, VerifiedArtifact,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationArtifactBindingError {
    WrongArtifactKind,
    PackageAbsent,
    GenerationMismatch,
    ArtifactMismatch,
    InvalidRoute(IsolationApplicationSpecError),
}

/// Exact application identity derived from two already authenticated inputs:
/// the application artifact and its package record in one immutable
/// `SystemGeneration`. Neither a filename nor package metadata grants launch
/// authority. The caller must separately possess authority to route the result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedApplicationImage {
    system_generation: u64,
    application_generation: u64,
    artifact_digest: [u8; 64],
}

impl VerifiedApplicationImage {
    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn application_generation(self) -> u64 {
        self.application_generation
    }

    pub const fn artifact_digest(self) -> [u8; 64] {
        self.artifact_digest
    }

    pub fn route_spec(
        self,
        domain: ObjectId,
        application: ObjectId,
        policy_generation: u64,
        placement: IsolationPlacement,
    ) -> Result<IsolationApplicationSpec, ApplicationArtifactBindingError> {
        IsolationApplicationSpec::new(
            domain,
            application,
            self.application_generation,
            self.artifact_digest,
            self.system_generation,
            policy_generation,
            placement,
        )
        .map_err(ApplicationArtifactBindingError::InvalidRoute)
    }
}

/// Binds signed application payload identity to the exact package generation
/// selected by the active system generation. All comparisons precede creation
/// of route-ready state and fail closed on absence or substitution.
pub fn bind_verified_application_image(
    package_id: &str,
    generation: SystemGenerationView<'_>,
    artifact: &VerifiedArtifact,
) -> Result<VerifiedApplicationImage, ApplicationArtifactBindingError> {
    if artifact.kind() != ArtifactKind::ApplicationImage {
        return Err(ApplicationArtifactBindingError::WrongArtifactKind);
    }
    let package = generation
        .package(package_id)
        .ok_or(ApplicationArtifactBindingError::PackageAbsent)?;
    if package.version() != artifact.version() {
        return Err(ApplicationArtifactBindingError::GenerationMismatch);
    }
    if package.artifact_digest() != artifact.digest() {
        return Err(ApplicationArtifactBindingError::ArtifactMismatch);
    }
    Ok(VerifiedApplicationImage {
        system_generation: generation.generation(),
        application_generation: artifact.version(),
        artifact_digest: *artifact.digest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, Sha3_512,
        lamport_public_key, lamport_sign,
    };
    use mrml_package_format::{SystemGenerationDigestRecord, encode_system_generation};

    use crate::{IsolationPlacement, TrustRoot, artifact_statement};

    const PACKAGE_ID: &str = "org.mrml.app.isolation-probe";

    fn verified_kind(kind: ArtifactKind, version: u64, payload: &[u8]) -> VerifiedArtifact {
        let private = [0x5a; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let digest = Sha3_512::digest(payload);
        let statement = artifact_statement(kind, version, payload.len() as u64, digest);
        let mut signature = [0; LAMPORT_SIGNATURE_BYTES];
        lamport_sign(&private, &statement, &mut signature).unwrap();
        TrustRoot::new(kind, Sha3_512::digest(&public), version)
            .verify(version, payload, &public, &signature)
            .unwrap()
    }

    fn verified(version: u64, payload: &[u8]) -> VerifiedArtifact {
        verified_kind(ArtifactKind::ApplicationImage, version, payload)
    }

    fn generation(version: u64, digest: &[u8; 64]) -> ([u8; 256], usize) {
        let mut bytes = [0; 256];
        let length = encode_system_generation(
            19,
            &[SystemGenerationDigestRecord {
                package_id: PACKAGE_ID,
                version,
                artifact_digest: digest,
            }],
            &mut bytes,
        )
        .unwrap();
        (bytes, length)
    }

    #[test]
    fn exact_signed_application_generation_produces_route_identity() {
        let artifact = verified(7, b"application-image");
        let (bytes, length) = generation(7, artifact.digest());
        let view = SystemGenerationView::decode(&bytes[..length]).unwrap();
        let bound = bind_verified_application_image(PACKAGE_ID, view, &artifact).unwrap();
        let spec = bound
            .route_spec(
                ObjectId(0x444f_4d41_494e),
                ObjectId(0x4150_50),
                23,
                IsolationPlacement::Microvm,
            )
            .unwrap();
        assert_eq!(bound.system_generation(), 19);
        assert_eq!(spec.system_generation(), 19);
        assert_eq!(spec.application_generation(), 7);
        assert_eq!(spec.application_artifact(), *artifact.digest());
        assert_eq!(spec.placement(), IsolationPlacement::Microvm);
    }

    #[test]
    fn package_absence_version_and_digest_substitution_fail_closed() {
        let artifact = verified(7, b"application-image");
        let (bytes, length) = generation(8, artifact.digest());
        let view = SystemGenerationView::decode(&bytes[..length]).unwrap();
        assert_eq!(
            bind_verified_application_image(PACKAGE_ID, view, &artifact),
            Err(ApplicationArtifactBindingError::GenerationMismatch)
        );
        assert_eq!(
            bind_verified_application_image("org.mrml.app.other", view, &artifact),
            Err(ApplicationArtifactBindingError::PackageAbsent)
        );

        let other = verified(7, b"other-application-image");
        let (bytes, length) = generation(7, artifact.digest());
        let view = SystemGenerationView::decode(&bytes[..length]).unwrap();
        assert_eq!(
            bind_verified_application_image(PACKAGE_ID, view, &other),
            Err(ApplicationArtifactBindingError::ArtifactMismatch)
        );

        let service = verified_kind(ArtifactKind::ServiceImage, 7, b"application-image");
        assert_eq!(
            bind_verified_application_image(PACKAGE_ID, view, &service),
            Err(ApplicationArtifactBindingError::WrongArtifactKind)
        );
    }
}
