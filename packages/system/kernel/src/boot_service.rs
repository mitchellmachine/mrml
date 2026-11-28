use crate::{
    ArtifactError, ArtifactKind, MAX_SERVICE_IMAGE_BYTES, PAGE_SIZE, PeError, PeImage,
    ServiceLaunch, SignedArtifact,
};
use mrml_crypto::Sha3_512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootServiceImageError {
    Container(ArtifactError),
    WrongKind,
    ReleaseMismatch,
    MeasurementMismatch,
    Image(PeError),
    LayoutMismatch,
}

/// A retained boot payload checked against the loader's service handoff.
/// This is data for a future guest builder, not signature verification, a
/// supervisor identity, a capability, or permission to execute natively.
pub struct BootServiceImage<'a> {
    image: PeImage<'a>,
}

impl<'a> BootServiceImage<'a> {
    /// The caller must separately trust the handoff: the expected digest
    /// comes from the loader's authenticated coherent release, not the
    /// envelope's self-declared digest or a key supplied by the payload.
    pub fn check(
        launch: ServiceLaunch,
        accepted_release: u64,
        bytes: &'a [u8],
    ) -> Result<Self, BootServiceImageError> {
        if u64::try_from(bytes.len()).ok() != Some(launch.artifact_length()) {
            return Err(BootServiceImageError::LayoutMismatch);
        }
        let artifact = SignedArtifact::decode(bytes).map_err(BootServiceImageError::Container)?;
        if artifact.kind() != ArtifactKind::ServiceImage {
            return Err(BootServiceImageError::WrongKind);
        }
        if artifact.version() != accepted_release || launch.version() != accepted_release {
            return Err(BootServiceImageError::ReleaseMismatch);
        }
        if Sha3_512::digest(artifact.payload()) != launch.measurement() {
            return Err(BootServiceImageError::MeasurementMismatch);
        }
        let image = PeImage::parse_with_limit(artifact.payload(), MAX_SERVICE_IMAGE_BYTES)
            .map_err(BootServiceImageError::Image)?;
        if u64::from(image.image_size()).div_ceil(PAGE_SIZE) != launch.image_pages()
            || image.image_base() != launch.image_virtual()
            || image.image_base().checked_add(u64::from(image.entry_rva())) != Some(launch.entry())
        {
            return Err(BootServiceImageError::LayoutMismatch);
        }
        Ok(Self { image })
    }

    /// Guests must be materialized from these checked source bytes, not
    /// by adopting the loader's legacy native page tables or staging image.
    pub const fn image(&self) -> &PeImage<'a> {
        &self.image
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PhysAddr, SIGNED_ARTIFACT_OVERHEAD_BYTES};

    const BASE: u64 = 0x0000_0001_4000_0000;

    fn bundle(
        payload: [u8; 1024],
        kind: ArtifactKind,
        version: u64,
    ) -> [u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024] {
        // Only the envelope and its digest are relevant to this test. This
        // intentionally has no valid signature; check() is a transport check.
        let mut bytes = [0; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024];
        bytes[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        bytes[16] = kind as u8;
        bytes[24..32].copy_from_slice(&version.to_le_bytes());
        bytes[32..40].copy_from_slice(&1024u64.to_le_bytes());
        bytes[40..104].copy_from_slice(&Sha3_512::digest(&payload));
        bytes[SIGNED_ARTIFACT_OVERHEAD_BYTES..].copy_from_slice(&payload);
        bytes
    }

    fn launch(payload: &[u8], pages: u64, entry: u64) -> ServiceLaunch {
        let phys = |at| PhysAddr::new(at).unwrap();
        ServiceLaunch::new(
            phys(0x10000),
            (SIGNED_ARTIFACT_OVERHEAD_BYTES + payload.len()) as u64,
            phys(0x30000),
            pages,
            BASE,
            entry,
            phys(0x40000),
            4,
            0x0000_0002_0000_0000,
            phys(0x50000),
            4,
            7,
            Sha3_512::digest(payload),
        )
        .unwrap()
    }

    #[test]
    fn retained_service_matches_exact_release_digest_and_single_image_layout() {
        let payload = crate::pe::tests::valid_pe();
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let expected = launch(&payload, 2, BASE + PAGE_SIZE);
        assert_eq!(
            BootServiceImage::check(expected, 7, &original)
                .unwrap()
                .image()
                .entry_rva(),
            4096
        );
        assert_eq!(
            BootServiceImage::check(expected, 8, &original).err(),
            Some(BootServiceImageError::ReleaseMismatch)
        );
        assert_eq!(
            BootServiceImage::check(expected, 7, &bundle(payload, ArtifactKind::ServiceImage, 8))
                .err(),
            Some(BootServiceImageError::ReleaseMismatch)
        );
        assert_eq!(
            BootServiceImage::check(
                expected,
                7,
                &bundle(payload, ArtifactKind::ApplicationImage, 7)
            )
            .err(),
            Some(BootServiceImageError::WrongKind)
        );
        let mut changed = payload;
        changed[0x200] ^= 1;
        assert_eq!(
            BootServiceImage::check(expected, 7, &bundle(changed, ArtifactKind::ServiceImage, 7))
                .err(),
            Some(BootServiceImageError::MeasurementMismatch)
        );
        assert_eq!(
            BootServiceImage::check(expected, 7, &original[1..]).err(),
            Some(BootServiceImageError::LayoutMismatch)
        );
        for mismatched in [
            launch(&payload, 4, BASE + PAGE_SIZE),
            launch(&payload, 2, BASE + PAGE_SIZE + 1),
        ] {
            assert_eq!(
                BootServiceImage::check(mismatched, 7, &original).err(),
                Some(BootServiceImageError::LayoutMismatch)
            );
        }
        let invalid = [0; 1024];
        assert!(matches!(
            BootServiceImage::check(
                launch(&invalid, 2, BASE + PAGE_SIZE),
                7,
                &bundle(invalid, ArtifactKind::ServiceImage, 7)
            ),
            Err(BootServiceImageError::Image(_))
        ));
    }
}
