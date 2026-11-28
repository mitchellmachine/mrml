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
    release: u64,
    measurement: [u8; 64],
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
        Ok(Self {
            image,
            release: accepted_release,
            measurement: launch.measurement(),
        })
    }

    /// Guests must be materialized from these checked source bytes, not
    /// by adopting the loader's legacy native page tables or staging image.
    pub const fn image(&self) -> &PeImage<'a> {
        &self.image
    }
}

/// Canonical boot-owner policy record for the first supervisor role. Decoding
/// does not grant authority. The enrolled owner policy must pin the hash of the
/// record separately from the publisher's release and build receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootSupervisorSelection {
    release: u64,
    manifest: [u8; 64],
    service: [u8; 64],
}

pub const BOOT_SUPERVISOR_SELECTION_BYTES: usize = 152;
const SUPERVISOR_ROLE: &[u8; 16] = b"MRML-SUPERVISOR1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSupervisorError {
    InvalidSelection,
    NotOwnerSelected,
    WrongRelease,
    WrongService,
    Image(PeError),
}

impl BootSupervisorSelection {
    pub fn new(
        release: u64,
        manifest: [u8; 64],
        service: [u8; 64],
    ) -> Result<Self, BootSupervisorError> {
        if release == 0 || manifest == [0; 64] || service == [0; 64] {
            return Err(BootSupervisorError::InvalidSelection);
        }
        Ok(Self {
            release,
            manifest,
            service,
        })
    }

    pub(crate) fn matches_launch(self, release: u64, service: ServiceLaunch) -> bool {
        self.release == release
            && service.version() == release
            && self.service == service.measurement()
    }

    pub fn encode(self) -> [u8; BOOT_SUPERVISOR_SELECTION_BYTES] {
        let mut bytes = [0; BOOT_SUPERVISOR_SELECTION_BYTES];
        bytes[..16].copy_from_slice(SUPERVISOR_ROLE);
        bytes[16..24].copy_from_slice(&self.release.to_le_bytes());
        bytes[24..88].copy_from_slice(&self.manifest);
        bytes[88..].copy_from_slice(&self.service);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BootSupervisorError> {
        if bytes.len() != BOOT_SUPERVISOR_SELECTION_BYTES || &bytes[..16] != SUPERVISOR_ROLE {
            return Err(BootSupervisorError::InvalidSelection);
        }
        Self::new(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            bytes[24..88].try_into().unwrap(),
            bytes[88..].try_into().unwrap(),
        )
    }

    /// Bind checked transport to independently authenticated owner policy and
    /// the manifest identity of the accepted coherent release. Neither input
    /// may come from the untrusted record itself or the service image.
    pub fn bind<'a>(
        self,
        owner_selected_digest: [u8; 64],
        accepted_manifest: [u8; 64],
        service: BootServiceImage<'a>,
    ) -> Result<SelectedBootSupervisor<'a>, BootSupervisorError> {
        if owner_selected_digest == [0; 64]
            || Sha3_512::digest(&self.encode()) != owner_selected_digest
        {
            return Err(BootSupervisorError::NotOwnerSelected);
        }
        if self.release != service.release || self.manifest != accepted_manifest {
            return Err(BootSupervisorError::WrongRelease);
        }
        if self.service != service.measurement {
            return Err(BootSupervisorError::WrongService);
        }
        Ok(SelectedBootSupervisor {
            image: service.image,
        })
    }
}

/// An owner-selected source, not a launched guest or a capability.
///
/// The fresh backing and its eventual EPT ownership remain the responsibility
/// of the guest builder. No references to the loader's native PE, stack or
/// page-table mappings are accepted by this interface.
pub struct SelectedBootSupervisor<'a> {
    image: PeImage<'a>,
}

impl<'image> SelectedBootSupervisor<'image> {
    pub const fn image_size(&self) -> u32 {
        self.image.image_size()
    }

    /// Populate a caller-owned, non-executable buffer. The returned entry is
    /// a guest virtual address at the PE's preferred base, not a host pointer.
    /// The final guest plan maps only the validated PE regions.
    pub fn stage<'a>(
        self,
        destination: &'a mut [u8],
    ) -> Result<StagedBootSupervisor<'a, 'image>, BootSupervisorError> {
        let entry = self
            .image
            .materialize(destination)
            .map_err(BootSupervisorError::Image)?;
        Ok(StagedBootSupervisor {
            image: self.image,
            bytes: destination,
            entry,
        })
    }
}

pub struct StagedBootSupervisor<'memory, 'image> {
    image: PeImage<'image>,
    bytes: &'memory [u8],
    entry: u64,
}

impl StagedBootSupervisor<'_, '_> {
    pub const fn guest_entry(&self) -> u64 {
        self.entry
    }

    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub const fn guest_image_base(&self) -> u64 {
        self.image.image_base()
    }

    pub const fn load_region_count(&self) -> usize {
        self.image.load_region_count()
    }

    pub fn load_region(&self, index: usize) -> Result<crate::PeLoadRegion, PeError> {
        self.image.load_region(index)
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

    #[test]
    fn owner_selected_supervisor_stages_exact_pe_from_source() {
        let payload = crate::pe::tests::valid_pe();
        let original = bundle(payload, ArtifactKind::ServiceImage, 7);
        let expected = launch(&payload, 2, BASE + PAGE_SIZE);
        let checked = || BootServiceImage::check(expected, 7, &original).unwrap();
        let manifest = [0x12; 64];
        let selection =
            BootSupervisorSelection::new(7, manifest, Sha3_512::digest(&payload)).unwrap();
        let record = selection.encode();
        let pin = Sha3_512::digest(&record);
        assert_eq!(BootSupervisorSelection::decode(&record), Ok(selection));
        assert_eq!(
            selection.bind([0; 64], manifest, checked()).err(),
            Some(BootSupervisorError::NotOwnerSelected),
        );
        assert_eq!(
            selection.bind(pin, [0x13; 64], checked()).err(),
            Some(BootSupervisorError::WrongRelease),
        );
        let old = BootSupervisorSelection::new(6, manifest, Sha3_512::digest(&payload)).unwrap();
        assert_eq!(
            old.bind(Sha3_512::digest(&old.encode()), manifest, checked())
                .err(),
            Some(BootSupervisorError::WrongRelease),
        );
        let substitute = BootSupervisorSelection::new(7, manifest, [0x24; 64]).unwrap();
        assert_eq!(
            substitute.bind(pin, manifest, checked()).err(),
            Some(BootSupervisorError::NotOwnerSelected),
        );
        assert_eq!(
            substitute
                .bind(Sha3_512::digest(&substitute.encode()), manifest, checked())
                .err(),
            Some(BootSupervisorError::WrongService),
        );
        let selected = || selection.bind(pin, manifest, checked()).unwrap();
        assert_eq!(selected().image_size(), 8192);
        let mut short = [0xa5; 8191];
        assert_eq!(
            selected().stage(&mut short).err(),
            Some(BootSupervisorError::Image(PeError::InvalidDestination)),
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));
        let mut backing = [0xa5; 8192];
        let staged = selected().stage(&mut backing).unwrap();
        assert_eq!(staged.guest_image_base(), BASE);
        assert_eq!(staged.guest_entry(), BASE + PAGE_SIZE);
        assert_eq!(&staged.bytes()[4096..4608], &payload[0x200..0x400]);
        assert!(staged.bytes()[4608..].iter().all(|byte| *byte == 0));
        assert_eq!(staged.load_region_count(), 2);
        assert!(!staged.load_region(0).unwrap().executable());
        assert!(!staged.load_region(0).unwrap().writable());
        assert!(staged.load_region(1).unwrap().executable());
        assert!(!staged.load_region(1).unwrap().writable());
        assert_eq!(staged.load_region(2), Err(PeError::InvalidSection));
    }

    #[test]
    fn supervisor_selection_rejects_noncanonical_records() {
        let mut record = BootSupervisorSelection::new(7, [1; 64], [2; 64])
            .unwrap()
            .encode();
        assert_eq!(
            BootSupervisorSelection::decode(&record[..151]),
            Err(BootSupervisorError::InvalidSelection),
        );
        for (offset, width) in [(0, 16), (16, 8), (24, 64), (88, 64)] {
            let original = record;
            record[offset..offset + width].fill(0);
            assert_eq!(
                BootSupervisorSelection::decode(&record),
                Err(BootSupervisorError::InvalidSelection),
            );
            record = original;
        }
    }
}
