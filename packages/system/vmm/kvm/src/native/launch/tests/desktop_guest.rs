//! Opt-in proof that the built desktop state machine executes in a signed VM.
use super::*;
use mrml_kernel::{
    IsolationAdmissionTable, IsolationMode, IsolationPlacement, IsolationServiceSpec,
    TotalMicrovmClass, VmDeadlineOutcome, prepare_isolation_service_route,
};

const VIRTUAL: u64 = 0xffff_8001_400f_0000;

#[test]
#[ignore = "requires KVM and a release desktop guest diagnostic image"]
fn live_desktop_guest_handles_seat_events_and_withdraws_mailbox() {
    let path = mrml_runtime::environment_variable("MRML_DESKTOP_GUEST_PROBE")
        .expect("set MRML_DESKTOP_GUEST_PROBE to the built release EFI diagnostic");
    let image = mrml_runtime::read_file_bounded(path.as_str(), 1024 * 1024).unwrap();
    let mut signed =
        mrml_runtime::Vector::with_capacity(SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len()).unwrap();
    signed.resize(SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len(), 0);
    write_signed_fixture_bytes(&image, ArtifactKind::VmImage, &mut signed, 41);
    let peer_image = signed_payload_vector(framebuffer_pe(), ArtifactKind::VmImage);
    let root = |bytes: &[u8]| {
        let at = SIGNED_ARTIFACT_HEADER_BYTES;
        TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&bytes[at..at + LAMPORT_PUBLIC_KEY_BYTES]),
            1,
        )
    };
    let a = SignedArtifact::decode(&signed)
        .unwrap()
        .verify_executable(&root(&signed), ArtifactKind::VmImage)
        .unwrap();
    let b = SignedArtifact::decode(&peer_image)
        .unwrap()
        .verify_executable(&root(&peer_image), ArtifactKind::VmImage)
        .unwrap();
    let layout = |base| {
        KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            base,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap()
    };
    let mut admission =
        IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 1, 1).unwrap();
    let spec = IsolationServiceSpec::new(
        ObjectId(0xd01),
        ObjectId(0xd02),
        1,
        1,
        1,
        1,
        TotalMicrovmClass::MicrovmEligible,
        IsolationPlacement::Microvm,
    )
    .unwrap();
    let prepared = prepare_isolation_service_route(&mut admission, spec).unwrap();
    let system = KvmSystem::open().expect("live KVM needed");
    let mut first = system
        .prepare_guest::<8>(0, &a, &valid_handoff(), layout(0xffff_8001_4000_0000))
        .unwrap();
    let mut second = system
        .prepare_guest::<8>(0, &b, &valid_handoff(), layout(b.image().image_base()))
        .unwrap();

    let mut caps = CapabilitySpace::<8>::new();
    let mut memory = MemoryPoolTable::<1, 1, 2>::new(0xd10).unwrap();
    let (pool, quota) = memory
        .create_root(
            1,
            2,
            0,
            Rights::ALLOCATE
                .union(Rights::CONTROL)
                .union(Rights::INSPECT),
            &mut caps,
        )
        .unwrap();
    let right = Rights::MAP.union(Rights::CONTROL).union(Rights::INSPECT);
    let left = caps.insert(ObjectId(0xd11), right).unwrap();
    let right = caps.insert(ObjectId(0xd12), right).unwrap();
    let (projection, _) = reserve_microvm_peer_page_projection(
        &mut memory,
        pool,
        quota,
        left,
        right,
        VIRTUAL / PAGE_SIZE,
        VIRTUAL / PAGE_SIZE,
        &mut caps,
    )
    .unwrap();
    let mut page = PreparedKvmPeerPage::prepare(
        &mut first,
        &mut second,
        &projection,
        left,
        right,
        &caps,
        0x70_0000,
        0x80_0000,
    )
    .unwrap_or_else(|failure| panic!("desktop fixture mailbox: {:?}", failure.error()));
    let route = prepared.commit(&mut admission, ()).unwrap();
    assert!(route.is_live_in(&admission));

    let mut step = |operation: u8, payload: [u8; 4]| {
        let mut packet = [0; 32];
        packet[0] = operation;
        packet[2..6].copy_from_slice(&payload);
        page.write_second(&packet).unwrap();
        assert_eq!(
            DeadlineVmBackend::run_with_deadline(page.first, 0, 1_000_000).unwrap(),
            VmDeadlineOutcome::Exit(VmExit::Halted)
        );
        page.read_second(&mut packet).unwrap();
        packet
    };
    // Tap opens the terminal without a cursor; input still lives in the guest.
    assert_eq!(step(5, [150, 0, 15, 0])[..2], [0x51, 4]);
    let tap = step(6, [150, 0, 15, 0]);
    assert_eq!(tap[..2], [0x51, 5]);
    assert_eq!(tap[16..20], 2u32.to_le_bytes());
    let typed = step(7, u32::from('λ').to_le_bytes());
    assert_eq!(typed[8..12], u32::from('λ').to_le_bytes());
    assert_eq!(typed[12..16], 1u32.to_le_bytes());
    assert_eq!(step(2, [0; 4])[..2], [0x51, 7]);
    let motion = step(3, [2, 0, 1, 0]);
    assert_eq!(motion[2..6], [242, 0, 141, 0]);
    assert_eq!(motion[20..24], 1u32.to_le_bytes());
    assert_eq!(step(4, [0; 4])[..2], [0x51, 5]);
    assert_eq!(step(0xff, [0; 4])[..2], [0x52, 5]);

    admission.retire(route.domain()).unwrap();
    assert!(!route.is_live_in(&admission));
    page.retire()
        .unwrap_or_else(|(error, _)| panic!("desktop fixture retirement: {error:?}"));
    for guest in [&first, &second] {
        assert_eq!(
            guest.page_walk(VIRTUAL).unwrap().physical_address(VIRTUAL),
            None
        );
    }
}
