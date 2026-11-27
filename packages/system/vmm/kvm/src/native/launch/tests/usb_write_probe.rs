//! Live KVM exercise for the USB diagnostic queue, with a synthetic BOT disk.
//! The signed consumer supplies the marker via its actual shared-page mapping.
//! No physical controller, guest driver, host file, or raw device is exposed.

use super::*;
use mrml_interface_storage_block_provider_v1::{OpaqueHandle, WRITE_REQUEST_BYTES};
use mrml_kernel::VmDeadlineOutcome;
use mrml_storage_usb::{
    BulkTransport, SECTOR_BYTES, UsbDisk,
    block_provider::UsbReadProvider,
    diagnostic_partition::{
        DiagnosticPartition, DiagnosticPartitionAssignment,
        microvm_queue::{ProbeQueueGenerations, bind_probe_write},
    },
};

const VIRTUAL: u64 = 0xffff_8001_400f_0000;
const QUEUE_HEADER: u64 = PAGE_SIZE - mrml_kernel::MICROVM_INTERFACE_QUEUE_MAX_PAYLOAD as u64;
const INPUT_OFFSET: u64 = QUEUE_HEADER + WRITE_REQUEST_BYTES as u64;
const RECORD_OFFSET: u64 = 1024;
const PARTITION_START: u32 = 32;
const FILE_SECTOR: u32 = PARTITION_START + 1;

struct SyntheticDisk<'a> {
    data: &'a mut [u8; SECTOR_BYTES],
    command: Option<(u8, u32, [u8; 4], bool)>,
    flush_confirmed: &'a mut bool,
}

impl BulkTransport for SyntheticDisk<'_> {
    type Error = ();

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        match self.command {
            None if bytes.len() == 31 && &bytes[..4] == b"USBC" => {
                let opcode = bytes[15];
                let lba = u32::from_be_bytes(bytes[17..21].try_into().unwrap());
                let tag = bytes[4..8].try_into().unwrap();
                if !matches!(opcode, 0x25 | 0x28 | 0x2a | 0x35) {
                    return Err(());
                }
                if opcode == 0x35 {
                    *self.flush_confirmed = true;
                }
                self.command = Some((opcode, lba, tag, opcode == 0x35));
            }
            Some((0x2a, FILE_SECTOR, tag, false)) if bytes.len() == SECTOR_BYTES => {
                self.data.copy_from_slice(bytes);
                *self.flush_confirmed = false;
                self.command = Some((0x2a, FILE_SECTOR, tag, true));
            }
            _ => return Err(()),
        }
        Ok(bytes.len())
    }

    fn bulk_in(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        let (opcode, lba, tag, status) = self.command.ok_or(())?;
        output.fill(0);
        match (opcode, lba, status, output.len()) {
            (_, _, true, 13) => {
                output[..4].copy_from_slice(b"USBS");
                output[4..8].copy_from_slice(&tag);
                self.command = None;
                return Ok(output.len());
            }
            (0x25, _, false, 8) => {
                output[..4].copy_from_slice(&63u32.to_be_bytes());
                output[4..].copy_from_slice(&(SECTOR_BYTES as u32).to_be_bytes());
            }
            (0x28, 0, false, SECTOR_BYTES) => {
                output[450] = 0x0c;
                output[454..458].copy_from_slice(&PARTITION_START.to_le_bytes());
                output[458..462].copy_from_slice(&32u32.to_le_bytes());
                output[510..].copy_from_slice(&[0x55, 0xaa]);
            }
            (0x28, FILE_SECTOR, false, SECTOR_BYTES) if *self.flush_confirmed => {
                output.copy_from_slice(self.data);
            }
            _ => return Err(()),
        }
        self.command = Some((opcode, lba, tag, true));
        Ok(output.len())
    }
}

fn guest_pe(check_reply: bool) -> [u8; 1024] {
    let mut pe = framebuffer_pe();
    let mut code = [0; 512];
    let mut at = 0;
    if check_reply {
        emit_mov(&mut code, &mut at, 0xbf, VIRTUAL + QUEUE_HEADER);
        emit(&mut code, &mut at, &[0x48, 0x83, 0x3f, 0, 0x74, 1, 0xcc]); // exact success
        emit(
            &mut code,
            &mut at,
            &[0x48, 0x81, 0x7f, 8, 0, 2, 0, 0, 0x74, 1, 0xcc],
        ); // 512
        emit_mov(&mut code, &mut at, 0xbf, VIRTUAL + RECORD_OFFSET);
        emit(&mut code, &mut at, &[0xc6, 0x07, 0x61]); // record guest observation
    } else {
        emit_mov(&mut code, &mut at, 0xbf, VIRTUAL + INPUT_OFFSET);
        emit(&mut code, &mut at, &[0x66, 0xc7, 0x07, b'n', b'e']);
        emit(&mut code, &mut at, &[0xc6, 0x47, 2, b'w']);
    }
    emit(&mut code, &mut at, &[0xf4]); // halt at the diagnostic boundary
    let section = 0x98 + 240;
    pe[section + 8..section + 12].copy_from_slice(&(at as u32).to_le_bytes());
    pe[0x200..0x200 + at].copy_from_slice(&code[..at]);
    pe
}

fn signed_guest(pe: [u8; 1024], seed: u8) -> [u8; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024] {
    let mut bytes = [0; SIGNED_ARTIFACT_OVERHEAD_BYTES + 1024];
    write_signed_fixture(pe, ArtifactKind::VmImage, &mut bytes, seed);
    bytes
}

pub(super) fn exercise() {
    let system = KvmSystem::open().expect("live KVM required for this diagnostic");
    let first_image = signed_guest(guest_pe(false), 0);
    let second_image = signed_guest(guest_pe(true), 1);
    let verify = |encoded: &[u8]| {
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_at + LAMPORT_PUBLIC_KEY_BYTES]),
            1,
        )
    };
    let a = SignedArtifact::decode(&first_image).unwrap();
    let b = SignedArtifact::decode(&second_image).unwrap();
    let a = a
        .verify_executable(&verify(&first_image), ArtifactKind::VmImage)
        .unwrap();
    let b = b
        .verify_executable(&verify(&second_image), ArtifactKind::VmImage)
        .unwrap();
    assert_ne!(a.artifact().digest(), b.artifact().digest());
    let layout = KvmLaunchLayout::new(
        0x10_0000,
        16,
        0x20_0000,
        0xffff_8001_4000_0000,
        0x30_0000,
        0xffff_8001_5000_0000,
        0x40_0000,
        0xffff_8001_6000_0000,
        PRIVILEGE_STACK_ARENA_PAGES,
        false,
    )
    .unwrap();
    let mut first = system
        .prepare_guest::<8>(0, &a, &valid_handoff(), layout)
        .unwrap();
    let mut second = system
        .prepare_guest::<8>(0, &b, &valid_handoff(), layout)
        .unwrap();

    let mut caps = CapabilitySpace::<9>::new();
    let mut memory = MemoryPoolTable::<1, 1, 2>::new(0xa10).unwrap();
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
    let peer_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
    let client_cap = caps.insert(ObjectId(0xa11), peer_rights).unwrap();
    let provider_cap = caps.insert(ObjectId(0xa12), peer_rights).unwrap();
    let object = ObjectId(0xa13);
    let storage_cap = caps
        .insert(object, Rights::READ.union(Rights::WRITE))
        .unwrap();
    let (projection, _) = reserve_microvm_peer_page_projection(
        &mut memory,
        pool,
        quota,
        client_cap,
        provider_cap,
        VIRTUAL / PAGE_SIZE,
        VIRTUAL / PAGE_SIZE,
        &mut caps,
    )
    .unwrap();
    let mut peer = PreparedKvmPeerPage::prepare(
        &mut first,
        &mut second,
        &projection,
        client_cap,
        provider_cap,
        &caps,
        0x70_0000,
        0x80_0000,
    )
    .unwrap_or_else(|failed| panic!("guest peer mapping: {:?}", failed.error()));

    let mut data = [0xa5; SECTOR_BYTES];
    data[..3].copy_from_slice(b"old");
    let mut flushed = false;
    let disk = UsbDisk::probe(SyntheticDisk {
        data: &mut data,
        command: None,
        flush_confirmed: &mut flushed,
    })
    .unwrap();
    let disk_session = OpaqueHandle::new(1, 1).unwrap();
    let partition_session = OpaqueHandle::new(2, 1).unwrap();
    let mut usb = UsbReadProvider::new(disk, disk_session, 3).unwrap();
    let partition = DiagnosticPartition::open(
        &mut usb,
        DiagnosticPartitionAssignment {
            disk_session,
            partition_session,
            media_generation: 3,
            partition: object,
            first_lba: PARTITION_START,
            sectors: 32,
            file_sector: 1,
        },
        storage_cap,
        &caps,
    )
    .unwrap();
    let (mut client, mut provider) = bind_probe_write(
        partition,
        ProbeQueueGenerations {
            provider: 1,
            system: 1,
            policy: 1,
            binding: 1,
        },
        &projection,
        client_cap,
        provider_cap,
        &caps,
    )
    .unwrap();
    let mut page = [0; PAGE_SIZE as usize];
    let mut old = [0xa5; SECTOR_BYTES];
    old[..3].copy_from_slice(b"old");
    client.initialize(&mut page, &projection, &caps).unwrap();
    let request = client
        .submit(&mut page, &projection, &caps, 1, &old)
        .unwrap();
    peer.write_first(&page).unwrap();
    assert_eq!(
        DeadlineVmBackend::run_with_deadline(peer.first, 0, 1_000_000).unwrap(),
        VmDeadlineOutcome::Exit(VmExit::Halted)
    );
    peer.read_second(&mut page).unwrap();
    let pos = INPUT_OFFSET as usize;
    assert_eq!(&page[pos..pos + 3], b"new");
    assert_eq!(&page[pos + 3..pos + SECTOR_BYTES], &old[3..]);

    let response = provider
        .serve(&mut page, &projection, &caps, request)
        .unwrap();
    peer.write_second(&page).unwrap();
    assert_eq!(
        DeadlineVmBackend::run_with_deadline(peer.second, 0, 1_000_000).unwrap(),
        VmDeadlineOutcome::Exit(VmExit::Halted)
    );
    peer.read_first(&mut page).unwrap();
    assert_eq!(page[RECORD_OFFSET as usize], 0x61);
    client
        .complete(&mut page, &projection, &caps, response)
        .unwrap();
    peer.retire()
        .unwrap_or_else(|(error, _)| panic!("guest peer retirement: {error:?}"));
    assert_eq!(
        first.page_walk(VIRTUAL).unwrap().physical_address(VIRTUAL),
        None
    );
    assert_eq!(
        second.page_walk(VIRTUAL).unwrap().physical_address(VIRTUAL),
        None
    );
    assert_eq!(&data[..3], b"new");
    assert_eq!(&data[3..], &old[3..]);
    assert!(flushed);
    mrml_runtime::mrml_println!(
        "usb-write-guest|status=PASS|backend=kvm|bot=synthetic|guest_marker=new"
    );
}

pub(super) fn exercise_in_guest() {
    run_signed_probe(ProbeMode::Synthetic);
}

pub(super) fn exercise_external() {
    for super_speed in [false, true] {
        mrml_usb_fat32_qtest::with_emulated_probe_disk(super_speed, &mut |pipe| {
            run_signed_probe(ProbeMode::Bulk(pipe));
        });
    }
    mrml_runtime::mrml_println!(
        "usb-write-guest|status=PASS|backend=kvm|bot=guest|xhci=qemu|speeds=2,3|file=PROBE.TXT"
    );
}

pub(super) fn exercise_preflight() {
    for super_speed in [false, true] {
        mrml_usb_fat32_qtest::with_emulated_probe_preflight(super_speed, &mut |io| {
            run_signed_probe(ProbeMode::Preflight(io));
        });
    }
    mrml_runtime::mrml_println!(
        "usb-preflight-guest|status=PASS|backend=kvm|xhci=qemu|speeds=2,3|bus_master=off"
    );
}

enum ProbeMode<'a> {
    Synthetic,
    Bulk(&'a mut dyn BulkTransport<Error = ()>),
    Preflight(&'a mut (dyn mrml_usb_fat32_qtest::PreflightIo + 'a)),
}

fn run_signed_probe(mut mode: ProbeMode<'_>) {
    const PAYLOAD: usize = 16;
    // Three BOT transfers for every metadata sector, plus probe and readback.
    const MAX_EXITS: usize = 3_400;
    let path = mrml_runtime::environment_variable("MRML_USB_GUEST_PROBE")
        .expect("set MRML_USB_GUEST_PROBE to the release EFI diagnostic path");
    let image = mrml_runtime::read_file_bounded(path.as_str(), 1024 * 1024).unwrap();
    let mut signed =
        mrml_runtime::Vector::with_capacity(SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len()).unwrap();
    signed.resize(SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len(), 0);
    // These fixture keys are intentionally public and never trusted by a deployed system.
    write_signed_fixture_bytes(&image, ArtifactKind::VmImage, &mut signed, 27);
    let peer_image = signed_guest(framebuffer_pe(), 28);
    let verify = |encoded: &[u8]| {
        let public_at = SIGNED_ARTIFACT_HEADER_BYTES;
        TrustRoot::new(
            ArtifactKind::VmImage,
            Sha3_512::digest(&encoded[public_at..public_at + LAMPORT_PUBLIC_KEY_BYTES]),
            1,
        )
    };
    let a = SignedArtifact::decode(&signed)
        .unwrap()
        .verify_executable(&verify(&signed), ArtifactKind::VmImage)
        .unwrap();
    let b = SignedArtifact::decode(&peer_image)
        .unwrap()
        .verify_executable(&verify(&peer_image), ArtifactKind::VmImage)
        .unwrap();
    let layout = |image_virtual| {
        KvmLaunchLayout::new(
            0x10_0000,
            16,
            0x20_0000,
            image_virtual,
            0x30_0000,
            0xffff_8001_5000_0000,
            0x40_0000,
            0xffff_8001_6000_0000,
            PRIVILEGE_STACK_ARENA_PAGES,
            false,
        )
        .unwrap()
    };
    let system = KvmSystem::open().expect("live KVM required for the USB guest");
    let mut first = system
        .prepare_guest::<8>(0, &a, &valid_handoff(), layout(0xffff_8001_4000_0000))
        .unwrap();
    let mut second = system
        .prepare_guest::<8>(0, &b, &valid_handoff(), layout(b.image().image_base()))
        .unwrap();

    let mut caps = CapabilitySpace::<8>::new();
    let mut memory = MemoryPoolTable::<1, 1, 2>::new(0xb10).unwrap();
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
    let peer_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
    let client_cap = caps.insert(ObjectId(0xb11), peer_rights).unwrap();
    let provider_cap = caps.insert(ObjectId(0xb12), peer_rights).unwrap();
    let (projection, _) = reserve_microvm_peer_page_projection(
        &mut memory,
        pool,
        quota,
        client_cap,
        provider_cap,
        VIRTUAL / PAGE_SIZE,
        VIRTUAL / PAGE_SIZE,
        &mut caps,
    )
    .unwrap();
    let mut peer = PreparedKvmPeerPage::prepare(
        &mut first,
        &mut second,
        &projection,
        client_cap,
        provider_cap,
        &caps,
        0x70_0000,
        0x80_0000,
    )
    .unwrap_or_else(|failed| panic!("guest result mapping: {:?}", failed.error()));
    let mut observed = [0; PAGE_SIZE as usize];
    let (bridged, exits, kind) = match mode {
        ProbeMode::Synthetic => (false, 1, 0),
        ProbeMode::Bulk(_) => (true, MAX_EXITS, 0x60),
        ProbeMode::Preflight(_) => (true, 72, 0x61),
    };
    observed[0] = kind;
    peer.write_first(&observed).unwrap();
    let mut completed = false;
    for _ in 0..exits {
        let outcome = DeadlineVmBackend::run_with_deadline(peer.first, 0, 1_000_000).unwrap();
        assert_eq!(outcome, VmDeadlineOutcome::Exit(VmExit::Halted));
        peer.read_second(&mut observed).unwrap();

        let opcode = observed[0];
        if matches!(opcode, 0x51 | 0x52) {
            completed = true;
            break;
        }
        assert!(observed[3..8].iter().all(|&byte| byte == 0));
        let address = u64::from_le_bytes(observed[8..PAYLOAD].try_into().unwrap());
        assert!(observed[PAYLOAD + 512..].iter().all(|&byte| byte == 0));
        let size = usize::from(u16::from_le_bytes([observed[1], observed[2]]));
        let mut reply = [0; PAGE_SIZE as usize];
        let result = match (&mut mode, opcode, size) {
            (ProbeMode::Bulk(pipe), 1, 31 | 512) if address == 0 => {
                pipe.bulk_out(&observed[PAYLOAD..PAYLOAD + size])
            }
            (ProbeMode::Bulk(pipe), 2, 8 | 13 | 18 | 512) if address == 0 => {
                pipe.bulk_in(&mut reply[PAYLOAD..PAYLOAD + size])
            }
            (ProbeMode::Preflight(io), 5, 4) => u32::try_from(address)
                .map_err(|_| ())
                .and_then(|offset| io.capability(offset))
                .map(|value| {
                    reply[PAYLOAD..PAYLOAD + 4].copy_from_slice(&value.to_le_bytes());
                    4
                }),
            (ProbeMode::Preflight(io), 6, 4) => io
                .write_marker(address, &observed[PAYLOAD..PAYLOAD + 4])
                .map(|()| 4),
            (ProbeMode::Preflight(io), 7, 4) => io
                .read_marker(address, &mut reply[PAYLOAD..PAYLOAD + 4])
                .map(|()| 4),
            _ => Err(()),
        };
        reply[0] = if result == Ok(size) { 3 } else { 4 };
        peer.write_second(&reply).unwrap();
    }
    peer.retire()
        .unwrap_or_else(|(error, _)| panic!("guest result page retirement: {error:?}"));
    assert!(
        completed,
        "guest exceeded its bounded diagnostic exit budget"
    );
    assert_eq!(
        observed[0], 0x51,
        "0x52 means a verified write failed; zero means no report"
    );
    if !bridged {
        assert!(observed[1..].iter().all(|&byte| byte == 0));
    }
    for guest in [&first, &second] {
        assert_eq!(
            guest.page_walk(VIRTUAL).unwrap().physical_address(VIRTUAL),
            None
        );
    }
    if !bridged {
        mrml_runtime::mrml_println!(
            "usb-write-guest|status=PASS|backend=kvm|driver=guest|bot=synthetic|file=PROBE.TXT"
        );
    }
}
