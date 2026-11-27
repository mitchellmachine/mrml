use mrml_interface_storage_block_provider_v1::{
    BLOCK_DEVICE_FLAG_READ_ONLY, BlockProviderTransport, BorrowedReadView, BorrowedWriteView,
    OpaqueHandle, ReadError, WriteError, decode_block_device_catalog_record,
    decode_enumerate_response, decode_write_response, encode_enumerate_request,
    encode_write_request, validate_block_device_catalog,
};
use mrml_kernel::{
    CapabilitySpace, MemoryPoolTable, ObjectId, PAGE_SIZE, Rights,
    reserve_microvm_peer_page_projection,
};
use mrml_storage::{MicrovmBlockReadError, bind_microvm_block_read};
use mrml_storage_fat32::provisioned_probe::{
    PROBE_DATA_SECTOR, PROBE_PARTITION_SECTORS, ProbeError, ProvisionedProbe, probe_metadata_sector,
};
use mrml_storage_fat32::{FixedFileWriteError, VerifiedSectorDevice};
use mrml_storage_usb::block_provider::UsbReadProvider;
use mrml_storage_usb::diagnostic_partition::{
    DiagnosticPartition, DiagnosticPartitionAssignment, DiagnosticPartitionError,
};
use mrml_storage_usb::xhci::{
    BulkDma, Controller, ControllerRetirement, DeviceDma, DmaLayout, Error, Platform,
    ProjectionError, RevocablePlatform, ScopedXhci,
};
use std::{
    format, fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::String,
    thread,
    time::Duration,
};

use mrml_storage_usb::xhci::pci::{PciController, PciError, PciLocation, PciSnapshot};
use mrml_storage_usb::xhci::{DmaAssignment, PciActivation, StartFailure};

const DMA: DmaLayout = DmaLayout {
    device_contexts: 0x10_0000,
    command_ring: 0x10_0100,
    event_segments: 0x10_0200,
    event_ring: 0x10_0300,
};

const BAR: u32 = 0xfeb0_0000;

struct Qtest {
    socket: BufReader<UnixStream>,
    child: Child,
    assigned: Option<DmaAssignment>,
}

impl Drop for Qtest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct FixtureDir(std::path::PathBuf);

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("qtest.sock"));
        let _ = fs::remove_file(self.0.join("qmp.sock"));
        let _ = fs::remove_file(self.0.join("media.img"));
        let _ = fs::remove_dir(&self.0);
    }
}

impl Qtest {
    fn call(&mut self, message: &str) -> io::Result<String> {
        writeln!(self.socket.get_mut(), "{message}")?;
        let mut line = String::new();
        loop {
            line.clear();
            if self.socket.read_line(&mut line)? == 0 {
                return Err(io::Error::other("QEMU qtest disconnected"));
            }
            if line.starts_with("IRQ ") {
                continue;
            }
            if !line.starts_with("OK") {
                return Err(io::Error::other(line));
            }
            return Ok(line);
        }
    }

    fn value(&mut self, message: &str) -> io::Result<u32> {
        let line = self.call(message)?;
        let s = line
            .trim()
            .strip_prefix("OK 0x")
            .ok_or_else(|| io::Error::other(line.clone()))?;
        u32::from_str_radix(s, 16).map_err(io::Error::other)
    }

    fn config_read(&mut self, offset: u32) -> io::Result<u32> {
        self.call(&format!("outl 0xcf8 {:#x}", 0x8000_1800 | offset))?;
        self.value("inl 0xcfc")
    }

    fn pci_snapshot(&mut self, bytes: u64) -> io::Result<PciSnapshot> {
        Ok(PciSnapshot {
            location: PciLocation {
                segment: 0,
                bus: 0,
                device: 3,
                function: 0,
            },
            configuration_generation: 1,
            vendor_device: self.config_read(0)?,
            class_revision: self.config_read(8)?,
            header_type: (self.config_read(12)? >> 16) as u8,
            command: self.config_read(4)? as u16,
            bar0: self.config_read(0x10)?,
            bar1: self.config_read(0x14)?,
            bar0_bytes: bytes,
        })
    }

    fn enumerate_xhci(&mut self) -> PciSnapshot {
        // Probe only this fixture's PCI function, with both decoders off.
        assert_eq!(self.config_read(4).unwrap() & 7, 0);
        let low = self.config_read(0x10).unwrap();
        let high = self.config_read(0x14).unwrap();
        assert_eq!(low & 0xf, 4);
        self.config(0x10, u32::MAX).unwrap();
        self.config(0x14, u32::MAX).unwrap();
        let mask = (u64::from(self.config_read(0x14).unwrap()) << 32)
            | u64::from(self.config_read(0x10).unwrap() & !0xf);
        let bytes = (!mask).checked_add(1).unwrap();
        self.config(0x10, low).unwrap();
        self.config(0x14, high).unwrap();
        assert_eq!(self.config_read(0x10).unwrap(), low);
        assert_eq!(self.config_read(0x14).unwrap(), high);
        self.config(0x10, BAR).unwrap();
        self.config(0x14, 0).unwrap();
        self.pci_snapshot(bytes).unwrap()
    }

    fn config(&mut self, offset: u32, value: u32) -> io::Result<()> {
        self.call(&format!("outl 0xcf8 {:#x}", 0x8000_1800 | offset))?;
        self.call(&format!("outl 0xcfc {value:#x}"))?;
        Ok(())
    }
}

impl Platform for Qtest {
    type Error = io::Error;
    fn read32(&mut self, offset: u32) -> io::Result<u32> {
        self.value(&format!("readl {:#x}", BAR + offset))
    }
    fn write32(&mut self, offset: u32, value: u32) -> io::Result<()> {
        self.call(&format!("writel {:#x} {value:#x}", BAR + offset))
            .map(|_| ())
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> io::Result<()> {
        let mut text = format!("write {address:#x} {} 0x", bytes.len());
        use core::fmt::Write as _;
        for byte in bytes {
            write!(text, "{byte:02x}").unwrap();
        }
        self.call(&text).map(|_| ())
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> io::Result<()> {
        let line = self.call(&format!("read {address:#x} {}", bytes.len()))?;
        let payload = line
            .trim()
            .strip_prefix("OK 0x")
            .ok_or_else(|| io::Error::other(line.clone()))?;
        if payload.len() != 2 * bytes.len() || !payload.is_ascii() {
            return Err(io::Error::other("unexpected qtest DMA length"));
        }
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&payload[i * 2..i * 2 + 2], 16).map_err(io::Error::other)?;
        }
        Ok(())
    }
    fn publish_dma(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn acquire_dma(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn wait_tick(&mut self) -> io::Result<()> {
        thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}

impl PciActivation for Qtest {
    fn activation_state(&mut self) -> io::Result<(PciSnapshot, DmaAssignment)> {
        let mapping = self.assigned.expect("fixture aperture assigned");
        Ok((
            self.pci_snapshot(u64::from(mapping.controller.bar0().1))?,
            mapping,
        ))
    }

    fn enable_bus_master(&mut self, expected: DmaAssignment, before: u16) -> io::Result<()> {
        let (live, mapping) = self.activation_state()?;
        assert_eq!(mapping, expected);
        assert_eq!(live.command, before);
        let op = self.read32(0)? & 0xff;
        assert_eq!(self.read32(op)? & 3, 0, "still stopped and out of reset");
        assert_ne!(self.read32(op + 4)? & 1, 0, "halted before enabling");
        assert_eq!(self.read32(op + 0x30)?, 0, "reset cleared old pointers");
        self.call("outl 0xcf8 0x80001804")?;
        self.call(&format!("outw 0xcfc {:#x}", before | 4))?;
        Ok(())
    }
}

impl RevocablePlatform for Qtest {
    fn revoke_after_halt(&mut self) -> io::Result<()> {
        // Synthetic PCI device only: turn off memory decoding and bus
        // mastering. The fixture's isolated guest RAM is destroyed at drop.
        self.config(4, 0)?;
        if self.value("inl 0xcfc")? & 6 != 0 {
            return Err(io::Error::other("emulated PCI command bits still enabled"));
        }
        Ok(())
    }
}

#[test]
#[ignore = "requires qemu-system-x86_64 and an available Unix socket"]
fn qemu_controller_command_round_trip() {
    exercise_qemu(false);
    exercise_qemu(true);
}

fn exercise_qemu(super_speed: bool) {
    let controller_arg = if super_speed {
        "qemu-xhci,id=xhci,addr=03.0"
    } else {
        "qemu-xhci,id=xhci,addr=03.0,p3=0"
    };
    let dir = std::env::temp_dir().join(format!("mrml-xhci-qtest-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let _fixture = FixtureDir(dir.clone());
    let sock = dir.join("qtest.sock");
    let qmp_sock = dir.join("qmp.sock");
    let media = dir.join("media.img");
    let mut expected = synthetic_image();
    fs::File::create_new(&media)
        .unwrap()
        .write_all(&expected)
        .unwrap();
    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-machine",
            "q35,accel=tcg",
            "-m",
            "64M",
            "-S",
            "-nodefaults",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-device",
            controller_arg,
            "-drive",
        ])
        .arg(format!(
            "if=none,format=raw,id=media,file={}",
            media.display()
        ))
        .args([
            "-device",
            "usb-storage,id=stick,bus=xhci.0,port=1,drive=media",
            "-qtest",
        ])
        .arg(format!("unix:{},server=on,wait=off", sock.display()))
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp_sock.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let socket = (0..100).find_map(|_| {
        if let Ok(stream) = UnixStream::connect(&sock) {
            return Some(stream);
        }
        thread::sleep(Duration::from_millis(10));
        None
    });
    let Some(socket) = socket else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("QEMU qtest socket not available");
    };
    let mut qtest = Qtest {
        socket: BufReader::new(socket),
        child,
        assigned: None,
    };
    qtest
        .socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    qtest
        .socket
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut qmp = Qmp::open(&qmp_sock);
    // Configure only the explicitly created emulated controller.
    let snapshot = qtest.enumerate_xhci();
    let pci = PciController::discover(snapshot).unwrap();
    assert_eq!(pci.bar0(), (u64::from(BAR), 0x4000));
    let observed = qtest.pci_snapshot(snapshot.bar0_bytes).unwrap();
    assert_eq!(
        pci.verify_unarmed(PciSnapshot {
            configuration_generation: 2,
            ..observed
        }),
        Err(PciError::AssignmentChanged)
    );
    assert_eq!(qtest.config_read(4).unwrap() & 4, 0);
    pci.verify_unarmed(observed).unwrap();
    qtest.config(4, 2).unwrap();
    // Synthetic guest RAM only. This is not an IOMMU mapping.
    let assignment = DmaAssignment {
        controller: pci,
        mapping_generation: 1,
        device_base: 0x10_0000,
        bytes: 0x8000,
    };
    qtest.assigned = Some(assignment);
    let wrong = DmaAssignment {
        mapping_generation: 2,
        ..assignment
    };
    let Err(StartFailure::Untouched {
        error: Error::InvalidDma,
        platform: mut qtest,
    }) = Controller::start_pci(qtest, wrong, DMA, 100)
    else {
        panic!("stale mapping generation must be rejected before xHCI startup");
    };
    assert_eq!(qtest.config_read(4).unwrap() & 4, 0);
    let invalid_layout = DmaLayout {
        event_ring: 0x10_8000,
        ..DMA
    };
    let Err(StartFailure::Untouched {
        error: Error::InvalidDma,
        platform: mut qtest,
    }) = Controller::start_pci(qtest, assignment, invalid_layout, 100)
    else {
        panic!("DMA outside the aperture must be rejected before startup");
    };
    assert_eq!(qtest.config_read(4).unwrap() & 4, 0);
    let Err((ProjectionError::Assignment, qtest)) =
        ScopedXhci::new(qtest, assignment, [0, 0x1000, 0x1000])
    else {
        panic!("duplicated BAR page must not open a projection");
    };
    let projection = mrml_kernel::DeviceDmaProjection {
        requester: mrml_kernel::DeviceAddress::new(0, 0, 3, 0).unwrap(),
        device: ObjectId(0x1010),
        dma_memory: ObjectId(0x1011),
        bar_generation: 1,
        dma_generation: assignment.mapping_generation,
        dma_allocation_generation: 1,
        bar_base: u64::from(BAR),
        bar_bytes: 0x4000,
        bar_pages: [0, 0x1000, 0x2000],
        dma_base: assignment.device_base,
        dma_bytes: assignment.bytes,
    };
    let mut qtest = qtest;
    for invalid in [
        mrml_kernel::DeviceDmaProjection {
            requester: mrml_kernel::DeviceAddress::new(0, 0, 4, 0).unwrap(),
            ..projection
        },
        mrml_kernel::DeviceDmaProjection {
            dma_generation: 2,
            ..projection
        },
        mrml_kernel::DeviceDmaProjection {
            dma_bytes: 0x4000,
            ..projection
        },
    ] {
        let Err((ProjectionError::Assignment, returned)) =
            ScopedXhci::for_device_projection(qtest, assignment, invalid)
        else {
            panic!("substituted broker projection was accepted");
        };
        qtest = returned;
    }
    let mut projected = ScopedXhci::for_device_projection(qtest, assignment, projection)
        .unwrap_or_else(|(error, _)| panic!("invalid fixture projection: {error:?}"));
    assert!(matches!(
        projected.read32(0x3000),
        Err(ProjectionError::MmioRange)
    ));
    assert!(matches!(
        projected.write32(0x3000, 0),
        Err(ProjectionError::MmioRange)
    ));
    assert!(matches!(
        projected.read32(2),
        Err(ProjectionError::MmioRange)
    ));
    assert!(matches!(
        projected.dma_write(0x10_7ffe, &[0; 4]),
        Err(ProjectionError::DmaRange)
    ));
    let mut denied = [0x5c; 4];
    assert!(matches!(
        projected.dma_read(0xf_fffc, &mut denied),
        Err(ProjectionError::DmaRange)
    ));
    assert_eq!(denied, [0x5c; 4]);
    assert!(matches!(
        projected.enable_bus_master(wrong, 2),
        Err(ProjectionError::Assignment)
    ));
    let mut controller = Controller::start_pci(projected, assignment, DMA, 100).unwrap();
    let port = (1..=u8::MAX)
        .find(|&port| {
            controller
                .port_status(port)
                .is_ok_and(|status| status.connected)
        })
        .expect("emulated USB disk should be connected");
    assert_eq!(
        controller.port_status(port).unwrap().speed_id,
        if super_speed { 4 } else { 3 }
    );
    controller.no_op(100).unwrap();
    let dma = DeviceDma {
        input_context: 0x10_1000,
        output_context: 0x10_2000,
        control_ring: 0x10_3000,
        control_buffer: 0x10_4000,
    };
    assert!(matches!(
        controller.address_device(
            port,
            DeviceDma {
                input_context: DMA.command_ring,
                ..dma
            },
            100
        ),
        Err(Error::InvalidDma)
    ));
    assert!(matches!(
        controller.address_device(
            port,
            DeviceDma {
                control_buffer: 0x10_8000,
                ..dma
            },
            100
        ),
        Err(Error::InvalidDma)
    ));
    let addressed = controller.address_device(port, dma, 100).unwrap();
    assert_eq!(addressed.port, port);
    assert!((1..=127).contains(&addressed.address));
    assert!(controller.port_status(port).unwrap().enabled);
    let mut descriptor = [0; 18];
    controller
        .read_descriptor(1, 0, &mut descriptor, 100)
        .unwrap();
    assert_eq!(&descriptor[..2], &[18, 1]);
    let mut header = [0; 9];
    controller.read_descriptor(2, 0, &mut header, 100).unwrap();
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let mut configuration = [0; 256];
    controller
        .read_descriptor(2, 0, &mut configuration[..length], 100)
        .unwrap();
    let interface = mrml_storage_usb::find_bulk_interface(&configuration[..length]).unwrap();
    assert_ne!(interface.bulk_in & 0x80, 0);
    assert_eq!(interface.bulk_out & 0x80, 0);
    assert!(matches!(
        controller.address_device(port, dma, 100),
        Err(Error::InvalidPort)
    ));
    let bulk_dma = BulkDma {
        input_ring: 0x10_5000,
        output_ring: 0x10_6000,
        buffer: 0x10_7000,
    };
    assert!(matches!(
        controller.configure_bulk(
            &configuration[..length],
            BulkDma {
                buffer: 0x10_8000,
                ..bulk_dma
            },
            1000
        ),
        Err(Error::InvalidDma)
    ));
    {
        let pipe = controller
            .configure_bulk(&configuration[..length], bulk_dma, 1000)
            .unwrap();
        let disk = mrml_storage_usb::UsbDisk::probe(pipe).unwrap();
        assert_eq!(disk.sectors(), (START + TOTAL) as u64);
        let session = OpaqueHandle::new(1, 2).unwrap();
        let mut provider = UsbReadProvider::new(disk, session, 3).unwrap();
        exercise_fat32(&mut provider, session);
        let catalog_view = BorrowedWriteView::within(7, 48, 64).unwrap();
        let enumerate = encode_enumerate_request(catalog_view).unwrap();
        let mut catalog = [0xa5; 64];
        let response = provider.enumerate(&enumerate, &mut catalog).unwrap();
        assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(48)));
        assert_eq!(validate_block_device_catalog(&catalog[7..55]), Ok(1));
        let device = decode_block_device_catalog_record(&catalog[7..55], 0).unwrap();
        assert_eq!(device.session, session);
        assert_eq!(device.flags, BLOCK_DEVICE_FLAG_READ_ONLY);
        assert_eq!(device.logical_block_count, (START + TOTAL) as u64);
        assert_eq!(device.media_generation, 3);

        // Drive the same capability-checked queue a service uses, with
        // the USB adapter attached to QEMU's live xHCI controller.
        let mut caps = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 2, 4>::new(0x91).unwrap();
        let (pool, quota) = memory
            .create_root(
                2,
                4,
                0,
                Rights::ALLOCATE
                    .union(Rights::CONTROL)
                    .union(Rights::INSPECT),
                &mut caps,
            )
            .unwrap();
        let target = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let client = caps.insert(ObjectId(0x92), target).unwrap();
        let server = caps.insert(ObjectId(0x93), target).unwrap();
        let (projection, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            quota,
            client,
            server,
            0x700,
            0x800,
            &mut caps,
        )
        .unwrap();
        let (_, mut consumer, mut endpoint) =
            bind_microvm_block_read(3, 1, 1, 1, session, &projection, client, server, &caps)
                .unwrap();
        let mut page = [0; PAGE_SIZE as usize];
        consumer.initialize(&mut page, &projection, &caps).unwrap();
        let mut sector = [0x5c; 512];
        let request = consumer
            .submit(FILE_SECTOR as u64, &mut page, &projection, &caps)
            .unwrap();
        let response = endpoint
            .serve(&mut page, &projection, &caps, request, &mut provider)
            .unwrap();
        consumer
            .complete(&mut page, &projection, &caps, response, &mut sector)
            .unwrap();
        assert_eq!(&sector[..3], b"new");
        assert_eq!(&sector[3..], &[0xa5; 509]);

        let expected_errors: &[ReadError] = if super_speed {
            let cap = caps
                .insert(ObjectId(0xa1), Rights::READ.union(Rights::WRITE))
                .unwrap();
            let mut view =
                DiagnosticPartition::open(&mut provider, test_assignment(session), cap, &caps)
                    .unwrap();
            qmp.remove_stick();
            let wire_view = BorrowedReadView::within(0, SECTOR as u64, SECTOR as u64).unwrap();
            let wire =
                encode_write_request(probe_session(), u64::from(PROBE_DATA_SECTOR), 1, wire_view)
                    .unwrap();
            for error in [WriteError::IoFailure, WriteError::StaleObject] {
                let response = view.write(&caps, &wire, &[0x3c; SECTOR]).unwrap();
                assert_eq!(
                    decode_write_response(&response, SECTOR as u64),
                    Ok(Err(error))
                );
            }
            &[ReadError::StaleObject]
        } else {
            qmp.remove_stick();
            &[ReadError::IoFailure, ReadError::StaleObject]
        };
        for &error in expected_errors {
            sector.fill(0xc3);
            let request = consumer
                .submit(FILE_SECTOR as u64, &mut page, &projection, &caps)
                .unwrap();
            let response = endpoint
                .serve(&mut page, &projection, &caps, request, &mut provider)
                .unwrap();
            assert_eq!(
                consumer.complete(&mut page, &projection, &caps, response, &mut sector),
                Err(MicrovmBlockReadError::Provider(error))
            );
            assert_eq!(sector, [0xc3; 512]);
        }
        let response = provider.enumerate(&enumerate, &mut catalog).unwrap();
        assert_eq!(decode_enumerate_response(&response, 48), Ok(Ok(16)));
        assert_eq!(validate_block_device_catalog(&catalog[7..23]), Ok(0));
        let mut disk = provider.into_disk();
        assert!(matches!(
            disk.write_sector_verified(4, &[0x3c; 512]),
            Err(mrml_storage_usb::Error::Faulted)
        ));
    }
    let mut retirement = ControllerRetirement::new(controller);
    retirement.withdraw(100).unwrap();
    retirement.withdraw(100).unwrap();
    sector_mut(&mut expected, FILE_SECTOR)[..3].copy_from_slice(b"new");
    let bytes = fs::read(&media).unwrap();
    assert_eq!(bytes.len(), expected.len());
    assert_eq!(
        bytes
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected),
        None,
        "unexpected byte offset in persisted image"
    );
}

/// QEMU's line-based monitor is used only to remove the synthetic USB disk.
/// No monitor command is constructed from a device path or external input.
struct Qmp(BufReader<UnixStream>);

impl Qmp {
    fn open(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut qmp = Self(BufReader::new(stream));
        assert!(qmp.line().starts_with(r#"{"QMP":"#));
        writeln!(qmp.0.get_mut(), r#"{{"execute":"qmp_capabilities"}}"#).unwrap();
        assert!(qmp.line().starts_with(r#"{"return":"#));
        qmp
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        assert_ne!(self.0.read_line(&mut line).unwrap(), 0);
        line
    }

    fn remove_stick(&mut self) {
        writeln!(
            self.0.get_mut(),
            r#"{{"execute":"device_del","arguments":{{"id":"stick"}}}}"#
        )
        .unwrap();
        // Unplug notification may arrive before the command reply.
        let mut removed = false;
        let mut acknowledged = false;
        for _ in 0..8 {
            let line = self.line();
            assert!(!line.starts_with(r#"{"error":"#), "{line}");
            removed |= line.contains(r#""event": "DEVICE_DELETED""#)
                && line.contains(r#""device": "stick""#);
            acknowledged |= line.starts_with(r#"{"return":"#);
            if removed && acknowledged {
                return;
            }
        }
        panic!("QEMU did not confirm deletion of the emulated USB disk");
    }
}

const SECTOR: usize = 512;
const START: usize = 32;
const TOTAL: usize = PROBE_PARTITION_SECTORS as usize;
const FILE_SECTOR: usize = START + PROBE_DATA_SECTOR as usize;
const SERIAL: u32 = 42;

fn synthetic_image() -> Vec<u8> {
    // One known partition; exclusive ownership and no aliases follow from
    // constructing the entire disposable image here, not from its name.
    let mut image = vec![0; (START + TOTAL) * SECTOR];
    let mbr = &mut image[..SECTOR];
    mbr[450] = 0x0c;
    mbr[454..458].copy_from_slice(&(START as u32).to_le_bytes());
    mbr[458..462].copy_from_slice(&(TOTAL as u32).to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);

    for sector in 0..PROBE_DATA_SECTOR {
        let metadata = probe_metadata_sector(START as u32, SERIAL, sector).unwrap();
        sector_mut(&mut image, START + sector as usize).copy_from_slice(&metadata);
    }
    let data = sector_mut(&mut image, FILE_SECTOR);
    data.fill(0xa5);
    data[..3].copy_from_slice(b"old");
    image
}

fn sector_mut(image: &mut [u8], lba: usize) -> &mut [u8] {
    &mut image[lba * SECTOR..(lba + 1) * SECTOR]
}

struct TestPartition<'a, 'b, T: mrml_storage_usb::BulkTransport> {
    view: DiagnosticPartition<'a, T>,
    session: OpaqueHandle,
    caps: &'b CapabilitySpace<4>,
}

impl<T: mrml_storage_usb::BulkTransport> VerifiedSectorDevice for TestPartition<'_, '_, T> {
    type Error = DiagnosticPartitionError;

    fn read_sector(&mut self, sector: u32, output: &mut [u8; SECTOR]) -> Result<(), Self::Error> {
        self.view.read(self.caps, sector, output)
    }

    fn write_sector_verified(
        &mut self,
        sector: u32,
        input: &[u8; SECTOR],
    ) -> Result<(), Self::Error> {
        let view = BorrowedReadView::within(0, SECTOR as u64, SECTOR as u64).unwrap();
        let request = encode_write_request(self.session, u64::from(sector), 1, view).unwrap();
        let response = self.view.write(self.caps, &request, input).unwrap();
        match decode_write_response(&response, SECTOR as u64).unwrap() {
            Ok(bytes) if bytes == SECTOR as u64 => Ok(()),
            Err(WriteError::PermissionDenied) => Err(DiagnosticPartitionError::Denied),
            Err(WriteError::StaleObject) => Err(DiagnosticPartitionError::StaleSession),
            _ => Err(DiagnosticPartitionError::IoFailure),
        }
    }
}

fn probe_session() -> OpaqueHandle {
    OpaqueHandle::new(2, 1).unwrap()
}

fn test_assignment(session: OpaqueHandle) -> DiagnosticPartitionAssignment {
    DiagnosticPartitionAssignment {
        disk_session: session,
        partition_session: probe_session(),
        media_generation: 3,
        partition: ObjectId(0xa1),
        first_lba: START as u32,
        sectors: PROBE_PARTITION_SECTORS,
        file_sector: PROBE_DATA_SECTOR,
    }
}

fn exercise_fat32<T>(provider: &mut UsbReadProvider<T>, session: OpaqueHandle)
where
    T: mrml_storage_usb::BulkTransport,
    T::Error: std::fmt::Debug,
{
    let mut caps = CapabilitySpace::<4>::new();
    let partition_object = ObjectId(0xa1);
    let read_only = caps.insert(partition_object, Rights::READ).unwrap();
    let write_rights = Rights::READ.union(Rights::WRITE);
    let foreign = caps.insert(ObjectId(0xa2), write_rights).unwrap();
    let granted = caps.insert(partition_object, write_rights).unwrap();
    let assignment = test_assignment(session);
    for (changed, cap, expected) in [
        (assignment, read_only, DiagnosticPartitionError::Denied),
        (assignment, foreign, DiagnosticPartitionError::Denied),
        (
            DiagnosticPartitionAssignment {
                partition_session: session,
                ..assignment
            },
            granted,
            DiagnosticPartitionError::InvalidExtent,
        ),
        (
            DiagnosticPartitionAssignment {
                media_generation: 2,
                ..assignment
            },
            granted,
            DiagnosticPartitionError::StaleSession,
        ),
        (
            DiagnosticPartitionAssignment {
                first_lba: (START - 1) as u32,
                ..assignment
            },
            granted,
            DiagnosticPartitionError::InvalidPartitionTable,
        ),
        (
            DiagnosticPartitionAssignment {
                sectors: PROBE_PARTITION_SECTORS + 1,
                ..assignment
            },
            granted,
            DiagnosticPartitionError::InvalidExtent,
        ),
    ] {
        assert!(matches!(
            DiagnosticPartition::open(provider, changed, cap, &caps),
            Err(error) if error == expected
        ));
    }

    let mut view = DiagnosticPartition::open(provider, assignment, granted, &caps).unwrap();
    let input = [0x3c; SECTOR];
    let wire_view = BorrowedReadView::within(0, SECTOR as u64, SECTOR as u64).unwrap();
    let write = |handle, sector| encode_write_request(handle, sector, 1, wire_view).unwrap();
    for (wire, expected) in [
        (write(probe_session(), 0), WriteError::InvalidRequest),
        (
            write(session, u64::from(PROBE_DATA_SECTOR)),
            WriteError::StaleObject,
        ),
    ] {
        let response = view.write(&caps, &wire, &input).unwrap();
        assert_eq!(
            decode_write_response(&response, SECTOR as u64),
            Ok(Err(expected))
        );
    }

    {
        let mut partition = TestPartition {
            view,
            session: probe_session(),
            caps: &caps,
        };
        let mut probe = ProvisionedProbe::verify(
            &mut partition,
            START as u32,
            PROBE_PARTITION_SECTORS,
            SERIAL,
        )
        .unwrap();
        assert!(matches!(
            probe.update(b"bad", b"new"),
            Err(ProbeError::Update(FixedFileWriteError::StaleContents))
        ));
        // Cross multiple bulk and event ring wraps. The host compares the
        // whole persisted image, not just the driver's readback.
        let mut previous = *b"old";
        for byte in b'A'..=b'K' {
            let next = [byte; 3];
            probe.update(&previous, &next).unwrap();
            previous = next;
        }
        probe.update(&previous, b"new").unwrap();
    }

    let mut view = DiagnosticPartition::open(provider, assignment, granted, &caps).unwrap();
    caps.revoke(granted).unwrap();
    let replacement = caps.insert(partition_object, write_rights).unwrap();
    assert_ne!(granted, replacement);
    let response = view
        .write(
            &caps,
            &write(probe_session(), u64::from(PROBE_DATA_SECTOR)),
            &input,
        )
        .unwrap();
    assert_eq!(
        decode_write_response(&response, SECTOR as u64),
        Ok(Err(WriteError::PermissionDenied))
    );
    let mut output = [0x5c; SECTOR];
    assert_eq!(
        view.read(&caps, PROBE_DATA_SECTOR, &mut output),
        Err(DiagnosticPartitionError::Denied)
    );
    assert_eq!(output, [0x5c; SECTOR]);
}
