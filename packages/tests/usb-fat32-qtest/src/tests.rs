use mrml_interface_storage_block_provider_v1::{
    BLOCK_DEVICE_FLAG_READ_ONLY, BlockProviderTransport, BorrowedWriteView, OpaqueHandle,
    ReadError, decode_block_device_catalog_record, decode_enumerate_response,
    encode_enumerate_request, validate_block_device_catalog,
};
use mrml_kernel::{
    CapabilitySpace, MemoryPoolTable, ObjectId, PAGE_SIZE, Rights,
    reserve_microvm_peer_page_projection,
};
use mrml_storage::{MicrovmBlockReadError, bind_microvm_block_read};
use mrml_storage_fat32::{
    Fat32EntryReader, FixedFileWriteError, VerifiedSectorDevice, overwrite_fixed_file,
    parse_fat32_boot_sector, parse_fat32_short_directory, read_fat32_cluster_chain,
};
use mrml_storage_usb::block_provider::UsbReadProvider;
use mrml_storage_usb::xhci::{
    BulkDma, Controller, DeviceDma, DmaLayout, Error, Platform, RevocablePlatform,
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
    let mut controller = Controller::start_pci(qtest, assignment, DMA, 100).unwrap();
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
        let mut disk = mrml_storage_usb::UsbDisk::probe(pipe).unwrap();
        assert_eq!(disk.sectors(), (START + TOTAL) as u64);
        exercise_fat32(&mut disk);
        let session = OpaqueHandle::new(1, 2).unwrap();
        let mut provider = UsbReadProvider::new(disk, session, 3).unwrap();
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

        qmp.remove_stick();
        for error in [ReadError::IoFailure, ReadError::StaleObject] {
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
    controller.stop(100).unwrap().revoke().unwrap();
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
const RESERVED: usize = 32;
const FAT_LEN: usize = 520;
const DATA: usize = RESERVED + 2 * FAT_LEN;
const TOTAL: usize = DATA + 65_525;
const FILE_SECTOR: usize = START + DATA + 1;

fn synthetic_image() -> Vec<u8> {
    // One known partition; exclusive ownership and no aliases follow from
    // constructing the entire disposable image here, not from its name.
    let mut image = vec![0; (START + TOTAL) * SECTOR];
    let mbr = &mut image[..SECTOR];
    mbr[450] = 0x0c;
    mbr[454..458].copy_from_slice(&(START as u32).to_le_bytes());
    mbr[458..462].copy_from_slice(&(TOTAL as u32).to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);

    let boot = sector_mut(&mut image, START);
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MRMLTEST");
    boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    boot[16] = 2;
    boot[21] = 0xf8;
    boot[28..32].copy_from_slice(&(START as u32).to_le_bytes());
    boot[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&(FAT_LEN as u32).to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes());
    boot[64] = 0x80;
    boot[66] = 0x29;
    boot[67..71].copy_from_slice(&42u32.to_le_bytes());
    boot[71..82].copy_from_slice(b"NO NAME    ");
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    for table in [START + RESERVED, START + RESERVED + FAT_LEN] {
        for (index, value) in [0x0fff_fff8u32, 0x0fff_ffff, 0x0fff_ffff, 0x0fff_ffff]
            .into_iter()
            .enumerate()
        {
            sector_mut(&mut image, table)[index * 4..index * 4 + 4]
                .copy_from_slice(&value.to_le_bytes());
        }
    }
    let root = sector_mut(&mut image, START + DATA);
    root[..11].copy_from_slice(b"PROBE   TXT");
    root[11] = 0x20;
    root[26..28].copy_from_slice(&3u16.to_le_bytes());
    root[28..32].copy_from_slice(&3u32.to_le_bytes());
    let data = sector_mut(&mut image, FILE_SECTOR);
    data.fill(0xa5);
    data[..3].copy_from_slice(b"old");
    image
}

fn sector_mut(image: &mut [u8], lba: usize) -> &mut [u8] {
    &mut image[lba * SECTOR..(lba + 1) * SECTOR]
}

struct TestPartition<'a, T: mrml_storage_usb::BulkTransport>(&'a mut mrml_storage_usb::UsbDisk<T>);

impl<T: mrml_storage_usb::BulkTransport> TestPartition<'_, T> {
    fn lba(sector: u32) -> u64 {
        assert!((sector as usize) < TOTAL, "fixture partition out of bounds");
        (START as u64) + u64::from(sector)
    }
}

impl<T: mrml_storage_usb::BulkTransport> VerifiedSectorDevice for TestPartition<'_, T> {
    type Error = mrml_storage_usb::Error<T::Error>;

    fn read_sector(&mut self, sector: u32, output: &mut [u8; SECTOR]) -> Result<(), Self::Error> {
        self.0.read_sector(Self::lba(sector), output)
    }

    fn write_sector_verified(
        &mut self,
        sector: u32,
        input: &[u8; SECTOR],
    ) -> Result<(), Self::Error> {
        self.0.write_sector_verified(Self::lba(sector), input)
    }
}

impl<T: mrml_storage_usb::BulkTransport> Fat32EntryReader for TestPartition<'_, T> {
    fn read_entry(&mut self, fat_index: u8, cluster: u32) -> Result<u32, ()> {
        assert!(fat_index < 2 && matches!(cluster, 2 | 3));
        let table = RESERVED + usize::from(fat_index) * FAT_LEN;
        let mut bytes = [0; SECTOR];
        self.read_sector(table as u32, &mut bytes).map_err(|_| ())?;
        let offset = cluster as usize * 4;
        Ok(u32::from_le_bytes(
            bytes[offset..offset + 4].try_into().unwrap(),
        ))
    }
}

fn exercise_fat32<T>(disk: &mut mrml_storage_usb::UsbDisk<T>)
where
    T: mrml_storage_usb::BulkTransport,
    T::Error: std::fmt::Debug,
{
    let mut mbr = [0; SECTOR];
    disk.read_sector(0, &mut mbr).unwrap();
    assert_eq!(&mbr[510..], &[0x55, 0xaa]);
    assert_eq!(mbr[450], 0x0c);
    assert_eq!(
        u32::from_le_bytes(mbr[454..458].try_into().unwrap()),
        START as u32
    );
    assert_eq!(
        u32::from_le_bytes(mbr[458..462].try_into().unwrap()),
        TOTAL as u32
    );

    let mut partition = TestPartition(disk);
    let mut boot = [0; SECTOR];
    partition.read_sector(0, &mut boot).unwrap();
    let geometry = parse_fat32_boot_sector(&boot).unwrap();
    assert_eq!(geometry.total_sectors, TOTAL as u32);
    assert_eq!(geometry.data_start_sector, DATA as u32);
    assert_eq!(geometry.root_cluster, 2);

    let root =
        read_fat32_cluster_chain::<1, _>(geometry, geometry.root_cluster, &mut partition).unwrap();
    assert_eq!(root.clusters(), &[2]);
    let mut directory = [0; SECTOR];
    partition
        .read_sector(geometry.data_start_sector, &mut directory)
        .unwrap();
    let entries = parse_fat32_short_directory::<2>(geometry, &directory).unwrap();
    let [entry] = entries.entries() else {
        panic!("expected exactly one fixture file");
    };
    assert_eq!(entry.short_name, *b"PROBE   TXT");
    let chain =
        read_fat32_cluster_chain::<1, _>(geometry, entry.first_cluster, &mut partition).unwrap();
    assert_eq!(chain.clusters(), &[3]);
    assert!(matches!(
        overwrite_fixed_file(&mut partition, geometry, *entry, &chain, b"bad", b"new"),
        Err(FixedFileWriteError::StaleContents)
    ));
    let mut contents = [0; SECTOR];
    partition
        .read_sector((DATA + 1) as u32, &mut contents)
        .unwrap();
    assert_eq!(&contents[..3], b"old");
    assert_eq!(&contents[3..], &[0xa5; SECTOR - 3]);
    // Cross multiple bulk and event ring wraps without changing any other byte
    // in the image. Each readback must see the newly written payload.
    let mut previous = *b"old";
    for byte in b'A'..=b'K' {
        let next = [byte; 3];
        overwrite_fixed_file(&mut partition, geometry, *entry, &chain, &previous, &next).unwrap();
        previous = next;
    }
    overwrite_fixed_file(&mut partition, geometry, *entry, &chain, &previous, b"new").unwrap();
}
