//! Opt-in test of the emulated controller, never the host's physical ports.
use super::*;
use mrml_hardware_supervisor::{
    DriverMicrovmManager, HardwareSupervisor, PciInventoryProvider, PciObservation, PciSnapshot,
    XhciLaunch, XhciRouteBinding, XhciRouteCatalog,
};
use mrml_input_ps2_keyboard::{KeyboardEvent, Ps2Keyboard};
use mrml_input_ps2_mouse::Ps2Mouse;
use mrml_kernel::{
    CapabilitySpace, DeviceAddress, IsolationAdmissionTable, IsolationMode, IsolationPlacement,
    IsolationServiceSpec, ObjectId, Rights, TotalMicrovmClass,
};
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    string::String,
    thread,
    time::{Duration, Instant},
    vec::Vec,
};

struct Guest(Child);

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Channel(BufReader<UnixStream>);

impl Channel {
    fn connect(path: &Path, guest: &mut Guest) -> io::Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(socket) = UnixStream::connect(path) {
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                return Ok(Self(BufReader::new(socket)));
            }
            if Instant::now() >= deadline || guest.0.try_wait()?.is_some() {
                return Err(io::Error::other("QEMU socket did not become available"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn line(&mut self) -> io::Result<String> {
        use std::io::Read as _;
        let mut line = String::new();
        if self.0.by_ref().take(8192).read_line(&mut line)? == 0 || !line.ends_with('\n') {
            return Err(io::Error::other("missing or oversized QEMU reply"));
        }
        Ok(line)
    }

    fn send(&mut self, command: &str) -> io::Result<()> {
        writeln!(self.0.get_mut(), "{command}")
    }

    fn qmp(&mut self, json: &str) -> io::Result<()> {
        self.send(json)?;
        for _ in 0..8 {
            let line = self.line()?;
            if line.contains("\"return\"") {
                return Ok(());
            }
            if line.contains("\"error\"") {
                return Err(io::Error::other(line));
            }
        }
        Err(io::Error::other("no QMP command result"))
    }

    fn qtest(&mut self, command: &str) -> io::Result<String> {
        self.send(command)?;
        let reply = self.line()?;
        if reply == "OK\n" || reply.starts_with("OK ") {
            return Ok(reply);
        }
        Err(io::Error::other(reply))
    }

    fn read_port(&mut self, port: u16) -> io::Result<u8> {
        let result = self.qtest(&std::format!("inb {port:#x}"))?;
        let value = result
            .trim()
            .strip_prefix("OK 0x")
            .ok_or_else(|| io::Error::other("invalid port response"))?;
        u8::from_str_radix(value, 16).map_err(io::Error::other)
    }
}

impl ControllerSource for Channel {
    type Error = io::Error;

    fn next(&mut self) -> io::Result<Option<Sample>> {
        let status = self.read_port(0x64)?;
        if status & OBF == 0 {
            return Ok(None);
        }
        let data = self.read_port(0x60)?;
        Ok(Some(Sample::Stream { status, data }))
    }
}

#[test]
#[ignore = "requires the local QEMU emulator"]
fn emulated_i8042_and_pci_inventory_reach_separate_services() {
    let dir = std::env::temp_dir().join(std::format!("mrml-ps2-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let result = run(&dir);
    for file in ["qmp", "qtest", "halt.rom"] {
        let _ = fs::remove_file(dir.join(file));
    }
    fs::remove_dir(&dir).unwrap();
    result.unwrap();
}

fn emulated_pci_read(
    qtest: &mut Channel,
    device: u8,
    function: u8,
    register: u8,
) -> io::Result<u32> {
    let selector =
        0x8000_0000 | (u32::from(device) << 11) | (u32::from(function) << 8) | u32::from(register);
    qtest.qtest(&std::format!("outl 0xcf8 {selector:#x}"))?;
    let reply = qtest.qtest("inl 0xcfc")?;
    let value = reply
        .trim()
        .strip_prefix("OK 0x")
        .ok_or_else(|| io::Error::other("invalid emulated PCI response"))?;
    u32::from_str_radix(value, 16).map_err(io::Error::other)
}

struct EmulatedInventory<'a> {
    qtest: &'a mut Channel,
    sequence: u64,
    saved: Vec<PciObservation>,
}

impl PciInventoryProvider for EmulatedInventory<'_> {
    type Error = io::Error;

    fn snapshot(&mut self) -> io::Result<PciSnapshot<'_>> {
        let mut observed = Vec::new();
        // This fixture fixes all devices on root bus zero. Refuse rather
        // than certify a partial inventory if a PCI bridge appears.
        for device in 0..32 {
            let id = emulated_pci_read(self.qtest, device, 0, 0)?;
            if id as u16 == u16::MAX {
                continue;
            }
            let header = emulated_pci_read(self.qtest, device, 0, 0x0c)?;
            let functions = if header & (1 << 23) != 0 { 8 } else { 1 };
            for function in 0..functions {
                let id = if function == 0 {
                    id
                } else {
                    emulated_pci_read(self.qtest, device, function, 0)?
                };
                if id as u16 == u16::MAX {
                    continue;
                }
                let class_revision = emulated_pci_read(self.qtest, device, function, 8)?;
                if class_revision >> 16 == 0x0604 {
                    return Err(io::Error::other("non-flat emulation fixture"));
                }
                observed.push(PciObservation {
                    address: DeviceAddress::new(0, 0, device, function)
                        .map_err(|_| io::Error::other("invalid emulated PCI address"))?,
                    vendor: id as u16,
                    device: (id >> 16) as u16,
                    class_revision,
                    // No hotplug in this private emulator lifetime.
                    incarnation: 1,
                });
            }
        }
        self.qtest.qtest("outl 0xcf8 0")?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("snapshot counter exhausted"))?;
        self.saved = observed;
        Ok(PciSnapshot {
            sequence: self.sequence,
            devices: &self.saved,
        })
    }
}

/// Records requested launches only. This fixture never starts driver
/// guests or grants a register/interrupt/DMA capability.
#[derive(Default)]
struct LaunchRecorder(Vec<XhciLaunch>);

impl DriverMicrovmManager for LaunchRecorder {
    type Instance = usize;
    type Error = ();

    fn launch_xhci(&mut self, request: XhciLaunch) -> Result<usize, ()> {
        self.0.push(request);
        Ok(self.0.len())
    }

    fn retire_xhci(&mut self, _: &mut usize) -> Result<(), ()> {
        panic!("fixed QEMU fixture must retain both controllers")
    }
}

fn verify_pci_supervisor(qtest: &mut Channel) -> io::Result<()> {
    let mut inventory = EmulatedInventory {
        qtest,
        sequence: 0,
        saved: Vec::new(),
    };
    let mut manager = LaunchRecorder::default();
    let mut supervisor = HardwareSupervisor::<usize, 2>::default();
    let first = supervisor
        .refresh(&mut inventory, &mut manager)
        .ok()
        .ok_or_else(|| io::Error::other("initial emulated inventory refused"))?;
    assert_eq!(first.started, 2);
    for (request, expected_slot) in manager.0.iter().zip([5, 6]) {
        let controller = request.controller();
        assert_eq!(
            controller.address,
            DeviceAddress::new(0, 0, expected_slot, 0).unwrap()
        );
        assert_eq!(
            (
                controller.vendor,
                controller.device,
                controller.class_revision >> 8
            ),
            (0x1b36, 0x000d, 0x0c0330)
        );
    }
    let second = supervisor
        .refresh(&mut inventory, &mut manager)
        .ok()
        .ok_or_else(|| io::Error::other("second emulated inventory refused"))?;
    assert_eq!(
        (second.retained, second.started, manager.0.len()),
        (2, 0, 2)
    );
    verify_prepared_routes(&manager.0)
}

fn verify_prepared_routes(requests: &[XhciLaunch]) -> io::Result<()> {
    let mut caps = CapabilitySpace::<2>::new();
    // Expected identities and domains come from the fixture, not discovery.
    let entries = [5u8, 6].map(|device| {
        let object = ObjectId(u64::from(device));
        XhciRouteBinding {
            controller: PciObservation {
                address: DeviceAddress::new(0, 0, device, 0).unwrap(),
                vendor: 0x1b36,
                device: 0x000d,
                class_revision: 0x0c03_3001,
                incarnation: 1,
            },
            device_object: object,
            device_control: caps.insert(object, Rights::CONTROL).unwrap(),
            spec: IsolationServiceSpec::new(
                ObjectId(100 + u64::from(device)),
                ObjectId(42),
                1,
                1,
                1,
                1,
                TotalMicrovmClass::MicrovmEligible,
                IsolationPlacement::Microvm,
            )
            .unwrap(),
        }
    });
    let catalog = XhciRouteCatalog::new(&entries).unwrap();
    let mut admission =
        IsolationAdmissionTable::<2>::new(IsolationMode::TotalMicrovm, 1, 1).unwrap();
    let [a, b] = requests else {
        return Err(io::Error::other("expected two xHCI requests"));
    };
    let (_, a) = catalog
        .prepare(*a, &mut admission, &caps)
        .unwrap()
        .into_parts();
    let (_, b) = catalog
        .prepare(*b, &mut admission, &caps)
        .unwrap()
        .into_parts();
    assert_eq!(
        (a.spec().domain(), b.spec().domain()),
        (ObjectId(105), ObjectId(106))
    );
    a.cancel(&mut admission).unwrap();
    b.cancel(&mut admission).unwrap();
    Ok(())
}

fn run(dir: &Path) -> io::Result<()> {
    // The guest CPU executes HLT at its reset vector; no OS or firmware can
    // race the test for the emulated controller. No physical device is
    // attached. QMP emits test events into the private emulator only.
    fs::write(dir.join("halt.rom"), [0xf4; 65536])?;
    let mut guest = Guest(
        Command::new("qemu-system-x86_64")
            .args([
                "-machine",
                "q35,accel=tcg",
                "-m",
                "64M",
                "-nodefaults",
                "-display",
                "none",
                "-no-reboot",
                "-bios",
                "halt.rom",
                "-qmp",
                "unix:qmp,server=on,wait=off",
                "-qtest",
                "unix:qtest,server=on,wait=off",
            ])
            .args([
                "-device",
                "qemu-xhci,addr=05.0",
                "-device",
                "qemu-xhci,addr=06.0",
            ])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut qtest = Channel::connect(&dir.join("qtest"), &mut guest)?;
    let mut qmp = Channel::connect(&dir.join("qmp"), &mut guest)?;
    assert!(qmp.line()?.contains("\"QMP\""));
    qmp.qmp(r#"{"execute":"qmp_capabilities"}"#)?;
    qtest.qtest("outb 0x64 0x60")?;
    qtest.qtest("outb 0x60 0x00")?; // both channels enabled, no scan translation
    qtest.qtest("outb 0x64 0xd4")?;
    qtest.qtest("outb 0x60 0xf4")?; // enable auxiliary streaming
    assert_eq!(qtest.read_port(0x64)? & (OBF | AUX_DATA), OBF | AUX_DATA);
    assert_eq!(qtest.read_port(0x60)?, 0xfa); // control reply stays private

    qmp.qmp(
        r#"{"execute":"input-send-event","arguments":{"events":[
        {"type":"key","data":{"down":true,"key":{"type":"qcode","data":"a"}}},
        {"type":"rel","data":{"axis":"x","value":2}},
        {"type":"rel","data":{"axis":"y","value":1}}
    ]}}"#
            .split_whitespace()
            .collect::<String>()
            .as_str(),
    )?;

    let mut broker = Ps2Broker::<16>::default();
    assert_eq!(broker.poll(&mut qtest)?, 4);
    assert_eq!(broker.next_keyboard(), Some(InputByte::Data(0x1c)));
    let mut keyboard = Ps2Keyboard::default();
    assert_eq!(
        keyboard.push(0x1c),
        Some(KeyboardEvent::Key {
            scan: 0x1c,
            extended: false,
            pressed: true,
        })
    );
    assert_eq!(broker.next_keyboard(), None);
    let mut mouse = Ps2Mouse::default();
    let mut decoded = None;
    for _ in 0..3 {
        let Some(InputByte::Data(byte)) = broker.next_mouse() else {
            return Err(io::Error::other(
                "emulator did not produce three mouse bytes",
            ));
        };
        decoded = mouse.push(byte);
    }
    let mouse = decoded.ok_or_else(|| io::Error::other("invalid emulated mouse packet"))?;
    assert_eq!((mouse.dx, mouse.dy), (2, 1));
    assert_eq!(broker.next_mouse(), None);
    qmp.qmp(r#"{"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":false,"key":{"type":"qcode","data":"a"}}}]}}"#)?;
    assert_eq!(broker.poll(&mut qtest)?, 2);
    for byte in [0xf0, 0x1c] {
        assert_eq!(broker.next_keyboard(), Some(InputByte::Data(byte)));
        assert_eq!(
            keyboard.push(byte),
            (byte == 0x1c).then_some(KeyboardEvent::Key {
                scan: 0x1c,
                extended: false,
                pressed: false,
            })
        );
    }
    assert_eq!(broker.next_keyboard(), None);
    assert_eq!(broker.next_mouse(), None);
    verify_pci_supervisor(&mut qtest)
}
