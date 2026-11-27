extern crate std;
use self::std::{
    format, fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::String,
    thread,
    time::Duration,
};
use super::*;

const BAR: u32 = 0xfeb0_0000;

struct Qtest {
    socket: BufReader<UnixStream>,
    child: Child,
    directory: std::path::PathBuf,
}

impl Drop for Qtest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(self.directory.join("qtest.sock"));
        let _ = fs::remove_file(self.directory.join("media.img"));
        let _ = fs::remove_dir(&self.directory);
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
    let sock = dir.join("qtest.sock");
    let media = dir.join("media.img");
    fs::File::create_new(&media)
        .unwrap()
        .set_len(2 * 1024 * 1024)
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
            "usb-storage,bus=xhci.0,port=1,drive=media",
            "-qtest",
        ])
        .arg(format!("unix:{},server=on,wait=off", sock.display()))
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
        let _ = fs::remove_file(&sock);
        let _ = fs::remove_file(&media);
        let _ = fs::remove_dir(&dir);
        panic!("QEMU qtest socket not available");
    };
    let mut qtest = Qtest {
        socket: BufReader::new(socket),
        child,
        directory: dir,
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
    // Configure only the explicitly created emulated controller.
    qtest.call("outl 0xcf8 0x80001808").unwrap();
    assert_eq!(qtest.value("inl 0xcfc").unwrap() >> 8, 0x0c0330);
    qtest.config(0x10, BAR).unwrap();
    qtest.config(0x14, 0).unwrap();
    qtest.config(4, 6).unwrap();
    let mut controller = Controller::start(qtest, 0x4000, DMA, 100).unwrap();
    let port = (1..=controller.registers.ports)
        .find(|&port| controller.port_status(port).unwrap().connected)
        .expect("emulated USB disk should be connected");
    assert_eq!(
        controller.port_status(port).unwrap().speed_id,
        if super_speed {
            SUPER_SPEED_ID
        } else {
            HIGH_SPEED_ID
        }
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
    let interface = crate::find_bulk_interface(&configuration[..length]).unwrap();
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
    {
        let pipe = controller
            .configure_bulk(&configuration[..length], bulk_dma, 1000)
            .unwrap();
        let mut disk = crate::UsbDisk::probe(pipe).unwrap();
        assert_eq!(disk.sectors(), 4096);
        let mut contents = [0xff; 512];
        disk.read_sector(3, &mut contents).unwrap();
        assert_eq!(contents, [0; 512]);
        disk.write_sector_verified(3, &[0x5a; 512]).unwrap();
    }
    controller.halt(100).unwrap();
    let bytes = fs::read(&media).unwrap();
    assert_eq!(&bytes[3 * 512..4 * 512], &[0x5a; 512]);
    assert!(
        bytes[..3 * 512]
            .iter()
            .chain(&bytes[4 * 512..])
            .all(|&byte| byte == 0)
    );
}
