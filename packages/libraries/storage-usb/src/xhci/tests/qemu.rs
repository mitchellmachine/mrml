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
    let dir = std::env::temp_dir().join(format!("mrml-xhci-qtest-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let sock = dir.join("qtest.sock");
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
            "qemu-xhci,id=xhci,addr=03.0",
            "-device",
            "usb-kbd,bus=xhci.0",
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
    let ports = controller.registers.ports;
    assert_eq!(
        (1..=ports)
            .filter(|&port| controller.port_status(port).unwrap().connected)
            .count(),
        1
    );
    controller.no_op(100).unwrap();
    controller.no_op(100).unwrap();
    controller.halt(100).unwrap();
}
