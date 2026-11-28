//! Opt-in test of the emulated controller, never the host's physical ports.
use super::*;
use mrml_input_ps2_keyboard::{KeyboardEvent, Ps2Keyboard};
use mrml_input_ps2_mouse::Ps2Mouse;
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    string::String,
    thread,
    time::{Duration, Instant},
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
fn emulated_i8042_routes_keyboard_and_mouse_to_distinct_decoders() {
    let dir = std::env::temp_dir().join(std::format!("mrml-ps2-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let result = run(&dir);
    for file in ["qmp", "qtest", "halt.rom"] {
        let _ = fs::remove_file(dir.join(file));
    }
    fs::remove_dir(&dir).unwrap();
    result.unwrap();
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
    Ok(())
}
