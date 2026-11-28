#![no_std]
#![no_main]

//! Opt-in diagnostic VM image, not a firmware entry in a deployed system.
use core::arch::asm;
use core::num::NonZeroU64;
use mrml_desktop::{Control, Desktop, Event, Key, Point, RouteError, TerminalRoute};
use mrml_desktop::{boot_frame, raster};
use mrml_terminal_probe::Terminal;

const PAGE: *mut u8 = 0xffff_8001_400f_0000 as *mut u8;
const RECORD: usize = 32;

struct Echo(Option<Terminal>);

impl TerminalRoute for Echo {
    fn launch_terminal(&mut self) -> Result<NonZeroU64, RouteError> {
        self.0 = Some(Terminal::new());
        Ok(NonZeroU64::MIN)
    }

    fn send_key(&mut self, _: NonZeroU64, key: Key) -> Result<(), RouteError> {
        self.0.as_mut().ok_or(RouteError::Retired)?.key(key);
        Ok(())
    }

    fn retire_terminal(&mut self, _: NonZeroU64) -> Result<(), RouteError> {
        self.0 = None;
        Ok(())
    }
}

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main() -> ! {
    let mut desktop = Desktop::new(480, 280).unwrap();
    let mut echo = Echo(None);
    loop {
        let request: [u8; RECORD] = core::array::from_fn(|offset| {
            // SAFETY: in this signed diagnostic the harness maps the dedicated
            // writable, non-executable page before starting the only vCPU.
            unsafe { PAGE.add(offset).read_volatile() }
        });
        let x = u16::from_le_bytes([request[2], request[3]]);
        let y = u16::from_le_bytes([request[4], request[5]]);
        let event = match request[0] {
            1 => Some(Event::Enter),
            2 => Some(Event::AttachMouse),
            3 => Some(Event::MouseMotion(i32::from(x as i16), i32::from(y as i16))),
            4 => Some(Event::DetachMouse),
            5 => Some(Event::TouchDown(1, Point(x, y))),
            6 => Some(Event::TouchUp(1, Point(x, y))),
            7 => char::from_u32(u32::from_le_bytes(request[2..6].try_into().unwrap()))
                .map(|ch| Event::TerminalKey(Key::Text(ch))),
            _ => None,
        };
        let wants_row = request[0] == 8 && y == 0;
        let wants_frame = request[0] == 9 && x == 0 && y == 0;
        let mut pixels = [0; boot_frame::MAX_BYTES];
        let mut payload_bytes = 0;
        let canonical = request[1] == 0 && request[6..].iter().all(|&byte| byte == 0);
        let accepted = canonical
            && if wants_row || wants_frame {
                let echo_line = echo
                    .0
                    .as_ref()
                    .and_then(|app| app.rows().last())
                    .unwrap_or(&[]);
                if wants_frame {
                    payload_bytes =
                        boot_frame::encode(&desktop, echo_line, &mut pixels).unwrap_or(0);
                    payload_bytes != 0
                } else {
                    let row = (&mut pixels[..raster::ROW_BYTES]).try_into().unwrap();
                    let painted = raster::row(&desktop, echo_line, usize::from(x), row);
                    if painted {
                        payload_bytes = raster::ROW_BYTES;
                    }
                    painted
                }
            } else {
                event.is_some_and(|event| desktop.event(event, &mut echo).is_ok())
            };
        if accepted {
            for (offset, &byte) in pixels[..payload_bytes].iter().enumerate() {
                // SAFETY: raster replies fit wholly within the one fixture page,
                // start after the command record and cannot overlap it.
                unsafe { PAGE.add(RECORD + offset).write_volatile(byte) };
            }
        }
        let mut reply = [0u8; RECORD];
        reply[0] = if accepted { 0x51 } else { 0x52 };
        let d = desktop.diagnostics();
        reply[1] = u8::from(d.terminal_open)
            | (u8::from(desktop.cursor().is_some()) << 1)
            | (u8::from(
                desktop
                    .nodes()
                    .any(|node| node.control == Control::Diagnostics),
            ) << 2);
        if let Some(Point(x, y)) = desktop.cursor() {
            reply[2..4].copy_from_slice(&x.to_le_bytes());
            reply[4..6].copy_from_slice(&y.to_le_bytes());
        }
        let last = echo
            .0
            .as_ref()
            .and_then(|app| app.rows().last())
            .and_then(|row| row.last())
            .copied()
            .unwrap_or('\0');
        reply[8..12].copy_from_slice(&(last as u32).to_le_bytes());
        reply[12..16].copy_from_slice(&d.keys_delivered.to_le_bytes());
        reply[16..20].copy_from_slice(&d.touch_reports.to_le_bytes());
        reply[20..24].copy_from_slice(&d.pointer_reports.to_le_bytes());
        reply[24..26].copy_from_slice(&(payload_bytes as u16).to_le_bytes());
        for (offset, byte) in reply.into_iter().enumerate() {
            // SAFETY: bounded to the first RECORD bytes of the fixture page.
            unsafe { PAGE.add(offset).write_volatile(byte) };
        }
        pause();
    }
}

fn pause() {
    // SAFETY: the hosted diagnostic monitor pauses this VM at HLT, updates
    // the mailbox, and resumes at the following instruction.
    unsafe { asm!("hlt", options(nostack)) };
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        pause();
    }
}
