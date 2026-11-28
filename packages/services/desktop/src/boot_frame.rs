//! A fixed-geometry, single-mailbox diagnostic frame. Contains pixels, not
//! guest-provided addresses, framebuffer authority, or display-mode requests.
use crate::{Desktop, Event, Key, RouteError, TerminalRoute, raster};
use core::num::NonZeroU64;
pub use mrml_boot_frame::{BootScene, MAX_LIVE_KEYS};

pub use mrml_boot_frame::{
    BOOT_REPLY_BYTES, BOOT_REQUEST, Error, HEADER_BYTES, MAX_BYTES, decode, decode_boot_reply,
    validate_boot_reply,
};
use mrml_boot_frame::{COLORS, TAG};

/// The size becomes valid only after the payload is complete.
pub fn encode(
    desktop: &Desktop,
    echo: &[char],
    packet: &mut [u8; MAX_BYTES],
) -> Result<usize, Error> {
    packet[..HEADER_BYTES].fill(0);
    let mut row = [0; raster::ROW_BYTES];
    let mut end = HEADER_BYTES;
    let mut color = 0u8;
    let mut count = 0u8;
    let mut flush = |count: u8, color: u8| -> Result<(), Error> {
        let slot = packet.get_mut(end..end + 2).ok_or(Error::TooLarge)?;
        slot.copy_from_slice(&[count, color]);
        end += 2;
        Ok(())
    };
    for y in 0..raster::HEIGHT {
        if !raster::row(desktop, echo, y, &mut row) {
            return Err(Error::InvalidDesktop);
        }
        for pixel in row.chunks_exact(4) {
            let next = COLORS
                .iter()
                .position(|value| value == pixel)
                .ok_or(Error::UnknownColor)? as u8;
            if count != 0 && (next != color || count == u8::MAX) {
                flush(count, color)?;
                count = 0;
            }
            color = next;
            count += 1;
        }
    }
    flush(count, color)?;
    packet[..4].copy_from_slice(&TAG);
    packet[4..6].copy_from_slice(&(end as u16).to_le_bytes());
    Ok(end)
}

/// No independent application is started in this fixture. The normal
/// desktop policy is exercised against a guest-private terminal placeholder.
struct BootTerminalFixture(Option<mrml_terminal_probe::Terminal>);

impl TerminalRoute for BootTerminalFixture {
    fn launch_terminal(&mut self) -> Result<NonZeroU64, RouteError> {
        if self.0.is_some() {
            return Err(RouteError::Unavailable);
        }
        self.0 = Some(mrml_terminal_probe::Terminal::new());
        Ok(NonZeroU64::MIN)
    }

    fn send_key(&mut self, incarnation: NonZeroU64, key: Key) -> Result<(), RouteError> {
        if incarnation != NonZeroU64::MIN {
            return Err(RouteError::Retired);
        }
        self.0.as_mut().ok_or(RouteError::Retired)?.key(key);
        Ok(())
    }

    fn retire_terminal(&mut self, _: NonZeroU64) -> Result<(), RouteError> {
        Err(RouteError::Unavailable)
    }
}

/// One-shot Win64 diagnostic entry: fixed request, separate RAM reply.
/// The reply is zero on failure, and padding remains zero on success.
pub fn render_boot_reply(
    request: &[u8; BOOT_REQUEST.len()],
    reply: &mut [u8; BOOT_REPLY_BYTES],
) -> Result<(), Error> {
    reply.fill(0);
    let scene = BootScene::parse(request)?;
    if !matches!(scene, BootScene::Idle | BootScene::Enter) {
        return Err(Error::InvalidRequest);
    }
    BootDesktop::new()?.step(scene, reply)
}

/// State owned by the signed guest, never serialized into the monitor.
pub struct BootDesktop {
    desktop: Desktop,
    terminal: BootTerminalFixture,
}

impl BootDesktop {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            desktop: Desktop::new(480, 280).ok_or(Error::InvalidDesktop)?,
            terminal: BootTerminalFixture(None),
        })
    }

    pub fn step(
        &mut self,
        scene: BootScene,
        reply: &mut [u8; BOOT_REPLY_BYTES],
    ) -> Result<(), Error> {
        reply.fill(0);
        let open = self.desktop.diagnostics().terminal_open;
        let event = match (scene, open) {
            (BootScene::Idle | BootScene::Begin | BootScene::LiveBegin, false) => None,
            (BootScene::End, true) => None,
            (BootScene::Letter(letter), true) => {
                Some(Event::TerminalKey(Key::Text(letter.character())))
            }
            (BootScene::Enter, false) => Some(Event::Enter),
            (BootScene::TextA, true) => Some(Event::TerminalKey(Key::Text('A'))),
            _ => return Err(Error::InvalidRequest),
        };
        if let Some(event) = event {
            self.desktop
                .event(event, &mut self.terminal)
                .map_err(|_| Error::InvalidDesktop)?;
            if !self.desktop.diagnostics().terminal_open {
                return Err(Error::InvalidDesktop);
            }
        }
        let echo = self
            .terminal
            .0
            .as_ref()
            .and_then(|terminal| terminal.rows().last())
            .unwrap_or(&[]);
        let packet = (&mut reply[..MAX_BYTES])
            .try_into()
            .map_err(|_| Error::WrongOutputSize)?;
        match encode(&self.desktop, echo, packet) {
            Ok(_) => Ok(()),
            Err(error) => {
                reply.fill(0);
                Err(error)
            }
        }
    }
}

/// A shell instance stays private to the signed desktop diagnostic. No
/// external program, filesystem or inherited host authority is available.
#[derive(Default)]
struct PanelTerminal(Option<mrml_terminal_probe::CliShell>);

impl TerminalRoute for PanelTerminal {
    fn launch_terminal(&mut self) -> Result<NonZeroU64, RouteError> {
        if self.0.is_some() {
            return Err(RouteError::Unavailable);
        }
        self.0 = Some(mrml_terminal_probe::CliShell::new());
        Ok(NonZeroU64::MIN)
    }

    fn send_key(&mut self, id: NonZeroU64, key: Key) -> Result<(), RouteError> {
        if id != NonZeroU64::MIN {
            return Err(RouteError::Retired);
        }
        self.0.as_mut().ok_or(RouteError::Retired)?.key(key);
        Ok(())
    }

    fn retire_terminal(&mut self, _: NonZeroU64) -> Result<(), RouteError> {
        Err(RouteError::Unavailable)
    }
}

pub struct BootPanelDesktop {
    desktop: Desktop,
    terminal: PanelTerminal,
}

impl BootPanelDesktop {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            desktop: Desktop::new(480, 280).ok_or(Error::InvalidDesktop)?,
            terminal: PanelTerminal::default(),
        })
    }

    pub fn step(
        &mut self,
        scene: BootScene,
        reply: &mut [u8; BOOT_REPLY_BYTES],
    ) -> Result<(), Error> {
        reply.fill(0);
        let open = self.desktop.diagnostics().terminal_open;
        let mut send = |event| {
            self.desktop
                .event(event, &mut self.terminal)
                .map(|_| ())
                .map_err(|_| Error::InvalidDesktop)
        };
        match (scene, open) {
            (BootScene::Idle | BootScene::Begin | BootScene::LiveBegin, false)
            | (BootScene::End, true) => (),
            (BootScene::Enter, false) => send(Event::Enter)?,
            (BootScene::Letter(letter), true) => {
                send(Event::TerminalKey(Key::Text(letter.character())))?
            }
            (BootScene::Space, true) => send(Event::TerminalKey(Key::Text(' ')))?,
            (BootScene::Submit, true) => send(Event::TerminalKey(Key::Enter))?,
            (BootScene::Backspace, true) => send(Event::TerminalKey(Key::Backspace))?,
            (BootScene::TextA, true) => {
                // Device-free display regression; never a physical key claim.
                for ch in "echo ready".chars() {
                    send(Event::TerminalKey(Key::Text(ch)))?;
                }
                send(Event::TerminalKey(Key::Enter))?;
            }
            _ => return Err(Error::InvalidRequest),
        }
        let mut input = [0; 32];
        let mut output = [0; 32];
        let mut n = 0;
        let mut m = 0;
        if let Some(terminal) = self.terminal.0.as_ref() {
            n = copy_ascii(terminal.input(), &mut input)?;
            m = copy_ascii(terminal.output(), &mut output)?;
        }
        let diagnostics = self.desktop.diagnostics();
        mrml_boot_frame::BootPanel {
            open: diagnostics.terminal_open,
            keys: u8::try_from(diagnostics.keys_delivered).map_err(|_| Error::InvalidDesktop)?,
            input: &input[..n],
            output: &output[..m],
        }
        .encode(reply)
    }
}

fn copy_ascii(source: &[char], target: &mut [u8; 32]) -> Result<usize, Error> {
    for (from, to) in source.iter().zip(target.iter_mut()) {
        if !from.is_ascii() {
            return Err(Error::InvalidDesktop);
        }
        *to = *from as u8;
    }
    if source.len() > target.len() {
        return Err(Error::TooLarge);
    }
    Ok(source.len())
}

#[cfg(test)]
#[test]
fn panel_routes_shell_commands_and_preserves_literal_echo() {
    use mrml_boot_frame::{BootLetter, BootPanel};
    let mut app = BootPanelDesktop::new().unwrap();
    let mut page = [0; BOOT_REPLY_BYTES];
    app.step(BootScene::LiveBegin, &mut page).unwrap();
    assert!(!BootPanel::decode(&page).unwrap().open);
    app.step(BootScene::Enter, &mut page).unwrap();
    for &b in b"ECHO HI" {
        let event = BootLetter::new(b).map_or(BootScene::Space, BootScene::Letter);
        app.step(event, &mut page).unwrap();
    }
    assert_eq!(BootPanel::decode(&page).unwrap().input, b"ECHO HI");
    app.step(BootScene::Submit, &mut page).unwrap();
    let panel = BootPanel::decode(&page).unwrap();
    assert_eq!(panel.output, b"HI");
    assert_eq!(panel.input, b"");
    assert_eq!(panel.keys, 8);
}

#[cfg(test)]
#[test]
fn usb_boot_reports_drive_the_focused_clishell_without_repeating_held_keys() {
    use mrml_input_usb_keyboard::{BootKeyStream, BootKeyboard, KeyPress};
    let mut seat = BootKeyStream::new(BootKeyboard::bind(3, 1, 1, true).unwrap());
    let mut app = BootPanelDesktop::new().unwrap();
    let mut deliver = |usage: u8| {
        assert_eq!(seat.ingest(&[0; 8]).unwrap(), None);
        let report = [0, 0, usage, 0, 0, 0, 0, 0];
        let press = seat.ingest(&report).unwrap().unwrap();
        assert_eq!(seat.ingest(&report).unwrap(), None);
        app.desktop
            .event(crate::seat::usb_keyboard(press).unwrap(), &mut app.terminal)
            .unwrap();
    };
    // USB keyboard usages for Enter, E C H O, Space, H I, Enter.
    for usage in [0x28, 0x08, 0x06, 0x0b, 0x12, 0x2c, 0x0b, 0x0c, 0x28] {
        deliver(usage);
    }
    let shell = app.terminal.0.as_ref().unwrap();
    assert_eq!(shell.input(), []);
    assert_eq!(shell.output(), ['h', 'i']);
    assert_eq!(app.desktop.diagnostics().keys_delivered, 8);
    assert_eq!(
        crate::seat::usb_keyboard(KeyPress {
            usage: 0x28,
            modifiers: 1
        }),
        None
    );
    assert_eq!(
        crate::seat::usb_keyboard(KeyPress {
            usage: 0x04,
            modifiers: 2
        }),
        Some(Event::TerminalKey(Key::Text('A')))
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_mailbox_renders_multiple_distinct_keypresses_without_relaunch() {
        use mrml_boot_frame::BootLetter;
        let mut desktop = BootDesktop::new().unwrap();
        let mut reply = [0; BOOT_REPLY_BYTES];
        let letter = |byte| BootScene::Letter(BootLetter::new(byte).unwrap());
        desktop.step(BootScene::LiveBegin, &mut reply).unwrap();
        assert!(desktop.step(letter(b'A'), &mut reply).is_err());
        desktop.step(BootScene::Enter, &mut reply).unwrap();
        for byte in b"ABBA" {
            let before = reply;
            desktop.step(letter(*byte), &mut reply).unwrap();
            assert_ne!(reply, before);
        }
        let present = reply;
        desktop.step(BootScene::End, &mut reply).unwrap();
        assert_eq!(reply, present);
        assert_eq!(desktop.desktop.diagnostics().keys_delivered, 4);
    }

    #[test]
    fn boot_request_seals_frame_and_rejects_nonzero_padding() {
        let mut reply = [0xa7; BOOT_REPLY_BYTES];
        assert_eq!(
            render_boot_reply(b"wrongabi", &mut reply),
            Err(Error::InvalidRequest)
        );
        assert!(reply.iter().all(|&byte| byte == 0));
        render_boot_reply(&BOOT_REQUEST, &mut reply).unwrap();
        validate_boot_reply(&reply).unwrap();
        let mut frame = [0; raster::FRAME_BYTES];
        decode_boot_reply(&reply, &mut frame).unwrap();
        assert_eq!(frame[..4], COLORS[0]);
        reply[BOOT_REPLY_BYTES - 1] = 1;
        assert_eq!(validate_boot_reply(&reply), Err(Error::InvalidPacket));
        frame.fill(0xa7);
        assert_eq!(
            decode_boot_reply(&reply, &mut frame),
            Err(Error::InvalidPacket)
        );
        assert!(frame.iter().all(|&byte| byte == 0xa7));
    }

    #[test]
    fn enter_opens_the_focused_terminal_and_unknown_input_clears_the_reply() {
        let mut reply = [0; BOOT_REPLY_BYTES];
        let mut frame = [0; raster::FRAME_BYTES];
        let tile = (30 * raster::WIDTH + 20) * 4;

        render_boot_reply(&BootScene::Idle.request(), &mut reply).unwrap();
        decode_boot_reply(&reply, &mut frame).unwrap();
        assert_eq!(frame[tile..tile + 4], COLORS[1]);

        render_boot_reply(&BootScene::Enter.request(), &mut reply).unwrap();
        decode_boot_reply(&reply, &mut frame).unwrap();
        assert_eq!(frame[tile..tile + 4], COLORS[3]);

        let mut bad = BootScene::Enter.request();
        bad[7] = 4;
        assert_eq!(
            render_boot_reply(&bad, &mut reply),
            Err(Error::InvalidRequest)
        );
        assert!(reply.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn persistent_reply_rejects_text_before_enter_and_keeps_the_echo() {
        let mut desktop = BootDesktop::new().unwrap();
        let mut reply = [0; BOOT_REPLY_BYTES];
        assert_eq!(
            desktop.step(BootScene::TextA, &mut reply),
            Err(Error::InvalidRequest)
        );
        desktop.step(BootScene::Begin, &mut reply).unwrap();
        desktop.step(BootScene::Enter, &mut reply).unwrap();
        let opened = reply;
        desktop.step(BootScene::TextA, &mut reply).unwrap();
        assert_ne!(reply, opened);
        assert_eq!(
            desktop.terminal.0.as_ref().unwrap().rows().last(),
            Some(&['A'][..])
        );
        validate_boot_reply(&reply).unwrap();
    }

    #[test]
    fn complete_frame_fits_and_invalid_packet_does_not_modify_output() {
        let desktop = Desktop::new(480, 280).unwrap();
        let mut packet = [0; MAX_BYTES];
        let len = encode(&desktop, &[], &mut packet).unwrap();
        let mut output = [0xa7; raster::FRAME_BYTES];
        for cut in [0, 7, len - 1, len - 2] {
            assert_eq!(
                decode(&packet[..cut], &mut output),
                Err(Error::InvalidPacket)
            );
        }
        let first_run = packet[HEADER_BYTES + 1];
        packet[HEADER_BYTES + 1] = u8::MAX;
        assert_eq!(
            decode(&packet[..len], &mut output),
            Err(Error::InvalidPacket)
        );
        assert!(output.iter().all(|&b| b == 0xa7));
        packet[HEADER_BYTES + 1] = first_run;
        decode(&packet[..len], &mut output).unwrap();
        assert_eq!(output[..4], COLORS[0]);
    }
}
