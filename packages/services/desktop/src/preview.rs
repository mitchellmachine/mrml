//! Hosted visual fixture. This is not an MRML session or a device backend.
use core::num::NonZeroU64;
use mrml_desktop::{Control, Desktop, Event, Key, Rect, RouteError, TerminalRoute};
use mrml_terminal_probe::Terminal;
use std::fmt::Write;

#[derive(Default)]
struct Fixture(Option<Terminal>);

impl TerminalRoute for Fixture {
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

fn text(svg: &mut String, x: u16, y: u16, size: u16, color: &str, value: &str) {
    write!(
        svg,
        r#"<text x="{x}" y="{y}" font-size="{size}" fill="{color}">"#
    )
    .unwrap();
    for char in value.chars() {
        match char {
            '<' => svg.push_str("&lt;"),
            '>' => svg.push_str("&gt;"),
            '&' => svg.push_str("&amp;"),
            char => svg.push(char),
        }
    }
    svg.push_str("</text>\n");
}

fn rect(svg: &mut String, Rect(x, y, w, h): Rect, color: &str, border: &str) {
    writeln!(
        svg,
        r#"<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{color}" stroke="{border}"/>"#
    )
    .unwrap();
}

fn main() {
    let mut desktop = Desktop::new(960, 520).unwrap();
    let mut app = Fixture::default();
    desktop.event(Event::SuperEnter, &mut app).unwrap();
    for ch in "hello from MRML".chars() {
        desktop
            .event(Event::TerminalKey(Key::Text(ch)), &mut app)
            .unwrap();
    }
    desktop
        .event(Event::TerminalKey(Key::Enter), &mut app)
        .unwrap();
    desktop.event(Event::AttachMouse, &mut app).unwrap();
    desktop
        .event(Event::MouseMotion(96, -94), &mut app)
        .unwrap();

    let (w, h) = desktop.size();
    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" font-family="monospace" role="img" aria-labelledby="title desc">
<title id="title">MRML desktop preview</title><desc id="desc">A dark tiling desktop with numbered workspaces, a focused dummy terminal showing keyboard echo, a diagnostics tile and a mouse cursor.</desc>"#
    );
    rect(&mut svg, Rect(0, 0, w, h), "#0e151f", "none");
    rect(&mut svg, Rect(0, 0, w, 44), "#171f2c", "none");
    text(&mut svg, w - 142, 27, 14, "#9db4c8", "MRML  /  DEMO");
    for node in desktop.nodes() {
        let Rect(x, y, width, height) = node.bounds;
        let accent = if node.focused || node.selected {
            "#85cfff"
        } else {
            "#394b62"
        };
        match node.control {
            Control::Terminal => {
                rect(&mut svg, node.bounds, "#101722", accent);
                rect(
                    &mut svg,
                    Rect(x + 1, y + 1, width - 2, 41),
                    "#243c52",
                    "none",
                );
                text(&mut svg, x + 16, y + 26, 16, "#ecf8ff", node.label);
                text(
                    &mut svg,
                    x + 20,
                    y + 78,
                    15,
                    "#a9bdd0",
                    "Keyboard echo only. No shell or command execution.",
                );
                for (index, row) in app.0.as_ref().unwrap().rows().enumerate() {
                    let line = format!("> {}", row.iter().collect::<String>());
                    text(
                        &mut svg,
                        x + 20,
                        y + 120 + index as u16 * 24,
                        17,
                        "#d9f5ee",
                        &line,
                    );
                }
                text(
                    &mut svg,
                    x + 20,
                    y + height - 22,
                    14,
                    "#a9bdd0",
                    "Super + Enter opens terminal  |  Tab moves focus",
                );
            }
            Control::Diagnostics => {
                rect(&mut svg, node.bounds, "#101722", accent);
                rect(
                    &mut svg,
                    Rect(x + 1, y + 1, width - 2, 41),
                    "#233449",
                    "none",
                );
                text(&mut svg, x + 14, y + 26, 16, "#ecf8ff", "Diagnostics");
                let d = desktop.diagnostics();
                let lines = [
                    String::from("Mode: hosted demo"),
                    format!(
                        "Terminal: {}",
                        if d.terminal_open { "open" } else { "closed" }
                    ),
                    format!("Keys delivered: {}", d.keys_delivered),
                    format!(
                        "Mouse: {}",
                        if d.mouse_attached {
                            "attached"
                        } else {
                            "absent"
                        }
                    ),
                    format!("Pointer events: {}", d.pointer_reports),
                    format!("Touch events: {}", d.touch_reports),
                    format!("Launch failures: {}", d.launch_failures),
                    String::from("Hardware: not tested"),
                ];
                for (index, line) in lines.iter().enumerate() {
                    text(
                        &mut svg,
                        x + 14,
                        y + 76 + index as u16 * 26,
                        15,
                        "#c4d8ec",
                        line,
                    );
                }
            }
            Control::CloseTerminal => {
                rect(&mut svg, node.bounds, "#263444", accent);
                text(&mut svg, x + 18, y + 27, 17, "#f2f7ff", "×");
            }
            _ => {
                rect(
                    &mut svg,
                    node.bounds,
                    if node.selected { "#244867" } else { "#182638" },
                    accent,
                );
                text(&mut svg, x + 12, y + 23, 15, "#f2f7ff", node.label);
            }
        }
    }
    if let Some(mrml_desktop::Point(x, y)) = desktop.cursor() {
        writeln!(svg, r##"<path transform="translate({x} {y})" d="M0 0v19l5-4 4 8 4-2-4-8h7Z" fill="#f5fbff" stroke="#101722" stroke-width="2"/>"##).unwrap();
    }
    println!("{svg}</svg>");
}
