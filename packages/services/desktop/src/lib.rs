#![no_std]
#![forbid(unsafe_code)]

//! Bounded shell policy over normalized seat events and an admitted app route.
//! This core neither consumes raw HID nor grants access to any output.

use core::num::NonZeroU64;
pub use mrml_terminal_probe::Key;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Point(pub u16, pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect(pub u16, pub u16, pub u16, pub u16);

impl Rect {
    fn contains(self, Point(x, y): Point) -> bool {
        x.checked_sub(self.0).is_some_and(|x| x < self.2)
            && y.checked_sub(self.1).is_some_and(|y| y < self.3)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Workspace(u8),
    OpenTerminal,
    Terminal,
    CloseTerminal,
    Diagnostics,
    TaskManagerButton,
    TaskManager,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    AttachMouse,
    DetachMouse,
    MouseMotion(i32, i32),
    MousePrimary(bool),
    TouchDown(u32, Point),
    TouchUp(u32, Point),
    TouchCancel(u32),
    Tab,
    ActivateFocused,
    Enter,
    SuperEnter,
    TerminalKey(Key),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    Unavailable,
    Retired,
}

/// Supplied by the launcher, not by the seat or GUI client. Every send must
/// recheck the exact admitted incarnation. Tokens alone grant no authority.
pub trait TerminalRoute {
    fn launch_terminal(&mut self) -> Result<NonZeroU64, RouteError>;
    fn send_key(&mut self, route: NonZeroU64, key: Key) -> Result<(), RouteError>;
    fn retire_terminal(&mut self, route: NonZeroU64) -> Result<(), RouteError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    pub control: Control,
    pub label: &'static str,
    pub bounds: Rect,
    pub focused: bool,
    pub selected: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    pub mouse_attached: bool,
    pub pointer_reports: u32,
    pub touch_reports: u32,
    pub keys_delivered: u32,
    pub terminal_open: bool,
    pub launch_failures: u32,
}

pub struct Desktop {
    width: u16,
    height: u16,
    active: u8,
    focus: Control,
    app: Option<(u8, NonZeroU64)>,
    mouse: Option<Point>,
    mouse_down: Option<Control>,
    primary_pressed: bool,
    touch: Option<(u32, Option<Control>)>,
    counters: Diagnostics,
    task_manager_open: bool,
}

impl Desktop {
    pub fn new(width: u16, height: u16) -> Option<Self> {
        if !(480..=8192).contains(&width) || !(280..=8192).contains(&height) {
            return None;
        }
        Some(Self {
            width,
            height,
            active: 1,
            focus: Control::OpenTerminal,
            app: None,
            mouse: None,
            mouse_down: None,
            primary_pressed: false,
            touch: None,
            counters: Diagnostics::default(),
            task_manager_open: false,
        })
    }

    pub const fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    pub const fn cursor(&self) -> Option<Point> {
        self.mouse
    }

    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics {
            mouse_attached: self.mouse.is_some(),
            terminal_open: self.app.is_some(),
            ..self.counters
        }
    }

    fn visible_app(&self) -> Option<NonZeroU64> {
        self.app
            .filter(|(workspace, _)| *workspace == self.active)
            .map(|(_, id)| id)
    }

    /// One bounded semantic snapshot drives both rendering and hit testing.
    /// Publishing it to other clients is a separate, authorized projection.
    pub fn nodes(&self) -> impl Iterator<Item = Node> + use<> {
        let tile_visible = self.visible_app().is_some() && !self.task_manager_open;
        let (focus, active) = (self.focus, self.active);
        let monitor_width = if self.width >= 720 { 252 } else { 144 };
        let monitor_x = self.width - 12 - monitor_width;
        let terminal_width = monitor_x - 24;
        [
            (Control::Workspace(1), "1", Rect(8, 4, 36, 36), true),
            (Control::Workspace(2), "2", Rect(48, 4, 36, 36), true),
            (Control::Workspace(3), "3", Rect(88, 4, 36, 36), true),
            (
                Control::OpenTerminal,
                "Terminal",
                Rect(132, 4, 112, 36),
                true,
            ),
            (
                Control::TaskManagerButton,
                "Task manager",
                Rect(252, 4, 136, 36),
                true,
            ),
            (
                Control::TaskManager,
                "MicroVM task manager",
                Rect(12, 56, terminal_width, self.height - 68),
                self.task_manager_open,
            ),
            (
                Control::Terminal,
                "Keyboard test terminal",
                Rect(12, 56, terminal_width, self.height - 68),
                tile_visible,
            ),
            (
                Control::CloseTerminal,
                "Close terminal",
                Rect(monitor_x - 60, 56, 48, 42),
                tile_visible,
            ),
            (
                Control::Diagnostics,
                "Diagnostics",
                Rect(monitor_x, 56, monitor_width, self.height - 68),
                true,
            ),
        ]
        .into_iter()
        .filter(|(_, _, _, visible)| *visible)
        .map(move |(control, label, bounds, _)| Node {
            control,
            label,
            bounds,
            focused: focus == control,
            selected: control == Control::Workspace(active),
        })
    }

    fn hit(&self, point: Point) -> Option<Control> {
        self.nodes()
            .filter(|node| node.bounds.contains(point))
            .last()
            .map(|node| node.control)
    }

    pub fn activate(
        &mut self,
        control: Control,
        route: &mut impl TerminalRoute,
    ) -> Result<(), RouteError> {
        if !self.nodes().any(|node| node.control == control) {
            return Ok(());
        }
        match control {
            Control::Workspace(workspace) => {
                self.active = workspace;
                self.focus = control;
            }
            Control::OpenTerminal => {
                let (workspace, id) = match self.app {
                    Some(app) => app,
                    None => match route.launch_terminal() {
                        Ok(id) => (self.active, id),
                        Err(error) => {
                            self.counters.launch_failures =
                                self.counters.launch_failures.saturating_add(1);
                            return Err(error);
                        }
                    },
                };
                self.app = Some((workspace, id));
                self.active = workspace;
                self.task_manager_open = false;
                self.focus = Control::Terminal;
            }
            Control::TaskManagerButton => {
                self.task_manager_open = !self.task_manager_open;
                self.focus = if self.task_manager_open {
                    Control::TaskManager
                } else {
                    control
                };
            }
            Control::Terminal | Control::Diagnostics | Control::TaskManager => self.focus = control,
            Control::CloseTerminal => {
                let id = self.visible_app().ok_or(RouteError::Retired)?;
                match route.retire_terminal(id) {
                    Ok(()) | Err(RouteError::Retired) => self.withdraw(id),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// This notice is accepted only from the launcher for the exact route.
    pub fn withdraw(&mut self, id: NonZeroU64) {
        if self.app.is_some_and(|(_, current)| current == id) {
            self.app = None;
            self.focus = Control::OpenTerminal;
            self.mouse_down = None;
            self.touch = None;
        }
    }

    pub fn event(
        &mut self,
        event: Event,
        route: &mut impl TerminalRoute,
    ) -> Result<(), RouteError> {
        let mut action = None;
        let event = match event {
            Event::Enter if self.focus == Control::Terminal => Event::TerminalKey(Key::Enter),
            Event::Enter => Event::ActivateFocused,
            event => event,
        };
        if matches!(
            event,
            Event::TouchDown(..) | Event::TouchUp(..) | Event::TouchCancel(..)
        ) {
            self.counters.touch_reports = self.counters.touch_reports.saturating_add(1);
        }
        if self.mouse.is_some() && matches!(event, Event::MouseMotion(..) | Event::MousePrimary(..))
        {
            self.counters.pointer_reports = self.counters.pointer_reports.saturating_add(1);
        }
        match event {
            Event::AttachMouse => {
                if self.mouse.is_none() {
                    self.mouse = Some(Point(self.width / 2, self.height / 2));
                }
            }
            Event::DetachMouse => {
                self.mouse = None;
                self.mouse_down = None;
                self.primary_pressed = false;
            }
            Event::MouseMotion(dx, dy) => {
                if let Some(Point(x, y)) = self.mouse {
                    let add = |v, d, n: u16| {
                        i32::from(v).saturating_add(d).clamp(0, i32::from(n - 1)) as u16
                    };
                    self.mouse = Some(Point(add(x, dx, self.width), add(y, dy, self.height)));
                }
            }
            Event::MousePrimary(true) if !self.primary_pressed && self.mouse.is_some() => {
                self.primary_pressed = true;
                self.mouse_down = self.mouse.and_then(|p| self.hit(p));
            }
            Event::MousePrimary(false) => {
                self.primary_pressed = false;
                action = self
                    .mouse_down
                    .take()
                    .filter(|&target| self.mouse.and_then(|p| self.hit(p)) == Some(target));
            }
            Event::TouchDown(id, point) if self.touch.is_none() => {
                self.touch = Some((id, self.hit(point)))
            }
            Event::TouchCancel(id) if self.touch.is_some_and(|(active, _)| active == id) => {
                self.touch = None
            }
            Event::TouchUp(id, point) if self.touch.is_some_and(|(active, _)| active == id) => {
                action = self
                    .touch
                    .take()
                    .and_then(|(_, target)| target)
                    .filter(|&target| self.hit(point) == Some(target));
            }
            Event::Tab => {
                let mut nodes = self.nodes();
                let first = nodes.next().map(|n| n.control);
                let after_focus = if first == Some(self.focus) {
                    nodes.next().map(|n| n.control)
                } else {
                    nodes
                        .skip_while(|node| !node.focused)
                        .nth(1)
                        .map(|n| n.control)
                };
                if let Some(next) = after_focus.or(first) {
                    self.focus = next;
                }
            }
            Event::ActivateFocused => action = Some(self.focus),
            Event::SuperEnter => action = Some(Control::OpenTerminal),
            Event::TerminalKey(key) if self.focus == Control::Terminal => {
                if let Some(id) = self.visible_app() {
                    if let Err(error) = route.send_key(id, key) {
                        if error == RouteError::Retired {
                            self.withdraw(id);
                        }
                        return Err(error);
                    }
                    self.counters.keys_delivered = self.counters.keys_delivered.saturating_add(1);
                }
            }
            _ => {}
        }
        if let Some(control) = action {
            self.activate(control, route)?;
        }
        Ok(())
    }
}

pub mod boot_frame;
pub mod raster;
pub mod seat;
pub mod tasks;

#[cfg(test)]
mod tests;
