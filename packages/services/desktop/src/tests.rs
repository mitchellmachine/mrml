use super::*;
use mrml_terminal_probe::Terminal;

#[derive(Default)]
struct Fixture {
    generation: u64,
    current: Option<(NonZeroU64, Terminal)>,
    unavailable: bool,
}

impl TerminalRoute for Fixture {
    fn launch_terminal(&mut self) -> Result<NonZeroU64, RouteError> {
        if self.unavailable {
            return Err(RouteError::Unavailable);
        }
        assert!(self.current.is_none());
        self.generation += 1;
        let id = NonZeroU64::new(self.generation).unwrap();
        self.current = Some((id, Terminal::new()));
        Ok(id)
    }
    fn send_key(&mut self, route: NonZeroU64, key: Key) -> Result<(), RouteError> {
        let (_, app) = self
            .current
            .as_mut()
            .filter(|(id, _)| *id == route)
            .ok_or(RouteError::Retired)?;
        app.key(key);
        Ok(())
    }
    fn retire_terminal(&mut self, route: NonZeroU64) -> Result<(), RouteError> {
        if self.current.as_ref().is_some_and(|(id, _)| *id == route) {
            self.current = None;
            Ok(())
        } else {
            Err(RouteError::Retired)
        }
    }
}

#[test]
fn keyboard_launches_one_application_and_routes_echo_only_when_focused() {
    let mut shell = Desktop::new(960, 520).unwrap();
    let mut fixture = Fixture::default();
    for event in [
        Event::ActivateFocused,
        Event::SuperEnter,
        Event::TerminalKey(Key::Text('a')),
    ] {
        shell.event(event, &mut fixture).unwrap();
    }
    assert_eq!(fixture.generation, 1);
    assert_eq!(shell.cursor(), None);
    assert_eq!(
        fixture.current.as_ref().unwrap().1.rows().next(),
        Some(&['a'][..])
    );
    shell.event(Event::Tab, &mut fixture).unwrap();
    assert!(
        shell
            .nodes()
            .any(|n| n.control == Control::CloseTerminal && n.focused)
    );
    shell
        .event(Event::TerminalKey(Key::Text('b')), &mut fixture)
        .unwrap();
    assert_eq!(
        fixture.current.as_ref().unwrap().1.rows().next(),
        Some(&['a'][..])
    );
    shell.event(Event::ActivateFocused, &mut fixture).unwrap();
    assert!(fixture.current.is_none());
    assert!(shell.nodes().all(|node| node.control != Control::Terminal));
}

#[test]
fn touch_taps_and_cancellation_never_create_a_mouse_cursor() {
    let mut shell = Desktop::new(480, 280).unwrap();
    let mut fixture = Fixture::default();
    let launcher = Point(150, 15);
    shell
        .event(Event::TouchDown(4, launcher), &mut fixture)
        .unwrap();
    shell
        .event(Event::TouchUp(5, launcher), &mut fixture)
        .unwrap();
    shell.event(Event::TouchCancel(4), &mut fixture).unwrap();
    shell
        .event(Event::TouchUp(4, launcher), &mut fixture)
        .unwrap();
    assert!(fixture.current.is_none());
    shell
        .event(Event::TouchDown(6, launcher), &mut fixture)
        .unwrap();
    shell
        .event(Event::TouchUp(6, Point(5, 120)), &mut fixture)
        .unwrap();
    assert!(fixture.current.is_none());
    shell
        .event(Event::TouchDown(7, launcher), &mut fixture)
        .unwrap();
    shell
        .event(Event::TouchUp(7, launcher), &mut fixture)
        .unwrap();
    assert!(fixture.current.is_some());
    assert_eq!(shell.cursor(), None);
}

#[test]
fn mouse_shows_cursor_only_while_attached_and_click_requires_same_target() {
    let mut shell = Desktop::new(480, 280).unwrap();
    let mut fixture = Fixture::default();
    shell
        .event(Event::MouseMotion(20, 30), &mut fixture)
        .unwrap();
    assert_eq!(shell.cursor(), None);
    shell.event(Event::AttachMouse, &mut fixture).unwrap();
    assert_eq!(shell.cursor(), Some(Point(240, 140)));
    shell
        .event(Event::MouseMotion(-90, -125), &mut fixture)
        .unwrap();
    shell
        .event(Event::MousePrimary(true), &mut fixture)
        .unwrap();
    shell
        .event(Event::MouseMotion(i32::MAX, i32::MIN), &mut fixture)
        .unwrap();
    assert_eq!(shell.cursor(), Some(Point(479, 0)));
    shell
        .event(Event::MousePrimary(false), &mut fixture)
        .unwrap();
    assert!(fixture.current.is_none());
    shell
        .event(Event::MouseMotion(-329, 15), &mut fixture)
        .unwrap();
    shell
        .event(Event::MousePrimary(true), &mut fixture)
        .unwrap();
    shell
        .event(Event::MousePrimary(false), &mut fixture)
        .unwrap();
    assert!(fixture.current.is_some());
    shell.event(Event::DetachMouse, &mut fixture).unwrap();
    assert_eq!(shell.cursor(), None);
}

#[test]
fn launch_failure_and_retired_routes_cannot_send_keys_or_show_a_fake_tile() {
    let mut shell = Desktop::new(960, 520).unwrap();
    let mut fixture = Fixture {
        unavailable: true,
        ..Fixture::default()
    };
    assert_eq!(
        shell.event(Event::SuperEnter, &mut fixture),
        Err(RouteError::Unavailable)
    );
    assert!(shell.nodes().all(|node| node.control != Control::Terminal));
    fixture.unavailable = false;
    shell.event(Event::SuperEnter, &mut fixture).unwrap();
    let old = fixture.current.take().unwrap().0;
    assert_eq!(
        shell.event(Event::TerminalKey(Key::Text('x')), &mut fixture),
        Err(RouteError::Retired)
    );
    shell.event(Event::SuperEnter, &mut fixture).unwrap();
    shell.withdraw(old);
    assert!(
        shell
            .nodes()
            .any(|node| node.control == Control::Terminal && node.focused)
    );
    shell.activate(Control::Workspace(2), &mut fixture).unwrap();
    assert!(shell.nodes().all(|node| node.control != Control::Terminal));
    shell.event(Event::SuperEnter, &mut fixture).unwrap();
    assert_eq!(fixture.generation, 2);
    assert!(
        shell
            .nodes()
            .any(|node| node.control == Control::Workspace(1) && node.selected)
    );
}
