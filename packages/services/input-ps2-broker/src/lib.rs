#![no_std]
#![forbid(unsafe_code)]

//! Read-only PS/2 routing core. No port, interrupt or guest authority is
//! created by the byte classification or the resulting stream.

const OBF: u8 = 0x01;
const AUX_DATA: u8 = 0x20;
const TIMEOUT_OR_PARITY: u8 = 0xc0;
pub const MAX_SAMPLES_PER_POLL: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputByte {
    Data(u8),
    /// Desynchronization: discard any partial input and reconcile held state.
    Gap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sample {
    /// Captured together by the exclusive controller owner. Only set this
    /// variant when the controller's command engine is in the streaming phase.
    Stream { status: u8, data: u8 },
    /// Controller/device command result handled by the exclusive owner.
    Command,
    /// Loss or reset when the affected stream is not known.
    Discontinuity,
    /// The owner re-established the indicated protocol's event boundary.
    Resynchronized { auxiliary: bool },
}

/// Implemented only at the trusted controller transport. Collect status and
/// data as one observation and never dequeue an input byte without OBF.
/// Errors mean the current stream continuity cannot be established.
pub trait ControllerSource {
    type Error;
    fn next(&mut self) -> Result<Option<Sample>, Self::Error>;
}

struct Stream<const N: usize> {
    queue: [u8; N],
    head: usize,
    len: usize,
    gap: bool,
    blocked: bool,
}

impl<const N: usize> Stream<N> {
    const fn new() -> Self {
        Self {
            queue: [0; N],
            head: 0,
            len: 0,
            gap: false,
            blocked: false,
        }
    }

    fn invalidate(&mut self) {
        self.head = 0;
        self.len = 0;
        self.gap = true;
        self.blocked = true;
    }

    fn push(&mut self, byte: u8) {
        if self.blocked {
            return;
        }
        if self.len == N {
            // Do not consume buffered bytes as contiguous after dropping one.
            self.invalidate();
            return;
        }
        let index = self.head.wrapping_add(self.len) % N;
        self.queue[index] = byte;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<InputByte> {
        if core::mem::take(&mut self.gap) {
            return Some(InputByte::Gap);
        }
        if self.len == 0 {
            return None;
        }
        let byte = self.queue[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(InputByte::Data(byte))
    }
}

/// Owns two independent queues. A failed source read invalidates both;
/// a tagged parity fault or overflow only invalidates the affected stream.
pub struct Ps2Broker<const N: usize> {
    keyboard: Stream<N>,
    mouse: Stream<N>,
}

impl<const N: usize> Default for Ps2Broker<N> {
    fn default() -> Self {
        Self {
            keyboard: Stream::new(),
            mouse: Stream::new(),
        }
    }
}

impl<const N: usize> Ps2Broker<N> {
    /// Process at most one bounded batch; never spins waiting for input.
    pub fn poll<S: ControllerSource>(&mut self, source: &mut S) -> Result<usize, S::Error> {
        for count in 0..MAX_SAMPLES_PER_POLL {
            match source.next() {
                Ok(Some(sample)) => self.accept(sample),
                Ok(None) => return Ok(count),
                Err(err) => {
                    self.invalidate();
                    return Err(err);
                }
            }
        }
        Ok(MAX_SAMPLES_PER_POLL)
    }

    fn invalidate(&mut self) {
        self.keyboard.invalidate();
        self.mouse.invalidate();
    }

    fn accept(&mut self, sample: Sample) {
        match sample {
            Sample::Discontinuity => self.invalidate(),
            Sample::Command => {}
            Sample::Resynchronized { auxiliary } => {
                let stream = if auxiliary {
                    &mut self.mouse
                } else {
                    &mut self.keyboard
                };
                stream.invalidate();
                stream.blocked = false;
            }
            Sample::Stream { status, data } => {
                if status & OBF == 0 {
                    return;
                }
                let stream = if status & AUX_DATA == 0 {
                    &mut self.keyboard
                } else {
                    &mut self.mouse
                };
                if status & TIMEOUT_OR_PARITY != 0 {
                    stream.invalidate();
                } else {
                    stream.push(data);
                }
            }
        }
    }

    /// The runtime adapter must expose these as distinct receive endpoints.
    pub fn next_keyboard(&mut self) -> Option<InputByte> {
        self.keyboard.pop()
    }
    pub fn next_mouse(&mut self) -> Option<InputByte> {
        self.mouse.pop()
    }
}

#[cfg(all(test, target_os = "linux"))]
extern crate std;

#[cfg(all(test, target_os = "linux"))]
mod qemu;

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_input_ps2_keyboard::{KeyboardEvent, Ps2Keyboard};
    use mrml_input_ps2_mouse::{MouseReport, Ps2Mouse};

    struct Source<'a>(&'a [Result<Sample, ()>]);

    impl ControllerSource for Source<'_> {
        type Error = ();
        fn next(&mut self) -> Result<Option<Sample>, ()> {
            let Some((item, rest)) = self.0.split_first() else {
                return Ok(None);
            };
            self.0 = rest;
            item.map(Some)
        }
    }

    const fn sample(status: u8, data: u8) -> Result<Sample, ()> {
        Ok(Sample::Stream { status, data })
    }

    #[test]
    fn interleaved_controller_samples_reach_only_their_decoder() {
        let mut broker = Ps2Broker::<8>::default();
        assert_eq!(
            broker.poll(&mut Source(&[
                sample(OBF, 0xf0),
                sample(OBF | AUX_DATA, 9),
                Ok(Sample::Command),
                sample(OBF, 0x1c),
                sample(OBF | AUX_DATA, 2),
                sample(OBF | AUX_DATA, 1),
                sample(AUX_DATA, 0xff),
            ])),
            Ok(7)
        );
        let mut keyboard = Ps2Keyboard::default();
        let mut mouse = Ps2Mouse::default();
        assert_eq!(broker.next_keyboard(), Some(InputByte::Data(0xf0)));
        assert_eq!(keyboard.push(0xf0), None);
        let Some(InputByte::Data(scan)) = broker.next_keyboard() else {
            panic!()
        };
        assert_eq!(
            keyboard.push(scan),
            Some(KeyboardEvent::Key {
                scan: 0x1c,
                extended: false,
                pressed: false
            })
        );
        assert_eq!(broker.next_keyboard(), None);
        for expected in [9, 2] {
            let Some(InputByte::Data(data)) = broker.next_mouse() else {
                panic!()
            };
            assert_eq!(data, expected);
            assert_eq!(mouse.push(data), None);
        }
        let Some(InputByte::Data(data)) = broker.next_mouse() else {
            panic!()
        };
        assert_eq!(
            mouse.push(data),
            Some(MouseReport {
                left: true,
                right: false,
                middle: false,
                dx: 2,
                dy: -1
            })
        );
        assert_eq!(broker.next_mouse(), None);
    }

    #[test]
    fn overflow_and_bad_parity_do_not_cross_streams() {
        let mut broker = Ps2Broker::<2>::default();
        let mut source = Source(&[
            sample(OBF | AUX_DATA, 42),
            sample(OBF, 0xe0),
            sample(OBF, 0xf0),
            sample(OBF, 0x75),
            sample(OBF, 0x14),
            Ok(Sample::Resynchronized { auxiliary: false }),
            sample(OBF, 0x1c),
        ]);
        assert_eq!(broker.poll(&mut source), Ok(7));
        assert_eq!(broker.next_mouse(), Some(InputByte::Data(42)));
        assert_eq!(broker.next_keyboard(), Some(InputByte::Gap));
        assert_eq!(broker.next_keyboard(), Some(InputByte::Data(0x1c)));
        let mut source = Source(&[
            sample(OBF | AUX_DATA, 8),
            sample(OBF, 0x1b),
            sample(OBF | AUX_DATA | 0x80, 1),
        ]);
        assert_eq!(broker.poll(&mut source), Ok(3));
        assert_eq!(broker.next_mouse(), Some(InputByte::Gap));
        assert_eq!(broker.next_mouse(), None);
        assert_eq!(broker.next_keyboard(), Some(InputByte::Data(0x1b)));
    }

    #[test]
    fn source_error_invalidates_both_and_poll_work_is_bounded() {
        let mut broker = Ps2Broker::<1>::default();
        assert_eq!(
            broker.poll(&mut Source(&[sample(OBF, 0x1c), Err(())])),
            Err(())
        );
        assert_eq!(broker.next_keyboard(), Some(InputByte::Gap));
        assert_eq!(broker.next_mouse(), Some(InputByte::Gap));
        assert_eq!(broker.next_keyboard(), None);
        let samples = [Ok(Sample::Command); MAX_SAMPLES_PER_POLL + 1];
        let mut source = Source(&samples);
        assert_eq!(broker.poll(&mut source), Ok(MAX_SAMPLES_PER_POLL));
        assert_eq!(broker.poll(&mut source), Ok(1));
    }
}
