#![no_std]

use mrml_interface_gui_surface_v1 as surface;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuiProbeError {
    Protocol(surface::SurfaceProtocolError),
    CommitPending,
    NoCommitPending,
    SerialExhausted,
    ResponseSerialMismatch,
    Rejected(surface::CommitError),
}

/// Placement-independent client state for the representative GUI probe.
///
/// Handles identify objects already supplied by the control plane. This client
/// can only construct the fixed interface data-plane frame and validate its
/// typed completion; it cannot create capabilities or choose a provider.
pub struct GuiProbeClient {
    surface: surface::OpaqueHandle,
    output: surface::OpaqueHandle,
    buffer: surface::OpaqueHandle,
    next_serial: u64,
    pending_serial: Option<u64>,
}

impl GuiProbeClient {
    pub const fn new(
        surface: surface::OpaqueHandle,
        output: surface::OpaqueHandle,
        buffer: surface::OpaqueHandle,
    ) -> Self {
        Self {
            surface,
            output,
            buffer,
            next_serial: 1,
            pending_serial: None,
        }
    }

    pub const fn pending_serial(&self) -> Option<u64> {
        self.pending_serial
    }

    pub fn prepare_commit(
        &mut self,
        mut state: surface::SurfaceState,
    ) -> Result<surface::SurfaceCallFrame, GuiProbeError> {
        if self.pending_serial.is_some() {
            return Err(GuiProbeError::CommitPending);
        }
        let serial = self.next_serial;
        let next = serial
            .checked_add(1)
            .ok_or(GuiProbeError::SerialExhausted)?;
        state.serial = serial;
        let frame = surface::encode_surface_call(self.surface, self.output, self.buffer, state)
            .map_err(GuiProbeError::Protocol)?;
        self.pending_serial = Some(serial);
        self.next_serial = next;
        Ok(frame)
    }

    pub fn complete(
        &mut self,
        response: &[u8; surface::COMMIT_RESPONSE_BYTES],
    ) -> Result<u64, GuiProbeError> {
        let pending = self.pending_serial.ok_or(GuiProbeError::NoCommitPending)?;
        match surface::decode_commit_response(response).map_err(GuiProbeError::Protocol)? {
            Ok(serial) if serial == pending => {
                self.pending_serial = None;
                Ok(serial)
            }
            Ok(_) => Err(GuiProbeError::ResponseSerialMismatch),
            Err(error) => {
                self.pending_serial = None;
                Err(GuiProbeError::Rejected(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surface::{LogicalRect, SurfaceFormat, SurfaceState};

    fn client() -> GuiProbeClient {
        GuiProbeClient::new(
            surface::OpaqueHandle::new(1, 7).unwrap(),
            surface::OpaqueHandle::new(2, 8).unwrap(),
            surface::OpaqueHandle::new(3, 9).unwrap(),
        )
    }

    fn state() -> SurfaceState {
        SurfaceState {
            logical_bounds: LogicalRect {
                x: 0,
                y: 0,
                width: 640,
                height: 480,
            },
            scale_numerator: 1,
            scale_denominator: 1,
            buffer_width: 640,
            buffer_height: 480,
            buffer_stride: 2560,
            buffer_byte_length: 1_228_800,
            format: SurfaceFormat::Bgra8Srgb,
            serial: 999,
            damage_count: 0,
            damage: [LogicalRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; surface::MAX_DAMAGE_RECTS],
        }
    }

    #[test]
    fn native_and_microvm_placements_receive_identical_interface_bytes() {
        let mut native = client();
        let mut microvm = client();
        let native_frame = native.prepare_commit(state()).unwrap();
        let microvm_frame = microvm.prepare_commit(state()).unwrap();
        assert_eq!(native_frame, microvm_frame);
        let (_, decoded) = surface::decode_surface_call(native_frame.bytes()).unwrap();
        assert_eq!(decoded.serial, 1);
        let response = surface::encode_commit_response(Ok(1));
        assert_eq!(native.complete(&response), Ok(1));
        assert_eq!(microvm.complete(&response), Ok(1));
    }

    #[test]
    fn pending_and_mismatched_completions_fail_closed() {
        let mut client = client();
        client.prepare_commit(state()).unwrap();
        assert_eq!(
            client.prepare_commit(state()),
            Err(GuiProbeError::CommitPending)
        );
        assert_eq!(
            client.complete(&surface::encode_commit_response(Ok(2))),
            Err(GuiProbeError::ResponseSerialMismatch)
        );
        assert_eq!(client.pending_serial(), Some(1));
        assert_eq!(
            client.complete(&surface::encode_commit_response(Err(
                surface::CommitError::PermissionDenied,
            ))),
            Err(GuiProbeError::Rejected(
                surface::CommitError::PermissionDenied
            ))
        );
        assert_eq!(client.pending_serial(), None);
    }

    #[test]
    fn invalid_state_does_not_consume_a_serial() {
        let mut client = client();
        let mut invalid = state();
        invalid.buffer_stride = 1;
        assert_eq!(
            client.prepare_commit(invalid),
            Err(GuiProbeError::Protocol(
                surface::SurfaceProtocolError::InvalidState
            ))
        );
        let frame = client.prepare_commit(state()).unwrap();
        let (_, decoded) = surface::decode_surface_call(frame.bytes()).unwrap();
        assert_eq!(decoded.serial, 1);
    }
}
