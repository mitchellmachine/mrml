use crate::{ReceivedZstdEnvelope, ZstdServiceSyscalls};
use mrml_interface_zstd_v3::{DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES};
use mrml_kernel::Capability;

const SEND_BUFFER: u64 = 4;
const RECEIVE_BUFFER: u64 = 5;
const READ_SHARED_BUFFER: u64 = 7;
const WRITE_SHARED_BUFFER: u64 = 8;
const RELEASE_CAPABILITY: u64 = 12;

/// Exact x86-64 register frame used by MRML's userspace `int 0x80` boundary.
/// Pointer fields are valid only for the duration of one `invoke` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZstdSyscallFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

/// Lowest-level architecture adapter for one synchronous syscall trap.
///
/// # Safety
///
/// The implementation must preserve the MRML syscall ABI and may access only
/// the exact pointer/length pairs in `frame` for the duration of the call. It
/// must return the kernel status in `rax` and completion values only in the
/// registers defined by the selected operation.
pub unsafe trait ZstdRawSyscall {
    unsafe fn invoke(&mut self, frame: &mut ZstdSyscallFrame);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdUserspaceSyscallError {
    InvalidLaunchBinding,
    Kernel(u64),
    Range,
}

/// Concrete register-level adapter for the existing MRML buffer syscalls.
/// Endpoint and reply task are immutable launch state and never request data.
pub struct ZstdUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

impl<R> ZstdUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, ZstdUserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(ZstdUserspaceSyscallError::InvalidLaunchBinding);
        }
        Ok(Self {
            raw,
            reply_endpoint,
            reply_task,
        })
    }

    pub fn into_raw(self) -> R {
        self.raw
    }
}

impl<R: ZstdRawSyscall> ZstdUserspaceSyscalls<R> {
    fn invoke(&mut self, frame: &mut ZstdSyscallFrame) -> Result<(), ZstdUserspaceSyscallError> {
        unsafe { self.raw.invoke(frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(ZstdUserspaceSyscallError::Kernel(frame.rax))
        }
    }

    fn shared_buffer_call(
        &mut self,
        operation: u64,
        capability: Capability,
        offset: u64,
        buffer: *mut u8,
        length: usize,
    ) -> Result<(), ZstdUserspaceSyscallError> {
        let mut frame = ZstdSyscallFrame {
            rax: operation,
            rdi: capability.token(),
            rsi: offset,
            rdx: buffer as u64,
            r10: length as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }

    fn receive_counts(
        frame: &ZstdSyscallFrame,
        payload_capacity: usize,
        capability_capacity: usize,
    ) -> Result<(usize, usize), ZstdUserspaceSyscallError> {
        let payload_length =
            usize::try_from(frame.rdx).map_err(|_| ZstdUserspaceSyscallError::Range)?;
        let capability_count =
            usize::try_from(frame.r10).map_err(|_| ZstdUserspaceSyscallError::Range)?;
        if payload_length > payload_capacity || capability_count > capability_capacity {
            return Err(ZstdUserspaceSyscallError::Range);
        }
        Ok((payload_length, capability_count))
    }
}

unsafe impl<R: ZstdRawSyscall> ZstdServiceSyscalls for ZstdUserspaceSyscalls<R> {
    type Error = ZstdUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedZstdEnvelope, Self::Error> {
        let mut frame = ZstdSyscallFrame {
            rax: RECEIVE_BUFFER,
            rdi: request.as_mut_ptr() as u64,
            rsi: request.len() as u64,
            rdx: capability_tokens.as_mut_ptr() as u64,
            r10: capability_tokens.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)?;
        let (payload_length, capability_count) =
            Self::receive_counts(&frame, request.len(), capability_tokens.len())?;
        Ok(ReceivedZstdEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.shared_buffer_call(
            READ_SHARED_BUFFER,
            capability,
            offset,
            output.as_mut_ptr(),
            output.len(),
        )
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        self.shared_buffer_call(
            WRITE_SHARED_BUFFER,
            capability,
            offset,
            input.as_ptr().cast_mut(),
            input.len(),
        )
    }

    fn send_response(
        &mut self,
        response: &[u8; DECOMPRESS_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut frame = ZstdSyscallFrame {
            rax: SEND_BUFFER,
            rdi: self.reply_endpoint,
            rsi: self.reply_task,
            rdx: response.as_ptr() as u64,
            r10: response.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        let mut frame = ZstdSyscallFrame {
            rax: RELEASE_CAPABILITY,
            rdi: capability.token(),
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZstdServiceLoop;
    use mrml_interface_zstd_v3::{
        BorrowedReadView, BorrowedWriteView, decode_decompress_response, encode_decompress_request,
    };

    const TOKEN: u64 = (7_u64 << 32) | 3;
    const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];

    struct Raw {
        request: [u8; DECOMPRESS_REQUEST_BYTES],
        memory: [u8; 128],
        response: [u8; DECOMPRESS_RESPONSE_BYTES],
        operations: [u64; 5],
        count: usize,
    }

    unsafe impl ZstdRawSyscall for Raw {
        unsafe fn invoke(&mut self, frame: &mut ZstdSyscallFrame) {
            self.operations[self.count] = frame.rax;
            self.count += 1;
            match frame.rax {
                RECEIVE_BUFFER => {
                    assert_eq!(frame.rsi, DECOMPRESS_REQUEST_BYTES as u64);
                    assert_eq!(frame.r10, 1);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.request.as_ptr(),
                            frame.rdi as *mut u8,
                            self.request.len(),
                        );
                        (frame.rdx as *mut u64).write(TOKEN);
                    }
                    frame.rdx = DECOMPRESS_REQUEST_BYTES as u64;
                    frame.r10 = 1;
                }
                READ_SHARED_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.memory.as_ptr().add(frame.rsi as usize),
                        frame.rdx as *mut u8,
                        frame.r10 as usize,
                    );
                },
                WRITE_SHARED_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.memory.as_mut_ptr().add(frame.rsi as usize),
                        frame.r10 as usize,
                    );
                },
                RELEASE_CAPABILITY => assert_eq!(frame.rdi, TOKEN),
                SEND_BUFFER => {
                    assert_eq!((frame.rdi, frame.rsi), (0x51, 0x61));
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            frame.rdx as *const u8,
                            self.response.as_mut_ptr(),
                            self.response.len(),
                        );
                    }
                }
                _ => panic!("unexpected syscall operation"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn exact_syscall_frames_complete_one_bounded_service_call() {
        assert!(matches!(
            ZstdUserspaceSyscalls::new(
                Raw {
                    request: [0; DECOMPRESS_REQUEST_BYTES],
                    memory: [0; 128],
                    response: [0; DECOMPRESS_RESPONSE_BYTES],
                    operations: [0; 5],
                    count: 0,
                },
                0,
                1,
            ),
            Err(ZstdUserspaceSyscallError::InvalidLaunchBinding)
        ));
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, 128).unwrap(),
            BorrowedWriteView::within(64, 32, 128).unwrap(),
        )
        .unwrap();
        let mut raw = Raw {
            request,
            memory: [0xa5; 128],
            response: [0xcc; DECOMPRESS_RESPONSE_BYTES],
            operations: [0; 5],
            count: 0,
        };
        raw.memory[..FRAME.len()].copy_from_slice(&FRAME);
        let mut syscalls = ZstdUserspaceSyscalls::new(raw, 0x51, 0x61).unwrap();
        ZstdServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut [0xcc; DECOMPRESS_REQUEST_BYTES],
                &mut [u64::MAX; 1],
                &mut [0xcc; 128],
                &mut [0xcc; DECOMPRESS_RESPONSE_BYTES],
            )
            .unwrap();
        let raw = syscalls.into_raw();
        assert_eq!(
            raw.operations,
            [
                RECEIVE_BUFFER,
                READ_SHARED_BUFFER,
                WRITE_SHARED_BUFFER,
                RELEASE_CAPABILITY,
                SEND_BUFFER,
            ]
        );
        assert_eq!(&raw.memory[64..69], b"xxxxx");
        assert_eq!(decode_decompress_response(&raw.response), Ok(Ok(5)));
    }

    #[test]
    fn rejects_kernel_counts_beyond_supplied_receive_buffers() {
        let frame = ZstdSyscallFrame {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: DECOMPRESS_REQUEST_BYTES as u64 + 1,
            r10: 1,
            r8: 0,
            r9: 0,
        };
        assert_eq!(
            ZstdUserspaceSyscalls::<Raw>::receive_counts(&frame, DECOMPRESS_REQUEST_BYTES, 1),
            Err(ZstdUserspaceSyscallError::Range)
        );
        let frame = ZstdSyscallFrame {
            rdx: 0,
            r10: 2,
            ..frame
        };
        assert_eq!(
            ZstdUserspaceSyscalls::<Raw>::receive_counts(&frame, DECOMPRESS_REQUEST_BYTES, 1),
            Err(ZstdUserspaceSyscallError::Range)
        );
    }
}
