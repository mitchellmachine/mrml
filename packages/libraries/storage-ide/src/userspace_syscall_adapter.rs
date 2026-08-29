use crate::{IdeServiceSyscalls, ReceivedIdeEnvelope};
use mrml_interface_storage_block_provider_v1::{ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES};
use mrml_kernel::Capability;

const SEND_BUFFER: u64 = 4;
const RECEIVE_BUFFER: u64 = 5;
const WRITE_SHARED_BUFFER: u64 = 8;
const RELEASE_CAPABILITY: u64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeSyscallFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

/// # Safety
///
/// Implementations preserve the MRML syscall ABI and access only the exact
/// pointer/length pairs in the frame during one call.
pub unsafe trait IdeRawSyscall {
    unsafe fn invoke(&mut self, frame: &mut IdeSyscallFrame);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeUserspaceSyscallError {
    InvalidLaunchBinding,
    Kernel(u64),
    Range,
}

pub struct IdeUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

impl<R> IdeUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, IdeUserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(IdeUserspaceSyscallError::InvalidLaunchBinding);
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

impl<R: IdeRawSyscall> IdeUserspaceSyscalls<R> {
    fn invoke(&mut self, frame: &mut IdeSyscallFrame) -> Result<(), IdeUserspaceSyscallError> {
        unsafe { self.raw.invoke(frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(IdeUserspaceSyscallError::Kernel(frame.rax))
        }
    }
}

unsafe impl<R: IdeRawSyscall> IdeServiceSyscalls for IdeUserspaceSyscalls<R> {
    type Error = IdeUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
    ) -> Result<ReceivedIdeEnvelope, Self::Error> {
        let mut frame = IdeSyscallFrame {
            rax: RECEIVE_BUFFER,
            rdi: request.as_mut_ptr() as u64,
            rsi: request.len() as u64,
            rdx: tokens.as_mut_ptr() as u64,
            r10: tokens.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)?;
        Ok(ReceivedIdeEnvelope {
            payload_length: usize::try_from(frame.rdx)
                .map_err(|_| IdeUserspaceSyscallError::Range)?,
            capability_count: usize::try_from(frame.r10)
                .map_err(|_| IdeUserspaceSyscallError::Range)?,
        })
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let mut frame = IdeSyscallFrame {
            rax: WRITE_SHARED_BUFFER,
            rdi: capability.token(),
            rsi: offset,
            rdx: input.as_ptr() as u64,
            r10: input.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }

    fn send_response(
        &mut self,
        response: &[u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut frame = IdeSyscallFrame {
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
        let mut frame = IdeSyscallFrame {
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
    use crate::IdeEnumerationServiceLoop;
    use mrml_interface_storage_block_provider_v1::{
        decode_enumerate_response, encode_enumerate_request, BlockProviderDevice,
        BorrowedWriteView, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
    };

    const TOKEN: u64 = (17_u64 << 32) | 6;
    struct Raw {
        request: [u8; ENUMERATE_REQUEST_BYTES],
        memory: [u8; 128],
        response: [u8; ENUMERATE_RESPONSE_BYTES],
        operations: [u64; 4],
        count: usize,
    }

    unsafe impl IdeRawSyscall for Raw {
        unsafe fn invoke(&mut self, frame: &mut IdeSyscallFrame) {
            self.operations[self.count] = frame.rax;
            self.count += 1;
            match frame.rax {
                RECEIVE_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.request.as_ptr(),
                        frame.rdi as *mut u8,
                        self.request.len(),
                    );
                    (frame.rdx as *mut u64).write(TOKEN);
                    frame.rdx = ENUMERATE_REQUEST_BYTES as u64;
                    frame.r10 = 1;
                },
                WRITE_SHARED_BUFFER => unsafe {
                    assert_eq!(frame.rdi, TOKEN);
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.memory.as_mut_ptr().add(frame.rsi as usize),
                        frame.r10 as usize,
                    );
                },
                RELEASE_CAPABILITY => assert_eq!(frame.rdi, TOKEN),
                SEND_BUFFER => unsafe {
                    assert_eq!((frame.rdi, frame.rsi), (0x91, 0xa1));
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.response.as_mut_ptr(),
                        self.response.len(),
                    );
                },
                _ => panic!("unexpected syscall"),
            }
            frame.rax = 0;
        }
    }

    fn raw(request: [u8; ENUMERATE_REQUEST_BYTES]) -> Raw {
        Raw {
            request,
            memory: [0xa5; 128],
            response: [0; 16],
            operations: [0; 4],
            count: 0,
        }
    }

    #[test]
    fn exact_frames_preserve_copy_release_reply_order() {
        let request =
            encode_enumerate_request(BorrowedWriteView::within(32, 48, 128).unwrap()).unwrap();
        assert!(matches!(
            IdeUserspaceSyscalls::new(raw(request), 0, 1),
            Err(IdeUserspaceSyscallError::InvalidLaunchBinding)
        ));
        let mut syscalls = IdeUserspaceSyscalls::new(raw(request), 0x91, 0xa1).unwrap();
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(2, 5).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 131_072,
            media_generation: 11,
        }];
        IdeEnumerationServiceLoop::new(&devices)
            .serve_one(
                &mut syscalls,
                &mut [0; ENUMERATE_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 64],
                &mut [0; ENUMERATE_RESPONSE_BYTES],
            )
            .unwrap();
        let raw = syscalls.into_raw();
        assert_eq!(
            raw.operations,
            [
                RECEIVE_BUFFER,
                WRITE_SHARED_BUFFER,
                RELEASE_CAPABILITY,
                SEND_BUFFER
            ]
        );
        assert_eq!(&raw.memory[32..40], b"MRMLBLK\0");
        assert_eq!(decode_enumerate_response(&raw.response, 48), Ok(Ok(48)));
    }
}
