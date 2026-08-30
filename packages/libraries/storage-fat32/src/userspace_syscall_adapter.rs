use crate::{
    Fat32LookupServiceSyscalls, Fat32MountServiceSyscalls, Fat32ServiceSyscalls,
    Fat32UnmountServiceSyscalls, ReceivedFat32Envelope, ReceivedFat32LookupEnvelope,
    ReceivedFat32MountEnvelope, ReceivedFat32UnmountEnvelope,
};
use mrml_interface_storage_filesystem_v2::{
    LOOKUP_REQUEST_BYTES, LOOKUP_RESPONSE_BYTES, MOUNT_REQUEST_BYTES, MOUNT_RESPONSE_BYTES,
    PROBE_REQUEST_BYTES, PROBE_RESPONSE_BYTES, UNMOUNT_REQUEST_BYTES, UNMOUNT_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

const SEND_BUFFER: u64 = 4;
const RECEIVE_BUFFER: u64 = 5;
const READ_SHARED_BUFFER: u64 = 7;
const RELEASE_CAPABILITY: u64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32SyscallFrame {
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
/// Implementations must preserve the MRML syscall ABI and access only the exact
/// pointer/length pairs carried by the frame for the duration of the call.
pub unsafe trait Fat32RawSyscall {
    unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32UserspaceSyscallError {
    InvalidLaunchBinding,
    Kernel(u64),
    Range,
}

pub struct Fat32UserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

pub struct Fat32MountUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

pub struct Fat32LookupUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

impl<R> Fat32LookupUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, Fat32UserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(Fat32UserspaceSyscallError::InvalidLaunchBinding);
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

pub struct Fat32UnmountUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

impl<R> Fat32UnmountUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, Fat32UserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(Fat32UserspaceSyscallError::InvalidLaunchBinding);
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

impl<R> Fat32MountUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, Fat32UserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(Fat32UserspaceSyscallError::InvalidLaunchBinding);
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

impl<R> Fat32UserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, Fat32UserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(Fat32UserspaceSyscallError::InvalidLaunchBinding);
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

impl<R: Fat32RawSyscall> Fat32UserspaceSyscalls<R> {
    fn invoke(&mut self, frame: &mut Fat32SyscallFrame) -> Result<(), Fat32UserspaceSyscallError> {
        unsafe { self.raw.invoke(frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }

    fn receive_counts(
        frame: &Fat32SyscallFrame,
        payload_capacity: usize,
        capability_capacity: usize,
    ) -> Result<(usize, usize), Fat32UserspaceSyscallError> {
        let payload_length =
            usize::try_from(frame.rdx).map_err(|_| Fat32UserspaceSyscallError::Range)?;
        let capability_count =
            usize::try_from(frame.r10).map_err(|_| Fat32UserspaceSyscallError::Range)?;
        if payload_length > payload_capacity || capability_count > capability_capacity {
            return Err(Fat32UserspaceSyscallError::Range);
        }
        Ok((payload_length, capability_count))
    }
}

unsafe impl<R: Fat32RawSyscall> Fat32ServiceSyscalls for Fat32UserspaceSyscalls<R> {
    type Error = Fat32UserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; PROBE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32Envelope, Self::Error> {
        let mut frame = Fat32SyscallFrame {
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
        Ok(ReceivedFat32Envelope {
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
        let mut frame = Fat32SyscallFrame {
            rax: READ_SHARED_BUFFER,
            rdi: capability.token(),
            rsi: offset,
            rdx: output.as_mut_ptr() as u64,
            r10: output.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }

    fn send_response(&mut self, response: &[u8; PROBE_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        let mut frame = Fat32SyscallFrame {
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
        let mut frame = Fat32SyscallFrame {
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

unsafe impl<R: Fat32RawSyscall> Fat32MountServiceSyscalls for Fat32MountUserspaceSyscalls<R> {
    type Error = Fat32UserspaceSyscallError;

    fn receive_mount(
        &mut self,
        request: &mut [u8; MOUNT_REQUEST_BYTES],
    ) -> Result<ReceivedFat32MountEnvelope, Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: RECEIVE_BUFFER,
            rdi: request.as_mut_ptr() as u64,
            rsi: request.len() as u64,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax != 0 {
            return Err(Fat32UserspaceSyscallError::Kernel(frame.rax));
        }
        let (payload_length, capability_count) =
            Fat32UserspaceSyscalls::<R>::receive_counts(&frame, request.len(), 0)?;
        Ok(ReceivedFat32MountEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn send_mount_response(
        &mut self,
        response: &[u8; MOUNT_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: SEND_BUFFER,
            rdi: self.reply_endpoint,
            rsi: self.reply_task,
            rdx: response.as_ptr() as u64,
            r10: response.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }
}

unsafe impl<R: Fat32RawSyscall> Fat32UnmountServiceSyscalls for Fat32UnmountUserspaceSyscalls<R> {
    type Error = Fat32UserspaceSyscallError;

    fn receive_unmount(
        &mut self,
        request: &mut [u8; UNMOUNT_REQUEST_BYTES],
    ) -> Result<ReceivedFat32UnmountEnvelope, Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: RECEIVE_BUFFER,
            rdi: request.as_mut_ptr() as u64,
            rsi: request.len() as u64,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax != 0 {
            return Err(Fat32UserspaceSyscallError::Kernel(frame.rax));
        }
        let (payload_length, capability_count) =
            Fat32UserspaceSyscalls::<R>::receive_counts(&frame, request.len(), 0)?;
        Ok(ReceivedFat32UnmountEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn send_unmount_response(
        &mut self,
        response: &[u8; UNMOUNT_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: SEND_BUFFER,
            rdi: self.reply_endpoint,
            rsi: self.reply_task,
            rdx: response.as_ptr() as u64,
            r10: response.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }
}

unsafe impl<R: Fat32RawSyscall> Fat32LookupServiceSyscalls for Fat32LookupUserspaceSyscalls<R> {
    type Error = Fat32UserspaceSyscallError;

    fn receive_lookup(
        &mut self,
        request: &mut [u8; LOOKUP_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32LookupEnvelope, Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: RECEIVE_BUFFER,
            rdi: request.as_mut_ptr() as u64,
            rsi: request.len() as u64,
            rdx: capability_tokens.as_mut_ptr() as u64,
            r10: capability_tokens.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax != 0 {
            return Err(Fat32UserspaceSyscallError::Kernel(frame.rax));
        }
        let (payload_length, capability_count) = Fat32UserspaceSyscalls::<R>::receive_counts(
            &frame,
            request.len(),
            capability_tokens.len(),
        )?;
        Ok(ReceivedFat32LookupEnvelope {
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
        let mut frame = Fat32SyscallFrame {
            rax: READ_SHARED_BUFFER,
            rdi: capability.token(),
            rsi: offset,
            rdx: output.as_mut_ptr() as u64,
            r10: output.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }

    fn send_lookup_response(
        &mut self,
        response: &[u8; LOOKUP_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: SEND_BUFFER,
            rdi: self.reply_endpoint,
            rsi: self.reply_task,
            rdx: response.as_ptr() as u64,
            r10: response.len() as u64,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        let mut frame = Fat32SyscallFrame {
            rax: RELEASE_CAPABILITY,
            rdi: capability.token(),
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(Fat32UserspaceSyscallError::Kernel(frame.rax))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fat32ServiceLoop;
    use mrml_interface_storage_filesystem_v2::{
        decode_probe_response, encode_probe_request, BorrowedReadView, OpaqueHandle,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    struct Raw {
        request: [u8; PROBE_REQUEST_BYTES],
        shared: [u8; 512],
        response: [u8; PROBE_RESPONSE_BYTES],
        operations: [u64; 4],
        count: usize,
    }

    unsafe impl Fat32RawSyscall for Raw {
        unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame) {
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
                    frame.rdx = PROBE_REQUEST_BYTES as u64;
                    frame.r10 = 1;
                },
                READ_SHARED_BUFFER => unsafe {
                    assert_eq!(frame.rdi, TOKEN);
                    core::ptr::copy_nonoverlapping(
                        self.shared.as_ptr().add(frame.rsi as usize),
                        frame.rdx as *mut u8,
                        frame.r10 as usize,
                    );
                },
                RELEASE_CAPABILITY => assert_eq!(frame.rdi, TOKEN),
                SEND_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.response.as_mut_ptr(),
                        frame.r10 as usize,
                    );
                },
                _ => panic!("unexpected syscall"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn register_adapter_preserves_exact_call_release_reply_order() {
        let request = encode_probe_request(
            OpaqueHandle::new(3, 8).unwrap(),
            BorrowedReadView::within(0, 512, 512).unwrap(),
        )
        .unwrap();
        let raw = Raw {
            request,
            shared: crate::tests::boot_sector(),
            response: [0; PROBE_RESPONSE_BYTES],
            operations: [0; 4],
            count: 0,
        };
        let mut syscalls = Fat32UserspaceSyscalls::new(raw, 12, 13).unwrap();
        let mut request_buffer = [0; PROBE_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut scratch = [0; 4096];
        let mut response = [0; PROBE_RESPONSE_BYTES];
        Fat32ServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        let raw = syscalls.into_raw();
        assert_eq!(
            raw.operations,
            [
                RECEIVE_BUFFER,
                READ_SHARED_BUFFER,
                RELEASE_CAPABILITY,
                SEND_BUFFER
            ]
        );
        assert_eq!(decode_probe_response(&raw.response), Ok(Ok(100)));
    }

    #[test]
    fn rejects_kernel_counts_beyond_supplied_receive_buffers() {
        let frame = Fat32SyscallFrame {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: PROBE_REQUEST_BYTES as u64 + 1,
            r10: 1,
            r8: 0,
            r9: 0,
        };
        assert_eq!(
            Fat32UserspaceSyscalls::<Raw>::receive_counts(&frame, PROBE_REQUEST_BYTES, 1),
            Err(Fat32UserspaceSyscallError::Range)
        );
        let frame = Fat32SyscallFrame {
            rdx: 0,
            r10: 2,
            ..frame
        };
        assert_eq!(
            Fat32UserspaceSyscalls::<Raw>::receive_counts(&frame, PROBE_REQUEST_BYTES, 1),
            Err(Fat32UserspaceSyscallError::Range)
        );
    }

    struct MountRaw {
        request: [u8; MOUNT_REQUEST_BYTES],
        response: [u8; MOUNT_RESPONSE_BYTES],
        operations: [u64; 2],
        count: usize,
        reported_capabilities: u64,
    }

    unsafe impl Fat32RawSyscall for MountRaw {
        unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame) {
            self.operations[self.count] = frame.rax;
            self.count += 1;
            match frame.rax {
                RECEIVE_BUFFER => unsafe {
                    assert_eq!(frame.rdx, 0);
                    assert_eq!(frame.r10, 0);
                    core::ptr::copy_nonoverlapping(
                        self.request.as_ptr(),
                        frame.rdi as *mut u8,
                        self.request.len(),
                    );
                    frame.rdx = MOUNT_REQUEST_BYTES as u64;
                    frame.r10 = self.reported_capabilities;
                },
                SEND_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.response.as_mut_ptr(),
                        frame.r10 as usize,
                    );
                },
                _ => panic!("unexpected mount syscall"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn mount_adapter_uses_zero_capability_receive_and_exact_reply() {
        use mrml_interface_storage_filesystem_v2::{
            encode_mount_request, encode_mount_response, BorrowedReadView, MountResponse,
            OpaqueHandle,
        };

        let request = encode_mount_request(
            OpaqueHandle::new(3, 8).unwrap(),
            BorrowedReadView::within(0, 0, 0).unwrap(),
        )
        .unwrap();
        let raw = MountRaw {
            request,
            response: [0; MOUNT_RESPONSE_BYTES],
            operations: [0; 2],
            count: 0,
            reported_capabilities: 0,
        };
        let mut adapter = Fat32MountUserspaceSyscalls::new(raw, 12, 13).unwrap();
        let mut received = [0; MOUNT_REQUEST_BYTES];
        assert_eq!(
            adapter.receive_mount(&mut received),
            Ok(ReceivedFat32MountEnvelope {
                payload_length: MOUNT_REQUEST_BYTES,
                capability_count: 0,
            })
        );
        assert_eq!(received, request);
        let response = encode_mount_response(Ok(MountResponse {
            generation: 1,
            root: OpaqueHandle::new(0, 1).unwrap(),
        }));
        adapter.send_mount_response(&response).unwrap();
        let raw = adapter.into_raw();
        assert_eq!(raw.operations, [RECEIVE_BUFFER, SEND_BUFFER]);
        assert_eq!(raw.response, response);
    }

    #[test]
    fn mount_adapter_rejects_kernel_reported_capability_transfer() {
        let raw = MountRaw {
            request: [0; MOUNT_REQUEST_BYTES],
            response: [0; MOUNT_RESPONSE_BYTES],
            operations: [0; 2],
            count: 0,
            reported_capabilities: 1,
        };
        let mut adapter = Fat32MountUserspaceSyscalls::new(raw, 12, 13).unwrap();
        assert_eq!(
            adapter.receive_mount(&mut [0; MOUNT_REQUEST_BYTES]),
            Err(Fat32UserspaceSyscallError::Range)
        );
        assert_eq!(adapter.into_raw().count, 1);
    }

    struct UnmountRaw {
        request: [u8; UNMOUNT_REQUEST_BYTES],
        response: [u8; UNMOUNT_RESPONSE_BYTES],
        operations: [u64; 2],
        count: usize,
        reported_capabilities: u64,
    }

    unsafe impl Fat32RawSyscall for UnmountRaw {
        unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame) {
            self.operations[self.count] = frame.rax;
            self.count += 1;
            match frame.rax {
                RECEIVE_BUFFER => unsafe {
                    assert_eq!((frame.rdx, frame.r10), (0, 0));
                    core::ptr::copy_nonoverlapping(
                        self.request.as_ptr(),
                        frame.rdi as *mut u8,
                        self.request.len(),
                    );
                    frame.rdx = UNMOUNT_REQUEST_BYTES as u64;
                    frame.r10 = self.reported_capabilities;
                },
                SEND_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.response.as_mut_ptr(),
                        frame.r10 as usize,
                    );
                },
                _ => panic!("unexpected unmount syscall"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn unmount_adapter_uses_zero_capability_receive_and_exact_reply() {
        use mrml_interface_storage_filesystem_v2::{
            encode_unmount_request, encode_unmount_response, OpaqueHandle,
        };

        let request = encode_unmount_request(OpaqueHandle::new(3, 8).unwrap(), 12).unwrap();
        let raw = UnmountRaw {
            request,
            response: [0; UNMOUNT_RESPONSE_BYTES],
            operations: [0; 2],
            count: 0,
            reported_capabilities: 0,
        };
        let mut adapter = Fat32UnmountUserspaceSyscalls::new(raw, 12, 13).unwrap();
        let mut received = [0; UNMOUNT_REQUEST_BYTES];
        assert_eq!(
            adapter.receive_unmount(&mut received),
            Ok(ReceivedFat32UnmountEnvelope {
                payload_length: UNMOUNT_REQUEST_BYTES,
                capability_count: 0,
            })
        );
        assert_eq!(received, request);
        let response = encode_unmount_response(Ok(17));
        adapter.send_unmount_response(&response).unwrap();
        let raw = adapter.into_raw();
        assert_eq!(raw.operations, [RECEIVE_BUFFER, SEND_BUFFER]);
        assert_eq!(raw.response, response);
    }

    #[test]
    fn unmount_adapter_rejects_kernel_reported_capability_transfer() {
        let raw = UnmountRaw {
            request: [0; UNMOUNT_REQUEST_BYTES],
            response: [0; UNMOUNT_RESPONSE_BYTES],
            operations: [0; 2],
            count: 0,
            reported_capabilities: 1,
        };
        let mut adapter = Fat32UnmountUserspaceSyscalls::new(raw, 12, 13).unwrap();
        assert_eq!(
            adapter.receive_unmount(&mut [0; UNMOUNT_REQUEST_BYTES]),
            Err(Fat32UserspaceSyscallError::Range)
        );
        assert_eq!(adapter.into_raw().count, 1);
    }

    struct LookupRaw {
        request: [u8; LOOKUP_REQUEST_BYTES],
        shared: [u8; 16],
        response: [u8; LOOKUP_RESPONSE_BYTES],
        operations: [u64; 4],
        count: usize,
        reported_capabilities: u64,
    }

    unsafe impl Fat32RawSyscall for LookupRaw {
        unsafe fn invoke(&mut self, frame: &mut Fat32SyscallFrame) {
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
                    frame.rdx = LOOKUP_REQUEST_BYTES as u64;
                    frame.r10 = self.reported_capabilities;
                },
                READ_SHARED_BUFFER => unsafe {
                    assert_eq!(frame.rdi, TOKEN);
                    core::ptr::copy_nonoverlapping(
                        self.shared.as_ptr().add(frame.rsi as usize),
                        frame.rdx as *mut u8,
                        frame.r10 as usize,
                    );
                },
                RELEASE_CAPABILITY => assert_eq!(frame.rdi, TOKEN),
                SEND_BUFFER => unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame.rdx as *const u8,
                        self.response.as_mut_ptr(),
                        frame.r10 as usize,
                    );
                },
                _ => panic!("unexpected lookup syscall"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn lookup_adapter_preserves_receive_read_release_reply_register_order() {
        use mrml_interface_storage_filesystem_v2::{
            encode_lookup_request, encode_lookup_response, BorrowedReadView, OpaqueHandle,
        };

        let request = encode_lookup_request(
            OpaqueHandle::new(3, 8).unwrap(),
            12,
            OpaqueHandle::new(0, 1).unwrap(),
            BorrowedReadView::within(2, 10, 16).unwrap(),
        )
        .unwrap();
        let mut shared = [0; 16];
        shared[2..12].copy_from_slice(b"KERNEL.MRP");
        let raw = LookupRaw {
            request,
            shared,
            response: [0; LOOKUP_RESPONSE_BYTES],
            operations: [0; 4],
            count: 0,
            reported_capabilities: 1,
        };
        let mut adapter = Fat32LookupUserspaceSyscalls::new(raw, 12, 13).unwrap();
        let mut received = [0; LOOKUP_REQUEST_BYTES];
        let mut tokens = [0; 1];
        assert_eq!(
            adapter.receive_lookup(&mut received, &mut tokens),
            Ok(ReceivedFat32LookupEnvelope {
                payload_length: LOOKUP_REQUEST_BYTES,
                capability_count: 1,
            })
        );
        let mut name = [0; 10];
        adapter
            .read_shared(Capability::from_token(TOKEN), 2, &mut name)
            .unwrap();
        assert_eq!(&name, b"KERNEL.MRP");
        adapter
            .release_received(Capability::from_token(TOKEN))
            .unwrap();
        let response = encode_lookup_response(Ok(7));
        adapter.send_lookup_response(&response).unwrap();
        let raw = adapter.into_raw();
        assert_eq!(
            raw.operations,
            [
                RECEIVE_BUFFER,
                READ_SHARED_BUFFER,
                RELEASE_CAPABILITY,
                SEND_BUFFER
            ]
        );
        assert_eq!(raw.response, response);
    }

    #[test]
    fn lookup_adapter_rejects_kernel_capability_over_count() {
        let raw = LookupRaw {
            request: [0; LOOKUP_REQUEST_BYTES],
            shared: [0; 16],
            response: [0; LOOKUP_RESPONSE_BYTES],
            operations: [0; 4],
            count: 0,
            reported_capabilities: 2,
        };
        let mut adapter = Fat32LookupUserspaceSyscalls::new(raw, 12, 13).unwrap();
        assert_eq!(
            adapter.receive_lookup(&mut [0; LOOKUP_REQUEST_BYTES], &mut [0; 1]),
            Err(Fat32UserspaceSyscallError::Range)
        );
        assert_eq!(adapter.into_raw().count, 1);
    }
}
