use crate::{
    AhciControlServiceSyscalls, AhciDataCapabilityAuthorizer, AhciDataServiceSyscalls,
    AhciDispatchSyscalls, AhciServiceSyscalls, InstalledAhciServiceLaunch,
    ReceivedAhciControlEnvelope, ReceivedAhciDataEnvelope, ReceivedAhciDispatchEnvelope,
    ReceivedAhciEnvelope, AHCI_DISPATCH_REQUEST_BYTES,
};
use mrml_interface_storage_block_provider_v1::{
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES, FLUSH_REQUEST_BYTES, FLUSH_RESPONSE_BYTES,
    READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
};
use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights};
#[cfg(target_arch = "x86_64")]
use core::arch::asm;

const AUTHORIZE_EXACT: u64 = 6;
const SEND_BUFFER: u64 = 4;
const RECEIVE_BUFFER: u64 = 5;
const READ_SHARED_BUFFER: u64 = 7;
const WRITE_SHARED_BUFFER: u64 = 8;
const RELEASE_CAPABILITY: u64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciSyscallFrame {
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
pub unsafe trait AhciRawSyscall {
    unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame);
}

/// Zero-state MRML x86-64 userspace syscall transition.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeAhciRawSyscall;

#[cfg(target_arch = "x86_64")]
unsafe impl AhciRawSyscall for NativeAhciRawSyscall {
    unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame) {
        let mut rax = frame.rax;
        let mut rdi = frame.rdi;
        let mut rsi = frame.rsi;
        let mut rdx = frame.rdx;
        let mut r10 = frame.r10;
        let mut r8 = frame.r8;
        let mut r9 = frame.r9;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") rax,
                inlateout("rdi") rdi,
                inlateout("rsi") rsi,
                inlateout("rdx") rdx,
                inlateout("r10") r10,
                inlateout("r8") r8,
                inlateout("r9") r9,
                options(nostack)
            )
        };
        *frame = AhciSyscallFrame {
            rax,
            rdi,
            rsi,
            rdx,
            r10,
            r8,
            r9,
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciUserspaceSyscallError {
    InvalidLaunchBinding,
    Kernel(u64),
    Range,
}

pub struct AhciUserspaceSyscalls<R> {
    raw: R,
    reply_endpoint: u64,
    reply_task: u64,
}

/// Launch-bound adapter for the kernel's exact capability authorization
/// syscall. It recognizes only the two installed data-DMA roles.
pub struct AhciInstalledDataAuthorizer<R> {
    raw: R,
    data_object: ObjectId,
    device_write_data: Capability,
    device_read_data: Capability,
}

impl<R> AhciInstalledDataAuthorizer<R> {
    pub fn from_installed_launch(raw: R, launch: InstalledAhciServiceLaunch) -> Self {
        Self {
            raw,
            data_object: launch.record().data().memory_object,
            device_write_data: launch.device_write_data(),
            device_read_data: launch.device_read_data(),
        }
    }

    pub fn into_raw(self) -> R {
        self.raw
    }
}

impl<R: AhciRawSyscall> AhciDataCapabilityAuthorizer for AhciInstalledDataAuthorizer<R> {
    fn authorize_exact(
        &mut self,
        capability: Capability,
        rights: Rights,
    ) -> Result<ObjectId, CapabilityError> {
        let expected = if capability == self.device_write_data {
            Rights::PIN.union(Rights::MAP).union(Rights::WRITE)
        } else if capability == self.device_read_data {
            Rights::PIN.union(Rights::MAP).union(Rights::READ)
        } else {
            return Err(CapabilityError::Invalid);
        };
        if rights != expected {
            return Err(CapabilityError::PermissionDenied);
        }
        let mut frame = AhciSyscallFrame {
            rax: AUTHORIZE_EXACT,
            rdi: capability.token(),
            rsi: self.data_object.0,
            rdx: u64::from(rights.bits()),
            r10: 0,
            r8: 0,
            r9: 0,
        };
        unsafe { self.raw.invoke(&mut frame) };
        if frame.rax == 0 {
            Ok(self.data_object)
        } else {
            Err(CapabilityError::PermissionDenied)
        }
    }
}

impl<R> AhciUserspaceSyscalls<R> {
    pub fn new(
        raw: R,
        reply_endpoint: u64,
        reply_task: u64,
    ) -> Result<Self, AhciUserspaceSyscallError> {
        if reply_endpoint == 0 || reply_task == 0 {
            return Err(AhciUserspaceSyscallError::InvalidLaunchBinding);
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

impl<R: AhciRawSyscall> AhciUserspaceSyscalls<R> {
    /// Copies immutable startup data through the exact launch-data capability
    /// installed by the kernel. The capability token is authority; the copied
    /// record contains identity and geometry only.
    pub fn read_launch_data(
        &mut self,
        capability: Capability,
        output: &mut [u8],
    ) -> Result<(), AhciUserspaceSyscallError> {
        if output.len() != crate::AHCI_SERVICE_LAUNCH_BYTES {
            return Err(AhciUserspaceSyscallError::Range);
        }
        let mut frame = AhciSyscallFrame {
            rax: READ_SHARED_BUFFER,
            rdi: capability.token(),
            rsi: 0,
            rdx: output.as_mut_ptr() as u64,
            r10: output.len() as u64,
            r8: 0,
            r9: 0,
        };
        self.invoke(&mut frame)
    }

    fn invoke(&mut self, frame: &mut AhciSyscallFrame) -> Result<(), AhciUserspaceSyscallError> {
        unsafe { self.raw.invoke(frame) };
        if frame.rax == 0 {
            Ok(())
        } else {
            Err(AhciUserspaceSyscallError::Kernel(frame.rax))
        }
    }

    fn receive_counts(
        frame: &AhciSyscallFrame,
        payload_capacity: usize,
        capability_capacity: usize,
    ) -> Result<(usize, usize), AhciUserspaceSyscallError> {
        let payload_length =
            usize::try_from(frame.rdx).map_err(|_| AhciUserspaceSyscallError::Range)?;
        let capability_count =
            usize::try_from(frame.r10).map_err(|_| AhciUserspaceSyscallError::Range)?;
        if payload_length > payload_capacity || capability_count > capability_capacity {
            return Err(AhciUserspaceSyscallError::Range);
        }
        Ok((payload_length, capability_count))
    }
}

unsafe impl<R: AhciRawSyscall> AhciServiceSyscalls for AhciUserspaceSyscalls<R> {
    type Error = AhciUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciEnvelope, Self::Error> {
        let mut frame = AhciSyscallFrame {
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
        Ok(ReceivedAhciEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let mut frame = AhciSyscallFrame {
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
        let mut frame = AhciSyscallFrame {
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
        let mut frame = AhciSyscallFrame {
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

unsafe impl<R: AhciRawSyscall> AhciDataServiceSyscalls for AhciUserspaceSyscalls<R> {
    type Error = AhciUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciDataEnvelope, Self::Error> {
        let mut frame = AhciSyscallFrame {
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
        Ok(ReceivedAhciDataEnvelope {
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
        let mut frame = AhciSyscallFrame {
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

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        <Self as AhciServiceSyscalls>::write_shared(self, capability, offset, input)
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        <Self as AhciServiceSyscalls>::release_received(self, capability)
    }

    fn send_response(&mut self, response: &[u8; READ_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        let mut frame = AhciSyscallFrame {
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
}

unsafe impl<R: AhciRawSyscall> AhciControlServiceSyscalls for AhciUserspaceSyscalls<R> {
    type Error = AhciUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; FLUSH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciControlEnvelope, Self::Error> {
        let mut frame = AhciSyscallFrame {
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
        Ok(ReceivedAhciControlEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn send_response(&mut self, response: &[u8; FLUSH_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        let mut frame = AhciSyscallFrame {
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
}

unsafe impl<R: AhciRawSyscall> AhciDispatchSyscalls for AhciUserspaceSyscalls<R> {
    type Error = AhciUserspaceSyscallError;

    fn receive(
        &mut self,
        request: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciDispatchEnvelope, Self::Error> {
        let mut frame = AhciSyscallFrame {
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
        Ok(ReceivedAhciDispatchEnvelope {
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
        <Self as AhciDataServiceSyscalls>::read_shared(self, capability, offset, output)
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        <Self as AhciDataServiceSyscalls>::write_shared(self, capability, offset, input)
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        <Self as AhciDataServiceSyscalls>::release_received(self, capability)
    }

    fn send_response(&mut self, response: &[u8; READ_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        <Self as AhciDataServiceSyscalls>::send_response(self, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AhciEnumerationServiceLoop;
    use mrml_interface_storage_block_provider_v1::{
        decode_enumerate_response, encode_enumerate_request, BlockProviderDevice,
        BorrowedWriteView, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_raw_syscall_bridge_retains_no_ambient_state() {
        assert_eq!(core::mem::size_of::<NativeAhciRawSyscall>(), 0);
        let _: NativeAhciRawSyscall = NativeAhciRawSyscall;
    }

    struct Raw {
        request: [u8; ENUMERATE_REQUEST_BYTES],
        memory: [u8; 128],
        response: [u8; ENUMERATE_RESPONSE_BYTES],
        operations: [u64; 4],
        count: usize,
    }

    unsafe impl AhciRawSyscall for Raw {
        unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame) {
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
                    assert_eq!((frame.rdi, frame.rsi), (0x51, 0x61));
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

    #[test]
    fn register_adapter_preserves_copy_release_reply_order() {
        let request =
            encode_enumerate_request(BorrowedWriteView::within(32, 48, 128).unwrap()).unwrap();
        let raw = Raw {
            request,
            memory: [0xa5; 128],
            response: [0; ENUMERATE_RESPONSE_BYTES],
            operations: [0; 4],
            count: 0,
        };
        assert!(matches!(
            AhciUserspaceSyscalls::new(raw, 0, 1),
            Err(AhciUserspaceSyscallError::InvalidLaunchBinding)
        ));
        let raw = Raw {
            request,
            memory: [0xa5; 128],
            response: [0; ENUMERATE_RESPONSE_BYTES],
            operations: [0; 4],
            count: 0,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 0x51, 0x61).unwrap();
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(4, 8).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 65_536,
            media_generation: 12,
        }];
        AhciEnumerationServiceLoop::new(&devices)
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
                SEND_BUFFER,
            ]
        );
        assert_eq!(&raw.memory[32..40], b"MRMLBLK\0");
        assert_eq!(decode_enumerate_response(&raw.response, 48), Ok(Ok(48)));
    }

    struct OperationRaw {
        operations: [u64; 7],
        count: usize,
        received_capabilities: u64,
    }

    unsafe impl AhciRawSyscall for OperationRaw {
        unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame) {
            self.operations[self.count] = frame.rax;
            self.count += 1;
            match frame.rax {
                RECEIVE_BUFFER => {
                    frame.rdx = frame.rsi;
                    frame.r10 = self.received_capabilities;
                }
                READ_SHARED_BUFFER => unsafe {
                    assert_eq!(frame.rdi, TOKEN);
                    core::ptr::write_bytes(frame.rdx as *mut u8, 0x5a, frame.r10 as usize);
                },
                WRITE_SHARED_BUFFER | RELEASE_CAPABILITY | SEND_BUFFER => {}
                _ => panic!("unexpected syscall"),
            }
            frame.rax = 0;
        }
    }

    #[test]
    fn data_and_control_adapters_map_only_the_canonical_syscalls() {
        let raw = OperationRaw {
            operations: [0; 7],
            count: 0,
            received_capabilities: 1,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 0x51, 0x61).unwrap();
        let mut request = [0; READ_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let envelope =
            AhciDataServiceSyscalls::receive(&mut syscalls, &mut request, &mut tokens).unwrap();
        assert_eq!(
            envelope,
            ReceivedAhciDataEnvelope {
                payload_length: READ_REQUEST_BYTES,
                capability_count: 1,
            }
        );
        let capability = Capability::from_token(TOKEN);
        let mut output = [0; 8];
        AhciDataServiceSyscalls::read_shared(&mut syscalls, capability, 4, &mut output).unwrap();
        assert_eq!(output, [0x5a; 8]);
        AhciDataServiceSyscalls::write_shared(&mut syscalls, capability, 8, &[0xa5; 8]).unwrap();
        AhciDataServiceSyscalls::release_received(&mut syscalls, capability).unwrap();
        AhciDataServiceSyscalls::send_response(&mut syscalls, &[0; READ_RESPONSE_BYTES]).unwrap();

        syscalls.raw.received_capabilities = 0;
        let mut control_request = [0; FLUSH_REQUEST_BYTES];
        let control =
            AhciControlServiceSyscalls::receive(&mut syscalls, &mut control_request, &mut tokens)
                .unwrap();
        assert_eq!(
            control,
            ReceivedAhciControlEnvelope {
                payload_length: FLUSH_REQUEST_BYTES,
                capability_count: 0,
            }
        );
        AhciControlServiceSyscalls::send_response(&mut syscalls, &[0; FLUSH_RESPONSE_BYTES])
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
                RECEIVE_BUFFER,
                SEND_BUFFER,
            ]
        );
    }

    #[test]
    fn launch_data_copy_uses_only_the_installed_read_capability() {
        let raw = OperationRaw {
            operations: [0; 7],
            count: 0,
            received_capabilities: 0,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 0x51, 0x61).unwrap();
        let mut output = [0; crate::AHCI_SERVICE_LAUNCH_BYTES];
        syscalls
            .read_launch_data(Capability::from_token(TOKEN), &mut output)
            .unwrap();
        assert_eq!(output, [0x5a; crate::AHCI_SERVICE_LAUNCH_BYTES]);
        assert_eq!(syscalls.raw.operations[0], READ_SHARED_BUFFER);
        assert_eq!(syscalls.raw.count, 1);
        assert_eq!(
            syscalls.read_launch_data(Capability::from_token(TOKEN), &mut []),
            Err(AhciUserspaceSyscallError::Range)
        );
        assert_eq!(syscalls.raw.count, 1);
    }

    #[test]
    fn rejects_kernel_counts_beyond_supplied_receive_buffers() {
        let frame = AhciSyscallFrame {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: ENUMERATE_REQUEST_BYTES as u64 + 1,
            r10: 1,
            r8: 0,
            r9: 0,
        };
        assert_eq!(
            AhciUserspaceSyscalls::<OperationRaw>::receive_counts(
                &frame,
                ENUMERATE_REQUEST_BYTES,
                1,
            ),
            Err(AhciUserspaceSyscallError::Range)
        );
        let frame = AhciSyscallFrame {
            rdx: 0,
            r10: 2,
            ..frame
        };
        assert_eq!(
            AhciUserspaceSyscalls::<OperationRaw>::receive_counts(
                &frame,
                ENUMERATE_REQUEST_BYTES,
                1,
            ),
            Err(AhciUserspaceSyscallError::Range)
        );
        let frame = AhciSyscallFrame { r10: 1, ..frame };
        assert_eq!(
            AhciUserspaceSyscalls::<OperationRaw>::receive_counts(
                &frame,
                ENUMERATE_REQUEST_BYTES,
                1,
            ),
            Ok((0, 1))
        );
    }

    #[test]
    fn unified_dispatch_adapter_receives_into_the_maximum_canonical_buffer() {
        let raw = OperationRaw {
            operations: [0; 7],
            count: 0,
            received_capabilities: 1,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 0x51, 0x61).unwrap();
        let mut request = [0; AHCI_DISPATCH_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let envelope = AhciDispatchSyscalls::receive(&mut syscalls, &mut request, &mut tokens)
            .unwrap();
        assert_eq!(
            envelope,
            ReceivedAhciDispatchEnvelope {
                payload_length: AHCI_DISPATCH_REQUEST_BYTES,
                capability_count: 1,
            }
        );
        assert_eq!(syscalls.raw.operations[0], RECEIVE_BUFFER);
        assert_eq!(syscalls.raw.count, 1);
    }
}
