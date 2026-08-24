use core::arch::asm;
use core::convert::Infallible;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::{
    PAGE_SIZE, VIRTUAL_BLOCK_COMPLETION_BYTES, VIRTUAL_BLOCK_REQUEST_BYTES, VirtualBlockError,
    VirtualBlockGuestNotification, VirtualBlockGuestQueueTransport,
};

/// Exact x86 port output used by the native virtual-block guest transport.
///
/// # Safety
///
/// Implementations must issue exactly one 32-bit output to the supplied port
/// and value and may return only after the virtual-device transport has
/// accepted the exit. They must not redirect, widen, repeat, or suppress it.
pub unsafe trait X86VirtualBlockPortIo {
    /// # Safety
    ///
    /// `port` and `value` must be the exact tuple authorized for the bound
    /// virtual-block device, and the caller must be executing with guest I/O
    /// privilege under the corresponding fail-closed exit handler.
    unsafe fn output32(&mut self, port: u16, value: u32);

    /// # Safety
    ///
    /// `address` must be the exact live write-only notification register for
    /// the bound PCI BAR. The implementation must issue exactly one 32-bit
    /// write and return only after the VMM has accepted and retired it.
    unsafe fn write_mmio32(&mut self, address: u64, value: u32);
}

/// Privileged x86 `OUT DX, EAX` implementation for a native MRML guest.
pub struct NativeX86VirtualBlockPortIo;

unsafe impl X86VirtualBlockPortIo for NativeX86VirtualBlockPortIo {
    unsafe fn output32(&mut self, port: u16, value: u32) {
        // SAFETY: the trait and enclosing transport construction require guest
        // privilege and an exact allowlisted virtual-device port.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nostack, preserves_flags)
            )
        };
    }

    unsafe fn write_mmio32(&mut self, address: u64, value: u32) {
        if value != 1 {
            fail_stop();
        }
        // Keep one fixed, auditable encoding for the initial WHP decoder.
        // SAFETY: the trait binds RAX to the exact trapped notification
        // register and the VMM retires this write before guest re-entry.
        unsafe {
            asm!(
                "mov dword ptr [rax], 1",
                in("rax") address,
                options(nostack, preserves_flags)
            )
        };
    }
}

#[derive(Clone, Copy)]
enum X86VirtualBlockNotificationBinding {
    ScalarIo,
    PciMmio { base: u64, bytes: u32 },
}

/// Direct identity-mapped x86_64 implementation of the common block guest
/// queue transport.
pub struct X86VirtualBlockGuestQueueTransport<I> {
    io: I,
    notification: X86VirtualBlockNotificationBinding,
}

impl<I: X86VirtualBlockPortIo> X86VirtualBlockGuestQueueTransport<I> {
    /// # Safety
    ///
    /// Every address later supplied by a common-driver call must name its exact
    /// live identity-mapped queue byte range. Counter addresses must be
    /// naturally aligned, request memory must be writable, completion memory
    /// must be readable, and no actor may mutate a copied slot contrary to the
    /// queue protocol. `io` must target the same configured virtual device.
    pub const unsafe fn new(io: I) -> Self {
        Self {
            io,
            notification: X86VirtualBlockNotificationBinding::ScalarIo,
        }
    }

    /// Constructs a transport bound to one already-authorized live PCI BAR.
    ///
    /// # Safety
    ///
    /// `base..base + bytes` must remain the exact guest-visible write-only
    /// notification window for the same configured block device throughout
    /// this transport's lifetime. It must not alias ordinary guest RAM.
    pub unsafe fn new_pci_mmio(io: I, base: u64, bytes: u32) -> Result<Self, VirtualBlockError> {
        if base == 0
            || !base.is_multiple_of(PAGE_SIZE)
            || bytes != PAGE_SIZE as u32
            || base.checked_add(u64::from(bytes)).is_none()
        {
            return Err(VirtualBlockError::InvalidConfiguration);
        }
        Ok(Self {
            io,
            notification: X86VirtualBlockNotificationBinding::PciMmio { base, bytes },
        })
    }

    fn notify(&mut self, notification: VirtualBlockGuestNotification) {
        match (self.notification, notification) {
            (
                X86VirtualBlockNotificationBinding::ScalarIo,
                VirtualBlockGuestNotification::ScalarIo { port, value },
            ) => {
                // SAFETY: construction and the typed notification bind the
                // exact scalar tuple for this configured device.
                unsafe { self.io.output32(port, value) };
            }
            (
                X86VirtualBlockNotificationBinding::PciMmio { base, bytes },
                VirtualBlockGuestNotification::PciMmio { offset, value },
            ) if offset.checked_add(4).is_some_and(|end| end <= bytes) => {
                let Some(address) = base.checked_add(u64::from(offset)) else {
                    fail_stop();
                };
                // SAFETY: construction binds the exact live BAR and the
                // descriptor bounds this write to its fixed register set.
                unsafe { self.io.write_mmio32(address, value) };
            }
            _ => fail_stop(),
        }
    }
}

unsafe impl<I: X86VirtualBlockPortIo> VirtualBlockGuestQueueTransport
    for X86VirtualBlockGuestQueueTransport<I>
{
    type Error = Infallible;

    fn publish_request_and_notify(
        &mut self,
        request_address: u64,
        request: &[u8; VIRTUAL_BLOCK_REQUEST_BYTES],
        producer_address: u64,
        producer: u64,
        notification: VirtualBlockGuestNotification,
    ) -> Result<(), Self::Error> {
        // SAFETY: construction binds every supplied address to the exact live
        // identity mapping. Byte-wise volatile access preserves exact length
        // without imposing alignment on the wire record.
        unsafe { write_exact_volatile(request_address, request) };
        compiler_fence(Ordering::Release);
        // SAFETY: construction requires an aligned writable producer counter.
        unsafe { (producer_address as *mut u64).write_volatile(producer) };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: the unsafe I/O contract binds the exact accepted tuple.
        self.notify(notification);
        Ok(())
    }

    fn read_completion(
        &mut self,
        published_address: u64,
        completion_address: u64,
        published: &mut u64,
        completion: &mut [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
    ) -> Result<(), Self::Error> {
        // SAFETY: construction requires an aligned readable published counter.
        *published = unsafe { (published_address as *const u64).read_volatile() };
        compiler_fence(Ordering::Acquire);
        // SAFETY: construction binds the exact readable completion slot.
        unsafe { read_exact_volatile(completion_address, completion) };
        Ok(())
    }

    fn acknowledge_completion(
        &mut self,
        consumer_address: u64,
        consumer: u64,
        notification: VirtualBlockGuestNotification,
    ) -> Result<(), Self::Error> {
        compiler_fence(Ordering::Release);
        // SAFETY: the protected handler must publish the supplied consumer at
        // the bound address before the accepted exit resumes this guest.
        self.notify(notification);
        compiler_fence(Ordering::Acquire);
        // A successful return is permitted only after the protected counter is
        // observable. Any mismatch is integrity failure, not a retryable error.
        // SAFETY: construction requires an aligned readable consumer counter.
        if unsafe { (consumer_address as *const u64).read_volatile() } != consumer {
            fail_stop();
        }
        Ok(())
    }
}

unsafe fn write_exact_volatile<const N: usize>(address: u64, input: &[u8; N]) {
    let target = address as *mut u8;
    for (offset, byte) in input.iter().copied().enumerate() {
        // SAFETY: the caller binds the complete exact writable range.
        unsafe { target.add(offset).write_volatile(byte) };
    }
}

unsafe fn read_exact_volatile<const N: usize>(address: u64, output: &mut [u8; N]) {
    let source = address as *const u8;
    for (offset, byte) in output.iter_mut().enumerate() {
        // SAFETY: the caller binds the complete exact readable range.
        *byte = unsafe { source.add(offset).read_volatile() };
    }
}

fn fail_stop() -> ! {
    loop {
        // SAFETY: integrity failure cannot return to guest execution.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        VIRTUAL_BLOCK_COMPLETION_ACK_PORT, VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        VIRTUAL_BLOCK_DOORBELL_PORT, VIRTUAL_BLOCK_DOORBELL_VALUE,
        VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET, VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET,
        VirtualBlockDevice, VirtualBlockGuestDriver, VirtualBlockQueueLayout, VirtualBlockRequest,
        VirtualBlockTransport,
    };

    const QUEUE_HEADER_BYTES: usize = 128;

    #[repr(C, align(4096))]
    struct QueuePage([u8; 4096]);

    struct PortModel {
        outputs: [(u16, u32); 2],
        mmio: [(u64, u32); 2],
        count: usize,
        mmio_count: usize,
        acknowledgement_address: u64,
        acknowledgement: u64,
        mmio_acknowledgement_address: u64,
    }

    unsafe impl X86VirtualBlockPortIo for PortModel {
        unsafe fn output32(&mut self, port: u16, value: u32) {
            self.outputs[self.count] = (port, value);
            self.count += 1;
            if port == VIRTUAL_BLOCK_COMPLETION_ACK_PORT
                && value == VIRTUAL_BLOCK_COMPLETION_ACK_VALUE
            {
                // SAFETY: the test binds this aligned counter in its live page.
                unsafe {
                    (self.acknowledgement_address as *mut u64).write_volatile(self.acknowledgement)
                };
            }
        }

        unsafe fn write_mmio32(&mut self, address: u64, value: u32) {
            self.mmio[self.mmio_count] = (address, value);
            self.mmio_count += 1;
            if address == self.mmio_acknowledgement_address
                && value == VIRTUAL_BLOCK_COMPLETION_ACK_VALUE
            {
                // SAFETY: the test binds this aligned counter in its live page.
                unsafe {
                    (self.acknowledgement_address as *mut u64).write_volatile(self.acknowledgement)
                };
            }
        }
    }

    #[test]
    fn native_transport_uses_exact_volatile_ranges_order_and_ports() {
        let mut requests = QueuePage([0; 4096]);
        let mut completions = QueuePage([0; 4096]);
        let request_base = requests.0.as_mut_ptr() as u64;
        let completion_base = completions.0.as_mut_ptr() as u64;
        let layout = VirtualBlockQueueLayout::new(request_base, completion_base, 1).unwrap();
        let mut device = VirtualBlockDevice::<1>::new(4096, 2, 0).unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        let mut configuration = [0; crate::VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        device.configuration().unwrap().encode(&mut configuration);
        let mut driver = VirtualBlockGuestDriver::discover(&configuration, 0, 0, 0, 0).unwrap();
        let io = PortModel {
            outputs: [(0, 0); 2],
            mmio: [(0, 0); 2],
            count: 0,
            mmio_count: 0,
            acknowledgement_address: completion_base + 64,
            acknowledgement: 1,
            mmio_acknowledgement_address: 0,
        };
        // SAFETY: both aligned pages remain live and uniquely controlled for
        // the complete transport lifetime.
        let mut transport = unsafe { X86VirtualBlockGuestQueueTransport::new(io) };

        let submission = driver.prepare_read(0, 1, 0xa0000, 4096).unwrap();
        driver
            .publish_submission(&mut transport, submission)
            .unwrap();
        assert_eq!(u64::from_le_bytes(requests.0[..8].try_into().unwrap()), 1);
        assert_eq!(
            VirtualBlockRequest::decode(
                &requests.0[QUEUE_HEADER_BYTES..QUEUE_HEADER_BYTES + VIRTUAL_BLOCK_REQUEST_BYTES]
            ),
            Ok(submission.request())
        );

        let completion = &mut completions.0
            [QUEUE_HEADER_BYTES..QUEUE_HEADER_BYTES + VIRTUAL_BLOCK_COMPLETION_BYTES];
        completion[..4].copy_from_slice(b"MRBC");
        completion[4] = 1;
        completion[8..12].copy_from_slice(&1u32.to_le_bytes());
        completion[16..24].copy_from_slice(&1u64.to_le_bytes());
        completion[24..28].copy_from_slice(&4096u32.to_le_bytes());
        completions.0[..8].copy_from_slice(&1u64.to_le_bytes());
        let ticket = driver
            .prepare_completion_from_transport(&mut transport)
            .unwrap();
        driver
            .acknowledge_completion_with_transport(&mut transport, ticket)
            .unwrap();
        assert_eq!(transport.io.count, 2);
        assert_eq!(
            transport.io.outputs,
            [
                (VIRTUAL_BLOCK_DOORBELL_PORT, VIRTUAL_BLOCK_DOORBELL_VALUE),
                (
                    VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                    VIRTUAL_BLOCK_COMPLETION_ACK_VALUE
                ),
            ]
        );
        assert_eq!(
            u64::from_le_bytes(completions.0[64..72].try_into().unwrap()),
            1
        );
        assert_eq!(driver.completion_consumer(), 1);
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn native_transport_uses_exact_pci_mmio_notification_offsets() {
        const MMIO_BASE: u64 = 0x20_0000;
        let mut requests = QueuePage([0; 4096]);
        let mut completions = QueuePage([0; 4096]);
        let request_base = requests.0.as_mut_ptr() as u64;
        let completion_base = completions.0.as_mut_ptr() as u64;
        let layout = VirtualBlockQueueLayout::new(request_base, completion_base, 1).unwrap();
        let mut device = VirtualBlockDevice::<1>::new_with_transport(
            4096,
            2,
            0,
            VirtualBlockTransport::MrmlSpecificPciMmio,
        )
        .unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        let mut configuration = [0; crate::VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        device.configuration().unwrap().encode(&mut configuration);
        let mut driver = VirtualBlockGuestDriver::discover(&configuration, 0, 0, 0, 0).unwrap();
        let io = PortModel {
            outputs: [(0, 0); 2],
            mmio: [(0, 0); 2],
            count: 0,
            mmio_count: 0,
            acknowledgement_address: completion_base + 64,
            acknowledgement: 1,
            mmio_acknowledgement_address: MMIO_BASE
                + u64::from(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET),
        };
        // SAFETY: the queue pages and exact synthetic one-page BAR remain live
        // for this deterministic model.
        let mut transport = unsafe {
            X86VirtualBlockGuestQueueTransport::new_pci_mmio(io, MMIO_BASE, PAGE_SIZE as u32)
                .unwrap()
        };

        let submission = driver.prepare_read(0, 1, 0xa0000, 4096).unwrap();
        driver
            .publish_submission(&mut transport, submission)
            .unwrap();
        let completion = &mut completions.0
            [QUEUE_HEADER_BYTES..QUEUE_HEADER_BYTES + VIRTUAL_BLOCK_COMPLETION_BYTES];
        completion[..4].copy_from_slice(b"MRBC");
        completion[4] = 1;
        completion[8..12].copy_from_slice(&1u32.to_le_bytes());
        completion[16..24].copy_from_slice(&1u64.to_le_bytes());
        completion[24..28].copy_from_slice(&4096u32.to_le_bytes());
        completions.0[..8].copy_from_slice(&1u64.to_le_bytes());
        let ticket = driver
            .prepare_completion_from_transport(&mut transport)
            .unwrap();
        driver
            .acknowledge_completion_with_transport(&mut transport, ticket)
            .unwrap();

        assert_eq!(transport.io.count, 0);
        assert_eq!(
            transport.io.mmio,
            [
                (
                    MMIO_BASE + u64::from(VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET),
                    VIRTUAL_BLOCK_DOORBELL_VALUE,
                ),
                (
                    MMIO_BASE + u64::from(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET),
                    VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
                ),
            ]
        );
        assert_eq!(driver.completion_consumer(), 1);
        assert_eq!(driver.pending_count(), 0);
    }
}
