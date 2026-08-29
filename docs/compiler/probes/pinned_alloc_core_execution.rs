#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

struct Arena {
    next: AtomicUsize,
    bytes: UnsafeCell<[u8; 4096]>,
}

unsafe impl Sync for Arena {}

unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align() - 1;
        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            let start = (current + align_mask) & !align_mask;
            let Some(end) = start.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if end > 4096 {
                return core::ptr::null_mut();
            }
            match self.next.compare_exchange_weak(
                current,
                end,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return unsafe { (*self.bytes.get()).as_mut_ptr().add(start) },
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: Arena = Arena {
    next: AtomicUsize::new(0),
    bytes: UnsafeCell::new([0; 4096]),
};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let mut values = Vec::new();
    values.push(19u32);
    values.push(23u32);
    values.into_iter().sum()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
