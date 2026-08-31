use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

type Handle = *mut c_void;
type ThreadStart = unsafe extern "system" fn(*mut c_void) -> u32;

unsafe extern "system" {
    fn CreateThread(
        attributes: *mut c_void,
        stack_size: usize,
        start: Option<ThreadStart>,
        parameter: *mut c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeThread(handle: Handle, exit_code: *mut u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

static DROPS: AtomicU32 = AtomicU32::new(0);

struct Value(Cell<u32>);

impl Drop for Value {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::Release);
    }
}

std::thread_local! {
    static VALUE: Value = const { Value(Cell::new(40)) };
}

unsafe extern "system" fn thread_entry(_: *mut c_void) -> u32 {
    VALUE.with(|value| {
        value.0.set(value.0.get() + 2);
        value.0.get()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let thread = unsafe {
        CreateThread(
            ptr::null_mut(),
            0,
            Some(thread_entry),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return 1;
    }
    let mut child = 0u32;
    let wait = unsafe { WaitForSingleObject(thread, u32::MAX) };
    let read = unsafe { GetExitCodeThread(thread, &mut child) };
    let closed = unsafe { CloseHandle(thread) };
    if wait == 0 && read != 0 && closed != 0 && child == 42 && DROPS.load(Ordering::Acquire) == 1 {
        42
    } else {
        1
    }
}
